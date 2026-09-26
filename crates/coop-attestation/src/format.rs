use crate::error::AttestationError;
use crate::keys::key_id;
use crate::strict_json;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::num::NonZeroUsize;

/// The only DSSE payload type accepted by this profile.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The in-toto Statement schema URI used by this profile.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The globally unique Rookhold execution-predicate type URI.
///
/// The legacy repository URL is immutable wire identity for predicate v1.
pub const COOP_EXECUTION_PREDICATE_TYPE: &str =
    "https://github.com/sambai-dev/coop/blob/main/crates/coop-attestation/FORMAT.md#predicate-v1";
/// The predicate's integer schema discriminator.
pub const COOP_EXECUTION_SCHEMA_VERSION: u32 = 1;
/// Maximum serialized DSSE envelope accepted by the verifier.
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum decoded in-toto statement accepted by the verifier.
pub const MAX_STATEMENT_BYTES: usize = 1024 * 1024;
/// Maximum signatures accepted in one envelope.
pub const MAX_SIGNATURES: usize = 32;
/// Maximum configured Ed25519 trust roots considered by one verification.
pub const MAX_TRUSTED_KEYS: usize = 16;

const MAX_EXECUTION_ID_CHARS: usize = 256;
const MAX_TENANT_CHARS: usize = 128;
const MAX_SUBJECT_NAME_CHARS: usize = 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_KEY_ID_HINT_BYTES: usize = 256;
const MAX_RECEIPT_JSON_DEPTH: usize = 64;
const MAX_RECEIPT_JSON_NODES: usize = 65_536;
const MAX_RECEIPT_ESTIMATED_BYTES: usize = 768 * 1024;

/// SHA-256 and byte-length metadata computed from an immutable artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    sha256: String,
    size_bytes: u64,
}

impl ArtifactDigest {
    /// Hash an in-memory artifact.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }
    }

    /// Hash an artifact incrementally without retaining its contents.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, AttestationError> {
        let mut hasher = Sha256::new();
        let mut size_bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(AttestationError::Io(error)),
            };
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            size_bytes = size_bytes.checked_add(read as u64).ok_or(
                AttestationError::InvalidProfileField {
                    field: "result.size_bytes",
                },
            )?;
        }
        Ok(Self {
            sha256: bytes_to_hex(hasher.finalize().as_slice()),
            size_bytes,
        })
    }

    /// Construct metadata from a precomputed lowercase SHA-256 digest.
    ///
    /// This is intended for a trusted server component that already hashed
    /// the immutable result bytes. Callers are responsible for the accuracy of
    /// the supplied digest and size.
    pub fn from_precomputed(
        sha256: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, AttestationError> {
        let sha256 = sha256.into();
        validate_sha256(&sha256, "result.sha256")?;
        Ok(Self { sha256, size_bytes })
    }

    /// Lowercase hexadecimal SHA-256 of the exact artifact bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Exact artifact byte length.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Authenticated metadata describing the one result artifact in a Rookhold statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectArtifact {
    name: String,
    media_type: String,
    digest: ArtifactDigest,
}

impl SubjectArtifact {
    /// Describe and hash an in-memory result artifact.
    pub fn from_bytes(
        name: impl Into<String>,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, AttestationError> {
        Self::from_digest(name, media_type, ArtifactDigest::from_bytes(bytes))
    }

    /// Describe a result artifact whose digest was already computed by a trusted component.
    pub fn from_digest(
        name: impl Into<String>,
        media_type: impl Into<String>,
        digest: ArtifactDigest,
    ) -> Result<Self, AttestationError> {
        let subject = Self {
            name: name.into(),
            media_type: media_type.into(),
            digest,
        };
        validate_text(&subject.name, MAX_SUBJECT_NAME_CHARS, "subject.name")?;
        validate_media_type(&subject.media_type)?;
        Ok(subject)
    }

    /// Stable name carried by the in-toto ResourceDescriptor.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Media type carried by both the subject and predicate result descriptor.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Digest and length of the exact artifact bytes.
    pub fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }
}

/// Strict Rookhold profile of an in-toto ResourceDescriptor.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResourceDescriptor {
    name: String,
    digest: BTreeMap<String, String>,
    #[serde(rename = "mediaType")]
    media_type: String,
}

impl ResourceDescriptor {
    /// Authenticated artifact name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Authenticated artifact media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Authenticated lowercase SHA-256 digest.
    pub fn sha256(&self) -> Option<&str> {
        self.digest.get("sha256").map(String::as_str)
    }
}

/// Result metadata duplicated in the predicate for direct policy evaluation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoopResultDescriptorV1 {
    name: String,
    media_type: String,
    size_bytes: u64,
    sha256: String,
}

impl CoopResultDescriptorV1 {
    /// Authenticated artifact name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Authenticated artifact media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Authenticated byte length.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Authenticated lowercase SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Version 1 Rookhold execution predicate carried by the in-toto statement.
#[derive(Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CoopExecutionPredicateV1 {
    schema_version: u32,
    execution_id: String,
    tenant: String,
    result: CoopResultDescriptorV1,
    receipt: Value,
}

impl CoopExecutionPredicateV1 {
    /// Predicate schema discriminator. This profile accepts only `1`.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Stable Rookhold execution/job identifier supplied by the control plane.
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    /// Authenticated tenant that authoritatively owned the execution.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Authenticated result descriptor.
    pub fn result(&self) -> &CoopResultDescriptorV1 {
        &self.result
    }

    /// Existing Rookhold receipt object embedded without exposing it through CLI output.
    pub fn receipt(&self) -> &Value {
        &self.receipt
    }
}

impl fmt::Debug for CoopExecutionPredicateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoopExecutionPredicateV1")
            .field("schema_version", &self.schema_version)
            .field("execution_id", &self.execution_id)
            .field("tenant", &self.tenant)
            .field("result", &self.result)
            .field("receipt", &"[REDACTED]")
            .finish()
    }
}

/// Strict Rookhold profile of an in-toto Statement/v1.
#[derive(Clone, Serialize, PartialEq)]
pub struct StatementV1 {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: CoopExecutionPredicateV1,
}

impl StatementV1 {
    /// Authenticated in-toto statement type.
    pub fn statement_type(&self) -> &str {
        &self.statement_type
    }

    /// Statement subjects. A verified Rookhold profile contains exactly one.
    pub fn subjects(&self) -> &[ResourceDescriptor] {
        &self.subject
    }

    /// Authenticated predicate type URI.
    pub fn predicate_type(&self) -> &str {
        &self.predicate_type
    }

    /// Authenticated Rookhold execution predicate.
    pub fn predicate(&self) -> &CoopExecutionPredicateV1 {
        &self.predicate
    }
}

impl fmt::Debug for StatementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatementV1")
            .field("statement_type", &self.statement_type)
            .field("subject", &self.subject)
            .field("predicate_type", &self.predicate_type)
            .field("predicate", &self.predicate)
            .finish()
    }
}

/// One signature entry in the JSON DSSE envelope.
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct DsseSignature {
    #[serde(default)]
    keyid: String,
    sig: String,
}

impl DsseSignature {
    /// Unauthenticated trial-order hint supplied by the signer.
    pub fn key_id_hint(&self) -> &str {
        &self.keyid
    }
}

impl fmt::Debug for DsseSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DsseSignature")
            .field("keyid", &self.keyid)
            .field("sig", &"[REDACTED]")
            .finish()
    }
}

/// JSON DSSE envelope carrying exact in-toto statement bytes.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Authenticated payload type after successful verification.
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    /// Signature entries. Their `keyid` members are never trust decisions.
    pub fn signatures(&self) -> &[DsseSignature] {
        &self.signatures
    }

    /// Encode the envelope as compact deterministic JSON.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        let bytes = serde_json::to_vec(self).map_err(|_| AttestationError::JsonEncoding {
            document: "DSSE envelope",
        })?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(AttestationError::EnvelopeTooLarge {
                max_bytes: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(bytes)
    }
}

impl fmt::Debug for DsseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DsseEnvelope")
            .field("payload_type", &self.payload_type)
            .field("payload_base64_bytes", &self.payload.len())
            .field("signatures", &self.signatures)
            .finish()
    }
}

// Wire-only decoders keep unverified JSON from constructing public typed
// values. Unknown fields are intentionally ignored for DSSE and in-toto
// monotonic forward compatibility; the strict JSON preflight still rejects
// duplicate keys at every depth.
#[derive(Deserialize)]
struct WireResourceDescriptor {
    name: String,
    digest: BTreeMap<String, String>,
    #[serde(rename = "mediaType")]
    media_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCoopResultDescriptorV1 {
    name: String,
    media_type: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCoopExecutionPredicateV1 {
    schema_version: u32,
    execution_id: String,
    tenant: String,
    result: WireCoopResultDescriptorV1,
    receipt: Value,
}

#[derive(Deserialize)]
struct WireStatementV1 {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<WireResourceDescriptor>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: WireCoopExecutionPredicateV1,
}

#[derive(Deserialize)]
struct WireDsseSignature {
    #[serde(default)]
    keyid: String,
    sig: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDsseEnvelope {
    payload_type: String,
    payload: String,
    #[serde(deserialize_with = "deserialize_signatures_bounded")]
    signatures: Vec<WireDsseSignature>,
}

fn deserialize_signatures_bounded<'de, D>(
    deserializer: D,
) -> Result<Vec<WireDsseSignature>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct SignaturesVisitor;

    impl<'de> Visitor<'de> for SignaturesVisitor {
        type Value = Vec<WireDsseSignature>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_SIGNATURES} DSSE signatures")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|hint| hint > MAX_SIGNATURES)
            {
                return Err(A::Error::custom("too many DSSE signatures"));
            }
            let mut signatures =
                Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(MAX_SIGNATURES));
            while let Some(signature) = sequence.next_element()? {
                if signatures.len() == MAX_SIGNATURES {
                    return Err(A::Error::custom("too many DSSE signatures"));
                }
                signatures.push(signature);
            }
            Ok(signatures)
        }
    }

    deserializer.deserialize_seq(SignaturesVisitor)
}

impl From<WireStatementV1> for StatementV1 {
    fn from(wire: WireStatementV1) -> Self {
        Self {
            statement_type: wire.statement_type,
            subject: wire
                .subject
                .into_iter()
                .map(|subject| ResourceDescriptor {
                    name: subject.name,
                    digest: subject.digest,
                    media_type: subject.media_type,
                })
                .collect(),
            predicate_type: wire.predicate_type,
            predicate: CoopExecutionPredicateV1 {
                schema_version: wire.predicate.schema_version,
                execution_id: wire.predicate.execution_id,
                tenant: wire.predicate.tenant,
                result: CoopResultDescriptorV1 {
                    name: wire.predicate.result.name,
                    media_type: wire.predicate.result.media_type,
                    size_bytes: wire.predicate.result.size_bytes,
                    sha256: wire.predicate.result.sha256,
                },
                receipt: wire.predicate.receipt,
            },
        }
    }
}

impl From<WireDsseEnvelope> for DsseEnvelope {
    fn from(wire: WireDsseEnvelope) -> Self {
        Self {
            payload_type: wire.payload_type,
            payload: wire.payload,
            signatures: wire
                .signatures
                .into_iter()
                .map(|signature| DsseSignature {
                    keyid: signature.keyid,
                    sig: signature.sig,
                })
                .collect(),
        }
    }
}

/// Verification constraints separate from the configured trusted key set.
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    minimum_signatures: NonZeroUsize,
    expected_tenant: Option<String>,
    expected_subject_name: Option<String>,
    expected_media_type: Option<String>,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            minimum_signatures: NonZeroUsize::MIN,
            expected_tenant: None,
            expected_subject_name: None,
            expected_media_type: None,
        }
    }
}

impl VerificationPolicy {
    /// Require signatures from at least this many distinct trusted public keys.
    pub fn with_minimum_signatures(mut self, minimum: NonZeroUsize) -> Self {
        self.minimum_signatures = minimum;
        self
    }

    /// Require the authenticated execution tenant to equal this value.
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.expected_tenant = Some(tenant.into());
        self
    }

    /// Require the authenticated subject name to equal this value.
    pub fn with_subject_name(mut self, name: impl Into<String>) -> Self {
        self.expected_subject_name = Some(name.into());
        self
    }

    /// Require the authenticated result media type to equal this value.
    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.expected_media_type = Some(media_type.into());
        self
    }

    /// Configured distinct-trusted-key threshold.
    pub fn minimum_signatures(&self) -> NonZeroUsize {
        self.minimum_signatures
    }
}

/// Authenticated, schema-validated statement and the trust result that admitted it.
#[derive(Clone)]
pub struct VerifiedAttestation {
    statement_bytes: Vec<u8>,
    statement: StatementV1,
    verified_key_ids: Vec<String>,
}

impl VerifiedAttestation {
    /// Exact payload bytes whose DSSE PAE signatures were verified.
    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement_bytes
    }

    /// Parsed statement. Parsing occurs only after the signature threshold is met.
    pub fn statement(&self) -> &StatementV1 {
        &self.statement
    }

    /// The profile's single schema-validated result subject.
    pub fn subject(&self) -> &ResourceDescriptor {
        // VerifiedAttestation has no public constructor and is created only
        // after validate_statement enforces exactly one subject.
        &self.statement.subject[0]
    }

    /// The guaranteed SHA-256 digest of the schema-validated result subject.
    pub fn subject_sha256(&self) -> &str {
        &self.statement.subject[0].digest["sha256"]
    }

    /// Derived IDs of distinct trusted keys that admitted the attestation.
    ///
    /// Verification stops once the configured threshold is met, so this is an
    /// admitting subset rather than an inventory of every valid signature.
    pub fn verified_key_ids(&self) -> &[String] {
        &self.verified_key_ids
    }
}

impl fmt::Debug for VerifiedAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAttestation")
            .field("statement_bytes", &"[REDACTED]")
            .field("statement", &self.statement)
            .field("verified_key_ids", &self.verified_key_ids)
            .finish()
    }
}

/// Build a tenant-bound in-toto Statement/v1 around one result artifact and Rookhold receipt.
pub fn build_statement(
    tenant: impl Into<String>,
    execution_id: impl Into<String>,
    subject: &SubjectArtifact,
    receipt: Value,
) -> Result<StatementV1, AttestationError> {
    let tenant = tenant.into();
    let execution_id = execution_id.into();
    validate_text(&tenant, MAX_TENANT_CHARS, "predicate.tenant")?;
    validate_text(
        &execution_id,
        MAX_EXECUTION_ID_CHARS,
        "predicate.execution_id",
    )?;
    if !receipt.is_object() {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt",
        });
    }
    validate_json_limits(&receipt)?;

    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), subject.digest.sha256.clone());
    let statement = StatementV1 {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
        subject: vec![ResourceDescriptor {
            name: subject.name.clone(),
            digest,
            media_type: subject.media_type.clone(),
        }],
        predicate_type: COOP_EXECUTION_PREDICATE_TYPE.to_string(),
        predicate: CoopExecutionPredicateV1 {
            schema_version: COOP_EXECUTION_SCHEMA_VERSION,
            execution_id,
            tenant,
            result: CoopResultDescriptorV1 {
                name: subject.name.clone(),
                media_type: subject.media_type.clone(),
                size_bytes: subject.digest.size_bytes,
                sha256: subject.digest.sha256.clone(),
            },
            receipt: normalize_json(receipt),
        },
    };
    validate_statement(&statement, None, &VerificationPolicy::default())?;
    // A builder never returns a value that is guaranteed to fail the crate's
    // own wire-size ceiling later during signing.
    let _ = encode_statement(&statement)?;
    Ok(statement)
}

/// Strictly parse a stored receipt JSON object and build the tenant-bound Rookhold statement.
///
/// This is the preferred server-integration entry point when the existing
/// receipt is available as canonical JSON text. It rejects duplicate keys
/// before constructing the typed predicate.
pub fn build_statement_from_receipt_json(
    tenant: impl Into<String>,
    execution_id: impl Into<String>,
    subject: &SubjectArtifact,
    receipt_json: &[u8],
) -> Result<StatementV1, AttestationError> {
    if receipt_json.len() > MAX_STATEMENT_BYTES {
        return Err(AttestationError::StatementTooLarge {
            max_bytes: MAX_STATEMENT_BYTES,
        });
    }
    let receipt: Value = strict_json::from_slice(receipt_json, "Rookhold receipt")?;
    build_statement(tenant, execution_id, subject, receipt)
}

/// Encode a validated statement as compact deterministic JSON.
///
/// This is an encoder profile, not RFC 8785. DSSE authenticates the exact
/// returned bytes, and verifiers never parse and reserialize before checking
/// signatures.
pub fn encode_statement(statement: &StatementV1) -> Result<Vec<u8>, AttestationError> {
    validate_statement(statement, None, &VerificationPolicy::default())?;
    let bytes = serde_json::to_vec(statement).map_err(|_| AttestationError::JsonEncoding {
        document: "in-toto statement",
    })?;
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(AttestationError::StatementTooLarge {
            max_bytes: MAX_STATEMENT_BYTES,
        });
    }
    Ok(bytes)
}

/// Sign a validated statement with one or more distinct Ed25519 keys.
pub fn sign_statement(
    statement: &StatementV1,
    signing_keys: &[&SigningKey],
) -> Result<DsseEnvelope, AttestationError> {
    if signing_keys.is_empty() {
        return Err(AttestationError::NoSigningKeys);
    }
    if signing_keys.len() > MAX_SIGNATURES {
        return Err(AttestationError::TooManySignatures {
            max: MAX_SIGNATURES,
        });
    }

    let statement_bytes = encode_statement(statement)?;
    let pae = dsse_v1_pae(DSSE_PAYLOAD_TYPE, &statement_bytes)?;
    let mut unique = BTreeMap::<String, &SigningKey>::new();
    for signing_key in signing_keys {
        let id = key_id(&signing_key.verifying_key());
        match unique.get(&id) {
            Some(existing) if existing.verifying_key() == signing_key.verifying_key() => {
                return Err(AttestationError::DuplicateSigningKey)
            }
            Some(_) => return Err(AttestationError::KeyIdCollision),
            None => {
                unique.insert(id, signing_key);
            }
        }
    }

    let signatures = unique
        .into_iter()
        .map(|(keyid, signing_key)| DsseSignature {
            keyid,
            sig: BASE64_STANDARD.encode(signing_key.sign(&pae).to_bytes()),
        })
        .collect();
    Ok(DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STANDARD.encode(statement_bytes),
        signatures,
    })
}

/// Build, encode, and sign a Rookhold execution attestation.
pub fn create_attestation(
    tenant: impl Into<String>,
    execution_id: impl Into<String>,
    subject: &SubjectArtifact,
    receipt: Value,
    signing_keys: &[&SigningKey],
) -> Result<DsseEnvelope, AttestationError> {
    let statement = build_statement(tenant, execution_id, subject, receipt)?;
    sign_statement(&statement, signing_keys)
}

/// Verify DSSE signatures before parsing and validating the in-toto statement.
///
/// The envelope's `keyid` values only prioritize trial order. Acceptance is
/// based exclusively on strict Ed25519 verification by distinct configured
/// trusted public keys and the supplied threshold.
pub fn verify_attestation(
    envelope_json: &[u8],
    expected_artifact: &ArtifactDigest,
    trusted_keys: &[VerifyingKey],
    policy: &VerificationPolicy,
) -> Result<VerifiedAttestation, AttestationError> {
    if envelope_json.len() > MAX_ENVELOPE_BYTES {
        return Err(AttestationError::EnvelopeTooLarge {
            max_bytes: MAX_ENVELOPE_BYTES,
        });
    }
    let trusted = unique_trusted_keys(trusted_keys)?;
    let required = policy.minimum_signatures.get();
    if required > trusted.len() {
        return Err(AttestationError::InvalidSignatureThreshold {
            required,
            available: trusted.len(),
        });
    }

    let envelope = DsseEnvelope::from(strict_json::from_slice::<WireDsseEnvelope>(
        envelope_json,
        "DSSE envelope",
    )?);
    validate_envelope_structure(&envelope)?;

    let statement_bytes = decode_dsse_base64(&envelope.payload, "payload")?;
    if statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(AttestationError::StatementTooLarge {
            max_bytes: MAX_STATEMENT_BYTES,
        });
    }

    let pae = dsse_v1_pae(&envelope.payload_type, &statement_bytes)?;
    // DSSE decoding is all-or-nothing. Decode every bounded signature before
    // applying the threshold, then allow expensive cryptographic work to stop
    // as soon as the configured policy is satisfied.
    let decoded_signatures = envelope
        .signatures
        .iter()
        .map(|envelope_signature| {
            let signature_bytes = decode_dsse_base64(&envelope_signature.sig, "signature")?;
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| AttestationError::InvalidSignatureLength)?;
            Ok(Signature::from_bytes(&signature_array))
        })
        .collect::<Result<Vec<_>, AttestationError>>()?;
    let mut verified = BTreeSet::new();
    for (envelope_signature, signature) in envelope.signatures.iter().zip(&decoded_signatures) {
        // A matching hint is tried first, but every other trusted key is still
        // attempted. A false, missing, or attacker-chosen hint cannot grant or
        // deny trust.
        let usable_hint = if envelope_signature.keyid.len() <= MAX_KEY_ID_HINT_BYTES
            && !envelope_signature.keyid.chars().any(char::is_control)
        {
            envelope_signature.keyid.as_str()
        } else {
            ""
        };
        let candidates = trusted
            .iter()
            .filter(|(id, _)| id == usable_hint)
            .chain(trusted.iter().filter(|(id, _)| id != usable_hint));
        for (id, verifying_key) in candidates {
            if verifying_key.verify_strict(&pae, signature).is_ok() {
                verified.insert(id.clone());
                break;
            }
        }
        if verified.len() >= required {
            break;
        }
    }
    if verified.len() < required {
        return Err(AttestationError::SignatureThresholdNotMet {
            required,
            verified: verified.len(),
        });
    }

    // payloadType is authenticated by the signatures above. Check it only
    // after threshold verification, before parsing the payload as a Statement.
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(AttestationError::PayloadTypeMismatch);
    }
    let statement = StatementV1::from(strict_json::from_slice::<WireStatementV1>(
        &statement_bytes,
        "in-toto statement",
    )?);
    validate_statement(&statement, Some(expected_artifact), policy)?;

    Ok(VerifiedAttestation {
        statement_bytes,
        statement,
        verified_key_ids: verified.into_iter().collect(),
    })
}

fn unique_trusted_keys(
    trusted_keys: &[VerifyingKey],
) -> Result<Vec<(String, VerifyingKey)>, AttestationError> {
    if trusted_keys.is_empty() {
        return Err(AttestationError::NoTrustedKeys);
    }
    if trusted_keys.len() > MAX_TRUSTED_KEYS {
        return Err(AttestationError::TooManyTrustedKeys {
            max: MAX_TRUSTED_KEYS,
        });
    }
    let mut unique = BTreeMap::<String, VerifyingKey>::new();
    for verifying_key in trusted_keys {
        let id = key_id(verifying_key);
        match unique.get(&id) {
            Some(existing) if existing == verifying_key => {}
            Some(_) => return Err(AttestationError::KeyIdCollision),
            None => {
                unique.insert(id, *verifying_key);
            }
        }
    }
    Ok(unique.into_iter().collect())
}

fn validate_envelope_structure(envelope: &DsseEnvelope) -> Result<(), AttestationError> {
    if envelope.signatures.is_empty() {
        return Err(AttestationError::NoSignatures);
    }
    if envelope.payload_type.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(AttestationError::InvalidProfileField {
            field: "DSSE payloadType",
        });
    }
    for signature in &envelope.signatures {
        if signature.sig.is_empty() {
            return Err(AttestationError::InvalidSignatureLength);
        }
    }
    Ok(())
}

fn validate_statement(
    statement: &StatementV1,
    expected_artifact: Option<&ArtifactDigest>,
    policy: &VerificationPolicy,
) -> Result<(), AttestationError> {
    if statement.statement_type != IN_TOTO_STATEMENT_TYPE {
        return Err(AttestationError::StatementTypeMismatch);
    }
    if statement.predicate_type != COOP_EXECUTION_PREDICATE_TYPE {
        return Err(AttestationError::PredicateTypeMismatch);
    }
    if statement.predicate.schema_version != COOP_EXECUTION_SCHEMA_VERSION {
        return Err(AttestationError::PredicateSchemaVersionMismatch);
    }
    if statement.subject.len() != 1 {
        return Err(AttestationError::InvalidProfileField { field: "subject" });
    }
    validate_text(
        &statement.predicate.execution_id,
        MAX_EXECUTION_ID_CHARS,
        "predicate.execution_id",
    )?;
    validate_text(
        &statement.predicate.tenant,
        MAX_TENANT_CHARS,
        "predicate.tenant",
    )?;
    if !statement.predicate.receipt.is_object() {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt",
        });
    }
    validate_receipt_core(
        &statement.predicate.receipt,
        &statement.predicate.execution_id,
        &statement.predicate.tenant,
    )?;

    let subject = &statement.subject[0];
    validate_text(&subject.name, MAX_SUBJECT_NAME_CHARS, "subject.name")?;
    validate_media_type(&subject.media_type)?;
    if !subject.digest.contains_key("sha256") {
        return Err(AttestationError::InvalidProfileField {
            field: "subject.digest",
        });
    }
    let subject_sha256 = &subject.digest["sha256"];
    validate_sha256(subject_sha256, "subject.digest.sha256")?;

    let result = &statement.predicate.result;
    validate_text(
        &result.name,
        MAX_SUBJECT_NAME_CHARS,
        "predicate.result.name",
    )?;
    validate_media_type(&result.media_type)?;
    validate_sha256(&result.sha256, "predicate.result.sha256")?;
    if result.name != subject.name
        || result.media_type != subject.media_type
        || result.sha256 != *subject_sha256
    {
        return Err(AttestationError::SubjectDescriptorMismatch);
    }

    if let Some(expected) = expected_artifact {
        if expected.sha256 != *subject_sha256 {
            return Err(AttestationError::SubjectDigestMismatch);
        }
        if expected.size_bytes != result.size_bytes {
            return Err(AttestationError::SubjectSizeMismatch);
        }
    }
    if policy
        .expected_tenant
        .as_ref()
        .is_some_and(|expected| expected != &statement.predicate.tenant)
    {
        return Err(AttestationError::TenantPolicyMismatch);
    }
    if policy
        .expected_subject_name
        .as_ref()
        .is_some_and(|expected| expected != &subject.name)
    {
        return Err(AttestationError::SubjectPolicyMismatch { field: "name" });
    }
    if policy
        .expected_media_type
        .as_ref()
        .is_some_and(|expected| expected != &subject.media_type)
    {
        return Err(AttestationError::SubjectPolicyMismatch {
            field: "media type",
        });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    max_chars: usize,
    field: &'static str,
) -> Result<(), AttestationError> {
    if value.is_empty() || value.chars().count() > max_chars || value.chars().any(char::is_control)
    {
        return Err(AttestationError::InvalidProfileField { field });
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), AttestationError> {
    validate_text(value, MAX_MEDIA_TYPE_BYTES, "media_type")?;
    let Some((top_level, subtype)) = value.split_once('/') else {
        return Err(AttestationError::InvalidProfileField {
            field: "media_type",
        });
    };
    if !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || top_level.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
    {
        return Err(AttestationError::InvalidProfileField {
            field: "media_type",
        });
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), AttestationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AttestationError::InvalidProfileField { field });
    }
    Ok(())
}

fn validate_receipt_core(
    receipt: &Value,
    execution_id: &str,
    tenant: &str,
) -> Result<(), AttestationError> {
    validate_json_limits(receipt)?;
    let Some(receipt) = receipt.as_object() else {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt",
        });
    };
    if receipt.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.version",
        });
    }
    if receipt.get("job_id").and_then(Value::as_str) != Some(execution_id) {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.job_id",
        });
    }
    if receipt
        .get("tenant")
        .is_some_and(|value| value.as_str() != Some(tenant))
    {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.tenant",
        });
    }
    if !matches!(
        receipt.get("outcome").and_then(Value::as_str),
        Some("succeeded" | "failed" | "timed_out" | "oom_killed" | "cancelled" | "error")
    ) {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.outcome",
        });
    }
    let receipt_sha256 = receipt
        .get("receipt_sha256")
        .and_then(Value::as_str)
        .ok_or(AttestationError::InvalidProfileField {
            field: "predicate.receipt.receipt_sha256",
        })?;
    validate_sha256(receipt_sha256, "predicate.receipt.receipt_sha256")?;

    let event_chain = receipt
        .get("event_chain")
        .and_then(Value::as_object)
        .ok_or(AttestationError::InvalidProfileField {
            field: "predicate.receipt.event_chain",
        })?;
    if event_chain.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.event_chain.version",
        });
    }
    if event_chain.get("events").and_then(Value::as_u64).is_none() {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.event_chain.events",
        });
    }
    if event_chain
        .get("complete")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.event_chain.complete",
        });
    }
    let head = event_chain.get("head").and_then(Value::as_str).ok_or(
        AttestationError::InvalidProfileField {
            field: "predicate.receipt.event_chain.head",
        },
    )?;
    validate_sha256(head, "predicate.receipt.event_chain.head")?;
    if canonical_receipt_sha256(&Value::Object(receipt.clone()))? != receipt_sha256 {
        return Err(AttestationError::InvalidProfileField {
            field: "predicate.receipt.receipt_sha256",
        });
    }
    Ok(())
}

fn validate_json_limits(root: &Value) -> Result<(), AttestationError> {
    let mut pending = vec![(root, 1_usize)];
    let mut scheduled_nodes = 1_usize;
    let mut estimated_bytes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_RECEIPT_JSON_DEPTH {
            return Err(AttestationError::InvalidProfileField {
                field: "predicate.receipt.depth",
            });
        }
        match value {
            Value::Array(values) => {
                estimated_bytes = estimated_bytes.saturating_add(2 + values.len());
                for value in values {
                    scheduled_nodes = scheduled_nodes.saturating_add(1);
                    if scheduled_nodes > MAX_RECEIPT_JSON_NODES {
                        return Err(receipt_too_complex());
                    }
                    pending.push((value, depth + 1));
                }
            }
            Value::Object(object) => {
                estimated_bytes = estimated_bytes.saturating_add(2 + object.len());
                for (key, value) in object {
                    estimated_bytes = estimated_bytes
                        .saturating_add(key.len().saturating_mul(6).saturating_add(3));
                    scheduled_nodes = scheduled_nodes.saturating_add(1);
                    if scheduled_nodes > MAX_RECEIPT_JSON_NODES {
                        return Err(receipt_too_complex());
                    }
                    pending.push((value, depth + 1));
                }
            }
            Value::String(value) => {
                estimated_bytes =
                    estimated_bytes.saturating_add(value.len().saturating_mul(6).saturating_add(2));
            }
            Value::Number(value) => {
                estimated_bytes = estimated_bytes.saturating_add(value.to_string().len());
            }
            Value::Bool(_) => estimated_bytes = estimated_bytes.saturating_add(5),
            Value::Null => estimated_bytes = estimated_bytes.saturating_add(4),
        }
        if estimated_bytes > MAX_RECEIPT_ESTIMATED_BYTES {
            return Err(receipt_too_complex());
        }
    }
    Ok(())
}

fn receipt_too_complex() -> AttestationError {
    AttestationError::ReceiptTooComplex {
        max_nodes: MAX_RECEIPT_JSON_NODES,
        max_bytes: MAX_RECEIPT_ESTIMATED_BYTES,
    }
}

fn canonical_receipt_sha256(receipt: &Value) -> Result<String, AttestationError> {
    let mut unsigned = receipt.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or(AttestationError::InvalidProfileField {
            field: "predicate.receipt",
        })?;
    object.remove("receipt_sha256");
    let mut canonical = String::new();
    write_canonical_json(&unsigned, &mut canonical)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_json).collect()),
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut normalized = serde_json::Map::new();
            for (key, value) in entries {
                normalized.insert(key, normalize_json(value));
            }
            Value::Object(normalized)
        }
        scalar => scalar,
    }
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), AttestationError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(&serde_json::to_string(value).map_err(|_| {
            AttestationError::JsonEncoding {
                document: "Rookhold receipt",
            }
        })?),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|_| {
                    AttestationError::JsonEncoding {
                        document: "Rookhold receipt",
                    }
                })?);
                output.push(':');
                write_canonical_json(&object[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn decode_dsse_base64(encoded: &str, field: &'static str) -> Result<Vec<u8>, AttestationError> {
    for engine in [&BASE64_STANDARD, &URL_SAFE] {
        if let Ok(decoded) = engine.decode(encoded) {
            return Ok(decoded);
        }
    }
    Err(AttestationError::InvalidBase64 { field })
}

/// Encode DSSE v1 pre-authentication encoding (PAE) for exact payload bytes.
///
/// This helper applies the Rookhold profile's payload and media-type limits. It
/// does not sign, parse, or canonicalize either input.
pub fn dsse_v1_pae(payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if payload_type.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(AttestationError::InvalidProfileField {
            field: "DSSE payloadType",
        });
    }
    if payload.len() > MAX_STATEMENT_BYTES {
        return Err(AttestationError::StatementTooLarge {
            max_bytes: MAX_STATEMENT_BYTES,
        });
    }
    let payload_type = payload_type.as_bytes();
    let payload_type_len = payload_type.len().to_string();
    let payload_len = payload.len().to_string();
    let capacity = 8_usize
        .saturating_add(payload_type_len.len())
        .saturating_add(payload_type.len())
        .saturating_add(payload_len.len())
        .saturating_add(payload.len());
    let mut pae = Vec::with_capacity(capacity);
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type_len.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type);
    pae.push(b' ');
    pae.extend_from_slice(payload_len.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    Ok(pae)
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(Sha256::digest(bytes).as_slice())
}

/// Lowercase hexadecimal encoding without relying on a `LowerHex` impl
/// for the digest output type (generic-array 1.x no longer provides one).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_hex_matches_nist_vector() {
        // SHA-256("abc") from FIPS 180-4; locks the encoding independently
        // of the digest crate version (generic-array 1.x dropped LowerHex).
        assert_eq!(
            bytes_to_hex(Sha256::digest(b"abc").as_slice()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            bytes_to_hex(Sha256::digest(b"abc").as_slice())
        );
    }

    #[test]
    fn dsse_pae_matches_v1_shape_and_is_unambiguous() {
        assert_eq!(
            dsse_v1_pae("text/plain", b"hello").unwrap(),
            b"DSSEv1 10 text/plain 5 hello"
        );
        assert_ne!(
            dsse_v1_pae("a", b"bc").unwrap(),
            dsse_v1_pae("ab", b"c").unwrap()
        );
    }

    #[test]
    fn artifact_reader_matches_in_memory_digest() {
        let bytes = b"a deterministic result artifact";
        assert_eq!(
            ArtifactDigest::from_reader(bytes.as_slice()).unwrap(),
            ArtifactDigest::from_bytes(bytes)
        );
    }

    #[test]
    fn coop_receipt_canonicalization_edge_vector_is_frozen() {
        let receipt = serde_json::json!({
            "receipt_sha256": "ignored",
            "z": [0, -1, 1.5, -0.0, 1e30],
            "é": "line\nquote\"slash\\snowman☃",
            "a": {"β": true, "alpha": null}
        });
        let actual = canonical_receipt_sha256(&receipt).unwrap();
        assert_eq!(
            actual,
            "b72615478bc37dd1335636bcfb4c75626560a075e011e6bb70eca96b51ae674c"
        );
    }
}
