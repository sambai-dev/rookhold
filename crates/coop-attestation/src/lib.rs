//! Portable, exact-byte signed execution attestations for Rookhold.
//!
//! The crate defines a deliberately narrow profile:
//!
//! - one in-toto [`StatementV1`] subject, identified by SHA-256;
//! - one tenant-bound [`CoopExecutionPredicateV1`] containing a Rookhold receipt;
//! - JSON DSSE with v1 pre-authentication encoding (PAE);
//! - strict Ed25519 signing and verification against configured public keys;
//! - signature verification before statement JSON parsing.
//!
//! DSSE `keyid` strings are unauthenticated hints. This crate never treats a
//! matching ID as trust: a configured public key must verify the signature.

#![forbid(unsafe_code)]

mod error;
mod format;
mod keys;
mod strict_json;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::AttestationError;
pub use format::{
    build_statement, build_statement_from_receipt_json, bytes_to_hex, create_attestation,
    dsse_v1_pae, encode_statement, sign_statement, verify_attestation, ArtifactDigest,
    CoopExecutionPredicateV1, CoopResultDescriptorV1, DsseEnvelope, DsseSignature,
    ResourceDescriptor, StatementV1, SubjectArtifact, VerificationPolicy, VerifiedAttestation,
    COOP_EXECUTION_PREDICATE_TYPE, COOP_EXECUTION_SCHEMA_VERSION, DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE, MAX_ENVELOPE_BYTES, MAX_SIGNATURES, MAX_STATEMENT_BYTES,
    MAX_TRUSTED_KEYS,
};
pub use keys::{
    decode_private_key_pem, decode_public_key_pem, encode_private_key_pem, encode_public_key_pem,
    generate_signing_key, key_id, read_private_key_file, read_public_key_file,
    write_private_key_file_new, write_public_key_file_new, MAX_KEY_FILE_BYTES,
};
