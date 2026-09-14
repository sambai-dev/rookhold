use clap::{Parser, Subcommand};
use coop_attestation::{
    generate_signing_key, key_id, read_private_key_file, read_public_key_file, verify_attestation,
    write_private_key_file_new, write_public_key_file_new, ArtifactDigest, AttestationError,
    VerificationPolicy, MAX_ENVELOPE_BYTES,
};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

// Keep this in lockstep with coop_store::MAX_RESULT_ARTIFACT_BYTES so every
// exact artifact the server can persist remains verifiable by the release CLI.
const MAX_SUBJECT_FILE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Generate Rookhold attestation keys and verify portable execution attestations"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new canonical unencrypted PKCS#8 Ed25519 private key.
    GenerateKey {
        /// New private-key path. The command refuses to overwrite it.
        #[arg(long)]
        output: PathBuf,
    },
    /// Derive a canonical SubjectPublicKeyInfo PEM public key.
    PublicKey {
        /// Existing mode-safe canonical private-key path.
        #[arg(long)]
        private_key: PathBuf,
        /// New public-key path. The command refuses to overwrite it.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify signatures, profile/schema constraints, and result-artifact SHA-256.
    Verify {
        /// JSON DSSE envelope to verify.
        #[arg(long)]
        envelope: PathBuf,
        /// Exact immutable result artifact named by the in-toto subject.
        #[arg(long)]
        subject: PathBuf,
        /// Trusted canonical Ed25519 public-key PEM. Repeat for key rotation/thresholds.
        #[arg(long = "public-key", required = true)]
        public_keys: Vec<PathBuf>,
        /// Distinct trusted-key signatures required.
        #[arg(long, default_value = "1")]
        threshold: NonZeroUsize,
        /// Optional policy assertion for the authenticated execution tenant.
        #[arg(long)]
        tenant: Option<String>,
        /// Optional policy assertion for the authenticated subject name.
        #[arg(long)]
        subject_name: Option<String>,
        /// Optional policy assertion for the authenticated result media type.
        #[arg(long)]
        media_type: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct KeyOperationOutput<'a> {
    key_id: &'a str,
}

#[derive(Debug, Serialize)]
struct VerifyOutput<'a> {
    verified: bool,
    execution_id: &'a str,
    tenant: &'a str,
    subject_name: &'a str,
    subject_media_type: &'a str,
    subject_sha256: &'a str,
    subject_size_bytes: u64,
    outcome: &'a str,
    event_chain_complete: bool,
    verified_key_ids: &'a [String],
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}: {error}", env!("CARGO_BIN_NAME"));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), AttestationError> {
    match cli.command {
        Command::GenerateKey { output } => {
            let signing_key = generate_signing_key()?;
            write_private_key_file_new(output, &signing_key)?;
            let id = key_id(&signing_key.verifying_key());
            write_json(&KeyOperationOutput { key_id: &id })?;
        }
        Command::PublicKey {
            private_key,
            output,
        } => {
            let signing_key = read_private_key_file(private_key)?;
            let verifying_key = signing_key.verifying_key();
            write_public_key_file_new(output, &verifying_key)?;
            let id = key_id(&verifying_key);
            write_json(&KeyOperationOutput { key_id: &id })?;
        }
        Command::Verify {
            envelope,
            subject,
            public_keys,
            threshold,
            tenant,
            subject_name,
            media_type,
        } => {
            let mut policy = VerificationPolicy::default().with_minimum_signatures(threshold);
            if let Some(tenant) = tenant {
                policy = policy.with_tenant(tenant);
            }
            if let Some(name) = subject_name {
                policy = policy.with_subject_name(name);
            }
            if let Some(media_type) = media_type {
                policy = policy.with_media_type(media_type);
            }

            let envelope = read_limited_regular_file(&envelope, MAX_ENVELOPE_BYTES, true)?;
            let subject = read_limited_regular_file(&subject, MAX_SUBJECT_FILE_BYTES, false)?;
            let artifact = ArtifactDigest::from_bytes(&subject);
            let trusted_keys = public_keys
                .iter()
                .map(read_public_key_file)
                .collect::<Result<Vec<_>, _>>()?;
            let verified = verify_attestation(&envelope, &artifact, &trusted_keys, &policy)?;
            let statement = verified.statement();
            let result = statement.predicate().result();
            let receipt = statement.predicate().receipt();
            let outcome = receipt
                .get("outcome")
                .and_then(serde_json::Value::as_str)
                .ok_or(AttestationError::InvalidProfileField {
                    field: "predicate.receipt.outcome",
                })?;
            let event_chain_complete = receipt
                .get("event_chain")
                .and_then(serde_json::Value::as_object)
                .and_then(|chain| chain.get("complete"))
                .and_then(serde_json::Value::as_bool)
                .ok_or(AttestationError::InvalidProfileField {
                    field: "predicate.receipt.event_chain.complete",
                })?;
            write_json(&VerifyOutput {
                verified: true,
                execution_id: statement.predicate().execution_id(),
                tenant: statement.predicate().tenant(),
                subject_name: verified.subject().name(),
                subject_media_type: verified.subject().media_type(),
                subject_sha256: verified.subject_sha256(),
                subject_size_bytes: result.size_bytes(),
                outcome,
                event_chain_complete,
                verified_key_ids: verified.verified_key_ids(),
            })?;
        }
    }
    Ok(())
}

fn read_limited_regular_file(
    path: &std::path::Path,
    max_bytes: usize,
    envelope: bool,
) -> Result<Vec<u8>, AttestationError> {
    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AttestationError::UnsafeInputFileType);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AttestationError::UnsafeInputFileType);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(input_too_large(envelope, max_bytes));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(input_too_large(envelope, max_bytes));
    }
    Ok(bytes)
}

fn input_too_large(envelope: bool, max_bytes: usize) -> AttestationError {
    if envelope {
        AttestationError::EnvelopeTooLarge { max_bytes }
    } else {
        AttestationError::SubjectArtifactTooLarge { max_bytes }
    }
}

fn write_json(value: &impl Serialize) -> Result<(), AttestationError> {
    let encoded = serde_json::to_vec(value).map_err(|_| AttestationError::JsonEncoding {
        document: "CLI output",
    })?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(&encoded)?;
    locked.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_reader_accepts_server_limit_and_rejects_one_byte_more() {
        let temporary = tempfile::tempdir().unwrap();
        let subject = temporary.path().join("result-artifact.json");
        let file = std::fs::File::create(&subject).unwrap();
        file.set_len(MAX_SUBJECT_FILE_BYTES as u64).unwrap();
        drop(file);

        let accepted = read_limited_regular_file(&subject, MAX_SUBJECT_FILE_BYTES, false).unwrap();
        assert_eq!(accepted.len(), MAX_SUBJECT_FILE_BYTES);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&subject)
            .unwrap();
        file.set_len(MAX_SUBJECT_FILE_BYTES as u64 + 1).unwrap();
        drop(file);
        assert!(matches!(
            read_limited_regular_file(&subject, MAX_SUBJECT_FILE_BYTES, false),
            Err(AttestationError::SubjectArtifactTooLarge { max_bytes })
                if max_bytes == MAX_SUBJECT_FILE_BYTES
        ));
    }
}
