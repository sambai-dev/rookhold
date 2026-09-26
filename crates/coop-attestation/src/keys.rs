use crate::error::AttestationError;
use crate::format::bytes_to_hex;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::LineEnding;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// Maximum accepted size of a PEM key file.
pub const MAX_KEY_FILE_BYTES: usize = 16 * 1024;

const PRIVATE_KEY_KIND: &str = "private";
const PUBLIC_KEY_KIND: &str = "public";
const PRIVATE_KEY_FORMAT: &str = "PKCS#8 Ed25519 PEM";
const PUBLIC_KEY_FORMAT: &str = "SubjectPublicKeyInfo Ed25519 PEM";

/// Generate an Ed25519 signing key using the operating system's CSPRNG.
pub fn generate_signing_key() -> Result<SigningKey, AttestationError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|_| AttestationError::RandomnessUnavailable)?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

/// Return the non-authoritative key ID used as a DSSE trial-order hint.
///
/// The identifier is `sha256:` followed by lowercase hexadecimal SHA-256 of
/// the 32-byte Ed25519 public key. Verifiers must still authenticate a
/// signature with a configured trusted key.
pub fn key_id(verifying_key: &VerifyingKey) -> String {
    format!(
        "sha256:{}",
        bytes_to_hex(Sha256::digest(verifying_key.as_bytes()).as_slice())
    )
}

/// Encode a private key using Rookhold's canonical unencrypted PKCS#8 PEM profile.
pub fn encode_private_key_pem(
    signing_key: &SigningKey,
) -> Result<Zeroizing<String>, AttestationError> {
    signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| AttestationError::InvalidKeyEncoding {
            kind: PRIVATE_KEY_KIND,
            format: PRIVATE_KEY_FORMAT,
        })
}

/// Parse a canonical unencrypted PKCS#8 Ed25519 PEM private key.
pub fn decode_private_key_pem(pem: &str) -> Result<SigningKey, AttestationError> {
    if pem.len() > MAX_KEY_FILE_BYTES {
        return Err(AttestationError::KeyFileTooLarge {
            kind: PRIVATE_KEY_KIND,
            max_bytes: MAX_KEY_FILE_BYTES,
        });
    }
    let signing_key =
        SigningKey::from_pkcs8_pem(pem).map_err(|_| AttestationError::InvalidKeyEncoding {
            kind: PRIVATE_KEY_KIND,
            format: PRIVATE_KEY_FORMAT,
        })?;
    let canonical = encode_private_key_pem(&signing_key)?;
    if canonical.as_str() != pem {
        return Err(AttestationError::InvalidKeyEncoding {
            kind: PRIVATE_KEY_KIND,
            format: PRIVATE_KEY_FORMAT,
        });
    }
    Ok(signing_key)
}

/// Encode a public key using Rookhold's canonical SubjectPublicKeyInfo PEM profile.
pub fn encode_public_key_pem(verifying_key: &VerifyingKey) -> Result<String, AttestationError> {
    verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| AttestationError::InvalidKeyEncoding {
            kind: PUBLIC_KEY_KIND,
            format: PUBLIC_KEY_FORMAT,
        })
}

/// Parse a canonical SubjectPublicKeyInfo Ed25519 PEM public key.
pub fn decode_public_key_pem(pem: &str) -> Result<VerifyingKey, AttestationError> {
    if pem.len() > MAX_KEY_FILE_BYTES {
        return Err(AttestationError::KeyFileTooLarge {
            kind: PUBLIC_KEY_KIND,
            max_bytes: MAX_KEY_FILE_BYTES,
        });
    }
    let verifying_key = VerifyingKey::from_public_key_pem(pem).map_err(|_| {
        AttestationError::InvalidKeyEncoding {
            kind: PUBLIC_KEY_KIND,
            format: PUBLIC_KEY_FORMAT,
        }
    })?;
    let canonical = encode_public_key_pem(&verifying_key)?;
    if canonical != pem {
        return Err(AttestationError::InvalidKeyEncoding {
            kind: PUBLIC_KEY_KIND,
            format: PUBLIC_KEY_FORMAT,
        });
    }
    Ok(verifying_key)
}

/// Create a new mode-0600 private-key file without ever overwriting a path.
pub fn write_private_key_file_new(
    path: impl AsRef<Path>,
    signing_key: &SigningKey,
) -> Result<(), AttestationError> {
    let pem = encode_private_key_pem(signing_key)?;
    write_key_file_new(path.as_ref(), pem.as_bytes(), true)
}

/// Create a new mode-0644 public-key file without ever overwriting a path.
pub fn write_public_key_file_new(
    path: impl AsRef<Path>,
    verifying_key: &VerifyingKey,
) -> Result<(), AttestationError> {
    let pem = encode_public_key_pem(verifying_key)?;
    write_key_file_new(path.as_ref(), pem.as_bytes(), false)
}

/// Read a private key through a non-symlink regular file and enforce safe Unix modes.
pub fn read_private_key_file(path: impl AsRef<Path>) -> Result<SigningKey, AttestationError> {
    let bytes = Zeroizing::new(read_key_file(path.as_ref(), true)?);
    let pem = std::str::from_utf8(&bytes).map_err(|_| AttestationError::InvalidKeyEncoding {
        kind: PRIVATE_KEY_KIND,
        format: PRIVATE_KEY_FORMAT,
    })?;
    decode_private_key_pem(pem)
}

/// Read a public key through a non-symlink regular file and enforce safe Unix modes.
pub fn read_public_key_file(path: impl AsRef<Path>) -> Result<VerifyingKey, AttestationError> {
    let bytes = read_key_file(path.as_ref(), false)?;
    let pem = std::str::from_utf8(&bytes).map_err(|_| AttestationError::InvalidKeyEncoding {
        kind: PUBLIC_KEY_KIND,
        format: PUBLIC_KEY_FORMAT,
    })?;
    decode_public_key_pem(pem)
}

fn write_key_file_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), AttestationError> {
    #[cfg(unix)]
    let resolved_path = resolve_key_path(
        path,
        if private {
            PRIVATE_KEY_KIND
        } else {
            PUBLIC_KEY_KIND
        },
    )?;
    #[cfg(unix)]
    let path = resolved_path.as_path();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(if private { 0o600 } else { 0o644 });
    #[cfg(not(unix))]
    let _ = private;

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AttestationError::KeyFileAlreadyExists)
        }
        Err(error) => return Err(AttestationError::Io(error)),
    };
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(if private {
        0o600
    } else {
        0o644
    }))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_key_file(path: &Path, private: bool) -> Result<Vec<u8>, AttestationError> {
    let kind = if private {
        PRIVATE_KEY_KIND
    } else {
        PUBLIC_KEY_KIND
    };

    #[cfg(unix)]
    let resolved_path = resolve_key_path(path, kind)?;
    #[cfg(unix)]
    let path = resolved_path.as_path();

    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(AttestationError::UnsafeKeyFileType { kind });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);

    let mut file = match options.open(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(AttestationError::UnsafeKeyFileType { kind })
        }
        Err(error) => return Err(AttestationError::Io(error)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AttestationError::UnsafeKeyFileType { kind });
    }
    if metadata.len() > MAX_KEY_FILE_BYTES as u64 {
        return Err(AttestationError::KeyFileTooLarge {
            kind,
            max_bytes: MAX_KEY_FILE_BYTES,
        });
    }

    #[cfg(unix)]
    {
        let mode = metadata.mode();
        let effective_uid = rustix::process::geteuid().as_raw();
        let owner_is_safe = if private {
            metadata.uid() == effective_uid
        } else {
            metadata.uid() == effective_uid || metadata.uid() == 0
        };
        if !owner_is_safe {
            return Err(AttestationError::UnsafeKeyFileOwner { kind });
        }
        let unsafe_bits = if private {
            // Private material may be owner-readable/writable only and never executable.
            mode & 0o7177
        } else {
            // Trusted public keys may be world-readable but not group/other-writable or executable.
            mode & (0o7000 | 0o022 | 0o111)
        };
        if unsafe_bits != 0 {
            return Err(AttestationError::UnsafeKeyFilePermissions { kind });
        }
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_KEY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(AttestationError::KeyFileTooLarge {
            kind,
            max_bytes: MAX_KEY_FILE_BYTES,
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn resolve_key_path(
    path: &Path,
    kind: &'static str,
) -> Result<std::path::PathBuf, AttestationError> {
    let file_name = path
        .file_name()
        .ok_or(AttestationError::UnsafeKeyFileType { kind })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let original_parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    validate_original_parent_path(&original_parent, kind)?;
    // Resolve platform-owned aliases such as macOS /tmp -> /private/tmp once,
    // then perform the final O_NOFOLLOW open through that canonical parent.
    // Later mutation of the original alias cannot redirect the actual open.
    let canonical_parent = std::fs::canonicalize(&original_parent)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let mut current = Some(canonical_parent.as_path());
    while let Some(directory) = current {
        let metadata = std::fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AttestationError::UnsafeKeyFileType { kind });
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(AttestationError::UnsafeKeyFileOwner { kind });
        }
        let mode = metadata.mode();
        let externally_writable = mode & 0o022 != 0;
        let root_owned_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if externally_writable && !root_owned_sticky_directory {
            return Err(AttestationError::UnsafeKeyFilePermissions { kind });
        }
        current = directory.parent();
    }
    Ok(canonical_parent.join(file_name))
}

#[cfg(unix)]
fn validate_original_parent_path(
    parent: &Path,
    kind: &'static str,
) -> Result<(), AttestationError> {
    use std::path::Component;

    let effective_uid = rustix::process::geteuid().as_raw();
    let mut current = std::path::PathBuf::new();
    for component in parent.components() {
        if matches!(component, Component::ParentDir) {
            return Err(AttestationError::UnsafeKeyFileType { kind });
        }
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            if metadata.uid() != 0 {
                return Err(AttestationError::UnsafeKeyFileOwner { kind });
            }
            continue;
        }
        if !metadata.is_dir() {
            return Err(AttestationError::UnsafeKeyFileType { kind });
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(AttestationError::UnsafeKeyFileOwner { kind });
        }
        let mode = metadata.mode();
        let externally_writable = mode & 0o022 != 0;
        let root_owned_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if externally_writable && !root_owned_sticky_directory {
            return Err(AttestationError::UnsafeKeyFilePermissions { kind });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    #[test]
    fn canonical_key_round_trip_and_id_are_stable() {
        let signing_key = test_key();
        let private = encode_private_key_pem(&signing_key).unwrap();
        let public = encode_public_key_pem(&signing_key.verifying_key()).unwrap();
        assert_eq!(
            decode_private_key_pem(&private).unwrap().to_bytes(),
            signing_key.to_bytes()
        );
        assert_eq!(
            decode_public_key_pem(&public).unwrap(),
            signing_key.verifying_key()
        );
        assert_eq!(key_id(&signing_key.verifying_key()).len(), 71);
    }

    #[test]
    fn strict_pem_profile_rejects_cosmetic_variants() {
        let signing_key = test_key();
        let private = encode_private_key_pem(&signing_key).unwrap();
        let public = encode_public_key_pem(&signing_key.verifying_key()).unwrap();
        assert!(decode_private_key_pem(&private.replace('\n', "\r\n")).is_err());
        assert!(decode_private_key_pem(&format!("\n{}", private.as_str())).is_err());
        assert!(decode_public_key_pem(&public.replace('\n', "\r\n")).is_err());
        assert!(decode_public_key_pem(&format!("{public}\n")).is_err());
        assert!(decode_private_key_pem(&public).is_err());
        assert!(decode_public_key_pem(&private).is_err());
        assert!(decode_public_key_pem(&public.replace("MCowBQYDK2Vw", "MCowBQYDK2Vx")).is_err());
        let oversized = "x".repeat(MAX_KEY_FILE_BYTES + 1);
        assert!(matches!(
            decode_private_key_pem(&oversized),
            Err(AttestationError::KeyFileTooLarge { .. })
        ));
        assert!(matches!(
            decode_public_key_pem(&oversized),
            Err(AttestationError::KeyFileTooLarge { .. })
        ));
    }
}
