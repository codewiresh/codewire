use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssh_key::private::Ed25519Keypair;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use thiserror::Error;

/// The gateway's host-key path. Deleted with the gateway.
pub const DEFAULT_HOST_KEY_PATH: &str = "/codewire/gateway/ssh/host_ed25519";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeySource {
    ExistingOpenSsh,
    GeneratedOpenSsh,
}

pub struct HostKey {
    pub key: PrivateKey,
    pub source: HostKeySource,
}

#[derive(Debug, Error)]
pub enum HostKeyError {
    #[error("read gateway host key: {0}")]
    Read(#[source] io::Error),
    #[error("create gateway host key directory: {0}")]
    CreateDir(#[source] io::Error),
    #[error("write gateway host key: {0}")]
    Write(#[source] io::Error),
    #[error("rename gateway host key: {0}")]
    Rename(#[source] io::Error),
    #[error("encode OpenSSH gateway host key: {0}")]
    EncodeOpenSsh(#[source] ssh_key::Error),
    #[error("parse OpenSSH gateway host key: {0}")]
    ParseOpenSsh(#[source] ssh_key::Error),
    #[error("gateway host key must be Ed25519, got {0:?}")]
    UnsupportedAlgorithm(Algorithm),
}

pub fn load_or_create(path: impl AsRef<Path>) -> Result<HostKey, HostKeyError> {
    let path = normalize_path(path.as_ref());
    match fs::read(&path) {
        Ok(bytes) => load_existing(&bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let key = generate_ed25519_key();
            write_open_ssh_key(&path, &key)?;
            Ok(HostKey {
                key,
                source: HostKeySource::GeneratedOpenSsh,
            })
        }
        Err(err) => Err(HostKeyError::Read(err)),
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    if path.as_os_str().is_empty() {
        PathBuf::from(DEFAULT_HOST_KEY_PATH)
    } else {
        path.to_path_buf()
    }
}

fn load_existing(bytes: &[u8]) -> Result<HostKey, HostKeyError> {
    let key = parse_open_ssh(bytes).map_err(HostKeyError::ParseOpenSsh)?;
    validate_ed25519(&key)?;
    Ok(HostKey {
        key,
        source: HostKeySource::ExistingOpenSsh,
    })
}

fn parse_open_ssh(bytes: &[u8]) -> Result<PrivateKey, ssh_key::Error> {
    PrivateKey::from_openssh(bytes)
}

pub fn generate_ed25519_key() -> PrivateKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    signing_key_to_ssh_key(signing_key)
}

fn signing_key_to_ssh_key(signing_key: SigningKey) -> PrivateKey {
    let seed = signing_key.to_bytes();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

fn validate_ed25519(key: &PrivateKey) -> Result<(), HostKeyError> {
    if key.algorithm() == Algorithm::Ed25519 {
        Ok(())
    } else {
        Err(HostKeyError::UnsupportedAlgorithm(key.algorithm()))
    }
}

fn write_open_ssh_key(path: &Path, key: &PrivateKey) -> Result<(), HostKeyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(HostKeyError::CreateDir)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(HostKeyError::CreateDir)?;

    let encoded = key
        .to_openssh(LineEnding::LF)
        .map_err(HostKeyError::EncodeOpenSsh)?;
    let tmp_path = temporary_path(path);
    fs::write(&tmp_path, encoded.as_bytes()).map_err(HostKeyError::Write)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .map_err(HostKeyError::Write)?;
    fs::rename(&tmp_path, path).map_err(HostKeyError::Rename)?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("host_ed25519");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_persists_as_openssh() {
        let dir = std::env::temp_dir().join(format!(
            "codewire-gateway-host-key-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("host_ed25519");

        let first = load_or_create(&path).unwrap();
        assert_eq!(first.source, HostKeySource::GeneratedOpenSsh);
        let first_public = first.key.public_key().to_openssh().unwrap();
        let bytes = fs::read_to_string(&path).unwrap();
        assert!(bytes.contains("BEGIN OPENSSH PRIVATE KEY"));

        let second = load_or_create(&path).unwrap();
        assert_eq!(second.source, HostKeySource::ExistingOpenSsh);
        assert_eq!(second.key.public_key().to_openssh().unwrap(), first_public);
    }

    #[test]
    fn pkcs8_key_is_rejected_without_rewriting() {
        let dir = std::env::temp_dir().join(format!(
            "codewire-gateway-pkcs8-host-key-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("host_ed25519");
        let pkcs8 = [
            b"-----BEGIN ".as_slice(),
            b"PRIVATE KEY-----\n",
            b"MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n",
            b"-----END ",
            b"PRIVATE KEY-----\n",
        ]
        .concat();
        fs::write(&path, &pkcs8).unwrap();

        assert!(matches!(
            load_or_create(&path),
            Err(HostKeyError::ParseOpenSsh(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), pkcs8);
    }
}
