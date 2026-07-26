//! Authenticated envelopes for persisted OIDC Ed25519 signing seeds.
//!
//! Version 1 encrypts only the 32-byte seed. The public key remains in the
//! public JWK and is bound, together with the row `kid`, into the AEAD AAD.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::RngCore;

/// Current database envelope format.
pub const FORMAT_V1: i16 = 1;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const AAD_DOMAIN_V1: &[u8] = b"codewire/idp/ed25519-seed-envelope/v1\0";
// Linux O_NOFOLLOW. The idp deploys only on Linux, and `/proc/self/fd` below
// is the descriptor-relative boundary that prevents atomic-writer path swaps.
const O_NOFOLLOW: i32 = 0o400000;

/// A value-blind error. Its display form is deliberately restricted to the
/// failure class and non-secret row/envelope identifiers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EnvelopeError {
    class: &'static str,
    kid: Option<String>,
    kek_id: Option<String>,
    format: Option<i16>,
}

impl EnvelopeError {
    fn keyring(class: &'static str, kek_id: Option<&str>) -> Self {
        Self {
            class,
            kid: None,
            kek_id: kek_id.map(str::to_owned),
            format: None,
        }
    }

    pub(crate) fn envelope(class: &'static str, kid: &str, kek_id: &str, format: i16) -> Self {
        Self {
            class,
            kid: Some(kid.to_owned()),
            kek_id: Some(kek_id.to_owned()),
            format: Some(format),
        }
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jwk-envelope failure_class={}", self.class)?;
        if let Some(kid) = &self.kid {
            write!(f, " kid={kid:?}")?;
        }
        if let Some(kek_id) = &self.kek_id {
            write!(f, " kek_id={kek_id:?}")?;
        }
        if let Some(format) = self.format {
            write!(f, " format={format}")?;
        }
        Ok(())
    }
}

impl std::error::Error for EnvelopeError {}

/// The complete persisted representation of one encrypted signing seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwkEnvelope {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kek_id: String,
    pub format: i16,
}

/// A versioned, in-memory KEK keyring loaded from the idp-only Secret mount.
#[derive(Clone)]
pub struct SigningKekKeyring {
    active_id: String,
    keys: Arc<HashMap<String, [u8; 32]>>,
}

impl SigningKekKeyring {
    /// Load the keyring selected by `IDP_SIGNING_KEK_DIR` and
    /// `IDP_SIGNING_ACTIVE_KEK_ID`.
    pub fn from_env() -> Result<Self, EnvelopeError> {
        let dir = std::env::var("IDP_SIGNING_KEK_DIR")
            .map_err(|_| EnvelopeError::keyring("missing-keyring-directory", None))?;
        let active_id = std::env::var("IDP_SIGNING_ACTIVE_KEK_ID")
            .map_err(|_| EnvelopeError::keyring("missing-active-kek-id", None))?;
        Self::load(Path::new(&dir), &active_id)
    }

    /// Strictly load all versioned KEK files from a Kubernetes-compatible
    /// directory. Kubernetes's dot-prefixed atomic-writer entries are ignored;
    /// every other entry must be a canonical `vN` key file.
    pub fn load(dir: &Path, active_id: &str) -> Result<Self, EnvelopeError> {
        if !valid_kek_id(active_id) {
            return Err(EnvelopeError::keyring(
                "invalid-active-kek-id",
                Some(active_id),
            ));
        }

        let canonical_dir = fs::canonicalize(dir)
            .map_err(|_| EnvelopeError::keyring("keyring-directory-unreadable", None))?;
        let dir_metadata = fs::metadata(&canonical_dir)
            .map_err(|_| EnvelopeError::keyring("keyring-directory-metadata", None))?;
        if !dir_metadata.is_dir() {
            return Err(EnvelopeError::keyring("keyring-directory-mode", None));
        }
        let atomic_data_dir = atomic_writer_data_dir(&canonical_dir, &dir_metadata)?;

        let entries = fs::read_dir(&canonical_dir)
            .map_err(|_| EnvelopeError::keyring("keyring-directory-unreadable", None))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| EnvelopeError::keyring("keyring-entry-read", None))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| EnvelopeError::keyring("invalid-kek-id", None))?;
            if name.starts_with('.') {
                continue;
            }
            if !valid_kek_id(&name) {
                return Err(EnvelopeError::keyring("invalid-kek-id", Some(&name)));
            }
            names.push(name);
        }
        names.sort();

        let mut keys = HashMap::new();
        for kek_id in names {
            let path = canonical_dir.join(&kek_id);
            let mut file = if let Some(data_dir) = &atomic_data_dir {
                let link_metadata = fs::symlink_metadata(&path)
                    .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(&kek_id)))?;
                let expected_target = Path::new("..data").join(&kek_id);
                if !link_metadata.file_type().is_symlink()
                    || link_metadata.uid() != dir_metadata.uid()
                    || fs::read_link(&path).ok().as_deref() != Some(expected_target.as_path())
                {
                    return Err(EnvelopeError::keyring(
                        "key-file-atomic-link",
                        Some(&kek_id),
                    ));
                }
                data_dir.open_key(&kek_id, &dir_metadata)?
            } else {
                let canonical_file = fs::canonicalize(&path)
                    .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(&kek_id)))?;
                if !canonical_file.starts_with(&canonical_dir) {
                    return Err(EnvelopeError::keyring(
                        "key-file-outside-keyring",
                        Some(&kek_id),
                    ));
                }
                File::open(&canonical_file)
                    .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(&kek_id)))?
            };
            let metadata = file
                .metadata()
                .map_err(|_| EnvelopeError::keyring("key-file-metadata", Some(&kek_id)))?;
            if !metadata.is_file()
                || metadata.uid() != dir_metadata.uid()
                || metadata.mode() & 0o400 == 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(EnvelopeError::keyring("key-file-mode", Some(&kek_id)));
            }

            let mut encoded = Vec::new();
            file.read_to_end(&mut encoded)
                .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(&kek_id)))?;
            let key = decode_lower_hex_key(&encoded)
                .ok_or_else(|| EnvelopeError::keyring("key-file-format", Some(&kek_id)))?;
            keys.insert(kek_id, key);
        }

        if !keys.contains_key(active_id) {
            return Err(EnvelopeError::keyring(
                "active-kek-not-found",
                Some(active_id),
            ));
        }
        Ok(Self {
            active_id: active_id.to_owned(),
            keys: Arc::new(keys),
        })
    }

    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    /// Encrypt a seed under the active KEK with a fresh 96-bit nonce.
    pub fn encrypt(
        &self,
        kid: &str,
        public_key: &[u8],
        seed: &[u8],
    ) -> Result<JwkEnvelope, EnvelopeError> {
        let format = FORMAT_V1;
        let error = |class| Self::row_error(class, kid, self.active_id(), format);
        let public: [u8; SEED_LEN] = public_key
            .try_into()
            .map_err(|_| error("invalid-public-key-length"))?;
        let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| error("invalid-seed-length"))?;
        if Ed25519SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            != public
        {
            return Err(error("derived-public-mismatch"));
        }
        let key = self
            .keys
            .get(self.active_id())
            .ok_or_else(|| error("active-kek-not-found"))?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| error("invalid-kek-length"))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = aad_v1(kid, &public);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &seed,
                    aad: &aad,
                },
            )
            .map_err(|_| error("encryption-failed"))?;
        Ok(JwkEnvelope {
            ciphertext,
            nonce: nonce.to_vec(),
            kek_id: self.active_id.clone(),
            format,
        })
    }

    /// Decrypt and authenticate an envelope, then derive and compare the
    /// Ed25519 public key before returning the seed.
    pub fn decrypt(
        &self,
        kid: &str,
        public_key: &[u8],
        envelope: &JwkEnvelope,
    ) -> Result<[u8; 32], EnvelopeError> {
        let error = |class| Self::row_error(class, kid, &envelope.kek_id, envelope.format);
        if envelope.format != FORMAT_V1 {
            return Err(error("unknown-envelope-format"));
        }
        let public: [u8; SEED_LEN] = public_key
            .try_into()
            .map_err(|_| error("invalid-public-key-length"))?;
        let nonce: [u8; NONCE_LEN] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| error("invalid-nonce-length"))?;
        if envelope.ciphertext.len() != SEED_LEN + 16 {
            return Err(error("invalid-ciphertext-length"));
        }
        let key = self
            .keys
            .get(&envelope.kek_id)
            .ok_or_else(|| error("unknown-kek-id"))?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| error("invalid-kek-length"))?;
        let aad = aad_v1(kid, &public);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| error("authentication-failed"))?;
        let seed: [u8; SEED_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| error("invalid-plaintext-length"))?;
        if Ed25519SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            != public
        {
            return Err(error("derived-public-mismatch"));
        }
        Ok(seed)
    }

    fn row_error(class: &'static str, kid: &str, kek_id: &str, format: i16) -> EnvelopeError {
        EnvelopeError::envelope(class, kid, kek_id, format)
    }
}

struct AtomicWriterDataDir {
    // Keep the selected immutable revision open and resolve every key through
    // that descriptor. Neither a kubelet `..data` swap nor replacement of the
    // selected revision pathname can redirect a key read.
    handle: File,
    dev: u64,
    ino: u64,
}

impl AtomicWriterDataDir {
    fn open_key(&self, kek_id: &str, root_metadata: &fs::Metadata) -> Result<File, EnvelopeError> {
        self.validate_opened_directory(root_metadata)?;

        // Opening below `/proc/self/fd/<dirfd>` is descriptor-relative on
        // Linux. O_NOFOLLOW also rejects a final-component symlink even if it
        // appears between the metadata check and open.
        let path = Path::new("/proc/self/fd")
            .join(self.handle.as_raw_fd().to_string())
            .join(kek_id);
        let path_metadata = fs::symlink_metadata(&path)
            .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(kek_id)))?;
        if !path_metadata.file_type().is_file()
            || path_metadata.uid() != root_metadata.uid()
            || path_metadata.mode() & 0o400 == 0
            || path_metadata.mode() & 0o022 != 0
        {
            return Err(EnvelopeError::keyring(
                "key-file-atomic-target",
                Some(kek_id),
            ));
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
            .map_err(|_| EnvelopeError::keyring("key-file-unreadable", Some(kek_id)))?;
        let opened_metadata = file
            .metadata()
            .map_err(|_| EnvelopeError::keyring("key-file-metadata", Some(kek_id)))?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
        {
            return Err(EnvelopeError::keyring(
                "key-file-atomic-target",
                Some(kek_id),
            ));
        }
        self.validate_opened_directory(root_metadata)?;
        Ok(file)
    }

    fn validate_opened_directory(&self, root_metadata: &fs::Metadata) -> Result<(), EnvelopeError> {
        let metadata = self
            .handle
            .metadata()
            .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
        if !metadata.is_dir()
            || metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || metadata.uid() != root_metadata.uid()
            || metadata.mode() & 0o022 != 0
        {
            return Err(EnvelopeError::keyring("keyring-directory-mode", None));
        }
        Ok(())
    }
}

/// Kubernetes's atomic writer deliberately exposes a sticky `01777` mount
/// root. Accept that otherwise-writable mode only when the root has the exact
/// same-owner `..data` indirection to one confined, non-writable revision
/// directory. Conventional keyring directories retain the stricter mode
/// requirement.
fn atomic_writer_data_dir(
    canonical_dir: &Path,
    dir_metadata: &fs::Metadata,
) -> Result<Option<AtomicWriterDataDir>, EnvelopeError> {
    if dir_metadata.mode() & 0o022 == 0 {
        return Ok(None);
    }
    if dir_metadata.mode() & 0o7777 != 0o1777 {
        return Err(EnvelopeError::keyring("keyring-directory-mode", None));
    }

    let data_link = canonical_dir.join("..data");
    let link_metadata = fs::symlink_metadata(&data_link)
        .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
    if !link_metadata.file_type().is_symlink() || link_metadata.uid() != dir_metadata.uid() {
        return Err(EnvelopeError::keyring("keyring-directory-mode", None));
    }

    let relative_target = fs::read_link(&data_link)
        .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
    let target_name = relative_target.to_str().unwrap_or_default();
    if relative_target.is_absolute()
        || relative_target.components().count() != 1
        || !target_name.starts_with("..")
        || target_name == "..data"
    {
        return Err(EnvelopeError::keyring("keyring-directory-mode", None));
    }

    let data_dir = canonical_dir.join(relative_target);
    let data_metadata = fs::symlink_metadata(&data_dir)
        .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
    if !data_metadata.file_type().is_dir()
        || data_metadata.uid() != dir_metadata.uid()
        || data_metadata.mode() & 0o022 != 0
    {
        return Err(EnvelopeError::keyring("keyring-directory-mode", None));
    }

    let handle = File::open(&data_dir)
        .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
    let opened_metadata = handle
        .metadata()
        .map_err(|_| EnvelopeError::keyring("keyring-directory-mode", None))?;
    if !opened_metadata.is_dir()
        || opened_metadata.dev() != data_metadata.dev()
        || opened_metadata.ino() != data_metadata.ino()
        || opened_metadata.uid() != dir_metadata.uid()
        || opened_metadata.mode() & 0o022 != 0
    {
        return Err(EnvelopeError::keyring("keyring-directory-mode", None));
    }

    Ok(Some(AtomicWriterDataDir {
        handle,
        dev: opened_metadata.dev(),
        ino: opened_metadata.ino(),
    }))
}

fn valid_kek_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && bytes[0] == b'v'
        && matches!(bytes[1], b'1'..=b'9')
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn decode_lower_hex_key(encoded: &[u8]) -> Option<[u8; 32]> {
    if encoded.len() != 64
        || !encoded
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(key)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn aad_v1(kid: &str, public_key: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN_V1.len() + 8 + kid.len() + public_key.len());
    aad.extend_from_slice(AAD_DOMAIN_V1);
    aad.extend_from_slice(&(kid.len() as u64).to_be_bytes());
    aad.extend_from_slice(kid.as_bytes());
    aad.extend_from_slice(public_key);
    aad
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const ATOMIC_REVISION: &str = "..2026_07_14_06_28_34.3514726726";

    fn write_atomic_revision(dir: &Path, name: &str, key: &str) {
        let revision = dir.join(name);
        fs::create_dir(&revision).unwrap();
        fs::set_permissions(&revision, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(revision.join("v1"), key).unwrap();
        fs::set_permissions(revision.join("v1"), fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn make_keyring(hex: &str) -> (SigningKekKeyring, std::path::PathBuf) {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "codewire-idp-kek-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("v1"), hex).unwrap();
        let keyring = SigningKekKeyring::load(&dir, "v1").unwrap();
        (keyring, dir)
    }

    fn fixture() -> ([u8; 32], [u8; 32]) {
        let seed = [7u8; 32];
        let public = Ed25519SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        (seed, public)
    }

    fn make_atomic_writer_keyring() -> std::path::PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(2000);
        let dir = std::env::temp_dir().join(format!(
            "codewire-idp-kek-atomic-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777)).unwrap();

        write_atomic_revision(
            &dir,
            ATOMIC_REVISION,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        symlink(ATOMIC_REVISION, dir.join("..data")).unwrap();
        symlink(Path::new("..data").join("v1"), dir.join("v1")).unwrap();
        dir
    }

    fn load_error(dir: &Path) -> String {
        match SigningKekKeyring::load(dir, "v1") {
            Ok(_) => panic!("invalid keyring unexpectedly loaded"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn accepts_confined_kubernetes_atomic_writer_layout() {
        let dir = make_atomic_writer_keyring();
        let keyring = SigningKekKeyring::load(&dir, "v1").unwrap();
        assert_eq!(keyring.active_id(), "v1");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_writable_or_tampered_atomic_writer_layouts() {
        let direct = std::env::temp_dir().join(format!(
            "codewire-idp-kek-sticky-direct-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&direct);
        fs::create_dir(&direct).unwrap();
        fs::set_permissions(&direct, fs::Permissions::from_mode(0o1777)).unwrap();
        fs::write(direct.join("v1"), "00").unwrap();
        assert!(load_error(&direct).contains("failure_class=keyring-directory-mode"));
        fs::remove_dir_all(direct).unwrap();

        let unexpected_root_bits = make_atomic_writer_keyring();
        fs::set_permissions(&unexpected_root_bits, fs::Permissions::from_mode(0o3777)).unwrap();
        assert!(load_error(&unexpected_root_bits).contains("failure_class=keyring-directory-mode"));
        fs::remove_dir_all(unexpected_root_bits).unwrap();

        let writable_revision = make_atomic_writer_keyring();
        let revision = fs::canonicalize(writable_revision.join("..data")).unwrap();
        fs::set_permissions(&revision, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load_error(&writable_revision).contains("failure_class=keyring-directory-mode"));
        fs::remove_dir_all(writable_revision).unwrap();

        let writable_file = make_atomic_writer_keyring();
        fs::set_permissions(
            writable_file.join(ATOMIC_REVISION).join("v1"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(load_error(&writable_file).contains("failure_class=key-file-atomic-target"));
        fs::remove_dir_all(writable_file).unwrap();

        let wrong_link = make_atomic_writer_keyring();
        fs::remove_file(wrong_link.join("v1")).unwrap();
        symlink(Path::new("..data").join("v2"), wrong_link.join("v1")).unwrap();
        let rendered = load_error(&wrong_link);
        assert!(rendered.contains("failure_class=key-file-atomic-link"));
        assert!(
            !rendered.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
        fs::remove_dir_all(wrong_link).unwrap();

        let chained_data_link = make_atomic_writer_keyring();
        fs::remove_file(chained_data_link.join("..data")).unwrap();
        symlink(ATOMIC_REVISION, chained_data_link.join("..alias")).unwrap();
        symlink("..alias", chained_data_link.join("..data")).unwrap();
        assert!(load_error(&chained_data_link).contains("failure_class=keyring-directory-mode"));
        fs::remove_dir_all(chained_data_link).unwrap();

        let escaping_data_link = make_atomic_writer_keyring();
        fs::remove_file(escaping_data_link.join("..data")).unwrap();
        symlink("../outside", escaping_data_link.join("..data")).unwrap();
        assert!(load_error(&escaping_data_link).contains("failure_class=keyring-directory-mode"));
        fs::remove_dir_all(escaping_data_link).unwrap();

        let inner_link = make_atomic_writer_keyring();
        let revision = inner_link.join(ATOMIC_REVISION);
        fs::write(
            revision.join("v2"),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        fs::remove_file(revision.join("v1")).unwrap();
        symlink("v2", revision.join("v1")).unwrap();
        assert!(load_error(&inner_link).contains("failure_class=key-file-atomic-target"));
        fs::remove_dir_all(inner_link).unwrap();
    }

    #[test]
    fn selected_atomic_revision_survives_data_link_swap() {
        let dir = make_atomic_writer_keyring();
        let canonical_dir = fs::canonicalize(&dir).unwrap();
        let root_metadata = fs::metadata(&canonical_dir).unwrap();
        let selected = atomic_writer_data_dir(&canonical_dir, &root_metadata)
            .unwrap()
            .unwrap();

        const NEXT_REVISION: &str = "..2026_07_14_07_00_00.0000000000";
        write_atomic_revision(
            &dir,
            NEXT_REVISION,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        fs::remove_file(dir.join("..data")).unwrap();
        symlink(NEXT_REVISION, dir.join("..data")).unwrap();

        let mut file = selected.open_key("v1", &root_metadata).unwrap();
        let mut value = String::new();
        file.read_to_string(&mut value).unwrap();
        assert_eq!(
            value,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn selected_atomic_revision_survives_revision_path_replacement() {
        let dir = make_atomic_writer_keyring();
        let canonical_dir = fs::canonicalize(&dir).unwrap();
        let root_metadata = fs::metadata(&canonical_dir).unwrap();
        let selected = atomic_writer_data_dir(&canonical_dir, &root_metadata)
            .unwrap()
            .unwrap();

        fs::rename(dir.join(ATOMIC_REVISION), dir.join("..retained")).unwrap();
        write_atomic_revision(
            &dir,
            ATOMIC_REVISION,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        let mut file = selected.open_key("v1", &root_metadata).unwrap();
        let mut value = String::new();
        file.read_to_string(&mut value).unwrap();
        assert_eq!(
            value,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn v1_round_trip_uses_fresh_random_nonces() {
        let (keyring, dir) =
            make_keyring("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let (seed, public) = fixture();
        let first = keyring.encrypt("codewire-1", &public, &seed).unwrap();
        let second = keyring.encrypt("codewire-1", &public, &seed).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            keyring.decrypt("codewire-1", &public, &first).unwrap(),
            seed
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_every_authenticated_or_structural_corruption_class() {
        let (keyring, dir) =
            make_keyring("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let (seed, public) = fixture();
        let envelope = keyring.encrypt("codewire-2", &public, &seed).unwrap();

        let mut wrong_format = envelope.clone();
        wrong_format.format = 2;
        assert!(
            keyring
                .decrypt("codewire-2", &public, &wrong_format)
                .is_err()
        );

        let mut wrong_id = envelope.clone();
        wrong_id.kek_id = "v2".into();
        assert!(keyring.decrypt("codewire-2", &public, &wrong_id).is_err());

        let mut wrong_nonce = envelope.clone();
        wrong_nonce.nonce[0] ^= 1;
        assert!(
            keyring
                .decrypt("codewire-2", &public, &wrong_nonce)
                .is_err()
        );
        wrong_nonce.nonce.pop();
        assert!(
            keyring
                .decrypt("codewire-2", &public, &wrong_nonce)
                .is_err()
        );

        let mut wrong_ciphertext = envelope.clone();
        wrong_ciphertext.ciphertext[0] ^= 1;
        assert!(
            keyring
                .decrypt("codewire-2", &public, &wrong_ciphertext)
                .is_err()
        );
        wrong_ciphertext.ciphertext.pop();
        assert!(
            keyring
                .decrypt("codewire-2", &public, &wrong_ciphertext)
                .is_err()
        );

        let other_public = Ed25519SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            keyring
                .decrypt("codewire-2", &other_public, &envelope)
                .is_err()
        );
        assert!(
            keyring
                .decrypt("codewire-other", &public, &envelope)
                .is_err()
        );

        let (wrong_keyring, wrong_dir) =
            make_keyring("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(
            wrong_keyring
                .decrypt("codewire-2", &public, &envelope)
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(wrong_dir).unwrap();
    }

    #[test]
    fn strict_keyring_parser_is_value_blind() {
        for (name, value) in [
            ("short", "00"),
            (
                "uppercase",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                "newline",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
            ),
        ] {
            static SEQUENCE: AtomicU64 = AtomicU64::new(1000);
            let dir = std::env::temp_dir().join(format!(
                "codewire-idp-kek-invalid-{name}-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("v1"), value).unwrap();
            let error = match SigningKekKeyring::load(&dir, "v1") {
                Ok(_) => panic!("invalid key file unexpectedly loaded"),
                Err(error) => error,
            };
            let rendered = error.to_string();
            assert!(rendered.contains("failure_class=key-file-format"));
            assert!(!rendered.contains(value));
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
