//! Authenticated envelopes for persisted OIDC Ed25519 signing seeds.
//!
//! Version 1 encrypts only the 32-byte seed. The public key remains in the
//! public JWK and is bound, together with the row `kid`, into the AEAD AAD.

use std::fmt;
use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use codewire_server_core::kek::{KekKeyring, KekKeyringError};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::RngCore;

/// Current database envelope format.
pub const FORMAT_V1: i16 = 1;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const AAD_DOMAIN_V1: &[u8] = b"codewire/idp/ed25519-seed-envelope/v1\0";

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
    inner: KekKeyring,
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
        let inner = KekKeyring::load(dir, active_id).map_err(Self::keyring_error)?;
        Ok(Self { inner })
    }

    pub fn active_id(&self) -> &str {
        self.inner.active_id()
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
            .inner
            .key(self.active_id())
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
            kek_id: self.active_id().to_owned(),
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
            .inner
            .key(&envelope.kek_id)
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

    fn keyring_error(error: KekKeyringError) -> EnvelopeError {
        EnvelopeError::keyring(error.failure_class(), error.kek_id())
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

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
