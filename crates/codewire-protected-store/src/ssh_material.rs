//! Pure, bounded SSH credential preparation for placement authorities.
//!
//! This module reads no paths, environment, agents or protected stores. An
//! authority must separately admit the owner, exact credential revision and
//! original deadline before publication or use. Import does synchronous bounded
//! cryptographic work: cancelling an async waiter does not cancel that work.
//! Callers retain their worker/permit until it drains and recheck authority
//! before publishing. This module creates no profile or runtime grant.

use std::fmt;

use rand::RngCore as _;
use ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{Cipher, HashAlg, Kdf, LineEnding, Mpint, PrivateKey, PublicKey};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::ProtectedValue;

pub const MAX_OPENSSH_PRIVATE_KEY_BYTES: usize = 64 * 1024;
pub const MAX_SSH_PASSPHRASE_BYTES: usize = 1024;
pub const MAX_SSH_PUBLIC_KEY_BYTES: usize = 4 * 1024;
pub const MAX_SSH_BCRYPT_ROUNDS: u32 = 64;
const MAX_RSA_COMPONENT_BYTES: usize = 1025;
const MAX_RSA_EXPONENT: u64 = (1_u64 << 33) - 1;
const BUNDLE_PREFIX: &[u8] = b"codewire-ssh\0\x01";
const MAX_BUNDLE_BYTES: usize =
    BUNDLE_PREFIX.len() + 8 + MAX_OPENSSH_PRIVATE_KEY_BYTES + MAX_SSH_PASSPHRASE_BYTES;
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const SELF_TEST_NAMESPACE: &str = "codewire-ssh-enrollment-v1";
const SELF_TEST_MESSAGE: &[u8] = b"Codewire SSH private/public consistency check";

/// Closed failures: no parser, cipher, random-source or material-bearing error
/// is retained as a source or formatted into these messages.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SshMaterialError {
    #[error("SSH private key is invalid")]
    InvalidKey,
    #[error("SSH key type or size is unsupported")]
    UnsupportedKey,
    #[error("SSH key encryption or KDF parameters are unsupported")]
    UnsupportedEncryption,
    #[error("SSH key requires a protected passphrase")]
    PassphraseRequired,
    #[error("SSH passphrase is invalid or unexpected")]
    InvalidPassphrase,
    #[error("SSH private key could not be decrypted")]
    DecryptionFailed,
    #[error("SSH key generation entropy is unavailable")]
    EntropyUnavailable,
    #[error("protected SSH credential is invalid")]
    InvalidBundle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshKeyAlgorithm {
    Ed25519,
    Rsa { bits: u32 },
}

/// Derived public metadata only. Imported comments and authorized_keys options
/// never enter this value; it is safe to display for public-key registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshPublicKey {
    algorithm: SshKeyAlgorithm,
    openssh: String,
    fingerprint: String,
    key_blob: Vec<u8>,
}

impl SshPublicKey {
    pub fn algorithm(&self) -> SshKeyAlgorithm {
        self.algorithm
    }

    /// One canonical public-key line, with neither comment nor final newline.
    pub fn openssh(&self) -> &str {
        &self.openssh
    }

    /// The standard `SHA256:` fingerprint of the public SSH key blob.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Public RFC SSH encoding for comparison with the selected agent identity.
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }
}

/// Parse one authority-persisted canonical public identity and prove that its
/// stored fingerprint describes those exact RFC SSH bytes. This reads no
/// protected material and accepts no authorized-keys options or comments.
pub fn parse_public_key(
    openssh: &str,
    fingerprint: &str,
) -> Result<SshPublicKey, SshMaterialError> {
    if openssh.is_empty()
        || openssh.len() > MAX_SSH_PUBLIC_KEY_BYTES
        || openssh.split_ascii_whitespace().count() != 2
        || fingerprint.len() != 50
        || !fingerprint.starts_with("SHA256:")
    {
        return Err(SshMaterialError::InvalidKey);
    }
    let public = PublicKey::from_openssh(openssh).map_err(|_| SshMaterialError::InvalidKey)?;
    let algorithm = validate_public_key(&public)?;
    let canonical = public
        .to_openssh()
        .map_err(|_| SshMaterialError::InvalidKey)?;
    let derived_fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let key_blob = public
        .to_bytes()
        .map_err(|_| SshMaterialError::InvalidKey)?;
    if canonical != openssh
        || derived_fingerprint != fingerprint
        || key_blob.is_empty()
        || key_blob.len() > MAX_SSH_PUBLIC_KEY_BYTES
    {
        return Err(SshMaterialError::InvalidKey);
    }
    Ok(SshPublicKey {
        algorithm,
        openssh: canonical,
        fingerprint: derived_fingerprint,
        key_blob,
    })
}

/// A validated public identity and one opaque key-plus-passphrase payload.
/// Neither cloning nor serialization of this material-bearing holder is exposed.
pub struct PreparedSshCredential {
    public_key: SshPublicKey,
    material: ProtectedValue,
}

impl PreparedSshCredential {
    pub fn public_key(&self) -> &SshPublicKey {
        &self.public_key
    }

    /// The caller publishes both parts in its existing credential transaction.
    pub fn into_parts(self) -> (SshPublicKey, ProtectedValue) {
        (self.public_key, self.material)
    }
}

impl fmt::Debug for PreparedSshCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSshCredential([REDACTED])")
    }
}

/// Exact input to an already-authorized selected-key agent. This is an in-memory
/// codec result, not a store lookup or a general material RPC.
pub struct SshAgentMaterial {
    public_key: SshPublicKey,
    private_key: Zeroizing<Vec<u8>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

impl SshAgentMaterial {
    pub fn public_key(&self) -> &SshPublicKey {
        &self.public_key
    }

    /// Consume inside the trusted broker only, after comparing the public
    /// identity with metadata and rechecking the original operation lease.
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>) {
        (self.private_key, self.passphrase)
    }
}

impl fmt::Debug for SshAgentMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SshAgentMaterial([REDACTED])")
    }
}

/// Generate one Ed25519 key in memory. The unencrypted OpenSSH encoding is
/// protected by the caller's existing OS-store or platform envelope; no private
/// key file or user-managed export passphrase is created.
pub fn generate_ed25519() -> Result<PreparedSshCredential, SshMaterialError> {
    generate_with_entropy(|seed| {
        rand::rngs::OsRng
            .try_fill_bytes(seed)
            .map_err(|_| SshMaterialError::EntropyUnavailable)
    })
}

fn generate_with_entropy(
    fill: impl FnOnce(&mut [u8; 32]) -> Result<(), SshMaterialError>,
) -> Result<PreparedSshCredential, SshMaterialError> {
    // Workspace rand 0.8 and ssh-key's rand_core 0.10 do not share RNG traits.
    // Pass only a zeroizing OS-random seed, never an incompatible RNG adapter.
    let mut seed = Zeroizing::new([0_u8; 32]);
    fill(&mut seed)?;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let encoded = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshMaterialError::InvalidKey)?;
    import_openssh(Zeroizing::new(encoded.as_bytes().to_vec()), None)
}

/// Import exactly one explicit standard OpenSSH private key. Ordinary
/// ssh-keygen Ed25519/RSA output is supported: unencrypted, or AES-CTR with
/// bcrypt's 16-byte salt and 1..=64 rounds. Other ciphers/formats are rejected,
/// never converted through a subprocess or discovered in an ambient home.
/// Armor is canonicalized to LF with a final newline; encrypted key bytes and
/// their existing KDF parameters are preserved without re-encryption.
pub fn import_openssh(
    private_key: Zeroizing<Vec<u8>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
) -> Result<PreparedSshCredential, SshMaterialError> {
    let (public_key, private_key) =
        validate_material(&private_key, passphrase.as_deref().map(Vec::as_slice))?;
    let material = encode_bundle(&private_key, passphrase.as_deref().map(Vec::as_slice))?;
    Ok(PreparedSshCredential {
        public_key,
        material,
    })
}

/// Decode one exact already-retrieved protected payload. Revalidate its key,
/// KDF bounds and derived identity; persistence is not an authorization proof.
/// The encrypted key and its passphrase remain together in this payload, never
/// in credential metadata, argv, environment or a private mount. Returned armor
/// is always canonical, including when a payload contains noncanonical input.
pub fn decode_protected_material(
    material: ProtectedValue,
) -> Result<SshAgentMaterial, SshMaterialError> {
    let bytes = material.expose_secret();
    if bytes.len() > MAX_BUNDLE_BYTES || !bytes.starts_with(BUNDLE_PREFIX) {
        return Err(SshMaterialError::InvalidBundle);
    }
    let mut rest = &bytes[BUNDLE_PREFIX.len()..];
    let private_key = take_field(&mut rest, MAX_OPENSSH_PRIVATE_KEY_BYTES)?;
    if private_key.is_empty() {
        return Err(SshMaterialError::InvalidBundle);
    }
    let passphrase = take_field(&mut rest, MAX_SSH_PASSPHRASE_BYTES)?;
    if !rest.is_empty() {
        return Err(SshMaterialError::InvalidBundle);
    }
    let private_key = Zeroizing::new(private_key.to_vec());
    let passphrase = (!passphrase.is_empty()).then(|| Zeroizing::new(passphrase.to_vec()));
    drop(material);
    let (public_key, private_key) =
        validate_material(&private_key, passphrase.as_deref().map(Vec::as_slice))?;
    Ok(SshAgentMaterial {
        public_key,
        private_key,
        passphrase,
    })
}

fn validate_material(
    encoded: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<(SshPublicKey, Zeroizing<Vec<u8>>), SshMaterialError> {
    let key = parse_openssh(encoded)?;
    // Serialize the still-encrypted parsed key, not its decrypted validation
    // copy. This changes only armor framing: ciphertext, salt, rounds and the
    // original public identity are unchanged, with no additional KDF work.
    // ssh-add requires BEGIN at byte zero and a newline-terminated END marker.
    let canonical = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshMaterialError::InvalidKey)?;
    if canonical.len() > MAX_OPENSSH_PRIVATE_KEY_BYTES {
        return Err(SshMaterialError::InvalidKey);
    }
    let key = admit_with_decrypt(key, passphrase, |key, passphrase| {
        key.decrypt(passphrase)
            .map_err(|_| SshMaterialError::DecryptionFailed)
    })?;
    let algorithm = validate_public_key(key.public_key())?;
    match key.key_data() {
        KeypairData::Ed25519(_) => {
            // The enabled ed25519 parser checks seed/public correspondence.
        }
        KeypairData::Rsa(pair) => validate_rsa_private(pair)?,
        _ => return Err(SshMaterialError::UnsupportedKey),
    }
    // Fixed-domain consistency proof, not a caller-controlled signing API.
    let signature = key
        .sign(SELF_TEST_NAMESPACE, HashAlg::Sha256, SELF_TEST_MESSAGE)
        .map_err(|_| SshMaterialError::InvalidKey)?;
    key.public_key()
        .verify(SELF_TEST_NAMESPACE, SELF_TEST_MESSAGE, &signature)
        .map_err(|_| SshMaterialError::InvalidKey)?;
    let public = PublicKey::from(key.public_key().key_data().clone());
    let openssh = public
        .to_openssh()
        .map_err(|_| SshMaterialError::InvalidKey)?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let key_blob = public
        .to_bytes()
        .map_err(|_| SshMaterialError::InvalidKey)?;
    if openssh.len() > MAX_SSH_PUBLIC_KEY_BYTES
        || key_blob.len() > MAX_SSH_PUBLIC_KEY_BYTES
        || fingerprint.len() != 50
        || !fingerprint.starts_with("SHA256:")
    {
        return Err(SshMaterialError::InvalidKey);
    }
    Ok((
        SshPublicKey {
            algorithm,
            openssh,
            fingerprint,
            key_blob,
        },
        Zeroizing::new(canonical.as_bytes().to_vec()),
    ))
}

fn parse_openssh(encoded: &[u8]) -> Result<PrivateKey, SshMaterialError> {
    if encoded.is_empty() || encoded.len() > MAX_OPENSSH_PRIVATE_KEY_BYTES {
        return Err(SshMaterialError::InvalidKey);
    }
    let text = std::str::from_utf8(encoded)
        .map_err(|_| SshMaterialError::InvalidKey)?
        .trim();
    if !text.starts_with(PEM_BEGIN)
        || !text.ends_with(PEM_END)
        || text.matches(PEM_BEGIN).count() != 1
        || text.matches(PEM_END).count() != 1
    {
        return Err(SshMaterialError::InvalidKey);
    }
    PrivateKey::from_openssh(text).map_err(|_| SshMaterialError::InvalidKey)
}

fn admit_with_decrypt(
    key: PrivateKey,
    passphrase: Option<&[u8]>,
    decrypt: impl FnOnce(&PrivateKey, &[u8]) -> Result<PrivateKey, SshMaterialError>,
) -> Result<PrivateKey, SshMaterialError> {
    validate_public_key(key.public_key())?;
    if passphrase.is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_SSH_PASSPHRASE_BYTES
            || value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    }) {
        return Err(SshMaterialError::InvalidPassphrase);
    }
    match (key.cipher(), key.kdf()) {
        (Cipher::None, Kdf::None) => {
            if passphrase.is_some() {
                return Err(SshMaterialError::InvalidPassphrase);
            }
            Ok(key)
        }
        (
            Cipher::Aes128Ctr | Cipher::Aes192Ctr | Cipher::Aes256Ctr,
            Kdf::Bcrypt { salt, rounds },
        ) if salt.len() == 16 && (1..=MAX_SSH_BCRYPT_ROUNDS).contains(rounds) => {
            let passphrase = passphrase.ok_or(SshMaterialError::PassphraseRequired)?;
            decrypt(&key, passphrase)
        }
        _ => Err(SshMaterialError::UnsupportedEncryption),
    }
}

fn validate_public_key(public: &PublicKey) -> Result<SshKeyAlgorithm, SshMaterialError> {
    match public.key_data() {
        KeyData::Ed25519(_) => Ok(SshKeyAlgorithm::Ed25519),
        KeyData::Rsa(key) => {
            let n = bounded_positive(key.n())?;
            let bits = u32::try_from(n.len()).map_err(|_| SshMaterialError::UnsupportedKey)? * 8
                - n[0].leading_zeros();
            let exponent = bounded_positive(key.e())?;
            if exponent.len() > 5 || !(2048..=8192).contains(&bits) {
                return Err(SshMaterialError::UnsupportedKey);
            }
            let exponent = exponent
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            if !(3..=MAX_RSA_EXPONENT).contains(&exponent)
                || exponent & 1 == 0
                || n[n.len() - 1] & 1 == 0
            {
                return Err(SshMaterialError::UnsupportedKey);
            }
            Ok(SshKeyAlgorithm::Rsa { bits })
        }
        // Match actual plain key variants, not certificate.algorithm().
        _ => Err(SshMaterialError::UnsupportedKey),
    }
}

fn bounded_positive(value: &Mpint) -> Result<&[u8], SshMaterialError> {
    if value.as_bytes().len() > MAX_RSA_COMPONENT_BYTES {
        return Err(SshMaterialError::UnsupportedKey);
    }
    let bytes = value
        .as_positive_bytes()
        .ok_or(SshMaterialError::InvalidKey)?;
    if bytes.is_empty() || bytes[0] == 0 {
        return Err(SshMaterialError::InvalidKey);
    }
    Ok(bytes)
}

fn validate_rsa_private(pair: &RsaKeypair) -> Result<(), SshMaterialError> {
    let private = pair.private();
    for value in [private.d(), private.p(), private.q(), private.iqmp()] {
        bounded_positive(value)?;
    }
    for prime in [private.p(), private.q()] {
        let value = bounded_positive(prime)?;
        if value[value.len() - 1] & 1 == 0 || (value.len() == 1 && value[0] <= 1) {
            return Err(SshMaterialError::InvalidKey);
        }
    }
    // ssh-key's RsaKeypair::new intentionally does not check components. The
    // same locked RSA implementation validates n/p/q/d/e and reconstructs CRT;
    // compare the reconstruction so a corrupt imported iqmp cannot survive.
    let validated = rsa::RsaPrivateKey::try_from(pair).map_err(|_| SshMaterialError::InvalidKey)?;
    let normalized = RsaKeypair::try_from(&validated).map_err(|_| SshMaterialError::InvalidKey)?;
    // Do not use aggregate RsaKeypair/RsaPrivateKey equality: ssh-key
    // 0.7.0-rc.10 compares iqmp with itself. Compare all six Mpints directly;
    // their equality compares both operands, including the reconstructed CRT.
    let same_components = (normalized.public().n() == pair.public().n())
        & (normalized.public().e() == pair.public().e())
        & (normalized.private().d() == private.d())
        & (normalized.private().iqmp() == private.iqmp())
        & (normalized.private().p() == private.p())
        & (normalized.private().q() == private.q());
    if !same_components {
        return Err(SshMaterialError::InvalidKey);
    }
    Ok(())
}

fn encode_bundle(
    key: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<ProtectedValue, SshMaterialError> {
    if key.is_empty()
        || key.len() > MAX_OPENSSH_PRIVATE_KEY_BYTES
        || passphrase
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SSH_PASSPHRASE_BYTES)
    {
        return Err(SshMaterialError::InvalidBundle);
    }
    let passphrase = passphrase.unwrap_or_default();
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        BUNDLE_PREFIX.len() + 8 + key.len() + passphrase.len(),
    ));
    encoded.extend_from_slice(BUNDLE_PREFIX);
    for field in [key, passphrase] {
        let length = u32::try_from(field.len()).map_err(|_| SshMaterialError::InvalidBundle)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    ProtectedValue::new(std::mem::take(&mut *encoded)).map_err(|_| SshMaterialError::InvalidBundle)
}

fn take_field<'a>(input: &mut &'a [u8], limit: usize) -> Result<&'a [u8], SshMaterialError> {
    let length = input.get(..4).ok_or(SshMaterialError::InvalidBundle)?;
    let length = u32::from_be_bytes(
        length
            .try_into()
            .map_err(|_| SshMaterialError::InvalidBundle)?,
    );
    let length = usize::try_from(length).map_err(|_| SshMaterialError::InvalidBundle)?;
    if length > limit {
        return Err(SshMaterialError::InvalidBundle);
    }
    *input = &input[4..];
    let field = input.get(..length).ok_or(SshMaterialError::InvalidBundle)?;
    *input = &input[length..];
    Ok(field)
}

#[cfg(test)]
mod tests;
