//! Per-environment credential placeholders (#3999).
//!
//! An environment is given a placeholder in place of each credential its
//! profile selects. The value is derived, never stored: an HMAC over the
//! environment, its binding's profile revision, the slot and the credential,
//! under a key the credential authority keeps in its protected store. No
//! environment can read that key; any process of the authority's own OS user
//! that can read the store can. So a placeholder differs for every one of
//! them, the authority can compute it again at any time, and an environment
//! cannot compute any other environment's. A placeholder grants nothing by
//! itself; it only names, to that environment's own broker, the credential it
//! stands for.
//!
//! The revision input is the binding's, not the VM generation (#3999,
//! deliberately changed from #4308): a VM checkpoint restored in place boots
//! a new generation with the same binding, so its running agents keep their
//! placeholder and keep working. A fork is another environment, so it gets
//! new placeholders and its agents start again: that isolation comes from the
//! environment ID. Any rebind to another revision or credential changes it.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{AccessError, CapabilitySlot, CredentialId, EnvironmentId};

mod secret;
pub use secret::{ApplicationSecretKey, SecretPlaceholder};

/// The wire form's leading tag, which also versions the derivation.
pub const CREDENTIAL_PLACEHOLDER_TAG: &str = "cwp1_";
/// The derived value's length before encoding.
const PLACEHOLDER_BYTES: usize = 32;
/// The unpadded base64url length of [`PLACEHOLDER_BYTES`].
const PLACEHOLDER_ENCODED_BYTES: usize = 43;
/// The wire form's fixed length: the tag and 43 base64url characters.
pub const CREDENTIAL_PLACEHOLDER_LENGTH: usize =
    CREDENTIAL_PLACEHOLDER_TAG.len() + PLACEHOLDER_ENCODED_BYTES;
/// The key's length.
pub const PLACEHOLDER_KEY_BYTES: usize = 32;
/// HMAC input prefix that keeps this derivation apart from any other use of
/// the key. The environment, a zero byte, the profile revision, the slot, a zero
/// byte and the credential ID follow it.
const DERIVATION_DOMAIN: &[u8] = b"codewire.credential-placeholder/v1\0";

/// The authority's placeholder key. Never sent to an environment or a
/// broker; only placeholders derived from it are. Not `Clone`, and zeroized
/// when dropped.
pub struct PlaceholderKey(Zeroizing<[u8; PLACEHOLDER_KEY_BYTES]>);

impl PlaceholderKey {
    /// A key the authority read from its store: exactly
    /// [`PLACEHOLDER_KEY_BYTES`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AccessError> {
        let mut key = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
        if bytes.len() != PLACEHOLDER_KEY_BYTES {
            return Err(AccessError::InvalidField {
                field: "credential placeholder key",
            });
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// HKDF info prefix for an owner-local environment's key (#6191). The
/// environment ID follows it.
const OWNER_LOCAL_KEY_INFO: &[u8] = b"codewire local placeholder key v1\0";

impl PlaceholderKey {
    /// The key of one local VM that runs on a platform profile (#4909,
    /// #6191), derived from its owner's local placeholder root: HKDF-SHA256
    /// Expand of one block with the root as the pseudorandom key (it is 32
    /// uniformly random bytes, so no Extract step is needed) and the info
    /// `codewire local placeholder key v1`, a zero byte and the environment
    /// ID, which can contain no zero byte. That is HMAC-SHA256 keyed by the
    /// root over the info and the block counter `0x01`. Each environment of
    /// one owner gets its own key; another owner's root never gives the
    /// same one.
    pub fn owner_local(root: &PlaceholderKey, environment_id: &EnvironmentId) -> Self {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&*root.0).expect("HMAC accepts any key length");
        mac.update(OWNER_LOCAL_KEY_INFO);
        mac.update(environment_id.as_str().as_bytes());
        mac.update(&[1]);
        let mut derived = mac.finalize().into_bytes();
        let mut key = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
        key.copy_from_slice(&derived);
        derived.as_mut_slice().zeroize();
        Self(key)
    }
}

impl fmt::Debug for PlaceholderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlaceholderKey([REDACTED])")
    }
}

/// One environment's stand-in for one credential: `cwp1_` and the unpadded
/// base64url of 32 derived bytes, 48 ASCII characters in all.
///
/// It has no `PartialEq`: compare with [`Self::ct_eq`], which takes the same
/// time wherever two values differ. `Debug` never prints the value and there
/// is no `Display`; [`Self::as_str`] is the one way to read it.
#[derive(Clone)]
pub struct CredentialPlaceholder(String);

impl CredentialPlaceholder {
    /// The placeholder for `credential_id` in `slot` of one environment at
    /// one binding: HMAC-SHA256 keyed by `key` over
    /// `codewire.credential-placeholder/v1\0`, the environment ID, a zero
    /// byte, `binding_revision` as eight big-endian bytes, the slot, a zero
    /// byte and the credential ID. No identifier can contain a zero byte and
    /// the revision has a fixed width, so the input is unambiguous.
    /// `binding_revision` is the selected binding's profile revision, zero
    /// for a grant no profile selects; never the VM generation (see the
    /// module documentation).
    pub fn derive(
        key: &PlaceholderKey,
        environment_id: &EnvironmentId,
        binding_revision: u64,
        slot: &CapabilitySlot,
        credential_id: &CredentialId,
    ) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*key.0).expect("HMAC accepts any key length");
        mac.update(DERIVATION_DOMAIN);
        mac.update(environment_id.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(&binding_revision.to_be_bytes());
        mac.update(slot.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(credential_id.as_str().as_bytes());
        // Not a secret: the environment holds it.
        Self(format!(
            "{CREDENTIAL_PLACEHOLDER_TAG}{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Accept exactly the wire form: the lowercase tag, then 43 base64url
    /// characters that are the canonical encoding of 32 bytes.
    pub fn parse(value: &str) -> Result<Self, AccessError> {
        let invalid = AccessError::InvalidField {
            field: "credential placeholder",
        };
        if !Self::looks_like(value) {
            return Err(invalid);
        }
        match URL_SAFE_NO_PAD.decode(&value[CREDENTIAL_PLACEHOLDER_TAG.len()..]) {
            Ok(decoded) if decoded.len() == PLACEHOLDER_BYTES => Ok(Self(value.to_owned())),
            _ => Err(invalid),
        }
    }

    /// Whether `value` has the wire form's shape: the tag, the fixed length,
    /// the base64url alphabet, and a last character that leaves no stray bits.
    /// It decodes nothing, so it is a cheap test of whether a header could
    /// hold a placeholder, and it accepts exactly what [`Self::parse`] accepts.
    pub fn looks_like(value: &str) -> bool {
        let Some(encoded) = value.strip_prefix(CREDENTIAL_PLACEHOLDER_TAG) else {
            return false;
        };
        let encoded = encoded.as_bytes();
        let Some((&last, body)) = encoded.split_last() else {
            return false;
        };
        // 32 bytes fill 42 characters and four bits of the 43rd, so the
        // canonical last character's value is a multiple of four.
        encoded.len() == PLACEHOLDER_ENCODED_BYTES
            && body.iter().all(|&byte| base64url_value(byte).is_some())
            && base64url_value(last).is_some_and(|value| value % 4 == 0)
    }

    /// The wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Equality in time that does not depend on where two values differ.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl fmt::Debug for CredentialPlaceholder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CredentialPlaceholder({CREDENTIAL_PLACEHOLDER_TAG}[REDACTED])"
        )
    }
}

/// The value of one base64url character, or `None` outside that alphabet.
fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// One worked derivation, written out: a key of the bytes 0 to 31, the inputs
/// below, and the placeholder they give. The access tests and the hosted
/// broker's tests both derive it, so neither the layout nor how a hosted lease
/// passes its grant to [`CredentialPlaceholder::derive`] can drift from local
/// (#4001). Test data only; it grants nothing.
#[doc(hidden)]
pub mod known_answer {
    /// The key: the bytes 0 to 31.
    pub const KEY: [u8; super::PLACEHOLDER_KEY_BYTES] = {
        let mut key = [0_u8; super::PLACEHOLDER_KEY_BYTES];
        let mut index = 0;
        while index < key.len() {
            key[index] = index as u8;
            index += 1;
        }
        key
    };
    pub const ENVIRONMENT: &str = "environment-a";
    /// The selected binding's profile revision (#4812).
    pub const BINDING_REVISION: u64 = 0x0102_0304_0506_0708;
    pub const SLOT: &str = "codex";
    pub const CREDENTIAL: &str = "credential-a";
    pub const PLACEHOLDER: &str = "cwp1_CrtskkVMKO8hWIv0dqtomFhFamB5zbu6Peo4NJ8QLZc";
}

#[cfg(test)]
mod tests;
