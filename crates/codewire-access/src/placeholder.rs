//! Per-environment credential placeholders (#3999).
//!
//! An environment is given a placeholder in place of each credential its
//! profile selects. The value is derived, never stored: an HMAC over the
//! environment, its generation, the slot and the credential, under a key the
//! credential authority keeps in its protected store. No environment can read
//! that key; any process of the authority's own OS user that can read the
//! store can. So a placeholder differs for every one of them, the authority
//! can compute it again for any generation, and an environment cannot compute
//! any other environment's. A placeholder grants nothing by itself; it only
//! names, to that environment's own broker, the credential it stands for.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{AccessError, CapabilitySlot, CredentialId, EnvironmentId};

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
/// the key. The environment, a zero byte, the generation, the slot, a zero
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
    /// The placeholder for `credential_id` in `slot` of one environment
    /// generation: HMAC-SHA256 keyed by `key` over
    /// `codewire.credential-placeholder/v1\0`, the environment ID, a zero
    /// byte, the generation as eight big-endian bytes, the slot, a zero byte
    /// and the credential ID. No identifier can contain a zero byte and the
    /// generation has a fixed width, so the input is unambiguous.
    pub fn derive(
        key: &PlaceholderKey,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
        credential_id: &CredentialId,
    ) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*key.0).expect("HMAC accepts any key length");
        mac.update(DERIVATION_DOMAIN);
        mac.update(environment_id.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(&environment_generation.to_be_bytes());
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

#[cfg(test)]
mod tests;
