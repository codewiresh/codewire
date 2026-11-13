//! The configuration-owned signup invite policy: which invite codes admit an
//! account immediately. Moved out of `auth_session.rs` unchanged.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

const SIGNUP_INVITE_CODE_HASHES_ENV: &str = "IDP_SIGNUP_INVITE_CODE_HASHES";
const SHA256_DIGEST_BYTES: usize = 32;
const SHA256_HEX_CHARS: usize = SHA256_DIGEST_BYTES * 2;

/// Configuration-owned signup invite policy.
///
/// Runtime configuration sends signups through access review when the hash
/// list is empty. Trusted tests can opt into the explicit open-signup policy.
/// A configured policy stores only fixed-size SHA-256 digests; plaintext
/// invite codes are never retained.
#[derive(Clone, Default)]
pub struct SignupInvitePolicy {
    accepted_hashes: Arc<[[u8; SHA256_DIGEST_BYTES]]>,
    open_signup: bool,
}

impl fmt::Debug for SignupInvitePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignupInvitePolicy")
            .field("configured", &self.is_configured())
            .field("open_signup", &self.open_signup)
            .field("accepted_hash_count", &self.accepted_hashes.len())
            .finish()
    }
}

impl SignupInvitePolicy {
    /// Construct the explicit open-signup policy used by trusted tests.
    pub fn open() -> Self {
        Self {
            accepted_hashes: Arc::default(),
            open_signup: true,
        }
    }

    /// Parse an optional comma-separated list of lowercase SHA-256 hex
    /// digests. Absent or whitespace-only input selects access review.
    pub fn from_sha256_hashes(value: Option<&str>) -> anyhow::Result<Self> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::default());
        };

        let mut accepted_hashes = Vec::new();
        for encoded in value.split(',').map(str::trim) {
            let digest = decode_sha256_digest(encoded)?;
            if accepted_hashes.contains(&digest) {
                anyhow::bail!("{SIGNUP_INVITE_CODE_HASHES_ENV} contains a duplicate digest");
            }
            accepted_hashes.push(digest);
        }

        Ok(Self {
            accepted_hashes: accepted_hashes.into(),
            open_signup: false,
        })
    }

    /// Whether signup requires one of the configured invite codes.
    pub fn is_configured(&self) -> bool {
        !self.accepted_hashes.is_empty()
    }

    pub(crate) fn accepts(&self, invite_code: &str) -> bool {
        if self.open_signup {
            return true;
        }
        if !self.is_configured() || invite_code.is_empty() {
            return false;
        }

        let candidate: [u8; SHA256_DIGEST_BYTES] = Sha256::digest(invite_code.as_bytes()).into();
        let mut accepted = 0u8;
        for expected in self.accepted_hashes.iter() {
            accepted |= constant_time_digest_eq(&candidate, expected);
        }
        accepted == 1
    }
}

fn decode_sha256_digest(encoded: &str) -> anyhow::Result<[u8; SHA256_DIGEST_BYTES]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != SHA256_HEX_CHARS
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        anyhow::bail!(
            "{SIGNUP_INVITE_CODE_HASHES_ENV} entries must be {SHA256_HEX_CHARS}-character lowercase SHA-256 hex digests"
        );
    }

    let mut digest = [0u8; SHA256_DIGEST_BYTES];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax is validated before decoding"),
    }
}

fn constant_time_digest_eq(
    left: &[u8; SHA256_DIGEST_BYTES],
    right: &[u8; SHA256_DIGEST_BYTES],
) -> u8 {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    u8::from(difference == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite_digest(invite_code: &str) -> String {
        format!("{:x}", Sha256::digest(invite_code.as_bytes()))
    }

    #[test]
    fn signup_invite_policy_requires_review_without_hashes() {
        for value in [None, Some(""), Some("   ")] {
            let policy = SignupInvitePolicy::from_sha256_hashes(value).unwrap();
            assert!(!policy.is_configured());
            assert!(!policy.accepts(""));
            assert!(!policy.accepts("any-value"));
        }

        let open = SignupInvitePolicy::open();
        assert!(open.accepts(""));
        assert!(open.accepts("any-value"));
    }

    #[test]
    fn configured_signup_invite_policy_accepts_only_matching_values() {
        let first = invite_digest("synthetic-invite-one");
        let second = invite_digest("synthetic-invite-two");
        let configured = format!("{first}, {second}");
        let policy = SignupInvitePolicy::from_sha256_hashes(Some(&configured)).unwrap();

        assert!(policy.is_configured());
        assert!(policy.accepts("synthetic-invite-one"));
        assert!(policy.accepts("synthetic-invite-two"));
        assert!(!policy.accepts(""));
        assert!(!policy.accepts("synthetic-invite-three"));

        let debug = format!("{policy:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains("synthetic-invite"));
    }

    #[test]
    fn signup_invite_policy_rejects_invalid_hash_configuration() {
        let digest = invite_digest("synthetic-invite");
        for value in [
            "abc".to_owned(),
            "A".repeat(SHA256_HEX_CHARS),
            "g".repeat(SHA256_HEX_CHARS),
            format!("{digest},"),
            format!("{digest},{digest}"),
        ] {
            let error = SignupInvitePolicy::from_sha256_hashes(Some(&value)).unwrap_err();
            assert!(error.to_string().contains(SIGNUP_INVITE_CODE_HASHES_ENV));
            assert!(!error.to_string().contains("synthetic-invite"));
        }
    }
}
