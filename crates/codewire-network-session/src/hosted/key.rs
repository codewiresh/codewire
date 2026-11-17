//! The network key for one admitted stream (#4000). Both ends derive it from
//! what the hello carried and cw-egress's answer, so the existing network
//! session handshake and frame tags run unchanged. Every stream gets its own
//! key from its two nonces, and another Pod's from its UID. The generation is
//! not an input: a re-placed environment runs in a new Pod with a new UID,
//! and an unbound warm member has none.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::hello::NONCE_LEN;
use crate::{NETWORK_KEY_LEN, NetworkError, NetworkKey};

const KEY_DOMAIN: &[u8] = b"codewire.egress-stream/v1\0";

pub struct StreamKeyInput<'a> {
    pub token: &'a str,
    pub guest_nonce: &'a [u8; NONCE_LEN],
    pub node_nonce: &'a [u8; NONCE_LEN],
    pub pod_uid: Uuid,
}

pub fn stream_key(input: &StreamKeyInput<'_>) -> Result<NetworkKey, NetworkError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(input.token.as_bytes())
        .map_err(|_| NetworkError::InvalidKey)?;
    mac.update(KEY_DOMAIN);
    mac.update(input.guest_nonce);
    mac.update(input.node_nonce);
    mac.update(input.pod_uid.as_bytes());
    let bytes: Zeroizing<[u8; NETWORK_KEY_LEN]> =
        Zeroizing::new(mac.finalize().into_bytes().into());
    NetworkKey::from_derived_bytes(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_bytes(input: &StreamKeyInput<'_>) -> [u8; NETWORK_KEY_LEN] {
        stream_key(input).unwrap().with_bytes(|bytes| *bytes)
    }

    #[test]
    fn both_ends_derive_the_same_key_and_any_changed_input_changes_it() {
        let pod = Uuid::from_u128(1);
        let base = StreamKeyInput {
            token: "token",
            guest_nonce: &[1; NONCE_LEN],
            node_nonce: &[2; NONCE_LEN],
            pod_uid: pod,
        };
        let same = StreamKeyInput { ..base };
        assert_eq!(key_bytes(&base), key_bytes(&same));

        let variants = [
            StreamKeyInput {
                token: "other",
                ..base
            },
            StreamKeyInput {
                guest_nonce: &[3; NONCE_LEN],
                ..base
            },
            StreamKeyInput {
                node_nonce: &[3; NONCE_LEN],
                ..base
            },
            StreamKeyInput {
                pod_uid: Uuid::from_u128(2),
                ..base
            },
        ];
        for variant in &variants {
            assert_ne!(key_bytes(&base), key_bytes(variant));
        }
    }
}
