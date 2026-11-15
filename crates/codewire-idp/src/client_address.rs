//! The client address an abuser controls as one unit, kept only as a keyed
//! hash. OAuth sign-in stores it to bound the starts one client may hold, and
//! the per-address sign-up limit counts under it (#3297), so no IdP table
//! keeps a client's address for its limits.

use std::net::IpAddr;

use sha2::Sha256;

/// The label the hash key is derived under from the session secret, so a
/// stored hash can't be reversed by trying every address. The value predates
/// sign-up's use of it; changing it would orphan the OAuth starts in flight.
pub const CLIENT_ADDRESS_KEY_LABEL: &str = "codewire/idp-oauth-client-address/v1";

/// The keyed hash of the address an abuser controls as one unit: an IPv4
/// address (also when IPv4-mapped) or an IPv6 /64, as the feedback limiter
/// counts them. `None` when the edge named no address.
pub(crate) fn unit_hash(key: &str, address: Option<IpAddr>) -> Option<String> {
    use hmac::Mac as _;
    let unit = match address? {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let segments = v6.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            }
        },
    };
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(unit.as_bytes());
    Some(crate::auth_session::hex_lower(&mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(address: &str) -> Option<String> {
        unit_hash("synthetic-key", Some(address.parse().unwrap()))
    }

    #[test]
    fn one_unit_is_one_hash_and_the_address_is_never_kept() {
        // A host usually holds a whole IPv6 /64, so its addresses are one unit.
        assert_eq!(hash("2001:db8:7:1::1"), hash("2001:db8:7:1:ffff::2"));
        assert_ne!(hash("2001:db8:7:1::1"), hash("2001:db8:7:2::1"));
        assert_eq!(hash("::ffff:203.0.113.7"), hash("203.0.113.7"));
        assert_ne!(hash("203.0.113.7"), hash("203.0.113.8"));
        let hashed = hash("203.0.113.7").unwrap();
        assert!(!hashed.contains("203.0.113"), "{hashed}");
        assert_ne!(
            unit_hash("another-key", Some("203.0.113.7".parse().unwrap())),
            Some(hashed)
        );
        assert_eq!(unit_hash("synthetic-key", None), None);
    }
}
