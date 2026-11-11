//! The client address a request came from, as our edge reports it.
//!
//! Trust model (issue #2505, M1): read the LAST entry of `X-Forwarded-For`
//! that parses as an IP, never the first. The first entry is trivially
//! client-controlled (any request may carry a forged header), so reading it
//! would let anyone choose the address recorded or rate-limited. The last hop
//! is the only one attributable to our own edge:
//! - Caddy 2.10's default proxy posture is REPLACE: the client chain is
//!   discarded and the peer IP is forwarded as the sole hop (verified against
//!   caddy 2.10.2; see the comments in the Caddyfiles).
//! - An APPEND-mode proxy (e.g. Caddy with `trusted_proxies`, or a chain of
//!   proxies) adds the real peer at the END of the chain, so the last hop is
//!   still ours; earlier hops stay attacker-controlled and are ignored.
//!
//! Residual risk: a request that reaches a service DIRECTLY with a forged
//! header (bypassing the edge) cannot be distinguished here; the edge's
//! replace posture is the primary control and this parsing is the backstop.
//! Unparseable junk, or no header, yields no address, never a spoofed one.

use std::net::{IpAddr, Ipv4Addr};

use http::HeaderMap;

/// The nearest `X-Forwarded-For` hop that parses as an IP, exactly as it was
/// written (without a `:port` or brackets). See the module docs for why it
/// is the last parseable hop.
pub fn forwarded_client_hop(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .rsplit(',')
        .map(str::trim)
        .map(strip_forwarded_port)
        .find(|hop| hop.parse::<IpAddr>().is_ok())
}

/// [`forwarded_client_hop`] as an address, so equal addresses compare equal
/// however they were spelled.
pub fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    forwarded_client_hop(headers)?.parse().ok()
}

/// Drop a trailing `:port` (or bracketed-IPv6 `]:port`) from one forwarded
/// hop. `"http"`/`"https"` scheme suffixes from RFC 7239-style proxies are
/// left in place and fail IP parsing, which is the conservative outcome for a
/// value we cannot attribute.
fn strip_forwarded_port(hop: &str) -> &str {
    if let Some(stripped) = hop.strip_prefix('[') {
        // `[2001:db8::1]:443` -> `2001:db8::1`
        let Some(end) = stripped.find(']') else {
            return hop;
        };
        return &stripped[..end];
    }
    match hop.rfind(':') {
        // `203.0.113.9:443` -> `203.0.113.9`; bare IPv6 has no port to strip.
        Some(colon) if hop[..colon].parse::<Ipv4Addr>().is_ok() => &hop[..colon],
        _ => hop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(xff) = xff {
            headers.insert("x-forwarded-for", xff.parse().unwrap());
        }
        headers
    }

    #[test]
    fn the_edge_appended_hop_wins_over_client_supplied_ones() {
        assert_eq!(
            forwarded_client_hop(&headers(Some("1.2.3.4, 5.6.7.8, 203.0.113.9"))),
            Some("203.0.113.9")
        );
        assert_eq!(
            forwarded_client_hop(&headers(Some("1.2.3.4, 203.0.113.9:443, junk"))),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn ipv6_hops_parse_with_and_without_brackets_and_compare_equal() {
        assert_eq!(
            forwarded_client_ip(&headers(Some("[2001:DB8::1]:443"))),
            forwarded_client_ip(&headers(Some("2001:db8::1")))
        );
        assert!(forwarded_client_ip(&headers(Some("2001:db8::1"))).is_some());
    }

    #[test]
    fn no_parseable_hop_is_no_address() {
        for xff in [None, Some(""), Some("junk"), Some("unknown, http")] {
            assert_eq!(forwarded_client_hop(&headers(xff)), None, "{xff:?}");
        }
    }
}
