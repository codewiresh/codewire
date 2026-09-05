//! Peer / node wire types (#48).
//!
//! The [`crate::node::Node`] struct is the WireGuard connectivity record exchanged
//! between clients and environment sidecars via the coordinator (JSON over
//! WebSocket). It is the Rust port of `libs/tailnet/node.go` and its JSON
//! encoding must preserve the Go wire contract **byte-for-byte**.
//!
//! Field-name + encoding parity with Go (`json` tags / stdlib marshalers):
//!
//! | Go field / type                  | JSON key         | encoding                                  |
//! |----------------------------------|------------------|-------------------------------------------|
//! | `ID uuid.UUID`                   | `id`             | hyphenated UUID string                    |
//! | `AsOf time.Time`                 | `as_of`          | RFC3339 (nanos)                           |
//! | `Key key.NodePublic`             | `key`            | `"nodekey:" + hex(32)`                    |
//! | `DiscoKey key.DiscoPublic`       | `disco_key`      | `"discokey:" + hex(32)`                   |
//! | `PreferredDERP int`              | `preferred_derp` | integer                                   |
//! | `DERPLatency map[string]float64` | `derp_latency`   | object, **omitempty**                     |
//! | `Endpoints []netip.AddrPort`     | `endpoints`      | `["1.2.3.4:41641","[2001:db8::1]:41641"]` |
//! | `Addresses []netip.Prefix`       | `addresses`      | `["fd7a:115c:a1e0:.../128"]`              |
//!
//! The ULA addressing helper ([`crate::node::CW_SERVICE_PREFIX`] /
//! [`crate::node::prefix_from_uuid`])
//! reproduces Go's deterministic `ServicePrefix.PrefixFromUUID`: the 6-byte
//! `fd7a:115c:a1e0` prefix followed by the **first 10 bytes** of the UUID,
//! giving a stable `/128`.

use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Length of a raw Curve25519 public key on the wire.
pub const KEY_LEN: usize = 32;

/// The Codewire service prefix for deterministic ULA IPv6 addressing:
/// `fd7a:115c:a1e0::/48`. Mirrors Go's `CWServicePrefix`.
pub const CW_SERVICE_PREFIX: [u8; 6] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0];

/// A node public key (Curve25519). Mirrors Go `key.NodePublic`.
///
/// JSON-encodes as `"nodekey:<64 hex chars>"`, matching Tailscale's
/// `key.NodePublic.MarshalText`. This is a parallel minimal type to the
/// DERP module's `derp::key::NodePublic`: that one is built for the DERP
/// NaCl-box handshake (no serde, raw 32-byte wire form), whereas the
/// coordinator needs the typed-hex JSON text form. They share the same
/// 32-byte payload; conversions are provided via [`NodePublic::as_bytes`] /
/// [`NodePublic::from_raw`]. Merging them is deferred to #59 (would mean
/// adding serde + a text codec to the DERP key without disturbing the #193
/// PR).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodePublic {
    raw: [u8; KEY_LEN],
}

/// A disco public key (Curve25519). Mirrors Go `key.DiscoPublic`.
///
/// JSON-encodes as `"discokey:<64 hex chars>"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiscoPublic {
    raw: [u8; KEY_LEN],
}

impl NodePublic {
    /// Construct from the raw 32 bytes.
    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self { raw }
    }

    /// The raw 32-byte key.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.raw
    }

    /// Whether this is the zero key.
    pub fn is_zero(&self) -> bool {
        self.raw == [0u8; KEY_LEN]
    }
}

impl DiscoPublic {
    /// Construct from the raw 32 bytes.
    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self { raw }
    }

    /// The raw 32-byte key.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.raw
    }

    /// Whether this is the zero key.
    pub fn is_zero(&self) -> bool {
        self.raw == [0u8; KEY_LEN]
    }
}

impl Default for NodePublic {
    fn default() -> Self {
        Self {
            raw: [0u8; KEY_LEN],
        }
    }
}

impl Default for DiscoPublic {
    fn default() -> Self {
        Self {
            raw: [0u8; KEY_LEN],
        }
    }
}

fn hex_encode(raw: &[u8; KEY_LEN]) -> String {
    let mut s = String::with_capacity(KEY_LEN * 2);
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<[u8; KEY_LEN], String> {
    if s.len() != KEY_LEN * 2 {
        return Err(format!(
            "key hex has the wrong size, got {} want {}",
            s.len(),
            KEY_LEN * 2
        ));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        let hi = from_hex_char(bytes[i * 2]).ok_or("invalid hex character in key")?;
        let lo = from_hex_char(bytes[i * 2 + 1]).ok_or("invalid hex character in key")?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn from_hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Serialize a typed-prefix hex key (Go `appendHexKey`).
fn ser_typed_hex<S: Serializer>(
    prefix: &str,
    raw: &[u8; KEY_LEN],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{prefix}{}", hex_encode(raw)))
}

/// Deserialize a typed-prefix hex key (Go `parseHex`).
fn de_typed_hex<'de, D: Deserializer<'de>>(prefix: &str, d: D) -> Result<[u8; KEY_LEN], D::Error> {
    let s = String::deserialize(d)?;
    let hex = s.strip_prefix(prefix).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "key hex string doesn't have expected type prefix {prefix}"
        ))
    })?;
    hex_decode(hex).map_err(serde::de::Error::custom)
}

impl Serialize for NodePublic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_typed_hex("nodekey:", &self.raw, s)
    }
}

impl<'de> Deserialize<'de> for NodePublic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self {
            raw: de_typed_hex("nodekey:", d)?,
        })
    }
}

impl Serialize for DiscoPublic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_typed_hex("discokey:", &self.raw, s)
    }
}

impl<'de> Deserialize<'de> for DiscoPublic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self {
            raw: de_typed_hex("discokey:", d)?,
        })
    }
}

impl std::fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodePublic(nodekey:")?;
        for b in &self.raw[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

impl std::fmt::Debug for DiscoPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DiscoPublic(discokey:")?;
        for b in &self.raw[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// An IPv6 `/128` (or other) prefix, mirroring Go's `netip.Prefix`.
///
/// We keep this as a thin wrapper over [`std::net::IpAddr`] + bit length so
/// the JSON text form (`"addr/bits"`) round-trips byte-for-byte with Go's
/// `netip.Prefix.MarshalText`, including IPv6 zero-compression (`::`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prefix {
    addr: std::net::IpAddr,
    bits: u8,
}

impl Prefix {
    /// Construct a prefix from an address and prefix length in bits.
    pub fn new(addr: std::net::IpAddr, bits: u8) -> Self {
        Self { addr, bits }
    }

    /// The prefix address.
    pub fn addr(&self) -> std::net::IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn bits(&self) -> u8 {
        self.bits
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (addr, bits) = s
            .rsplit_once('/')
            .ok_or_else(|| serde::de::Error::custom("prefix missing '/'"))?;
        let addr: std::net::IpAddr = addr
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid prefix address"))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid prefix length"))?;
        // Reject out-of-range prefix lengths the way Go's netip.ParsePrefix
        // does (/33+ for IPv4, /129+ for IPv6). Without this an oversized
        // `bits` slices past the address octets in the Conn's prefix match
        // and panics the pump task on attacker-influenced coordinator data.
        let max = match addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        if bits > max {
            return Err(serde::de::Error::custom("prefix length out of range"));
        }
        Ok(Self { addr, bits })
    }
}

/// An IP address + port, mirroring Go's `netip.AddrPort`.
///
/// Serialized as a string (`"1.2.3.4:41641"` / `"[2001:db8::1]:41641"`) to
/// match Go's `netip.AddrPort.MarshalText`. `std::net::SocketAddr`'s
/// `Display`/`FromStr` already use that exact bracketed-IPv6 form, so we
/// wrap it directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrPort(pub SocketAddr);

impl Serialize for AddrPort {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for AddrPort {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let sa: SocketAddr = s
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid addr:port"))?;
        Ok(AddrPort(sa))
    }
}

/// The WireGuard connectivity information for a single peer.
///
/// Exchanged between clients and agents via the coordinator (JSON over
/// WebSocket). Field names and ordering match `libs/tailnet/node.go`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    /// Stable identity (the environment UUID for a sidecar; a per-connection
    /// UUID for a client).
    pub id: Uuid,
    /// Timestamp this record was produced.
    pub as_of: DateTime<Utc>,
    /// WireGuard node public key.
    pub key: NodePublic,
    /// Disco public key (used for direct-path discovery).
    pub disco_key: DiscoPublic,
    /// Preferred DERP region for this node.
    pub preferred_derp: i32,
    /// Per-region DERP latencies (seconds). Omitted when empty, matching
    /// Go's `omitempty`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_latency: Option<std::collections::BTreeMap<String, f64>>,
    /// Known local/STUN endpoints. Go marshals a nil slice as JSON `null`
    /// (these fields have no `omitempty`), so we tolerate `null` → empty on
    /// the way in while still emitting `[]` when non-nil.
    #[serde(deserialize_with = "null_as_empty")]
    pub endpoints: Vec<AddrPort>,
    /// Addresses (ULA prefixes) this node owns. Same `null`-tolerance as
    /// `endpoints`.
    #[serde(deserialize_with = "null_as_empty")]
    pub addresses: Vec<Prefix>,
}

/// Deserialize a JSON array that may be `null` into a `Vec`, mapping `null`
/// to an empty vec. Go emits `null` for nil slices on these no-`omitempty`
/// fields.
fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// Return a `/128` IPv6 [`Prefix`] for `uid` under [`CW_SERVICE_PREFIX`].
///
/// Reproduces Go's `ServicePrefix.PrefixFromUUID`: the 6-byte prefix
/// followed by the **first 10 bytes** of the UUID (`addr[6:] = uid[:10]`),
/// yielding a deterministic `/128`. Note only 10 of the UUID's 16 bytes are
/// used — this is faithful to the Go source.
pub fn prefix_from_uuid(uid: &Uuid) -> Prefix {
    let uid_bytes = uid.as_bytes();
    let mut addr = [0u8; 16];
    addr[..6].copy_from_slice(&CW_SERVICE_PREFIX);
    addr[6..].copy_from_slice(&uid_bytes[..10]);
    Prefix {
        addr: std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)),
        bits: 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors captured from the Go source via `go test` against
    // `libs/tailnet/node.go` (CWServicePrefix.PrefixFromUUID). These are the
    // cross-language parity anchors; if Go changes, regenerate.
    const ULA_UUID_1: &str = "12345678-1234-5678-1234-567812345678";
    const ULA_PREFIX_1: &str = "fd7a:115c:a1e0:1234:5678:1234:5678:1234/128";
    const ULA_UUID_2: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const ULA_PREFIX_2: &str = "fd7a:115c:a1e0:11:2233:4455:6677:8899/128";

    // Byte-for-byte Node JSON captured from Go's json.Marshal.
    const NODE_JSON: &str = r#"{"id":"12345678-1234-5678-1234-567812345678","as_of":"2026-06-19T12:00:00Z","key":"nodekey:0000000000000000000000000000000000000000000000000000000000000001","disco_key":"discokey:0000000000000000000000000000000000000000000000000000000000000002","preferred_derp":3,"derp_latency":{"1":0.05},"endpoints":["1.2.3.4:41641","[2001:db8::1]:41641"],"addresses":["fd7a:115c:a1e0:1234:5678:1234:5678:1234/128"]}"#;

    #[test]
    fn ula_derivation_matches_go() {
        let p1 = prefix_from_uuid(&Uuid::parse_str(ULA_UUID_1).unwrap());
        assert_eq!(p1.to_string(), ULA_PREFIX_1);
        let p2 = prefix_from_uuid(&Uuid::parse_str(ULA_UUID_2).unwrap());
        assert_eq!(p2.to_string(), ULA_PREFIX_2);
    }

    #[test]
    fn node_json_deserializes_go_output() {
        let n: Node = serde_json::from_str(NODE_JSON).unwrap();
        assert_eq!(n.id, Uuid::parse_str(ULA_UUID_1).unwrap());
        assert_eq!(n.preferred_derp, 3);
        assert_eq!(n.key.as_bytes()[31], 0x01);
        assert_eq!(n.disco_key.as_bytes()[31], 0x02);
        assert_eq!(n.endpoints.len(), 2);
        assert_eq!(n.endpoints[0].0.to_string(), "1.2.3.4:41641");
        assert_eq!(n.endpoints[1].0.to_string(), "[2001:db8::1]:41641");
        assert_eq!(n.addresses[0].to_string(), ULA_PREFIX_1);
        assert_eq!(
            n.derp_latency.as_ref().unwrap().get("1").copied(),
            Some(0.05)
        );
    }

    #[test]
    fn prefix_rejects_out_of_range_bits() {
        // Oversized prefix lengths must fail deserialization (mirrors Go's
        // netip.ParsePrefix) so they can never reach the Conn route table and
        // panic the pump task by slicing past the address octets.
        assert!(serde_json::from_str::<Prefix>("\"1.2.3.4/33\"").is_err());
        assert!(serde_json::from_str::<Prefix>("\"1.2.3.4/200\"").is_err());
        assert!(serde_json::from_str::<Prefix>("\"fd7a::1/129\"").is_err());
        assert!(serde_json::from_str::<Prefix>("\"fd7a::1/200\"").is_err());
        // Edge values at the family maximum must still parse.
        assert!(serde_json::from_str::<Prefix>("\"1.2.3.4/32\"").is_ok());
        assert!(serde_json::from_str::<Prefix>("\"1.2.3.4/0\"").is_ok());
        assert!(serde_json::from_str::<Prefix>("\"fd7a::1/128\"").is_ok());
    }

    #[test]
    fn node_json_serializes_byte_for_byte() {
        // Round-trip: deserialize Go output, re-serialize, compare exactly.
        let n: Node = serde_json::from_str(NODE_JSON).unwrap();
        let out = serde_json::to_string(&n).unwrap();
        assert_eq!(out, NODE_JSON, "Node JSON must match Go byte-for-byte");
    }

    #[test]
    fn derp_latency_omitempty() {
        // No derp_latency → key must be absent, matching Go omitempty.
        let n = Node {
            id: Uuid::nil(),
            as_of: "2026-06-19T12:00:00Z".parse().unwrap(),
            key: NodePublic::default(),
            disco_key: DiscoPublic::default(),
            preferred_derp: 1,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![],
        };
        let out = serde_json::to_string(&n).unwrap();
        assert!(
            !out.contains("derp_latency"),
            "omitempty: derp_latency must be absent, got {out}"
        );
    }

    #[test]
    fn node_with_null_slices_deserializes() {
        // Captured from Go: a zero Node marshals endpoints/addresses as null
        // (no omitempty). The Rust client must accept that.
        const NIL_NODE: &str = r#"{"id":"00000000-0000-0000-0000-000000000000","as_of":"0001-01-01T00:00:00Z","key":"nodekey:0000000000000000000000000000000000000000000000000000000000000000","disco_key":"discokey:0000000000000000000000000000000000000000000000000000000000000000","preferred_derp":0,"endpoints":null,"addresses":null}"#;
        let n: Node = serde_json::from_str(NIL_NODE).unwrap();
        assert_eq!(n.id, Uuid::nil());
        assert!(n.endpoints.is_empty());
        assert!(n.addresses.is_empty());
    }

    #[test]
    fn node_public_typed_hex_roundtrip() {
        let raw = [0xabu8; KEY_LEN];
        let k = NodePublic::from_raw(raw);
        let j = serde_json::to_string(&k).unwrap();
        assert_eq!(
            j,
            format!("\"nodekey:{}\"", "ab".repeat(KEY_LEN)),
            "NodePublic must encode as nodekey:<hex>"
        );
        let back: NodePublic = serde_json::from_str(&j).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn disco_public_typed_hex_roundtrip() {
        let raw = [0xcdu8; KEY_LEN];
        let k = DiscoPublic::from_raw(raw);
        let j = serde_json::to_string(&k).unwrap();
        assert_eq!(j, format!("\"discokey:{}\"", "cd".repeat(KEY_LEN)));
        let back: DiscoPublic = serde_json::from_str(&j).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn wrong_prefix_rejected() {
        let r: Result<NodePublic, _> =
            serde_json::from_str(&format!("\"discokey:{}\"", "00".repeat(KEY_LEN)));
        assert!(r.is_err(), "nodekey parser must reject discokey prefix");
    }
}
