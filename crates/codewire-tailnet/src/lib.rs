//! `codewire-tailnet` — a minimal, Codewire-owned tailnet client.
//!
//! This is the Rust port of `libs/tailnet` (#59). It is **bounded by the
//! ~933 LoC of behaviour Codewire actually uses**, not by Tailscale's full
//! stack. The Go side wraps `wgengine` + `magicsock` + gvisor `netstack`;
//! here we reimplement only the subset behind a small public API:
//!
//! - WireGuard **data plane** via `boringtun` (Noise handshake + transport
//!   crypto).
//! - **DERP relay client** (transport) — interops with the Codewire
//!   `codewire-derp` server binary (#46).
//! - **Coordinator HTTP/WS client** — interops with the existing Go
//!   coordinator; app-level JSON, no Tailscale dep (#47).
//! - **Peer / node state** — the `Node` wire model + ULA addressing (#48).
//! - A userspace TCP listener/dialer so consumers get `Listen("tcp", ":22")`
//!   / `DialContextTCP` (gvisor `netstack` → `smoltcp`-class, ours).
//! - **Disco message framing** for direct UDP and UDP peer relay:
//!   Tailscale-compatible sealed Ping/Pong/CallMeMaybe plus the
//!   CallMeMaybeVia/UDP-relay allocation and bind handshake messages used by
//!   magicsock.
//!
//! Consumer API surface to reach (from `libs/tailnet/conn.go` + the gateway):
//! `Conn::new` · `listen` · `dial_tcp` · `update_peers` · `set_node_callback`
//! · `set_derp_map` · `node` · `close`; plus `Node`, `DerpMap`, the
//! `CWServicePrefix` ULA helper.
//!
//! Direct-path parity is being ported through #265/#276/#257. The current Rust
//! path includes disco framing plus a UDP transport adapter with endpoint
//! validation, STUN mapped endpoint discovery, path selection, and DERP
//! fallback. #257 adds the shared UDP peer-relay data path so relayed UDP can
//! report as `peer_relay` instead of pretending to be `direct_udp`.

/// DERP relay client (transport). Interops with the Codewire
/// `codewire-derp` server binary.
pub mod derp;

/// Peer / node wire types (#48): the `Node` JSON model, the
/// `NodePublic`/`DiscoPublic` typed-hex keys, and the deterministic ULA
/// addressing helper (`CW_SERVICE_PREFIX` / `prefix_from_uuid`).
pub mod node;

/// Tailscale-compatible disco message framing for direct UDP path discovery.
pub mod disco;

/// Direct UDP path selection layered over the relay transport.
pub mod direct_udp;

/// Reconnecting DERP transport adapter for Conn.
pub mod derp_transport;

/// UDP peer relay server/client primitives for #257.
pub mod udp_relay;

/// Local endpoint advertisement tracking used by the direct UDP transport.
pub mod endpoint_tracker;

/// Minimal RFC5389 STUN binding client used by the direct UDP transport.
pub mod stun;

/// Coordinator HTTP/WebSocket client (#47). Interops with the existing Go
/// coordinator (app-level JSON over WebSocket).
pub mod coordinator;

/// Native Connect-RPC coordinator client (Connect bidi over HTTP/2).
pub mod coordinator_connect;

/// Userspace TCP/IP netstack (transport → sockets). The
/// gvisor-`netstack` equivalent (`smoltcp`-based) that turns the WireGuard
/// tunnel into ordinary `bind`/`connect`, mirroring the Go
/// `Conn::Listen`/`DialContextTCP`.
pub mod netstack;

/// The top-level [`conn::Conn`] (#59 capstone): ties the WireGuard data plane
/// (#45), relay/direct transport (#46/#265), node/peer state (#48), and
/// userspace netstack (#59) into a working tunnel exposing `listen` /
/// `dial_context_tcp`. Mirrors `libs/tailnet/conn.go`.
pub mod conn;

/// WireGuard data-plane core (boringtun). Spike for #45.
pub mod wg {
    pub use boringtun::x25519::{PublicKey, StaticSecret};

    /// A WireGuard peer endpoint built on boringtun's `Tunn` state machine.
    /// This is the crypto/transport half of the data plane; path selection
    /// (DERP vs direct) and the userspace netstack sit above it.
    pub struct Peer {
        pub tunn: Box<boringtun::noise::Tunn>,
    }

    impl Peer {
        /// Create a peer endpoint keyed by our static secret + the remote's
        /// static public key (the WireGuard identity exchanged via the
        /// coordinator's `Node` records).
        pub fn new(our_secret: &StaticSecret, their_public: PublicKey, index: u32) -> Self {
            let tunn = boringtun::noise::Tunn::new(
                our_secret.clone(),
                their_public,
                None, // no preshared key
                None, // no persistent keepalive
                index,
                None, // no rate limiter (single-peer test)
            );
            Self {
                tunn: Box::new(tunn),
            }
        }
    }
}

#[cfg(test)]
mod spike_tests {
    //! Proves the WireGuard data plane works in Rust via boringtun
    //! — a full Noise handshake (init → response → established) between two
    //! peers, then an encrypted data packet round-tripping. This is the
    //! highest-uncertainty piece of the tailnet port; everything else
    //! (DERP client, coordinator) is protocol-plumbing over this.

    use super::wg::{Peer, PublicKey, StaticSecret};
    use boringtun::noise::TunnResult;
    use rand::rngs::OsRng;

    fn keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Minimal valid IPv4 packet (20-byte header, no payload) so boringtun's
    /// decapsulate routes it to WriteToTunnelV4 with the decrypted bytes.
    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        let total_len = (p.len() as u16).to_be_bytes();
        p[2] = total_len[0];
        p[3] = total_len[1];
        p[8] = 64; // TTL
        p[9] = 0; // protocol
                  // src 10.0.0.1 / dst 10.0.0.2
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    #[test]
    fn boringtun_handshake_and_data_roundtrip() {
        let (a_sec, a_pub) = keypair();
        let (b_sec, b_pub) = keypair();

        let mut a = Peer::new(&a_sec, b_pub, 1);
        let mut b = Peer::new(&b_sec, a_pub, 2);

        let mut buf = vec![0u8; 2048];

        // 1) A initiates: encapsulate with no data → handshake initiation.
        let init = match a.tunn.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected handshake init, got {other:?}"),
        };

        // 2) B receives init → handshake response.
        let mut buf2 = vec![0u8; 2048];
        let resp = match b.tunn.decapsulate(None, &init, &mut buf2) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };

        // 3) A receives response → handshake complete (queued keepalive).
        let mut buf3 = vec![0u8; 2048];
        match a.tunn.decapsulate(None, &resp, &mut buf3) {
            // boringtun returns the queued keepalive (or Done) once established.
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
            other => panic!("expected established, got {other:?}"),
        }

        // 4) A sends a real data packet → B decrypts it back to plaintext.
        let plaintext = ipv4_packet();
        let mut buf4 = vec![0u8; 2048];
        let encrypted = match a.tunn.encapsulate(&plaintext, &mut buf4) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected encrypted data, got {other:?}"),
        };
        assert_ne!(encrypted, plaintext, "data must be encrypted on the wire");

        let mut buf5 = vec![0u8; 2048];
        match b.tunn.decapsulate(None, &encrypted, &mut buf5) {
            TunnResult::WriteToTunnelV4(decrypted, _) => {
                assert_eq!(decrypted, plaintext.as_slice(), "decrypted == original");
            }
            other => panic!("expected decrypted IPv4, got {other:?}"),
        }
    }
}
