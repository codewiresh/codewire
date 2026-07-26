//! DERP client tests.
//!
//! Three tiers, strongest last:
//! 1. **Unit** — frame encode/decode round-trips for every frame type;
//!    NaCl seal/open round-trip; handshake byte layout (magic preamble,
//!    `ClientInfo` framing).
//! 2. **In-process interop** — the real [`Client`] handshake + `send` +
//!    `recv` driven against a minimal hand-rolled DERP server over a
//!    tokio duplex pipe. Proves our wire bytes are self-consistent and
//!    the handshake/seal logic works end-to-end without a network.
//! 3. **Real server-binary interop** (`#[ignore]`, opt-in) — spawns the
//!    actual `codewire-derp` binary and relays a packet between two
//!    Rust clients through it (A `send` → server → B `recv`). This is
//!    the true #46 proof. Gated behind an env var + the prebuilt binary
//!    so `cargo test` stays hermetic; see the ignored interop test docs.

use super::frame::{self, FrameType, MAGIC, PROTOCOL_VERSION};
use super::key::{NodePrivate, NodePublic, KEY_LEN, NONCE_LEN};
use super::{client::ReceivedMessage, Client};
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Tier 1: unit
// ---------------------------------------------------------------------------

#[test]
fn frame_header_roundtrip_all_types() {
    let types = [
        FrameType::ServerKey,
        FrameType::ClientInfo,
        FrameType::ServerInfo,
        FrameType::SendPacket,
        FrameType::RecvPacket,
        FrameType::KeepAlive,
        FrameType::NotePreferred,
        FrameType::PeerGone,
        FrameType::PeerPresent,
        FrameType::ForwardPacket,
        FrameType::WatchConns,
        FrameType::ClosePeer,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Health,
        FrameType::Restarting,
        FrameType::Unknown(0x7f),
    ];
    for t in types {
        // Type byte round-trips.
        assert_eq!(FrameType::from_u8(t.to_u8()), t, "type byte for {t:?}");

        // Header + payload round-trips, with a representative length.
        let payload = vec![0xabu8; 37];
        let buf = frame::encode_frame(t, &payload);
        let (dt, dlen) = frame::decode_header(&buf).unwrap();
        assert_eq!(dt, t);
        assert_eq!(dlen as usize, payload.len());
        assert_eq!(&buf[frame::FRAME_HEADER_LEN..], &payload[..]);
    }
}

#[test]
fn frame_header_is_type_plus_be_length() {
    // SendPacket (0x04) with a 0x0102 (258) byte payload → header bytes
    // are exactly [0x04, 0x00, 0x00, 0x01, 0x02].
    let payload = vec![0u8; 258];
    let buf = frame::encode_frame(FrameType::SendPacket, &payload);
    assert_eq!(
        &buf[..frame::FRAME_HEADER_LEN],
        &[0x04, 0x00, 0x00, 0x01, 0x02]
    );
}

#[test]
fn magic_preamble_is_correct_bytes() {
    // "DERP🔑" == 0x44 45 52 50 f0 9f 94 91, 8 bytes.
    assert_eq!(MAGIC, &[0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91]);
    assert_eq!(MAGIC.len(), 8);
    assert_eq!(MAGIC, "DERP\u{1f511}".as_bytes());
}

#[test]
fn seal_open_roundtrip() {
    let mut rng = OsRng;
    let a = NodePrivate::generate(&mut rng);
    let b = NodePrivate::generate(&mut rng);

    let msg = br#"{"version":2}"#;
    let sealed = a.seal_to(&b.public(), msg, &mut rng).unwrap();

    // On-wire layout: 24-byte nonce prefix + box (plaintext + 16-byte
    // Poly1305 tag), matching Go's NodePrivate.SealTo.
    assert_eq!(sealed.len(), NONCE_LEN + msg.len() + 16);

    // Peer opens it.
    let opened = b.open_from(&a.public(), &sealed).unwrap();
    assert_eq!(opened, msg);

    // Wrong sender key fails to authenticate.
    let c = NodePrivate::generate(&mut rng);
    assert!(b.open_from(&c.public(), &sealed).is_err());
}

#[test]
fn public_key_wire_encoding_is_32_raw_bytes() {
    let k = NodePrivate::generate(&mut OsRng).public();
    assert_eq!(k.as_bytes().len(), KEY_LEN);
    let rt = NodePublic::from_slice(k.as_bytes()).unwrap();
    assert_eq!(rt.as_bytes(), k.as_bytes());
    assert!(NodePublic::from_slice(&[0u8; 31]).is_err());
}

// ---------------------------------------------------------------------------
// Tier 2: in-process interop against a minimal hand-rolled DERP server.
// ---------------------------------------------------------------------------

/// A tiny server-side handshake: send ServerKey, read+open ClientInfo,
/// send ServerInfo. Returns the client's public key it learned. Operates
/// on the raw DERP stream (no HTTP upgrade — the duplex pipe is already
/// at the DERP layer).
async fn server_handshake<S>(conn: &mut S, server_priv: &NodePrivate) -> NodePublic
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // ServerKey: magic + pubkey.
    let mut payload = Vec::new();
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(server_priv.public().as_bytes());
    let buf = frame::encode_frame(FrameType::ServerKey, &payload);
    conn.write_all(&buf).await.unwrap();
    conn.flush().await.unwrap();

    // Read ClientInfo frame.
    let (t, body) = read_frame(conn).await;
    assert_eq!(t, FrameType::ClientInfo);
    let client_pub = NodePublic::from_slice(&body[..KEY_LEN]).unwrap();
    // Decrypt the sealed ClientInfo to prove the seal interops.
    let clear = server_priv
        .open_from(&client_pub, &body[KEY_LEN..])
        .expect("server opens ClientInfo box");
    let v: serde_json::Value = serde_json::from_slice(&clear).unwrap();
    assert_eq!(v["version"], PROTOCOL_VERSION);

    // ServerInfo: sealed JSON.
    let info = br#"{"version":2}"#;
    let sealed = server_priv.seal_to(&client_pub, info, &mut OsRng).unwrap();
    let buf = frame::encode_frame(FrameType::ServerInfo, &sealed);
    conn.write_all(&buf).await.unwrap();
    conn.flush().await.unwrap();

    client_pub
}

async fn read_frame<S>(conn: &mut S) -> (FrameType, Vec<u8>)
where
    S: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; frame::FRAME_HEADER_LEN];
    conn.read_exact(&mut hdr).await.unwrap();
    let (t, len) = frame::decode_header(&hdr).unwrap();
    let mut body = vec![0u8; len as usize];
    conn.read_exact(&mut body).await.unwrap();
    (t, body)
}

#[tokio::test]
async fn handshake_and_send_recv_inprocess() {
    let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
    let server_priv = NodePrivate::generate(&mut OsRng);
    let client_priv = NodePrivate::generate(&mut OsRng);
    let client_pub = client_priv.public();
    let server_pub = server_priv.public();

    // Server task: handshake, then expect a SendPacket and echo a
    // RecvPacket back (simulating a relay to a peer == ourselves).
    let dst_peer = NodePrivate::generate(&mut OsRng).public();
    let dst_for_server = dst_peer.clone();
    let server = tokio::spawn(async move {
        let learned = server_handshake(&mut server_side, &server_priv).await;
        assert_eq!(
            learned.as_bytes(),
            client_pub.as_bytes(),
            "server learns client key"
        );

        // Read the SendPacket the client sends.
        let (t, body) = read_frame(&mut server_side).await;
        assert_eq!(t, FrameType::SendPacket);
        let dst = NodePublic::from_slice(&body[..KEY_LEN]).unwrap();
        assert_eq!(dst.as_bytes(), dst_for_server.as_bytes());
        let pkt = body[KEY_LEN..].to_vec();

        // Relay it back as a RecvPacket sourced from `learned` (client).
        let mut rp = Vec::new();
        rp.extend_from_slice(learned.as_bytes());
        rp.extend_from_slice(&pkt);
        let buf = frame::encode_frame(FrameType::RecvPacket, &rp);
        server_side.write_all(&buf).await.unwrap();
        server_side.flush().await.unwrap();
    });

    // Client: handshake over the duplex pipe (already at DERP layer).
    let mut rng = OsRng;
    let mut client = Client::handshake(client_side, client_priv, &mut rng)
        .await
        .expect("client handshake");
    assert_eq!(client.server_public_key().as_bytes(), server_pub.as_bytes());

    // Send a packet to the peer.
    let payload = b"hello over DERP".to_vec();
    client.send(&dst_peer, &payload).await.unwrap();

    // First message back should be ServerInfo, then our relayed packet.
    let mut got_packet = None;
    for _ in 0..3 {
        match client.recv().await.unwrap() {
            ReceivedMessage::ServerInfo => continue,
            ReceivedMessage::Packet { source, data } => {
                assert_eq!(source.as_bytes(), client.public_key().as_bytes());
                got_packet = Some(data);
                break;
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
    assert_eq!(got_packet.as_deref(), Some(payload.as_slice()));
    server.await.unwrap();
}

// ---------------------------------------------------------------------------
// Tier 3: real server-binary interop (opt-in).
// ---------------------------------------------------------------------------

/// Relay a packet between two Rust clients through the real
/// `codewire-derp` server: A `send(B, pkt)` → server → B `recv` == pkt.
///
/// Opt-in because it shells out to a prebuilt server binary and binds a port:
/// run with
///
/// ```sh
/// CODEWIRE_DERP_BIN=/tmp/codewire-derp \
///   cargo test -p codewire-tailnet --release derp_interop -- --ignored --nocapture
/// ```
///
/// Uses the server's cleartext `PORT` listener (set `STUN_PORT=-1`,
/// `TLS_PORT=` empty) so the test exercises the full DERP protocol
/// without needing a custom rustls cert verifier. (TLS connect is also
/// implemented and used in production via [`super::connect_tls`].)
#[tokio::test]
#[ignore = "spawns the codewire-derp server binary; run explicitly with CODEWIRE_DERP_BIN set"]
async fn derp_interop_relay_two_rust_clients_via_server_binary() {
    use std::process::Stdio;
    use std::time::Duration;

    let bin = std::env::var("CODEWIRE_DERP_BIN")
        .expect("set CODEWIRE_DERP_BIN to the prebuilt codewire-derp binary");

    // Pick a port and launch the server binary (DERP only, no TLS, no STUN).
    let port = "34879";
    let mut child = tokio::process::Command::new(&bin)
        .env("PORT", port)
        .env("TLS_PORT", "")
        .env("STUN_PORT", "-1")
        .env("CODEWIRE_DEBUG_DERP", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn codewire-derp");

    // Wait for the listener to come up.
    let addr = format!("127.0.0.1:{port}");
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "DERP server never started listening on {addr}");

    let mut rng = OsRng;
    let a_priv = NodePrivate::generate(&mut rng);
    let b_priv = NodePrivate::generate(&mut rng);
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    // Connect both clients over plain TCP + HTTP upgrade + DERP handshake.
    let mut a = super::connect_plain(&addr, "127.0.0.1", a_priv, &mut rng)
        .await
        .expect("client A connect");
    let mut b = super::connect_plain(&addr, "127.0.0.1", b_priv, &mut rng)
        .await
        .expect("client B connect");

    assert_eq!(a.public_key().as_bytes(), a_pub.as_bytes());
    assert_eq!(
        a.server_public_key().as_bytes(),
        b.server_public_key().as_bytes(),
        "both clients see the same server key"
    );

    // The server routes by dst key; it learns B's presence from B's
    // connection. Give B a moment to be registered, then A sends to B.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let payload = b"relayed through the DERP server".to_vec();
    a.send(&b_pub, &payload).await.expect("A sends to B");

    // B receives the relayed packet, sourced from A. Skip ServerInfo /
    // keepalive / health frames.
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match b.recv().await.unwrap() {
                ReceivedMessage::Packet { source, data } => {
                    assert_eq!(source.as_bytes(), a_pub.as_bytes(), "src is A");
                    return data;
                }
                ReceivedMessage::ServerInfo
                | ReceivedMessage::KeepAlive
                | ReceivedMessage::Health(_) => continue,
                other => panic!("unexpected frame on B: {other:?}"),
            }
        }
    })
    .await
    .expect("B receives relayed packet within timeout");

    assert_eq!(received, payload, "B got exactly what A sent");

    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Relay a packet between two Rust clients through an already-running TLS
/// DERP endpoint.
///
/// Opt-in live dev probe. A useful way to run it against the dev cluster is:
///
/// ```sh
/// KUBECONFIG=/home/user/src/infra/kubeconfig-oidc.yaml \
///   kubectl --context codewire-dev -n dev port-forward svc/codewire-derp 18443:8443
///
/// CODEWIRE_TAILNET_LIVE_DERP_ADDR=127.0.0.1:18443 \
/// CODEWIRE_TAILNET_LIVE_DERP_HOST=codewire-derp.dev.svc.cluster.local \
///   cargo test -p codewire-tailnet live_tls_derp -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "live DERP endpoint probe; set CODEWIRE_TAILNET_LIVE_DERP_ADDR/HOST and run explicitly"]
async fn live_tls_derp_relay_two_rust_clients() {
    let addr = std::env::var("CODEWIRE_TAILNET_LIVE_DERP_ADDR")
        .expect("set CODEWIRE_TAILNET_LIVE_DERP_ADDR, for example 127.0.0.1:18443");
    let host = std::env::var("CODEWIRE_TAILNET_LIVE_DERP_HOST").expect(
        "set CODEWIRE_TAILNET_LIVE_DERP_HOST, for example codewire-derp.dev.svc.cluster.local",
    );
    let verify = std::env::var("CODEWIRE_TAILNET_LIVE_DERP_VERIFY")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let tls_config = || {
        if verify {
            super::webpki_tls_config()
        } else {
            super::insecure_tls_config_for_tests()
        }
    };

    let mut rng = OsRng;
    let a_priv = NodePrivate::generate(&mut rng);
    let b_priv = NodePrivate::generate(&mut rng);
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let mut a = super::connect_tls(&addr, &host, tls_config(), a_priv, &mut rng)
        .await
        .expect("client A connects to live DERP TLS endpoint");
    let mut b = super::connect_tls(&addr, &host, tls_config(), b_priv, &mut rng)
        .await
        .expect("client B connects to live DERP TLS endpoint");

    assert_eq!(a.public_key().as_bytes(), a_pub.as_bytes());
    assert_eq!(
        a.server_public_key().as_bytes(),
        b.server_public_key().as_bytes(),
        "both clients see the same live DERP server key"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;

    let payload = b"relayed through live DERP TLS".to_vec();
    a.send(&b_pub, &payload)
        .await
        .expect("client A sends to client B over live DERP");

    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match b.recv().await.unwrap() {
                ReceivedMessage::Packet { source, data } => {
                    assert_eq!(source.as_bytes(), a_pub.as_bytes(), "src is A");
                    return data;
                }
                ReceivedMessage::ServerInfo
                | ReceivedMessage::KeepAlive
                | ReceivedMessage::Health(_) => continue,
                other => panic!("unexpected frame on B: {other:?}"),
            }
        }
    })
    .await
    .expect("client B receives live DERP packet within timeout");

    assert_eq!(received, payload, "B got exactly what A sent");
}
