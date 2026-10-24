//! The port must match Tailscale's own wire formats.
//!
//! `tests/fixtures/tailnet/tailscale_golden.json` is produced by Tailscale's Go
//! packages (`tests/contract/tailscalegolden`) at the pinned `tailscale.com`.
//! When a Tailscale upgrade changes a format, that Go test fails first; once
//! the golden is regenerated, this test shows which part of the port must
//! follow.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

use crate::derp::frame::{
    decode_header, encode_frame, FrameType, FRAME_HEADER_LEN, MAGIC as DERP_MAGIC, MAX_PACKET_SIZE,
    PROTOCOL_VERSION,
};
use crate::derp::{NodePrivate, NodePublic as DerpNodePublic};
use crate::disco::{
    self, AllocateUDPRelayEndpointRequest, AllocateUDPRelayEndpointResponse, BindUDPRelayEndpoint,
    BindUDPRelayEndpointAnswer, BindUDPRelayEndpointChallenge, BindUDPRelayEndpointCommon,
    CallMeMaybe, CallMeMaybeVia, DiscoPrivate, Message, Ping, Pong, UDPRelayEndpoint,
};
use crate::node::{DiscoPublic, NodePublic};
use crate::stun::{parse_binding_response, BindingRequest};
use crate::udp_relay::{
    decode_packet, encode_control_packet, encode_data_packet, encode_disco_packet, RelayPacket,
};

const GOLDEN: &str = include_str!("../../../tests/fixtures/tailnet/tailscale_golden.json");

#[derive(Deserialize)]
struct Golden {
    version: u32,
    tailscale: ModuleInfo,
    keys: Keys,
    derp: Derp,
    disco: Disco,
    stun: Stun,
    geneve: Vec<GeneveCase>,
}

#[derive(Deserialize)]
struct ModuleInfo {
    module: String,
    version: String,
}

#[derive(Deserialize)]
struct KeyPair {
    private_hex: String,
    public_hex: String,
    public_text: String,
}

#[derive(Deserialize)]
struct Keys {
    node_a: KeyPair,
    node_b: KeyPair,
    disco_a: KeyPair,
    disco_b: KeyPair,
}

#[derive(Deserialize)]
struct FrameCase {
    name: String,
    #[serde(rename = "type")]
    frame_type: u8,
    payload_hex: String,
    frame_hex: String,
}

#[derive(Deserialize)]
struct SealedCase {
    name: String,
    from: String,
    to: String,
    plaintext_hex: String,
    sealed_hex: String,
}

#[derive(Deserialize)]
struct Derp {
    magic_hex: String,
    protocol_version: i32,
    frame_header_len: usize,
    max_packet_size: usize,
    magic_ip_addr: String,
    frame_types: std::collections::BTreeMap<String, u8>,
    frames: Vec<FrameCase>,
    sealed: Vec<SealedCase>,
}

#[derive(Deserialize)]
struct DiscoCase {
    name: String,
    #[serde(rename = "type")]
    message_type: u8,
    #[serde(default)]
    tx_id_hex: String,
    #[serde(default)]
    node_key_hex: String,
    #[serde(default)]
    padding: usize,
    #[serde(default)]
    src: String,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    vni: u32,
    #[serde(default)]
    generation: u32,
    #[serde(default)]
    remote_key_hex: String,
    #[serde(default)]
    challenge_hex: String,
    #[serde(default)]
    client_disco_hex: Vec<String>,
    #[serde(default)]
    server_disco_hex: String,
    #[serde(default)]
    lamport_id: u64,
    #[serde(default)]
    bind_lifetime_ns: u64,
    #[serde(default)]
    steady_state_lifetime_ns: u64,
    payload_hex: String,
}

#[derive(Deserialize)]
struct SealedDisco {
    name: String,
    from: String,
    to: String,
    payload_hex: String,
    packet_hex: String,
}

#[derive(Deserialize)]
struct Disco {
    magic_hex: String,
    nonce_len: usize,
    messages: Vec<DiscoCase>,
    sealed: Vec<SealedDisco>,
}

#[derive(Deserialize)]
struct StunCase {
    tx_id_hex: String,
    #[serde(default)]
    addr: String,
    packet_hex: String,
}

#[derive(Deserialize)]
struct Stun {
    request: StunCase,
    responses: Vec<StunCase>,
}

#[derive(Deserialize)]
struct GeneveCase {
    name: String,
    vni: u32,
    control: bool,
    protocol: u16,
    header_hex: String,
}

fn golden() -> Golden {
    let g: Golden = serde_json::from_str(GOLDEN).expect("tailscale golden parses");
    assert_eq!(g.version, 1);
    assert_eq!(g.tailscale.module, "tailscale.com");
    assert!(!g.tailscale.version.is_empty());
    g
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn raw32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn raw<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("fixed-size hex")
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("socket address")
}

impl Keys {
    fn pair(&self, name: &str) -> &KeyPair {
        match name {
            "node_a" => &self.node_a,
            "node_b" => &self.node_b,
            "disco_a" => &self.disco_a,
            "disco_b" => &self.disco_b,
            other => panic!("unknown key {other}"),
        }
    }
}

#[test]
fn keys_derive_and_encode_like_tailscale() {
    let g = golden();
    for pair in [&g.keys.node_a, &g.keys.node_b] {
        let private = NodePrivate::from_raw(raw32(&pair.private_hex));
        assert_eq!(private.public().as_bytes(), &raw32(&pair.public_hex));
        let public = NodePublic::from_raw(raw32(&pair.public_hex));
        assert_eq!(
            serde_json::to_string(&public).unwrap(),
            format!("\"{}\"", pair.public_text)
        );
        let parsed: NodePublic =
            serde_json::from_str(&format!("\"{}\"", pair.public_text)).unwrap();
        assert_eq!(parsed, public);
    }
    for pair in [&g.keys.disco_a, &g.keys.disco_b] {
        let private = DiscoPrivate::from_raw(raw32(&pair.private_hex));
        assert_eq!(private.public().as_bytes(), &raw32(&pair.public_hex));
        let public = DiscoPublic::from_raw(raw32(&pair.public_hex));
        assert_eq!(
            serde_json::to_string(&public).unwrap(),
            format!("\"{}\"", pair.public_text)
        );
    }
}

#[test]
fn derp_constants_and_frames_match_tailscale() {
    let g = golden();
    assert_eq!(DERP_MAGIC, unhex(&g.derp.magic_hex).as_slice());
    assert_eq!(PROTOCOL_VERSION, g.derp.protocol_version);
    assert_eq!(FRAME_HEADER_LEN, g.derp.frame_header_len);
    assert_eq!(MAX_PACKET_SIZE, g.derp.max_packet_size);
    // magicsock reports DERP paths as <magic IP>:<region>.
    assert_eq!(
        crate::direct_udp::derp_magic_addr(7),
        SocketAddr::new(g.derp.magic_ip_addr.parse().unwrap(), 7)
    );
    for (name, value) in &g.derp.frame_types {
        let t = FrameType::from_u8(*value);
        assert!(
            !matches!(t, FrameType::Unknown(_)),
            "DERP frame type {name} ({value:#04x}) is unknown to the port"
        );
        assert_eq!(t.to_u8(), *value, "{name}");
    }
    for case in &g.derp.frames {
        let payload = unhex(&case.payload_hex);
        let frame = unhex(&case.frame_hex);
        assert_eq!(
            encode_frame(FrameType::from_u8(case.frame_type), &payload),
            frame,
            "{}",
            case.name
        );
        let (t, len) = decode_header(&frame).unwrap();
        assert_eq!(
            (t.to_u8(), len as usize),
            (case.frame_type, payload.len()),
            "{}",
            case.name
        );
    }
}

#[test]
fn derp_opens_tailscale_sealed_client_info() {
    let g = golden();
    assert!(!g.derp.sealed.is_empty());
    for case in &g.derp.sealed {
        let to = NodePrivate::from_raw(raw32(&g.keys.pair(&case.to).private_hex));
        let from = DerpNodePublic::from_raw(raw32(&g.keys.pair(&case.from).public_hex));
        let opened = to.open_from(&from, &unhex(&case.sealed_hex)).unwrap();
        assert_eq!(opened, unhex(&case.plaintext_hex), "{}", case.name);
    }
}

fn relay_endpoint(case: &DiscoCase) -> UDPRelayEndpoint {
    UDPRelayEndpoint {
        server_disco: DiscoPublic::from_raw(raw32(&case.server_disco_hex)),
        client_disco: [
            DiscoPublic::from_raw(raw32(&case.client_disco_hex[0])),
            DiscoPublic::from_raw(raw32(&case.client_disco_hex[1])),
        ],
        lamport_id: case.lamport_id,
        vni: case.vni,
        bind_lifetime: Duration::from_nanos(case.bind_lifetime_ns),
        steady_state_lifetime: Duration::from_nanos(case.steady_state_lifetime_ns),
        addr_ports: case.endpoints.iter().map(|e| addr(e)).collect(),
    }
}

fn bind_common(case: &DiscoCase) -> BindUDPRelayEndpointCommon {
    BindUDPRelayEndpointCommon {
        vni: case.vni,
        generation: case.generation,
        remote_key: DiscoPublic::from_raw(raw32(&case.remote_key_hex)),
        challenge: raw32(&case.challenge_hex),
    }
}

/// The port's message for a golden case, built from the case's inputs.
fn message(case: &DiscoCase) -> Message {
    match case.name.as_str() {
        "ping" | "ping_with_node_key" | "ping_padded" => Message::Ping(Ping {
            tx_id: raw(&case.tx_id_hex),
            node_key: (!case.node_key_hex.is_empty())
                .then(|| NodePublic::from_raw(raw32(&case.node_key_hex))),
            padding: case.padding,
        }),
        "pong_v4" | "pong_v6" => Message::Pong(Pong {
            tx_id: raw(&case.tx_id_hex),
            src: addr(&case.src),
        }),
        "call_me_maybe" => Message::CallMeMaybe(CallMeMaybe {
            endpoints: case.endpoints.iter().map(|e| addr(e)).collect(),
        }),
        "bind_udp_relay_endpoint" => Message::BindUDPRelayEndpoint(BindUDPRelayEndpoint {
            common: bind_common(case),
        }),
        "bind_udp_relay_endpoint_challenge" => {
            Message::BindUDPRelayEndpointChallenge(BindUDPRelayEndpointChallenge {
                common: bind_common(case),
            })
        }
        "bind_udp_relay_endpoint_answer" => {
            Message::BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer {
                common: bind_common(case),
            })
        }
        "allocate_udp_relay_endpoint_request" => {
            Message::AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest {
                client_disco: [
                    DiscoPublic::from_raw(raw32(&case.client_disco_hex[0])),
                    DiscoPublic::from_raw(raw32(&case.client_disco_hex[1])),
                ],
                generation: case.generation,
            })
        }
        "allocate_udp_relay_endpoint_response" => {
            Message::AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse {
                generation: case.generation,
                endpoint: relay_endpoint(case),
            })
        }
        "call_me_maybe_via" => Message::CallMeMaybeVia(CallMeMaybeVia {
            endpoint: relay_endpoint(case),
        }),
        other => panic!("golden disco case {other} has no port mapping; add one"),
    }
}

#[test]
fn disco_messages_marshal_and_parse_like_tailscale() {
    let g = golden();
    assert_eq!(disco::MAGIC, unhex(&g.disco.magic_hex).as_slice());
    assert_eq!(disco::NONCE_LEN, g.disco.nonce_len);
    for case in &g.disco.messages {
        let payload = unhex(&case.payload_hex);
        assert_eq!(payload[0], case.message_type, "{} type byte", case.name);
        assert_eq!(message(case).marshal(), payload, "{} marshal", case.name);
        let parsed =
            Message::parse(&payload).unwrap_or_else(|e| panic!("{} parse: {e}", case.name));
        assert_eq!(parsed.marshal(), payload, "{} parse round trip", case.name);
    }
}

#[test]
fn disco_opens_tailscale_sealed_packets() {
    let g = golden();
    assert!(!g.disco.sealed.is_empty());
    for case in &g.disco.sealed {
        let packet = unhex(&case.packet_hex);
        assert!(disco::looks_like_wrapper(&packet), "{}", case.name);
        let to = DiscoPrivate::from_raw(raw32(&g.keys.pair(&case.to).private_hex));
        let opened = to.open(&packet).unwrap();
        assert_eq!(
            opened.sender.as_bytes(),
            &raw32(&g.keys.pair(&case.from).public_hex),
            "{} sender",
            case.name
        );
        assert_eq!(
            opened.message.marshal(),
            unhex(&case.payload_hex),
            "{}",
            case.name
        );
    }
}

#[test]
fn stun_matches_tailscale() {
    let g = golden();
    let request = BindingRequest::with_transaction_id(raw(&g.stun.request.tx_id_hex));
    assert_eq!(request.packet, unhex(&g.stun.request.packet_hex));
    assert!(!g.stun.responses.is_empty());
    for case in &g.stun.responses {
        let got = parse_binding_response(&unhex(&case.packet_hex), raw(&case.tx_id_hex)).unwrap();
        assert_eq!(got, addr(&case.addr));
    }
}

#[test]
fn udp_relay_geneve_headers_match_tailscale() {
    let g = golden();
    let payload = [0xaa_u8; 4];
    for case in &g.geneve {
        let header = unhex(&case.header_hex);
        let packet = match case.name.as_str() {
            "control_disco" => encode_control_packet(case.vni, &payload),
            "relay_disco" => encode_disco_packet(case.vni, &payload),
            "relay_wireguard" => encode_data_packet(case.vni, &payload),
            other => panic!("golden Geneve case {other} has no port mapping; add one"),
        };
        assert_eq!(&packet[..header.len()], header.as_slice(), "{}", case.name);
        let decoded = decode_packet(&packet).unwrap();
        assert_eq!(decoded.vni(), case.vni, "{}", case.name);
        let kind_matches = match decoded {
            RelayPacket::Control { .. } => case.control,
            RelayPacket::Disco { .. } => !case.control && case.protocol == 0x7a11,
            RelayPacket::Data { .. } => !case.control && case.protocol == 0x7a12,
        };
        assert!(
            kind_matches,
            "{} decoded as the wrong packet kind",
            case.name
        );
    }
}
