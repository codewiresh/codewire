use super::binding::{BINDING_LEN, Binding, Control, Profile, Role, Status};
use super::{invalid, packet, product_network};
use async_trait::async_trait;
use codewire_egress_policy::{CompiledPolicy, EgressRequest, RouteClass};
use codewire_netstack::DnsQuestion;
use codewire_vmm_guest_probe::NetworkKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

fn document(role: Role) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2, "kind": "product-network",
        "role": if role == Role::Guest { "guest" } else { "service" },
        "vmID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "generation": 7,
        "runNonce": "11".repeat(32), "networkKey": "22".repeat(32),
        "statusKey": "33".repeat(32),
    })
}

fn sealed(document: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(document).unwrap();
    bytes.resize(BINDING_LEN, 0);
    bytes
}

fn binding(role: Role) -> Binding {
    Binding::decode_for(&sealed(&document(role)), role, Profile::ProductNetwork).unwrap()
}

#[test]
fn binding_modes_cross_reject_including_null_kind_and_duplicate_fields() {
    let product = document(Role::Guest);
    let mut old = product.clone();
    old.as_object_mut().unwrap().remove("kind");
    old["schemaVersion"] = serde_json::json!(1);
    assert!(Binding::decode(&sealed(&old), Role::Guest).is_ok());
    assert!(Binding::decode(&sealed(&product), Role::Guest).is_err());
    assert!(Binding::decode_for(&sealed(&old), Role::Guest, Profile::ProductNetwork).is_err());
    old["kind"] = serde_json::Value::Null;
    assert!(Binding::decode(&sealed(&old), Role::Guest).is_err());
    for field in [
        "schemaVersion",
        "kind",
        "role",
        "vmID",
        "generation",
        "runNonce",
        "networkKey",
        "statusKey",
    ] {
        let mut missing = product.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            Binding::decode_for(&sealed(&missing), Role::Guest, Profile::ProductNetwork).is_err(),
            "{field}"
        );
        let mut duplicate = serde_json::to_string(&product).unwrap();
        duplicate.insert_str(1, &format!("{field:?}:{},", product[field]));
        let mut bytes = duplicate.into_bytes();
        bytes.resize(BINDING_LEN, 0);
        assert!(
            Binding::decode_for(&bytes, Role::Guest, Profile::ProductNetwork).is_err(),
            "{field}"
        );
    }
}

#[test]
fn product_binding_preserves_exact_identity_keys_and_padding() {
    for (field, value) in [
        ("schemaVersion", serde_json::json!(1)),
        ("kind", serde_json::json!("console-pair")),
        ("kind", serde_json::Value::Null),
        ("role", serde_json::json!("service")),
        ("generation", serde_json::json!(0)),
        ("vmID", serde_json::json!(Uuid::nil().to_string())),
        ("runNonce", serde_json::json!("00".repeat(32))),
        ("networkKey", serde_json::json!("33".repeat(32))),
        ("statusKey", serde_json::json!("AA".repeat(32))),
        ("destination", serde_json::json!("127.0.0.1:443")),
    ] {
        let mut bad = document(Role::Guest);
        bad[field] = value;
        assert!(
            Binding::decode_for(&sealed(&bad), Role::Guest, Profile::ProductNetwork).is_err(),
            "{field}"
        );
    }
    let mut bytes = sealed(&document(Role::Guest));
    assert!(
        Binding::decode_for(
            &bytes[..BINDING_LEN - 1],
            Role::Guest,
            Profile::ProductNetwork
        )
        .is_err()
    );
    bytes[BINDING_LEN - 1] = 1;
    assert!(Binding::decode_for(&bytes, Role::Guest, Profile::ProductNetwork).is_err());
}

#[test]
fn controls_and_status_are_cryptographically_mode_separated() {
    let product = binding(Role::Guest);
    let mut old_document = document(Role::Guest);
    old_document.as_object_mut().unwrap().remove("kind");
    old_document["schemaVersion"] = serde_json::json!(1);
    let old = Binding::decode(&sealed(&old_document), Role::Guest).unwrap();
    for code in [
        Control::Start,
        Control::Cancel,
        Control::ClosePacket,
        Control::ObserveEof,
        Control::PowerOff,
    ] {
        let frame = product.test_control(code, 1);
        assert_eq!(product.control(&frame, 1).unwrap(), code);
        assert!(product.control(&frame, 2).is_err());
        assert!(old.control(&frame, 1).is_err());
        assert!(product.control(&old.test_control(code, 1), 1).is_err());
        for offset in [0, 8, 9, 10, 16, 32, 40, 72, 80, 95, 96, 127] {
            let mut bad = frame;
            bad[offset] ^= 1;
            assert!(product.control(&bad, 1).is_err());
        }
        let mut changed_magic = old.test_control(code, 1);
        changed_magic[..8].copy_from_slice(b"CWPNCT1\0");
        assert!(product.control(&changed_magic, 1).is_err());
    }
    assert!(
        product
            .control(&product.status(Status::PortsReady, 1), 1)
            .is_err()
    );
}

#[test]
fn four_child_reap_metadata_and_new_status_codes_are_authenticated() {
    let service = binding(Role::Service);
    let frame = service.product_reaped(11, [9472, 0, 18432, 0]).unwrap();
    assert_eq!(&frame[..10], b"CWPNST1\0\x02\x0a");
    for (index, value) in [9472_i32, 0, 18432, 0].into_iter().enumerate() {
        assert_eq!(&frame[80 + index * 4..84 + index * 4], value.to_le_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x33; 32]).unwrap();
    mac.update(b"codewire-product-network-status-v1\0");
    mac.update(&frame[..96]);
    mac.verify_slice(&frame[96..]).unwrap();
    assert!(service.reaped(1, 9472, 0).is_err());
    assert!(binding(Role::Guest).product_reaped(1, [0; 4]).is_err());
    for (code, expected) in [
        (Status::TopologyReady, 14),
        (Status::EndpointReady, 15),
        (Status::BrokerPrepared, 16),
        (Status::BrokerReady, 17),
        (Status::WorkerBrokerReady, 18),
        (Status::EndpointCompleted, 19),
    ] {
        let frame = service.status(code, 1);
        assert_eq!(frame[9], expected);
        assert_eq!(&frame[80..96], &[0; 16]);
    }
}

#[test]
fn fixed_numeric_peer_is_allowed_without_weakening_baseline() {
    let policy = CompiledPolicy::developer_baseline();
    let accepted = product_network::destination();
    for (address, port, allowed) in [
        (accepted.ip(), accepted.port(), true),
        ("127.0.0.1".parse().unwrap(), 443, false),
        ("198.51.100.7".parse().unwrap(), 443, false),
        (accepted.ip(), 4242, false),
    ] {
        let request = EgressRequest::tcp(address, port, None, RouteClass::General).unwrap();
        assert_eq!(policy.evaluate(&request).is_allowed(), allowed);
    }
    let dns = EgressRequest::dns_query("console-pair.test", RouteClass::General).unwrap();
    assert!(!policy.evaluate(&dns).is_allowed());
}

/// Unit-only transcript peer. Native acceptance must use the distinct real
/// broker process/SystemTcpConnector; this only verifies numeric guest framing.
struct TranscriptBroker {
    connected: AtomicBool,
    dns_calls: AtomicUsize,
}

#[async_trait]
impl crate::network_worker::EgressBroker for TranscriptBroker {
    async fn authorize_tcp(&self, flow: crate::network_worker::TcpFlow) -> io::Result<()> {
        if flow.destination != product_network::destination()
            || flow.source.ip() != "192.0.2.2".parse::<std::net::IpAddr>().unwrap()
        {
            return Err(invalid());
        }
        Ok(())
    }

    async fn connect_tcp(
        &self,
        flow: crate::network_worker::TcpFlow,
    ) -> io::Result<crate::network_worker::BoxedBrokerStream> {
        self.authorize_tcp(flow).await?;
        if self.connected.swap(true, Ordering::SeqCst) {
            return Err(invalid());
        }
        let (stream, mut peer) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let mut request = [0_u8; product_network::PAYLOAD_LEN];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(request, product_network::payload(false));
            let mut extra = [0];
            assert_eq!(peer.read(&mut extra).await.unwrap(), 0);
            peer.write_all(&product_network::payload(true))
                .await
                .unwrap();
            peer.shutdown().await.unwrap();
        });
        Ok(Box::pin(stream))
    }

    async fn resolve_dns(
        &self,
        _: &DnsQuestion,
    ) -> io::Result<crate::network_worker::BrokerDnsAnswer> {
        self.dns_calls.fetch_add(1, Ordering::SeqCst);
        Err(invalid())
    }
}

#[tokio::test]
async fn numeric_guest_transcript_has_no_dns_and_matches_fixed_endpoint_bytes() {
    let identity = Uuid::from_u128(0xdddddddddddd4ddd8ddddddddddddddd);
    let key = || NetworkKey::from_derived_bytes([0x22; 32]).unwrap();
    let broker = Arc::new(TranscriptBroker {
        connected: AtomicBool::new(false),
        dns_calls: AtomicUsize::new(0),
    });
    let (host, mut guest) = tokio::io::duplex(64 * 1024);
    let host = tokio::spawn(crate::network_worker::run_host_session(
        host,
        key(),
        identity,
        7,
        broker.clone(),
        || Ok(()),
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        let session = packet::authenticate(&mut guest, key(), identity, 7)
            .await
            .unwrap();
        packet::traffic_for(&mut guest, session, Profile::ProductNetwork)
            .await
            .unwrap();
    })
    .await
    .expect("numeric packet transcript exceeded bound");
    assert!(broker.connected.load(Ordering::SeqCst));
    assert_eq!(broker.dns_calls.load(Ordering::SeqCst), 0);
    drop(guest);
    let error = tokio::time::timeout(Duration::from_secs(2), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.exit_code(), 37);
}
