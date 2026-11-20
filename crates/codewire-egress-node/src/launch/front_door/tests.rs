//! Both ends of the control socket in this process: the supervisor's half
//! here, and the front door's own `run` with a stand-in for confinement,
//! which a test process must not apply to itself. `tests/launch.rs` starts
//! the real, confined process.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_egress_front_door::SignedLeaves;
use codewire_egress_policy::handoff::{
    HANDOFF_ROLE_TAG, HANDOFF_VERSION, HandoffSender, InterceptedStreamHeader,
};
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use super::*;
use crate::front_door::FrontDoorProcessError;
use crate::front_door::protocol::{FrontDoorStage, LeafRefusal};

const POD: Uuid = Uuid::from_u128(0x0b8f_6a52_0f6c_4a59_9f43_1b1f_0c3a_9e01);
const BOUND: &str = "api.openai.com";
const WAIT: Duration = Duration::from_secs(30);

fn spec() -> FrontDoorSpec {
    FrontDoorSpec {
        environment_id: Uuid::from_u128(0x6f1c_2a0e_8b4d_4e2a_9c3f_1d2e_3f4a_5b6c),
        generation: 2,
        intercepts: InterceptSet::new([
            InterceptBinding::new(BOUND, 443).unwrap(),
            InterceptBinding::new("api.anthropic.com", 443).unwrap(),
        ])
        .unwrap(),
    }
}

fn deadline() -> Instant {
    Instant::now() + WAIT
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("bounded test step")
}

/// A front door running in this process: the supervisor's end of its
/// control socket, its task, and whether it has confined itself.
struct Running {
    control: ControlChannel,
    sessions: ControlChannel,
    door: JoinHandle<Result<(), FrontDoorProcessError>>,
    confined: Arc<AtomicBool>,
}

impl Running {
    fn start() -> Self {
        let (supervisor, child) = stream_pair().unwrap();
        let (sessions, sessions_child) = stream_pair().unwrap();
        let confined = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&confined);
        let door = tokio::spawn(crate::front_door::run(
            ControlChannel::new(child).unwrap(),
            ControlChannel::new(sessions_child).unwrap(),
            POD,
            move || {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        ));
        Self {
            control: ControlChannel::new(supervisor).unwrap(),
            sessions: ControlChannel::new(sessions).unwrap(),
            door,
            confined,
        }
    }

    fn confined(&self) -> bool {
        self.confined.load(Ordering::SeqCst)
    }
}

/// The credential service's signer, standing in with its own CA.
struct Signer {
    certificate: Certificate,
    key: KeyPair,
}

/// The front door's public key as the signer sees it: its SPKI.
struct Spki(Vec<u8>);

impl PublicKeyData for Spki {
    fn der_bytes(&self) -> &[u8] {
        // A P-256 SPKI ends with the 65-byte uncompressed point.
        &self.0[self.0.len() - 65..]
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl Signer {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "test signer");
        let certificate = params.self_signed(&key).unwrap();
        Self { certificate, key }
    }

    fn leaf(&self, spki: &[u8], host: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::hours(1);
        params
            .signed_by(&Spki(spki.to_vec()), &self.certificate, &self.key)
            .unwrap()
            .der()
            .to_vec()
    }

    /// A TLS client on `stream` that trusts only this signer.
    async fn connect(&self, stream: tokio::net::UnixStream) -> std::io::Result<()> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.certificate.der().to_vec()))
            .unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        bounded(
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(BOUND).unwrap(), stream),
        )
        .await
        .map(drop)
    }
}

/// The broker's side of the hand-off socket.
struct Broker {
    sender: HandoffSender,
    next_stream: u64,
}

impl Broker {
    /// The pair's two ends: the front door's, and the broker's, which sends
    /// its role tag first as the broker does.
    fn new() -> (OwnedFd, Self) {
        let (door_end, broker_end) = stream_pair().unwrap();
        let mut sender = HandoffSender::new(broker_end).unwrap();
        sender.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
        (
            door_end,
            Self {
                sender,
                next_stream: 1,
            },
        )
    }

    /// Hands over a stream for `host` on 443, stamped `identity` as a hosted
    /// broker stamps its Pod's; the guest's end.
    fn hand_over(&mut self, host: &str, identity: Uuid) -> tokio::net::UnixStream {
        let (guest, handed) = std::os::unix::net::UnixStream::pair().unwrap();
        let header = InterceptedStreamHeader {
            version: HANDOFF_VERSION,
            hostname: host.to_owned(),
            aliases: Vec::new(),
            port: 443,
            destination_ip: std::net::Ipv4Addr::new(192, 0, 2, 1),
            stream_id: self.next_stream,
            environment_id: identity.to_string(),
        };
        self.next_stream += 1;
        self.sender
            .send_intercepted_stream(&header, handed.as_fd())
            .unwrap();
        guest.set_nonblocking(true).unwrap();
        tokio::net::UnixStream::from_std(guest).unwrap()
    }
}

/// The image check runs while the child waits unconfined; a failed one is
/// the end of the start, and the child never confines or makes a key.
#[tokio::test]
async fn a_front_door_whose_image_check_fails_is_never_told_to_confine() {
    let mut running = Running::start();
    let confined = Arc::clone(&running.confined);
    let checked = prepare(&mut running.control, &spec(), deadline(), || {
        assert!(!confined.load(Ordering::SeqCst));
        Err(StartError::Image)
    })
    .await;
    assert_eq!(checked, Err(StartError::Image));

    // The supervisor kills it; here, its control socket closes.
    drop(running.control);
    let ended = bounded(running.door).await.unwrap();
    assert!(
        matches!(
            ended,
            Err(FrontDoorProcessError::Startup(FrontDoorStage::Admission))
        ),
        "{ended:?}"
    );
    assert!(!running.confined.load(Ordering::SeqCst));
}

/// No leaf, no handshake: a bound host fails closed until the signer's leaf
/// for the front door's own key is installed, and a leaf for any other key
/// changes nothing.
#[tokio::test]
async fn a_bound_host_is_served_only_with_a_leaf_signed_for_the_front_doors_key() {
    let mut running = Running::start();
    let confined = Arc::clone(&running.confined);
    let spki = prepare(&mut running.control, &spec(), deadline(), || {
        assert!(!confined.load(Ordering::SeqCst), "checked before confining");
        Ok(())
    })
    .await
    .unwrap();
    assert!(running.confined());
    let (door_end, mut broker) = Broker::new();
    take_handoff(&mut running.control, door_end, deadline())
        .await
        .unwrap();
    let signer = Signer::new();

    assert!(signer.connect(broker.hand_over(BOUND, POD)).await.is_err());

    let another = SignedLeaves::generate().unwrap();
    assert_eq!(
        install(
            &mut running.control,
            &[signer.leaf(another.public_key_spki(), BOUND)]
        )
        .await,
        Err(StartError::Leaves(LeafRefusal::Invalid))
    );
    assert!(signer.connect(broker.hand_over(BOUND, POD)).await.is_err());

    install(&mut running.control, &[signer.leaf(&spki, BOUND)])
        .await
        .unwrap();
    signer
        .connect(broker.hand_over(BOUND, POD))
        .await
        .expect("a handshake with the signer's leaf");

    // A refused install keeps the leaf it had.
    assert_eq!(
        install(&mut running.control, &[b"not a certificate".to_vec()]).await,
        Err(StartError::Leaves(LeafRefusal::Invalid))
    );
    signer
        .connect(broker.hand_over(BOUND, POD))
        .await
        .expect("the previous leaf still serves");

    // Only its own Pod's broker is heard, and only for its bindings.
    assert!(
        signer
            .connect(broker.hand_over(BOUND, Uuid::from_u128(9)))
            .await
            .is_err()
    );
    assert!(
        signer
            .connect(broker.hand_over("chatgpt.com", POD))
            .await
            .is_err()
    );

    // Its supervisor gone, it ends.
    drop(running.control);
    let ended = bounded(running.door).await.unwrap();
    assert!(
        matches!(ended, Err(FrontDoorProcessError::Ended(_))),
        "{ended:?}"
    );
}

/// A hand-off end that does not open with the broker's role tag is not the
/// broker's: the front door refuses it and never serves.
#[tokio::test]
async fn a_hand_off_without_the_brokers_role_tag_is_refused() {
    let mut running = Running::start();
    prepare(&mut running.control, &spec(), deadline(), || Ok(()))
        .await
        .unwrap();
    let (door_end, impostor) = stream_pair().unwrap();
    rustix::io::write(&impostor, b"\x01\x00X").unwrap();
    assert_eq!(
        take_handoff(&mut running.control, door_end, deadline()).await,
        Err(StartError::FrontDoor(FrontDoorStage::Handoff))
    );
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Err(FrontDoorProcessError::Startup(FrontDoorStage::Handoff))
    ));
}

/// A key that is not P-256 is never taken as the front door's, so it is
/// never relayed to the signer: the start fails at the node.
#[tokio::test]
async fn a_front_door_whose_key_is_not_p256_does_not_start() {
    let (supervisor, child) = stream_pair().unwrap();
    let mut control = ControlChannel::new(supervisor).unwrap();
    let mut child = ControlChannel::new(child).unwrap();
    let door = tokio::spawn(async move {
        child.receive(MAX_CONTROL_MESSAGE, 0).await.unwrap();
        child.send(PREPARED, &[]).await.unwrap();
        let (confine, _) = child.receive(MAX_CONTROL_MESSAGE, 0).await.unwrap();
        assert_eq!(confine, CONFINE);
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let ready = crate::front_door::protocol::ready_message(&p384.public_key_der());
        child.send(&ready, &[]).await.unwrap();
        child
    });
    assert_eq!(
        prepare(&mut control, &spec(), deadline(), || Ok(())).await,
        Err(StartError::Bootstrap)
    );
    bounded(door).await.unwrap();
}

/// Bindings it cannot serve stop the front door before it confines.
#[tokio::test]
async fn a_front_door_refuses_bindings_off_443_before_it_confines() {
    let mut running = Running::start();
    let off_443 = FrontDoorSpec {
        intercepts: InterceptSet::new([InterceptBinding::new(BOUND, 8443).unwrap()]).unwrap(),
        ..spec()
    };
    let started = prepare(&mut running.control, &off_443, deadline(), || Ok(())).await;
    assert_eq!(
        started,
        Err(StartError::FrontDoor(FrontDoorStage::Bindings))
    );
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Err(FrontDoorProcessError::Startup(FrontDoorStage::Bindings))
    ));
    assert!(!running.confined.load(Ordering::SeqCst));
}

/// A front door brought to serving, and its broker.
async fn serving() -> (Running, Broker) {
    let mut running = Running::start();
    prepare(&mut running.control, &spec(), deadline(), || Ok(()))
        .await
        .unwrap();
    let (door_end, broker) = Broker::new();
    take_handoff(&mut running.control, door_end, deadline())
        .await
        .unwrap();
    (running, broker)
}

/// A socket pair whose far end opens with `tag`, as the supervisor writes
/// it; our end.
fn tagged(tag: Option<u8>) -> (OwnedFd, tokio::net::UnixStream) {
    use std::io::Write as _;
    let (ours, theirs) = stream_pair().unwrap();
    let mut ours = std::os::unix::net::UnixStream::from(ours);
    if let Some(tag) = tag {
        ours.write_all(&[tag]).unwrap();
    }
    ours.set_nonblocking(true).unwrap();
    (theirs, tokio::net::UnixStream::from_std(ours).unwrap())
}

/// The front door takes a session only as a connected stream socket that
/// opens with the session role tag; anything else is answered with its code
/// and closed. A frame other than a session's ends the front door.
#[tokio::test]
async fn a_session_is_admitted_only_as_a_tagged_stream_socket() {
    use codewire_egress_front_door_bridge::FRONT_DOOR_SESSION_ROLE_TAG;
    use tokio::io::AsyncReadExt as _;

    let (mut running, _broker) = serving().await;
    let (theirs, _ours) = tagged(Some(FRONT_DOOR_SESSION_ROLE_TAG));
    hand_session(&mut running.sessions, theirs, WAIT)
        .await
        .expect("a tagged session is served");

    for (tag, why) in [
        (Some(b'X'), SessionRefusal::Tag),
        (None, SessionRefusal::Tag),
    ] {
        let (theirs, mut ours) = tagged(tag);
        assert_eq!(
            hand_session(&mut running.sessions, theirs, WAIT).await,
            Err(HandError::Dropped(why)),
            "{tag:?}"
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            bounded(ours.read(&mut byte)).await.unwrap(),
            0,
            "a dropped session is closed"
        );
    }
    let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert_eq!(
        hand_session(&mut running.sessions, OwnedFd::from(datagram), WAIT).await,
        Err(HandError::Dropped(SessionRefusal::Kind))
    );

    // A frame other than a session's ends the front door, even with one
    // well-formed socket beside it.
    let (theirs, _ours) = tagged(Some(FRONT_DOOR_SESSION_ROLE_TAG));
    running
        .sessions
        .send(b"CWHF1 other\n", &[theirs.as_fd()])
        .await
        .unwrap();
    let ended = bounded(running.door).await.unwrap();
    assert!(
        matches!(ended, Err(FrontDoorProcessError::Ended(_))),
        "{ended:?}"
    );
}

/// Its sessions socket gone, the front door ends rather than serving on
/// with every request failing closed.
#[tokio::test]
async fn a_front_door_whose_sessions_socket_closes_ends() {
    let (running, _broker) = serving().await;
    drop(running.sessions);
    let ended = bounded(running.door).await.unwrap();
    assert!(
        matches!(ended, Err(FrontDoorProcessError::Ended(_))),
        "{ended:?}"
    );
}
