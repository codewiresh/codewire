use std::time::Duration;

use tokio::net::TcpListener;
use uuid::Uuid;

use super::*;
use crate::hosted::hello::{
    PREFIX_LEN, TOKEN_LEN_LEN, VERSION_ANSWER, body_len, decode_body, decode_prefix, encode_answer,
};
use crate::{
    EgressTrust, NETWORK_GUEST_ACK_LEN, NetworkGuestAck, NetworkHostHello, NetworkHostReady,
    NetworkRole, NetworkSession, SessionLimits,
};

const POD: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
const TOKEN: &str = "egress-token-for-the-test";

/// What the fake cw-egress answers after reading the hello.
enum Reply {
    Good,
    WrongMagic,
    /// The version refusal, sent as cw-egress sends it: after the magic and
    /// the version, before the token is read.
    VersionRefused,
}

/// cw-egress's side for one stream: read the hello, answer with a nonce,
/// derive the same key and run the host's handshake. Returns the token and
/// nonce the guest sent.
async fn fake_egress(listener: TcpListener, answer: Reply) -> (String, [u8; NONCE_LEN]) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut prefix = [0_u8; PREFIX_LEN];
    stream.read_exact(&mut prefix).await.unwrap();
    let version = decode_prefix(&prefix).unwrap();
    assert_eq!(version, NETWORK_PROTOCOL_VERSION);
    if let Reply::VersionRefused = answer {
        stream.write_all(&VERSION_ANSWER).await.unwrap();
        return (String::new(), [0_u8; NONCE_LEN]);
    }
    let mut token_len = [0_u8; TOKEN_LEN_LEN];
    stream.read_exact(&mut token_len).await.unwrap();
    let mut body = vec![0_u8; body_len(&token_len).unwrap()];
    stream.read_exact(&mut body).await.unwrap();
    let hello = decode_body(version, &body).unwrap();
    let node_nonce = [7_u8; NONCE_LEN];
    let mut reply = encode_answer(&node_nonce);
    if let Reply::WrongMagic = answer {
        reply[0] ^= 0xff;
        stream.write_all(&reply).await.unwrap();
        return (hello.token.to_string(), hello.nonce);
    }
    stream.write_all(&reply).await.unwrap();
    let key = stream_key(&StreamKeyInput {
        token: &hello.token,
        guest_nonce: &hello.nonce,
        node_nonce: &node_nonce,
        pod_uid: POD,
    })
    .unwrap();
    let bound = SessionLimits::HOSTED.packet_bound();
    let session_nonce = [9_u8; 32];
    let host_hello = NetworkHostHello::new(POD, HOSTED_GENERATION, session_nonce, bound).unwrap();
    stream.write_all(&host_hello.encode(&key)).await.unwrap();
    let mut ack = [0_u8; NETWORK_GUEST_ACK_LEN];
    stream.read_exact(&mut ack).await.unwrap();
    NetworkGuestAck::decode(&ack, &key, &session_nonce, bound).unwrap();
    stream
        .write_all(&NetworkHostReady::new(session_nonce).unwrap().encode(&key))
        .await
        .unwrap();
    let mut session = NetworkSession::new(&key, &session_nonce, NetworkRole::Host, bound).unwrap();
    stream
        .write_all(
            &session
                .encode_egress_trust(&EgressTrust::Ca(vec![0x30; 32]))
                .unwrap(),
        )
        .await
        .unwrap();
    (hello.token.to_string(), hello.nonce)
}

/// A private folder for one test's token file, removed when dropped.
struct TokenDir(std::path::PathBuf);

impl Drop for TokenDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn connector(token: Option<&str>, bound: Duration) -> (PodConnector, TcpListener, TokenDir) {
    let directory = std::env::temp_dir().join(format!(
        "cw-egress-connector-{}-{}",
        std::process::id(),
        Uuid::from_bytes(random_nonce().unwrap()[..16].try_into().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let token_path = directory.join("token");
    if let Some(token) = token {
        // A projected token file ends with a newline; the connector trims it.
        std::fs::write(&token_path, format!("{token}\n")).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let std::net::SocketAddr::V4(stream_addr) = listener.local_addr().unwrap() else {
        unreachable!("an IPv4 listener has an IPv4 address");
    };
    let connector = PodConnector {
        stream_addr,
        token_path,
        pod_uid: POD,
        bound,
        // Loopback stands in for the Pod interface.
        interface: "lo",
    };
    (connector, listener, TokenDir(directory))
}

#[tokio::test]
async fn a_stream_is_opened_with_a_fresh_token_and_nonce_and_the_derived_key() {
    let (connector, listener, _directory) = connector(Some(TOKEN), Duration::from_secs(10)).await;
    let egress = tokio::spawn(fake_egress(listener, Reply::Good));
    let session = connector.connect().await.unwrap();
    assert_eq!(session.egress_trust, EgressTrust::Ca(vec![0x30; 32]));
    let (token, first_nonce) = egress.await.unwrap();
    assert_eq!(token, TOKEN);

    // The next stream reads the token again and draws a new nonce.
    std::fs::write(&connector.token_path, "rotated-token\n").unwrap();
    let listener = TcpListener::bind(connector.stream_addr).await.unwrap();
    let egress = tokio::spawn(fake_egress(listener, Reply::Good));
    connector.connect().await.unwrap();
    let (token, second_nonce) = egress.await.unwrap();
    assert_eq!(token, "rotated-token");
    assert_ne!(first_nonce, second_nonce);
}

#[tokio::test]
async fn a_missing_token_or_a_bad_answer_opens_no_stream() {
    let (missing, _listener, _directory) = connector(None, Duration::from_secs(10)).await;
    assert!(matches!(
        missing.connect().await,
        Err(ConnectError::Token(_))
    ));

    let (connector, listener, _directory) = connector(Some(TOKEN), Duration::from_secs(10)).await;
    let egress = tokio::spawn(fake_egress(listener, Reply::WrongMagic));
    assert!(matches!(
        connector.connect().await,
        Err(ConnectError::Answer(_))
    ));
    egress.await.unwrap();
}

/// A cw-egress that speaks other session versions says so before it reads
/// the token, and the connector reports both ranges and opens no stream.
#[tokio::test]
async fn a_version_refusal_opens_no_stream_and_names_both_ranges() {
    let (connector, listener, _directory) = connector(Some(TOKEN), Duration::from_secs(10)).await;
    let egress = tokio::spawn(fake_egress(listener, Reply::VersionRefused));
    let refused = connector.connect().await.err().unwrap();
    let accepted = crate::hosted::hello::ACCEPTED_VERSIONS;
    assert!(matches!(
        refused,
        ConnectError::VersionRefused { lowest, highest, spoken }
            if lowest == *accepted.start()
                && highest == *accepted.end()
                && spoken == NETWORK_PROTOCOL_VERSION
    ));
    // The loop reads the refusal from the error, to pace and report it.
    assert_eq!(
        PodConnector::version_refused(&refused),
        Some(VersionRefused {
            lowest: *accepted.start(),
            highest: *accepted.end(),
            spoken: NETWORK_PROTOCOL_VERSION,
        })
    );
    assert_eq!(PodConnector::version_refused(&ConnectError::TimedOut), None);
    assert_eq!(
        refused.to_string(),
        format!(
            "cw-egress accepts session versions {} to {}, and this daemon speaks {NETWORK_PROTOCOL_VERSION}",
            accepted.start(),
            accepted.end()
        )
    );
    egress.await.unwrap();
}

#[tokio::test]
async fn a_silent_egress_ends_at_the_bound() {
    let (connector, listener, _directory) =
        connector(Some(TOKEN), Duration::from_millis(100)).await;
    // cw-egress accepts and never answers.
    let hold = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(stream);
    });
    assert!(matches!(
        connector.connect().await,
        Err(ConnectError::TimedOut)
    ));
    hold.abort();
}
