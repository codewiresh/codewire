//! The host session over a real HTTP/2 listener and the generated client, in
//! both wire protocols (#3609, slice 1): a host that proves its key attaches
//! and is online; an unknown host, a wrong key and a revoked host are refused;
//! a host revoked while attached is told so; out-of-order messages, a wrong
//! platform, a missed proof and silence each end the session.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use axum::http::{Request, Response};
use codewire_proto::codewire::v1::{
    AttachHostRequest, AttachHostResponse, AttachHostResponseView, HostAgentServiceClient,
    HostAttachOpen, HostAttachProof, HostHello, HostPlatform as ProtoHostPlatform,
    attach_host_request, attach_host_response,
};
use codewire_server_core::connect::{ProtocolPolicy, connect_router_with_protocol_policy};
use connectrpc::client::{BidiStream, BoxFuture, ClientBody, ClientTransport};
use connectrpc::{ConnectError, ErrorCode, Protocol};
use ed25519_dalek::{Signer as _, SigningKey};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::api::host_session::attach_statement;
use crate::api::hosts::{HostState, get_host};
use crate::test_database_support::TestDatabase;
use codewire_server_core::auth::AuthUser;

const BOUND: Duration = Duration::from_secs(20);
const ORG: &str = "host-session-org";
const OWNER: &str = "host-session-owner";

type HostStream = BidiStream<reqwest::Body, AttachHostRequest, AttachHostResponseView<'static>>;

/// The generated client over reqwest's HTTP/2, as the CLI's transport does.
#[derive(Clone)]
struct Transport(reqwest::Client);

impl ClientTransport for Transport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(reqwest::Body::wrap_stream(
                    axum::body::Body::new(body).into_data_stream(),
                ))
                .send()
                .await
                .map_err(|_| ConnectError::unavailable("synthetic HTTP/2 transport"))?;
            Ok(Response::from(response))
        })
    }
}

struct Served {
    url: String,
    client: reqwest::Client,
    stop: CancellationToken,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn serve(db: &TestDatabase, timing: Timing) -> Result<Served> {
    serve_with(db, timing, MAX_HANDSHAKES).await
}

async fn serve_with(db: &TestDatabase, timing: Timing, max_handshakes: usize) -> Result<Served> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = connect_router_with_protocol_policy(
        router_with(db.pool.clone(), timing, max_handshakes),
        ProtocolPolicy::ConnectAndGrpc,
    );
    let stop = CancellationToken::new();
    let stopped = stop.clone();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(stopped.cancelled_owned())
            .await
    });
    Ok(Served {
        url: format!("http://{address}"),
        client: reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .build()?,
        stop,
    })
}

async fn open_stream(served: &Served, protocol: Protocol) -> Result<HostStream> {
    let client = HostAgentServiceClient::new(
        Transport(served.client.clone()),
        connectrpc::client::ClientConfig::new(served.url.parse()?).with_protocol(protocol),
    );
    Ok(client.attach_host().await?)
}

/// A host of the test organization, enrolled directly, with its key.
async fn host(db: &TestDatabase, name: &str, seed: u8) -> Result<(String, SigningKey)> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id: String = sqlx::query_scalar(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, public_key)
         VALUES ($1, $2, $3, 'linux-x86_64-kvm', 1, $4) RETURNING id",
    )
    .bind(ORG)
    .bind(OWNER)
    .bind(name)
    .bind(key.verifying_key().to_bytes().to_vec())
    .fetch_one(&db.pool)
    .await?;
    Ok((id, key))
}

async fn setup(db: &TestDatabase) -> Result<()> {
    db.organization(ORG).await?;
    db.user(OWNER).await?;
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'member')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(ORG)
    .bind(OWNER)
    .execute(&db.pool)
    .await?;
    Ok(())
}

fn input(input: attach_host_request::Input) -> AttachHostRequest {
    AttachHostRequest {
        input: Some(input),
        ..Default::default()
    }
}

fn open(host_id: &str) -> AttachHostRequest {
    input(attach_host_request::Input::Open(Box::new(HostAttachOpen {
        host_id: host_id.to_owned(),
        ..Default::default()
    })))
}

fn proof(signature: Vec<u8>) -> AttachHostRequest {
    input(attach_host_request::Input::Proof(Box::new(
        HostAttachProof {
            signature,
            ..Default::default()
        },
    )))
}

fn hello(platform: ProtoHostPlatform, capability_version: u32) -> AttachHostRequest {
    input(attach_host_request::Input::Hello(Box::new(HostHello {
        capability_version,
        platform: platform.into(),
        ..Default::default()
    })))
}

fn ping() -> AttachHostRequest {
    input(attach_host_request::Input::Ping(Box::default()))
}

/// The next response, or the error that ended the stream.
async fn next(stream: &mut HostStream) -> Result<Result<AttachHostResponse, ConnectError>> {
    let message = tokio::time::timeout(BOUND, stream.message::<AttachHostResponse>())
        .await
        .context("no response in time")?;
    Ok(match message {
        Ok(Some(message)) => Ok(message.to_owned_message()),
        Ok(None) => Err(stream
            .error()
            .cloned()
            .unwrap_or_else(|| ConnectError::new(ErrorCode::Unknown, "ended"))),
        Err(error) => Err(error),
    })
}

async fn output(stream: &mut HostStream) -> Result<attach_host_response::Output> {
    next(stream)
        .await?
        .map_err(|error| anyhow::anyhow!("stream ended: {error:?}"))?
        .output
        .context("empty response")
}

async fn refused(stream: &mut HostStream, code: ErrorCode) -> Result<()> {
    match next(stream).await? {
        Err(error) => ensure!(error.code == code, "ended with {error:?}, want {code:?}"),
        Ok(message) => anyhow::bail!("got {message:?}, want the stream to end with {code:?}"),
    }
    Ok(())
}

async fn answer_challenge(stream: &mut HostStream, host_id: &str, key: &SigningKey) -> Result<()> {
    let attach_host_response::Output::Challenge(challenge) = output(stream).await? else {
        anyhow::bail!("expected a challenge");
    };
    ensure!(challenge.nonce.len() == 32);
    stream
        .send(proof(
            key.sign(&attach_statement(host_id, &challenge.nonce))
                .to_bytes()
                .to_vec(),
        ))
        .await?;
    Ok(())
}

/// Opens, proves the key and says hello.
async fn attach(
    served: &Served,
    protocol: Protocol,
    host_id: &str,
    key: &SigningKey,
) -> Result<HostStream> {
    let mut stream = open_stream(served, protocol).await?;
    stream.send(open(host_id)).await?;
    answer_challenge(&mut stream, host_id, key).await?;
    let attach_host_response::Output::Attached(attached) = output(&mut stream).await? else {
        anyhow::bail!("expected attached");
    };
    ensure!(attached.ping_interval_seconds >= 1);
    stream
        .send(hello(ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM, 2))
        .await?;
    Ok(stream)
}

async fn state(db: &TestDatabase, host_id: &str) -> Result<HostState> {
    let owner = AuthUser {
        user_id: OWNER.into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    Ok(get_host(&db.pool, &owner, ORG, host_id)
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?
        .host
        .state())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_that_proves_its_key_attaches_and_is_online() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        for (protocol, name, seed) in [
            (Protocol::Connect, "connect", 1),
            (Protocol::Grpc, "grpc", 2),
        ] {
            let (id, key) = host(&db, name, seed).await?;
            ensure!(
                state(&db, &id).await? == HostState::Offline,
                "{name}: never seen"
            );
            let mut stream = attach(&served, protocol, &id, &key).await?;
            stream.send(ping()).await?;
            ensure!(
                matches!(
                    output(&mut stream).await?,
                    attach_host_response::Output::Pong(_)
                ),
                "{name}: ping answered"
            );
            ensure!(
                state(&db, &id).await? == HostState::Online,
                "{name}: online"
            );
            let version: i32 =
                sqlx::query_scalar("SELECT capability_version FROM hosts WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&db.pool)
                    .await?;
            ensure!(
                version == 2,
                "{name}: hello recorded the capability version"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_unknown_hosts_wrong_keys_and_revoked_hosts_are_refused() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let (id, key) = host(&db, "known", 1).await?;
        let stranger = SigningKey::from_bytes(&[9; 32]);

        // An unknown host and a wrong key look the same to the caller: a
        // challenge, then unauthenticated.
        for (host_id, signer) in [
            (uuid::Uuid::new_v4().to_string(), &key),
            ("not-a-uuid".to_owned(), &key),
            (id.clone(), &stranger),
        ] {
            let mut stream = open_stream(&served, Protocol::Connect).await?;
            stream.send(open(&host_id)).await?;
            answer_challenge(&mut stream, &host_id, signer).await?;
            refused(&mut stream, ErrorCode::Unauthenticated).await?;
        }
        ensure!(
            state(&db, &id).await? == HostState::Offline,
            "a refused caller is not liveness"
        );

        // A revoked host proves its key and is still refused.
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        let mut stream = open_stream(&served, Protocol::Connect).await?;
        stream.send(open(&id)).await?;
        answer_challenge(&mut stream, &id, &key).await?;
        refused(&mut stream, ErrorCode::PermissionDenied).await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_revoked_while_attached_is_told_and_ended() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let (id, key) = host(&db, "revoked-live", 1).await?;
        let mut stream = attach(&served, Protocol::Connect, &id, &key).await?;
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        stream.send(ping()).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Revoked(_)
        ));
        // Then the stream ends.
        ensure!(next(&mut stream).await?.is_err(), "the stream ended");
        ensure!(state(&db, &id).await? == HostState::Revoked);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_out_of_order_messages_and_a_wrong_platform_end_the_session() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let (id, key) = host(&db, "orderly", 1).await?;

        // Anything but open first.
        let mut stream = open_stream(&served, Protocol::Connect).await?;
        stream.send(ping()).await?;
        refused(&mut stream, ErrorCode::InvalidArgument).await?;

        // Anything but a proof after the challenge is a failed proof.
        let mut stream = open_stream(&served, Protocol::Connect).await?;
        stream.send(open(&id)).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Challenge(_)
        ));
        stream.send(ping()).await?;
        refused(&mut stream, ErrorCode::Unauthenticated).await?;

        // A ping before the hello.
        let mut stream = open_stream(&served, Protocol::Connect).await?;
        stream.send(open(&id)).await?;
        answer_challenge(&mut stream, &id, &key).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Attached(_)
        ));
        stream.send(ping()).await?;
        refused(&mut stream, ErrorCode::InvalidArgument).await?;

        // A platform other than the enrolled one, and a zero capability.
        for (platform, version, code) in [
            (
                ProtoHostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ,
                1,
                ErrorCode::FailedPrecondition,
            ),
            (
                ProtoHostPlatform::HOST_PLATFORM_UNSPECIFIED,
                1,
                ErrorCode::FailedPrecondition,
            ),
            (
                ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM,
                0,
                ErrorCode::InvalidArgument,
            ),
        ] {
            let mut stream = open_stream(&served, Protocol::Connect).await?;
            stream.send(open(&id)).await?;
            answer_challenge(&mut stream, &id, &key).await?;
            ensure!(matches!(
                output(&mut stream).await?,
                attach_host_response::Output::Attached(_)
            ));
            stream.send(hello(platform, version)).await?;
            refused(&mut stream, code).await?;
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_attached_host_proves_its_key_again_or_is_ended() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let timing = Timing {
            rechallenge: Duration::from_millis(500),
            proof_timeout: Duration::from_secs(1),
            ..Timing::DEFAULT
        };
        let served = serve(&db, timing).await?;
        let (id, key) = host(&db, "rechallenged", 1).await?;

        // Answering the rechallenge keeps the session, even with a ping
        // already on its way when the challenge came.
        let mut stream = attach(&served, Protocol::Connect, &id, &key).await?;
        let attach_host_response::Output::Challenge(challenge) = output(&mut stream).await? else {
            anyhow::bail!("expected a rechallenge");
        };
        stream.send(ping()).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Pong(_)
        ));
        stream
            .send(proof(
                key.sign(&attach_statement(&id, &challenge.nonce))
                    .to_bytes()
                    .to_vec(),
            ))
            .await?;
        stream.send(ping()).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Pong(_)
        ));
        // A proof nobody asked for is out of order.
        let mut stream = attach(&served, Protocol::Connect, &id, &key).await?;
        stream.send(proof(vec![0; 64])).await?;
        refused(&mut stream, ErrorCode::InvalidArgument).await?;

        // Not answering ends it.
        let mut stream = attach(&served, Protocol::Connect, &id, &key).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Challenge(_)
        ));
        refused(&mut stream, ErrorCode::DeadlineExceeded).await?;

        // A wrong answer ends it too.
        let mut stream = attach(
            &served,
            Protocol::Connect,
            &id,
            &SigningKey::from_bytes(&[1; 32]),
        )
        .await?;
        answer_challenge(&mut stream, &id, &SigningKey::from_bytes(&[9; 32])).await?;
        refused(&mut stream, ErrorCode::Unauthenticated).await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_silent_host_and_a_silent_caller_are_ended() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let timing = Timing {
            handshake: Duration::from_millis(500),
            offline_after: Duration::from_millis(500),
            ..Timing::DEFAULT
        };
        let served = serve(&db, timing).await?;
        let (id, key) = host(&db, "silent", 1).await?;

        // A caller that opens nothing.
        let mut stream = open_stream(&served, Protocol::Connect).await?;
        refused(&mut stream, ErrorCode::DeadlineExceeded).await?;
        // An attached host that stops pinging.
        let mut stream = attach(&served, Protocol::Connect, &id, &key).await?;
        refused(&mut stream, ErrorCode::DeadlineExceeded).await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// How an unproven stream ends after the challenge, as the caller sees it.
async fn unproven_ending(served: &Served, host_id: &str, answer: &str) -> Result<String> {
    let mut stream = open_stream(served, Protocol::Connect).await?;
    stream.send(open(host_id)).await?;
    ensure!(matches!(
        output(&mut stream).await?,
        attach_host_response::Output::Challenge(_)
    ));
    match answer {
        "ping" => stream.send(ping()).await?,
        "bad signature" => stream.send(proof(vec![7; 64])).await?,
        "close" => stream.close_send(),
        "silence" => {}
        other => anyhow::bail!("unknown answer {other}"),
    }
    Ok(match next(&mut stream).await? {
        Err(error) => format!("{:?} {:?}", error.code, error.message),
        Ok(message) => format!("message {message:?}"),
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_known_and_unknown_host_ids_end_alike_until_proven() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let timing = Timing {
            handshake: Duration::from_millis(500),
            ..Timing::DEFAULT
        };
        let served = serve(&db, timing).await?;
        let (known, _) = host(&db, "known", 1).await?;
        let unknown = uuid::Uuid::new_v4().to_string();
        for answer in ["ping", "silence", "close", "bad signature"] {
            let known_end = unproven_ending(&served, &known, answer).await?;
            let unknown_end = unproven_ending(&served, &unknown, answer).await?;
            ensure!(
                known_end == unknown_end,
                "{answer}: known {known_end} differs from unknown {unknown_end}"
            );
            ensure!(
                known_end.starts_with("Unauthenticated"),
                "{answer}: {known_end}"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_unproven_streams_are_bounded_and_attaching_frees_the_place() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let served = serve_with(&db, Timing::DEFAULT, 1).await?;
        let (id, key) = host(&db, "bounded", 1).await?;

        // The first stream holds the only place while it is unproven, so a
        // second is refused at once.
        let mut first = open_stream(&served, Protocol::Connect).await?;
        first.send(open(&id)).await?;
        let attach_host_response::Output::Challenge(challenge) = output(&mut first).await? else {
            anyhow::bail!("expected a challenge");
        };
        let mut second = open_stream(&served, Protocol::Connect).await?;
        let _ = second.send(open(&id)).await;
        refused(&mut second, ErrorCode::ResourceExhausted).await?;

        // Attaching frees it for the next caller, while the first stays
        // attached.
        first
            .send(proof(
                key.sign(&attach_statement(&id, &challenge.nonce))
                    .to_bytes()
                    .to_vec(),
            ))
            .await?;
        ensure!(matches!(
            output(&mut first).await?,
            attach_host_response::Output::Attached(_)
        ));
        let mut third = open_stream(&served, Protocol::Connect).await?;
        third.send(open(&id)).await?;
        ensure!(matches!(
            output(&mut third).await?,
            attach_host_response::Output::Challenge(_)
        ));
        Ok(())
    }
    .await;
    db.finish(result).await
}
