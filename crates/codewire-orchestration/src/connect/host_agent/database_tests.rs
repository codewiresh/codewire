//! The host session over a real HTTP/2 listener and the generated client, in
//! both wire protocols (#3609, slice 1): a host that proves its key attaches
//! and is online; an unknown host, a wrong key and a revoked host are refused;
//! a host revoked while attached is told so; out-of-order messages, a wrong
//! platform, a missed proof and silence each end the session. And slice 2:
//! an operation reaches only the host's current session, a newer session
//! supersedes an older one and takes its unanswered operations, and the
//! host's answer is recorded.

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
/// What this test server's access grants are signed with and name.
const ACCESS_SECRET: &str = "synthetic-host-access-session-secret";
const ACCESS_COORDINATOR: &str = "https://coordinator.example.test";

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
    /// The tunnels this server's sessions carry, as the API state holds them.
    tunnels: Arc<crate::api::host_tunnels::HostTunnels>,
    client: reqwest::Client,
    stop: CancellationToken,
    /// The process-wide `LISTEN host_operation`, as production runs it.
    operation_listener: tokio::task::JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.cancel();
        self.operation_listener.abort();
    }
}

async fn serve(db: &TestDatabase, timing: Timing) -> Result<Served> {
    serve_with(db, timing, MAX_HANDSHAKES, Drain::default()).await
}

async fn serve_with(
    db: &TestDatabase,
    timing: Timing,
    max_handshakes: usize,
    drain: Drain,
) -> Result<Served> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let signals = crate::api::host_operation_signals::HostOperationSignals::new();
    let tunnels = crate::api::host_tunnels::HostTunnels::new();
    let operation_listener = crate::api::host_operation_signals::spawn_host_operation_listener(
        db.pool.clone(),
        signals.clone(),
    );
    let router = connect_router_with_protocol_policy(
        router_with(
            db.pool.clone(),
            timing,
            max_handshakes,
            drain,
            signals,
            tunnels.clone(),
            Some(Arc::new(HostAccessSettings {
                session_secret: ACCESS_SECRET.into(),
                coordinator_url: ACCESS_COORDINATOR.into(),
            })),
        ),
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
        tunnels,
        client: reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .build()?,
        stop,
        operation_listener,
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

/// Opens, proves the key and says hello as a host that runs operations.
async fn attach(
    served: &Served,
    protocol: Protocol,
    host_id: &str,
    key: &SigningKey,
) -> Result<HostStream> {
    attach_as(served, protocol, host_id, key, 2).await
}

/// [`attach`], for a host of `capability_version`.
async fn attach_as(
    served: &Served,
    protocol: Protocol,
    host_id: &str,
    key: &SigningKey,
    capability_version: u32,
) -> Result<HostStream> {
    let mut stream = open_stream(served, protocol).await?;
    stream.send(open(host_id)).await?;
    answer_challenge(&mut stream, host_id, key).await?;
    let attach_host_response::Output::Attached(attached) = output(&mut stream).await? else {
        anyhow::bail!("expected attached");
    };
    ensure!(attached.ping_interval_seconds >= 1);
    stream
        .send(hello(
            ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM,
            capability_version,
        ))
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
async fn db_attached_hosts_are_told_to_reattach_when_the_replica_begins_draining() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let drain = Drain::default();
        let served = serve_with(&db, Timing::DEFAULT, MAX_HANDSHAKES, drain.clone()).await?;
        let mut streams = Vec::new();
        for (protocol, name, seed) in [
            (Protocol::Connect, "connect", 1),
            (Protocol::Grpc, "grpc", 2),
        ] {
            let (id, key) = host(&db, name, seed).await?;
            streams.push((name, attach(&served, protocol, &id, &key).await?));
        }
        // The deadline is far off: only the beginning of the drain counts.
        drain.begin(Duration::from_secs(3600));
        for (name, mut stream) in streams {
            let ended = next(&mut stream).await?;
            ensure!(
                matches!(&ended, Err(error) if error.code == ErrorCode::Unavailable),
                "{name}: the host is told to re-attach, got {ended:?}"
            );
        }
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
        let served = serve_with(&db, Timing::DEFAULT, 1, Drain::default()).await?;
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

// ── Slice 2: operations ───────────────────────────────────────────────────

use codewire_proto::codewire::v1::{
    HostEnvironmentObservation as ProtoObservation, HostEnvironmentState as ProtoState,
    HostOperation as ProtoOperation, HostOperationResult, host_operation, host_operation_result,
};

use crate::api::host_operations::{
    HostOperationKind, HostOperationState, NewHostOperation, enqueue,
};

// Environment IDs are UUIDs (`environments.id` defaults to one), as the
// host contract requires.
const ENVIRONMENT: &str = "5d0c1f3e-2a4b-4c6d-8e9f-0a1b2c3d4e5f";
const LOCAL: &str = "9b2e7c1a-0d4f-4e8b-a6c3-5f1d2e3a4b5c";

/// An environment placed on `host_id`.
async fn placed_environment(db: &TestDatabase, host_id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
         VALUES ('host-session-preset', $1, 'Preset', 'ready', '{}'::jsonb)",
    )
    .bind(ORG)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, \
         runtime_backend, host_id) \
         VALUES ($1, $2, $3, 'sandbox', 'host-session-preset', '{}'::jsonb, 'host', $4)",
    )
    .bind(ENVIRONMENT)
    .bind(ORG)
    .bind(OWNER)
    .bind(host_id)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Enqueues a stop of the environment, as the driver does, and returns the
/// operation as the host must receive it.
async fn enqueue_stop(db: &TestDatabase, host_id: &str) -> Result<ProtoOperation> {
    let operation = ProtoOperation {
        operation_id: uuid::Uuid::new_v4().to_string(),
        environment_id: ENVIRONMENT.into(),
        local_environment_id: LOCAL.into(),
        expected_generation: 1,
        kind: Some(host_operation::Kind::Stop(Box::default())),
        ..Default::default()
    };
    let payload = buffa::Message::encode_to_vec(&operation);
    enqueue(
        &db.pool,
        &NewHostOperation {
            operation_id: &operation.operation_id,
            host_id,
            environment_id: ENVIRONMENT,
            expected_generation: 1,
            kind: HostOperationKind::Stop,
            payload: &payload,
        },
    )
    .await?;
    Ok(operation)
}

/// The next message that is not a pong.
async fn next_but_pongs(stream: &mut HostStream) -> Result<attach_host_response::Output> {
    loop {
        match output(stream).await? {
            attach_host_response::Output::Pong(_) => {}
            other => return Ok(other),
        }
    }
}

async fn received_operation(stream: &mut HostStream) -> Result<ProtoOperation> {
    match next_but_pongs(stream).await? {
        attach_host_response::Output::Operation(operation) => Ok(*operation),
        other => anyhow::bail!("expected an operation, got {other:?}"),
    }
}

async fn operation_state(db: &TestDatabase, operation_id: &str) -> Result<HostOperationState> {
    Ok(crate::api::host_operations::get(&db.pool, operation_id)
        .await?
        .context("the operation is stored")?
        .state)
}

fn stopped(operation_id: &str) -> AttachHostRequest {
    input(attach_host_request::Input::OperationResult(Box::new(
        HostOperationResult {
            operation_id: operation_id.into(),
            outcome: Some(host_operation_result::Outcome::Done(Box::new(
                ProtoObservation {
                    environment_id: ENVIRONMENT.into(),
                    local_environment_id: LOCAL.into(),
                    generation: 1,
                    state: ProtoState::HOST_ENVIRONMENT_STATE_STOPPED.into(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        },
    )))
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_operation_reaches_the_attached_host_and_its_answer_is_recorded() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "operations", 1).await?;
        placed_environment(&db, &id).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut stream = attach(&served, Protocol::Grpc, &id, &key).await?;
        // Attached and idle: the enqueue's notification brings it, with no
        // ping to wait for.
        stream.send(ping()).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Pong(_)
        ));
        let enqueued = enqueue_stop(&db, &id).await?;
        let received = received_operation(&mut stream).await?;
        ensure!(
            received == enqueued,
            "the host gets the stored operation as encoded"
        );
        ensure!(matches!(
            operation_state(&db, &enqueued.operation_id).await?,
            HostOperationState::Sent { .. }
        ));

        stream.send(stopped(&enqueued.operation_id)).await?;
        stream.send(ping()).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Pong(_)
        ));
        ensure!(
            matches!(
                operation_state(&db, &enqueued.operation_id).await?,
                HostOperationState::Done { .. }
            ),
            "the answer completes the operation"
        );
        let (observation, _) =
            crate::api::host_operations::latest_observation(&db.pool, &id, ENVIRONMENT)
                .await?
                .context("the result's observation is recorded")?;
        ensure!(observation.local_environment_id.to_string() == LOCAL);
        ensure!(observation.state == crate::api::host_operations::HostEnvironmentState::Stopped);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_newer_session_supersedes_the_older_and_is_sent_its_unanswered_operations()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "superseded", 1).await?;
        placed_environment(&db, &id).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut older = attach(&served, Protocol::Grpc, &id, &key).await?;
        let enqueued = enqueue_stop(&db, &id).await?;
        ensure!(received_operation(&mut older).await? == enqueued);

        // The agent restarted while the old stream lingers.
        let mut newer = attach(&served, Protocol::Grpc, &id, &key).await?;
        ensure!(
            received_operation(&mut newer).await? == enqueued,
            "the newer session is sent what the older one did not answer"
        );
        older.send(ping()).await?;
        ensure!(
            matches!(
                next(&mut older).await?,
                Ok(AttachHostResponse {
                    output: Some(attach_host_response::Output::Superseded(_)),
                    ..
                })
            ),
            "the older session is told it was superseded"
        );

        // Only the current session claims: a second operation goes to it.
        newer.send(stopped(&enqueued.operation_id)).await?;
        // Messages are handled in order: once this ping is answered, so is
        // the operation, and the environment may take another.
        newer.send(ping()).await?;
        ensure!(matches!(
            output(&mut newer).await?,
            attach_host_response::Output::Pong(_)
        ));
        let second = enqueue_stop(&db, &id).await?;
        ensure!(received_operation(&mut newer).await? == second);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_that_runs_no_operations_is_sent_none() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "liveness-only", 1).await?;
        placed_environment(&db, &id).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut stream = attach_as(&served, Protocol::Grpc, &id, &key, 1).await?;
        let enqueued = enqueue_stop(&db, &id).await?;
        for _ in 0..2 {
            stream.send(ping()).await?;
            ensure!(
                matches!(
                    output(&mut stream).await?,
                    attach_host_response::Output::Pong(_)
                ),
                "only pongs"
            );
        }
        ensure!(operation_state(&db, &enqueued.operation_id).await? == HostOperationState::Pending);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A report of `environment_id`, stopped.
fn stopped_report(environment_id: &str) -> ProtoObservation {
    ProtoObservation {
        environment_id: environment_id.into(),
        local_environment_id: LOCAL.into(),
        generation: 1,
        state: ProtoState::HOST_ENVIRONMENT_STATE_STOPPED.into(),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_answer_about_another_environment_fails_its_operation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "wrong-answer", 1).await?;
        placed_environment(&db, &id).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut stream = attach(&served, Protocol::Grpc, &id, &key).await?;
        let enqueued = enqueue_stop(&db, &id).await?;
        received_operation(&mut stream).await?;

        let other = uuid::Uuid::new_v4().to_string();
        stream
            .send(input(attach_host_request::Input::OperationResult(
                Box::new(HostOperationResult {
                    operation_id: enqueued.operation_id.clone(),
                    outcome: Some(host_operation_result::Outcome::Done(Box::new(
                        stopped_report(&other),
                    ))),
                    ..Default::default()
                }),
            )))
            .await?;
        stream.send(ping()).await?;
        ensure!(
            matches!(
                output(&mut stream).await?,
                attach_host_response::Output::Pong(_)
            ),
            "the session goes on"
        );
        ensure!(
            matches!(
                operation_state(&db, &enqueued.operation_id).await?,
                HostOperationState::Failed { .. }
            ),
            "the answer fails the operation"
        );
        for environment in [ENVIRONMENT, other.as_str()] {
            ensure!(
                crate::api::host_operations::latest_observation(&db.pool, &id, environment)
                    .await?
                    .is_none(),
                "the answer's report is not recorded"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_malformed_inventory_entry_is_skipped_and_the_host_attaches() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "odd-inventory", 1).await?;
        placed_environment(&db, &id).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut stream = open_stream(&served, Protocol::Grpc).await?;
        stream.send(open(&id)).await?;
        answer_challenge(&mut stream, &id, &key).await?;
        ensure!(matches!(
            output(&mut stream).await?,
            attach_host_response::Output::Attached(_)
        ));
        let mut malformed = stopped_report(ENVIRONMENT);
        malformed.state = ProtoState::HOST_ENVIRONMENT_STATE_UNSPECIFIED.into();
        stream
            .send(input(attach_host_request::Input::Hello(Box::new(
                HostHello {
                    capability_version: 2,
                    platform: ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM.into(),
                    inventory: vec![malformed, stopped_report(ENVIRONMENT)],
                    ..Default::default()
                },
            ))))
            .await?;
        stream.send(ping()).await?;
        ensure!(
            matches!(
                output(&mut stream).await?,
                attach_host_response::Output::Pong(_)
            ),
            "the host stays attached"
        );
        let (observation, _) =
            crate::api::host_operations::latest_observation(&db.pool, &id, ENVIRONMENT)
                .await?
                .context("the well-formed entry is recorded")?;
        ensure!(observation.state == crate::api::host_operations::HostEnvironmentState::Stopped);
        Ok(())
    }
    .await;
    db.finish(result).await
}

// ── Slice 2: tunnels ──────────────────────────────────────────────────────

use codewire_proto::codewire::v1::{
    HostTunnelOpen, HostTunnelReady, OpenHostTunnelRequest, OpenHostTunnelResponse,
    OpenHostTunnelResponseView, open_host_tunnel_request, open_host_tunnel_response,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::api::host_session::tunnel_statement;
use crate::api::host_tunnels::TunnelTarget;

type TunnelStream =
    BidiStream<reqwest::Body, OpenHostTunnelRequest, OpenHostTunnelResponseView<'static>>;

fn tunnel_input(input: open_host_tunnel_request::Input) -> OpenHostTunnelRequest {
    OpenHostTunnelRequest {
        input: Some(input),
        ..Default::default()
    }
}

async fn open_tunnel_stream(
    served: &Served,
    host_id: &str,
    tunnel_id: &str,
    signature: Vec<u8>,
) -> Result<TunnelStream> {
    let client = HostAgentServiceClient::new(
        Transport(served.client.clone()),
        connectrpc::client::ClientConfig::new(served.url.parse()?).with_protocol(Protocol::Grpc),
    );
    let mut stream = client.open_host_tunnel().await?;
    stream
        .send(tunnel_input(open_host_tunnel_request::Input::Open(
            Box::new(HostTunnelOpen {
                host_id: host_id.into(),
                tunnel_id: tunnel_id.into(),
                signature,
                ..Default::default()
            }),
        )))
        .await?;
    Ok(stream)
}

fn tunnel_target(host_id: &str) -> TunnelTarget {
    TunnelTarget {
        host_id: host_id.into(),
        environment_id: ENVIRONMENT.into(),
        local_environment_id: LOCAL.into(),
        generation: 1,
    }
}

/// The session's request for a tunnel, among its pongs.
async fn tunnel_request(
    stream: &mut HostStream,
) -> Result<codewire_proto::codewire::v1::HostOpenTunnel> {
    match next_but_pongs(stream).await? {
        attach_host_response::Output::OpenTunnel(request) => Ok(*request),
        other => anyhow::bail!("expected a tunnel request, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_tunnel_the_session_asks_for_carries_bytes_both_ways() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "tunnels", 1).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = attach(&served, Protocol::Grpc, &id, &key).await?;
        session.send(ping()).await?;
        ensure!(matches!(
            output(&mut session).await?,
            attach_host_response::Output::Pong(_)
        ));

        let opening = tokio::spawn({
            let tunnels = served.tunnels.clone();
            let target = tunnel_target(&id);
            async move { tunnels.open(&target).await }
        });
        let request = tunnel_request(&mut session).await?;
        ensure!(request.environment_id == ENVIRONMENT && request.generation == 1);
        let signature = key
            .sign(&tunnel_statement(&id, &request.tunnel_id, &request.nonce))
            .to_bytes()
            .to_vec();
        let mut host_end = open_tunnel_stream(&served, &id, &request.tunnel_id, signature).await?;
        host_end
            .send(tunnel_input(open_host_tunnel_request::Input::Ready(
                Box::new(HostTunnelReady {
                    daemon_capability: "synthetic-capability".into(),
                    ..Default::default()
                }),
            )))
            .await?;
        let mut opened = tokio::time::timeout(BOUND, opening).await???;
        ensure!(opened.daemon_capability.as_str() == "synthetic-capability");

        // Caller to host.
        opened.stream.write_all(b"to the daemon").await?;
        let message = tokio::time::timeout(BOUND, host_end.message::<OpenHostTunnelResponse>())
            .await??
            .context("a data frame")?;
        ensure!(
            message.to_owned_message().output
                == Some(open_host_tunnel_response::Output::Data(
                    b"to the daemon".to_vec()
                ))
        );
        // Host to caller.
        host_end
            .send(tunnel_input(open_host_tunnel_request::Input::Data(
                b"from the daemon".to_vec(),
            )))
            .await?;
        let mut received = [0; 15];
        tokio::time::timeout(BOUND, opened.stream.read_exact(&mut received)).await??;
        ensure!(&received == b"from the daemon");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_tunnel_opened_without_the_hosts_proof_is_refused() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "tunnel-proof", 1).await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = attach(&served, Protocol::Grpc, &id, &key).await?;
        session.send(ping()).await?;
        ensure!(matches!(
            output(&mut session).await?,
            attach_host_response::Output::Pong(_)
        ));
        let opening = tokio::spawn({
            let tunnels = served.tunnels.clone();
            let target = tunnel_target(&id);
            async move { tunnels.open(&target).await }
        });
        let request = tunnel_request(&mut session).await?;
        // Another key, over the right statement.
        let stranger = SigningKey::from_bytes(&[9; 32]);
        let forged = stranger
            .sign(&tunnel_statement(&id, &request.tunnel_id, &request.nonce))
            .to_bytes()
            .to_vec();
        let mut forged_end = open_tunnel_stream(&served, &id, &request.tunnel_id, forged).await?;
        // A forger goes on as a host would; the stream may already be closed.
        let _ = forged_end
            .send(tunnel_input(open_host_tunnel_request::Input::Ready(
                Box::new(HostTunnelReady {
                    daemon_capability: "forged-capability".into(),
                    ..Default::default()
                }),
            )))
            .await;
        let refusal =
            tokio::time::timeout(BOUND, forged_end.message::<OpenHostTunnelResponse>()).await?;
        ensure!(
            matches!(&refusal, Err(error) if error.code == ErrorCode::Unauthenticated),
            "refused as unrecognised: {refusal:?}"
        );
        // The forged attempt spent nothing: the host's own proof still opens
        // the tunnel, and the caller gets the host's capability, not the
        // forger's.
        let signature = key
            .sign(&tunnel_statement(&id, &request.tunnel_id, &request.nonce))
            .to_bytes()
            .to_vec();
        let mut host_end = open_tunnel_stream(&served, &id, &request.tunnel_id, signature).await?;
        host_end
            .send(tunnel_input(open_host_tunnel_request::Input::Ready(
                Box::new(HostTunnelReady {
                    daemon_capability: "synthetic-capability".into(),
                    ..Default::default()
                }),
            )))
            .await?;
        let opened = tokio::time::timeout(BOUND, opening).await???;
        ensure!(opened.daemon_capability.as_str() == "synthetic-capability");
        Ok(())
    }
    .await;
    db.finish(result).await
}

// ── Slice 3: access calls ──────────────────────────────────────────────────

use codewire_proto::codewire::v1::{
    HostAccessRefresh, HostKeyRecord as ProtoHostKeyRecord, HostPeerRelayAllocate,
};

const ACCESS_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const OTHER_ACCESS_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REQUEST: &str = "6f1d2e3a-4b5c-4d6e-8f70-819203a4b5c6";

/// The environment placed on `host_id`, running at operation generation 5,
/// and the host's report of its VM: `LOCAL` at boot generation 1, `state`.
async fn running_on_host(db: &TestDatabase, host_id: &str, state: &str) -> Result<()> {
    placed_environment(db, host_id).await?;
    sqlx::query(
        "UPDATE environments SET state = 'running', desired_state = 'started', \
         environment_operation_generation = 5 WHERE id = $1",
    )
    .bind(ENVIRONMENT)
    .execute(&db.pool)
    .await?;
    report(db, host_id, 1, state).await
}

/// The host's report of its VM, as its session would record it.
async fn report(db: &TestDatabase, host_id: &str, generation: i64, state: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO host_environments (host_id, environment_id, local_environment_id, \
         generation, state) VALUES ($1, $2, $3::uuid, $4, $5) \
         ON CONFLICT (host_id, environment_id) DO UPDATE SET \
         local_environment_id = EXCLUDED.local_environment_id, \
         generation = EXCLUDED.generation, state = EXCLUDED.state",
    )
    .bind(host_id)
    .bind(ENVIRONMENT)
    .bind(LOCAL)
    .bind(generation)
    .bind(state)
    .execute(&db.pool)
    .await?;
    Ok(())
}

fn refresh(local: &str, generation: u64) -> AttachHostRequest {
    input(attach_host_request::Input::AccessRefresh(Box::new(
        HostAccessRefresh {
            request_id: REQUEST.into(),
            environment_id: ENVIRONMENT.into(),
            local_environment_id: local.into(),
            generation,
            ..Default::default()
        },
    )))
}

fn record_key(generation: u64, key: &str) -> AttachHostRequest {
    input(attach_host_request::Input::HostKeyRecord(Box::new(
        ProtoHostKeyRecord {
            request_id: REQUEST.into(),
            environment_id: ENVIRONMENT.into(),
            local_environment_id: LOCAL.into(),
            generation,
            public_key_openssh: key.into(),
            ..Default::default()
        },
    )))
}

/// A capability-3 host's attached session, past its first pong.
async fn access_session(served: &Served, id: &str, key: &SigningKey) -> Result<HostStream> {
    let mut session = attach_as(served, Protocol::Grpc, id, key, 3).await?;
    session.send(ping()).await?;
    ensure!(matches!(
        output(&mut session).await?,
        attach_host_response::Output::Pong(_)
    ));
    Ok(session)
}

/// The refusal code an access call was answered with, or what came instead.
async fn access_refused(session: &mut HostStream) -> Result<String> {
    match next_but_pongs(session).await? {
        attach_host_response::Output::AccessRefused(refusal) => {
            ensure!(refusal.request_id == REQUEST);
            Ok(refusal.code)
        }
        other => anyhow::bail!("expected a refusal, got {other:?}"),
    }
}

async fn stored_keys(db: &TestDatabase) -> Result<Vec<(i64, String)>> {
    Ok(sqlx::query_as(
        "SELECT operation_generation, public_key FROM host_environment_ssh_host_keys \
         WHERE environment_id = $1 ORDER BY operation_generation",
    )
    .bind(ENVIRONMENT)
    .fetch_all(&db.pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_running_vms_peer_gets_a_grant_bound_to_the_operation_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "access-grant", 1).await?;
        running_on_host(&db, &id, "running").await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = access_session(&served, &id, &key).await?;
        session.send(refresh(LOCAL, 1)).await?;
        let attach_host_response::Output::AccessGrant(grant) = next_but_pongs(&mut session).await?
        else {
            anyhow::bail!("expected a grant");
        };
        ensure!(grant.request_id == REQUEST);
        ensure!(grant.coordinator_url == ACCESS_COORDINATOR && grant.app_ports.is_empty());
        // The environment's operation generation, not the boot generation the
        // host named.
        ensure!(grant.operation_generation == 5);
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?;
        let claims =
            codewire_server_core::peer_token::validate(ACCESS_SECRET, &grant.peer_token, now)?;
        ensure!(claims.environment_id == ENVIRONMENT && claims.generation == 5);
        ensure!(grant.peer_token_expires_at > now);

        // This control plane has no peer relay for hosts.
        session
            .send(input(attach_host_request::Input::PeerRelayAllocate(
                Box::new(HostPeerRelayAllocate {
                    request_id: REQUEST.into(),
                    environment_id: ENVIRONMENT.into(),
                    local_environment_id: LOCAL.into(),
                    generation: 1,
                    ..Default::default()
                }),
            )))
            .await?;
        ensure!(access_refused(&mut session).await? == "unsupported");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_access_calls_are_refused_unless_the_vm_is_held_running_and_current() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "access-refusals", 1).await?;
        let (other_host, _) = host(&db, "access-other", 2).await?;
        running_on_host(&db, &id, "running").await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = access_session(&served, &id, &key).await?;

        // Another local environment, and a boot generation not reported.
        session
            .send(refresh("00000000-0000-4000-8000-000000000009", 1))
            .await?;
        ensure!(access_refused(&mut session).await? == "not_held");
        session.send(refresh(LOCAL, 2)).await?;
        ensure!(access_refused(&mut session).await? == "stale_generation");

        // A boot generation the host reports but not RUNNING (cw-security).
        report(&db, &id, 1, "starting").await?;
        session.send(refresh(LOCAL, 1)).await?;
        ensure!(access_refused(&mut session).await? == "not_running");
        report(&db, &id, 1, "running").await?;

        // The environment stopping, moved to another host, or being deleted.
        for change in [
            "UPDATE environments SET desired_state = 'stopped' WHERE id = $1",
            "UPDATE environments SET host_id = $2 WHERE id = $1",
            "UPDATE environments SET deletion_requested_at = now() WHERE id = $1",
        ] {
            let mut transaction = db.pool.begin().await?;
            sqlx::query(change)
                .bind(ENVIRONMENT)
                .bind(&other_host)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            session.send(refresh(LOCAL, 1)).await?;
            let code = access_refused(&mut session).await?;
            ensure!(
                code == "not_running" || code == "not_held",
                "{change}: {code}"
            );
            sqlx::query(
                "UPDATE environments SET desired_state = 'started', host_id = $2, \
                 deletion_requested_at = NULL WHERE id = $1",
            )
            .bind(ENVIRONMENT)
            .bind(&id)
            .execute(&db.pool)
            .await?;
        }

        // A session that is no longer the host's current one, and a revoked
        // host.
        sqlx::query("UPDATE hosts SET session_generation = session_generation + 1 WHERE id = $1")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        session.send(refresh(LOCAL, 1)).await?;
        ensure!(access_refused(&mut session).await? == "not_held");
        sqlx::query("UPDATE hosts SET session_generation = session_generation - 1, revoked_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        session.send(refresh(LOCAL, 1)).await?;
        ensure!(access_refused(&mut session).await? == "not_held");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_vms_host_key_is_written_once_per_operation_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "access-keys", 1).await?;
        running_on_host(&db, &id, "running").await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = access_session(&served, &id, &key).await?;
        let recorded = |output: attach_host_response::Output| match output {
            attach_host_response::Output::HostKeyRecorded(recorded) => {
                recorded.request_id == REQUEST
            }
            _ => false,
        };

        session.send(record_key(1, "ssh-ed25519 AAAA")).await?;
        ensure!(access_refused(&mut session).await? == "invalid_key");
        session.send(record_key(1, ACCESS_KEY)).await?;
        ensure!(recorded(next_but_pongs(&mut session).await?));
        // The same key again is accepted; another is a conflict.
        session.send(record_key(1, ACCESS_KEY)).await?;
        ensure!(recorded(next_but_pongs(&mut session).await?));
        session.send(record_key(1, OTHER_ACCESS_KEY)).await?;
        ensure!(access_refused(&mut session).await? == "key_conflict");

        // A host that reports a new boot generation on its own gets no new
        // slot: the operation generation is unchanged (cw-security).
        report(&db, &id, 2, "running").await?;
        session.send(record_key(2, OTHER_ACCESS_KEY)).await?;
        ensure!(access_refused(&mut session).await? == "key_conflict");
        ensure!(stored_keys(&db).await? == [(5, ACCESS_KEY.to_owned())]);

        // A real start, at a new operation generation, has its own slot.
        sqlx::query("UPDATE environments SET environment_operation_generation = 6 WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        session.send(record_key(2, OTHER_ACCESS_KEY)).await?;
        ensure!(recorded(next_but_pongs(&mut session).await?));
        ensure!(
            stored_keys(&db).await?
                == [(5, ACCESS_KEY.to_owned()), (6, OTHER_ACCESS_KEY.to_owned())]
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_access_calls_end_a_session_below_capability_3_or_with_a_bad_request_id() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "access-capability", 1).await?;
        running_on_host(&db, &id, "running").await?;
        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = attach(&served, Protocol::Grpc, &id, &key).await?;
        session.send(refresh(LOCAL, 1)).await?;
        let ended = tokio::time::timeout(BOUND, session.message::<AttachHostResponse>()).await?;
        ensure!(
            matches!(&ended, Err(error) if error.code == ErrorCode::InvalidArgument),
            "a capability-2 host's access call: {ended:?}"
        );

        let mut session = access_session(&served, &id, &key).await?;
        session
            .send(input(attach_host_request::Input::AccessRefresh(Box::new(
                HostAccessRefresh {
                    request_id: "not-a-uuid".into(),
                    environment_id: ENVIRONMENT.into(),
                    local_environment_id: LOCAL.into(),
                    generation: 1,
                    ..Default::default()
                },
            ))))
            .await?;
        let ended = tokio::time::timeout(BOUND, async {
            loop {
                match session.message::<AttachHostResponse>().await {
                    Ok(Some(_)) => continue,
                    other => return other,
                }
            }
        })
        .await?;
        ensure!(
            matches!(&ended, Err(error) if error.code == ErrorCode::InvalidArgument),
            "a malformed request ID: {ended:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A Pod's key store that would answer for any environment it was asked
/// about: the host branch must never ask it.
struct PodKeys;

#[async_trait::async_trait]
impl crate::api::host_key::HostKeyStore for PodKeys {
    async fn current_host_key(
        &self,
        _environment_id: &str,
    ) -> Result<Option<(i64, String)>, sqlx::Error> {
        Ok(Some((99, OTHER_ACCESS_KEY.to_owned())))
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_environments_host_key_is_its_hosts_at_the_current_operation_generation()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, key) = host(&db, "access-lookup", 1).await?;
        running_on_host(&db, &id, "running").await?;
        let state = crate::api::test_state::offline(db.pool.clone()).await;
        let user = codewire_server_core::auth::AuthUser {
            user_id: OWNER.into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let lookup = || {
            crate::api::host_key::get_environment_host_key_core(
                &state,
                &user,
                ORG,
                ENVIRONMENT,
                &PodKeys,
            )
        };
        // No key yet is not found, and the Pod store is never asked.
        ensure!(matches!(
            lookup().await,
            Err(codewire_server_core::AppError::NotFound(_))
        ));

        let served = serve(&db, Timing::DEFAULT).await?;
        let mut session = access_session(&served, &id, &key).await?;
        session.send(record_key(1, ACCESS_KEY)).await?;
        ensure!(matches!(
            next_but_pongs(&mut session).await?,
            attach_host_response::Output::HostKeyRecorded(_)
        ));
        let found = lookup().await?;
        ensure!(
            found.generation == 5 && found.public_key_openssh == ACCESS_KEY,
            "{found:?}"
        );

        // A new operation generation has no key yet: not found, never the
        // older generation's.
        sqlx::query("UPDATE environments SET environment_operation_generation = 6 WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        ensure!(matches!(
            lookup().await,
            Err(codewire_server_core::AppError::NotFound(_))
        ));
        sqlx::query("UPDATE environments SET environment_operation_generation = 5 WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        ensure!(lookup().await?.public_key_openssh == ACCESS_KEY);

        // A revoked host's key, and a host environment with no host, are not
        // found; neither falls through to the Pod store (cw-security).
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        ensure!(matches!(
            lookup().await,
            Err(codewire_server_core::AppError::NotFound(_))
        ));
        sqlx::query("UPDATE environments SET host_id = NULL WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        ensure!(matches!(
            lookup().await,
            Err(codewire_server_core::AppError::NotFound(_))
        ));

        // Placement decides: the same environment off its host is a Pod's.
        sqlx::query(
            "UPDATE environments SET runtime_backend = 'kubernetes', host_id = NULL WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        let pods = lookup().await?;
        ensure!(pods.generation == 99 && pods.public_key_openssh == OTHER_ACCESS_KEY);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A host environment's daemon status is asked of its host, not of the
/// sandbox runtime (#6397): with no running report yet it is refused as not
/// running on its host, where it used to fail as a missing sandbox backend.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_environments_daemon_status_is_asked_of_its_host() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        setup(&db).await?;
        let (id, _key) = host(&db, "daemon-status", 1).await?;
        placed_environment(&db, &id).await?;
        sqlx::query(
            "UPDATE environments SET state = 'running', desired_state = 'started' WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        // No sandbox runtime at all: the sandbox path would fail on that.
        let state = crate::api::test_state::offline(db.pool.clone()).await;
        let user = codewire_server_core::auth::AuthUser {
            user_id: OWNER.into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let error = crate::api::environment_daemon::get_environment_daemon_status_core(
            &state,
            &user,
            ORG,
            ENVIRONMENT,
        )
        .await
        .err()
        .context("a status for a VM its host hasn't reported running")?;
        let text = format!("{error:?}");
        ensure!(
            text.contains("environment is not running on its host"),
            "refused on the host path: {text}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
