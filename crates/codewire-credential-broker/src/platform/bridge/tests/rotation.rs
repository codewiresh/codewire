//! Synthetic provider rotation over real generated gRPC and restricted SQL.
//! The listener is test-local plaintext loopback, not production TLS evidence.

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use codewire_platform_credentials::OAuthRefreshState;
use futures::stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::*;
use crate::codex_oauth::CodexOAuthCredential;
use crate::platform::tests::{
    Fixture as DatabaseFixture, SyntheticAuthority, support::TIMEOUT, token,
};

struct DatabaseAuthenticator(Arc<SyntheticAuthority>);

#[async_trait]
impl PlatformBridgeAuthenticator for DatabaseAuthenticator {
    type Authority = SyntheticAuthority;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Arc<Self::Authority>, PlatformBridgeAuthenticationError> {
        if metadata
            .get("x-synthetic-identity")
            .is_some_and(|value| value == "synthetic-allow")
        {
            Ok(Arc::clone(&self.0))
        } else {
            Err(PlatformBridgeAuthenticationError::Unauthenticated)
        }
    }
}

#[derive(Clone)]
struct RotatingUpstream {
    accepted: Arc<Notify>,
    release: Arc<Notify>,
    refresh_calls: Arc<AtomicUsize>,
    response_calls: Arc<AtomicUsize>,
    access_token: Arc<String>,
}

impl RotatingUpstream {
    fn new() -> Self {
        Self {
            accepted: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            refresh_calls: Arc::new(AtomicUsize::new(0)),
            response_calls: Arc::new(AtomicUsize::new(0)),
            access_token: Arc::new(token(serde_json::json!({
                "exp": crate::platform::unix_now().unwrap() + 7_200,
                "synthetic": "generated-service-rotated"
            }))),
        }
    }
}

#[async_trait]
impl BrokerUpstreamTransport for RotatingUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        if method != Method::POST {
            return Err(BrokerUpstreamError::Protocol);
        }
        match target.as_str() {
            "https://auth.openai.com/oauth/token" => {
                if self.refresh_calls.fetch_add(1, Ordering::SeqCst) != 0 {
                    return Err(BrokerUpstreamError::Protocol);
                }
                let payload: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| BrokerUpstreamError::Protocol)?;
                if payload["grant_type"] != "refresh_token"
                    || payload["refresh_token"] != "synthetic-refresh-old"
                    || headers.contains_key(http::header::AUTHORIZATION)
                {
                    return Err(BrokerUpstreamError::Protocol);
                }
                // This is the provider-accepted boundary. The response remains
                // pending while the generated call/owner is lost.
                self.accepted.notify_one();
                self.release.notified().await;
                let bytes = Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "access_token": self.access_token.as_str(),
                        "refresh_token": "synthetic-generated-service-refresh",
                        "token_type": "bearer"
                    }))
                    .map_err(|_| BrokerUpstreamError::Protocol)?,
                );
                Ok(BrokerUpstreamResponse::new(
                    StatusCode::OK,
                    HeaderMap::new(),
                    Box::pin(stream::once(async move { Ok(bytes) })),
                ))
            }
            "https://chatgpt.com/backend-api/codex/responses" => {
                self.response_calls.fetch_add(1, Ordering::SeqCst);
                let access = headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "));
                if access != Some(self.access_token.as_str())
                    || headers.get("chatgpt-account-id")
                        != Some(&HeaderValue::from_static("synthetic-account"))
                    || body != br#"{"input":"hello"}"#
                {
                    return Err(BrokerUpstreamError::Protocol);
                }
                Ok(BrokerUpstreamResponse::new(
                    StatusCode::OK,
                    HeaderMap::new(),
                    Box::pin(stream::once(async {
                        Ok(Bytes::from_static(b"synthetic response\n"))
                    })),
                ))
            }
            _ => Err(BrokerUpstreamError::Protocol),
        }
    }
}

type DatabaseService = PlatformCredentialBridgeService<DatabaseAuthenticator, RotatingUpstream>;

struct RunningService {
    service: DatabaseService,
    endpoint: String,
    stop_listener: CancellationToken,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl RunningService {
    async fn start(fixture: &DatabaseFixture, upstream: RotatingUpstream) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let service = DatabaseService::new(
            Arc::new(DatabaseAuthenticator(Arc::clone(&fixture.authority))),
            Arc::clone(&fixture.store),
            PlatformAccessProfileStore::new(fixture.pool.clone(), builtin_provider_catalog()),
            upstream,
        );
        let stop_listener = CancellationToken::new();
        let stop = stop_listener.clone();
        let generated = service.clone().into_server();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(generated)
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    stop.cancelled_owned(),
                )
                .await
        });
        Ok(Self {
            service,
            endpoint,
            stop_listener,
            server,
        })
    }

    async fn open(
        &self,
        fixture: &DatabaseFixture,
    ) -> Result<(
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Streaming<v1::CredentialBridgeHostMessage>,
    )> {
        let mut client = Client::connect(self.endpoint.clone()).await?;
        let (input, receiver) = mpsc::channel(4);
        input
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                    v1::CredentialBridgeReady {
                        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: fixture.context.environment_id.to_string(),
                        environment_generation: fixture.context.environment_generation,
                    },
                )),
            })
            .await?;
        let output = tokio::time::timeout(
            TIMEOUT,
            client.credential_bridge(rpc_request(receiver, Some("synthetic-allow"))),
        )
        .await
        .context("generated database bridge admission timed out")??
        .into_inner();
        Ok((input, output))
    }

    async fn finish(self) -> Result<()> {
        // No abort of the managed owner, including on a failed assertion. The
        // caller releases every synthetic barrier before invoking cleanup.
        let drained = tokio::time::timeout(TIMEOUT, self.service.shutdown())
            .await
            .context("generated service did not drain");
        self.stop_listener.cancel();
        let stopped = tokio::time::timeout(TIMEOUT, self.server)
            .await
            .context("generated test listener did not stop")?;
        drained??;
        stopped??;
        Ok(())
    }
}

fn request_frame() -> (String, v1::CredentialBridgeGuestMessage) {
    let id = Uuid::new_v4().to_string();
    (
        id.clone(),
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "codex".into(),
                    route: "openai-api".into(),
                    request_id: id,
                    method: "POST".into(),
                    path: "/responses".into(),
                    query: String::new(),
                    headers: vec![v1::CredentialHttpHeader {
                        name: "content-type".into(),
                        value: b"application/json".to_vec(),
                    }],
                    body: br#"{"input":"hello"}"#.to_vec(),
                },
            )),
        },
    )
}

async fn successful_response(
    output: &mut Streaming<v1::CredentialBridgeHostMessage>,
    request_id: &str,
) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let mut started = false;
        let mut body = Vec::new();
        loop {
            let message = output
                .message()
                .await?
                .context("response ended before End")?;
            match message.payload {
                Some(v1::credential_bridge_host_message::Payload::ResponseStart(start)) => {
                    ensure!(!started && start.request_id == request_id && start.status_code == 200);
                    started = true;
                }
                Some(v1::credential_bridge_host_message::Payload::ResponseBody(chunk)) => {
                    ensure!(started && chunk.request_id == request_id);
                    body.extend_from_slice(&chunk.data);
                    ensure!(body.len() <= 64);
                }
                Some(v1::credential_bridge_host_message::Payload::ResponseEnd(end)) => {
                    ensure!(started && end.request_id == request_id);
                    ensure!(body == b"synthetic response\n");
                    return Ok(());
                }
                _ => anyhow::bail!("unexpected generated response frame"),
            }
        }
    })
    .await
    .context("fresh generated response did not complete")?
}

async fn rotation_drain(shutdown: bool, direct: bool) -> Result<()> {
    // TEST_DATABASE_URL is required by this fixture: explicitly selecting an
    // ignored test cannot silently skip database acceptance.
    let fixture = DatabaseFixture::create_for_bridge().await?;
    let upstream = RotatingUpstream::new();
    let mut listeners = Vec::new();
    let result = async {
        listeners.push(RunningService::start(&fixture, upstream.clone()).await?);
        let service = listeners[0].service.clone();
        let (input, mut output): (_, BoxStream<'static, Result<v1::CredentialBridgeHostMessage, Status>>) = if direct {
            let (input, receiver) = mpsc::channel(4);
            input.send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ready(v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: fixture.context.environment_id.to_string(),
                    environment_generation: fixture.context.environment_generation,
                })),
            }).await?;
            let output = tokio::time::timeout(TIMEOUT, service.serve_authenticated(async {
                Ok((fixture.authority.clone(), ReceiverStream::new(receiver).map(Ok)))
            })).await.context("typed database bridge admission timed out")??.0;
            (input, output.boxed())
        } else {
            let (input, output) = listeners[0].open(&fixture).await?;
            (input, output.boxed())
        };
        input.send(request_frame().1).await?;
        tokio::time::timeout(TIMEOUT, async {
            tokio::select! {
                _ = upstream.accepted.notified() => Ok(()),
                frame = output.next() => {
                    match frame.and_then(|frame| frame.ok()).and_then(|frame| frame.payload) {
                        Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure)) => {
                            anyhow::bail!("synthetic request denied before provider acceptance (reason={})", failure.reason)
                        }
                        _ => anyhow::bail!("generated stream ended or responded before provider acceptance"),
                    }
                }
            }
        })
        .await
        .context("provider did not accept the synthetic refresh")??;
        let attempt = fixture
            .store
            .current_oauth_refresh_attempt(&fixture.owner, &fixture.record.metadata.id)
            .await?
            .context("durable Start missing at provider acceptance")?;
        ensure!(attempt.state == OAuthRefreshState::Started && attempt.execution_live);
        ensure!(attempt.expected == fixture.record.version);
        ensure!(upstream.refresh_calls.load(Ordering::SeqCst) == 1);
        ensure!(upstream.response_calls.load(Ordering::SeqCst) == 0);

        // The next unwrap is promotion's authentication of the durable staged
        // envelope. Initial admission/material reads have already completed.
        fixture.provider.unwrap_gate.arm();
        let mut shutdown_wait = Box::pin(service.shutdown());
        let mut retained_output = Some(output);
        let retained_input = if shutdown {
            ensure!(
                tokio::time::timeout(Duration::from_millis(50), &mut shutdown_wait)
                    .await
                    .is_err(),
                "shutdown returned while the provider response was pending"
            );
            ensure!(service.state.shutdown.is_cancelled());
            Some(input)
        } else {
            drop(retained_output.take());
            if direct {
                // The direct receiver's drop IS observable without input EOF.
                // Retain the input while proving the same publication drain.
                Some(input)
            } else {
                // A remote tonic response-half drop alone is not an HTTP/2
                // cancellation signal: that owner must release both halves.
                drop(input);
                None
            }
        };

        upstream.release.notify_one();
        fixture.provider.unwrap_gate.wait().await?;
        ensure!(fixture.state().await? == OAuthRefreshState::Staged);
        ensure!(
            fixture
                .store
                .record(&fixture.owner, &fixture.record.metadata.id)
                .await?
                .version
                == fixture.record.version,
            "staged data was published before authentication completed"
        );
        ensure!(service.state.workers.len() == 1);
        ensure!(
            tokio::time::timeout(
                Duration::from_millis(50),
                service
                    .state
                    .permits
                    .acquire_many(PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS as u32)
            )
            .await
            .is_err(),
            "the disconnected worker released capacity before publication"
        );
        if shutdown {
            ensure!(
                tokio::time::timeout(Duration::from_millis(50), &mut shutdown_wait)
                    .await
                    .is_err(),
                "shutdown returned while staged publication was pending"
            );
        }
        ensure!(upstream.refresh_calls.load(Ordering::SeqCst) == 1);
        ensure!(upstream.response_calls.load(Ordering::SeqCst) == 0);

        fixture.provider.unwrap_gate.release();
        let all_slots = tokio::time::timeout(
            TIMEOUT,
            service
                .state
                .permits
                .acquire_many(PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS as u32),
        )
        .await
        .context("managed publication did not release the original epoch")??;
        drop(all_slots);
        if shutdown {
            tokio::time::timeout(TIMEOUT, &mut shutdown_wait)
                .await
                .context("shutdown did not acknowledge completed publication")??;
        }
        drop(shutdown_wait);
        drop((retained_input, retained_output));
        ensure!(service.state.workers.is_empty());
        ensure!(upstream.response_calls.load(Ordering::SeqCst) == 0);

        let committed = fixture
            .store
            .current_oauth_refresh_attempt(&fixture.owner, &fixture.record.metadata.id)
            .await?
            .context("publication receipt missing")?;
        ensure!(committed.attempt_id == attempt.attempt_id);
        ensure!(committed.expected == attempt.expected);
        ensure!(committed.state == OAuthRefreshState::Committed);
        let record = fixture
            .store
            .record(&fixture.owner, &fixture.record.metadata.id)
            .await?;
        ensure!(
            record.version.revocation_generation
                == fixture.record.version.revocation_generation + 1
                && record.version.material_generation
                    == fixture.record.version.material_generation + 1
        );
        ensure!(record.metadata.expires_at_unix == fixture.record.metadata.expires_at_unix);
        let material = fixture
            .store
            .read_for_broker(&fixture.owner, &record.metadata.id, record.version)
            .await?;
        let credential = CodexOAuthCredential::parse(material.expose_secret())?;
        ensure!(credential.access_token() == upstream.access_token.as_str());
        ensure!(credential.refresh_token() == "synthetic-generated-service-refresh");
        ensure!(credential.account_id() == "synthetic-account");
        drop((credential, material));
        let private_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_credential_refresh_material WHERE attempt_id=$1",
        )
        .bind(attempt.attempt_id)
        .fetch_one(&fixture.pool)
        .await?;
        ensure!(
            private_rows == 0,
            "promoted staged material was not removed"
        );

        // A fresh generated service creates a fresh adapter and OpenAiBroker,
        // so success cannot come from the original request's private memory.
        listeners.push(RunningService::start(&fixture, upstream.clone()).await?);
        let (fresh_input, mut fresh_output) = listeners[1].open(&fixture).await?;
        let (request_id, frame) = request_frame();
        fresh_input.send(frame).await?;
        successful_response(&mut fresh_output, &request_id).await?;
        ensure!(upstream.refresh_calls.load(Ordering::SeqCst) == 1);
        ensure!(upstream.response_calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.state().await? == OAuthRefreshState::Committed);
        drop((fresh_input, fresh_output));
        Ok(())
    }
    .await;

    // Release even after a failed assertion; cleanup never aborts the managed
    // refresh owner or relies on the database disappearing to terminate work.
    upstream.release.notify_one();
    fixture.provider.unwrap_gate.release();
    let mut result = result;
    for listener in listeners {
        let cleanup = listener.finish().await;
        if result.is_ok() {
            result = cleanup;
        }
    }
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn generated_service_rpc_disconnect_drains_durable_oauth_rotation() -> Result<()> {
    rotation_drain(false, false).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn generated_service_shutdown_drains_durable_oauth_rotation() -> Result<()> {
    rotation_drain(true, false).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn trusted_receiver_drop_drains_durable_oauth_rotation_with_input_retained() -> Result<()> {
    rotation_drain(false, true).await
}

/// Answers only Codex Responses requests, with a fixed synthetic stream.
#[derive(Clone, Default)]
struct ResponsesUpstream(Arc<AtomicUsize>);

#[async_trait]
impl BrokerUpstreamTransport for ResponsesUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, _, _) = request.into_parts();
        if method != Method::POST
            || target.as_str() != "https://chatgpt.com/backend-api/codex/responses"
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Box::pin(stream::once(async {
                Ok(Bytes::from_static(b"synthetic response\n"))
            })),
        ))
    }
}

async fn completed_response(
    output: &mut ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>,
    request_id: &str,
) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let mut started = false;
        loop {
            let message = output
                .next()
                .await
                .context("epoch ended before the response End")??;
            match message.payload {
                Some(v1::credential_bridge_host_message::Payload::ResponseStart(start)) => {
                    ensure!(
                        !started && start.request_id == request_id && start.status_code == 200,
                        "unexpected response start (status={})",
                        start.status_code
                    );
                    started = true;
                }
                Some(v1::credential_bridge_host_message::Payload::ResponseBody(chunk)) => {
                    ensure!(started && chunk.request_id == request_id);
                }
                Some(v1::credential_bridge_host_message::Payload::ResponseEnd(end)) => {
                    ensure!(started && end.request_id == request_id);
                    return Ok(());
                }
                Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure)) => {
                    anyhow::bail!("synthetic request failed (reason={})", failure.reason)
                }
                _ => anyhow::bail!("unexpected response frame"),
            }
        }
    })
    .await
    .context("synthetic response did not complete")?
}

/// Each admitted epoch gets its own empty material cache: the first proxied
/// request of every epoch unwraps, and later requests in that epoch reuse.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn each_admitted_epoch_starts_with_a_cold_material_cache() -> Result<()> {
    let fixture = DatabaseFixture::create_for_bridge().await?;
    let upstream = ResponsesUpstream::default();
    let service = PlatformCredentialBridgeService::new(
        Arc::new(DatabaseAuthenticator(Arc::clone(&fixture.authority))),
        Arc::clone(&fixture.store),
        PlatformAccessProfileStore::new(fixture.pool.clone(), builtin_provider_catalog()),
        upstream.clone(),
    );
    let result = async {
        // A login whose access token is still valid needs no refresh.
        fixture
            .store
            .replace(
                &fixture.owner,
                &fixture.record.metadata.id,
                fixture.record.version,
                &crate::platform::tests::support::value(
                    crate::platform::tests::bundle(false, "fresh").as_bytes(),
                ),
                None,
            )
            .await?;
        let unwraps = || fixture.provider.unwrap_calls.load(Ordering::SeqCst);
        let initial = unwraps();
        for epoch in 1..=2 {
            let (input, receiver) = mpsc::channel(4);
            input
                .send(v1::CredentialBridgeGuestMessage {
                    payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                        v1::CredentialBridgeReady {
                            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                            environment_id: fixture.context.environment_id.to_string(),
                            environment_generation: fixture.context.environment_generation,
                        },
                    )),
                })
                .await?;
            let (mut output, _expires_at) = tokio::time::timeout(
                TIMEOUT,
                service.serve_authenticated(async {
                    Ok((
                        fixture.authority.clone(),
                        ReceiverStream::new(receiver).map(Ok),
                    ))
                }),
            )
            .await
            .context("typed database bridge admission timed out")??;
            for request in 1..=3 {
                let (request_id, frame) = request_frame();
                input.send(frame).await?;
                completed_response(&mut output, &request_id).await?;
                ensure!(
                    unwraps() == initial + epoch,
                    "epoch {epoch} request {request}: expected one unwrap per epoch"
                );
            }
            drop((input, output));
        }
        ensure!(upstream.0.load(Ordering::SeqCst) == 6);
        Ok(())
    }
    .await;
    let drained = tokio::time::timeout(TIMEOUT, service.shutdown())
        .await
        .context("generated service did not drain")
        .and_then(|drained| drained.map_err(anyhow::Error::from));
    fixture.finish(result.and(drained)).await
}
