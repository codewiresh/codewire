//! Actual public OAuth route and generated client over synthetic loopback HTTP/2.
//! Native gRPC here is h2c component proof, not public-edge TLS or Dev acceptance.

use super::*;
use async_trait::async_trait;
use buffa::Message as _;
use codewire_client::{
    ClientConfig, CodewireClient, CredentialDelegationStream, StaticTokenProvider,
};
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES, CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use codewire_proto::codewire::{bridge::v1 as public_bridge, v1 as proto};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router_with_auth};
use connectrpc::client::{BoxFuture, CallOptions, ClientBody, ClientTransport};
use connectrpc::{ConnectError, ErrorCode, Protocol};
use http::{Request, Response, StatusCode};
use tokio_util::sync::CancellationToken;

use crate::mutation::tests::support::{BOB, SESSION, api_key};

const PATH: &str = "/codewire.v1.CredentialDelegationService/DelegateCredentials";
const BOUND: Duration = Duration::from_secs(20);

struct RejectPods;

/// The delegation route of a service with no local-boot seal key.
fn unsealed<A, U>(h: &Harness, bridge: PlatformCredentialBridgeService<A, U>) -> axum::Router
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    crate::delegation::router(
        h.pool.clone(),
        h.provider.clone(),
        bridge,
        crate::delegation::BootSeal::default(),
    )
}

#[async_trait]
impl PlatformBridgeAuthenticator for RejectPods {
    type Authority = OwnerLocalRuntimeAuthority;

    async fn authenticate(
        &self,
        _: &tonic::metadata::MetadataMap,
    ) -> Result<Arc<Self::Authority>, PlatformBridgeAuthenticationError> {
        panic!("public owner admission must not invoke private Pod authentication")
    }
}

#[derive(Clone)]
struct NoUpstream;

#[async_trait]
impl BrokerUpstreamTransport for NoUpstream {
    async fn execute(
        &self,
        _: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        panic!("empty profile must not reach a provider")
    }
}

/// The native-gRPC fixture uses the same generated client and lossless response
/// conversion as the facade, with an explicit h2c test protocol selection.
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

pub(super) fn opening(selection: &OwnerLocalSelection) -> proto::CredentialDelegationOpen {
    let source = &selection.platform;
    proto::CredentialDelegationOpen {
        runtime: Some(public_bridge::CredentialBridgeOpen {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: selection.local_environment_id.to_string(),
            environment_generation: selection.local_environment_generation,
            ..Default::default()
        })
        .into(),
        org_id: source.organization.clone(),
        selection_sha256: selection.selection_sha256.to_vec(),
        project_id: source.project_id.clone(),
        user_secrets: source.user_selected,
        organization_secrets: source.organization_selected,
        profile: source
            .profile
            .as_ref()
            .map(|(id, revision)| proto::CredentialDelegationProfile {
                profile_id: id.clone(),
                profile_revision: *revision,
                ..Default::default()
            })
            .into(),
        ordinary_environment_keys: source.ordinary_keys.iter().cloned().collect(),
        reserved_environment_keys: source.reserved_keys.iter().cloned().collect(),
        ..Default::default()
    }
}

fn frame(
    payload: public_bridge::credential_bridge_guest_message::Payload,
) -> proto::DelegateCredentialsRequest {
    proto::DelegateCredentialsRequest {
        input: Some(proto::delegate_credentials_request::Input::Frame(Box::new(
            public_bridge::CredentialBridgeGuestMessage {
                payload: Some(payload),
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn ready(open: &proto::CredentialDelegationOpen) -> proto::DelegateCredentialsRequest {
    frame(
        public_bridge::credential_bridge_guest_message::Payload::Ready(Box::new(
            public_bridge::CredentialBridgeReady {
                protocol_version: open.runtime.protocol_version,
                environment_id: open.runtime.environment_id.clone(),
                environment_generation: open.runtime.environment_generation,
                ..Default::default()
            },
        )),
    )
}

async fn raw(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    options: CallOptions,
) -> Result<CredentialDelegationStream> {
    let client = proto::CredentialDelegationServiceClient::new(
        Transport(client.clone()),
        connectrpc::client::ClientConfig::new(url.parse()?).with_protocol(protocol),
    );
    Ok(client.delegate_credentials_with_options(options).await?)
}

async fn response(
    stream: &mut CredentialDelegationStream,
) -> Result<proto::DelegateCredentialsResponse> {
    Ok(tokio::time::timeout(
        BOUND,
        stream.message::<proto::DelegateCredentialsResponse>(),
    )
    .await??
    .context("public stream ended without a response")?
    .to_owned_message())
}

async fn connect(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    open: proto::CredentialDelegationOpen,
) -> Result<CredentialDelegationStream> {
    if protocol == Protocol::Connect {
        let admitted = CodewireClient::with_http(
            ClientConfig::new(url)?,
            StaticTokenProvider::new(oauth(ALICE))?,
            client.clone(),
        )?
        .delegate_credentials(open)
        .await?;
        ensure!(
            admitted.accepts_keepalive,
            "admission did not offer keepalives"
        );
        return Ok(admitted.stream);
    }
    let mut stream = raw(
        client,
        url,
        protocol,
        CallOptions::default()
            .try_with_header("authorization", format!("Bearer {}", oauth(ALICE)))?,
    )
    .await?;
    stream
        .send(proto::DelegateCredentialsRequest {
            input: Some(proto::delegate_credentials_request::Input::Open(Box::new(
                open.clone(),
            ))),
            ..Default::default()
        })
        .await?;
    stream.send(ready(&open)).await?;
    let acknowledgment = response(&mut stream).await?;
    ensure!(
        acknowledgment.accepts_keepalive,
        "admission did not offer keepalives"
    );
    ensure!(matches!(acknowledgment.output,
        Some(proto::delegate_credentials_response::Output::Admitted(accepted)) if *accepted == open));
    Ok(stream)
}

/// A raw admission as `owner`, and the front-door handle its answer carries
/// (#4909).
async fn admit_raw(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    open: &proto::CredentialDelegationOpen,
) -> Result<(CredentialDelegationStream, Vec<u8>)> {
    let mut stream = raw(
        client,
        url,
        protocol,
        CallOptions::default()
            .try_with_header("authorization", format!("Bearer {}", oauth(ALICE)))?,
    )
    .await?;
    stream
        .send(proto::DelegateCredentialsRequest {
            input: Some(proto::delegate_credentials_request::Input::Open(Box::new(
                open.clone(),
            ))),
            ..Default::default()
        })
        .await?;
    stream.send(ready(open)).await?;
    let acknowledgment = response(&mut stream).await?;
    ensure!(matches!(
        acknowledgment.output,
        Some(proto::delegate_credentials_response::Output::Admitted(_))
    ));
    Ok((stream, acknowledgment.front_door_epoch))
}

/// A front-door join as `owner` presenting `handle`, its first frame the
/// epoch's Ready. The stream is held by the caller while it lives.
async fn join_front_door(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    owner: &str,
    handle: &[u8],
    open: &proto::CredentialDelegationOpen,
) -> Result<
    connectrpc::client::BidiStream<
        reqwest::Body,
        proto::FrontDoorDelegationRequest,
        proto::__buffa::view::FrontDoorDelegationResponseView<'static>,
    >,
> {
    let options = CallOptions::default()
        .try_with_header("authorization", format!("Bearer {}", oauth(owner)))?
        .try_with_header(
            CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(handle),
        )?;
    let mut stream = proto::CredentialDelegationServiceClient::new(
        Transport(client.clone()),
        connectrpc::client::ClientConfig::new(url.parse()?).with_protocol(protocol),
    )
    .front_door_delegation_with_options(options)
    .await?;
    let Some(proto::delegate_credentials_request::Input::Frame(frame)) = ready(open).input else {
        anyhow::bail!("the Ready helper changed");
    };
    let _ = stream
        .send(proto::FrontDoorDelegationRequest {
            frame: Some(*frame).into(),
            ..Default::default()
        })
        .await;
    Ok(stream)
}

/// What a join that must be refused was answered.
async fn join_refused(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    owner: &str,
    handle: &[u8],
    open: &proto::CredentialDelegationOpen,
) -> Result<(ErrorCode, String)> {
    let mut stream = join_front_door(client, url, protocol, owner, handle, open).await?;
    match tokio::time::timeout(
        BOUND,
        stream.message::<proto::FrontDoorDelegationResponse>(),
    )
    .await?
    {
        Err(error) => Ok((error.code, error.message.unwrap_or_default())),
        // An admission, or anything else, before the refusal is a join served.
        Ok(_) => anyhow::bail!("a front-door join that must be refused was answered"),
    }
}

/// A join that must be served: its first answer is the admission, naming
/// exactly the front-door operations the epoch serves.
async fn join_admitted(
    client: &reqwest::Client,
    url: &str,
    protocol: Protocol,
    handle: &[u8],
    open: &proto::CredentialDelegationOpen,
) -> Result<impl Sized> {
    let mut stream = join_front_door(client, url, protocol, ALICE, handle, open).await?;
    let first = tokio::time::timeout(
        BOUND,
        stream.message::<proto::FrontDoorDelegationResponse>(),
    )
    .await??
    .context("the join ended before its admission")?
    .to_owned_message();
    let Some(proto::front_door_delegation_response::Output::Admitted(admitted)) = first.output
    else {
        anyhow::bail!("a join's first answer was not its admission");
    };
    ensure!(
        admitted.capabilities
            == [
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
            ],
        "{:?}",
        admitted.capabilities
    );
    Ok(stream)
}

fn keepalive() -> proto::DelegateCredentialsRequest {
    proto::DelegateCredentialsRequest {
        input: Some(proto::delegate_credentials_request::Input::Keepalive(
            Box::default(),
        )),
        ..Default::default()
    }
}

async fn journey(protocol: Protocol) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let h = Harness::unserved(address).await?;
    let bridge = PlatformCredentialBridgeService::new(
        Arc::new(RejectPods),
        h.store.clone(),
        PlatformAccessProfileStore::new(h.pool.clone(), builtin_provider_catalog()),
        NoUpstream,
    );
    let stop = CancellationToken::new();
    let stopped = stop.clone();
    let router = unsealed(&h, bridge.clone()).merge(connect_router_with_auth(
        h.owner.router(),
        ConnectAuthLayer::oauth_bearer_only(AuthState {
            pool: h.pool.clone(),
        }),
    ));
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(stopped.cancelled_owned())
            .await
    });
    let result = tokio::time::timeout(BOUND, async {
        let (selection, _) = setup_owner_sources(&h).await?;
        let open = opening(&selection);
        let url = format!("http://{address}");
        let client = reqwest::Client::builder().no_proxy().http2_prior_knowledge().build()?;
        for options in [
            CallOptions::default(),
            CallOptions::default().try_with_header("cookie", format!("{}={SESSION}", codewire_server_core::auth::SESSION_COOKIE_NAME))?,
            CallOptions::default().try_with_header("authorization", format!("Bearer {}", api_key()))?,
            CallOptions::default().try_with_header("authorization", "Bearer synthetic-purported-pod")?,
        ] {
            let mut denied = raw(&client, &url, protocol, options).await?;
            let _ = denied.send(proto::DelegateCredentialsRequest {
                input: Some(proto::delegate_credentials_request::Input::Open(Box::new(open.clone()))), ..Default::default()
            }).await;
            ensure!(response(&mut denied).await.is_err(), "non-OAuth authority admitted");
        }
        for content_type in ["text/plain", "application/grpc-web+proto"] {
            ensure!(client.post(format!("{url}{PATH}")).header("content-type", content_type).body("synthetic").send().await?.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        // The mutation mount's fallback rejects native gRPC with 415 before
        // routing. Use admitted content/auth to prove the private route absent.
        ensure!(client.post(format!("{url}/broker.v1.CredentialBrokerService/CredentialBridge")).header("content-type", "application/connect+proto").bearer_auth(oauth(ALICE)).send().await?.status() == StatusCode::NOT_FOUND);
        ensure!(client.post(format!("{url}/codewire.v1.CredentialMutationService/EnrollCodex")).header("content-type", "application/grpc+proto").send().await?.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut wrong_runtime = raw(&client, &url, protocol, CallOptions::default().try_with_header("authorization", format!("Bearer {}", oauth(ALICE)))?).await?;
        wrong_runtime.send(proto::DelegateCredentialsRequest {
            input: Some(proto::delegate_credentials_request::Input::Open(Box::new(open.clone()))), ..Default::default()
        }).await?;
        let mut changed = open.clone();
        changed.runtime.get_or_insert_default().environment_generation += 1;
        wrong_runtime.send(ready(&changed)).await?;
        ensure!(response(&mut wrong_runtime).await.is_err(), "wrong native generation admitted");
        drop(wrong_runtime);

        // A keepalive before admission (between Open and Ready) ends the stream.
        let mut early = raw(&client, &url, protocol, CallOptions::default().try_with_header("authorization", format!("Bearer {}", oauth(ALICE)))?).await?;
        early.send(proto::DelegateCredentialsRequest {
            input: Some(proto::delegate_credentials_request::Input::Open(Box::new(open.clone()))), ..Default::default()
        }).await?;
        early.send(keepalive()).await?;
        let _ = early.send(ready(&open)).await;
        ensure!(response(&mut early).await.is_err(), "keepalive before admission accepted");
        drop(early);

        put(&format!("/users/{ALICE}"), "DATABASE_URL", b"synthetic-application-value", &h.db.pool).await?;
        let mut stream = connect(&client, &url, protocol, open.clone()).await?;
        // This legal bridge frame exceeds the default 4MiB Connect ceiling.
        // It must reach grant admission and be refused there as a slot the
        // empty profile doesn't select, with the readable refusal (#5057),
        // not fail in the dispatcher. No empty-profile material may be read.
        stream.send(frame(public_bridge::credential_bridge_guest_message::Payload::Request(Box::new(public_bridge::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(), method: "POST".into(), path: "/v1/responses".into(),
            body: vec![b' '; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES], capability_slot: "codex".into(), route: "openai-api".into(), ..Default::default()
        })))).await?;
        let refusal = codewire_access::Refusal::NoCredentialSelected;
        ensure!(matches!(response(&mut stream).await?.output, Some(proto::delegate_credentials_response::Output::Frame(frame))
            if matches!(&frame.payload, Some(public_bridge::credential_bridge_host_message::Payload::ResponseStart(start))
                if start.status_code == u32::from(refusal.status())
                    && start.headers.iter().any(|header| header.name == codewire_access::REFUSAL_HEADER
                        && header.value == refusal.reason().as_bytes()))),
            "an unselected slot was not refused as no_credential_selected");
        // Its body and end follow before the stream serves anything else.
        loop {
            let Some(proto::delegate_credentials_response::Output::Frame(frame)) = response(&mut stream).await?.output else { anyhow::bail!("missing refusal frame") };
            match frame.payload {
                Some(public_bridge::credential_bridge_host_message::Payload::ResponseBody(_)) => {}
                Some(public_bridge::credential_bridge_host_message::Payload::ResponseEnd(_)) => break,
                _ => anyhow::bail!("unexpected frame inside the refusal"),
            }
        }

        let (request, recipient, context) = projection_request(&selection, unix_millis()? + 15_000);
        let projection = public_bridge::EnvironmentProjectionRequest {
            request_id: request.request_id.clone(), recipient_public_key: request.recipient_public_key.clone(),
            selection_sha256: request.selection_sha256.clone(), deadline_unix_ms: request.deadline_unix_ms, ..Default::default()
        };
        stream.send(frame(public_bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(Box::new(projection.clone())))).await?;
        let sealed = response(&mut stream).await?;
        ensure!(!sealed.encode_to_vec().windows(b"synthetic-application-value".len()).any(|bytes| bytes == b"synthetic-application-value"));
        let Some(proto::delegate_credentials_response::Output::Frame(sealed)) = sealed.output else { anyhow::bail!("missing projection frame") };
        let Some(public_bridge::credential_bridge_host_message::Payload::EnvironmentProjection(sealed)) = sealed.payload else { anyhow::bail!("missing sealed projection") };
        ensure!(sealed.request_id == request.request_id);
        let Some(public_bridge::environment_projection_response::Result::SealedProjection(sealed)) = sealed.result else { anyhow::bail!("projection denied") };
        ensure!(recipient.open(&sealed, &context, unix_millis()?)?.entries().collect::<BTreeMap<_, _>>() == BTreeMap::from([("DATABASE_URL", "synthetic-application-value")]));

        // Each keepalive gets exactly one answer, on the same admitted stream,
        // and the stream still serves operations afterwards (#2702).
        for _ in 0..2 {
            stream.send(keepalive()).await?;
            let answer = response(&mut stream).await?;
            ensure!(matches!(answer.output, Some(proto::delegate_credentials_response::Output::Keepalive(_))), "keepalive not answered");
            ensure!(!answer.accepts_keepalive, "the flag belongs to the admission only");
        }

        // The owner's local front door joins its own epoch by the handle the
        // admission answered with; nobody else does (#4909). An unknown and
        // another owner's handle get one refusal, word for word.
        let step = Duration::from_secs(5);
        // An Open that doesn't declare a front door gets no handle.
        let (undeclared, none) = tokio::time::timeout(step, admit_raw(&client, &url, protocol, &open))
            .await
            .context("front door: undeclared admission")??;
        ensure!(none.is_empty(), "an undeclared delegation got a handle");
        drop(undeclared);
        let mut open = open.clone();
        open.front_door = true;
        let (epoch, handle) = tokio::time::timeout(step, admit_raw(&client, &url, protocol, &open))
            .await
            .context("front door: admission")??;
        ensure!(handle.len() == CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES, "the admission carries one handle");
        let joined = tokio::time::timeout(step, join_admitted(&client, &url, protocol, &handle, &open))
            .await
            .context("front door: first join")??;
        let (code, _) = tokio::time::timeout(step, join_refused(&client, &url, protocol, ALICE, &handle, &open))
            .await
            .context("front door: second join")??;
        ensure!(code == ErrorCode::AlreadyExists, "a second join of a live epoch: {code:?}");
        let mut unknown = handle.clone();
        unknown[0] ^= 1;
        for (owner, presented) in [(BOB, handle.as_slice()), (ALICE, unknown.as_slice())] {
            let refusal = tokio::time::timeout(step, join_refused(&client, &url, protocol, owner, presented, &open))
                .await
                .context("front door: refused join")??;
            ensure!(refusal == (ErrorCode::PermissionDenied, "credential delegation denied".to_owned()), "{refusal:?}");
        }
        drop((joined, epoch));

        // A repeated Open and an over-limit envelope close their own epochs.
        for oversized in [false, true] {
            let mut bad = connect(&client, &url, protocol, open.clone()).await?;
            let mut second = open.clone();
            if oversized { second.selection_sha256 = vec![0; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 9]; }
            let _ = bad.send(proto::DelegateCredentialsRequest {
                input: Some(proto::delegate_credentials_request::Input::Open(Box::new(second))), ..Default::default()
            }).await;
            ensure!(response(&mut bad).await.is_err(), "invalid epoch frame admitted");
        }
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1").bind(hash_oauth_token(&oauth(ALICE))).execute(&h.db.pool).await?;
        let mut revoked = projection;
        revoked.request_id = Uuid::new_v4().to_string();
        let _ = stream.send(frame(public_bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(Box::new(revoked)))).await;
        if let Ok(response) = response(&mut stream).await {
            let Some(proto::delegate_credentials_response::Output::Frame(frame)) = response.output else { anyhow::bail!("revoked epoch acknowledged") };
            ensure!(matches!(frame.payload.as_ref(), Some(public_bridge::credential_bridge_host_message::Payload::EnvironmentProjection(response))
                if matches!(response.result, Some(public_bridge::environment_projection_response::Result::Failure(_)))));
        }
        drop(stream);
        Ok::<_, anyhow::Error>(())
    }).await.context("bounded public owner-local journey").and_then(|result| result);
    stop.cancel();
    let drain = tokio::time::timeout(BOUND, bridge.shutdown())
        .await
        .context("public broker drain")
        .and_then(|result| result.map_err(anyhow::Error::from));
    let joined = tokio::time::timeout(BOUND, &mut server).await;
    if joined.is_err() {
        server.abort();
        let _ = server.await;
    }
    let joined = joined
        .context("public listener shutdown")
        .and_then(|result| result.context("public listener join"))
        .and_then(|result| result.map_err(anyhow::Error::from));
    h.finish(result.and(drain).and(joined)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn public_connect_owner_oauth_facade_projection_revocation_and_limits() -> Result<()> {
    journey(Protocol::Connect).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn public_native_grpc_owner_oauth_projection_revocation_and_limits() -> Result<()> {
    journey(Protocol::Grpc).await
}

/// An unsigned JWT with `payload`, the shape a synthetic Codex sign-in takes.
fn synthetic_jwt(payload: serde_json::Value) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.synthetic-signature",
        encode(br#"{"alg":"none"}"#),
        encode(&serde_json::to_vec(&payload).expect("JSON"))
    )
}

/// #6191, through the real owner-local authority and platform bridge on the
/// public delegation route: a local VM has no `environments` row, and its
/// delegation declares a front door. Its Codex login is delivered, and the
/// access token is the placeholder derived under its owner's local root, not
/// a refusal `no_placeholder_beside_front_door` (Dev, 2026-11-22 and 23). One
/// root is stored for the owner, and no hosted environment key is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_front_door_delegation_with_no_environment_row_gets_its_owners_local_placeholder()
-> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let h = Harness::unserved(address).await?;
    let bridge = PlatformCredentialBridgeService::new(
        Arc::new(RejectPods),
        h.store.clone(),
        PlatformAccessProfileStore::new(h.pool.clone(), builtin_provider_catalog()),
        NoUpstream,
    );
    let stop = CancellationToken::new();
    let stopped = stop.clone();
    let router = unsealed(&h, bridge.clone());
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(stopped.cancelled_owned())
            .await
    });
    let result = tokio::time::timeout(BOUND, async {
        let owner = OwnerId::parse(ALICE)?;
        let (bundle, _) = codewire_credential_broker::import_codex_tokens(
            Zeroizing::new(synthetic_jwt(serde_json::json!({
                "https://api.openai.com/auth": { "chatgpt_account_id": "synthetic-account" }
            }))),
            Zeroizing::new(synthetic_jwt(
                serde_json::json!({ "exp": 4_000_000_000_u64 }),
            )),
            Zeroizing::new("synthetic-codex-refresh-token".to_owned()),
        )?
        .into_parts();
        let credential = h
            .store
            .create(
                &Owner::User(owner.clone()),
                CredentialRegistration {
                    provider: ProviderId::parse("openai")?,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "owner-local codex sign-in".into(),
                    account_hint: None,
                    expires_at_unix: Some(4_000_000_000),
                },
                &ProtectedValue::from_slice(bundle.as_bytes())?,
            )
            .await?;
        let (selection, _) = setup_owner_sources_with_entries(
            &h,
            BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await?;
        let environment = EnvironmentId::parse(selection.local_environment_id.to_string())?;
        let rows = |table: &'static str| {
            let pool = h.db.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}"))
                    .fetch_one(&pool)
                    .await
            }
        };
        ensure!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM environments WHERE id=$1")
                .bind(environment.as_str())
                .fetch_one(&h.db.pool)
                .await?
                == 0,
            "the local VM must have no environments row"
        );
        ensure!(rows("platform_local_placeholder_roots").await? == 0);
        let hosted_keys = rows("platform_placeholder_keys").await?;

        let mut open = opening(&selection);
        open.front_door = true;
        open.runtime
            .get_or_insert_default()
            .capabilities
            .push(codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN.into());
        let client = reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .build()?;
        let mut stream = connect(
            &client,
            &format!("http://{address}"),
            Protocol::Grpc,
            open.clone(),
        )
        .await?;

        let recipient = ProjectionRecipient::new();
        let request_id = Uuid::new_v4();
        let context = codewire_workload_secrets::CodexLoginContext {
            environment_id: *selection.local_environment_id.as_bytes(),
            environment_generation: selection.local_environment_generation,
            request_id: *request_id.as_bytes(),
            deadline_unix_ms: unix_millis()? + 20_000,
        };
        stream
            .send(frame(
                public_bridge::credential_bridge_guest_message::Payload::CodexLogin(Box::new(
                    public_bridge::CodexLoginRequest {
                        request_id: request_id.to_string(),
                        recipient_public_key: recipient.public_key().to_vec(),
                        deadline_unix_ms: context.deadline_unix_ms,
                        ..Default::default()
                    },
                )),
            ))
            .await?;
        let Some(proto::delegate_credentials_response::Output::Frame(answer)) =
            response(&mut stream).await?.output
        else {
            anyhow::bail!("no login frame");
        };
        let Some(public_bridge::credential_bridge_host_message::Payload::CodexLogin(login)) =
            answer.payload
        else {
            anyhow::bail!("the answer is not a Codex login");
        };
        let Some(public_bridge::codex_login_response::Result::SealedLogin(sealed)) = login.result
        else {
            anyhow::bail!("the Codex login was refused: {:?}", login.result);
        };
        let opened = recipient.open_codex_login(&sealed, &context, unix_millis()?)?;

        let key = h
            .store
            .owner_local_placeholder_key(&owner, &environment)
            .await?;
        let profile_revision = selection
            .platform
            .profile
            .as_ref()
            .map_or(0, |(_, revision)| *revision);
        let expected = codewire_access::CredentialPlaceholder::derive(
            &key,
            &environment,
            profile_revision,
            &CapabilitySlot::codex(),
            &credential.metadata.id,
        );
        ensure!(
            opened.login.access_token() == expected.as_str(),
            "the access token is the owner-local placeholder"
        );
        ensure!(
            !opened.login.id_token().contains("synthetic-signature"),
            "the ID token is the placeholder form, not the sign-in's"
        );
        ensure!(rows("platform_local_placeholder_roots").await? == 1);
        ensure!(
            rows("platform_placeholder_keys").await? == hosted_keys,
            "no hosted environment key is made for a local VM"
        );
        drop(stream);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("bounded owner-local placeholder login")
    .and_then(|result| result);
    stop.cancel();
    let drain = tokio::time::timeout(BOUND, bridge.shutdown())
        .await
        .context("public broker drain")
        .and_then(|result| result.map_err(anyhow::Error::from));
    let joined = tokio::time::timeout(BOUND, &mut server).await;
    if joined.is_err() {
        server.abort();
        let _ = server.await;
    }
    let joined = joined
        .context("public listener shutdown")
        .and_then(|result| result.context("public listener join"))
        .and_then(|result| result.map_err(anyhow::Error::from));
    h.finish(result.and(drain).and(joined)).await
}

/// One seed placeholder route (#4001) over a fresh database: Alice's profile
/// selects one Anthropic API key, and the route's rate limit starts empty.
pub(super) struct SeedRoute<'a> {
    pub(super) h: &'a Harness,
    key: codewire_access::CredentialId,
    pub(super) selection: OwnerLocalSelection,
    pub(super) open: proto::CredentialDelegationOpen,
    url: String,
    http: reqwest::Client,
}

impl SeedRoute<'_> {
    pub(super) fn client(&self, bearer: String) -> Result<CodewireClient> {
        Ok(CodewireClient::with_http(
            ClientConfig::new(&self.url)?,
            StaticTokenProvider::new(bearer)?,
            self.http.clone(),
        )?)
    }
}

fn slots(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Serve the delegation route on its own listener, set up Alice's selection,
/// run `body` against it within [`BOUND`], and tear everything down.
async fn with_seed_route(body: impl AsyncFnOnce(&SeedRoute<'_>) -> Result<()>) -> Result<()> {
    with_route(crate::delegation::BootSeal::default(), body).await
}

/// [`with_seed_route`] with `seal` as the service's local-boot seal key.
pub(super) async fn with_route(
    seal: crate::delegation::BootSeal,
    body: impl AsyncFnOnce(&SeedRoute<'_>) -> Result<()>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let h = Harness::unserved(address).await?;
    let bridge = PlatformCredentialBridgeService::new(
        Arc::new(RejectPods),
        h.store.clone(),
        PlatformAccessProfileStore::new(h.pool.clone(), builtin_provider_catalog()),
        NoUpstream,
    );
    let stop = CancellationToken::new();
    let stopped = stop.clone();
    let router = crate::delegation::router(h.pool.clone(), h.provider.clone(), bridge, seal);
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(stopped.cancelled_owned())
            .await
    });
    let result = tokio::time::timeout(BOUND, async {
        let key = h
            .store
            .create(
                &Owner::User(OwnerId::parse(ALICE)?),
                CredentialRegistration {
                    provider: ProviderId::parse("anthropic")?,
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "Anthropic key".into(),
                    account_hint: None,
                    expires_at_unix: Some(4_102_444_800),
                },
                &ProtectedValue::from_slice(b"sk-ant-synthetic-key-never-public")?,
            )
            .await?;
        let (selection, _) = setup_owner_sources_with_entries(
            &h,
            BTreeMap::from([(CapabilitySlot::anthropic(), key.metadata.id.clone())]),
        )
        .await?;
        let route = SeedRoute {
            h: &h,
            key: key.metadata.id,
            open: opening(&selection),
            selection,
            url: format!("http://{address}"),
            http: reqwest::Client::builder()
                .no_proxy()
                .http2_prior_knowledge()
                .build()?,
        };
        body(&route).await
    })
    .await
    .context("seed placeholder test timed out")
    .and_then(|result| result);
    stop.cancel();
    let joined = tokio::time::timeout(BOUND, &mut server).await;
    if joined.is_err() {
        server.abort();
        let _ = server.await;
    }
    let joined = joined
        .context("public listener shutdown")
        .and_then(|result| result.context("public listener join"))
        .and_then(|result| result.map_err(anyhow::Error::from));
    h.finish(result.and(joined)).await
}

/// #4001: a granted slot's seed placeholder is its delegation leases'
/// derivation under the owner's local root (`platform::tests::placeholders`
/// holds that derivation equal to a lease's), stable across calls; a slot
/// not granted is left out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_seed_placeholder_is_its_delegation_leases_derivation() -> Result<()> {
    with_seed_route(async |route: &SeedRoute<'_>| {
        let alice = route.client(oauth(ALICE))?;
        let answer = seed_call(&alice, route.open.clone(), slots(&["anthropic", "github"])).await?;
        ensure!(
            answer.placeholders.len() == 1 && answer.placeholders[0].capability_slot == "anthropic",
            "only the granted slot is answered"
        );
        let environment = codewire_access::EnvironmentId::parse(
            route.selection.local_environment_id.to_string(),
        )?;
        let (_, revision) = route
            .selection
            .platform
            .profile
            .clone()
            .context("a profile")?;
        let derived = codewire_access::CredentialPlaceholder::derive(
            &route
                .h
                .store
                .owner_local_placeholder_key(&OwnerId::parse(ALICE)?, &environment)
                .await?,
            &environment,
            revision,
            &CapabilitySlot::anthropic(),
            &route.key,
        );
        ensure!(
            codewire_access::CredentialPlaceholder::parse(&answer.placeholders[0].placeholder)?
                .ct_eq(&derived),
            "the seed's placeholder is its leases' derivation"
        );
        let again = seed_call(&alice, route.open.clone(), slots(&["anthropic"])).await?;
        ensure!(
            again.placeholders == answer.placeholders,
            "the value is stable"
        );
        Ok(())
    })
    .await
}

/// #4001: the seed's selection is admitted exactly as its delegation's Open
/// is, before any key is read: every refused selection, and every slot list
/// that is unknown, repeated or past 16, is the same `PERMISSION_DENIED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_seed_refuses_each_selection_its_delegation_would() -> Result<()> {
    with_seed_route(async |route: &SeedRoute<'_>| {
        let alice = route.client(oauth(ALICE))?;
        let open = &route.open;
        let mut refused = Vec::new();
        let mut other_revision = open.clone();
        other_revision
            .profile
            .get_or_insert_default()
            .profile_revision += 1;
        refused.push(other_revision);
        let mut uppercase = open.clone();
        uppercase.runtime.get_or_insert_default().environment_id = route
            .selection
            .local_environment_id
            .to_string()
            .to_uppercase();
        refused.push(uppercase);
        let mut nil = open.clone();
        nil.runtime.get_or_insert_default().environment_id = Uuid::nil().to_string();
        refused.push(nil);
        let mut no_generation = open.clone();
        no_generation
            .runtime
            .get_or_insert_default()
            .environment_generation = 0;
        refused.push(no_generation);
        let mut no_digest = open.clone();
        no_digest.selection_sha256 = vec![0; 32];
        refused.push(no_digest);
        let mut other_organization = open.clone();
        other_organization.org_id = "another-organization".into();
        refused.push(other_organization);
        for selection in refused {
            let error = seed_call(&alice, selection, slots(&["anthropic"]))
                .await
                .expect_err("a refused selection was answered");
            ensure!(error.code() == codewire_client::ErrorCode::PermissionDenied);
        }
        for bad in [
            slots(&["not-a-slot"]),
            slots(&["anthropic", "anthropic"]),
            vec!["anthropic".to_owned(); 17],
        ] {
            let error = seed_call(&alice, open.clone(), bad)
                .await
                .expect_err("a bad slot list was answered");
            ensure!(error.code() == codewire_client::ErrorCode::PermissionDenied);
        }
        Ok(())
    })
    .await
}

/// #4001: only the selection's own creator is answered. Another user naming
/// Alice's selection is refused as any refused selection is, and an
/// organization API key never reaches the method.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_seed_answers_only_its_selections_owner_over_oauth() -> Result<()> {
    with_seed_route(async |route: &SeedRoute<'_>| {
        let error = seed_call(
            &route.client(oauth(BOB))?,
            route.open.clone(),
            slots(&["anthropic"]),
        )
        .await
        .expect_err("another user's selection was answered");
        ensure!(error.code() == codewire_client::ErrorCode::PermissionDenied);
        let error = seed_call(
            &route.client(api_key())?,
            route.open.clone(),
            slots(&["anthropic"]),
        )
        .await
        .expect_err("an API key was answered");
        ensure!(error.code() == codewire_client::ErrorCode::Unauthenticated);
        Ok(())
    })
    .await
}

/// #4001: a user's 31st seed call in a minute is `RESOURCE_EXHAUSTED`, and
/// a refused call counts toward the limit as an answered one does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_users_thirty_first_seed_call_in_a_minute_is_rate_limited() -> Result<()> {
    with_seed_route(async |route: &SeedRoute<'_>| {
        let alice = route.client(oauth(ALICE))?;
        let mut other_revision = route.open.clone();
        other_revision
            .profile
            .get_or_insert_default()
            .profile_revision += 1;
        let error = seed_call(&alice, other_revision, slots(&["anthropic"]))
            .await
            .expect_err("a refused selection was answered");
        ensure!(error.code() == codewire_client::ErrorCode::PermissionDenied);
        for _ in 1..30 {
            seed_call(&alice, route.open.clone(), slots(&["anthropic"])).await?;
        }
        let error = seed_call(&alice, route.open.clone(), slots(&["anthropic"]))
            .await
            .expect_err("a 31st call was answered");
        ensure!(error.code() == codewire_client::ErrorCode::ResourceExhausted);
        Ok(())
    })
    .await
}

async fn seed_call(
    client: &CodewireClient,
    selection: proto::CredentialDelegationOpen,
    capability_slots: Vec<String>,
) -> std::result::Result<
    codewire_client::EnvironmentCredentialPlaceholdersResponse,
    codewire_client::ClientError,
> {
    client
        .environment_credential_placeholders(
            codewire_client::EnvironmentCredentialPlaceholdersRequest {
                selection: Some(selection).into(),
                capability_slots,
                ..Default::default()
            },
        )
        .await
}
