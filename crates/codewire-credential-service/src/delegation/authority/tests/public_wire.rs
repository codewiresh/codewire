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
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use codewire_proto::codewire::{bridge::v1 as public_bridge, v1 as proto};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router_with_auth};
use connectrpc::client::{BoxFuture, CallOptions, ClientBody, ClientTransport};
use connectrpc::{ConnectError, Protocol};
use http::{Request, Response, StatusCode};
use tokio_util::sync::CancellationToken;

use crate::mutation::tests::support::{SESSION, api_key};

const PATH: &str = "/codewire.v1.CredentialDelegationService/DelegateCredentials";
const BOUND: Duration = Duration::from_secs(20);

struct RejectPods;

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

fn opening(selection: &OwnerLocalSelection) -> proto::CredentialDelegationOpen {
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
        return Ok(CodewireClient::with_http(
            ClientConfig::new(url)?,
            StaticTokenProvider::new(oauth(ALICE))?,
            client.clone(),
        )?
        .delegate_credentials(open)
        .await?);
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
    ensure!(matches!(response(&mut stream).await?.output,
        Some(proto::delegate_credentials_response::Output::Admitted(accepted)) if *accepted == open));
    Ok(stream)
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
    let router = crate::delegation::router(h.pool.clone(), h.provider.clone(), bridge.clone())
        .merge(connect_router_with_auth(
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

        put(&format!("/users/{ALICE}"), "DATABASE_URL", b"synthetic-application-value", &h.db.pool).await?;
        let mut stream = connect(&client, &url, protocol, open.clone()).await?;
        // This legal bridge frame exceeds the default 4MiB Connect ceiling.
        // It must reach grant admission and return a closed provider denial,
        // not fail in the dispatcher. No empty-profile material may be read.
        stream.send(frame(public_bridge::credential_bridge_guest_message::Payload::Request(Box::new(public_bridge::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(), method: "POST".into(), path: "/v1/responses".into(),
            body: vec![b' '; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES], capability_slot: "codex".into(), route: "openai-api".into(), ..Default::default()
        })))).await?;
        ensure!(matches!(response(&mut stream).await?.output, Some(proto::delegate_credentials_response::Output::Frame(frame))
            if matches!(frame.payload, Some(public_bridge::credential_bridge_host_message::Payload::ResponseFailure(_)))));

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
