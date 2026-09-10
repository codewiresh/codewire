//! Actual dual-listener runtime, restricted SQL, and synthetic provider owners.
//! TLS/authentication uses the real Kubernetes authenticator with rejecting
//! in-process TokenReviews. The drain case instead injects a synthetic runtime
//! identity, but uses the real broker, refresh journal and publication runner.
//! Neither case is a Kubernetes/Dev deployment or live OpenBao acceptance claim.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use axum::{Router, body::Body};
use base64::Engine as _;
use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, EnvironmentAccessBinding, EnvironmentId,
    GrantContext, GrantPlacement, Owner, OwnerId,
};
use codewire_credential_broker::platform::bridge::PlatformBridgeAuthenticationError;
use codewire_credential_broker::platform::{
    PlatformPodIdentity, PlatformRuntimeAuthority, PlatformRuntimeError, PlatformRuntimeSession,
};
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, import_codex_auth_json,
};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_gateway_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_platform_credentials::{CredentialRecord, OAuthRefreshState};
use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_tls::ClientTlsEndpoint;
use http::{Request, Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::Channel;
use tonic::{Code, Streaming};
use uuid::Uuid;

use crate::mutation::tests::install_commit_barrier;
use crate::mutation::tests::support::{ALICE, Auth, Harness, blocked_by};
use crate::platform_test_support::{TIMEOUT, registration, value};

type Client = CredentialBrokerServiceClient<Channel>;
const BROKER_PATH: &str = "/broker.v1.CredentialBrokerService/CredentialBridge";

struct Identity {
    _directory: TempDir,
    certificate: PathBuf,
    key: PathBuf,
    roots: PathBuf,
}

impl Identity {
    fn new(name: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let issuer_key = KeyPair::generate()?;
        let mut issuer = CertificateParams::new(Vec::<String>::new())?;
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = issuer.self_signed(&issuer_key)?;
        let key = KeyPair::generate()?;
        let mut certificate = CertificateParams::new(vec![name.to_owned()])?;
        certificate.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        certificate.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = certificate.signed_by(&key, &issuer, &issuer_key)?;
        let cert_path = directory.path().join("tls.crt");
        let key_path = directory.path().join("tls.key");
        let roots = directory.path().join("ca.crt");
        std::fs::write(&cert_path, certificate.pem())?;
        std::fs::write(&key_path, key.serialize_pem())?;
        std::fs::write(&roots, issuer.pem())?;
        Ok(Self {
            _directory: directory,
            certificate: cert_path,
            key: key_path,
            roots,
        })
    }

    fn files(&self) -> Result<ServerTlsFiles> {
        Ok(ServerTlsFiles::new(
            self.certificate.clone(),
            self.key.clone(),
        )?)
    }

    fn endpoint(&self, address: SocketAddr) -> Result<ClientTlsEndpoint> {
        Ok(ClientTlsEndpoint::new(
            format!("https://localhost:{}", address.port()),
            self.roots.clone(),
        )?)
    }

    fn replace_with(&self, other: &Self) -> Result<()> {
        std::fs::copy(&other.certificate, &self.certificate)?;
        std::fs::copy(&other.key, &self.key)?;
        std::fs::copy(&other.roots, &self.roots)?;
        Ok(())
    }
}

struct Addresses {
    public: TcpListener,
    private: TcpListener,
}

impl Addresses {
    async fn reserve() -> Result<Self> {
        Ok(Self {
            public: TcpListener::bind("127.0.0.1:0").await?,
            private: TcpListener::bind("127.0.0.1:0").await?,
        })
    }

    fn release(self, tls: ServerTlsFiles) -> Result<Listeners> {
        Ok(Listeners {
            public: self.public.local_addr()?,
            private: self.private.local_addr()?,
            tls,
        })
    }
}

#[derive(Clone, Default)]
struct NeverUpstream(Arc<AtomicUsize>);

#[async_trait]
impl BrokerUpstreamTransport for NeverUpstream {
    async fn execute(
        &self,
        _: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(BrokerUpstreamError::Protocol)
    }
}

fn rejecting_authenticator(
    h: &Harness,
) -> (Arc<KubernetesPlatformBridgeAuthenticator>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let client = kube::Client::new(Router::new().fallback(move |request: Request<Body>| {
        let calls = observed.clone();
        async move {
            assert_eq!(request.uri().path(), "/apis/authentication.k8s.io/v1/tokenreviews");
            calls.fetch_add(1, Ordering::SeqCst);
            Response::builder().header("content-type", "application/json")
                .body(Body::from(json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":false}}).to_string())).unwrap()
        }
    }), "synthetic-runtime");
    (
        Arc::new(KubernetesPlatformBridgeAuthenticator::new(
            client,
            h.pool.clone(),
            Arc::new(TestKekProvider),
        )),
        calls,
    )
}

fn bridge<A, U>(h: &Harness, auth: Arc<A>, upstream: U) -> PlatformCredentialBridgeService<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    PlatformCredentialBridgeService::new(
        auth,
        h.store.clone(),
        PlatformAccessProfileStore::new(h.pool.clone(), builtin_provider_catalog()),
        upstream,
    )
}

async fn bridge_closed<A, U>(bridge: &PlatformCredentialBridgeService<A, U>) -> Result<()>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    // Invoke the actual generated receiver without launching a second server.
    // Closed admission must beat malformed/absent authentication and Ready.
    let mut service = bridge.clone().into_server();
    let request = Request::builder()
        .method("POST")
        .uri(BROKER_PATH)
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())?;
    let response = tonic::codegen::Service::call(&mut service, request).await?;
    ensure!(
        response
            .headers()
            .get("grpc-status")
            .is_some_and(|value| value == "14"),
        "retained broker clone did not reject closed admission"
    );
    Ok(())
}

struct Running {
    public: SocketAddr,
    private: SocketAddr,
    stop: CancellationToken,
    task: Option<JoinHandle<Result<(), RuntimeError>>>,
}

impl Running {
    fn start<A, U>(
        listeners: Listeners,
        h: &Harness,
        bridge: PlatformCredentialBridgeService<A, U>,
    ) -> Self
    where
        A: PlatformBridgeAuthenticator + 'static,
        U: BrokerUpstreamTransport + Clone + 'static,
    {
        let public = listeners.public;
        let private = listeners.private;
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let pool = h.pool.clone();
        let owner = h.owner.clone();
        let provider = h.provider.clone();
        let task = tokio::spawn(serve_owned(
            listeners,
            http::HeaderValue::from_static("https://codewire.example"),
            pool,
            provider,
            owner,
            bridge,
            async move {
                stopped.cancelled().await;
                Ok(())
            },
        ));
        Self {
            public,
            private,
            stop,
            task: Some(task),
        }
    }

    async fn ready(&self, expected: StatusCode) -> Result<()> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                if let Ok(response) = client
                    .get(format!("http://{}/readyz", self.public))
                    .send()
                    .await
                    && response.status() == expected
                {
                    return Ok::<_, anyhow::Error>(());
                }
                ensure!(
                    self.task.as_ref().is_some_and(|task| !task.is_finished()),
                    "runtime stopped before expected readiness"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("runtime readiness did not reach expected state")?
    }

    async fn stays_pending(&mut self, duration: Duration) -> Result<()> {
        let task = self.task.as_mut().context("runtime already joined")?;
        if tokio::time::timeout(duration, task).await.is_ok() {
            self.task = None;
            anyhow::bail!("runtime returned while an issued operation was still blocked");
        }
        Ok(())
    }

    async fn finish(mut self, result: Result<()>) -> Result<()> {
        self.stop.cancel();
        let Some(mut task) = self.task.take() else {
            return result;
        };
        let joined = match tokio::time::timeout(TIMEOUT, &mut task).await {
            Ok(joined) => joined
                .context("runtime owner task")?
                .map_err(anyhow::Error::from),
            Err(_) => {
                // Never hide a drain bug by aborting the protected runtime.
                let _ = task.await;
                Err(anyhow::anyhow!(
                    "runtime exceeded its synthetic cleanup deadline"
                ))
            }
        };
        result.and(joined)
    }
}

async fn startup_failure(private_occupied: bool) -> Result<()> {
    let addresses = Addresses::reserve().await?;
    let identity = Identity::new("localhost")?;
    let public = addresses.public.local_addr()?;
    let private = addresses.private.local_addr()?;
    let h = Harness::unserved(public).await?;
    let (auth, reviews) = rejecting_authenticator(&h);
    let upstream = NeverUpstream::default();
    let bridge = bridge(&h, auth, upstream.clone());
    let result = async {
        if !private_occupied {
            std::fs::write(&identity.key, "synthetic-invalid-private-key-canary")?;
        }
        let listeners = Listeners {
            public,
            private,
            tls: identity.files()?,
        };
        drop(addresses.public);
        let occupied = private_occupied.then_some(addresses.private);
        // No work is issued in this startup-only branch. Both real owners
        // must still be closed by the runtime's error cleanup path.
        let actual = serve_owned(
            listeners,
            http::HeaderValue::from_static("https://codewire.example"),
            h.pool.clone(),
            h.provider.clone(),
            h.owner.clone(),
            bridge.clone(),
            std::future::pending(),
        )
        .await;
        ensure!(
            actual
                == Err(if private_occupied {
                    RuntimeError::Listener
                } else {
                    RuntimeError::Tls
                })
        );
        h.assert_admission_closed().await?;
        bridge_closed(&bridge).await?;
        h.drained().await?;
        ensure!(reviews.load(Ordering::SeqCst) == 0 && upstream.0.load(Ordering::SeqCst) == 0);
        ensure!(h.count().await? == 0 && h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        let public_rebound = TcpListener::bind(public).await?;
        drop((public_rebound, occupied));
        drop(TcpListener::bind(private).await?);
        Ok(())
    }
    .await;
    bridge.shutdown().await.unwrap();
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn invalid_tls_startup_closes_both_real_owners_without_admitting_work() -> Result<()> {
    startup_failure(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn private_bind_failure_releases_public_listener_and_closes_both_real_owners() -> Result<()> {
    startup_failure(true).await
}

fn token(expires: u64) -> Result<String> {
    Ok(format!(
        "e30.{}.synthetic-signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"exp":expires}))?)
    ))
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

async fn denied_private_call(client: &mut Client, projected_tokens: bool) -> Result<()> {
    let mut request =
        tonic::Request::new(futures::stream::empty::<v1::CredentialBridgeGuestMessage>());
    if projected_tokens {
        let bearer = format!("Bearer {}", token(unix_now()? + 300)?);
        request
            .metadata_mut()
            .insert("authorization", bearer.parse()?);
        let mut workspace = MetadataValue::from_bytes(bearer.as_bytes());
        workspace.set_sensitive(true);
        request
            .metadata_mut()
            .insert_bin(crate::authority::WORKSPACE_AUTHORIZATION, workspace);
    }
    let result = tokio::time::timeout(TIMEOUT, client.credential_bridge(request)).await?;
    let error = result
        .err()
        .context("private synthetic identity unexpectedly admitted")?;
    ensure!(error.code() == Code::Unauthenticated);
    ensure!(!error.message().contains("synthetic-signature"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn real_private_tls_authentication_and_readiness_follow_current_projected_identity()
-> Result<()> {
    let addresses = Addresses::reserve().await?;
    let identity = Identity::new("localhost")?;
    let h = Harness::unserved(addresses.public.local_addr()?).await?;
    let (auth, reviews) = rejecting_authenticator(&h);
    let upstream = NeverUpstream::default();
    let bridge = bridge(&h, auth, upstream.clone());
    let running = Running::start(addresses.release(identity.files()?)?, &h, bridge.clone());
    let result = async {
        running.ready(StatusCode::OK).await?;
        let endpoint = identity.endpoint(running.private)?;
        let mut original = Client::new(endpoint.connect().await?);
        denied_private_call(&mut original, false).await?;
        ensure!(reviews.load(Ordering::SeqCst) == 0);
        denied_private_call(&mut original, true).await?;
        ensure!(reviews.load(Ordering::SeqCst) > 0);
        let original_key = std::fs::read(&identity.key)?;
        std::fs::write(&identity.key, "synthetic-invalid-projected-key-canary")?;
        running.ready(StatusCode::SERVICE_UNAVAILABLE).await?;
        ensure!(
            endpoint.connect().await.is_err(),
            "cached TLS identity rescued an invalid projection"
        );
        // Existing TLS is still established; invalid rotation only prevents
        // new connections, and does not bypass application authentication.
        denied_private_call(&mut original, false).await?;
        std::fs::write(&identity.key, original_key)?;
        running.ready(StatusCode::OK).await?;
        denied_private_call(&mut Client::new(endpoint.connect().await?), false).await?;
        let wrong = Identity::new("wrong-broker.internal")?;
        identity.replace_with(&wrong)?;
        ensure!(
            endpoint.connect().await.is_err(),
            "broker DNS identity verification was bypassed"
        );
        let rotated = Identity::new("localhost")?;
        identity.replace_with(&rotated)?;
        running.ready(StatusCode::OK).await?;
        denied_private_call(&mut Client::new(endpoint.connect().await?), false).await?;
        ensure!(upstream.0.load(Ordering::SeqCst) == 0);
        ensure!(
            h.provider.generate_calls.load(Ordering::SeqCst) == 0
                && h.provider.unwrap_calls.load(Ordering::SeqCst) == 0
        );
        ensure!(h.count().await? == 0);
        drop(original);
        Ok(())
    }
    .await;
    let result = running.finish(result).await;
    let closed = async {
        h.assert_admission_closed().await?;
        bridge_closed(&bridge).await
    }
    .await;
    h.finish(result.and(closed)).await
}

struct SyntheticAuthority(PlatformRuntimeSession);

#[async_trait]
impl PlatformRuntimeAuthority for SyntheticAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        Ok(self.0.clone())
    }
}

struct SyntheticAuthenticator(Arc<SyntheticAuthority>);

#[async_trait]
impl PlatformBridgeAuthenticator for SyntheticAuthenticator {
    type Authority = SyntheticAuthority;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Arc<Self::Authority>, PlatformBridgeAuthenticationError> {
        if metadata
            .get("x-synthetic-runtime-identity")
            .is_some_and(|value| value == "accepted")
        {
            Ok(self.0.clone())
        } else {
            Err(PlatformBridgeAuthenticationError::Unauthenticated)
        }
    }
}

#[derive(Clone)]
struct RefreshUpstream {
    accepted: Arc<Notify>,
    release: Arc<Notify>,
    refresh_calls: Arc<AtomicUsize>,
    response_calls: Arc<AtomicUsize>,
    access: String,
}

impl RefreshUpstream {
    fn new() -> Result<Self> {
        Ok(Self {
            accepted: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            refresh_calls: Arc::new(AtomicUsize::new(0)),
            response_calls: Arc::new(AtomicUsize::new(0)),
            access: token(unix_now()? + 7200)?,
        })
    }
}

#[async_trait]
impl BrokerUpstreamTransport for RefreshUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        if target.as_str() != "https://auth.openai.com/oauth/token" {
            self.response_calls.fetch_add(1, Ordering::SeqCst);
            return Err(BrokerUpstreamError::Protocol);
        }
        let payload: Value =
            serde_json::from_slice(&body).map_err(|_| BrokerUpstreamError::Protocol)?;
        if method != http::Method::POST
            || headers.contains_key(http::header::AUTHORIZATION)
            || payload["grant_type"] != "refresh_token"
            || payload["refresh_token"] != "synthetic-runtime-refresh-old"
            || self.refresh_calls.fetch_add(1, Ordering::SeqCst) != 0
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        self.accepted.notify_one();
        self.release.notified().await;
        let body = serde_json::to_vec(&json!({"access_token":self.access,
            "refresh_token":"synthetic-runtime-refresh-rotated","token_type":"bearer"}))
        .map_err(|_| BrokerUpstreamError::Protocol)?;
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            http::HeaderMap::new(),
            Box::pin(futures::stream::once(async move { Ok(body.into()) })),
        ))
    }
}

async fn refresh_fixture(
    h: &Harness,
) -> Result<(CredentialRecord, GrantContext, Arc<SyntheticAuthenticator>)> {
    let owner = Owner::User(OwnerId::parse(ALICE)?);
    let id_payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "https://api.openai.com/auth":{"chatgpt_account_id":"synthetic-account"}
        }))?);
    let imported = import_codex_auth_json(&serde_json::to_vec(&json!({
        "auth_mode":"chatgpt","tokens":{"access_token":token(1)?,
        "refresh_token":"synthetic-runtime-refresh-old","id_token":format!("e30.{id_payload}.synthetic-signature"),
        "account_id":"synthetic-account"}
    }))?)?;
    let record = h
        .store
        .create(
            &owner,
            registration("Runtime refresh", CredentialAuthKind::OAuth),
            &value(imported.into_parts().0.as_bytes()),
        )
        .await?;
    let environment = EnvironmentId::parse(Uuid::new_v4().to_string())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
        VALUES ('runtime-preset','mutation-org','Synthetic runtime','runtime', \
        '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .execute(&h.db.pool)
    .await?;
    sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
        VALUES ($1,'mutation-org',$2,'sandbox','runtime-preset','running','started',7, \
        '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
        .bind(environment.as_str()).bind(ALICE).execute(&h.db.pool).await?;
    let context = GrantContext {
        environment_id: environment,
        environment_generation: 7,
        placement: GrantPlacement::Platform,
        user_id: OwnerId::parse(ALICE)?,
        organization_id: Some(OwnerId::parse("mutation-org")?),
        allow_personal_credentials: true,
        authorized_credentials: BTreeSet::from([record.metadata.id.clone()]),
    };
    let profiles = PlatformAccessProfileStore::new(h.db.pool.clone(), builtin_provider_catalog());
    let profile = profiles
        .create(
            &owner,
            AccessProfileName::parse("runtime-refresh")?,
            BTreeMap::from([(CapabilitySlot::codex(), record.metadata.id.clone())]),
        )
        .await?;
    profiles
        .create_binding(
            &context,
            EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: profile.id,
                profile_revision: profile.revision,
            },
            Some(&context.user_id),
        )
        .await?;
    let pod = |name: &str| PlatformPodIdentity {
        namespace: "synthetic-runtime".into(),
        name: name.into(),
        uid: Uuid::new_v4(),
    };
    let session = PlatformRuntimeSession::new(
        pod("gateway"),
        pod("workspace"),
        context.clone(),
        owner,
        unix_now()? + 3600,
    )?;
    Ok((
        record,
        context,
        Arc::new(SyntheticAuthenticator(Arc::new(SyntheticAuthority(
            session,
        )))),
    ))
}

async fn open_refresh(
    client: &mut Client,
    context: &GrantContext,
) -> Result<(
    mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    Streaming<v1::CredentialBridgeHostMessage>,
)> {
    let (input, receiver) = mpsc::channel(4);
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: context.environment_id.to_string(),
                    environment_generation: context.environment_generation,
                },
            )),
        })
        .await?;
    let stream = futures::stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|message| (message, receiver))
    });
    let mut request = tonic::Request::new(stream);
    request
        .metadata_mut()
        .insert("x-synthetic-runtime-identity", "accepted".parse()?);
    let output = tokio::time::timeout(TIMEOUT, client.credential_bridge(request))
        .await??
        .into_inner();
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "codex".into(),
                    route: "openai-api".into(),
                    request_id: Uuid::new_v4().to_string(),
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
        })
        .await?;
    Ok((input, output))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn shutdown_drains_issued_enrollment_commit_and_real_refresh_past_transport_grace()
-> Result<()> {
    let addresses = Addresses::reserve().await?;
    let identity = Identity::new("localhost")?;
    let upstream = RefreshUpstream::new()?;
    let h = Harness::unserved(addresses.public.local_addr()?).await?;
    let mut running = None;
    let result = async {
        let (record, context, auth) = refresh_fixture(&h).await?;
        let owner = Owner::User(context.user_id.clone());
        let bridge = bridge(&h, auth, upstream.clone());
        running = Some(Running::start(addresses.release(identity.files()?)?, &h, bridge.clone()));
        let runtime = running.as_mut().context("owned runtime")?;
        runtime.ready(StatusCode::OK).await?;
        let mut client = Client::new(identity.endpoint(runtime.private)?.connect().await?);
        let (input, mut output) = open_refresh(&mut client, &context).await?;
        tokio::time::timeout(TIMEOUT, async {
            tokio::select! {
                _ = upstream.accepted.notified() => Ok(()),
                frame = output.message() => {
                    let _ = frame;
                    Err(anyhow::anyhow!("broker responded before the synthetic refresh was accepted"))
                }
            }
        }).await.context("refresh acceptance deadline")??;
        let attempt = h.store.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.context("durable Start")?;
        ensure!(attempt.state == OAuthRefreshState::Started && attempt.execution_live);
        ensure!(attempt.expected == record.version && upstream.refresh_calls.load(Ordering::SeqCst) == 1);

        // Reuse the existing disposable-DB deferred COMMIT barrier. The
        // second credential is minted through the runtime's real public route.
        install_commit_barrier(&h.db.pool, 4191904).await?;
        let mut blocker = h.db.pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(4191904)").execute(&mut *blocker).await?;
        let mut enrollment = h.rpc.enroll(Auth::Alice, "runtime-issued-enrollment").await?;
        enrollment.challenge().await?;
        h.release()?;
        let publication_pid = blocked_by(&h.db.pool, blocker_pid).await?;
        let query: String = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
            .bind(publication_pid).fetch_one(&h.db.pool).await?;
        ensure!(query == "COMMIT", "enrollment barrier did not observe issued COMMIT");

        runtime.stop.cancel();
        h.wait_shutdown_started().await?;
        h.assert_admission_closed().await?;
        bridge_closed(&bridge).await?;
        runtime.stays_pending(Duration::from_millis(50)).await?;
        ensure!(h.count().await? == 1, "blocked enrollment published before its COMMIT was released");
        blocker.rollback().await?;
        h.drained().await?;
        ensure!(h.count().await? == 2 && !h.logged_out(), "issued enrollment was lost or logged out during runtime shutdown");

        // Transport grace may end, but the provider-accepted refresh must
        // retain its worker and finish publication, independently of RPC peers.
        runtime.stays_pending(TRANSPORT_GRACE + Duration::from_millis(100)).await?;
        h.provider.unwrap_gate.arm();
        upstream.release.notify_one();
        h.provider.unwrap_gate.wait().await?;
        let staged = h.store.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.context("staged refresh")?;
        ensure!(staged.state == OAuthRefreshState::Staged && staged.attempt_id == attempt.attempt_id);
        ensure!(h.store.record(&owner, &record.metadata.id).await?.version == record.version);
        runtime.stays_pending(Duration::from_millis(50)).await?;
        h.provider.unwrap_gate.release();
        drop((input, output, enrollment, client));
        let runtime = running.take().context("runtime finish owner")?;
        runtime.finish(Ok(())).await?;
        let committed = h.store.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.context("committed refresh")?;
        ensure!(committed.state == OAuthRefreshState::Committed && committed.attempt_id == attempt.attempt_id);
        let current = h.store.record(&owner, &record.metadata.id).await?;
        ensure!(current.version.material_generation == record.version.material_generation + 1);
        ensure!(current.version.revocation_generation == record.version.revocation_generation + 1);
        ensure!(upstream.refresh_calls.load(Ordering::SeqCst) == 1 && upstream.response_calls.load(Ordering::SeqCst) == 0);
        h.assert_admission_closed().await?;
        bridge_closed(&bridge).await?;
        Ok(())
    }.await;
    // Release every synthetic barrier before joining even after a failed
    // assertion. No protected task is aborted and no second refresh is sent.
    upstream.release.notify_one();
    h.provider.generate_gate.release();
    h.provider.unwrap_gate.release();
    let result = match running {
        Some(runtime) => runtime.finish(result).await,
        None => result,
    };
    h.finish(result).await
}
