use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use super::*;
use crate::GitHubAppAuthorizationConfig;
use crate::http_test_support::Lease;
use bytes::Bytes;
use codewire_access::{CredentialMetadata, GrantPermission};
use zeroize::Zeroizing;

struct Authority {
    slot: &'static str,
    wrong_slot: bool,
    calls: Arc<Mutex<Vec<(String, String, String)>>>,
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerLeaseProvider for Authority {
    type Lease = Lease;
    type RefreshReservation = ();
    type StartedRefresh = ();
    async fn lease_operation(
        &self,
        _id: Uuid,
        slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        self.calls.lock().unwrap().push((
            slot.to_string(),
            operation.to_string(),
            route.to_string(),
        ));
        if slot.as_str() != self.slot {
            return Err(BrokerLeaseError::Denied);
        }
        let (provider, kind) = match self.slot {
            "codex" | "openai" => ("openai", CredentialAuthKind::ApiKey),
            "anthropic" => ("anthropic", CredentialAuthKind::ApiKey),
            "github" => ("github", CredentialAuthKind::OAuth),
            _ => return Err(BrokerLeaseError::Denied),
        };
        let mut lease = Lease::new(
            provider,
            kind,
            self.slot,
            operation.as_str(),
            route.as_str(),
        );
        lease.reads = self.reads.clone();
        if self.wrong_slot {
            lease.grant.capability_slot = CapabilitySlot::parse("wrong-slot").unwrap();
        }
        Ok(lease)
    }
    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct Upstream {
    calls: Arc<Mutex<Vec<(Method, String)>>>,
    polls: Arc<AtomicUsize>,
    bad_encoding: bool,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, _) = request.into_parts();
        self.calls
            .lock()
            .unwrap()
            .push((method, target.to_string()));
        let material = headers
            .get("authorization")
            .or_else(|| headers.get("x-api-key"))
            .expect("synthetic injected authorization")
            .as_bytes()
            .to_vec();
        let media = if target.host_str() == Some("github.com") {
            if target.path().ends_with("/git-receive-pack") {
                "application/x-git-receive-pack-result"
            } else {
                "application/x-git-upload-pack-result"
            }
        } else {
            "application/json"
        };
        let mut headers =
            HeaderMap::from_iter([(http::header::CONTENT_TYPE, HeaderValue::from_static(media))]);
        if self.bad_encoding {
            headers.insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
        }
        let polls = self.polls.clone();
        let mut chunks = Vec::from([
            Bytes::copy_from_slice(&material[..material.len() / 2]),
            Bytes::copy_from_slice(&material[material.len() / 2..]),
        ])
        .into_iter();
        let body = futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(chunks.next().map(Ok))
        });
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Box::pin(body),
        ))
    }
}

fn broker(
    slot: &'static str,
    wrong_slot: bool,
    bad_encoding: bool,
) -> OpenAiBroker<Authority, Upstream> {
    OpenAiBroker::new(
        Authority {
            slot,
            wrong_slot,
            calls: Arc::new(Mutex::new(Vec::new())),
            reads: Arc::new(AtomicUsize::new(0)),
        },
        Upstream {
            calls: Arc::new(Mutex::new(Vec::new())),
            polls: Arc::new(AtomicUsize::new(0)),
            bad_encoding,
        },
    )
    .unwrap()
}

fn request(
    slot: &str,
    route: &str,
    method: &str,
    path: &str,
    body: &[u8],
    media: &str,
) -> v1::CredentialBridgeRequest {
    let mut headers = vec![v1::CredentialHttpHeader {
        name: "content-type".into(),
        value: media.as_bytes().to_vec(),
    }];
    if slot == "anthropic" {
        headers.push(v1::CredentialHttpHeader {
            name: "anthropic-version".into(),
            value: b"2023-06-01".to_vec(),
        });
    }
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        capability_slot: slot.into(),
        route: route.into(),
        method: method.into(),
        path: path.into(),
        query: String::new(),
        headers,
        body: body.to_vec(),
    }
}

type ProviderCase = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    &'static str,
    &'static str,
);

fn cases() -> Vec<ProviderCase> {
    vec![
        (
            "codex",
            "openai-api",
            "responses",
            "POST",
            "/responses",
            b"{}",
            "application/json",
            "https://api.openai.com/v1/responses",
        ),
        (
            "openai",
            "openai-api",
            "responses",
            "POST",
            "/responses",
            b"{}",
            "application/json",
            "https://api.openai.com/v1/responses",
        ),
        (
            "anthropic",
            "anthropic-api",
            "messages",
            "POST",
            "/messages",
            b"{}",
            "application/json",
            "https://api.anthropic.com/v1/messages",
        ),
        (
            "anthropic",
            "anthropic-api",
            "count-tokens",
            "POST",
            "/messages/count_tokens",
            b"{}",
            "application/json",
            "https://api.anthropic.com/v1/messages/count_tokens",
        ),
        (
            "github",
            "github-api",
            "rest",
            "GET",
            "/user",
            b"",
            "application/json",
            "https://api.github.com/user",
        ),
        (
            "github",
            "github-api",
            "graphql",
            "POST",
            "/graphql",
            br#"{"query":"query { viewer { login } }"}"#,
            "application/json",
            "https://api.github.com/graphql",
        ),
        (
            "github",
            "github-https",
            "git-fetch",
            "POST",
            "/owner/repo.git/git-upload-pack",
            b"0000",
            "application/x-git-upload-pack-request",
            "https://github.com/owner/repo.git/git-upload-pack",
        ),
        (
            "github",
            "github-https",
            "git-push",
            "POST",
            "/owner/repo.git/git-receive-pack",
            b"0000",
            "application/x-git-receive-pack-request",
            "https://github.com/owner/repo.git/git-receive-pack",
        ),
    ]
}

#[tokio::test]
async fn named_http_slots_dispatch_exact_operations_and_redact_before_guest_streaming() {
    for (slot, route, operation, method, path, body, media, target) in cases() {
        let broker = broker(slot, false, false);
        let response = broker
            .execute(request(slot, route, method, path, body, media))
            .await
            .unwrap();
        assert_eq!(
            *broker.leases.calls.lock().unwrap(),
            vec![(slot.into(), operation.into(), route.into())]
        );
        assert_eq!(
            *broker.upstream.calls.lock().unwrap(),
            vec![(
                Method::from_bytes(method.as_bytes()).unwrap(),
                target.into()
            )]
        );
        assert_eq!(broker.leases.reads.load(Ordering::Relaxed), 1);
        let (_, _, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            bytes.extend(chunk.unwrap());
        }
        assert_eq!(bytes, b"[REDACTED]", "{slot}/{operation}");
    }
}

#[tokio::test]
async fn wrong_slot_leases_and_unselected_routes_fail_before_material_or_upstream() {
    for (slot, route, _, method, path, body, media, _) in cases() {
        let broker = broker(slot, true, false);
        assert_eq!(
            broker
                .execute(request(slot, route, method, path, body, media))
                .await
                .err(),
            Some(BrokerRequestError::Denied)
        );
        assert_eq!(broker.leases.reads.load(Ordering::Relaxed), 0);
        assert!(broker.upstream.calls.lock().unwrap().is_empty());
    }
    for (slot, route) in [
        ("", "openai-api"),
        ("codex", ""),
        ("anthropic", "openai-api"),
        ("openai", "anthropic-api"),
        ("github", "https://evil.test"),
        ("other", "github-api"),
    ] {
        let broker = broker("codex", false, false);
        assert_eq!(
            broker
                .execute(request(
                    slot,
                    route,
                    "POST",
                    "/responses",
                    b"{}",
                    "application/json"
                ))
                .await
                .err(),
            Some(BrokerRequestError::InvalidRequest)
        );
        assert!(broker.leases.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn every_http_provider_rejects_encoded_response_before_any_body_poll() {
    for (slot, route, _, method, path, body, media, _) in cases() {
        let broker = broker(slot, false, true);
        assert_eq!(
            broker
                .execute(request(slot, route, method, path, body, media))
                .await
                .err(),
            Some(BrokerRequestError::UpstreamFailed)
        );
        assert_eq!(broker.upstream.polls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn application_only_none_transport_never_dials_a_provider() {
    let transport: Option<Upstream> = None;
    let request = BrokerUpstreamRequest {
        method: Method::POST,
        target: Url::parse("https://api.openai.com/v1/responses").unwrap(),
        headers: HeaderMap::new(),
        body: vec![],
    };
    assert_eq!(
        transport.execute(request).await.err(),
        Some(BrokerUpstreamError::DestinationDenied)
    );
}

const APP_INITIAL_ACCESS_TOKEN: &str = "ghu_synthetic_app_initial_token_1234567890";
const APP_INITIAL_REFRESH_TOKEN: &str = "ghr_synthetic_app_refresh_token_1234567890";
const APP_REFRESHED_ACCESS_TOKEN: &str = "ghu_synthetic_app_refreshed_token_1234567890";
const APP_REFRESHED_REFRESH_TOKEN: &str = "ghr_synthetic_app_refreshed_refresh_token_1234567890";

struct AppRefreshLease {
    lease: Lease,
    material_generation: u64,
}

impl BrokerCredentialLease for AppRefreshLease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        self.lease.credential_metadata()
    }

    fn grant(&self) -> &DerivedGrant {
        self.lease.grant()
    }

    fn permission(&self) -> &GrantPermission {
        self.lease.permission()
    }

    fn material_generation(&self) -> u64 {
        self.material_generation
    }

    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        self.lease.with_material(operation)
    }
}

struct AppRefreshState {
    material: Zeroizing<Vec<u8>>,
    revocation_generation: u64,
    material_generation: u64,
}

struct AppRefreshAuthority {
    state: Arc<Mutex<AppRefreshState>>,
    begins: Arc<AtomicUsize>,
    starts: Arc<AtomicUsize>,
    commits: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerLeaseProvider for AppRefreshAuthority {
    type Lease = AppRefreshLease;
    type RefreshReservation = (u64, u64);
    type StartedRefresh = (u64, u64);

    async fn lease_operation(
        &self,
        _request_id: Uuid,
        slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        if slot.as_str() != "github"
            || operation.as_str() != "rest"
            || route.as_str() != "github-api"
        {
            return Err(BrokerLeaseError::Denied);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let mut lease = Lease::new(
            "github",
            CredentialAuthKind::OAuth,
            "github",
            "rest",
            "github-api",
        );
        lease.metadata.revocation_generation = state.revocation_generation;
        lease.grant.credential_revocation_generation = state.revocation_generation;
        lease.material = Zeroizing::new(state.material.to_vec());
        Ok(AppRefreshLease {
            lease,
            material_generation: state.material_generation,
        })
    }

    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BrokerRefreshError::Unavailable)?;
        if request.kind != BrokerCredentialRefreshKind::GitHubAppUserOAuth
            || request.material_generation != state.material_generation
            || request.grant.credential_revocation_generation != state.revocation_generation
        {
            return Err(BrokerRefreshError::Stale);
        }
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(BrokerRefreshAdmission::Reserved((
            state.revocation_generation,
            state.material_generation,
        )))
    }

    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(reservation)
    }

    async fn commit_credential_refresh(
        &self,
        _: Self::StartedRefresh,
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }

    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        bundle: GitHubAppUserOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        let mut material = bundle.into_bytes();
        GitHubAppUserOAuthBundle::parse(&material)
            .map_err(|_| BrokerRefreshError::InvalidResponse)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BrokerRefreshError::Unavailable)?;
        if permit != (state.revocation_generation, state.material_generation) {
            return Err(BrokerRefreshError::Stale);
        }
        state.material = Zeroizing::new(std::mem::take(&mut *material));
        state.revocation_generation = state
            .revocation_generation
            .checked_add(1)
            .ok_or(BrokerRefreshError::InvalidResponse)?;
        state.material_generation = state
            .material_generation
            .checked_add(1)
            .ok_or(BrokerRefreshError::InvalidResponse)?;
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn abort_credential_refresh(
        &self,
        _: Self::RefreshReservation,
    ) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }

    async fn fail_credential_refresh(
        &self,
        _: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct AppAuthorizationUpstream {
    calls: AtomicUsize,
    refreshes: AtomicUsize,
    initial_access_lifetime: u64,
}

impl AppAuthorizationUpstream {
    fn new(initial_access_lifetime: u64) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            refreshes: AtomicUsize::new(0),
            initial_access_lifetime,
        }
    }
}

#[async_trait]
impl BrokerUpstreamTransport for AppAuthorizationUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        self.calls.fetch_add(1, Ordering::SeqCst);
        if method == Method::POST
            && target.host_str() == Some("github.com")
            && target.path() == "/login/oauth/access_token"
        {
            if headers.get(http::header::ACCEPT)
                != Some(&HeaderValue::from_static("application/json"))
                || headers.get(http::header::CONTENT_TYPE)
                    != Some(&HeaderValue::from_static(
                        "application/x-www-form-urlencoded",
                    ))
            {
                return Err(BrokerUpstreamError::Protocol);
            }
            let form =
                url::form_urlencoded::parse(&body).collect::<std::collections::BTreeMap<_, _>>();
            if form.get("client_id").map(|value| value.as_ref()) != Some("Iv1.syntheticclient")
                || form.get("client_secret").map(|value| value.as_ref())
                    != Some("synthetic-client-secret")
            {
                return Err(BrokerUpstreamError::Protocol);
            }
            if form.get("code").map(|value| value.as_ref()) == Some("synthetic-code-123")
                && !form.contains_key("grant_type")
            {
                return Ok(json_upstream_response(serde_json::json!({
                    "access_token": APP_INITIAL_ACCESS_TOKEN,
                    "token_type": "bearer",
                    "expires_in": self.initial_access_lifetime,
                    "refresh_token": APP_INITIAL_REFRESH_TOKEN,
                    "refresh_token_expires_in": 15_897_600,
                })));
            }
            if form.get("grant_type").map(|value| value.as_ref()) == Some("refresh_token")
                && form.get("refresh_token").map(|value| value.as_ref())
                    == Some(APP_INITIAL_REFRESH_TOKEN)
            {
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                return Ok(json_upstream_response(serde_json::json!({
                    "access_token": APP_REFRESHED_ACCESS_TOKEN,
                    "token_type": "bearer",
                    "expires_in": 28_800,
                    "refresh_token": APP_REFRESHED_REFRESH_TOKEN,
                    "refresh_token_expires_in": 15_897_600,
                })));
            }
            return Err(BrokerUpstreamError::Protocol);
        }
        let authorization = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(BrokerUpstreamError::Protocol)?;
        if method == Method::GET
            && target.host_str() == Some("api.github.com")
            && target.path() == "/user"
            && matches!(
                authorization,
                value if value == format!("Bearer {APP_INITIAL_ACCESS_TOKEN}")
                    || value == format!("Bearer {APP_REFRESHED_ACCESS_TOKEN}")
            )
        {
            return Ok(json_upstream_response(serde_json::json!({
                "id": 73,
                "login": "synthetic-user",
            })));
        }
        if method == Method::GET
            && target.host_str() == Some("api.github.com")
            && target.path() == "/user/installations"
            && matches!(
                authorization,
                value if value == format!("Bearer {APP_INITIAL_ACCESS_TOKEN}")
                    || value == format!("Bearer {APP_REFRESHED_ACCESS_TOKEN}")
            )
        {
            return Ok(json_upstream_response(serde_json::json!({
                "installations": [{"id": 41, "app_slug": "codewire"}],
            })));
        }
        Err(BrokerUpstreamError::Protocol)
    }
}

struct GitAppUpstream {
    authorizations: Arc<Mutex<Vec<String>>>,
    refreshed_status: StatusCode,
}

#[async_trait]
impl BrokerUpstreamTransport for GitAppUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        if method != Method::GET
            || target.host_str() != Some("api.github.com")
            || target.path() != "/user"
            || !body.is_empty()
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let authorization = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(BrokerUpstreamError::Protocol)?
            .to_owned();
        self.authorizations
            .lock()
            .map_err(|_| BrokerUpstreamError::Protocol)?
            .push(authorization.clone());
        let (status, body) = match authorization.as_str() {
            value if value == format!("Bearer {APP_INITIAL_ACCESS_TOKEN}") => (
                StatusCode::UNAUTHORIZED,
                Bytes::from_static(b"initial response is never released"),
            ),
            value if value == format!("Bearer {APP_REFRESHED_ACCESS_TOKEN}") => (
                self.refreshed_status,
                Bytes::from_static(APP_REFRESHED_ACCESS_TOKEN.as_bytes()),
            ),
            _ => return Err(BrokerUpstreamError::Protocol),
        };
        Ok(BrokerUpstreamResponse::new(
            status,
            HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move { Ok(body) })),
        ))
    }
}

fn json_upstream_response(value: serde_json::Value) -> BrokerUpstreamResponse {
    BrokerUpstreamResponse::new(
        StatusCode::OK,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move {
            Ok(Bytes::from(
                serde_json::to_vec(&value).expect("synthetic JSON"),
            ))
        })),
    )
}

fn app_authorization_config() -> GitHubAppAuthorizationConfig {
    GitHubAppAuthorizationConfig::new(
        "Iv1.syntheticclient".into(),
        Zeroizing::new("synthetic-client-secret".into()),
        "codewire".into(),
        "https://codewire.example/api/v1/github/oauth/callback".into(),
    )
    .expect("synthetic App configuration")
}

#[test]
fn github_app_refresh_accepts_only_the_direct_successor_generation() {
    let credential_id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let before = RefreshCredentialGeneration {
        credential_id: credential_id.clone(),
        revocation_generation: 7,
        material_generation: 2,
    };
    let direct = RefreshCredentialGeneration {
        credential_id: credential_id.clone(),
        revocation_generation: 8,
        material_generation: 3,
    };
    assert_eq!(require_direct_refresh_successor(&before, &direct), Ok(()));
    for replacement in [
        RefreshCredentialGeneration {
            credential_id: CredentialId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            revocation_generation: 8,
            material_generation: 3,
        },
        RefreshCredentialGeneration {
            credential_id: credential_id.clone(),
            revocation_generation: 9,
            material_generation: 3,
        },
        RefreshCredentialGeneration {
            credential_id,
            revocation_generation: 8,
            material_generation: 4,
        },
    ] {
        assert_eq!(
            require_direct_refresh_successor(&before, &replacement),
            Err(BrokerRequestError::Denied)
        );
    }
}

#[tokio::test]
async fn github_app_401_refreshes_once_then_retries_with_the_direct_successor() {
    let authorization_upstream = Arc::new(AppAuthorizationUpstream::new(28_800));
    let owner = Arc::new(GitHubAppAuthorizationOwner::new(
        app_authorization_config(),
        authorization_upstream.clone(),
    ));
    let mut import = owner
        .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
        .await
        .expect("initial App authorization");
    let (material, account_hint) = import.take_import().expect("protected App import");
    assert_eq!(account_hint.as_deref(), Some("synthetic-user"));
    assert!(GitHubAppUserOAuthBundle::is_tagged(&material));

    let state = Arc::new(Mutex::new(AppRefreshState {
        material,
        revocation_generation: 7,
        material_generation: 2,
    }));
    let begins = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));
    let commits = Arc::new(AtomicUsize::new(0));
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let broker = OpenAiBroker::new(
        AppRefreshAuthority {
            state: state.clone(),
            begins: begins.clone(),
            starts: starts.clone(),
            commits: commits.clone(),
        },
        GitAppUpstream {
            authorizations: authorizations.clone(),
            refreshed_status: StatusCode::OK,
        },
    )
    .expect("broker")
    .with_github_app_authorization_owner(owner);

    let response = broker
        .execute(request(
            "github",
            "github-api",
            "GET",
            "/user",
            b"",
            "application/json",
        ))
        .await
        .expect("one 401 retry through the App owner");
    let (_, _, mut body) = response.into_parts();
    let mut output = Vec::new();
    while let Some(chunk) = body.next().await {
        output.extend(chunk.expect("redacted response"));
    }

    assert_eq!(output, b"[REDACTED]");
    assert_eq!(
        *authorizations.lock().unwrap(),
        vec![
            format!("Bearer {APP_INITIAL_ACCESS_TOKEN}"),
            format!("Bearer {APP_REFRESHED_ACCESS_TOKEN}"),
        ]
    );
    assert_eq!(authorization_upstream.calls.load(Ordering::SeqCst), 6);
    assert_eq!(authorization_upstream.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(begins.load(Ordering::SeqCst), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    let state = state.lock().unwrap();
    assert_eq!(
        (state.revocation_generation, state.material_generation),
        (8, 3)
    );
    let rotated = GitHubAppUserOAuthBundle::parse(&state.material).expect("rotated bundle");
    assert_eq!(
        rotated
            .access_token()
            .expect("rotated access token")
            .as_str(),
        APP_REFRESHED_ACCESS_TOKEN
    );
}

#[tokio::test]
async fn github_app_early_refresh_does_not_rotate_again_after_a_successor_401() {
    let authorization_upstream = Arc::new(AppAuthorizationUpstream::new(60));
    let owner = Arc::new(GitHubAppAuthorizationOwner::new(
        app_authorization_config(),
        authorization_upstream.clone(),
    ));
    let mut import = owner
        .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
        .await
        .expect("initial App authorization");
    let (material, _) = import.take_import().expect("protected App import");

    let state = Arc::new(Mutex::new(AppRefreshState {
        material,
        revocation_generation: 7,
        material_generation: 2,
    }));
    let begins = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));
    let commits = Arc::new(AtomicUsize::new(0));
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let broker = OpenAiBroker::new(
        AppRefreshAuthority {
            state,
            begins: begins.clone(),
            starts: starts.clone(),
            commits: commits.clone(),
        },
        GitAppUpstream {
            authorizations: authorizations.clone(),
            refreshed_status: StatusCode::UNAUTHORIZED,
        },
    )
    .expect("broker")
    .with_github_app_authorization_owner(owner);

    let response = broker
        .execute(request(
            "github",
            "github-api",
            "GET",
            "/user",
            b"",
            "application/json",
        ))
        .await
        .expect("the successor rejection is returned without a second refresh");
    let (status, _, mut body) = response.into_parts();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut output = Vec::new();
    while let Some(chunk) = body.next().await {
        output.extend(chunk.expect("redacted response"));
    }
    assert_eq!(output, b"[REDACTED]");
    assert_eq!(
        *authorizations.lock().unwrap(),
        vec![format!("Bearer {APP_REFRESHED_ACCESS_TOKEN}")]
    );
    assert_eq!(authorization_upstream.calls.load(Ordering::SeqCst), 6);
    assert_eq!(authorization_upstream.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(begins.load(Ordering::SeqCst), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(commits.load(Ordering::SeqCst), 1);
}
