//! Real Connect admission and existing restricted SQL role, synthetic provider.
use super::*;
use crate::mutation::tests::support::{
    ALICE, BOB, GITHUB_TOKEN, Harness, SESSION, api_key, blind, oauth,
};
use crate::platform_test_support::TIMEOUT;
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use codewire_access::{AccessProfile, AccessProfileName, ProviderId, builtin_provider_catalog};
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
    GitHubAppAuthorizationConfig, GitHubAppAuthorizationOwner,
};
use codewire_platform_credentials::CredentialRegistration;
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_server_core::auth::{
    AuthState, SESSION_COOKIE_NAME, authenticate_headers_with_context, hash_oauth_token,
    hash_session_token,
};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router_with_auth};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;
use zeroize::Zeroizing;

const GITHUB_APP_INITIAL_TOKEN: &str = "ghu_synthetic_app_initial_token_1234567890";
const GITHUB_APP_REFRESH_TOKEN: &str = "ghr_synthetic_app_refresh_token_1234567890";
const GITHUB_APP_REFRESHED_TOKEN: &str = "ghu_synthetic_app_refreshed_token_1234567890";
const GITHUB_APP_REFRESHED_REFRESH_TOKEN: &str =
    "ghr_synthetic_app_refreshed_refresh_token_1234567890";
const GITHUB_APP_SECOND_REFRESHED_TOKEN: &str = "ghu_synthetic_app_second_refreshed_token_12345";
const GITHUB_APP_SECOND_REFRESH_TOKEN: &str = "ghr_synthetic_app_second_refresh_token_1234567";

struct Provider {
    calls: AtomicUsize,
    app_refreshes: AtomicUsize,
    reject_first_app_repository: AtomicBool,
    reject_first_refreshed_app_repository: AtomicBool,
    initial_app_access_lifetime: AtomicUsize,
    refreshed_app_access_lifetime: AtomicUsize,
    initial_refresh_used: AtomicBool,
    refreshed_refresh_used: AtomicBool,
    hold: AtomicBool,
    entered: Notify,
    released: Notify,
    /// The installation is still on the grant from before Codewire asked for
    /// write access (#2712).
    earlier_grant: AtomicBool,
    reject_first_installations: AtomicBool,
    fail_installations: AtomicBool,
    installation_calls: AtomicUsize,
}

impl Default for Provider {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            app_refreshes: AtomicUsize::new(0),
            reject_first_app_repository: AtomicBool::new(false),
            reject_first_refreshed_app_repository: AtomicBool::new(false),
            initial_app_access_lifetime: AtomicUsize::new(28_800),
            refreshed_app_access_lifetime: AtomicUsize::new(28_800),
            initial_refresh_used: AtomicBool::new(false),
            refreshed_refresh_used: AtomicBool::new(false),
            hold: AtomicBool::new(false),
            entered: Notify::new(),
            released: Notify::new(),
            earlier_grant: AtomicBool::new(false),
            reject_first_installations: AtomicBool::new(false),
            fail_installations: AtomicBool::new(false),
            installation_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl BrokerUpstreamTransport for Provider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        if method == Method::POST
            && target.origin().ascii_serialization() == "https://github.com"
            && target.path() == "/login/oauth/access_token"
        {
            return self.github_app_exchange(&headers, &body);
        }
        if method == Method::GET
            && target.origin().ascii_serialization() == "https://api.github.com"
            && target.path() == "/user"
        {
            return self.github_app_user(&headers, &body);
        }
        if method == Method::GET
            && target.origin().ascii_serialization() == "https://api.github.com"
            && target.path() == "/user/installations"
        {
            return self.github_app_installations(&target, &headers, &body);
        }
        assert_eq!(method, Method::GET);
        assert_eq!(
            target.origin().ascii_serialization(),
            "https://api.github.com"
        );
        assert_eq!(target.path(), "/user/repos");
        let authorization = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or(BrokerUpstreamError::Protocol)?;
        let app_initial = authorization == format!("Bearer {GITHUB_APP_INITIAL_TOKEN}");
        let app_refreshed = authorization == format!("Bearer {GITHUB_APP_REFRESHED_TOKEN}");
        if ![
            format!("Bearer {GITHUB_TOKEN}"),
            format!("Bearer {GITHUB_APP_INITIAL_TOKEN}"),
            format!("Bearer {GITHUB_APP_REFRESHED_TOKEN}"),
            format!("Bearer {GITHUB_APP_SECOND_REFRESHED_TOKEN}"),
        ]
        .contains(&authorization.to_owned())
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        assert!(body.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if app_initial
            && self
                .reject_first_app_repository
                .swap(false, Ordering::SeqCst)
        {
            return json_response(StatusCode::UNAUTHORIZED, json!({}));
        }
        if app_refreshed
            && self
                .reject_first_refreshed_app_repository
                .swap(false, Ordering::SeqCst)
        {
            return json_response(StatusCode::UNAUTHORIZED, json!({}));
        }
        if self.hold.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.released.notified().await;
        }
        let body = if target.query().unwrap().contains("page=2&") {
            json!([])
        } else {
            json!([{"id":42,"full_name":"synthetic/private-repo","default_branch":"main","private":true,
                "archived":false,"disabled":false,"temp_clone_token":"private-provider-clone-token",
                "clone_url":"https://attacker.example/not-forwarded"}])
        };
        json_response(StatusCode::OK, body)
    }
}

impl Provider {
    fn github_app_exchange(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if headers.get(http::header::ACCEPT) != Some(&HeaderValue::from_static("application/json"))
            || headers.get(http::header::CONTENT_TYPE)
                != Some(&HeaderValue::from_static(
                    "application/x-www-form-urlencoded",
                ))
            || headers.get(http::header::USER_AGENT)
                != Some(&HeaderValue::from_static("Codewire-Credential-Service"))
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let form = url::form_urlencoded::parse(body).collect::<BTreeMap<_, _>>();
        if form.get("client_id").map(|value| value.as_ref()) != Some("Iv1.syntheticclient")
            || form.get("client_secret").map(|value| value.as_ref())
                != Some("synthetic-client-secret")
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        match form.get("grant_type").map(|value| value.as_ref()) {
            None if form.get("code").map(|value| value.as_ref()) == Some("synthetic-code-123") => {
                json_response(
                    StatusCode::OK,
                    json!({
                        "access_token": GITHUB_APP_INITIAL_TOKEN,
                        "token_type": "bearer",
                        "expires_in": self.initial_app_access_lifetime.load(Ordering::SeqCst),
                        "refresh_token": GITHUB_APP_REFRESH_TOKEN,
                        "refresh_token_expires_in": 15_897_600,
                    }),
                )
            }
            Some("refresh_token")
                if matches!(
                    form.get("refresh_token").map(|value| value.as_ref()),
                    Some(GITHUB_APP_REFRESH_TOKEN | GITHUB_APP_REFRESHED_REFRESH_TOKEN)
                ) =>
            {
                // Each rotation consumes its refresh token and issues the next;
                // GitHub rejects a refresh token that was already used.
                let second = form.get("refresh_token").map(|value| value.as_ref())
                    == Some(GITHUB_APP_REFRESHED_REFRESH_TOKEN);
                let used = if second {
                    &self.refreshed_refresh_used
                } else {
                    &self.initial_refresh_used
                };
                if used.swap(true, Ordering::SeqCst) {
                    return json_response(StatusCode::OK, json!({"error": "bad_refresh_token"}));
                }
                self.app_refreshes.fetch_add(1, Ordering::SeqCst);
                json_response(
                    StatusCode::OK,
                    json!({
                        "access_token": if second {
                            GITHUB_APP_SECOND_REFRESHED_TOKEN
                        } else {
                            GITHUB_APP_REFRESHED_TOKEN
                        },
                        "token_type": "bearer",
                        "expires_in": self.refreshed_app_access_lifetime.load(Ordering::SeqCst),
                        "refresh_token": if second {
                            GITHUB_APP_SECOND_REFRESH_TOKEN
                        } else {
                            GITHUB_APP_REFRESHED_REFRESH_TOKEN
                        },
                        "refresh_token_expires_in": 15_897_600,
                    }),
                )
            }
            _ => Err(BrokerUpstreamError::Protocol),
        }
    }

    fn github_app_user(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !body.is_empty() || !github_app_headers(headers) {
            return Err(BrokerUpstreamError::Protocol);
        }
        json_response(StatusCode::OK, json!({"id": 73, "login": "synthetic-user"}))
    }

    fn github_app_installations(
        &self,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !body.is_empty()
            || target.as_str() != "https://api.github.com/user/installations?per_page=100&page=1"
            || !github_app_headers(headers)
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        self.installation_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_installations.load(Ordering::SeqCst) {
            return json_response(StatusCode::BAD_GATEWAY, json!({}));
        }
        if self
            .reject_first_installations
            .swap(false, Ordering::SeqCst)
        {
            return json_response(StatusCode::UNAUTHORIZED, json!({}));
        }
        let permissions = if self.earlier_grant.load(Ordering::SeqCst) {
            json!({"contents": "read", "metadata": "read"})
        } else {
            json!({"contents": "write", "pull_requests": "write", "metadata": "read"})
        };
        json_response(
            StatusCode::OK,
            json!({"installations": [{"id": 41, "app_slug": "codewire",
                "account": {"login": "synthetic-user", "type": "User"},
                "repository_selection": "selected", "permissions": permissions}]}),
        )
    }
}

fn github_app_headers(headers: &HeaderMap) -> bool {
    let Some(authorization) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    matches!(
        authorization,
        value if value == format!("Bearer {GITHUB_APP_INITIAL_TOKEN}")
            || value == format!("Bearer {GITHUB_APP_REFRESHED_TOKEN}")
            || value == format!("Bearer {GITHUB_APP_SECOND_REFRESHED_TOKEN}")
    ) && headers.get(http::header::ACCEPT)
        == Some(&HeaderValue::from_static("application/vnd.github+json"))
        && headers.get(http::header::USER_AGENT)
            == Some(&HeaderValue::from_static("Codewire-Credential-Service"))
}

fn json_response(
    status: StatusCode,
    body: serde_json::Value,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    Ok(BrokerUpstreamResponse::new(
        status,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move {
            Ok(serde_json::to_vec(&body)
                .map_err(|_| BrokerUpstreamError::Protocol)?
                .into())
        })),
    ))
}

struct Fixture {
    h: Harness,
    owner: Arc<GithubRepositoryOwner>,
    provider: Arc<Provider>,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    client: reqwest::Client,
    url: String,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Fixture {
    async fn new() -> Result<Self> {
        Self::with_github_app(false).await
    }

    async fn app() -> Result<Self> {
        Self::with_github_app(true).await
    }

    async fn with_github_app(github_app: bool) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let h = Harness::unserved(address).await?;
        let provider = Arc::new(Provider::default());
        let github_app_authorization = github_app.then(|| {
            Arc::new(GitHubAppAuthorizationOwner::new(
                GitHubAppAuthorizationConfig::new(
                    "Iv1.syntheticclient".into(),
                    Zeroizing::new("synthetic-client-secret".into()),
                    "codewire".into(),
                    "https://codewire.example/api/v1/github/oauth/callback".into(),
                )
                .expect("synthetic GitHub App configuration"),
                provider.clone(),
            ))
        });
        let owner = Arc::new(GithubRepositoryOwner::new(
            h.pool.clone(),
            h.store.clone(),
            provider.clone(),
            github_app_authorization.clone(),
        ));
        let app = connect_router_with_auth(
            owner.router(),
            ConnectAuthLayer::github_repository(
                AuthState {
                    pool: h.pool.clone(),
                },
                HeaderValue::from_static("https://codewire.example"),
            ),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            h,
            owner,
            provider,
            github_app_authorization,
            server,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(TIMEOUT)
                .build()?,
            url: format!(
                "http://{address}/codewire.v1.GithubRepositoryService/ListGithubRepositories"
            ),
        })
    }

    fn post(&self, _credential: &CredentialRecord) -> reqwest::RequestBuilder {
        self.client
            .post(&self.url)
            .header("connect-protocol-version", "1")
            .json(&json!({"pageSize":1}))
    }

    /// The live permission status of the authenticated owner's connection.
    fn status(&self) -> reqwest::RequestBuilder {
        self.client
            .post(
                self.url
                    .replace("/ListGithubRepositories", "/ListGithubPendingPermissions"),
            )
            .header("connect-protocol-version", "1")
            .json(&json!({}))
    }

    fn profiles(&self) -> PlatformAccessProfileStore {
        PlatformAccessProfileStore::new(self.h.db.pool.clone(), builtin_provider_catalog())
    }

    async fn credential(&self, connected: bool) -> Result<Option<CredentialRecord>> {
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let record = if connected {
            Some(
                self.h
                    .store
                    .create(
                        &owner,
                        CredentialRegistration {
                            provider: ProviderId::parse("github")?,
                            authentication_kind: CredentialAuthKind::OAuth,
                            display_name: uuid::Uuid::new_v4().to_string(),
                            account_hint: Some("synthetic".into()),
                            expires_at_unix: None,
                        },
                        &ProtectedValue::new(GITHUB_TOKEN.as_bytes().to_vec())?,
                    )
                    .await?,
            )
        } else {
            None
        };
        Ok(record)
    }

    async fn app_credential(&self) -> Result<CredentialRecord> {
        let github = self
            .github_app_authorization
            .as_ref()
            .context("GitHub App fixture owner")?;
        let mut imported = github
            .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
            .await
            .context("synthetic GitHub App authorization")?;
        let (mut material, account_hint) = imported.take_import()?;
        let protected = ProtectedValue::new(std::mem::take(&mut *material))?;
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let record = self
            .h
            .store
            .create(
                &owner,
                CredentialRegistration {
                    provider: ProviderId::parse("github")?,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: uuid::Uuid::new_v4().to_string(),
                    account_hint,
                    expires_at_unix: None,
                },
                &protected,
            )
            .await?;
        Ok(record)
    }

    /// A personal profile; it includes GitHub without naming the connection.
    async fn github_profile(&self) -> Result<AccessProfile> {
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        Ok(self
            .profiles()
            .create(
                &owner,
                AccessProfileName::parse(uuid::Uuid::new_v4().to_string())?,
                BTreeMap::new(),
            )
            .await?)
    }

    async fn authority(&self) -> Result<CredentialMutationAuthority> {
        let headers = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", oauth(ALICE)).parse()?,
        )]);
        let auth = authenticate_headers_with_context(
            &AuthState {
                pool: self.h.pool.clone(),
            },
            &headers,
        )
        .await?;
        Ok(auth
            .oauth_bearer_authority()
            .context("original synthetic OAuth")?
            .clone()
            .into())
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        self.owner.start_shutdown();
        self.provider.released.notify_one();
        self.server.abort();
        let _ = self.server.await;
        self.owner.shutdown().await;
        self.h.finish(result).await
    }
}

async fn response(request: reqwest::RequestBuilder) -> Result<(StatusCode, Value)> {
    let response = request.send().await?;
    let status = response.status();
    if status.is_success() {
        ensure!(
            response
                .headers()
                .get("cache-control")
                .is_some_and(|value| value == "private, no-store")
        );
    }
    let value = response.json::<Value>().await?;
    blind(&value)?;
    ensure!(!value.to_string().contains("private-provider-clone-token"));
    ensure!(!value.to_string().contains("attacker.example"));
    Ok((status, value))
}

async fn error(request: reqwest::RequestBuilder, expected: &str) -> Result<()> {
    let (status, value) = response(request).await?;
    ensure!(
        !status.is_success() && value["code"] == expected,
        "closed response mismatch: {status} {value}"
    );
    ensure!(value.get("repositories").is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn exact_account_origin_credential_and_cursor_admission_use_restricted_role() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let original = f.credential(true).await?.context("GitHub record")?;
        for request in [
            f.post(&original),
            f.post(&original).bearer_auth(api_key()),
            f.post(&original)
                .bearer_auth("invalid")
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}")),
        ] {
            error(request, "unauthenticated").await?;
        }
        error(
            f.post(&original)
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}")),
            "permission_denied",
        )
        .await?;
        error(
            f.post(&original)
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                .header("origin", "https://attacker.example"),
            "permission_denied",
        )
        .await?;
        error(
            f.post(&original).bearer_auth(oauth(BOB)),
            "failed_precondition",
        )
        .await?;
        error(
            f.post(&original)
                .bearer_auth(oauth(ALICE))
                .json(&json!({"pageSize":1,"pageToken":"not-a-cursor"})),
            "invalid_argument",
        )
        .await?;
        ensure!(f.h.provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        ensure!(f.provider.calls.load(Ordering::SeqCst) == 0);
        let rust_client = codewire_client::CodewireClient::with_http(
            codewire_client::ClientConfig::new(
                f.url
                    .split("/codewire.v1.")
                    .next()
                    .context("synthetic origin")?,
            )?,
            codewire_client::StaticTokenProvider::new(oauth(ALICE))?,
            f.client.clone(),
        )?;
        let generated = rust_client
            .list_github_repositories(ListGithubRepositoriesRequest {
                page_size: 50,
                ..Default::default()
            })
            .await?;
        ensure!(
            generated.repositories.len() == 1
                && generated.repositories[0].full_name == "synthetic/private-repo"
        );
        ensure!(generated.repositories[0].is_private && generated.next_page_token.is_empty());
        let (status, page) = response(f.post(&original).bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"][0]["cloneUrl"]
                    == "https://github.com/synthetic/private-repo.git"
        );
        let cursor = page["nextPageToken"].as_str().context("bounded cursor")?;
        ensure!(cursor.len() <= MAX_PAGE_TOKEN_BYTES);
        let (status, page) = response(
            f.post(&original)
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                .header("origin", "https://codewire.example"),
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"]
                    .as_array()
                    .context("repository list")?
                    .len()
                    == 1
        );
        let page_request = || {
            f.post(&original)
                .bearer_auth(oauth(ALICE))
                .json(&json!({"pageSize":1,"pageToken":cursor}))
        };
        let (_, last) = response(page_request()).await?;
        ensure!(last.get("nextPageToken").is_none_or(|value| value == ""));
        f.h.store
            .replace(
                &original.metadata.owner,
                &original.metadata.id,
                original.version,
                &ProtectedValue::new(GITHUB_TOKEN.as_bytes().to_vec())?,
                None,
            )
            .await?;
        let before = f.h.provider.unwrap_calls.load(Ordering::SeqCst);
        error(page_request(), "aborted").await?;
        ensure!(f.h.provider.unwrap_calls.load(Ordering::SeqCst) == before);
        // After Delete the continuation cannot survive: the account has no
        // GitHub connection, and nothing falls back to another credential.
        let current =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        let revoked =
            f.h.store
                .revoke(
                    &original.metadata.owner,
                    &original.metadata.id,
                    current.version,
                )
                .await?;
        f.h.store
            .delete_revoked(
                &original.metadata.owner,
                &original.metadata.id,
                revoked.version,
            )
            .await?;
        error(page_request(), "failed_precondition").await?;
        error(
            f.post(&original).bearer_auth(oauth(ALICE)),
            "failed_precondition",
        )
        .await?;
        ensure!(f.h.provider.unwrap_calls.load(Ordering::SeqCst) == before);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn original_authority_and_credential_races_never_release_metadata() -> Result<()> {
    for scenario in [
        "credential-unwrap",
        "session-unwrap",
        "oauth-unwrap",
        "credential-provider",
        "session-provider",
        "oauth-provider",
    ] {
        let f = Fixture::new().await?;
        let result = async {
            let record = f.credential(true).await?.context("GitHub record")?;
            let unwrap = scenario.ends_with("unwrap");
            if unwrap {
                f.h.provider.unwrap_gate.arm();
            } else {
                f.provider.hold.store(true, Ordering::SeqCst);
            }
            let request = if scenario.starts_with("session") {
                f.post(&record)
                    .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                    .header("origin", "https://codewire.example")
            } else {
                f.post(&record).bearer_auth(oauth(ALICE))
            };
            let task = tokio::spawn(response(request));
            if unwrap {
                f.h.provider.unwrap_gate.wait().await?;
            } else {
                tokio::time::timeout(TIMEOUT, f.provider.entered.notified()).await?;
            }
            let expected = if scenario.starts_with("credential") {
                f.h.store
                    .revoke(&record.metadata.owner, &record.metadata.id, record.version)
                    .await?;
                if unwrap {
                    "aborted"
                } else {
                    "failed_precondition"
                }
            } else if scenario.starts_with("session") {
                sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
                    .bind(hash_session_token(SESSION))
                    .execute(&f.h.db.pool)
                    .await?;
                "unauthenticated"
            } else {
                sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
                    .bind(hash_oauth_token(&oauth(ALICE)))
                    .execute(&f.h.db.pool)
                    .await?;
                "unauthenticated"
            };
            if unwrap {
                f.h.provider.unwrap_gate.release();
            } else {
                f.provider.released.notify_one();
            }
            let (status, value) = tokio::time::timeout(TIMEOUT, task).await???;
            ensure!(
                !status.is_success()
                    && value["code"] == expected
                    && value.get("repositories").is_none(),
                "race {scenario}: {status} {value}"
            );
            if unwrap {
                ensure!(f.provider.calls.load(Ordering::SeqCst) == 0);
            }
            Ok(())
        }
        .await;
        f.finish(result)
            .await
            .with_context(|| format!("discovery race {scenario}"))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_discovery_does_not_require_a_credential_profile() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let credential = f.credential(true).await?.context("GitHub record")?;
        let profile = f.github_profile().await?;
        f.provider.hold.store(true, Ordering::SeqCst);
        let task = tokio::spawn(response(f.post(&credential).bearer_auth(oauth(ALICE))));
        tokio::time::timeout(TIMEOUT, f.provider.entered.notified()).await?;
        f.profiles()
            .update(
                &profile.owner,
                &profile.id,
                profile.revision,
                BTreeMap::new(),
            )
            .await?;
        f.provider.released.notify_one();
        let (status, page) = tokio::time::timeout(TIMEOUT, task).await???;
        ensure!(
            status == StatusCode::OK
                && page["repositories"]
                    .as_array()
                    .is_some_and(|repositories| repositories.len() == 1),
            "profile removal changed direct GitHub discovery: {status} {page}"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_app_repository_picker_refreshes_once_and_never_rebinds_a_cursor() -> Result<()> {
    let f = Fixture::app().await?;
    let result = async {
        let original = f.app_credential().await?;
        let stale_cursor = Selection::parse(ListGithubRepositoriesRequest {
            page_size: 1,
            ..Default::default()
        })
        .map_err(|_| anyhow::anyhow!("synthetic repository selection must be valid"))?
        .cursor(&original.metadata.owner, &original, 2);
        f.provider
            .reject_first_app_repository
            .store(true, Ordering::SeqCst);
        let (status, page) = response(f.post(&original).bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"]
                    .as_array()
                    .is_some_and(|repositories| repositories.len() == 1)
        );
        ensure!(f.provider.calls.load(Ordering::SeqCst) == 2);
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        let current =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        ensure!(same_refreshed_record(&original, &current).is_ok());

        let calls_before_cursor = f.provider.calls.load(Ordering::SeqCst);
        error(
            f.post(&original).bearer_auth(oauth(ALICE)).json(&json!({
                "pageSize": 1,
                "pageToken": stale_cursor,
            })),
            "aborted",
        )
        .await?;
        ensure!(f.provider.calls.load(Ordering::SeqCst) == calls_before_cursor);
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_app_early_refresh_does_not_rotate_again_after_a_successor_401() -> Result<()> {
    let f = Fixture::app().await?;
    let result = async {
        // This is within the App bundle's renewal skew, so discovery refreshes
        // before its first repository request. The successor's 401 must be
        // surfaced, never trigger a second rotation and replay.
        f.provider
            .initial_app_access_lifetime
            .store(60, Ordering::SeqCst);
        let original = f.app_credential().await?;
        f.provider
            .reject_first_refreshed_app_repository
            .store(true, Ordering::SeqCst);
        error(
            f.post(&original).bearer_auth(oauth(ALICE)),
            "permission_denied",
        )
        .await?;
        ensure!(f.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        let current =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        ensure!(same_refreshed_record(&original, &current).is_ok());
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_app_repository_picker_refreshes_again_after_an_earlier_committed_refresh()
-> Result<()> {
    let f = Fixture::app().await?;
    let result = async {
        // Every issued App token is inside the renewal skew, so each listing
        // renews before its first repository request.
        f.provider
            .initial_app_access_lifetime
            .store(60, Ordering::SeqCst);
        f.provider
            .refreshed_app_access_lifetime
            .store(60, Ordering::SeqCst);
        let original = f.app_credential().await?;
        let owner = original.metadata.owner.clone();
        let id = original.metadata.id.clone();
        let (status, page) = response(f.post(&original).bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"]
                    .as_array()
                    .is_some_and(|repositories| repositories.len() == 1),
            "first renewal did not list repositories: {status} {page}"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        let first = f.h.store.record(&owner, &id).await?;
        ensure!(same_refreshed_record(&original, &first).is_ok());

        // The first attempt stays committed against the original generation.
        // That finished history must not read as a concurrent change.
        let (status, page) = response(f.post(&first).bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"]
                    .as_array()
                    .is_some_and(|repositories| repositories.len() == 1),
            "an earlier committed renewal blocked the next one: {status} {page}"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 2);
        let second = f.h.store.record(&owner, &id).await?;
        ensure!(same_refreshed_record(&first, &second).is_ok());
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn drop_and_shutdown_release_finite_account_capacity() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let _credential = f.credential(true).await?.context("GitHub record")?;
        for stop in [false, true] {
            let authority = f.authority().await?;
            let request = ListGithubRepositoriesRequest {
                ..Default::default()
            };
            f.provider.hold.store(true, Ordering::SeqCst);
            let owner = f.owner.clone();
            let mut task = tokio::spawn(async move { owner.list(authority, request).await });
            tokio::select! {
                result = &mut task => anyhow::bail!("discovery ended before provider barrier: {:?}",result?.err()),
                result = tokio::time::timeout(TIMEOUT, f.provider.entered.notified()) => {
                    result.context("discovery did not enter provider barrier")?;
                }
            }
            ensure!(f.owner.capacity.available_permits() == MAX_OPERATIONS - 1);
            if stop {
                f.owner.start_shutdown();
            } else {
                task.abort();
            }
            let result = task.await;
            if stop { ensure!(matches!(result?,Err(Error::Cancelled))); }
            else { ensure!(result.is_err_and(|error|error.is_cancelled())); }
            ensure!(f.owner.capacity.available_permits() == MAX_OPERATIONS);
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn deadline_releases_finite_account_capacity() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let _credential = f.credential(true).await?.context("GitHub record")?;
        let authority = f.authority().await?;
        let request = ListGithubRepositoriesRequest {
..Default::default()
        };
        f.provider.hold.store(true,Ordering::SeqCst);
        let owner = f.owner.clone();
        let mut task = tokio::spawn(async move {owner.list(authority,request).await});
        tokio::select! {
            result = &mut task => anyhow::bail!("discovery ended before deadline barrier: {:?}",result?.err()),
            result = tokio::time::timeout(TIMEOUT,f.provider.entered.notified()) => {result.context("deadline provider barrier")?;}
        }
        ensure!(f.owner.capacity.available_permits()==MAX_OPERATIONS-1);
        // Advance only once all real DB/auth I/O has finished. Do not admit a
        // second request afterwards: auth fences deliberately use std::Instant.
        tokio::time::pause();
        tokio::time::advance(REQUEST_TIMEOUT+Duration::from_secs(1)).await;
        let result = task.await;
        tokio::time::resume();
        ensure!(matches!(result?,Err(Error::Expired)));
        ensure!(f.owner.capacity.available_permits()==MAX_OPERATIONS);
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_pending_permissions_follow_the_live_grant_under_discovery_authority() -> Result<()>
{
    // #2712: the same stored App connection, read live, names its
    // installation while GitHub still holds the earlier grant and nothing
    // once the grant is accepted. Login, ID and kind only.
    let f = Fixture::app().await?;
    let result = async {
        let original = f.app_credential().await?;
        let pending = json!([{"account": "synthetic-user", "installationId": "41",
            "accountKind": "GITHUB_APP_ACCOUNT_KIND_USER"}]);
        f.provider.earlier_grant.store(true, Ordering::SeqCst);
        for request in [
            f.status(),
            f.status().bearer_auth(api_key()),
            f.status()
                .bearer_auth("invalid")
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}")),
        ] {
            error(request, "unauthenticated").await?;
        }
        error(
            f.status()
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                .header("origin", "https://attacker.example"),
            "permission_denied",
        )
        .await?;
        // Another account has no GitHub connection; nothing falls back to
        // the owner's.
        error(f.status().bearer_auth(oauth(BOB)), "failed_precondition").await?;
        ensure!(f.provider.installation_calls.load(Ordering::SeqCst) == 1);

        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value["pendingPermissions"] == pending,
            "{value}"
        );
        let rust_client = codewire_client::CodewireClient::with_http(
            codewire_client::ClientConfig::new(
                f.url
                    .split("/codewire.v1.")
                    .next()
                    .context("synthetic origin")?,
            )?,
            codewire_client::StaticTokenProvider::new(oauth(ALICE))?,
            f.client.clone(),
        )?;
        let generated = rust_client.list_github_pending_permissions().await?;
        ensure!(
            generated.pending_permissions.len() == 1
                && generated.pending_permissions[0].account == "synthetic-user"
                && generated.pending_permissions[0].installation_id == 41
                && generated.pending_permissions[0].account_kind
                    == codewire_client::GithubAppAccountKind::User
        );
        let (status, value) = response(
            f.status()
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                .header("origin", "https://codewire.example"),
        )
        .await?;
        ensure!(
            status == StatusCode::OK && value["pendingPermissions"] == pending,
            "{value}"
        );
        // The owner accepts on GitHub: the same connection now names nothing.
        f.provider.earlier_grant.store(false, Ordering::SeqCst);
        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value.get("pendingPermissions").is_none(),
            "{value}"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 0);
        let unchanged =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        ensure!(unchanged == original);

        // A refused token renews once, exactly as discovery does.
        f.provider.earlier_grant.store(true, Ordering::SeqCst);
        f.provider
            .reject_first_installations
            .store(true, Ordering::SeqCst);
        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value["pendingPermissions"] == pending,
            "{value}"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        let current =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        ensure!(same_refreshed_record(&original, &current).is_ok());

        // Any other GitHub answer is an error the caller shows as nothing.
        f.provider.fail_installations.store(true, Ordering::SeqCst);
        error(f.status().bearer_auth(oauth(ALICE)), "unavailable").await?;
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 1);
        ensure!(f.provider.calls.load(Ordering::SeqCst) == 0);

        // Advisory: with its own slots full it answers nothing at once,
        // without GitHub and without taking discovery's slots.
        f.provider.fail_installations.store(false, Ordering::SeqCst);
        let calls = f.provider.installation_calls.load(Ordering::SeqCst);
        let held = (0..MAX_STATUS_OPERATIONS)
            .map(|_| Arc::clone(&f.owner.status_capacity).try_acquire_owned())
            .collect::<Result<Vec<_>, _>>()?;
        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value.get("pendingPermissions").is_none(),
            "{value}"
        );
        ensure!(f.provider.installation_calls.load(Ordering::SeqCst) == calls);
        ensure!(f.owner.capacity.available_permits() == MAX_OPERATIONS);
        drop(held);
        Ok(())
    }
    .await;
    f.finish(result).await?;

    // The advisory read never renews ahead of time, and when GitHub refuses
    // the token while another renewal of the same credential is running it
    // answers nothing at once instead of waiting for it.
    let f = Fixture::app().await?;
    let result = async {
        f.provider
            .initial_app_access_lifetime
            .store(60, Ordering::SeqCst);
        let original = f.app_credential().await?;
        f.provider.earlier_grant.store(true, Ordering::SeqCst);
        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value["pendingPermissions"][0]["installationId"] == "41",
            "{value}"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 0);
        let unchanged =
            f.h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
        ensure!(unchanged == original);

        let attempt = uuid::Uuid::new_v4();
        f.h.store
            .begin_oauth_refresh(
                &original.metadata.owner,
                &original.metadata.id,
                original.version,
                attempt,
            )
            .await?;
        f.provider
            .reject_first_installations
            .store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        let (status, value) = response(f.status().bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK && value.get("pendingPermissions").is_none(),
            "{value}"
        );
        ensure!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the advisory read waited for another renewal"
        );
        ensure!(f.provider.app_refreshes.load(Ordering::SeqCst) == 0);
        f.h.store
            .cancel_oauth_refresh(
                &original.metadata.owner,
                &original.metadata.id,
                original.version,
                attempt,
            )
            .await?;
        Ok(())
    }
    .await;
    f.finish(result).await
}
