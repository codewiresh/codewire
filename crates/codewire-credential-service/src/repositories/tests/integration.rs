//! Real Connect admission and existing restricted SQL role, synthetic provider.
use super::*;
use crate::mutation::tests::support::{
    ALICE, BOB, GITHUB_TOKEN, Harness, SESSION, api_key, blind, oauth,
};
use crate::platform_test_support::TIMEOUT;
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use codewire_access::{AccessProfile, AccessProfileName, ProviderId};
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
};
use codewire_platform_credentials::CredentialRegistration;
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

#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
    hold: AtomicBool,
    entered: Notify,
    released: Notify,
}

#[async_trait]
impl BrokerUpstreamTransport for Provider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        assert_eq!(method, Method::GET);
        assert_eq!(
            target.origin().ascii_serialization(),
            "https://api.github.com"
        );
        assert_eq!(target.path(), "/user/repos");
        assert_eq!(
            headers.get("authorization").unwrap(),
            &format!("Bearer {GITHUB_TOKEN}")
        );
        assert!(body.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move {
                Ok(serde_json::to_vec(&body).unwrap().into())
            })),
        ))
    }
}

struct Fixture {
    h: Harness,
    owner: Arc<GithubRepositoryOwner>,
    provider: Arc<Provider>,
    client: reqwest::Client,
    url: String,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let h = Harness::unserved(address).await?;
        let provider = Arc::new(Provider::default());
        let owner = Arc::new(GithubRepositoryOwner::new(
            h.pool.clone(),
            h.store.clone(),
            provider.clone(),
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

    fn post(&self, profile: &AccessProfile) -> reqwest::RequestBuilder {
        self.client.post(&self.url).header("connect-protocol-version", "1")
            .json(&json!({"profileId":profile.id.as_str(),"profileRevision":profile.revision.to_string(),"pageSize":1}))
    }

    fn profiles(&self) -> PlatformAccessProfileStore {
        PlatformAccessProfileStore::new(self.h.db.pool.clone(), builtin_provider_catalog())
    }

    async fn profile(&self, connected: bool) -> Result<(AccessProfile, Option<CredentialRecord>)> {
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
        let entries = record
            .as_ref()
            .map(|record| BTreeMap::from([(CapabilitySlot::github(), record.metadata.id.clone())]))
            .unwrap_or_default();
        let profile = self
            .profiles()
            .create(
                &owner,
                AccessProfileName::parse(uuid::Uuid::new_v4().to_string())?,
                entries,
            )
            .await?;
        Ok((profile, record))
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
async fn exact_account_origin_profile_and_cursor_admission_use_restricted_role() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let (profile, original) = f.profile(true).await?;
        for request in [
            f.post(&profile),
            f.post(&profile).bearer_auth(api_key()),
            f.post(&profile)
                .bearer_auth("invalid")
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}")),
        ] {
            error(request, "unauthenticated").await?;
        }
        error(
            f.post(&profile)
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}")),
            "permission_denied",
        )
        .await?;
        error(
            f.post(&profile)
                .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                .header("origin", "https://attacker.example"),
            "permission_denied",
        )
        .await?;
        error(f.post(&profile).bearer_auth(oauth(BOB)), "not_found").await?;
        error(
            f.post(&profile)
                .bearer_auth(oauth(ALICE))
                .json(&json!({"profileId":profile.id.as_str(),"profileRevision":"2"})),
            "aborted",
        )
        .await?;
        let (empty, _) = f.profile(false).await?;
        error(
            f.post(&empty).bearer_auth(oauth(ALICE)),
            "failed_precondition",
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
                profile_id: profile.id.as_str().into(),
                profile_revision: profile.revision,
                page_size: 50,
                ..Default::default()
            })
            .await?;
        ensure!(
            generated.repositories.len() == 1
                && generated.repositories[0].full_name == "synthetic/private-repo"
        );
        ensure!(generated.repositories[0].is_private && generated.next_page_token.is_empty());
        let (status, page) = response(f.post(&profile).bearer_auth(oauth(ALICE))).await?;
        ensure!(
            status == StatusCode::OK
                && page["repositories"][0]["cloneUrl"]
                    == "https://github.com/synthetic/private-repo.git"
        );
        let cursor = page["nextPageToken"].as_str().context("bounded cursor")?;
        ensure!(cursor.len() <= MAX_PAGE_TOKEN_BYTES);
        let (status, page) = response(
            f.post(&profile)
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
            f.post(&profile)
                .bearer_auth(oauth(ALICE))
                .json(&json!({"profileId":profile.id.as_str(),
            "profileRevision":profile.revision.to_string(),"pageSize":1,"pageToken":cursor}))
        };
        let (_, last) = response(page_request()).await?;
        ensure!(last.get("nextPageToken").is_none_or(|value| value == ""));
        let original = original.context("GitHub record")?;
        f.h.store
            .replace(
                &profile.owner,
                &original.metadata.id,
                original.version,
                &ProtectedValue::new(GITHUB_TOKEN.as_bytes().to_vec())?,
                None,
            )
            .await?;
        let before = f.h.provider.unwrap_calls.load(Ordering::SeqCst);
        error(page_request(), "aborted").await?;
        ensure!(f.h.provider.unwrap_calls.load(Ordering::SeqCst) == before);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn original_authority_profile_and_credential_races_never_release_metadata() -> Result<()> {
    for scenario in [
        "profile-unwrap",
        "credential-unwrap",
        "session-unwrap",
        "oauth-unwrap",
        "profile-provider",
        "credential-provider",
        "session-provider",
        "oauth-provider",
    ] {
        let f = Fixture::new().await?;
        let result = async {
            let (profile, record) = f.profile(true).await?;
            let record = record.context("GitHub record")?;
            let unwrap = scenario.ends_with("unwrap");
            if unwrap {
                f.h.provider.unwrap_gate.arm();
            } else {
                f.provider.hold.store(true, Ordering::SeqCst);
            }
            let request = if scenario.starts_with("session") {
                f.post(&profile)
                    .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
                    .header("origin", "https://codewire.example")
            } else {
                f.post(&profile).bearer_auth(oauth(ALICE))
            };
            let task = tokio::spawn(response(request));
            if unwrap {
                f.h.provider.unwrap_gate.wait().await?;
            } else {
                tokio::time::timeout(TIMEOUT, f.provider.entered.notified()).await?;
            }
            let expected = if scenario.starts_with("profile") {
                f.profiles()
                    .update(
                        &profile.owner,
                        &profile.id,
                        profile.revision,
                        BTreeMap::new(),
                    )
                    .await?;
                "aborted"
            } else if scenario.starts_with("credential") {
                f.h.store
                    .revoke(&profile.owner, &record.metadata.id, record.version)
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

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn drop_and_shutdown_release_finite_account_capacity() -> Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let (profile, _) = f.profile(true).await?;
        for stop in [false, true] {
            let authority = f.authority().await?;
            let request = ListGithubRepositoriesRequest {
                profile_id: profile.id.as_str().into(),
                profile_revision: profile.revision,
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
        let (profile, _) = f.profile(true).await?;
        let authority = f.authority().await?;
        let request = ListGithubRepositoriesRequest {
            profile_id:profile.id.as_str().into(), profile_revision:profile.revision,..Default::default()
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
