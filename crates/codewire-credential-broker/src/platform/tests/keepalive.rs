//! OAuth keep-alive against real restricted PostgreSQL, a synthetic KEK and a
//! synthetic provider. No provider network, OpenBao or real credential.

use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use codewire_access::{CredentialAuthKind, ProviderId};
use codewire_platform_credentials::CredentialRegistration;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use zeroize::Zeroizing;

use super::*;
use crate::platform::keepalive::{OAuthKeepAlive, OAuthKeepAliveConfig};
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    GitHubAppAuthorizationConfig, GitHubAppAuthorizationOwner, GitHubAppUserOAuthBundle,
};

const DAY: u64 = 24 * 60 * 60;
const REJECTED_REFRESH_TOKEN: &str = "synthetic-refresh-rejected";
const GITHUB_REFRESH_TOKEN: &str = "ghr_synthetic_keepalive_refresh_1234567890";
const GITHUB_ROTATED_ACCESS_TOKEN: &str = "ghu_synthetic_keepalive_rotated_1234567890";

/// Holds the first provider exchange at an exact barrier when armed.
#[derive(Default)]
struct ExchangeGate {
    armed: AtomicBool,
    entered: Notify,
    released: Notify,
}

impl ExchangeGate {
    async fn pass(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.released.notified().await;
        }
    }

    async fn wait(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, self.entered.notified())
            .await
            .context("synthetic provider exchange did not reach its barrier")?;
        Ok(())
    }
}

/// Synthetic OpenAI token endpoint. It rotates every refresh token except the
/// fixed rejected one, which receives a definite 401.
#[derive(Default)]
struct CodexProvider {
    gate: ExchangeGate,
    refreshes: AtomicUsize,
    presented: Mutex<Vec<String>>,
}

#[async_trait]
impl BrokerUpstreamTransport for CodexProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, _, body) = request.into_parts();
        if method != Method::POST || target.as_str() != "https://auth.openai.com/oauth/token" {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        let request: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| BrokerUpstreamError::Protocol)?;
        let presented = request["refresh_token"]
            .as_str()
            .ok_or(BrokerUpstreamError::Protocol)?
            .to_owned();
        let call = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
        self.presented.lock().unwrap().push(presented.clone());
        self.gate.pass().await;
        let (status, body) = if presented == REJECTED_REFRESH_TOKEN {
            (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": {"code": "refresh_token_expired"}}),
            )
        } else {
            (
                StatusCode::OK,
                serde_json::json!({
                    "id_token": id_token(),
                    "access_token": token(serde_json::json!({"exp": unix_now().unwrap() + 3_600})),
                    "refresh_token": format!("synthetic-refresh-rotated-{call}"),
                }),
            )
        };
        Ok(json_response(status, body))
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> BrokerUpstreamResponse {
    BrokerUpstreamResponse::new(
        status,
        HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move {
            Ok(Bytes::from(serde_json::to_vec(&body).unwrap()))
        })),
    )
}

/// Codex material whose own refresh time is `age_seconds` in the past.
fn codex_material(label: &str, refresh_token: Option<&str>, age_seconds: u64) -> ProtectedValue {
    let now = unix_now().unwrap();
    let mut material =
        crate::codex_oauth::CodexOAuthCredential::parse(bundle(false, label).as_bytes())
            .unwrap()
            .refreshed(
                None,
                None,
                refresh_token.map(|token| Zeroizing::new(token.to_owned())),
                now - age_seconds,
            )
            .unwrap()
            .to_bundle()
            .unwrap()
            .into_bytes();
    ProtectedValue::new(std::mem::take(&mut *material)).unwrap()
}

struct KeepAliveFixture {
    db: TestDatabase,
    pools: Vec<PgPool>,
    kek: Arc<SyntheticKek>,
    store: Arc<PlatformCredentialStore>,
    owner: Owner,
}

impl KeepAliveFixture {
    async fn create() -> Result<Self> {
        let db = TestDatabase::create().await?;
        let setup = async {
            let owner = db.user("synthetic-keepalive-owner").await?;
            let kek = Arc::new(SyntheticKek::default());
            let (pool, _) = db.broker_pool().await?;
            let store = Arc::new(PlatformCredentialStore::new(
                pool.clone(),
                kek.clone(),
                builtin_provider_catalog(),
            ));
            Ok::<_, anyhow::Error>((pool, kek, store, owner))
        }
        .await;
        match setup {
            Ok((pool, kek, store, owner)) => Ok(Self {
                db,
                pools: vec![pool],
                kek,
                store,
                owner,
            }),
            Err(error) => {
                db.finish(Err(error)).await?;
                unreachable!("failed setup always returns its error")
            }
        }
    }

    /// Another replica: its own restricted login, store and decision cache.
    async fn replica(
        &mut self,
        upstream: Arc<dyn BrokerUpstreamTransport>,
        github_app: Option<Arc<GitHubAppAuthorizationOwner>>,
    ) -> Result<Arc<OAuthKeepAlive>> {
        let (pool, _) = self.db.broker_pool().await?;
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            self.kek.clone(),
            builtin_provider_catalog(),
        ));
        self.pools.push(pool);
        Ok(Arc::new(OAuthKeepAlive::new(
            store,
            upstream,
            github_app,
            config(),
        )))
    }

    async fn codex(&self, name: &str, material: &ProtectedValue) -> Result<CredentialRecord> {
        Ok(self
            .store
            .create(
                &self.owner,
                registration(name, CredentialAuthKind::OAuth),
                material,
            )
            .await?)
    }

    /// Date the database record as if it had been created `days` ago.
    async fn age(&self, record: &CredentialRecord, days: i32) -> Result<()> {
        sqlx::query(
            "UPDATE platform_credentials SET created_at=now()-make_interval(days=>$2), \
             updated_at=now()-make_interval(days=>$2) WHERE id=$1",
        )
        .bind(record.metadata.id.as_str())
        .bind(days)
        .execute(&self.db.pool)
        .await?;
        Ok(())
    }

    async fn current(&self, owner: &Owner, record: &CredentialRecord) -> Result<CredentialRecord> {
        Ok(self.store.record(owner, &record.metadata.id).await?)
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        for pool in self.pools {
            pool.close().await;
        }
        self.db.finish(result).await
    }
}

fn config() -> OAuthKeepAliveConfig {
    OAuthKeepAliveConfig {
        interval: Duration::from_secs(10),
        ..OAuthKeepAliveConfig::default()
    }
}

fn advanced(before: &CredentialRecord, after: &CredentialRecord) -> bool {
    after.version.material_generation == before.version.material_generation + 1
        && after.version.revocation_generation == before.version.revocation_generation + 1
        && after.metadata.status == CredentialStatus::Active
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn keepalive_refreshes_only_idle_codex_material_and_records_a_rejection() -> Result<()> {
    let mut f = KeepAliveFixture::create().await?;
    let result = async {
        let provider = Arc::new(CodexProvider::default());
        let keepalive = f.replica(provider.clone(), None).await?;

        let aged = f
            .codex("Aged", &codex_material("aged", None, 8 * DAY))
            .await?;
        f.age(&aged, 8).await?;
        let fresh = f.codex("Fresh", &codex_material("fresh", None, 0)).await?;
        let failed = f
            .codex("Failed", &codex_material("failed", None, 8 * DAY))
            .await?;
        f.age(&failed, 8).await?;
        sqlx::query("UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1")
            .bind(failed.metadata.id.as_str())
            .execute(&f.db.pool)
            .await?;
        // Reconnected yesterday, created long ago: the record is old enough to
        // select, but the material's own refresh time says it is not due.
        let reconnected = f
            .codex("Reconnected", &codex_material("before", None, 40 * DAY))
            .await?;
        let reconnected = f
            .store
            .replace(
                &f.owner,
                &reconnected.metadata.id,
                reconnected.version,
                &codex_material("reconnected", None, DAY),
                None,
            )
            .await?;
        f.age(&reconnected, 40).await?;
        let rejected = f
            .codex(
                "Rejected",
                &codex_material("rejected", Some(REJECTED_REFRESH_TOKEN), 8 * DAY),
            )
            .await?;
        f.age(&rejected, 8).await?;

        let sweep = keepalive.sweep().await;
        ensure!(
            sweep.refreshed == 1
                && sweep.failed == 1
                && sweep.not_due == 1
                && sweep.skipped == 0
                && sweep.material_reads == 3
                && sweep.complete,
            "unexpected first sweep {sweep:?}"
        );
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 2);
        let mut presented = provider.presented.lock().unwrap().clone();
        presented.sort();
        ensure!(
            presented == ["synthetic-refresh-aged", REJECTED_REFRESH_TOKEN],
            "only the aged and rejected tokens may be presented: {presented:?}"
        );

        let refreshed = f.current(&f.owner, &aged).await?;
        ensure!(advanced(&aged, &refreshed), "aged credential not rotated");
        let material = f
            .store
            .read_for_broker(&f.owner, &refreshed.metadata.id, refreshed.version)
            .await?;
        let credential = crate::codex_oauth::CodexOAuthCredential::parse(material.expose_secret())?;
        ensure!(
            credential
                .refresh_token()
                .starts_with("synthetic-refresh-rotated-")
        );
        ensure!(credential.refreshed_at_unix() + 60 >= unix_now()?);
        ensure!(
            f.store
                .current_oauth_refresh_attempt(&f.owner, &aged.metadata.id)
                .await?
                .is_some_and(|attempt| attempt.state == OAuthRefreshState::Committed)
        );
        for untouched in [&fresh, &failed, &reconnected] {
            ensure!(f.current(&f.owner, untouched).await?.version == untouched.version);
        }
        // A definite rejection after Start is terminal, exactly as on demand.
        let rejected_now = f.current(&f.owner, &rejected).await?;
        ensure!(rejected_now.metadata.status == CredentialStatus::RefreshFailed);
        ensure!(
            f.store
                .current_oauth_refresh_attempt(&f.owner, &rejected.metadata.id)
                .await?
                .is_some_and(|attempt| attempt.state == OAuthRefreshState::Unknown)
        );

        // The next sweep neither repeats an exchange nor rereads material:
        // the rotation is dated by its commit receipt, the failure is no
        // longer active, and the reconnected version's decision is cached.
        let unwraps = f.kek.unwrap_calls.load(Ordering::SeqCst);
        let again = keepalive.sweep().await;
        ensure!(
            again.refreshed == 0
                && again.failed == 0
                && again.not_due == 1
                && again.material_reads == 0
                && again.complete,
            "unexpected second sweep {again:?}"
        );
        ensure!(f.kek.unwrap_calls.load(Ordering::SeqCst) == unwraps);
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 2);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn concurrent_keepalive_replicas_refresh_one_idle_credential_exactly_once() -> Result<()> {
    let mut f = KeepAliveFixture::create().await?;
    let result = async {
        let provider = Arc::new(CodexProvider::default());
        let first = f.replica(provider.clone(), None).await?;
        let second = f.replica(provider.clone(), None).await?;
        let aged = f
            .codex("Aged", &codex_material("aged", None, 8 * DAY))
            .await?;
        f.age(&aged, 8).await?;

        // The first replica selects the credential and stops inside its
        // material read, before any reservation.
        f.kek.unwrap_gate.arm();
        let first_sweep = spawn({
            let first = first.clone();
            async move { first.sweep().await }
        });
        f.kek.unwrap_gate.wait().await?;
        // The second replica reads, reserves, starts and holds the exchange.
        provider.gate.armed.store(true, Ordering::SeqCst);
        let second_sweep = spawn({
            let second = second.clone();
            async move { second.sweep().await }
        });
        provider.gate.wait().await?;
        // The first now finds the same version due, but its begin observes the
        // started attempt and ends without sending.
        f.kek.unwrap_gate.release();
        let lost = finish_task(first_sweep).await?;
        ensure!(
            lost.refreshed == 0 && lost.failed == 0 && lost.skipped == 1,
            "losing replica {lost:?}"
        );
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        provider.gate.released.notify_one();
        let won = finish_task(second_sweep).await?;
        ensure!(
            won.refreshed == 1 && won.failed == 0,
            "winning replica {won:?}"
        );
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        ensure!(advanced(&aged, &f.current(&f.owner, &aged).await?));

        // Neither replica selects the freshly committed generation again.
        let (a, b) = tokio::join!(first.sweep(), second.sweep());
        ensure!(
            a.material_reads == 0 && b.material_reads == 0,
            "{a:?} {b:?}"
        );
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn keepalive_shutdown_waits_for_a_started_refresh_to_commit() -> Result<()> {
    let mut f = KeepAliveFixture::create().await?;
    let result = async {
        let provider = Arc::new(CodexProvider::default());
        let keepalive = f.replica(provider.clone(), None).await?;
        let aged = f
            .codex("Aged", &codex_material("aged", None, 8 * DAY))
            .await?;
        f.age(&aged, 8).await?;
        provider.gate.armed.store(true, Ordering::SeqCst);
        // The periodic owner's first sweep starts within a jittered quarter
        // of its 10-second interval.
        keepalive.start();
        provider.gate.wait().await?;
        let mut shutdown = spawn({
            let keepalive = keepalive.clone();
            async move { keepalive.shutdown().await }
        });
        ensure!(
            tokio::time::timeout(Duration::from_millis(300), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned while a started exchange was outstanding"
        );
        provider.gate.released.notify_one();
        finish_task(shutdown).await?;
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        ensure!(advanced(&aged, &f.current(&f.owner, &aged).await?));
        ensure!(
            f.store
                .current_oauth_refresh_attempt(&f.owner, &aged.metadata.id)
                .await?
                .is_some_and(|attempt| attempt.state == OAuthRefreshState::Committed)
        );
        // A stopped owner selects nothing further.
        let after = keepalive.sweep().await;
        ensure!(after.material_reads == 0 && !after.complete, "{after:?}");
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Synthetic GitHub App endpoints for exactly one rotation of the fixture
/// bundle: token exchange, user identity and installation proof.
#[derive(Default)]
struct GitHubProvider {
    requests: Mutex<Vec<String>>,
}

#[async_trait]
impl BrokerUpstreamTransport for GitHubProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, _, body) = request.into_parts();
        self.requests
            .lock()
            .unwrap()
            .push(format!("{method} {}", target.path()));
        let value = match (method, target.as_str()) {
            (Method::POST, "https://github.com/login/oauth/access_token") => {
                let form: BTreeMap<String, String> =
                    url::form_urlencoded::parse(&body).into_owned().collect();
                if form.get("grant_type").map(String::as_str) != Some("refresh_token")
                    || form.get("refresh_token").map(String::as_str) != Some(GITHUB_REFRESH_TOKEN)
                {
                    return Err(BrokerUpstreamError::Protocol);
                }
                serde_json::json!({
                    "access_token": GITHUB_ROTATED_ACCESS_TOKEN,
                    "token_type": "bearer",
                    "expires_in": 28_800,
                    "refresh_token": "ghr_synthetic_keepalive_rotated_1234567890",
                    "refresh_token_expires_in": 15_897_600
                })
            }
            (Method::GET, "https://api.github.com/user") => {
                serde_json::json!({"id": 73, "login": "octo-user"})
            }
            (Method::GET, "https://api.github.com/user/installations?per_page=100&page=1") => {
                serde_json::json!({"installations": [{"id": 41, "app_slug": "codewire"}]})
            }
            _ => return Err(BrokerUpstreamError::DestinationDenied),
        };
        Ok(json_response(StatusCode::OK, value))
    }
}

fn github_registration(account: &str) -> CredentialRegistration {
    CredentialRegistration {
        provider: ProviderId::parse("github").unwrap(),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: "GitHub".into(),
        account_hint: Some(account.into()),
        expires_at_unix: None,
    }
}

/// A tagged App bundle last rotated `age_seconds` ago (8-hour access token,
/// six-month refresh token, as GitHub issues them).
fn github_app_material(age_seconds: u64) -> ProtectedValue {
    let issued = unix_now().unwrap() - age_seconds;
    let payload = serde_json::json!({
        "version": 1,
        "access_token": "ghu_synthetic_keepalive_access_1234567890",
        "access_expires_at_unix": issued + 28_800,
        "refresh_token": GITHUB_REFRESH_TOKEN,
        "refresh_expires_at_unix": issued + 15_897_600,
        "user_id": 73,
        "app_slug": "codewire",
        "installation_id": 41
    });
    let mut bytes = b"codewire-github-app-user-v1:".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
    GitHubAppUserOAuthBundle::parse(&bytes).expect("synthetic App bundle is canonical");
    value(&bytes)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn keepalive_rotates_an_idle_github_app_connection_and_leaves_raw_tokens() -> Result<()> {
    let mut f = KeepAliveFixture::create().await?;
    let result = async {
        let github = Arc::new(GitHubProvider::default());
        let owner = Arc::new(GitHubAppAuthorizationOwner::new(
            GitHubAppAuthorizationConfig::new(
                "Iv1.syntheticclient".into(),
                Zeroizing::new("synthetic-client-secret".into()),
                "codewire".into(),
                "https://codewire.example/api/v1/github/oauth/callback".into(),
            )?,
            github.clone(),
        ));
        let codex = Arc::new(CodexProvider::default());
        let keepalive = f.replica(codex.clone(), Some(owner)).await?;

        let app_owner = f.db.user("synthetic-app-owner").await?;
        let app = f
            .store
            .create(
                &app_owner,
                github_registration("octo-user"),
                &github_app_material(31 * DAY),
            )
            .await?;
        f.age(&app, 31).await?;
        let raw_owner = f.db.user("synthetic-raw-owner").await?;
        let raw = f
            .store
            .create(
                &raw_owner,
                github_registration("raw-user"),
                &value(b"gho_synthetic_non_expiring_token_1234567890"),
            )
            .await?;
        f.age(&raw, 31).await?;

        let sweep = keepalive.sweep().await;
        ensure!(
            sweep.refreshed == 1 && sweep.not_due == 1 && sweep.material_reads == 2,
            "unexpected sweep {sweep:?}"
        );
        ensure!(
            *github.requests.lock().unwrap()
                == [
                    "POST /login/oauth/access_token",
                    "GET /user",
                    "GET /user/installations"
                ]
        );
        ensure!(codex.refreshes.load(Ordering::SeqCst) == 0);
        let rotated = f.current(&app_owner, &app).await?;
        ensure!(advanced(&app, &rotated));
        let material = f
            .store
            .read_for_broker(&app_owner, &rotated.metadata.id, rotated.version)
            .await?;
        let bundle = GitHubAppUserOAuthBundle::parse(material.expose_secret())?;
        ensure!(bundle.access_token()?.as_str() == GITHUB_ROTATED_ACCESS_TOKEN);
        ensure!(f.current(&raw_owner, &raw).await?.version == raw.version);

        // The non-expiring token is decided once per version, not reread.
        let unwraps = f.kek.unwrap_calls.load(Ordering::SeqCst);
        let again = keepalive.sweep().await;
        ensure!(again.material_reads == 0 && again.not_due == 1, "{again:?}");
        ensure!(f.kek.unwrap_calls.load(Ordering::SeqCst) == unwraps);
        ensure!(github.requests.lock().unwrap().len() == 3);
        Ok(())
    }
    .await;
    f.finish(result).await
}
