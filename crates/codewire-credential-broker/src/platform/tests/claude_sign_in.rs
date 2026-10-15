//! A Claude sign-in at the platform lease provider, against real restricted
//! PostgreSQL and a synthetic Claude. A proxied request whose access token is
//! about to expire refreshes it once through the durable journal and is sent
//! with the rotated token; a refused refresh is terminal and the credential
//! needs Reconnect. The previous refresh token is never presented twice.

use bytes::Bytes;
use codewire_daemon_proto::codewire::bridge::v1::{CredentialBridgeRequest, CredentialHttpHeader};
use codewire_platform_credentials::CredentialRegistration;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use zeroize::Zeroizing;

use super::*;
use crate::claude_oauth::{
    ClaudeIssuedTokens, ClaudeOAuthCredential, ClaudeProfile, ClaudeSubscriptionType,
    import_tokens_at,
};
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    OpenAiBroker,
};

const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
pub(super) const SCOPES: &str = "user:profile user:inference user:sessions:claude_code";

/// Synthetic Claude: the token endpoint rotates both tokens, or refuses every
/// refresh with `invalid_grant`; the Messages route records the bearer it saw.
#[derive(Clone, Default)]
pub(super) struct SyntheticClaude {
    pub(super) rejecting: Arc<AtomicBool>,
    pub(super) refreshes: Arc<AtomicUsize>,
    pub(super) presented: Arc<Mutex<Vec<serde_json::Value>>>,
    pub(super) bearers: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl BrokerUpstreamTransport for SyntheticClaude {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        if method == Method::POST && target.as_str() == TOKEN_URL {
            let request: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| BrokerUpstreamError::Protocol)?;
            let call = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
            self.presented.lock().unwrap().push(request.clone());
            return Ok(if self.rejecting.load(Ordering::SeqCst) {
                json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid_grant", "error_description": "synthetic"}),
                )
            } else {
                json(
                    StatusCode::OK,
                    serde_json::json!({
                        "token_type": "Bearer",
                        "access_token": format!("synthetic-rotated-access-{call}"),
                        "refresh_token": format!("synthetic-rotated-refresh-{call}"),
                        "expires_in": 28_800,
                        "scope": request["scope"],
                    }),
                )
            });
        }
        if method == Method::POST && target.as_str() == MESSAGES_URL {
            let bearer = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .ok_or(BrokerUpstreamError::Protocol)?;
            self.bearers.lock().unwrap().push(bearer.to_owned());
            return Ok(json(StatusCode::OK, serde_json::json!({"type": "message"})));
        }
        Err(BrokerUpstreamError::DestinationDenied)
    }
}

fn json(status: StatusCode, body: serde_json::Value) -> BrokerUpstreamResponse {
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

/// Sign-in material named `label` whose access token expires `remaining`
/// seconds from now and whose own refresh time is `age` seconds ago.
pub(super) fn sign_in_material(
    label: &str,
    remaining: u64,
    age: u64,
    refresh_token_lifetime: Option<u64>,
) -> ProtectedValue {
    let now = unix_now().unwrap();
    let (bundle, _) = import_tokens_at(
        ClaudeIssuedTokens {
            access_token: Zeroizing::new(format!("synthetic-access-{label}")),
            refresh_token: Some(Zeroizing::new(format!("synthetic-refresh-{label}"))),
            expires_in: age + remaining,
            refresh_token_expires_in: refresh_token_lifetime,
            scope: Some(SCOPES.into()),
        },
        ClaudeProfile {
            email: Some("person@example.test".into()),
            subscription_type: Some(ClaudeSubscriptionType::Max),
            rate_limit_tier: Some("default_claude_max_20x".into()),
        },
        now - age,
    )
    .unwrap()
    .into_parts();
    let mut bytes = bundle.into_bytes();
    ProtectedValue::new(std::mem::take(&mut *bytes)).unwrap()
}

pub(super) fn sign_in_registration(name: &str) -> CredentialRegistration {
    CredentialRegistration {
        provider: codewire_access::ProviderId::parse("anthropic").unwrap(),
        authentication_kind: CredentialAuthKind::ClaudeSignIn,
        display_name: name.into(),
        account_hint: Some("person@example.test".into()),
        expires_at_unix: None,
    }
}

/// Store a personal sign-in and bind the fixture environment to a new profile
/// revision that selects it in the Anthropic slot.
async fn bind_sign_in(f: &Fixture, material: &ProtectedValue) -> Result<CredentialRecord> {
    let sign_in = f
        .store
        .create(&f.owner, sign_in_registration("Claude"), material)
        .await?;
    let mut context = f.context.clone();
    context
        .authorized_credentials
        .insert(sign_in.metadata.id.clone());
    f.authority
        .change(|session| session.context = context.clone());
    let manager = PlatformAccessProfileStore::new(f.db.pool.clone(), builtin_provider_catalog());
    let mut entries = f.profile.entries.clone();
    entries.insert(CapabilitySlot::anthropic(), sign_in.metadata.id.clone());
    let changed = manager
        .update(&f.owner, &f.profile.id, f.profile.revision, entries)
        .await?;
    manager
        .replace_binding(
            &context,
            &EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: f.profile.id.clone(),
                profile_revision: f.profile.revision,
            },
            EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: changed.id.clone(),
                profile_revision: changed.revision,
            },
            Some(&context.user_id),
        )
        .await?;
    Ok(sign_in)
}

/// Claude Code's request through the route. In method 2 its bearer is its own
/// copy of the access token; the broker drops it and injects the stored one.
fn claude_code_request() -> CredentialBridgeRequest {
    let header = |name: &str, value: &str| CredentialHttpHeader {
        name: name.into(),
        value: value.as_bytes().to_vec(),
    };
    CredentialBridgeRequest {
        capability_slot: "anthropic".into(),
        route: "anthropic-api".into(),
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: "/v1/messages".into(),
        query: String::new(),
        headers: vec![
            header("content-type", "application/json"),
            header("anthropic-version", "2023-06-01"),
            header("authorization", "Bearer synthetic-guest-copy"),
        ],
        body: br#"{"model":"synthetic","max_tokens":1,"messages":[]}"#.to_vec(),
    }
}

/// A hosted bridge epoch admitted after the binding, owned so a broker can
/// hold it. Its leases are the normal hosted leases.
async fn hosted(f: &Fixture) -> Result<(PgPool, Adapter)> {
    let (pool, adapter) = f.second().await?;
    let adapter = Adapter {
        material: Some(EpochMaterialCache::new()),
        decision: Some(EpochDecision::new()),
        ..adapter
    };
    adapter.admit_authority().await?;
    Ok((pool, adapter))
}

async fn stored(f: &Fixture, record: &CredentialRecord) -> Result<ClaudeOAuthCredential> {
    let current = f.store.record(&f.owner, &record.metadata.id).await?;
    let material = f
        .store
        .read_for_broker(&f.owner, &current.metadata.id, current.version)
        .await?;
    Ok(ClaudeOAuthCredential::parse(material.expose_secret())?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_expiring_sign_in_refreshes_once_and_requests_use_the_rotated_token() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        // Two minutes left: inside the five-minute window.
        let sign_in = bind_sign_in(&f, &sign_in_material("old", 120, 3_600, None)).await?;
        let provider = SyntheticClaude::default();
        let (pool, adapter) = hosted(&f).await?;
        let broker = OpenAiBroker::new(adapter, provider.clone())?;
        for _ in 0..2 {
            let (status, _, _) = broker.execute(claude_code_request()).await?.into_parts();
            ensure!(status == StatusCode::OK);
        }
        // One refresh, as Claude Code sends it, with exactly the granted
        // scopes; both requests carried the rotated token, never the guest's.
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        ensure!(
            provider.presented.lock().unwrap()[0]
                == serde_json::json!({
                    "grant_type": "refresh_token",
                    "refresh_token": "synthetic-refresh-old",
                    "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
                    "scope": SCOPES,
                })
        );
        ensure!(
            *provider.bearers.lock().unwrap()
                == ["synthetic-rotated-access-1", "synthetic-rotated-access-1"]
        );
        let current = f.store.record(&f.owner, &sign_in.metadata.id).await?;
        ensure!(
            current.version.material_generation == sign_in.version.material_generation + 1
                && current.metadata.status == CredentialStatus::Active
                && current.metadata.authentication_kind == CredentialAuthKind::ClaudeSignIn
        );
        let rotated = stored(&f, &sign_in).await?;
        ensure!(rotated.refresh_token() == "synthetic-rotated-refresh-1");
        ensure!(rotated.expires_at_unix() >= unix_now()? + 28_000);
        // The plan and scopes survive the refresh.
        ensure!(rotated.subscription_type() == Some(ClaudeSubscriptionType::Max));
        ensure!(rotated.scopes().join(" ") == SCOPES);
        ensure!(
            f.store
                .current_oauth_refresh_attempt(&f.owner, &sign_in.metadata.id)
                .await?
                .is_some_and(|attempt| attempt.state == OAuthRefreshState::Committed)
        );
        drop(broker);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_refused_sign_in_refresh_needs_reconnect_and_is_never_replayed() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let sign_in = bind_sign_in(&f, &sign_in_material("old", 120, 3_600, None)).await?;
        let provider = SyntheticClaude::default();
        provider.rejecting.store(true, Ordering::SeqCst);
        let (pool, adapter) = hosted(&f).await?;
        let broker = OpenAiBroker::new(adapter, provider.clone())?;
        ensure!(broker.execute(claude_code_request()).await.is_err());
        let current = f.store.record(&f.owner, &sign_in.metadata.id).await?;
        ensure!(current.metadata.status == CredentialStatus::RefreshFailed);
        // The next request is answered with Reconnect, and nothing reaches
        // Claude: the refused refresh token is never presented again.
        let (status, _, _) = broker.execute(claude_code_request()).await?.into_parts();
        ensure!(status == StatusCode::FORBIDDEN);
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        ensure!(provider.bearers.lock().unwrap().is_empty());
        drop(broker);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_fresh_sign_in_is_used_as_stored_and_a_setup_token_never_refreshes() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let sign_in = bind_sign_in(&f, &sign_in_material("fresh", 7_200, 60, None)).await?;
        let provider = SyntheticClaude::default();
        let (pool, adapter) = hosted(&f).await?;
        let broker = OpenAiBroker::new(adapter, provider.clone())?;
        let (status, _, _) = broker.execute(claude_code_request()).await?.into_parts();
        ensure!(status == StatusCode::OK);
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 0);
        ensure!(*provider.bearers.lock().unwrap() == ["synthetic-access-fresh"]);
        ensure!(
            f.store
                .record(&f.owner, &sign_in.metadata.id)
                .await?
                .version
                == sign_in.version
        );
        // The refresh journal refuses a Claude subscription token outright.
        let token = f
            .store
            .create(
                &f.owner,
                CredentialRegistration {
                    provider: codewire_access::ProviderId::parse("anthropic")?,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "Setup token".into(),
                    account_hint: None,
                    expires_at_unix: Some(unix_now()? + 86_400),
                },
                &value(b"sk-ant-oat01-synthetic-platform-setup-token"),
            )
            .await?;
        ensure!(
            f.store
                .begin_oauth_refresh(&f.owner, &token.metadata.id, token.version, Uuid::new_v4())
                .await
                .is_err()
        );
        drop(broker);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}
