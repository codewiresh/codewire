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
    sign_in_material_with_scopes(label, remaining, age, refresh_token_lifetime, SCOPES)
}

/// [`sign_in_material`] granting `scopes`.
fn sign_in_material_with_scopes(
    label: &str,
    remaining: u64,
    age: u64,
    refresh_token_lifetime: Option<u64>,
    scopes: &str,
) -> ProtectedValue {
    let now = unix_now().unwrap();
    let (bundle, _) = import_tokens_at(
        ClaudeIssuedTokens {
            access_token: Zeroizing::new(format!("synthetic-access-{label}")),
            refresh_token: Some(Zeroizing::new(format!("synthetic-refresh-{label}"))),
            expires_in: age + remaining,
            refresh_token_expires_in: refresh_token_lifetime,
            scope: Some(scopes.into()),
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
    let manager = profiles(f.db.pool.clone(), builtin_provider_catalog());
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

fn claude_login_request(
    recipient: &codewire_workload_secrets::ProjectionRecipient,
) -> Result<codewire_daemon_proto::codewire::bridge::v1::ClaudeLoginRequest> {
    Ok(
        codewire_daemon_proto::codewire::bridge::v1::ClaudeLoginRequest {
            request_id: Uuid::new_v4().to_string(),
            recipient_public_key: recipient.public_key().to_vec(),
            deadline_unix_ms: unix_now()? * 1_000 + 25_000,
        },
    )
}

/// Ask `broker` for the Claude login and open it as the daemon would.
async fn deliver<U: BrokerUpstreamTransport + 'static>(
    f: &Fixture,
    broker: &OpenAiBroker<Adapter, U>,
) -> Result<codewire_workload_secrets::OpenedClaudeLogin> {
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    let request = claude_login_request(&recipient)?;
    let sealed = broker
        .claude_login(request.clone())
        .await
        .map_err(|error| anyhow::anyhow!("claude login refused: {error:?}"))?;
    for secret in ["synthetic-refresh-", "synthetic-rotated-refresh-"] {
        ensure!(
            !sealed
                .windows(secret.len())
                .any(|part| part == secret.as_bytes())
        );
    }
    Ok(recipient.open_claude_login(
        &sealed,
        &codewire_workload_secrets::CodexLoginContext {
            environment_id: *Uuid::parse_str(f.context.environment_id.as_str())?.as_bytes(),
            environment_generation: f.context.environment_generation,
            request_id: *Uuid::parse_str(&request.request_id)?.as_bytes(),
            deadline_unix_ms: request.deadline_unix_ms,
        },
        unix_now()? * 1_000,
    )?)
}

/// The Claude login delivers only the creator's own Active Claude sign-in, to
/// a hosted Sandbox or to the creator's own local VM through its owner-local
/// delegation: never a setup token or an API key in the same slot, a sign-in
/// that needs Reconnect, one the creator did not confirm, or one a delegation
/// without the creator's own profile asks for.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_claude_login_delivers_only_the_creators_own_active_sign_in() -> Result<()> {
    for case in [
        "deliver",
        "setup token",
        "api key",
        "reconnect needed",
        "revoked",
        "another user's credential",
        "organization profile",
        "not confirmed by the creator",
        "scopes outside the sign-in",
        "owner-local delegation",
        "owner-local delegation without a profile",
        "owner-local organization profile",
        "owner-local profile not confirmed by the creator",
    ] {
        let f = Fixture::create_for_bridge().await?;
        let result = async {
            let material = if case == "scopes outside the sign-in" {
                // A scope Claude might add on a later refresh.
                sign_in_material_with_scopes(
                    "widened",
                    7_200,
                    60,
                    None,
                    &format!("{SCOPES} user:billing"),
                )
            } else {
                sign_in_material("fresh", 7_200, 60, None)
            };
            let sign_in = bind_sign_in(&f, &material).await?;
            let outcome = match case {
                "deliver" => {
                    let provider = SyntheticClaude::default();
                    let (pool, adapter) = hosted(&f).await?;
                    // Only the dedicated path leases the login permission.
                    let permission = claude_login_permission();
                    ensure!(matches!(
                        adapter
                            .lease_operation(
                                Uuid::new_v4(),
                                CapabilitySlot::anthropic(),
                                permission.operation,
                                permission.route,
                            )
                            .await,
                        Err(BrokerLeaseError::Denied)
                    ));
                    let lease = adapter.lease_claude_login(Uuid::new_v4()).await?;
                    ensure!(lease.permission() == &claude_login_permission());
                    ensure!(lease.credential_metadata().id == sign_in.metadata.id);
                    drop(lease);
                    let broker = OpenAiBroker::new(adapter, provider.clone())?;
                    let opened = deliver(&f, &broker).await?;
                    ensure!(opened.login.access_token() == "synthetic-access-fresh");
                    ensure!(opened.login.scopes().join(" ") == SCOPES);
                    ensure!(opened.login.subscription_type() == Some("max"));
                    ensure!(opened.login.rate_limit_tier() == Some("default_claude_max_20x"));
                    let stored = stored(&f, &sign_in).await?;
                    ensure!(opened.login.expires_at_unix_ms() == stored.expires_at_unix() * 1_000);
                    ensure!(opened.binding.credential_id == sign_in.metadata.id.as_str());
                    ensure!(
                        opened.binding.material_generation == sign_in.version.material_generation
                    );
                    // Valid for two hours: delivered as stored, no refresh.
                    ensure!(provider.refreshes.load(Ordering::SeqCst) == 0);
                    drop(broker);
                    pool.close().await;
                    return Ok(());
                }
                "setup token" | "api key" => {
                    let (kind, material): (_, &[u8]) = if case == "setup token" {
                        (
                            CredentialAuthKind::OAuth,
                            b"sk-ant-oat01-synthetic-setup-token-never-delivered",
                        )
                    } else {
                        (
                            CredentialAuthKind::ApiKey,
                            b"sk-ant-api03-synthetic-key-never-delivered",
                        )
                    };
                    let other = f
                        .store
                        .create(
                            &f.owner,
                            CredentialRegistration {
                                provider: codewire_access::ProviderId::parse("anthropic")?,
                                authentication_kind: kind,
                                display_name: case.into(),
                                account_hint: None,
                                expires_at_unix: None,
                            },
                            &value(material),
                        )
                        .await?;
                    let mut context = f.context.clone();
                    context
                        .authorized_credentials
                        .insert(sign_in.metadata.id.clone());
                    context
                        .authorized_credentials
                        .insert(other.metadata.id.clone());
                    f.authority
                        .change(|session| session.context = context.clone());
                    let manager = profiles(f.db.pool.clone(), builtin_provider_catalog());
                    let current = manager.get(&f.owner, &f.profile.id).await?;
                    let mut entries = current.entries.clone();
                    entries.insert(CapabilitySlot::anthropic(), other.metadata.id.clone());
                    let changed = manager
                        .update(&f.owner, &current.id, current.revision, entries)
                        .await?;
                    manager
                        .replace_binding(
                            &context,
                            &EnvironmentAccessBinding {
                                environment_id: context.environment_id.clone(),
                                profile_id: current.id.clone(),
                                profile_revision: current.revision,
                            },
                            EnvironmentAccessBinding {
                                environment_id: context.environment_id.clone(),
                                profile_id: changed.id.clone(),
                                profile_revision: changed.revision,
                            },
                            Some(&context.user_id),
                        )
                        .await?;
                    let (_pool, adapter) = hosted(&f).await?;
                    adapter.lease_claude_login(Uuid::new_v4()).await
                }
                "reconnect needed" => {
                    sqlx::query(
                        "UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1",
                    )
                    .bind(sign_in.metadata.id.as_str())
                    .execute(&f.db.pool)
                    .await?;
                    let (_pool, adapter) = hosted(&f).await?;
                    adapter.lease_claude_login(Uuid::new_v4()).await
                }
                "revoked" => {
                    f.store
                        .revoke(&f.owner, &sign_in.metadata.id, sign_in.version)
                        .await?;
                    let (_pool, adapter) = hosted(&f).await?;
                    adapter.lease_claude_login(Uuid::new_v4()).await
                }
                "another user's credential" => {
                    f.db.user("synthetic-other-user").await?;
                    sqlx::query("UPDATE platform_credentials SET user_id=$2 WHERE id=$1")
                        .bind(sign_in.metadata.id.as_str())
                        .bind("synthetic-other-user")
                        .execute(&f.db.pool)
                        .await?;
                    let (_pool, adapter) = hosted(&f).await?;
                    adapter.lease_claude_login(Uuid::new_v4()).await
                }
                // An organization's profile: never the creator's own login.
                "organization profile" => {
                    f.authority.change(|session| {
                        session.credential_owner =
                            Owner::Organization(OwnerId::parse("synthetic-org").unwrap());
                    });
                    match hosted(&f).await {
                        Ok((_pool, adapter)) => adapter.lease_claude_login(Uuid::new_v4()).await,
                        Err(_) => Err(BrokerLeaseError::Denied),
                    }
                }
                "not confirmed by the creator" => {
                    f.authority.change(|session| {
                        session.context.allow_personal_credentials = false;
                    });
                    match hosted(&f).await {
                        Ok((_pool, adapter)) => adapter.lease_claude_login(Uuid::new_v4()).await,
                        Err(_) => Err(BrokerLeaseError::Denied),
                    }
                }
                // A local VM's delegation by the creator, with the creator's
                // own personal profile, gets the same sealed login (owner
                // decision, 2026-10-15), bound to the VM's environment.
                "owner-local delegation" => {
                    let binding = f.current_binding().await?;
                    let adapter = f
                        .owner_local(
                            f.owner.clone(),
                            true,
                            Some(binding),
                            CapabilitySlot::anthropic(),
                            &sign_in,
                            claude_login_permission(),
                        )
                        .await??;
                    let provider = SyntheticClaude::default();
                    let broker = OpenAiBroker::new(adapter, provider.clone())?;
                    let opened = deliver(&f, &broker).await?;
                    ensure!(opened.login.access_token() == "synthetic-access-fresh");
                    ensure!(opened.login.scopes().join(" ") == SCOPES);
                    ensure!(opened.login.subscription_type() == Some("max"));
                    ensure!(opened.binding.credential_id == sign_in.metadata.id.as_str());
                    ensure!(provider.refreshes.load(Ordering::SeqCst) == 0);
                    return Ok(());
                }
                "owner-local delegation without a profile"
                | "owner-local organization profile"
                | "owner-local profile not confirmed by the creator" => {
                    let owner = if case == "owner-local organization profile" {
                        Owner::Organization(OwnerId::parse("synthetic-org")?)
                    } else {
                        f.owner.clone()
                    };
                    let binding = if case == "owner-local delegation without a profile" {
                        None
                    } else {
                        Some(f.current_binding().await?)
                    };
                    let confirmed = case != "owner-local profile not confirmed by the creator";
                    match f
                        .owner_local(
                            owner,
                            confirmed,
                            binding,
                            CapabilitySlot::anthropic(),
                            &sign_in,
                            claude_login_permission(),
                        )
                        .await?
                    {
                        Ok(adapter) => adapter.lease_claude_login(Uuid::new_v4()).await,
                        Err(error) => Err(error),
                    }
                }
                // The lease admits it, but the broker never seals a login
                // whose scopes go beyond the sign-in's six.
                "scopes outside the sign-in" => {
                    let (pool, adapter) = hosted(&f).await?;
                    let broker = OpenAiBroker::new(adapter, SyntheticClaude::default())?;
                    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
                    let refused = broker.claude_login(claude_login_request(&recipient)?).await;
                    drop(broker);
                    pool.close().await;
                    ensure!(matches!(refused, Err(crate::BrokerRequestError::Denied)));
                    return Ok(());
                }
                _ => unreachable!(),
            };
            ensure!(
                matches!(
                    outcome,
                    Err(BrokerLeaseError::Denied | BrokerLeaseError::ReconnectRequired)
                ),
                "{case} must not deliver a login"
            );
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

/// A sign-in with less than thirty minutes left is refreshed once through the
/// durable journal before it is sealed, and the rotated refresh token stays in
/// the store.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_expiring_claude_login_is_refreshed_once_before_delivery() -> Result<()> {
    let f = Fixture::create_for_bridge().await?;
    let result = async {
        // Twenty minutes left of an eight-hour token.
        let sign_in = bind_sign_in(&f, &sign_in_material("old", 1_200, 27_600, None)).await?;
        let provider = SyntheticClaude::default();
        let (pool, adapter) = hosted(&f).await?;
        let broker = OpenAiBroker::new(adapter, provider.clone())?;
        let opened = deliver(&f, &broker).await?;
        ensure!(opened.login.access_token() == "synthetic-rotated-access-1");
        ensure!(opened.login.expires_at_unix_ms() >= (unix_now()? + 28_000) * 1_000);
        ensure!(opened.binding.material_generation == sign_in.version.material_generation + 1);
        // A second delivery uses the rotated token without refreshing again.
        let again = deliver(&f, &broker).await?;
        ensure!(again.login.access_token() == "synthetic-rotated-access-1");
        ensure!(provider.refreshes.load(Ordering::SeqCst) == 1);
        ensure!(stored(&f, &sign_in).await?.refresh_token() == "synthetic-rotated-refresh-1");
        drop(broker);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}
