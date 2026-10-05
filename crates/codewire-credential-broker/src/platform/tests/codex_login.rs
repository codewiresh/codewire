//! The delivery predicate of the one listed direct delivery exception, the
//! Sandbox creator's personal Codex login, against real restricted
//! PostgreSQL and a synthetic runtime authority, KEK and provider. No
//! Kubernetes, OpenBao, provider network or real credential.

use bytes::Bytes;
use codewire_access::{CredentialAuthKind, ProviderCatalog, ProviderId};
use codewire_platform_credentials::CredentialRegistration;
use codewire_workload_secrets::{CodexLoginContext, ProjectionRecipient};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use super::*;
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    OpenAiBroker,
};

async fn login(adapter: &Adapter) -> Result<PlatformCredentialLease, BrokerLeaseError> {
    adapter.lease_codex_login(Uuid::new_v4()).await
}

/// Bind the creator's profile to `entries` at its next revision, as an edit
/// in the dashboard would, and authorize exactly those credentials.
async fn select(f: &Fixture, entries: BTreeMap<CapabilitySlot, CredentialId>) -> Result<()> {
    let manager = PlatformAccessProfileStore::new(f.db.pool.clone(), builtin_provider_catalog());
    let changed = manager
        .update(&f.owner, &f.profile.id, f.profile.revision, entries.clone())
        .await?;
    let mut context = f.context.clone();
    context.authorized_credentials = entries.values().cloned().collect();
    manager
        .replace_binding(
            &context,
            &EnvironmentAccessBinding {
                environment_id: f.context.environment_id.clone(),
                profile_id: f.profile.id.clone(),
                profile_revision: f.profile.revision,
            },
            EnvironmentAccessBinding {
                environment_id: f.context.environment_id.clone(),
                profile_id: changed.id,
                profile_revision: changed.revision,
            },
            Some(&f.context.user_id),
        )
        .await?;
    f.authority
        .change(|session| session.context.authorized_credentials = context.authorized_credentials);
    Ok(())
}

/// A second adapter connected through `session` and a profile reader using
/// `catalog`, sharing the fixture's database and credential store.
async fn connect(
    f: &Fixture,
    session: PlatformRuntimeSession,
    catalog: ProviderCatalog,
) -> Result<Adapter, PlatformRuntimeError> {
    let authority = Arc::new(SyntheticAuthority::new(session));
    Adapter::connect(
        authority,
        f.store.clone(),
        PlatformAccessProfileStore::new(f.pool.clone(), catalog),
    )
    .await
}

fn catalog_without_login_permission() -> ProviderCatalog {
    let builtin = builtin_provider_catalog();
    ProviderCatalog::from_definitions(["ssh", "openai", "anthropic", "github"].map(|id| {
        let mut definition = builtin
            .get(&ProviderId::parse(id).unwrap())
            .unwrap()
            .clone();
        for policy in definition.capabilities.values_mut() {
            policy.permissions.remove(&codex_login_permission());
        }
        definition
    }))
    .unwrap()
}

fn current_session(f: &Fixture) -> PlatformRuntimeSession {
    f.authority.session.lock().unwrap().clone()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn codex_login_admits_only_the_creators_own_active_personal_oauth_login() -> Result<()> {
    for case in [
        "deliver",
        "api key",
        "reconnect needed",
        "revoked",
        "organization-owned row",
        "organization profile",
        "another user's credential",
        "not confirmed by the creator",
        "codex not selected",
        "owner-local runtime",
        "no codex-login permission",
    ] {
        let f = Fixture::create_for_bridge().await?;
        let result = async {
            let outcome = match case {
                "deliver" => {
                    let lease = login(&f.adapter).await?;
                    ensure!(lease.permission() == &codex_login_permission());
                    ensure!(lease.credential_metadata().id == f.record.metadata.id);
                    ensure!(lease.grant().capability_slot == CapabilitySlot::codex());
                    // Only the dedicated path leases the login permission.
                    let permission = codex_login_permission();
                    ensure!(matches!(
                        f.adapter
                            .lease_operation(
                                Uuid::new_v4(),
                                CapabilitySlot::codex(),
                                permission.operation,
                                permission.route,
                            )
                            .await,
                        Err(BrokerLeaseError::Denied)
                    ));
                    return Ok(());
                }
                "api key" => {
                    let key = f
                        .store
                        .create(
                            &f.owner,
                            registration("Codex key", CredentialAuthKind::ApiKey),
                            &value(b"sk-synthetic-codex-login-api-key-never-delivered"),
                        )
                        .await?;
                    select(
                        &f,
                        BTreeMap::from([(CapabilitySlot::codex(), key.metadata.id.clone())]),
                    )
                    .await?;
                    // The same selection still serves proxied requests with
                    // the API key: an epoch admitted after it leases it.
                    let selected = f.epoch().await?;
                    ensure!(lease(&selected).await?.credential_metadata().id == key.metadata.id);
                    login(&selected).await
                }
                "reconnect needed" => {
                    sqlx::query(
                        "UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1",
                    )
                    .bind(f.record.metadata.id.as_str())
                    .execute(&f.db.pool)
                    .await?;
                    login(&f.adapter).await
                }
                "revoked" => {
                    f.store
                        .revoke(&f.owner, &f.record.metadata.id, f.record.version)
                        .await?;
                    login(&f.adapter).await
                }
                // A row from before organizations were refused OAuth logins,
                // still selected by the creator's personal profile.
                "organization-owned row" => {
                    sqlx::query(
                        "UPDATE platform_credentials SET user_id=NULL,organization_id=$2 WHERE id=$1",
                    )
                    .bind(f.record.metadata.id.as_str())
                    .bind("synthetic-org")
                    .execute(&f.db.pool)
                    .await?;
                    login(&f.adapter).await
                }
                // An organization's profile: never the creator's own login.
                "organization profile" => {
                    let mut session = current_session(&f);
                    session.credential_owner =
                        Owner::Organization(OwnerId::parse("synthetic-org")?);
                    match connect(&f, session, builtin_provider_catalog()).await {
                        Ok(adapter) => login(&adapter).await,
                        Err(_) => Err(BrokerLeaseError::Denied),
                    }
                }
                "another user's credential" => {
                    f.db.user("synthetic-other-user").await?;
                    sqlx::query("UPDATE platform_credentials SET user_id=$2 WHERE id=$1")
                        .bind(f.record.metadata.id.as_str())
                        .bind("synthetic-other-user")
                        .execute(&f.db.pool)
                        .await?;
                    login(&f.adapter).await
                }
                // The hosted authority admits personal credentials only when
                // the creator confirmed the creator's own profile.
                "not confirmed by the creator" => {
                    let mut session = current_session(&f);
                    session.context.allow_personal_credentials = false;
                    login(&connect(&f, session, builtin_provider_catalog()).await?).await
                }
                "codex not selected" => {
                    let anthropic = f
                        .store
                        .create(
                            &f.owner,
                            CredentialRegistration {
                                provider: ProviderId::parse("anthropic")?,
                                ..registration("Claude key", CredentialAuthKind::ApiKey)
                            },
                            &value(b"sk-ant-synthetic-codex-login-never-delivered"),
                        )
                        .await?;
                    select(
                        &f,
                        BTreeMap::from([(CapabilitySlot::anthropic(), anthropic.metadata.id)]),
                    )
                    .await?;
                    login(&f.adapter).await
                }
                "owner-local runtime" => {
                    let mut context = f.context.clone();
                    context.placement = GrantPlacement::PlatformToLocal;
                    let session = PlatformRuntimeSession::owner_local(
                        context,
                        f.owner.clone(),
                        Some(EnvironmentAccessBinding {
                            environment_id: f.context.environment_id.clone(),
                            profile_id: f.profile.id.clone(),
                            profile_revision: f.profile.revision,
                        }),
                        [7; 32],
                        unix_now()? + 3_600,
                    )?;
                    login(&connect(&f, session, builtin_provider_catalog()).await?).await
                }
                "no codex-login permission" => {
                    let adapter =
                        connect(&f, current_session(&f), catalog_without_login_permission())
                            .await?;
                    // The proxied permission is unaffected.
                    ensure!(lease(&adapter).await.is_ok());
                    login(&adapter).await
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

/// Synthetic OpenAI token endpoint and ChatGPT Responses route. Each refresh
/// pauses so that every concurrent caller reaches the serialized path.
#[derive(Clone)]
struct Provider {
    exchanges: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
    rotated: String,
}

#[async_trait]
impl BrokerUpstreamTransport for Provider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, _) = request.into_parts();
        if method != Method::POST {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        let (content_type, body) = match target.as_str() {
            "https://auth.openai.com/oauth/token" => {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(300)).await;
                (
                    "application/json",
                    serde_json::to_vec(&serde_json::json!({
                        "id_token": id_token(),
                        "access_token": self.rotated,
                        "refresh_token": "synthetic-refresh-rotated",
                    }))
                    .unwrap(),
                )
            }
            "https://chatgpt.com/backend-api/codex/responses" => {
                self.responses.fetch_add(1, Ordering::SeqCst);
                let presented = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "));
                if presented != Some(self.rotated.as_str()) {
                    return Err(BrokerUpstreamError::Protocol);
                }
                ("text/event-stream", b"data: synthetic\n\n".to_vec())
            }
            _ => return Err(BrokerUpstreamError::DestinationDenied),
        };
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(header::CONTENT_TYPE, HeaderValue::from_static(content_type))]),
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(body)) })),
        ))
    }
}

fn proxied_request() -> codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeRequest {
    codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeRequest {
        capability_slot: "codex".into(),
        route: "openai-api".into(),
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: "/responses".into(),
        query: String::new(),
        headers: vec![
            codewire_gateway_proto::codewire::bridge::v1::CredentialHttpHeader {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            },
        ],
        body: br#"{"input":"hello"}"#.to_vec(),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn concurrent_logins_and_proxied_requests_across_epochs_refresh_once() -> Result<()> {
    let f = Fixture::create_for_bridge().await?;
    let result = async {
        let rotated = token(serde_json::json!({
            "exp": unix_now()? + 7_200,
            "synthetic": "rotated",
        }));
        let provider = Provider {
            exchanges: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(AtomicUsize::new(0)),
            rotated: rotated.clone(),
        };
        // Two epochs of the same Sandbox: separate in-process mutexes, one
        // durable refresh journal.
        let first = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let second = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let mut logins = Vec::new();
        for broker in [&first, &first, &first, &second, &second] {
            let recipient = ProjectionRecipient::new();
            let request = codewire_gateway_proto::codewire::bridge::v1::CodexLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: recipient.public_key().to_vec(),
                deadline_unix_ms: unix_now()? * 1_000 + 25_000,
            };
            let broker = Arc::clone(broker);
            let sent = request.clone();
            logins.push((
                recipient,
                request,
                spawn(async move { broker.codex_login(sent).await }),
            ));
        }
        let mut proxied = Vec::new();
        for broker in [&first, &second] {
            let broker = Arc::clone(broker);
            proxied.push(spawn(async move {
                let response = broker.execute(proxied_request()).await?;
                let (status, _, mut body) = response.into_parts();
                while let Some(chunk) = futures::StreamExt::next(&mut body).await {
                    chunk?;
                }
                Ok::<_, crate::BrokerRequestError>(status)
            }));
        }
        for (recipient, request, task) in logins {
            let sealed = finish_task(task).await??;
            let opened = recipient.open_codex_login(
                &sealed,
                &CodexLoginContext {
                    environment_id: *Uuid::parse_str(f.context.environment_id.as_str())?.as_bytes(),
                    environment_generation: f.context.environment_generation,
                    request_id: *Uuid::parse_str(&request.request_id)?.as_bytes(),
                    deadline_unix_ms: request.deadline_unix_ms,
                },
                unix_now()? * 1_000,
            )?;
            ensure!(opened.login.access_token() == rotated);
            ensure!(opened.login.account_id() == "synthetic-account");
            ensure!(opened.binding.credential_id == f.record.metadata.id.as_str());
            ensure!(opened.binding.material_generation == 2);
            ensure!(opened.binding.revocation_generation == 2);
        }
        for task in proxied {
            ensure!(finish_task(task).await?? == StatusCode::OK);
        }
        ensure!(provider.exchanges.load(Ordering::SeqCst) == 1);
        ensure!(provider.responses.load(Ordering::SeqCst) == 2);
        ensure!(f.state().await? == OAuthRefreshState::Committed);
        // The rotated refresh token stays in the store; no login carries it.
        let current = lease(&f.adapter).await?;
        current.with_material(|bytes| {
            ensure!(
                crate::codex_oauth::CodexOAuthCredential::parse(bytes)?.refresh_token()
                    == "synthetic-refresh-rotated"
            );
            Ok(())
        })?;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_login_selected_by_a_new_profile_revision_is_rechecked_after_refresh() -> Result<()> {
    // The refresh path re-leases through the login predicate: a selection
    // replaced by an API key while the refresh runs is never delivered.
    let f = Fixture::create_for_bridge().await?;
    let result = async {
        let rotated = token(serde_json::json!({"exp": unix_now()? + 7_200}));
        let provider = Provider {
            exchanges: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(AtomicUsize::new(0)),
            rotated,
        };
        let broker = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let recipient = ProjectionRecipient::new();
        let request = codewire_gateway_proto::codewire::bridge::v1::CodexLoginRequest {
            request_id: Uuid::new_v4().to_string(),
            recipient_public_key: recipient.public_key().to_vec(),
            deadline_unix_ms: unix_now()? * 1_000 + 25_000,
        };
        let task = spawn({
            let broker = Arc::clone(&broker);
            async move { broker.codex_login(request).await }
        });
        tokio::time::timeout(TIMEOUT, async {
            while provider.exchanges.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let key = f
            .store
            .create(
                &f.owner,
                registration("Codex key", CredentialAuthKind::ApiKey),
                &value(b"sk-synthetic-codex-login-api-key-never-delivered"),
            )
            .await?;
        select(
            &f,
            BTreeMap::from([(CapabilitySlot::codex(), key.metadata.id)]),
        )
        .await?;
        ensure!(matches!(
            finish_task(task).await?,
            Err(crate::BrokerRequestError::Denied)
        ));
        // The rotation itself completed and stays usable for its own grant.
        ensure!(provider.exchanges.load(Ordering::SeqCst) == 1);
        ensure!(f.state().await? == OAuthRefreshState::Committed);
        Ok(())
    }
    .await;
    f.finish(result).await
}
