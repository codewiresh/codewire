//! The delivery predicate of a listed direct delivery exception, the
//! environment creator's personal Codex login for a hosted Sandbox or the
//! creator's own local VM, against real restricted
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
    let manager = profiles(f.db.pool.clone(), builtin_provider_catalog());
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
        profiles(f.pool.clone(), catalog),
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

/// The Codex login a local VM's owner-local delegation leases: its profile
/// owner resolved to `owner`, the creator's personal consent `confirmed` or
/// not, and the fixture's profile selected when `profile`. The delegation
/// grants the fixture's login in the Codex slot.
async fn owner_local_login(
    f: &Fixture,
    owner: Owner,
    confirmed: bool,
    profile: bool,
) -> Result<Result<PlatformCredentialLease, BrokerLeaseError>> {
    owner_local_login_of(f, &f.record, owner, confirmed, profile).await
}

/// [`owner_local_login`] with the delegation granting `record` in the Codex
/// slot, whatever its kind or state, so the broker's own checks refuse it.
async fn owner_local_login_of(
    f: &Fixture,
    record: &CredentialRecord,
    owner: Owner,
    confirmed: bool,
    profile: bool,
) -> Result<Result<PlatformCredentialLease, BrokerLeaseError>> {
    let binding = if profile {
        Some(f.current_binding().await?)
    } else {
        None
    };
    Ok(
        match f
            .owner_local(
                owner,
                confirmed,
                binding,
                CapabilitySlot::codex(),
                record,
                codex_login_permission(),
            )
            .await?
        {
            Ok(adapter) => login(&adapter).await,
            Err(error) => Err(error),
        },
    )
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
        "owner-local delegation",
        "owner-local delegation without a profile",
        "owner-local organization profile",
        "owner-local profile not confirmed by the creator",
        "owner-local delegation, another user's credential",
        "owner-local delegation granting an api key",
        "owner-local delegation granting a revoked login",
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
                // A local VM's delegation by the creator, with the creator's
                // own personal profile, gets the same login (owner decision,
                // 2026-10-15), and still only through the dedicated path.
                "owner-local delegation" => {
                    let lease = owner_local_login(&f, f.owner.clone(), true, true).await??;
                    ensure!(lease.permission() == &codex_login_permission());
                    ensure!(lease.credential_metadata().id == f.record.metadata.id);
                    ensure!(lease.grant().capability_slot == CapabilitySlot::codex());
                    let adapter = f
                        .owner_local(
                            f.owner.clone(),
                            true,
                            Some(f.current_binding().await?),
                            CapabilitySlot::codex(),
                            &f.record,
                            codex_login_permission(),
                        )
                        .await??;
                    let permission = codex_login_permission();
                    ensure!(matches!(
                        adapter
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
                // A delegation without a profile leases no provider credential.
                "owner-local delegation without a profile" => {
                    owner_local_login(&f, f.owner.clone(), true, false).await?
                }
                // A delegation whose profile is an organization's: never the
                // creator's own login.
                "owner-local organization profile" => {
                    owner_local_login(
                        &f,
                        Owner::Organization(OwnerId::parse("synthetic-org")?),
                        true,
                        true,
                    )
                    .await?
                }
                "owner-local profile not confirmed by the creator" => {
                    owner_local_login(&f, f.owner.clone(), false, true).await?
                }
                "owner-local delegation, another user's credential" => {
                    f.db.user("synthetic-other-user").await?;
                    sqlx::query("UPDATE platform_credentials SET user_id=$2 WHERE id=$1")
                        .bind(f.record.metadata.id.as_str())
                        .bind("synthetic-other-user")
                        .execute(&f.db.pool)
                        .await?;
                    owner_local_login(&f, f.owner.clone(), true, true).await?
                }
                // Even a delegation authority that granted it: the broker
                // never delivers an API key or a revoked login.
                "owner-local delegation granting an api key" => {
                    let key = f
                        .store
                        .create(
                            &f.owner,
                            registration("Codex key", CredentialAuthKind::ApiKey),
                            &value(b"sk-synthetic-owner-local-api-key-never-delivered"),
                        )
                        .await?;
                    owner_local_login_of(&f, &key, f.owner.clone(), true, true).await?
                }
                "owner-local delegation granting a revoked login" => {
                    f.store
                        .revoke(&f.owner, &f.record.metadata.id, f.record.version)
                        .await?;
                    owner_local_login(&f, f.owner.clone(), true, true).await?
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
/// pauses so that every concurrent caller reaches the serialized path; with
/// `held`, it answers only once the test adds a permit.
#[derive(Clone)]
struct Provider {
    exchanges: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
    rotated: String,
    held: Option<Arc<tokio::sync::Semaphore>>,
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
                match &self.held {
                    Some(held) => drop(held.acquire().await),
                    None => tokio::time::sleep(Duration::from_millis(300)).await,
                }
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

fn proxied_request() -> codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeRequest {
    codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeRequest {
        capability_slot: "codex".into(),
        route: "openai-api".into(),
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: "/responses".into(),
        query: String::new(),
        headers: vec![
            codewire_daemon_proto::codewire::bridge::v1::CredentialHttpHeader {
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
            held: None,
        };
        // Two epochs of the same Sandbox: separate in-process mutexes, one
        // durable refresh journal.
        let first = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let second = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let mut logins = Vec::new();
        for broker in [&first, &first, &first, &second, &second] {
            let recipient = ProjectionRecipient::new();
            let request = codewire_daemon_proto::codewire::bridge::v1::CodexLoginRequest {
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

/// A lease of one epoch whose two record reads straddle another epoch's
/// refresh commit: the record it read first has moved to the next revocation
/// generation by its second read. The lease evaluates again once, as the
/// fresh lease it would have been, and delivers the rotated login or sends the
/// rotated token; it never releases the replaced one (main run 19775).
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_lease_straddling_another_epochs_refresh_commit_evaluates_again() -> Result<()> {
    for case in ["codex login", "proxied request"] {
        let f = Fixture::create_for_bridge().await?;
        let result = async {
            let rotated = token(serde_json::json!({"exp": unix_now()? + 7_200}));
            let provider = Provider {
                exchanges: Arc::new(AtomicUsize::new(0)),
                responses: Arc::new(AtomicUsize::new(0)),
                rotated: rotated.clone(),
                held: None,
            };
            let first = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
            let second = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
            let login_request = || -> Result<_> {
                let recipient = ProjectionRecipient::new();
                let request = codewire_daemon_proto::codewire::bridge::v1::CodexLoginRequest {
                    request_id: Uuid::new_v4().to_string(),
                    recipient_public_key: recipient.public_key().to_vec(),
                    deadline_unix_ms: unix_now()? * 1_000 + 25_000,
                };
                Ok((recipient, request))
            };
            let open =
                |recipient: ProjectionRecipient,
                 request: &codewire_daemon_proto::codewire::bridge::v1::CodexLoginRequest,
                 sealed: &[u8]|
                 -> Result<_> {
                    Ok(recipient.open_codex_login(
                        sealed,
                        &CodexLoginContext {
                            environment_id: *Uuid::parse_str(f.context.environment_id.as_str())?
                                .as_bytes(),
                            environment_generation: f.context.environment_generation,
                            request_id: *Uuid::parse_str(&request.request_id)?.as_bytes(),
                            deadline_unix_ms: request.deadline_unix_ms,
                        },
                        unix_now()? * 1_000,
                    )?)
                };
            // The second epoch's first lease stops between its two record
            // reads, holding the record and material of generation 1.
            let gate = Arc::new(SessionGate::default());
            gate.arm(1);
            let (straddling, login) = match case {
                "codex login" => {
                    let (recipient, request) = login_request()?;
                    let broker = Arc::clone(&second);
                    let sent = request.clone();
                    let task = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), async move {
                        Ok::<_, anyhow::Error>(Some(broker.codex_login(sent).await?))
                    }));
                    (task, Some((recipient, request)))
                }
                _ => {
                    let broker = Arc::clone(&second);
                    let task = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), async move {
                        let response = broker.execute(proxied_request()).await?;
                        let (status, _, mut body) = response.into_parts();
                        while let Some(chunk) = futures::StreamExt::next(&mut body).await {
                            chunk?;
                        }
                        ensure!(status == StatusCode::OK);
                        Ok::<Option<Vec<u8>>, anyhow::Error>(None)
                    }));
                    (task, None)
                }
            };
            gate.wait().await?;
            // The first epoch refreshes and commits generation 2 meanwhile.
            let (recipient, request) = login_request()?;
            let sealed = {
                let broker = Arc::clone(&first);
                let sent = request.clone();
                finish_task(spawn(async move { broker.codex_login(sent).await })).await??
            };
            ensure!(open(recipient, &request, &sealed)?.login.access_token() == rotated);
            let committed = f.store.record(&f.owner, &f.record.metadata.id).await?;
            ensure!(committed.version.revocation_generation == 2);
            ensure!(committed.version.material_generation == 2);
            gate.release();
            let straddled = finish_task(straddling).await?;
            let straddled = match straddled {
                Ok(sealed) => sealed,
                Err(error) => anyhow::bail!("{case} straddling the refresh commit: {error}"),
            };
            if let (Some(sealed), Some((recipient, request))) = (straddled, login) {
                let opened = open(recipient, &request, &sealed)?;
                ensure!(opened.login.access_token() == rotated);
                ensure!(opened.binding.revocation_generation == 2);
                ensure!(opened.binding.material_generation == 2);
            } else {
                // The provider answers only the rotated token.
                ensure!(provider.responses.load(Ordering::SeqCst) == 1);
            }
            ensure!(provider.exchanges.load(Ordering::SeqCst) == 1);
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_login_selected_by_a_new_profile_revision_is_rechecked_after_refresh() -> Result<()> {
    // The refresh path re-leases through the login predicate: a selection
    // replaced by an API key while the refresh runs is never delivered.
    let f = Fixture::create_for_bridge().await?;
    let result = async {
        let rotated = token(serde_json::json!({"exp": unix_now()? + 7_200}));
        // The refresh waits for this test's selection, so the selection is
        // made while it runs however slowly the database answers.
        let held = Arc::new(tokio::sync::Semaphore::new(0));
        let provider = Provider {
            exchanges: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(AtomicUsize::new(0)),
            rotated,
            held: Some(held.clone()),
        };
        let broker = Arc::new(OpenAiBroker::new(f.second().await?.1, provider.clone())?);
        let recipient = ProjectionRecipient::new();
        let request = codewire_daemon_proto::codewire::bridge::v1::CodexLoginRequest {
            request_id: Uuid::new_v4().to_string(),
            recipient_public_key: recipient.public_key().to_vec(),
            deadline_unix_ms: unix_now()? * 1_000
                + codewire_workload_secrets::MAX_CODEX_LOGIN_LIFETIME_MS,
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
        held.add_permits(1);
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
