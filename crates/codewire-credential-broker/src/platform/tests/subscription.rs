//! A Claude subscription token at the platform lease provider, against real
//! restricted PostgreSQL. A provider answer never changes the stored token:
//! only its owner replaces it, and a replacement fences an in-flight lease.

use bytes::Bytes;
use codewire_daemon_proto::codewire::bridge::v1::{CredentialBridgeRequest, CredentialHttpHeader};
use codewire_platform_credentials::CredentialRegistration;
use http::{HeaderMap, HeaderValue, StatusCode, header};

use super::*;
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    OpenAiBroker,
};

const TOKEN: &[u8] = b"sk-ant-oat01-synthetic-platform-subscription-token";
const REPLACEMENT: &[u8] = b"sk-ant-oat01-synthetic-platform-replacement-token";

fn messages() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse("messages").unwrap(),
        route: BrokerRouteId::parse("anthropic-api").unwrap(),
    }
}

async fn lease_anthropic(adapter: &Adapter) -> Result<PlatformCredentialLease, BrokerLeaseError> {
    let permission = messages();
    adapter
        .lease_operation(
            Uuid::new_v4(),
            CapabilitySlot::anthropic(),
            permission.operation,
            permission.route,
        )
        .await
}

fn material(lease: PlatformCredentialLease) -> Vec<u8> {
    lease.with_material(<[u8]>::to_vec)
}

/// Store a personal subscription token and bind the fixture environment to a
/// new profile revision that selects it in the Anthropic slot.
async fn bind_token(f: &Fixture) -> Result<CredentialRecord> {
    let token = f
        .store
        .create(
            &f.owner,
            CredentialRegistration {
                provider: codewire_access::ProviderId::parse("anthropic")?,
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "Claude".into(),
                account_hint: None,
                expires_at_unix: Some(unix_now()? + 365 * 24 * 60 * 60),
            },
            &value(TOKEN),
        )
        .await?;
    let mut context = f.context.clone();
    context
        .authorized_credentials
        .insert(token.metadata.id.clone());
    f.authority
        .change(|session| session.context = context.clone());
    let manager = PlatformAccessProfileStore::new(f.db.pool.clone(), builtin_provider_catalog());
    let mut entries = f.profile.entries.clone();
    entries.insert(CapabilitySlot::anthropic(), token.metadata.id.clone());
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
    Ok(token)
}

/// The provider refuses every token with its authentication error.
#[derive(Clone, Default)]
struct RefusingProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerUpstreamTransport for RefusingProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_, target, headers, _) = request.into_parts();
        if target.as_str() != "https://api.anthropic.com/v1/messages?beta=true"
            || headers
                .get(header::AUTHORIZATION)
                .map(HeaderValue::as_bytes)
                != Some([b"Bearer ".as_slice(), TOKEN].concat().as_slice())
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let body = br#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        Ok(BrokerUpstreamResponse::new(
            StatusCode::UNAUTHORIZED,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move {
                Ok(Bytes::from_static(body))
            })),
        ))
    }
}

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
        query: "beta=true".into(),
        headers: vec![
            header("content-type", "application/json"),
            header("anthropic-version", "2023-06-01"),
            header("authorization", "Bearer codewire-managed"),
            header("anthropic-beta", "claude-code-20250219,oauth-2025-04-20"),
        ],
        body: br#"{"model":"synthetic","max_tokens":1,"messages":[]}"#.to_vec(),
    }
}

/// A hosted bridge epoch admitted after the binding, as the Sandbox's bridge
/// admits one, owned so a broker can hold it. Its leases are the normal
/// hosted leases, served from the epoch's authority decision.
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

/// The owner's replacement of `token` with `material`, as the credential
/// service publishes one.
async fn replace_token(
    f: &Fixture,
    token: &CredentialRecord,
    material: &[u8],
) -> Result<CredentialRecord> {
    let prepared = f
        .store
        .prepare_subscription_token_replacement(
            &f.owner,
            token,
            &value(material),
            unix_now()? + 365 * 24 * 60 * 60,
        )
        .await?;
    let mut tx = f.pool.begin().await?;
    let replaced = f
        .store
        .replace_prepared_in(&mut tx, &f.owner, prepared)
        .await?;
    tx.commit().await?;
    ensure!(replaced.version.revocation_generation == token.version.revocation_generation + 1);
    Ok(replaced)
}

/// A Sandbox process shapes the request, so the provider's answer never
/// decides the token's fate: a 401 `authentication_error` reaches the client
/// unchanged and the credential stays Active with the same material.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_provider_401_leaves_the_subscription_token_active_with_its_material() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let token = bind_token(&f).await?;
        let provider = RefusingProvider::default();
        let (pool, adapter) = hosted(&f).await?;
        let broker = OpenAiBroker::new(adapter, provider.clone())?;
        for _ in 0..2 {
            let (response, timings) =
                crate::timing::measure(broker.execute(claude_code_request())).await;
            // The normal hosted lease: the epoch's decision admits it.
            ensure!(timings.authority_decision == crate::timing::AuthorityUse::Reused);
            let (status, _, mut body) = response?.into_parts();
            ensure!(status == StatusCode::UNAUTHORIZED);
            let mut bytes = Vec::new();
            while let Some(chunk) = futures::StreamExt::next(&mut body).await {
                bytes.extend(chunk?);
            }
            ensure!(
                serde_json::from_slice::<serde_json::Value>(&bytes)?["error"]["type"]
                    == "authentication_error"
            );
        }
        // Each request reached the provider once; nothing was refreshed or
        // replayed, and the second request was not withheld.
        ensure!(provider.calls.load(Ordering::SeqCst) == 2);
        let stored = f.store.record(&f.owner, &token.metadata.id).await?;
        ensure!(stored == token);
        ensure!(stored.metadata.status == CredentialStatus::Active);
        ensure!(
            f.store
                .read_for_broker(&f.owner, &token.metadata.id, token.version)
                .await?
                .expose_secret()
                == TOKEN
        );
        let epoch = f.epoch().await?;
        ensure!(material(lease_anthropic(&epoch).await?) == TOKEN);
        drop(broker);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// The owner replaces the token while a request's lease is in flight. No lease
/// ever releases the replaced token, and the next request presents the new
/// one. A hosted epoch's lease reread its record before the replacement, so
/// the material fence fails the stale version and the lease is admitted again
/// for the replacement. A lease with full per-request checks finds the record
/// moved at its second record read and evaluates again once, for the
/// replacement (owner, 2026-10-24).
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_replacement_racing_an_in_flight_request_never_releases_the_replaced_token() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        let token = bind_token(&f).await?;
        let epoch = f.epoch().await?;
        ensure!(material(lease_anthropic(&epoch).await?) == TOKEN);

        // The normal hosted lease, from a new epoch's decision. Its cache is
        // empty, so the lease reads the token and waits at its unwrap.
        let hosted = f.epoch().await?;
        let calls = f.authority.calls();
        f.provider.unwrap_gate.arm();
        let operation = spawn({
            let adapter = hosted.clone();
            async move { crate::timing::measure(lease_anthropic(&adapter)).await }
        });
        f.provider.unwrap_gate.wait().await?;
        let replaced = replace_token(&f, &token, REPLACEMENT).await?;
        f.provider.unwrap_gate.release();
        let (leased, timings) = finish_task(operation).await?;
        let leased = leased.map_err(|error| anyhow::anyhow!("hosted lease: {error:?}"))?;
        ensure!(
            leased.grant().credential_revocation_generation
                == replaced.version.revocation_generation
        );
        ensure!(material(leased) == REPLACEMENT);
        // One more evaluation and a second read, for the replacement.
        ensure!(timings.authority_decision == crate::timing::AuthorityUse::Evaluated);
        ensure!(timings.material_read.count == 2);
        ensure!(f.authority.calls() == calls + 1);
        ensure!(material(lease_anthropic(&hosted).await?) == REPLACEMENT);

        // Full per-request checks, outside any hosted epoch: the replacement
        // lands between the lease's two record reads. The lease evaluates
        // again and releases the replacement, never the replaced token.
        {
            let (pool, checked) = f.second().await?;
            let checked = Arc::new(checked);
            let gate = Arc::new(SessionGate::default());
            gate.arm(1);
            let operation = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), {
                let adapter = checked.clone();
                async move { lease_anthropic(&adapter).await.map(material) }
            }));
            gate.wait().await?;
            let again = replace_token(&f, &replaced, TOKEN).await?;
            gate.release();
            let leased = finish_task(operation)
                .await?
                .map_err(|error| anyhow::anyhow!("checked lease: {error:?}"))?;
            ensure!(
                leased != REPLACEMENT,
                "the in-flight lease released the replaced token"
            );
            ensure!(leased == TOKEN);
            let next = lease_anthropic(&checked).await?;
            ensure!(
                next.grant().credential_revocation_generation
                    == again.version.revocation_generation
            );
            ensure!(material(next) == TOKEN);
            drop(checked);
            pool.close().await;
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}
