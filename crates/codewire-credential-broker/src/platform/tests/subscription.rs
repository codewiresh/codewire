//! A Claude subscription token the provider refused, against real restricted
//! PostgreSQL and the platform lease provider's own two-check admission. The
//! token has no refresh: only its exact admitted generation is marked as
//! needing a new token, and only its own capability is withheld.

use codewire_platform_credentials::CredentialRegistration;

use super::*;

const TOKEN: &[u8] = b"sk-ant-oat01-synthetic-platform-subscription-token";

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

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_refused_subscription_token_is_marked_only_at_its_exact_admitted_generation() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
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
        let manager =
            PlatformAccessProfileStore::new(f.db.pool.clone(), builtin_provider_catalog());
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

        // A hosted epoch admitted after the binding, as the Sandbox's bridge
        // admits one: its first authority decision grants the Anthropic slot.
        let adapter = f.epoch().await?;
        let admitted = lease_anthropic(&adapter).await?;
        ensure!(admitted.credential_metadata().authentication_kind == CredentialAuthKind::OAuth);
        let rejection = BrokerCredentialRejection {
            request_id: Uuid::new_v4(),
            grant: admitted.grant().clone(),
            operation: admitted.permission().operation.clone(),
            route: admitted.permission().route.clone(),
            material_generation: admitted.material_generation(),
        };
        admitted.with_material(|bytes| {
            ensure!(bytes == TOKEN);
            Ok(())
        })?;

        // Another generation, slot or route is refused and marks nothing.
        let mut stale = rejection.clone();
        stale.material_generation += 1;
        ensure!(adapter.reject_credential(stale).await == Err(BrokerRefreshError::Stale));
        let mut codex = rejection.clone();
        codex.grant.capability_slot = CapabilitySlot::codex();
        ensure!(adapter.reject_credential(codex).await == Err(BrokerRefreshError::Denied));
        let mut nil = rejection.clone();
        nil.request_id = Uuid::nil();
        ensure!(adapter.reject_credential(nil).await == Err(BrokerRefreshError::InvalidRequest));
        ensure!(
            f.store
                .record(&f.owner, &token.metadata.id)
                .await?
                .metadata
                .status
                == CredentialStatus::Active
        );
        // The Codex refresh path never accepts a subscription token.
        let mut refresh = request(&adapter).await?;
        refresh.grant = rejection.grant.clone();
        refresh.operation = rejection.operation.clone();
        refresh.route = rejection.route.clone();
        refresh.material_generation = rejection.material_generation;
        ensure!(
            adapter.begin_credential_refresh(refresh).await.err()
                == Some(BrokerRefreshError::Denied)
        );

        adapter.reject_credential(rejection.clone()).await?;
        let rejected = f.store.record(&f.owner, &token.metadata.id).await?;
        ensure!(rejected.metadata.status == CredentialStatus::RefreshFailed);
        ensure!(rejected.version.revocation_generation == token.version.revocation_generation + 1);
        // Only the Anthropic capability is withheld, with Reconnect; Codex is
        // unaffected, and repeating the rejection finds no grant to mark.
        ensure!(lease_anthropic(&adapter).await.err() == Some(BrokerLeaseError::ReconnectRequired));
        lease(&adapter).await?;
        ensure!(adapter.reject_credential(rejection).await == Err(BrokerRefreshError::Denied));
        Ok(())
    }
    .await;
    f.finish(result).await
}
