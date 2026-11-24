//! A hosted epoch's leases carry their environment's placeholder only when
//! the bridge turns hosted placeholders on (#4001), derived under the
//! environment's one stored key; with it off they carry none and no key is
//! created.

use codewire_access::CredentialPlaceholder;

use super::*;
use crate::timing::{self, PlaceholderUse};

pub(super) async fn key_rows(pool: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM platform_placeholder_keys")
            .fetch_one(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_hosted_lease_carries_its_environments_placeholder_only_when_turned_on() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let off = fixture.epoch().await?;
        let unmarked = lease(&off).await?;
        anyhow::ensure!(BrokerCredentialLease::placeholder(&unmarked).is_none());
        drop(unmarked);
        anyhow::ensure!(
            key_rows(&fixture.pool).await? == 0,
            "a key was created while off"
        );

        let on = Adapter {
            placeholders: Some(EpochPlaceholders::default()),
            ..Arc::into_inner(fixture.epoch().await?).expect("one owner")
        };
        let first = lease(&on).await?;
        let second = lease(&on).await?;
        let grant = first.grant().clone();
        let key = fixture
            .store
            .environment_placeholder_key(&grant.environment_id)
            .await?;
        let expected = CredentialPlaceholder::derive(
            &key,
            &grant.environment_id,
            grant.profile.as_ref().map_or(0, |profile| profile.revision),
            &grant.capability_slot,
            &grant.credential_id,
        );
        for leased in [&first, &second] {
            anyhow::ensure!(
                BrokerCredentialLease::placeholder(leased)
                    .is_some_and(|value| value.ct_eq(&expected))
            );
        }
        anyhow::ensure!(
            key_rows(&fixture.pool).await? == 1,
            "one key per environment"
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

pub(super) fn placeholder_epoch(adapter: Arc<Adapter>) -> Adapter {
    Adapter {
        placeholders: Some(EpochPlaceholders::default()),
        ..Arc::into_inner(adapter).expect("one owner")
    }
}

// An epoch derives each placeholder once and keeps it, never the key: later
// leases read no key. A key that no longer opens leaves a new epoch's lease
// without a placeholder, and its request's timing line names one closed
// reason, never the row or the provider's error (#4001).
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_epoch_derives_each_placeholder_once_and_names_a_key_that_fails() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let epoch = placeholder_epoch(fixture.epoch().await?);
        let (first, timings) = timing::measure(lease(&epoch)).await;
        let first = first?;
        anyhow::ensure!(timings.placeholder == PlaceholderUse::Derived);
        // The broker's role can't delete or change a key; the schema owner can.
        sqlx::query("DELETE FROM platform_placeholder_keys")
            .execute(&fixture.db.pool)
            .await?;
        let (second, timings) = timing::measure(lease(&epoch)).await;
        let second = second?;
        anyhow::ensure!(timings.placeholder == PlaceholderUse::Reused);
        anyhow::ensure!(
            key_rows(&fixture.pool).await? == 0,
            "a reused placeholder read or created a key"
        );
        let (Some(first), Some(second)) = (
            BrokerCredentialLease::placeholder(&first),
            BrokerCredentialLease::placeholder(&second),
        ) else {
            anyhow::bail!("both leases carry a placeholder");
        };
        anyhow::ensure!(first.ct_eq(second));

        lease(&placeholder_epoch(fixture.epoch().await?)).await?;
        sqlx::query(
            "UPDATE platform_placeholder_keys SET ciphertext=decode(repeat('00',48),'hex')",
        )
        .execute(&fixture.db.pool)
        .await?;
        let (corrupt, timings) =
            timing::measure(lease(&placeholder_epoch(fixture.epoch().await?))).await;
        anyhow::ensure!(BrokerCredentialLease::placeholder(&corrupt?).is_none());
        anyhow::ensure!(timings.placeholder == PlaceholderUse::CorruptRecord);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

// A hosted lease derives the same placeholder local does from the same grant:
// the shared worked derivation (`codewire_access::known_answer`).
#[test]
fn a_hosted_lease_derives_the_shared_known_answer() {
    use codewire_access::{
        AccessProfileId, EnvironmentId, GrantProfile, PlaceholderKey, known_answer,
    };
    let grant = DerivedGrant {
        environment_id: EnvironmentId::parse(known_answer::ENVIRONMENT).unwrap(),
        // Not the derivation's input: a new generation of the same binding
        // keeps its placeholder (#4812).
        environment_generation: 1,
        profile: Some(GrantProfile {
            id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            revision: known_answer::BINDING_REVISION,
        }),
        capability_slot: CapabilitySlot::parse(known_answer::SLOT).unwrap(),
        credential_id: CredentialId::parse(known_answer::CREDENTIAL).unwrap(),
        credential_revocation_generation: 1,
        expires_at_unix: None,
        permissions: Default::default(),
    };
    let placeholder = super::super::placeholders::hosted_placeholder(
        &PlaceholderKey::from_slice(&known_answer::KEY).unwrap(),
        &grant,
    );
    assert_eq!(placeholder.as_str(), known_answer::PLACEHOLDER);
}

// The epoch's placeholder cache is keyed by exactly the derivation's inputs:
// a rebind to another profile revision derives again within the epoch, and a
// new generation of the same binding reuses (#4001 step C3).
#[test]
fn the_epoch_cache_key_follows_the_binding_revision_not_the_generation() {
    use codewire_access::{AccessProfileId, EnvironmentId, GrantProfile, known_answer};
    let grant = |generation: u64, revision: u64| DerivedGrant {
        environment_id: EnvironmentId::parse(known_answer::ENVIRONMENT).unwrap(),
        environment_generation: generation,
        profile: Some(GrantProfile {
            id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            revision,
        }),
        capability_slot: CapabilitySlot::parse(known_answer::SLOT).unwrap(),
        credential_id: CredentialId::parse(known_answer::CREDENTIAL).unwrap(),
        credential_revocation_generation: 1,
        expires_at_unix: None,
        permissions: Default::default(),
    };
    let inputs = super::super::placeholders::placeholder_inputs;
    assert_eq!(inputs(&grant(1, 5)), inputs(&grant(2, 5)));
    assert_ne!(inputs(&grant(1, 5)), inputs(&grant(1, 6)));
}

async fn local_root_rows(pool: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM platform_local_placeholder_roots")
            .fetch_one(pool)
            .await?,
    )
}

/// #6191: a local VM on a platform profile has no row in `environments`. Its
/// delegation's leases carry a placeholder derived under its owner's local
/// root, for the admitted session's user and environment, and no hosted key
/// is created for it. The two kinds never reach each other's key: the local
/// VM's ID has no hosted key, and a delegation naming a hosted environment's
/// ID derives under its owner's root, not that environment's key.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_owner_local_lease_carries_a_placeholder_from_its_owners_local_root() -> Result<()> {
    let fixture = Fixture::create_for_bridge().await?;
    let result = async {
        let delegated = |environment_id: EnvironmentId| {
            let fixture = &fixture;
            async move {
                let binding = EnvironmentAccessBinding {
                    environment_id: environment_id.clone(),
                    ..fixture.current_binding().await?
                };
                let adapter = fixture
                    .owner_local_in(
                        environment_id,
                        fixture.owner.clone(),
                        true,
                        Some(binding),
                        CapabilitySlot::codex(),
                        &fixture.record,
                        permission(),
                    )
                    .await?
                    .map_err(|error| {
                        anyhow::anyhow!("owner-local delegation refused: {error:?}")
                    })?;
                anyhow::Ok(Adapter {
                    placeholders: Some(EpochPlaceholders::default()),
                    ..adapter
                })
            }
        };
        let derived = |key: &codewire_access::PlaceholderKey,
                       grant: &codewire_access::DerivedGrant| {
            CredentialPlaceholder::derive(
                key,
                &grant.environment_id,
                grant.profile.as_ref().map_or(0, |profile| profile.revision),
                &grant.capability_slot,
                &grant.credential_id,
            )
        };
        let user = fixture.context.user_id.clone();

        // A local VM: an environment ID with no row.
        let local = EnvironmentId::parse(Uuid::new_v4().to_string())?;
        let leased = lease(&delegated(local.clone()).await?).await?;
        let grant = leased.grant().clone();
        anyhow::ensure!(grant.environment_id == local);
        let key = fixture
            .store
            .owner_local_placeholder_key(&user, &local)
            .await?;
        anyhow::ensure!(
            BrokerCredentialLease::placeholder(&leased)
                .is_some_and(|value| value.ct_eq(&derived(&key, &grant))),
            "the lease carries the owner-local placeholder"
        );
        anyhow::ensure!(!leased.placeholder_failed, "the lease is not marked failed");
        anyhow::ensure!(local_root_rows(&fixture.pool).await? == 1);
        anyhow::ensure!(key_rows(&fixture.pool).await? == 0, "no hosted key");
        anyhow::ensure!(matches!(
            fixture.store.environment_placeholder_key(&local).await,
            Err(codewire_platform_credentials::PlatformCredentialError::NotFound)
        ));

        // A delegation naming the hosted environment's ID: its owner's root,
        // never the hosted key.
        let hosted_id = fixture.context.environment_id.clone();
        let named = lease(&delegated(hosted_id.clone()).await?).await?;
        let hosted_key = fixture
            .store
            .environment_placeholder_key(&hosted_id)
            .await?;
        let named_grant = named.grant().clone();
        anyhow::ensure!(
            BrokerCredentialLease::placeholder(&named)
                .is_some_and(|value| !value.ct_eq(&derived(&hosted_key, &named_grant)))
        );
        anyhow::ensure!(
            local_root_rows(&fixture.pool).await? == 1,
            "one root per owner"
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
