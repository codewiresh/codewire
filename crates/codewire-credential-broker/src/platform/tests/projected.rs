//! The placeholders an intercepted hosted epoch's Sandbox projects (#4001):
//! the `anthropic` slot's when the binding grants it, derived exactly as the
//! epoch's leases derive theirs, the same for every epoch of one binding,
//! and never part of a set: a key that can't be read refuses the
//! projection, and a service that derives no placeholders projects none.

use codewire_access::CredentialPlaceholder;

use super::placeholders::{key_rows, placeholder_epoch};
use super::subscription::{bind_token, lease_anthropic};
use super::*;

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_intercepted_epoch_projects_the_granted_anthropic_placeholder_and_renewals_the_same()
-> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        bind_token(&fixture).await?;
        let epoch = placeholder_epoch(fixture.epoch().await?);
        let projected = epoch.projected_placeholders().await?;
        let lease = lease_anthropic(&epoch).await?;
        let grant = lease.grant().clone();
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
        anyhow::ensure!(
            projected
                .anthropic()
                .is_some_and(|placeholder| placeholder.ct_eq(&expected)),
            "the Open's placeholder is the grant's"
        );
        anyhow::ensure!(
            BrokerCredentialLease::placeholder(&lease)
                .is_some_and(|placeholder| placeholder.ct_eq(&expected)),
            "the epoch's leases swap the placeholder it projects"
        );
        // A renewal of the same binding is another epoch: its own cache, the
        // same inputs, so the same set. No epoch is a derivation input.
        let renewed = placeholder_epoch(fixture.epoch().await?)
            .projected_placeholders()
            .await?;
        anyhow::ensure!(renewed.ct_eq(&projected), "a renewal projects the same set");
        anyhow::ensure!(key_rows(&fixture.pool).await? == 1);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_binding_without_the_anthropic_slot_projects_none_and_reads_no_key() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        // The fixture's binding grants only the Codex slot, whose
        // placeholder travels in its delivered login.
        let projected = placeholder_epoch(fixture.epoch().await?)
            .projected_placeholders()
            .await?;
        anyhow::ensure!(projected.is_empty());
        anyhow::ensure!(
            key_rows(&fixture.pool).await? == 0,
            "a key was read or created for nothing"
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_unreadable_key_refuses_the_projection_and_placeholders_off_project_none() -> Result<()>
{
    let fixture = Fixture::create().await?;
    let result = async {
        bind_token(&fixture).await?;
        let off = fixture.epoch().await?;
        anyhow::ensure!(off.projected_placeholders().await?.is_empty());
        anyhow::ensure!(key_rows(&fixture.pool).await? == 0);
        placeholder_epoch(fixture.epoch().await?)
            .projected_placeholders()
            .await?;
        // The broker's role can't change a key; the schema owner can.
        sqlx::query(
            "UPDATE platform_placeholder_keys SET ciphertext=decode(repeat('00',48),'hex')",
        )
        .execute(&fixture.db.pool)
        .await?;
        anyhow::ensure!(matches!(
            placeholder_epoch(fixture.epoch().await?)
                .projected_placeholders()
                .await,
            Err(BrokerLeaseError::Unavailable)
        ));
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
