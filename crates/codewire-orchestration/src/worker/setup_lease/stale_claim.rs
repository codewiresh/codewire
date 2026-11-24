//! The running path's release of a `claimed` setup owner another activity
//! left behind (#6251). The rule and why it is safe are in
//! `docs/dev/ORCHESTRATION-FENCING.md`, "A claimed owner left behind".

use std::sync::OnceLock;

use prometheus::{IntCounter, register_int_counter};

use super::{
    SetupActivityIdentity, SetupLeaseRecord, SetupLeaseStatus, SetupPhaseAuthority, clear_owner,
};
use crate::worker::activity_authority::ActivityAuthority;

static RELEASES: OnceLock<IntCounter> = OnceLock::new();

fn releases_metric() -> &'static IntCounter {
    RELEASES.get_or_init(|| {
        register_int_counter!(
            "codewire_setup_claimed_owner_releases_total",
            "Claimed setup owners another activity left behind, released on the running path."
        )
        .expect("claimed setup owner release metric registration must be unique")
    })
}

/// Release the `claimed` setup owner another activity left on a running,
/// set-up Sandbox, for the activity `identity` holding `authority`. The
/// caller is on the running path: it found the Sandbox `running` with intent
/// `started`.
pub(crate) async fn release_stale_claimed_owner(
    authority: &ActivityAuthority,
    identity: SetupActivityIdentity,
) -> anyhow::Result<()> {
    SetupPhaseAuthority::new(authority.clone(), identity)?
        .release_stale_claimed_owner()
        .await
        .map(drop)
}

impl SetupPhaseAuthority {
    /// One transaction under the setup lock order: `lock_current` requires
    /// this activity's run, generation and the running, started Sandbox, and
    /// the owner is read under those locks and cleared by its exact tuple.
    /// Returns the owner it released.
    pub(crate) async fn release_stale_claimed_owner(
        &self,
    ) -> anyhow::Result<Option<SetupLeaseRecord>> {
        let mut tx = self.pool.begin().await?;
        let row = self.lock_current(&mut tx).await?;
        let Some(owner) = row.owner()?.filter(|owner| {
            row.setup_complete
                && owner.status == SetupLeaseStatus::Claimed
                && owner.identity != self.identity
        }) else {
            tx.commit().await?;
            return Ok(None);
        };
        clear_owner(&mut tx, &self.environment_id, &owner).await?;
        tx.commit().await?;
        releases_metric().inc();
        tracing::warn!(
            environment_id = self.environment_id,
            owner_generation = owner.identity.generation,
            owner_activity_id = owner.identity.activity_id,
            owner_attempt = owner.identity.attempt,
            owner_phase = owner.phase,
            activity_generation = self.identity.generation,
            activity_id = self.identity.activity_id,
            activity_attempt = self.identity.attempt,
            "setup lease: released a claimed owner another activity left behind"
        );
        Ok(Some(owner))
    }
}

#[cfg(test)]
#[path = "stale_claim_tests.rs"]
mod tests;
