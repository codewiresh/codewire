//! One hosted bridge epoch's authority decision: one runtime authority resolve
//! and one grant evaluation, evaluated at admission and reused for at most
//! [`AUTHORITY_DECISION_REUSE`] on the monotonic Tokio clock. An evaluation runs
//! while it holds the epoch's one lock, so concurrent leases wait for it.
//!
//! Every lease of a granted slot rereads its credential's record and evaluates
//! again once when the record is missing, inactive, expired or of another
//! revocation generation than the grant, or the material read fails its
//! version fence. Rotation, Reconnect, revocation and refresh advance that
//! generation and deletion removes the record, so they apply to the very next
//! request. A refused slot is answered from the decision, without an
//! evaluation, unless its credential may have changed: a slot withheld for
//! Reconnect whose credential is usable again, or a GitHub slot whose account
//! connection changed. Other authority changes apply within the reuse window:
//! a lease whose decision aged while it read is admitted again by a young one
//! before it releases anything. A denied evaluation installs nothing and
//! clears the epoch's material cache. Only bridge admission (`admit` in
//! `platform/bridge.rs`) creates an [`EpochDecision`]; it holds no material
//! and ends with its epoch.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{
    AvailableGrants, CapabilitySlot, CredentialId, CredentialMetadata, CredentialStatus,
    DerivedGrant, GrantPermission, Owner,
};
use codewire_platform_credentials::PlatformCredentialError;
use tokio::time::Instant;

use super::{
    Admission, PlatformBrokerLeaseProvider, PlatformCredentialLease, PlatformRuntimeAuthority,
    PlatformRuntimeSession, credential_error, ensure_live, record_matches, select_grant, unix_now,
};
use crate::BrokerLeaseError;
use crate::timing::{self, AuthorityUse, Phase};

/// How long a hosted epoch reuses one authority decision.
pub const AUTHORITY_DECISION_REUSE: Duration = Duration::from_secs(60);

/// One hosted epoch's authority decision. Deliberately not `Clone`, `Debug`
/// or `Default`: only an epoch's admission creates one.
pub(super) struct EpochDecision {
    /// Held across one evaluation (its GitHub connection read, resolve and
    /// grant evaluation), so concurrent leases wait for it; never across a
    /// lease's record or material read or provider I/O.
    current: tokio::sync::Mutex<Option<Arc<Decision>>>,
}

/// One evaluation: metadata only, never material.
struct Decision {
    /// When its runtime authority resolve began.
    evaluated_at: Instant,
    /// The resolved session, its identity expiry attenuated by the epoch's.
    session: PlatformRuntimeSession,
    /// Every slot's derived grant, and each slot withheld for Reconnect with
    /// its credential.
    grants: AvailableGrants,
    /// The account's active GitHub connection, read before the resolve. A
    /// GitHub slot this decision does not grant follows it.
    github: Result<Option<CredentialId>, BrokerLeaseError>,
}

impl Decision {
    fn young(&self) -> bool {
        self.evaluated_at.elapsed() < AUTHORITY_DECISION_REUSE
    }
}

impl EpochDecision {
    // A decision exists only where a hosted epoch is admitted.
    #[allow(clippy::new_without_default)]
    pub(super) fn new() -> Self {
        Self {
            current: tokio::sync::Mutex::new(None),
        }
    }
}

impl<A: PlatformRuntimeAuthority> PlatformBrokerLeaseProvider<A> {
    /// Admission's authority check, after the guest's Ready. A hosted epoch
    /// evaluates its first decision from this same resolve. Only a failed
    /// resolve fails admission: a failed grant evaluation installs nothing,
    /// and the first lease evaluates again.
    pub(super) async fn admit_authority(&self) -> Result<(), BrokerLeaseError> {
        let Some(epoch) = &self.decision else {
            return self.session().await.map(|_| ());
        };
        let mut current = epoch.current.lock().await;
        let evaluated_at = Instant::now();
        let github = self.github_connection().await;
        let session = self.session().await?;
        *current = self
            .decide(evaluated_at, github, session)
            .await
            .ok()
            .map(Arc::new);
        Ok(())
    }

    /// The epoch's decision while it is young, unless `again`; otherwise a
    /// new evaluation, installed for the epoch. A denial installs nothing and
    /// drops every value the epoch retains.
    async fn decision(
        &self,
        epoch: &EpochDecision,
        again: bool,
    ) -> Result<Arc<Decision>, BrokerLeaseError> {
        let mut current = epoch.current.lock().await;
        if let Some(decision) = current
            .as_ref()
            .filter(|decision| !again && decision.young())
        {
            timing::authority(AuthorityUse::Reused);
            return Ok(Arc::clone(decision));
        }
        timing::authority(AuthorityUse::Evaluated);
        let evaluated_at = Instant::now();
        let github = self.github_connection().await;
        let evaluated = match self.session().await {
            Ok(session) => self.decide(evaluated_at, github, session).await,
            Err(error) => Err(error),
        };
        match evaluated {
            Ok(decision) => Ok(Arc::clone(current.insert(Arc::new(decision)))),
            Err(error) => {
                if error == BrokerLeaseError::Denied {
                    *current = None;
                    if let Some(material) = &self.material {
                        material.clear();
                    }
                }
                Err(error)
            }
        }
    }

    async fn decide(
        &self,
        evaluated_at: Instant,
        github: Result<Option<CredentialId>, BrokerLeaseError>,
        session: PlatformRuntimeSession,
    ) -> Result<Decision, BrokerLeaseError> {
        let grants = self.available_grants(&session).await?;
        Ok(Decision {
            evaluated_at,
            session,
            grants,
            github,
        })
    }

    /// The creator's active GitHub connection: one indexed statement.
    async fn github_connection(&self) -> Result<Option<CredentialId>, BrokerLeaseError> {
        let owner = Owner::User(self.session.context.user_id.clone());
        timing::timed(
            Phase::Record,
            self.credentials.active_github_connection(&owner),
        )
        .await
        .map_err(credential_error)
    }

    /// Whether a refusal from `decision` may have changed since it was
    /// evaluated: the slot's withheld credential is usable again or
    /// unreadable, or the GitHub connection that an ungranted GitHub slot
    /// follows changed. Any other refusal stands until the decision ages out.
    async fn refusal_changed(&self, decision: &Decision, slot: &CapabilitySlot) -> bool {
        if decision
            .grants
            .grants
            .iter()
            .any(|grant| &grant.capability_slot == slot)
        {
            return false;
        }
        if let Some(credential) = decision.grants.reconnect_required.get(slot) {
            let owner = &decision.session.credential_owner;
            return match self.read_record(owner, credential).await {
                Ok(record) => usable(&record.metadata),
                Err(_) => true,
            };
        }
        *slot == CapabilitySlot::github()
            && !matches!(
                (self.github_connection().await, &decision.github),
                (Ok(now), Ok(then)) if now == *then
            )
    }

    /// The slot's grant in `decision` and its credential's current record,
    /// refused unless the record is live and of the grant's generation.
    async fn admit_from(
        &self,
        decision: &Decision,
        slot: &CapabilitySlot,
        permission: &GrantPermission,
        credential: &mut Option<CredentialId>,
    ) -> Result<Admission, BrokerLeaseError> {
        let grant = select_grant(&decision.grants, &decision.session, slot, permission)?;
        self.admit_grant(decision, grant, permission, credential)
            .await
    }

    async fn admit_grant(
        &self,
        decision: &Decision,
        grant: DerivedGrant,
        permission: &GrantPermission,
        credential: &mut Option<CredentialId>,
    ) -> Result<Admission, BrokerLeaseError> {
        *credential = Some(grant.credential_id.clone());
        let owner = &decision.session.credential_owner;
        let record = self.read_record(owner, &grant.credential_id).await?;
        if !record_matches(&record, &grant, owner) {
            return Err(BrokerLeaseError::Denied);
        }
        ensure_live(&record.metadata, &grant)?;
        Ok(Admission {
            record,
            grant,
            permission: permission.clone(),
        })
    }

    /// One lease from this hosted epoch's decision. A lease that fails drops
    /// its credential's value.
    pub(super) async fn lease_decided(
        &self,
        epoch: &EpochDecision,
        slot: &CapabilitySlot,
        permission: &GrantPermission,
    ) -> Result<PlatformCredentialLease, BrokerLeaseError> {
        let mut credential = None;
        let leased = self
            .lease_from(epoch, slot, permission, &mut credential)
            .await;
        if leased.is_err()
            && let Some(credential) = &credential
        {
            self.forget_material(credential);
        }
        leased
    }

    async fn lease_from(
        &self,
        epoch: &EpochDecision,
        slot: &CapabilitySlot,
        permission: &GrantPermission,
        credential: &mut Option<CredentialId>,
    ) -> Result<PlatformCredentialLease, BrokerLeaseError> {
        // The decision that admits this lease's current admission.
        let mut decided = self.decision(epoch, false).await?;
        let admitted = match select_grant(&decided.grants, &decided.session, slot, permission) {
            Ok(grant) => self
                .admit_grant(&decided, grant, permission, credential)
                .await
                .ok(),
            // A refusal stands, without an evaluation, unless the slot's
            // credential may have changed since.
            Err(refused) => {
                if !self.refusal_changed(&decided, slot).await {
                    return Err(refused);
                }
                None
            }
        };
        // A changed, missing or inactive record, or a refusal that may have
        // changed: evaluate again once, then refuse as a lease always has.
        let mut admission = match admitted {
            Some(admission) => admission,
            None => {
                decided = self.decision(epoch, true).await?;
                self.admit_from(&decided, slot, permission, credential)
                    .await?
            }
        };
        let mut retried = false;
        loop {
            let (cache, reused) = self.reusable(&admission.record, true);
            let read = reused.is_none();
            let material = match reused {
                Some(material) => material,
                None => match self.read_material(&admission.record).await {
                    Ok(material) => material,
                    // The record changed after this lease read it.
                    Err(PlatformCredentialError::StaleVersion) if !retried => {
                        retried = true;
                        decided = self.decision(epoch, true).await?;
                        admission = self
                            .admit_from(&decided, slot, permission, credential)
                            .await?;
                        continue;
                    }
                    Err(error) => return Err(credential_error(error)),
                },
            };
            // A decision that aged while this lease read is replaced first,
            // so nothing is released under a decision older than its window.
            // The value read goes out only for the record the new one admits.
            if !decided.young() {
                decided = self.decision(epoch, false).await?;
                let readmitted = self
                    .admit_from(&decided, slot, permission, credential)
                    .await?;
                if readmitted.record != admission.record {
                    return Err(BrokerLeaseError::Denied);
                }
                admission = readmitted;
            }
            // The final check. Nothing below awaits.
            ensure_live(&admission.record.metadata, &admission.grant)?;
            if let Some(cache) = cache.filter(|_| read) {
                cache.fill(&admission.record, &material);
            }
            return Ok(PlatformCredentialLease {
                record: admission.record,
                grant: admission.grant,
                permission: admission.permission,
                material,
            });
        }
    }
}

/// Whether a withheld credential is usable again: active and unexpired.
fn usable(metadata: &CredentialMetadata) -> bool {
    metadata.status == CredentialStatus::Active
        && unix_now().is_ok_and(|now| metadata.expires_at_unix.is_none_or(|expiry| expiry > now))
}

#[cfg(test)]
mod tests;
