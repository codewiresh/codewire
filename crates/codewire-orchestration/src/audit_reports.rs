//! `SandboxAuditService` on the internal-connect listener (#6189; SPEC.md
//! "Sandbox audit log", "The other sources"): what other platform services
//! report for the audit log.
//!
//! `ReportCredentialUses` accepts only the credential service, by TokenReview
//! of its own token for its own audience in this server's namespace. It files
//! each use under the environment of orchestration's own binding of the
//! reported workspace Pod, never under a name the report gives, and names
//! each credential from its own records of what that binding's owner holds.
//! It drops and counts the uses of a Pod it has no binding for, and of a
//! credential the owner does not hold under the reported provider.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, TimeDelta, Utc};
use codewire_access::{CredentialId, ProviderId};
use codewire_egress_policy::record::Destination;
use codewire_proto::codewire::internal::v1::{
    CredentialUse, ReportCredentialUsesRequest, ReportCredentialUsesResponse, SandboxAuditService,
};
use codewire_server_core::pod_identity::PodIdentityError;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::{self, Actor, Credentials, Event, What};
use crate::runtime::RuntimeAttestation;

/// The most folds one report may carry: the credential service's bound for
/// one binding between two reports, from the one shared value.
pub const MAX_USES_PER_REPORT: usize = codewire_daemon_proto::CREDENTIAL_USES_PER_REPORT;
/// How far a use may be from now. The credential service reports every few
/// seconds and drops what it can't send, so an older or later use is a
/// wrong clock, not a late report.
const MAX_AGE: TimeDelta = TimeDelta::hours(2);
const MAX_AHEAD: TimeDelta = TimeDelta::minutes(10);

pub struct AuditReportState {
    pub attestation: Arc<dyn RuntimeAttestation>,
    /// This server's namespace, which the credential service shares.
    pub server_namespace: String,
    pub pool: PgPool,
    /// Uses dropped because their Pod had no binding.
    pub unbound: AtomicU64,
    /// Uses dropped because their credential is not one the binding's owner
    /// holds, or not under the reported provider.
    pub foreign: AtomicU64,
}

/// The internal app with `SandboxAuditService` mounted when the runtime can
/// review the credential service's token; without one nothing is served.
pub fn mount(
    app: codewire_server_core::http::AppBuilder,
    api: &crate::api::ApiState,
) -> codewire_server_core::http::AppBuilder {
    match api.runtime.clone() {
        Some(runtime) => app.with_connect_routes(router(Arc::new(AuditReportState {
            attestation: runtime,
            server_namespace: api.sandbox_cfg.pod_namespace.clone(),
            pool: api.pool.clone(),
            unbound: AtomicU64::new(0),
            foreign: AtomicU64::new(0),
        }))),
        None => app,
    }
}

pub fn router(state: Arc<AuditReportState>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(AuditReportService { state }))
}

struct AuditReportService {
    state: Arc<AuditReportState>,
}

/// One reported use, parsed. Its credential's name is never the report's:
/// filing reads it from the credentials the binding's owner holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportedUse {
    pub(crate) credential: CredentialId,
    pub(crate) provider: ProviderId,
    /// A checked host; `None` when withheld.
    pub(crate) host: Option<String>,
    pub(crate) first: DateTime<Utc>,
    pub(crate) last: DateTime<Utc>,
    pub(crate) count: u64,
}

/// What filing a report did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filed {
    /// `written` folds were recorded; `foreign` uses were dropped because
    /// their credential is not one the binding's owner holds under the
    /// reported provider.
    Uses { written: usize, foreign: u64 },
    /// The Pod has no binding: nothing was written.
    Unbound,
}

fn invalid_report() -> ConnectError {
    ConnectError::invalid_argument("the credential use report is not well formed")
}

impl AuditReportState {
    /// Only the credential service, in this server's namespace.
    async fn credential_service(&self, ctx: &RequestContext) -> Result<(), ConnectError> {
        self.attestation
            .review_credential_service(ctx.headers(), &self.server_namespace)
            .await
            .map(drop)
            .map_err(|error| match error {
                PodIdentityError::PermissionDenied => {
                    ConnectError::permission_denied("credential use reports are not admitted")
                }
                PodIdentityError::Unavailable => {
                    ConnectError::unavailable("the caller could not be reviewed")
                }
                PodIdentityError::Unauthenticated => {
                    ConnectError::unauthenticated("credential service credential required")
                }
            })
    }
}

#[allow(refining_impl_trait)]
impl SandboxAuditService for AuditReportService {
    async fn report_credential_uses(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportCredentialUsesRequest>,
    ) -> ServiceResult<ReportCredentialUsesResponse> {
        self.state.credential_service(&ctx).await?;
        let request = request.to_owned_message();
        let pod_uid = canonical_pod_uid(&request.pod_uid).ok_or_else(invalid_report)?;
        let uses = parse_uses(&request.uses, Utc::now()).ok_or_else(invalid_report)?;
        let mut tx = self.state.pool.begin().await.map_err(store_unavailable)?;
        let filed = file_uses(&mut tx, &pod_uid, &uses)
            .await
            .map_err(store_unavailable)?;
        tx.commit().await.map_err(store_unavailable)?;
        match filed {
            Filed::Unbound => {
                let dropped = uses.iter().map(|used| used.count).sum::<u64>();
                let total = self.state.unbound.fetch_add(dropped, Ordering::Relaxed) + dropped;
                tracing::info!(
                    dropped,
                    total,
                    "credential uses of a Pod with no binding dropped"
                );
            }
            Filed::Uses { foreign, .. } if foreign > 0 => {
                let total = self.state.foreign.fetch_add(foreign, Ordering::Relaxed) + foreign;
                tracing::warn!(
                    dropped = foreign,
                    total,
                    "credential uses of a credential the Sandbox's owner does not hold dropped"
                );
            }
            Filed::Uses { .. } => {}
        }
        connectrpc::Response::ok(ReportCredentialUsesResponse::default())
    }
}

fn store_unavailable(error: impl std::fmt::Display) -> ConnectError {
    tracing::warn!(%error, "audit reports: storing credential uses failed");
    ConnectError::unavailable("credential uses could not be stored")
}

/// A Pod UID as Kubernetes writes it and the binding stores it.
fn canonical_pod_uid(value: &str) -> Option<String> {
    let uid = Uuid::parse_str(value).ok().filter(|uid| !uid.is_nil())?;
    (uid.to_string() == value).then(|| value.to_owned())
}

/// Every use, or `None` when one is not well formed: an unknown shape, a
/// count of zero, times out of order, in two hours, or far from `now`.
pub(crate) fn parse_uses(uses: &[CredentialUse], now: DateTime<Utc>) -> Option<Vec<ReportedUse>> {
    if uses.is_empty() || uses.len() > MAX_USES_PER_REPORT {
        return None;
    }
    uses.iter().map(|used| parse_use(used, now)).collect()
}

fn parse_use(used: &CredentialUse, now: DateTime<Utc>) -> Option<ReportedUse> {
    let credential = CredentialId::parse(used.credential_id.clone()).ok()?;
    let provider = ProviderId::parse(used.provider.clone()).ok()?;
    let time = |unix_ms: u64| DateTime::from_timestamp_millis(i64::try_from(unix_ms).ok()?);
    let (first, last) = (time(used.first_unix_ms)?, time(used.last_unix_ms)?);
    let hour = |at: DateTime<Utc>| at.timestamp().div_euclid(3600);
    if used.count == 0
        || first > last
        || hour(first) != hour(last)
        || first < now - MAX_AGE
        || last > now + MAX_AHEAD
    {
        return None;
    }
    // A host the check refuses is kept as withheld, never as text, whatever
    // the report said.
    let host = match (used.host_withheld, Destination::checked_name(&used.host)) {
        (false, Destination::Name(name)) if name == used.host => Some(name),
        (true, _) if used.host.is_empty() => None,
        (false, _) => None,
        (true, _) => return None,
    };
    Some(ReportedUse {
        credential,
        provider,
        host,
        first,
        last,
        count: used.count,
    })
}

#[derive(sqlx::FromRow)]
struct Binding {
    environment_id: String,
    org_id: String,
}

/// The environment and organization of `pod_uid`'s binding, released or
/// not: a Pod UID never moves to another environment, and a use reported
/// just after a release happened while it was bound.
const BINDING_QUERY: &str = "SELECT w.environment_id, e.org_id \
     FROM sandbox_workspace_bindings w JOIN environments e ON e.id = w.environment_id \
     WHERE w.pod_uid = $1";

#[derive(sqlx::FromRow)]
pub(crate) struct HeldCredential {
    pub(crate) name: String,
    pub(crate) provider: String,
}

/// The event's fields: the stored provider and name, and the checked host.
pub(crate) fn credential_used(credential: &HeldCredential, used: &ReportedUse) -> Credentials {
    Credentials::Used {
        provider: credential.provider.clone(),
        name: credential.name.clone(),
        host: used.host.clone().unwrap_or_default(),
        withheld: used.host.is_none(),
    }
}

/// The name and provider of credential `$2` when the owner whose credentials
/// environment `$1`'s Sandbox leases holds it: the organization for an
/// organization profile, otherwise the environment's creator, as the
/// credential service's authority decides (`Scope::owner`).
const HELD_CREDENTIAL_QUERY: &str = "SELECT c.display_name AS name, c.provider \
     FROM environments e \
     LEFT JOIN platform_environment_access_bindings b ON b.environment_id = e.id \
     LEFT JOIN platform_access_profiles p ON p.id = b.profile_id \
     JOIN platform_credentials c ON c.id = $2 AND CASE \
       WHEN p.organization_id IS NOT NULL \
         THEN p.organization_id = e.org_id AND c.organization_id = e.org_id \
       ELSE c.user_id = e.created_by END \
     WHERE e.id = $1";

/// Records each use as a `credentials` event of the Sandbox, folded per
/// hour, under the environment of `pod_uid`'s binding, named as the
/// binding's owner holds the credential; nothing when the Pod has none, and
/// nothing for a credential that owner does not hold under the reported
/// provider.
pub(crate) async fn file_uses(
    connection: &mut PgConnection,
    pod_uid: &str,
    uses: &[ReportedUse],
) -> Result<Filed, FileError> {
    let Some(binding) = sqlx::query_as::<_, Binding>(BINDING_QUERY)
        .bind(pod_uid)
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(Filed::Unbound);
    };
    let mut held: HashMap<&CredentialId, Option<HeldCredential>> = HashMap::new();
    let (mut written, mut foreign) = (0, 0_u64);
    for used in uses {
        if !held.contains_key(&used.credential) {
            let found = sqlx::query_as::<_, HeldCredential>(HELD_CREDENTIAL_QUERY)
                .bind(&binding.environment_id)
                .bind(used.credential.as_str())
                .fetch_optional(&mut *connection)
                .await?;
            held.insert(&used.credential, found);
        }
        let Some(credential) = held
            .get(&used.credential)
            .and_then(Option::as_ref)
            .filter(|credential| credential.provider == used.provider.as_str())
        else {
            foreign = foreign.saturating_add(used.count);
            continue;
        };
        audit::record(
            &mut *connection,
            &Event {
                org_id: binding.org_id.clone(),
                environment_id: binding.environment_id.clone(),
                actor: Actor::Sandbox,
                client_ip: None,
                first: used.first,
                last: used.last,
                count: used.count,
                what: What::Credentials(credential_used(credential, used)),
            },
        )
        .await?;
        written += 1;
    }
    Ok(Filed::Uses { written, foreign })
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FileError {
    #[error("read the workspace binding or credential: {0}")]
    Binding(#[from] sqlx::Error),
    #[error(transparent)]
    Audit(#[from] audit::AuditError),
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
