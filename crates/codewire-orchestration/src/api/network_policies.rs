//! Platform network policies (#4000, item 1), behind `NetworkPolicyService`:
//! an organization's named egress policies, which hosted environments select.
//!
//! A revision is made the way a local VM's policy store makes it
//! ([`TypedPolicy::with_rules`] and [`TypedPolicy::without_targets`]) and
//! holds the same canonical document and digest, so one set of rules has one
//! digest wherever it is stored. Members read policies and select them for
//! environments they created; owners and admins create, change and delete
//! them. A selection follows the policy's current revision. An environment
//! that selects nothing is on the built-in `open`, the default, and has no
//! row (#3997).
//!
//! An environment's status says what cw-egress reports its current Pod
//! enforces, and reads as not enforced wherever hosted egress is off
//! (#3997). Everything here is behind the deployment switch [`SWITCH`], off
//! by default.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_egress_policy::reference::{
    PolicyName, PolicyPlacement, PolicyReference, PolicyReferenceError,
};
use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy};
use codewire_egress_policy::{BuiltinPolicy, PolicyDigest, PolicyDocument};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::{AppError, AppResult};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Row};

use super::environments::coded;
use crate::egress::reports::FailureCode;

#[cfg(test)]
mod database_tests;

/// The deployment switch. It stays off in Production until something
/// enforces hosted policies (docs/CONFIGURATION.md).
pub const SWITCH: &str = "CODEWIRE_PLATFORM_NETWORK_POLICIES_ENABLED";
/// The reference that removes an environment's selection, so it is on
/// `open` by default. Clients from before #3997 send it; it is no policy's
/// name, and the database refuses it as one.
const CLEAR_SELECTION: &str = "hosted-default";
/// Policies one organization may hold, as a local store.
pub const MAX_POLICIES_PER_ORG: i64 = 256;
/// Revisions one policy may hold, as a local store.
pub const MAX_REVISIONS: u32 = 10_000;

/// The deployment's platform network policy switch, and whether it enforces
/// the policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkPolicyFlags {
    pub enabled: bool,
    /// Whether hosted egress is on, which is whether hosted policies are
    /// enforced (#3997). Startup sets it from the hosted egress settings.
    pub hosted_egress: bool,
}

impl NetworkPolicyFlags {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_setting(crate::confidential_storage::env_setting(SWITCH)?.as_deref())
    }

    /// The flags where hosted egress is `on` or off: hosted policies are
    /// enforced exactly where it is on (#3997).
    pub fn with_hosted_egress(self, on: bool) -> Self {
        Self {
            hosted_egress: on,
            ..self
        }
    }

    /// Off unless a deployment turns it on; any value but `true` or `false`
    /// fails startup.
    fn from_setting(value: Option<&str>) -> anyhow::Result<Self> {
        Ok(Self {
            enabled: crate::confidential_storage::parse_bool(SWITCH, value, false)?,
            hosted_egress: false,
        })
    }

    pub fn require(self) -> AppResult<()> {
        if self.enabled {
            return Ok(());
        }
        Err(AppError::Coded {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "NETWORK_POLICIES_DISABLED",
            detail: "platform network policies are not enabled on this deployment".into(),
        })
    }
}

/// One revision of a stored policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub revision: u32,
    pub current_revision: u32,
    pub policy: TypedPolicy,
    /// Lowercase hex.
    pub digest: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

/// A stored policy, by name or by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector<'a> {
    Name(&'a str),
    Id(&'a str),
}

/// One requested allow rule, before parsing.
#[derive(Debug, Clone, Copy)]
pub struct RuleInput<'a> {
    pub target: &'a str,
    pub ports: &'a [u32],
}

/// An environment's selection, resolved, and what its current Pod enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentPolicyView {
    /// `open`, `web`, `locked` or `platform:id:UUID`; empty when the
    /// environment selects nothing and is on `open` by default.
    pub reference: String,
    pub name: String,
    /// The stored policy's current revision; zero for a built-in.
    pub revision: u32,
    pub digest: String,
    pub enforcement: EnforcementView,
}

/// How old a cw-egress report may be and still describe the Pod: three of
/// cw-egress's 5-minute refreshes. The SQL in [`environment_policy_cols`]
/// states the same bound.
pub const ENFORCEMENT_REPORT_STALE_MINUTES: i64 = 15;

/// What cw-egress reports the environment's current Pod enforces (#4000).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementView {
    /// The deployment doesn't enforce hosted policies: hosted egress is off
    /// (#3997). Only [`EnvironmentPolicyView::on_deployment`] sets it.
    NotEnforced,
    /// Hosted egress is on, but no fresh report confirms the policy: there
    /// is none, the Pod's stream is down, or the latest is stale (#3997).
    Unconfirmed,
    /// The selected revision is in force.
    Enforced(EnforcedRevision),
    /// An older revision is in force while the selected one is applied.
    Enforcing(EnforcedRevision),
    /// The sandbox has no egress: its self-check, its policy or its lockdown
    /// failed.
    FailedClosed(FailedClosedReason),
}

/// Why a sandbox failed closed, as its public status names it (#5068). The
/// lockdown check's exact refusal is for operators and is not among these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedClosedReason {
    SelfCheckFailed,
    PolicyDigestMismatch,
    LockdownNotApplied,
}

impl FailedClosedReason {
    /// The public `failure_code`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelfCheckFailed => "self_check_failed",
            Self::PolicyDigestMismatch => "policy_digest_mismatch",
            Self::LockdownNotApplied => "lockdown_not_applied",
        }
    }
}

impl From<FailureCode> for FailedClosedReason {
    fn from(code: FailureCode) -> Self {
        match code {
            FailureCode::SelfCheckFailed => Self::SelfCheckFailed,
            FailureCode::PolicyDigestMismatch => Self::PolicyDigestMismatch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcedRevision {
    pub revision: u32,
    /// Lowercase hex.
    pub digest: String,
    pub at: DateTime<Utc>,
}

impl EnforcementView {
    /// From the current Pod's enforcement row, against the selected digest.
    /// Orchestration's own lockdown refusal decides first, at any age: it
    /// stands until the lockdown passes, whatever cw-egress reports after.
    /// Otherwise a report older than [`ENFORCEMENT_REPORT_STALE_MINUTES`] says
    /// nothing about now: cw-egress refreshes every live Pod's report every 5
    /// minutes, so a stale row means its cw-egress is gone.
    fn from_row(row: &PgRow, selected_digest: &str) -> Result<Self, sqlx::Error> {
        let lockdown_refused: Option<bool> = row.try_get("egress_lockdown_refused")?;
        if lockdown_refused == Some(true) {
            return Ok(Self::FailedClosed(FailedClosedReason::LockdownNotApplied));
        }
        let state: Option<String> = row.try_get("egress_state")?;
        let fresh: Option<bool> = row.try_get("egress_report_fresh")?;
        if fresh != Some(true) {
            return Ok(Self::Unconfirmed);
        }
        Ok(match state.as_deref() {
            None | Some("disconnected") => Self::Unconfirmed,
            Some("failed_closed") => {
                let detail: String = row.try_get("egress_detail")?;
                let code = FailureCode::parse(&detail).ok_or_else(corrupt_selection)?;
                Self::FailedClosed(code.into())
            }
            Some("enforced") => {
                let revision: i32 = row.try_get("egress_revision")?;
                let digest: Vec<u8> = row.try_get("egress_digest")?;
                let enforced = EnforcedRevision {
                    revision: stored_revision(revision)?,
                    digest: hex_digest(&digest)?,
                    at: row.try_get("egress_reported_at")?,
                };
                // The digest decides, not the revision: a revision number is
                // per policy, and the digest names the exact document.
                if enforced.digest == selected_digest {
                    Self::Enforced(enforced)
                } else {
                    Self::Enforcing(enforced)
                }
            }
            Some(_) => return Err(corrupt_selection()),
        })
    }
}

impl EnvironmentPolicyView {
    /// The status as this deployment reports it: with hosted egress off
    /// nothing enforces a hosted policy, whatever a report once said, so it
    /// is never shown as enforced or unconfirmed (#3997).
    pub fn on_deployment(mut self, hosted_egress: bool) -> Self {
        if !hosted_egress {
            self.enforcement = EnforcementView::NotEnforced;
        }
        self
    }

    /// No selection: `open`, by default.
    fn unselected() -> Self {
        Self {
            reference: String::new(),
            ..Self::builtin(BuiltinPolicy::Open)
        }
    }

    fn builtin(builtin: BuiltinPolicy) -> Self {
        Self {
            reference: builtin.name().to_owned(),
            name: builtin.name().to_owned(),
            revision: 0,
            digest: builtin.digest_hex().to_owned(),
            enforcement: EnforcementView::Unconfirmed,
        }
    }
}

/// The columns [`environment_policy_from_row`] reads, for an environment
/// query that joins [`environment_policy_joins!`]. Macros, so the environment
/// read's column list (`ENV_SELECT_COLS`) can include them with `concat!`.
macro_rules! environment_policy_cols {
    () => {
        "np.policy_id AS network_policy_id,
    np.builtin AS network_policy_builtin, npp.name AS network_policy_name,
    npp.current_revision AS network_policy_revision, npr.digest AS network_policy_digest,
    se.state AS egress_state, se.revision AS egress_revision, se.digest AS egress_digest,
    se.reported_at AS egress_reported_at, se.detail AS egress_detail,
    se.lockdown_refusal IS NOT NULL AS egress_lockdown_refused,
    se.reported_at > now() - interval '15 minutes' AS egress_report_fresh"
    };
}
pub(crate) use environment_policy_cols;

macro_rules! environment_policy_joins {
    () => {
        "LEFT JOIN platform_environment_network_policies np ON np.environment_id = e.id
    LEFT JOIN platform_network_policies npp ON npp.id = np.policy_id
    LEFT JOIN platform_network_policy_revisions npr
        ON npr.policy_id = npp.id AND npr.revision = npp.current_revision
    LEFT JOIN sandbox_environment_backend seb ON seb.environment_id = e.id
    LEFT JOIN sandbox_egress_enforcement se
        ON se.pod_uid = seb.pod_uid AND se.environment_id = e.id"
    };
}
pub(crate) use environment_policy_joins;

/// An environment's selection from a row with [`environment_policy_cols!`].
pub(crate) fn environment_policy_from_row(
    row: &PgRow,
) -> Result<EnvironmentPolicyView, sqlx::Error> {
    let policy_id: Option<String> = row.try_get("network_policy_id")?;
    let builtin: Option<String> = row.try_get("network_policy_builtin")?;
    let mut view = match (policy_id, builtin.as_deref()) {
        (None, None) => EnvironmentPolicyView::unselected(),
        (Some(id), None) => {
            let revision: i32 = row.try_get("network_policy_revision")?;
            let digest: Vec<u8> = row.try_get("network_policy_digest")?;
            EnvironmentPolicyView {
                reference: format!("platform:id:{id}"),
                name: row.try_get("network_policy_name")?,
                revision: stored_revision(revision)?,
                digest: hex_digest(&digest)?,
                enforcement: EnforcementView::Unconfirmed,
            }
        }
        (None, Some(name)) => EnvironmentPolicyView::builtin(
            BuiltinPolicy::from_name(name).ok_or_else(corrupt_selection)?,
        ),
        (Some(_), Some(_)) => return Err(corrupt_selection()),
    };
    view.enforcement = EnforcementView::from_row(row, &view.digest)?;
    Ok(view)
}

fn corrupt_selection() -> sqlx::Error {
    sqlx::Error::Decode(std::io::Error::other("invalid stored network policy selection").into())
}

fn stored_revision(revision: i32) -> Result<u32, sqlx::Error> {
    u32::try_from(revision).map_err(|_| corrupt_selection())
}

fn hex_digest(bytes: &[u8]) -> Result<String, sqlx::Error> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| corrupt_selection())?;
    Ok(PolicyDigest::from_bytes(bytes).to_hex())
}

// ── Authorization and errors ─────────────────────────────────────────────

/// The caller's role in the organization, or `organization not found`.
async fn member_role(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(pool, user, org_id).await?.ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        )
    })
}

async fn require_manager(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<()> {
    let role = member_role(pool, user, org_id).await?;
    if can_admin(&role, &user_assignments(pool, org_id, &user.user_id).await?) {
        return Ok(());
    }
    Err(coded(
        StatusCode::FORBIDDEN,
        "not_network_policy_manager",
        "only an organization owner or admin may change its network policies",
    ))
}

fn not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "network_policy_not_found",
        "network policy not found",
    )
}

fn corrupt() -> AppError {
    AppError::InternalMsg("a stored network policy revision does not match its digest".into())
}

fn reference_error(error: PolicyReferenceError) -> AppError {
    AppError::BadRequest(error.to_string().into())
}

fn parse_rules(rules: &[RuleInput<'_>]) -> AppResult<Vec<AllowRule>> {
    rules
        .iter()
        .map(|rule| {
            let target = AllowTarget::parse(rule.target)
                .map_err(|error| AppError::BadRequest(error.to_string().into()))?;
            let ports = rule
                .ports
                .iter()
                .map(|port| {
                    u16::try_from(*port).map_err(|_| {
                        AppError::BadRequest(format!("port {port} is not a TCP port").into())
                    })
                })
                .collect::<AppResult<Vec<u16>>>()?;
            AllowRule::new(target, ports)
                .map_err(|error| AppError::BadRequest(error.to_string().into()))
        })
        .collect()
}

fn parse_targets(targets: &[&str]) -> AppResult<Vec<AllowTarget>> {
    targets
        .iter()
        .map(|target| {
            AllowTarget::parse(target)
                .map_err(|error| AppError::BadRequest(error.to_string().into()))
        })
        .collect()
}

// ── Storage ──────────────────────────────────────────────────────────────

/// `(id, name, current_revision)` of the organization's policy `selector`
/// names, locked as `lock` says.
async fn find_policy(
    connection: &mut PgConnection,
    org_id: &str,
    selector: Selector<'_>,
    lock: &str,
) -> AppResult<(String, String, u32)> {
    let (column, key) = match selector {
        Selector::Name(name) => ("name", name),
        // Every policy ID is a canonical UUID; anything else names none.
        Selector::Id(id) => {
            if codewire_egress_policy::reference::PolicyId::parse(id).is_err() {
                return Err(not_found());
            }
            ("id", id)
        }
    };
    let row: Option<(String, String, i32)> = sqlx::query_as(&format!(
        "SELECT id, name, current_revision FROM platform_network_policies \
         WHERE org_id = $1 AND {column} = $2 {lock}"
    ))
    .bind(org_id)
    .bind(key)
    .fetch_optional(&mut *connection)
    .await?;
    let (id, name, revision) = row.ok_or_else(not_found)?;
    Ok((id, name, u32::try_from(revision).map_err(|_| corrupt())?))
}

/// One revision of the policy `id`.
async fn load_revision(
    connection: &mut PgConnection,
    org_id: &str,
    id: &str,
    revision: u32,
) -> AppResult<PolicyView> {
    let row = sqlx::query(
        "SELECT p.name, p.current_revision, r.document, r.digest, r.created_at, r.created_by \
           FROM platform_network_policies p \
           JOIN platform_network_policy_revisions r ON r.policy_id = p.id \
          WHERE p.org_id = $1 AND p.id = $2 AND r.revision = $3",
    )
    .bind(org_id)
    .bind(id)
    .bind(i32::try_from(revision).map_err(|_| not_found())?)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(not_found)?;
    let document: Vec<u8> = row.try_get("document")?;
    let digest: Vec<u8> = row.try_get("digest")?;
    let parsed: PolicyDocument = serde_json::from_slice(&document).map_err(|_| corrupt())?;
    let policy = TypedPolicy::from_document(&parsed).map_err(|_| corrupt())?;
    let compiled = policy.compile();
    if compiled.digest().as_bytes().as_slice() != digest.as_slice()
        || compiled.canonical_json().ok().as_deref() != Some(document.as_slice())
    {
        return Err(corrupt());
    }
    Ok(PolicyView {
        id: id.to_owned(),
        org_id: org_id.to_owned(),
        name: row.try_get("name")?,
        revision,
        current_revision: u32::try_from(row.try_get::<i32, _>("current_revision")?)
            .map_err(|_| corrupt())?,
        policy,
        digest: compiled.digest().to_hex(),
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

async fn insert_revision(
    connection: &mut PgConnection,
    id: &str,
    revision: u32,
    policy: &TypedPolicy,
    user: &AuthUser,
) -> AppResult<()> {
    let compiled = policy.compile();
    let document = compiled
        .canonical_json()
        .map_err(|_| AppError::InternalMsg("serialize a network policy".into()))?;
    sqlx::query(
        "INSERT INTO platform_network_policy_revisions \
           (policy_id, revision, document, digest, created_by) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(i32::try_from(revision).map_err(|_| corrupt())?)
    .bind(document)
    .bind(compiled.digest().as_bytes().as_slice())
    .bind(&user.user_id)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

// ── Policies ─────────────────────────────────────────────────────────────

/// A new policy at revision 1: `from`'s current rules, or none, plus `allow`.
pub async fn create_policy(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    name: &str,
    from: Option<Selector<'_>>,
    allow: &[RuleInput<'_>],
) -> AppResult<PolicyView> {
    require_manager(pool, user, org_id).await?;
    let name = PolicyName::parse(name).map_err(reference_error)?;
    // Older clients clear a selection with this name, so no organization
    // policy may take it. A local store may (#4000).
    if name.as_str() == CLEAR_SELECTION {
        return Err(AppError::BadRequest(
            "the network policy name hosted-default is reserved".into(),
        ));
    }
    let allow = parse_rules(allow)?;

    // One create per organization at a time, so two cannot both pass the
    // bound. The lock ends with the transaction.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('network-policies:' || $1, 0))")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM platform_network_policies WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await?;
    if count >= MAX_POLICIES_PER_ORG {
        return Err(AppError::Precondition(
            "this organization has the most network policies it can hold; delete one first".into(),
        ));
    }
    let start = match from {
        None => TypedPolicy::default(),
        Some(selector) => {
            let (id, _, revision) = find_policy(&mut tx, org_id, selector, "FOR SHARE").await?;
            load_revision(&mut tx, org_id, &id, revision).await?.policy
        }
    };
    let policy = start
        .with_rules(allow)
        .map_err(|error| AppError::BadRequest(error.to_string().into()))?;
    let inserted: Result<String, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO platform_network_policies (org_id, name, current_revision) \
         VALUES ($1, $2, 1) RETURNING id",
    )
    .bind(org_id)
    .bind(name.as_str())
    .fetch_one(&mut *tx)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(sqlx::Error::Database(error))
            if error.constraint() == Some("platform_network_policies_org_name_key") =>
        {
            return Err(coded(
                StatusCode::CONFLICT,
                "network_policy_name_taken",
                "this organization already has a network policy with this name",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    insert_revision(&mut tx, &id, 1, &policy, user).await?;
    let view = load_revision(&mut tx, org_id, &id, 1).await?;
    tx.commit().await?;
    Ok(view)
}

/// The organization's policies at their current revisions, by name.
pub async fn list_policies(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<PolicyView>> {
    member_role(pool, user, org_id).await?;
    let mut tx = pool.begin().await?;
    let policies: Vec<(String, i32)> = sqlx::query_as(
        "SELECT id, current_revision FROM platform_network_policies \
         WHERE org_id = $1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut views = Vec::with_capacity(policies.len());
    for (id, revision) in policies {
        let revision = u32::try_from(revision).map_err(|_| corrupt())?;
        views.push(load_revision(&mut tx, org_id, &id, revision).await?);
    }
    tx.commit().await?;
    Ok(views)
}

/// `selector` at `revision`, or at its current revision.
pub async fn get_policy(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    selector: Selector<'_>,
    revision: Option<u32>,
) -> AppResult<PolicyView> {
    member_role(pool, user, org_id).await?;
    let mut connection = pool.acquire().await?;
    let (id, _, current) = find_policy(&mut connection, org_id, selector, "").await?;
    load_revision(&mut connection, org_id, &id, revision.unwrap_or(current)).await
}

/// A new revision of `selector`: its current rules plus `allow`, minus the
/// rules for `remove`. A change that changes nothing is refused, as is one
/// made against a revision that is no longer current.
pub async fn update_policy(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    selector: Selector<'_>,
    allow: &[RuleInput<'_>],
    remove: &[&str],
    expected_revision: Option<u32>,
) -> AppResult<PolicyView> {
    require_manager(pool, user, org_id).await?;
    let allow = parse_rules(allow)?;
    let remove = parse_targets(remove)?;
    let mut tx = pool.begin().await?;
    let (id, name, current) = find_policy(&mut tx, org_id, selector, "FOR UPDATE").await?;
    if expected_revision.is_some_and(|expected| expected != current) {
        return Err(AppError::Precondition(
            format!("{name} has changed: it is at revision {current}").into(),
        ));
    }
    let existing = load_revision(&mut tx, org_id, &id, current).await?.policy;
    let edited = existing
        .with_rules(allow)
        .map_err(|error| AppError::BadRequest(error.to_string().into()))?
        .without_targets(&remove)
        .map_err(|missing| {
            AppError::Precondition(format!("{name} has no rule for {missing}").into())
        })?;
    if edited == existing {
        return Err(AppError::Precondition(
            format!("{name} already allows exactly that").into(),
        ));
    }
    if current >= MAX_REVISIONS {
        return Err(AppError::Precondition(
            format!("{name} has the most revisions a policy can hold").into(),
        ));
    }
    let next = current + 1;
    insert_revision(&mut tx, &id, next, &edited, user).await?;
    sqlx::query("UPDATE platform_network_policies SET current_revision = $1 WHERE id = $2")
        .bind(i32::try_from(next).map_err(|_| corrupt())?)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let view = load_revision(&mut tx, org_id, &id, next).await?;
    tx.commit().await?;
    Ok(view)
}

/// Removes `selector` and its revisions, unless an environment selects it:
/// then the refusal names the environments.
pub async fn delete_policy(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    selector: Selector<'_>,
) -> AppResult<PolicyView> {
    require_manager(pool, user, org_id).await?;
    let mut tx = pool.begin().await?;
    let (id, name, current) = find_policy(&mut tx, org_id, selector, "FOR UPDATE").await?;
    let selecting: Vec<String> = sqlx::query_scalar(
        "SELECT COALESCE(e.name, e.id) FROM platform_environment_network_policies b \
           JOIN environments e ON e.id = b.environment_id \
          WHERE b.policy_id = $1 ORDER BY 1 LIMIT $2",
    )
    .bind(&id)
    .bind(i64::from(NAMED_ENVIRONMENTS) + 1)
    .fetch_all(&mut *tx)
    .await?;
    if !selecting.is_empty() {
        let named = usize::from(NAMED_ENVIRONMENTS);
        let more = if selecting.len() > named {
            " and more"
        } else {
            ""
        };
        let shown = selecting.iter().take(named).cloned().collect::<Vec<_>>();
        return Err(AppError::Precondition(
            format!(
                "{name} is selected by {}{more}; select another policy for them first",
                shown.join(", ")
            )
            .into(),
        ));
    }
    let view = load_revision(&mut tx, org_id, &id, current).await?;
    sqlx::query("DELETE FROM platform_network_policies WHERE id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(view)
}

/// What some of an organization's hosted environments select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageSelection {
    /// A stored policy, by id.
    Policy(String),
    /// A built-in; `open` counts the environments that select nothing too.
    Builtin(BuiltinPolicy),
}

/// How many environments select one thing, and the first names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUsage {
    pub selection: UsageSelection,
    pub environments: u32,
    /// At most [`NAMED_ENVIRONMENTS`], in name order; an unnamed one by id.
    pub names: Vec<String>,
}

/// How many environments a refused delete and a policy's usage name.
pub const NAMED_ENVIRONMENTS: u8 = 10;

/// What the organization's hosted environments select, in one grouped read.
/// It counts the same selection rows [`delete_policy`] refuses for, so a
/// count never says nobody selects a policy whose delete is refused; an
/// environment with no row and not destroyed is on `open`, and counts there.
pub async fn policy_usage(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<PolicyUsage>> {
    member_role(pool, user, org_id).await?;
    let rows = sqlx::query(
        "WITH chosen AS ( \
           SELECT b.policy_id, b.builtin, COALESCE(e.name, e.id) AS label \
             FROM platform_environment_network_policies b \
             JOIN environments e ON e.id = b.environment_id \
            WHERE e.org_id = $1 \
           UNION ALL \
           SELECT NULL, $2, COALESCE(e.name, e.id) \
             FROM environments e \
            WHERE e.org_id = $1 AND e.type = 'sandbox' AND e.state <> 'destroyed' \
              AND NOT EXISTS (SELECT 1 FROM platform_environment_network_policies b \
                               WHERE b.environment_id = e.id) \
         ), ranked AS ( \
           SELECT policy_id, builtin, label, \
                  row_number() OVER (PARTITION BY policy_id, builtin ORDER BY label) AS n \
             FROM chosen \
         ) \
         SELECT policy_id, builtin, count(*) AS environments, \
                array_agg(label ORDER BY label) FILTER (WHERE n <= $3) AS names \
           FROM ranked GROUP BY policy_id, builtin ORDER BY policy_id, builtin",
    )
    .bind(org_id)
    .bind(BuiltinPolicy::Open.name())
    .bind(i64::from(NAMED_ENVIRONMENTS))
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            let policy_id: Option<String> = row.try_get("policy_id")?;
            let builtin: Option<String> = row.try_get("builtin")?;
            let selection = match (policy_id, builtin) {
                (Some(id), None) => UsageSelection::Policy(id),
                (None, Some(name)) => UsageSelection::Builtin(
                    BuiltinPolicy::from_name(&name).ok_or_else(corrupt_selection)?,
                ),
                _ => return Err(corrupt_selection()),
            };
            let environments: i64 = row.try_get("environments")?;
            Ok(PolicyUsage {
                selection,
                environments: u32::try_from(environments).map_err(|_| corrupt_selection())?,
                names: row
                    .try_get::<Option<Vec<String>>, _>("names")?
                    .unwrap_or_default(),
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

// ── Environment selections ───────────────────────────────────────────────

/// What a reference selects, resolved in an organization.
enum Selection {
    Unselected,
    Builtin(BuiltinPolicy),
    Stored(String),
}

/// Resolve `reference` in `org_id`, sharing the stored policy's row lock so
/// it cannot be deleted before the selection is written.
async fn resolve(
    connection: &mut PgConnection,
    org_id: &str,
    reference: &str,
) -> AppResult<Selection> {
    if reference == CLEAR_SELECTION {
        return Ok(Selection::Unselected);
    }
    let parsed = PolicyReference::parse(reference).map_err(reference_error)?;
    parsed
        .check_placement(PolicyPlacement::Hosted)
        .map_err(reference_error)?;
    let selector = match &parsed {
        PolicyReference::Builtin(builtin) => return Ok(Selection::Builtin(*builtin)),
        PolicyReference::Name { name, .. } => Selector::Name(name.as_str()),
        PolicyReference::Id { id, .. } => Selector::Id(id.as_str()),
    };
    let (id, _, _) = find_policy(connection, org_id, selector, "FOR SHARE").await?;
    Ok(Selection::Stored(id))
}

/// Records `reference` as `environment_id`'s selection inside the caller's
/// transaction. The environment must already be locked by the caller.
pub(crate) async fn select_in(
    connection: &mut PgConnection,
    org_id: &str,
    environment_id: &str,
    reference: &str,
) -> AppResult<()> {
    let (policy_id, builtin) = match resolve(connection, org_id, reference).await? {
        Selection::Unselected => {
            sqlx::query(
                "DELETE FROM platform_environment_network_policies WHERE environment_id = $1",
            )
            .bind(environment_id)
            .execute(&mut *connection)
            .await?;
            return Ok(());
        }
        Selection::Builtin(builtin) => (None, Some(builtin.name())),
        Selection::Stored(id) => (Some(id), None),
    };
    // A new selection has nothing enforcing it yet.
    sqlx::query(
        "INSERT INTO platform_environment_network_policies (environment_id, policy_id, builtin) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (environment_id) DO UPDATE \
           SET policy_id = EXCLUDED.policy_id, builtin = EXCLUDED.builtin, \
               enforced_revision = NULL, enforced_digest = NULL, enforced_at = NULL",
    )
    .bind(environment_id)
    .bind(policy_id)
    .bind(builtin)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// `environment_id`'s selection, as the environment read reports it.
async fn environment_policy_in(
    connection: &mut PgConnection,
    environment_id: &str,
) -> AppResult<EnvironmentPolicyView> {
    let row = sqlx::query(concat!(
        "SELECT ",
        environment_policy_cols!(),
        " FROM environments e ",
        environment_policy_joins!(),
        " WHERE e.id = $1"
    ))
    .bind(environment_id)
    .fetch_one(&mut *connection)
    .await?;
    Ok(environment_policy_from_row(&row)?)
}

/// Selects the network policy of a hosted environment the caller created.
/// `hosted-default` removes the selection. A running environment keeps
/// running: nothing enforces a hosted policy yet.
pub async fn select_for_environment(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    reference: &str,
) -> AppResult<EnvironmentPolicyView> {
    member_role(pool, user, org_id).await?;
    let mut tx = pool.begin().await?;
    let environment: Option<String> = sqlx::query_scalar(
        "SELECT id FROM environments \
         WHERE id = $1 AND created_by = $2 AND org_id = $3 AND type = 'sandbox' \
           AND deletion_requested_at IS NULL AND desired_state <> 'destroyed' \
           AND state NOT IN ('destroyed', 'destroying') FOR UPDATE",
    )
    .bind(environment_id)
    .bind(&user.user_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    if environment.is_none() {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "environment_not_found",
            "environment not found",
        ));
    }
    select_in(&mut tx, org_id, environment_id, reference).await?;
    let view = environment_policy_in(&mut tx, environment_id).await?;
    tx.commit().await?;
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_is_off_unless_turned_on_and_refuses_anything_else() {
        assert!(!NetworkPolicyFlags::from_setting(None).unwrap().enabled);
        assert!(
            NetworkPolicyFlags::from_setting(Some("true"))
                .unwrap()
                .enabled
        );
        assert!(
            !NetworkPolicyFlags::from_setting(Some("false"))
                .unwrap()
                .enabled
        );
        for value in ["", "1", "yes", "TRUE"] {
            assert!(
                NetworkPolicyFlags::from_setting(Some(value)).is_err(),
                "{value}"
            );
        }
        assert!(matches!(
            NetworkPolicyFlags::default().require(),
            Err(AppError::Coded {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "NETWORK_POLICIES_DISABLED",
                ..
            })
        ));
        assert!(
            NetworkPolicyFlags {
                enabled: true,
                ..NetworkPolicyFlags::default()
            }
            .require()
            .is_ok()
        );
    }

    #[test]
    fn rules_name_what_is_wrong_with_them() {
        let refused = |target: &str, ports: &[u32]| {
            parse_rules(&[RuleInput { target, ports }])
                .unwrap_err()
                .to_string()
        };
        assert!(refused("github.com", &[]).contains("at least one TCP port"));
        assert!(refused("github.com", &[70000]).contains("not a TCP port"));
        assert!(refused("10.0.0.0/8", &[443]).contains("invalid allow target"));
        assert_eq!(
            parse_rules(&[RuleInput {
                target: "github.com",
                ports: &[443, 22],
            }])
            .unwrap()[0]
                .ports(),
            &[22, 443]
        );
    }
}
