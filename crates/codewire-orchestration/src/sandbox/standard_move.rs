//! One organization moves onto `standard` (#5602,
//! `docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`, "Moving an organization").
//!
//! A deployment makes `standard` available without making it every
//! organization's default; a global administrator moves one organization,
//! and that organization's new creates record `standard`. Every environment
//! records the profile its create chose (`environments.runtime_profile`,
//! written once), and every later render and start reads only that record.

use anyhow::Context;
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

use crate::sandbox::template::{
    RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL, RUNTIME_PROFILE_STANDARD,
    StandardRuntime, is_commodity_runtime_class, runtime_profile_of,
};
use crate::worker::create::SandboxWorkerCfg;

/// The audit action of a move.
pub const AUDIT_ACTION: &str = "admin.organization.standard_runtime";

/// The standard runtime this deployment makes available: its runtime image
/// and image disk are configured, and hosted egress, its VM's only network,
/// is on. Startup, the create's choice and a move read this one function.
pub fn available(cfg: &SandboxWorkerCfg) -> Option<&StandardRuntime> {
    cfg.standard_runtime
        .as_ref()
        .filter(|_| cfg.hosted_egress.create().is_some())
}

/// The profile a standard-tier create wants before checking whether the
/// `standard` disk boots its image: `standard` when the organization is
/// moved and the deployment makes it available, otherwise the deployment's
/// own profile.
pub fn wanted_profile(cfg: &SandboxWorkerCfg, organization_moved: bool) -> &str {
    if organization_moved && available(cfg).is_some() {
        RUNTIME_PROFILE_STANDARD
    } else {
        cfg.runtime_profile.trim()
    }
}

/// The profile a create records, decided once: `confidential` on the
/// confidential tier; `standard` when the organization is moved and the
/// deployment makes it available; otherwise the deployment's own profile.
/// A `standard` VM boots only the image its disk was built from, so any other
/// image records `commodity` ([`runtime_profile_of`]).
pub fn create_profile<'a>(
    cfg: &'a SandboxWorkerCfg,
    isolation_tier: &str,
    image: &str,
    organization_moved: bool,
) -> &'a str {
    if isolation_tier == RUNTIME_PROFILE_CONFIDENTIAL {
        return RUNTIME_PROFILE_CONFIDENTIAL;
    }
    let wanted = wanted_profile(cfg, organization_moved);
    runtime_profile_of(wanted, cfg.standard_runtime.as_ref(), image)
}

/// Whether `org_id` is moved onto `standard`.
pub async fn organization_moved(pool: &sqlx::PgPool, org_id: &str) -> AppResult<bool> {
    sqlx::query_scalar("SELECT standard_runtime_enabled FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

/// A moved organization, as the admin list names it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MovedOrganization {
    pub organization_id: String,
    pub slug: String,
    pub name: String,
}

/// The organizations moved onto `standard`, by slug. Global administrators
/// only.
pub async fn list_core(pool: &sqlx::PgPool, actor: &AuthUser) -> AppResult<Vec<MovedOrganization>> {
    actor.require_global_admin()?;
    Ok(sqlx::query_as(
        r#"SELECT id AS organization_id, slug, name FROM organizations
            WHERE standard_runtime_enabled
            ORDER BY slug"#,
    )
    .fetch_all(pool)
    .await?)
}

/// While the deployment doesn't make `standard` available, no organization
/// is moved onto it.
fn unavailable() -> AppError {
    AppError::Coded {
        status: StatusCode::PRECONDITION_FAILED,
        code: "standard_runtime_unavailable",
        detail: "this deployment does not make the standard runtime available: it needs \
                 SANDBOX_STANDARD_RUNTIME_IMAGE, SANDBOX_STANDARD_IMAGE_DISK and hosted egress on"
            .into(),
    }
}

/// Moves one organization onto `standard`, or back. Global administrators
/// only; a move onto it is refused while the deployment doesn't make it
/// available. The flag and its audit entry, naming the actor, the
/// organization and the previous and new values, commit together. Setting
/// the value it already has changes nothing. Returns the previous value.
/// Only new creates follow it: an existing environment keeps its record.
pub async fn set_core(
    pool: &sqlx::PgPool,
    cfg: &SandboxWorkerCfg,
    actor: &AuthUser,
    organization_id: &str,
    enabled: bool,
) -> AppResult<bool> {
    actor.require_global_admin()?;
    if enabled && available(cfg).is_none() {
        return Err(unavailable());
    }
    let failure = |action: &'static str| {
        move |error| {
            tracing::error!(error = %error, action, "admin: organization standard runtime");
            AppError::InternalMsg("failed to update the organization's standard runtime".into())
        }
    };
    let mut transaction = pool.begin().await.map_err(failure("start the update"))?;
    let previous: Option<bool> = sqlx::query_scalar(
        "SELECT standard_runtime_enabled FROM organizations WHERE id = $1 FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(failure("read the organization"))?;
    let previous = previous.ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    if previous == enabled {
        return Ok(previous);
    }
    sqlx::query(
        "UPDATE organizations SET standard_runtime_enabled = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(organization_id)
    .bind(enabled)
    .execute(&mut *transaction)
    .await
    .map_err(failure("update the organization"))?;
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, 'warn')"#,
    )
    .bind(AUDIT_ACTION)
    .bind(&actor.user_id)
    .bind(serde_json::json!({
        "organization_id": organization_id,
        "previous": previous,
        "standard_runtime_enabled": enabled,
    }))
    .execute(&mut *transaction)
    .await
    .map_err(failure("record the audit entry"))?;
    transaction
        .commit()
        .await
        .map_err(failure("commit the update"))?;
    Ok(previous)
}

/// The environment a live Sandbox serves and its runtime class.
fn sandbox_runtime(sandbox: &kube::api::DynamicObject) -> Option<(String, String)> {
    let template = sandbox.data.get("spec")?.get("podTemplate")?;
    let environment = template
        .get("metadata")?
        .get("labels")?
        .get("codewire.sh/environment-id")?
        .as_str()?;
    let class = template
        .get("spec")
        .and_then(|spec| spec.get("runtimeClassName"))
        .and_then(|class| class.as_str())
        .unwrap_or_default();
    Some((environment.to_owned(), class.to_owned()))
}

/// The environments recorded `commodity` whose live Sandbox runs another
/// runtime class.
pub fn disagreeing(
    recorded_commodity: &[String],
    sandboxes: &[kube::api::DynamicObject],
) -> Vec<String> {
    let live: std::collections::HashMap<String, String> =
        sandboxes.iter().filter_map(sandbox_runtime).collect();
    recorded_commodity
        .iter()
        .filter(|id| {
            live.get(*id)
                .is_some_and(|class| !is_commodity_runtime_class(class))
        })
        .cloned()
        .collect()
}

/// On a deployment whose default is `standard`, refuse to start while any
/// plain environment the backfill recorded `commodity` runs on another
/// runtime class: its record would move it on its next start. Fails closed
/// when the Sandboxes can't be read.
pub async fn check_recorded_profiles(
    cfg: &SandboxWorkerCfg,
    pool: &sqlx::PgPool,
    kube: Option<&kube::Client>,
) -> anyhow::Result<()> {
    if cfg.runtime_profile.trim() != RUNTIME_PROFILE_STANDARD {
        return Ok(());
    }
    let kube = kube.context(
        "a standard default checks each environment's recorded profile against its live \
         Sandbox, which needs the cluster",
    )?;
    let recorded: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM environments
          WHERE runtime_profile = $1 AND NOT systemd_workspace AND destroyed_at IS NULL",
    )
    .bind(RUNTIME_PROFILE_COMMODITY)
    .fetch_all(pool)
    .await
    .context("read the environments recorded commodity")?;
    let sandboxes = super::client::SandboxClient::new(kube.clone(), &cfg.sandbox_namespace)
        .list_sandboxes()
        .await
        .context("read the live Sandboxes' runtime classes")?;
    let disagreeing = disagreeing(&recorded, &sandboxes);
    anyhow::ensure!(
        disagreeing.is_empty(),
        "{} environments recorded commodity run on another runtime class: {}; their next \
         start would move them",
        disagreeing.len(),
        disagreeing.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
