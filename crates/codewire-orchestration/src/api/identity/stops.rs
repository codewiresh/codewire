//! The kill switches (docs/dev/SANDBOX-IDENTITY.md, "Kill switches"): stop
//! minting for one Sandbox or a whole organization, and resume it. A row in
//! `identity_minting_stops` is the stop; minting checks it before its cache.
//! Tokens already issued stay valid until they expire: this is not
//! revocation.

use axum::http::StatusCode;
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use sqlx::PgPool;

use super::{audit, environment_in_org, require_org_admin};
use crate::api::environments::coded;

/// What a stop or resume applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopTarget<'a> {
    Organization,
    Environment(&'a str),
}

impl StopTarget<'_> {
    fn environment_id(self) -> Option<String> {
        match self {
            Self::Organization => None,
            Self::Environment(id) => Some(id.to_owned()),
        }
    }
}

/// Who may stop and resume minting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authority {
    OrganizationAdmin,
    PlatformAdministrator,
}

impl Authority {
    fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationAdmin => "organization_admin",
            Self::PlatformAdministrator => "platform_administrator",
        }
    }
}

/// A platform administrator acts on any organization that exists; anyone
/// else must be an owner or admin of it.
async fn authorize(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<Authority> {
    if user.require_global_admin().is_ok() {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)")
                .bind(org_id)
                .fetch_one(pool)
                .await?;
        if !exists {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "org_not_found",
                "organization not found",
            ));
        }
        return Ok(Authority::PlatformAdministrator);
    }
    require_org_admin(pool, user, org_id).await?;
    Ok(Authority::OrganizationAdmin)
}

/// Stop minting for `target`. Answers false when it was already stopped:
/// nothing is written then.
pub async fn stop_minting(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    target: StopTarget<'_>,
) -> AppResult<bool> {
    let authority = authorize(pool, user, org_id).await?;
    run_organization_database_mutation(pool, org_id, async {
        let mut tx = pool.begin().await?;
        if let StopTarget::Environment(environment_id) = target {
            environment_in_org(&mut tx, org_id, environment_id, "").await?;
        }
        let stopped = sqlx::query(
            "INSERT INTO identity_minting_stops (org_id, environment_id, stopped_by) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(org_id)
        .bind(target.environment_id())
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if stopped {
            audit(
                &mut tx,
                "identity.stopped",
                &user.user_id,
                serde_json::json!({
                    "org_id": org_id,
                    "environment_id": target.environment_id(),
                    "authority": authority.as_str(),
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(stopped)
    })
    .await
}

/// Resume minting for `target`. Resuming an organization leaves its
/// Sandboxes' own stops. Answers false when it was not stopped.
pub async fn resume_minting(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    target: StopTarget<'_>,
) -> AppResult<bool> {
    let authority = authorize(pool, user, org_id).await?;
    run_organization_database_mutation(pool, org_id, async {
        let mut tx = pool.begin().await?;
        let removed = match target {
            StopTarget::Organization => {
                sqlx::query(
                    "DELETE FROM identity_minting_stops \
                     WHERE org_id = $1 AND environment_id IS NULL",
                )
                .bind(org_id)
                .execute(&mut *tx)
                .await?
            }
            StopTarget::Environment(environment_id) => {
                environment_in_org(&mut tx, org_id, environment_id, "").await?;
                sqlx::query(
                    "DELETE FROM identity_minting_stops \
                     WHERE org_id = $1 AND environment_id = $2",
                )
                .bind(org_id)
                .bind(environment_id)
                .execute(&mut *tx)
                .await?
            }
        }
        .rows_affected()
            > 0;
        if removed {
            audit(
                &mut tx,
                "identity.resumed",
                &user.user_id,
                serde_json::json!({
                    "org_id": org_id,
                    "environment_id": target.environment_id(),
                    "authority": authority.as_str(),
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(removed)
    })
    .await
}
