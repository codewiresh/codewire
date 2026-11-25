//! An organization's registered audiences (docs/dev/SANDBOX-IDENTITY.md,
//! "Audiences"). A Sandbox gets a token only for one of these.
//!
//! A registration's version comes from a database sequence, never a clock, so
//! removing an audience and registering it again never reuses a version, and
//! the mint cache, keyed by it, misses.

use std::time::Duration;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use sqlx::PgPool;

use super::{audit, require_org_admin};
use crate::api::environments::{coded, coded_owned};
use crate::identity::audience::{AudienceDenylist, CanonicalAudience};
use crate::identity::groups::{AudienceLifetime, GroupSet, ProjectedFileName, VisibleGroups};

/// At most this many of an organization's audiences carry a file name, so the
/// files' renewals stay well inside a Sandbox's minting limit
/// (docs/dev/SANDBOX-IDENTITY.md, "Audiences").
pub const MAX_FILE_AUDIENCES: i64 = 8;

/// A registration as a request asks for it, before parsing.
#[derive(Debug, Clone, Default)]
pub struct AudienceRequest<'a> {
    pub audience: &'a str,
    /// `None` sees every group.
    pub visible_groups: Option<&'a [String]>,
    /// `None` is ten minutes.
    pub lifetime: Option<Duration>,
    pub claim_created_by: bool,
    pub claim_environment_name: bool,
    pub file_name: Option<&'a str>,
}

/// A stored registration.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AudienceView {
    pub org_id: String,
    pub audience: String,
    /// `None` sees every group.
    pub visible_groups: Option<Vec<String>>,
    pub lifetime_seconds: i32,
    pub claim_created_by: bool,
    pub claim_environment_name: bool,
    pub file_name: Option<String>,
    pub version: i64,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

const COLUMNS: &str = "org_id, audience, visible_groups, lifetime_seconds, claim_created_by, \
     claim_environment_name, file_name, version, created_by, created_at";

fn invalid(code: &'static str, error: impl ToString) -> codewire_server_core::AppError {
    coded_owned(StatusCode::BAD_REQUEST, code, error.to_string())
}

/// Register an audience in its canonical form, refused when its form or the
/// denylist refuses it, naming the rule.
pub async fn register_audience(
    pool: &PgPool,
    denylist: &AudienceDenylist,
    user: &AuthUser,
    org_id: &str,
    request: AudienceRequest<'_>,
) -> AppResult<AudienceView> {
    require_org_admin(pool, user, org_id).await?;
    let audience = CanonicalAudience::parse(request.audience)
        .map_err(|error| invalid("invalid_audience", error))?;
    denylist
        .check(&audience)
        .map_err(|error| invalid("invalid_audience", error))?;
    let visible = match request.visible_groups {
        None => VisibleGroups::All,
        Some(names) => VisibleGroups::Only(
            GroupSet::parse(names).map_err(|error| invalid("invalid_identity_group", error))?,
        ),
    };
    let lifetime = request
        .lifetime
        .map(AudienceLifetime::parse)
        .transpose()
        .map_err(|error| invalid("invalid_audience_lifetime", error))?
        .unwrap_or(AudienceLifetime::DEFAULT);
    let file_name = request
        .file_name
        .map(ProjectedFileName::parse)
        .transpose()
        .map_err(|error| invalid("invalid_identity_file_name", error))?;
    let visible_groups = match &visible {
        VisibleGroups::All => None,
        VisibleGroups::Only(groups) => Some(groups.names()),
    };

    run_organization_database_mutation(pool, org_id, async {
        let mut tx = pool.begin().await?;
        if file_name.is_some() {
            // One file registration at a time per organization, so two can't
            // both pass the count.
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended('identity-file-audiences:' || $1, 0))",
            )
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
            let files: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM identity_audiences \
                 WHERE org_id = $1 AND file_name IS NOT NULL",
            )
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await?;
            if files >= MAX_FILE_AUDIENCES {
                return Err(coded_owned(
                    StatusCode::CONFLICT,
                    "identity_file_limit",
                    format!(
                        "this organization already has {MAX_FILE_AUDIENCES} audiences with a \
                         file; remove one first"
                    ),
                ));
            }
        }
        let inserted: Result<AudienceView, sqlx::Error> = sqlx::query_as(&format!(
            "INSERT INTO identity_audiences (org_id, audience, visible_groups, lifetime_seconds, \
             claim_created_by, claim_environment_name, file_name, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING {COLUMNS}"
        ))
        .bind(org_id)
        .bind(audience.as_str())
        .bind(&visible_groups)
        .bind(i32::from(lifetime.seconds()))
        .bind(request.claim_created_by)
        .bind(request.claim_environment_name)
        .bind(file_name.as_ref().map(ProjectedFileName::as_str))
        .bind(&user.user_id)
        .fetch_one(&mut *tx)
        .await;
        let registered = match inserted {
            Ok(registered) => registered,
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some("identity_audiences_pkey") =>
            {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "identity_audience_exists",
                    "this organization already registered that audience",
                ));
            }
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some("identity_audiences_file_name_key") =>
            {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "identity_file_name_in_use",
                    "another of this organization's audiences already uses that file name",
                ));
            }
            Err(error) => return Err(error.into()),
        };
        audit(
            &mut tx,
            "identity.audience.registered",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id,
                "audience": registered.audience,
                "visible_groups": registered.visible_groups,
                "lifetime_seconds": registered.lifetime_seconds,
                "claim_created_by": registered.claim_created_by,
                "claim_environment_name": registered.claim_environment_name,
                "file_name": registered.file_name,
                "version": registered.version,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(registered)
    })
    .await
}

/// The organization's registrations, by audience.
pub async fn list_audiences(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<AudienceView>> {
    require_org_admin(pool, user, org_id).await?;
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM identity_audiences WHERE org_id = $1 ORDER BY audience"
    ))
    .bind(org_id)
    .fetch_all(pool)
    .await?)
}

/// Remove a registration, matched in its canonical form. Answers that form.
pub async fn remove_audience(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    audience: &str,
) -> AppResult<String> {
    require_org_admin(pool, user, org_id).await?;
    let not_found = || {
        coded(
            StatusCode::NOT_FOUND,
            "identity_audience_not_found",
            "this organization has not registered that audience",
        )
    };
    // An audience that isn't a URI was never registered.
    let audience = CanonicalAudience::parse(audience).map_err(|_| not_found())?;
    run_organization_database_mutation(pool, org_id, async {
        let mut tx = pool.begin().await?;
        let removed: Option<i64> = sqlx::query_scalar(
            "DELETE FROM identity_audiences WHERE org_id = $1 AND audience = $2 \
             RETURNING version",
        )
        .bind(org_id)
        .bind(audience.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let version = removed.ok_or_else(not_found)?;
        audit(
            &mut tx,
            "identity.audience.removed",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id,
                "audience": audience.as_str(),
                "version": version,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(audience.as_str().to_owned())
    })
    .await
}
