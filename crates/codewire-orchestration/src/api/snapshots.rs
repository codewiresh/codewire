//! Hosted disk snapshots (#3046 H1): the shared logic behind `SnapshotService`.
//!
//! A snapshot is private to its creator: every read and delete matches on the
//! organization and the authenticated user. Capture and deletion run in Temporal
//! workflows; this only records the request and starts them.

use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
    run_organization_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use sqlx::{FromRow, PgPool};

use super::ApiState;
use super::environments::{
    check_rate_limit, coded, fetch_env_summary, require_environment_access, require_org_member,
};

const MAX_NAME_CHARS: usize = 128;
/// Captures running at once in one organization. Each is a Kata VM and a restored
/// volume on a shared thin pool.
const MAX_CAPTURING_PER_ORG: i64 = 4;
/// Snapshots one organization may hold, failed ones included. A safety bound while
/// nothing bills for them: the owner's "no quota" (Q7, #3046) is for billed storage,
/// so this goes with the billing meter (H4), the gate for Production.
const MAX_SNAPSHOTS_PER_ORG: i64 = 32;
/// Snapshot creates per user per minute, as environment creates are limited.
const CREATES_PER_MINUTE: i32 = 10;
const COLUMNS: &str = "id, org_id, source_environment_id, name, state, failure_code, size_bytes, \
                       created_at, last_used_at";

#[derive(Clone, Debug, FromRow)]
pub struct SnapshotRow {
    pub id: String,
    pub org_id: String,
    pub source_environment_id: String,
    pub name: String,
    pub state: String,
    pub failure_code: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

/// A name is one visible token, so a command line and a later `--snapshot` can
/// carry it. Mirrors what `cw snapshot create` accepts locally.
pub(crate) fn valid_snapshot_name(name: &str) -> bool {
    let mut characters = name.chars();
    let starts = characters.next().is_some_and(|c| c.is_ascii_alphanumeric());
    starts
        && name.chars().count() <= MAX_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "snapshot_not_found",
        "snapshot not found",
    )
}

/// Insert the row, refusing a name the creator already uses.
async fn insert_snapshot(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
    environment_id: &str,
    name: &str,
) -> AppResult<SnapshotRow> {
    // One writer per organization at a time, so two creates can't both pass the
    // bounds. The lock ends with the transaction.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('hosted_snapshots:' || $1, 0))")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let (capturing, held): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE state = 'capturing'), count(*)
           FROM hosted_snapshots WHERE org_id = $1 AND state <> 'deleting'",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    if capturing >= MAX_CAPTURING_PER_ORG {
        return Err(coded(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_captures",
            "this organization has too many snapshots being captured; try again shortly",
        ));
    }
    if held >= MAX_SNAPSHOTS_PER_ORG {
        return Err(coded(
            StatusCode::CONFLICT,
            "snapshot_limit_reached",
            "this organization holds the most snapshots it can; remove one first",
        ));
    }
    let inserted = sqlx::query_as::<_, SnapshotRow>(&format!(
        "INSERT INTO hosted_snapshots (org_id, created_by, source_environment_id, name)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (org_id, created_by, name) DO NOTHING
         RETURNING {COLUMNS}"
    ))
    .bind(org_id)
    .bind(user_id)
    .bind(environment_id)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    inserted.ok_or_else(|| {
        coded(
            StatusCode::CONFLICT,
            "snapshot_name_taken",
            "you already have a snapshot with this name",
        )
    })
}

/// Only an environment's creator may capture it, for now. A snapshot is a durable
/// private copy of the environment's home and the logins in it, kept by whoever
/// took it, and the owner's reason for clearing only current token files assumes
/// the snapshotter owns those credentials. An organization admin, who may otherwise
/// manage the environment, may not. Whether to widen this is the owner's call.
async fn require_environment_creator(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
    environment_id: &str,
) -> AppResult<()> {
    let creator: Option<Option<String>> =
        sqlx::query_scalar("SELECT created_by FROM environments WHERE id = $1 AND org_id = $2")
            .bind(environment_id)
            .bind(org_id)
            .fetch_optional(pool)
            .await?;
    if creator.flatten().as_deref() == Some(user_id) {
        return Ok(());
    }
    Err(coded(
        StatusCode::FORBIDDEN,
        "access_denied",
        "only the environment's creator can snapshot it",
    ))
}

pub async fn create_snapshot_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    name: &str,
) -> AppResult<SnapshotRow> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        environment_id,
        org_id,
        "owner",
        "only the environment's creator can snapshot it",
    )
    .await?;
    require_environment_creator(&state.pool, &user.user_id, org_id, environment_id).await?;
    if state.sandbox_cfg.volume_snapshot_class.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "snapshots_unavailable",
            "this deployment does not offer hosted snapshots",
        ));
    }
    if !valid_snapshot_name(name) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_snapshot_name",
            "a snapshot name starts with a letter or digit and holds at most 128 letters, \
             digits, dots, underscores and hyphens",
        ));
    }
    // Fails open on a database error, as environment creates do: the per-org
    // bounds below still hold.
    match check_rate_limit(
        &state.pool,
        &format!("snapshot_create:{}", user.user_id),
        60,
        CREATES_PER_MINUTE,
    )
    .await
    {
        Err(error) => tracing::warn!(%error, "snapshot rate limit check failed, allowing"),
        Ok(false) => {
            return Err(coded(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many snapshot creates",
            ));
        }
        Ok(true) => {}
    }
    let env = fetch_env_summary(&state.pool, org_id, environment_id).await?;
    if env.isolation_tier == "confidential" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "snapshots_unavailable",
            "confidential environments do not support snapshots",
        ));
    }
    if env.state != "stopped" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment must be stopped to snapshot it",
        ));
    }

    let dispatch_ambiguous = AtomicBool::new(false);
    let owned_state = state.clone();
    let owned_user = user.clone();
    let owned_org_id = org_id.to_owned();
    let owned_environment_id = environment_id.to_owned();
    let owned_name = name.to_owned();
    run_environment_runtime_mutation(&state.pool, org_id, environment_id, async move {
        let result: AppResult<SnapshotRow> = async {
            let row = insert_snapshot(
                &owned_state.pool,
                &owned_user.user_id,
                &owned_org_id,
                &owned_environment_id,
                &owned_name,
            )
            .await?;
            // The row is durable, so a lost start is recovered by the reconciler.
            if owned_state
                .temporal_trigger
                .trigger_snapshot_capture(&row.id)
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to start the snapshot",
                ));
            }
            Ok(row)
        }
        .await;
        match result {
            Ok(row) => Ok(row),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

async fn creators_snapshots(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
) -> AppResult<Vec<SnapshotRow>> {
    Ok(sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {COLUMNS} FROM hosted_snapshots
          WHERE org_id = $1 AND created_by = $2
          ORDER BY created_at DESC, id"
    ))
    .bind(org_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

async fn creators_snapshot(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
    snapshot_id: &str,
) -> AppResult<SnapshotRow> {
    sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {COLUMNS} FROM hosted_snapshots
          WHERE id = $1 AND org_id = $2 AND created_by = $3"
    ))
    .bind(snapshot_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(not_found)
}

/// Mark a settled snapshot for deletion. A capture in progress isn't matched, so
/// its own cleanup can't race the delete. Nor is one an environment is still
/// being created from, whose volume may not exist yet to hold the snapshot in
/// place: the row lock waits out a create in flight, and the next statement
/// sees it.
async fn mark_deleting(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
    snapshot_id: &str,
) -> AppResult<SnapshotRow> {
    let mut transaction = pool.begin().await?;
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM hosted_snapshots
          WHERE id = $1 AND org_id = $2 AND created_by = $3
            AND state IN ('ready', 'failed', 'deleting')
          FOR UPDATE",
    )
    .bind(snapshot_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(not_found)?;
    let in_use: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM environments
                         WHERE source_snapshot_id = $1
                           AND state IN ('pending', 'creating'))",
    )
    .bind(snapshot_id)
    .fetch_one(&mut *transaction)
    .await?;
    if in_use {
        return Err(coded(
            StatusCode::CONFLICT,
            "snapshot_in_use",
            "an environment is being created from this snapshot; try again when it has started",
        ));
    }
    let row = sqlx::query_as::<_, SnapshotRow>(&format!(
        "UPDATE hosted_snapshots SET state = 'deleting', updated_at = now()
          WHERE id = $1
          RETURNING {COLUMNS}"
    ))
    .bind(snapshot_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(row)
}

pub async fn list_snapshots_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<SnapshotRow>> {
    require_org_member(&state.pool, user, org_id).await?;
    creators_snapshots(&state.pool, &user.user_id, org_id).await
}

pub async fn get_snapshot_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    snapshot_id: &str,
) -> AppResult<SnapshotRow> {
    require_org_member(&state.pool, user, org_id).await?;
    creators_snapshot(&state.pool, &user.user_id, org_id, snapshot_id).await
}

/// Mark the snapshot for deletion and start its workflow.
pub async fn delete_snapshot_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    snapshot_id: &str,
) -> AppResult<SnapshotRow> {
    let current = get_snapshot_core(state, user, org_id, snapshot_id).await?;
    if current.state == "capturing" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "this snapshot is still being captured",
        ));
    }

    let dispatch_ambiguous = AtomicBool::new(false);
    let owned_state = state.clone();
    let owned_user_id = user.user_id.clone();
    let owned_org_id = org_id.to_owned();
    let owned_snapshot_id = snapshot_id.to_owned();
    run_organization_runtime_mutation(&state.pool, org_id, async move {
        let result: AppResult<SnapshotRow> = async {
            let row = mark_deleting(
                &owned_state.pool,
                &owned_user_id,
                &owned_org_id,
                &owned_snapshot_id,
            )
            .await?;
            if owned_state
                .temporal_trigger
                .trigger_snapshot_delete(&row.id)
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to start the snapshot's deletion",
                ));
            }
            Ok(row)
        }
        .await;
        match result {
            Ok(row) => Ok(row),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    async fn seed(pool: &PgPool) -> (String, String, String) {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let creator = format!("user_snapshot_creator_{suffix}");
        let other = format!("user_snapshot_other_{suffix}");
        let org = format!("org-snapshot-{suffix}");
        for user in [&creator, &other] {
            sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                .bind(user)
                .bind(format!("{user}@example.test"))
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)",
        )
        .bind(&org)
        .bind(&creator)
        .execute(pool)
        .await
        .unwrap();
        (creator, other, org)
    }

    fn is_code(error: AppError, want: &str) -> bool {
        matches!(error, AppError::Coded { code, .. } if code == want)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_only_its_creator_starts_from_a_ready_snapshot_that_fits() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let (creator, other, org) = seed(&pool).await;
        let admit = |user: String, id: String, disk: i32| {
            let pool = pool.clone();
            let org = org.clone();
            async move {
                let mut transaction = pool.begin().await.unwrap();
                let result = crate::api::create::admit_source_snapshot(
                    &mut transaction,
                    &org,
                    &user,
                    &id,
                    disk,
                )
                .await;
                transaction.commit().await.unwrap();
                result
            }
        };
        let row = insert_snapshot(&pool, &creator, &org, "env-gone", "source")
            .await
            .unwrap();
        assert!(is_code(
            admit(creator.clone(), row.id.clone(), 80)
                .await
                .unwrap_err(),
            "snapshot_not_ready"
        ));
        sqlx::query(
            "UPDATE hosted_snapshots
                SET state = 'ready', size_bytes = $2,
                    last_used_at = now() - interval '1 day'
              WHERE id = $1",
        )
        .bind(&row.id)
        .bind(80_i64 << 30)
        .execute(&pool)
        .await
        .unwrap();

        assert!(is_code(
            admit(other.clone(), row.id.clone(), 80).await.unwrap_err(),
            "snapshot_not_found"
        ));
        assert!(is_code(
            admit(creator.clone(), "no-such-snapshot".into(), 80)
                .await
                .unwrap_err(),
            "snapshot_not_found"
        ));
        assert!(is_code(
            admit(creator.clone(), row.id.clone(), 79)
                .await
                .unwrap_err(),
            "snapshot_disk_too_small"
        ));
        let used = || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT last_used_at > now() - interval '1 minute'
                   FROM hosted_snapshots WHERE id = $1",
            )
            .bind(&row.id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        assert!(!used().await, "a refused create is not a use");
        admit(creator.clone(), row.id.clone(), 80).await.unwrap();
        assert!(used().await, "a create counts as a use");

        // While an environment is being created from it, its volume may not
        // exist yet to hold the snapshot, so it can't be deleted.
        let environment = format!("env-fork-{}", uuid::Uuid::new_v4().simple());
        const PROJECT_SPEC: &str = r#"{"schema_version":1,"working_directory":"/workspace"}"#;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
             VALUES ($1, $2, 'Fork test', $1, $3::jsonb)",
        )
        .bind(&environment)
        .bind(&org)
        .bind(PROJECT_SPEC)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environments
               (id, org_id, created_by, type, preset_id, project_spec, state, source_snapshot_id)
             VALUES ($1, $2, $3, 'sandbox', $1, $4::jsonb, 'creating', $5)",
        )
        .bind(&environment)
        .bind(&org)
        .bind(&creator)
        .bind(PROJECT_SPEC)
        .bind(&row.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(is_code(
            mark_deleting(&pool, &creator, &org, &row.id)
                .await
                .unwrap_err(),
            "snapshot_in_use"
        ));
        assert_eq!(
            creators_snapshot(&pool, &creator, &org, &row.id)
                .await
                .unwrap()
                .state,
            "ready"
        );
        sqlx::query("UPDATE environments SET state = 'running' WHERE id = $1")
            .bind(&environment)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            mark_deleting(&pool, &creator, &org, &row.id)
                .await
                .unwrap()
                .state,
            "deleting"
        );
        assert!(is_code(
            admit(creator.clone(), row.id.clone(), 80)
                .await
                .unwrap_err(),
            "snapshot_not_ready"
        ));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_a_snapshot_is_private_to_its_creator_and_a_capture_cannot_be_deleted() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let (creator, other, org) = seed(&pool).await;

        let row = insert_snapshot(&pool, &creator, &org, "env-gone", "one")
            .await
            .unwrap();
        assert_eq!(row.state, "capturing");
        assert!(row.size_bytes.is_none());

        // Taken for this creator, and free for another member.
        let taken = insert_snapshot(&pool, &creator, &org, "env-gone", "one")
            .await
            .unwrap_err();
        assert!(matches!(
            taken,
            AppError::Coded {
                code: "snapshot_name_taken",
                ..
            }
        ));
        let others = insert_snapshot(&pool, &other, &org, "env-other", "one")
            .await
            .unwrap();

        // Another member of the organization neither sees nor deletes it.
        let listed = creators_snapshots(&pool, &creator, &org).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, row.id);
        for result in [
            creators_snapshot(&pool, &other, &org, &row.id).await,
            mark_deleting(&pool, &other, &org, &row.id).await,
            creators_snapshot(&pool, &creator, "another-org", &row.id).await,
        ] {
            assert!(matches!(
                result.unwrap_err(),
                AppError::Coded {
                    code: "snapshot_not_found",
                    ..
                }
            ));
        }

        // Bounds: at most four captures at once, then a full organization.
        let mut extra = Vec::new();
        for index in 0..2 {
            let row = insert_snapshot(&pool, &creator, &org, "env", &format!("busy-{index}"))
                .await
                .unwrap();
            extra.push(row.id);
        }
        // `row`, `others` and these two are the bound's four captures.
        let refused = insert_snapshot(&pool, &creator, &org, "env", "fifth")
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            AppError::Coded {
                code: "too_many_captures",
                ..
            }
        ));
        sqlx::query("UPDATE hosted_snapshots SET state = 'ready' WHERE id = ANY($1)")
            .bind(&extra)
            .execute(&pool)
            .await
            .unwrap();
        for index in 0..MAX_SNAPSHOTS_PER_ORG - 4 {
            sqlx::query(
                "INSERT INTO hosted_snapshots
                   (org_id, created_by, source_environment_id, name, state)
                 VALUES ($1, $2, 'env', $3, 'ready')",
            )
            .bind(&org)
            .bind(&creator)
            .bind(format!("full-{index}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let refused = insert_snapshot(&pool, &creator, &org, "env", "one-too-many")
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            AppError::Coded {
                code: "snapshot_limit_reached",
                ..
            }
        ));
        sqlx::query(
            "DELETE FROM hosted_snapshots
              WHERE org_id = $1 AND (name LIKE 'full-%' OR name LIKE 'busy-%')",
        )
        .bind(&org)
        .execute(&pool)
        .await
        .unwrap();

        // Only the environment's creator may capture it: not another member,
        // and not for an environment of another organization.
        let environment = format!("env-snapshot-{}", uuid::Uuid::new_v4().simple());
        const PROJECT_SPEC: &str = r#"{"schema_version":1,"working_directory":"/workspace"}"#;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
             VALUES ($1, $2, 'Snapshot test', $1, $3::jsonb)",
        )
        .bind(&environment)
        .bind(&org)
        .bind(PROJECT_SPEC)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec)
             VALUES ($1, $2, $3, 'sandbox', $1, $4::jsonb)",
        )
        .bind(&environment)
        .bind(&org)
        .bind(&creator)
        .bind(PROJECT_SPEC)
        .execute(&pool)
        .await
        .unwrap();
        require_environment_creator(&pool, &creator, &org, &environment)
            .await
            .unwrap();
        for (user, in_org) in [(&other, org.as_str()), (&creator, "another-org")] {
            assert!(matches!(
                require_environment_creator(&pool, user, in_org, &environment)
                    .await
                    .unwrap_err(),
                AppError::Coded {
                    code: "access_denied",
                    ..
                }
            ));
        }
        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(&environment)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&environment)
            .execute(&pool)
            .await
            .unwrap();

        // A capture in progress can't be deleted, even by its creator.
        assert!(mark_deleting(&pool, &creator, &org, &row.id).await.is_err());
        sqlx::query("UPDATE hosted_snapshots SET state = 'ready' WHERE id = $1")
            .bind(&row.id)
            .execute(&pool)
            .await
            .unwrap();
        let deleting = mark_deleting(&pool, &creator, &org, &row.id).await.unwrap();
        assert_eq!(deleting.state, "deleting");
        // A retried delete finds it again and starts the same workflow.
        mark_deleting(&pool, &creator, &org, &row.id).await.unwrap();

        sqlx::query("DELETE FROM hosted_snapshots WHERE id = ANY($1)")
            .bind(vec![row.id, others.id])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![creator, other])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn snapshot_names_are_one_visible_token() {
        for valid in ["good-toolchain", "a", "v1.2_rc-3", &"x".repeat(128)] {
            assert!(valid_snapshot_name(valid), "{valid}");
        }
        for invalid in [
            "",
            "-leading",
            ".hidden",
            "has space",
            "new\nline",
            "slash/name",
            "é",
            &"x".repeat(129),
        ] {
            assert!(!valid_snapshot_name(invalid), "{invalid:?}");
        }
    }
}
