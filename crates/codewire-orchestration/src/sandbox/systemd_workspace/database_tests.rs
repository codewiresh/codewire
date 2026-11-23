//! Disposable-PostgreSQL proof of the systemd workspace's organization opt-in
//! at a bring-up, of the reconciler's stop after it goes off, and of a fork
//! taking its source's record. Only synthetic rows are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;
use crate::test_database_support::TestDatabase;

const ORGANIZATION: &str = "systemd-organization";
const MEMBER: &str = "fixture-admin";
const OUTSIDER: &str = "systemd-outsider";

fn caller(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn pinned() -> String {
    format!(
        "registry.example.invalid/codewire/workspace-systemd@sha256:{}",
        "0123456789abcdef".repeat(4)
    )
}

fn offering() -> RuntimeImages {
    RuntimeImages::example()
        .with_systemd_workspace_repository("registry.example.invalid/codewire/workspace-systemd")
        .unwrap()
}

async fn opt_in(pool: &PgPool, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE organizations SET systemd_environments_enabled = $2 WHERE id = $1")
        .bind(ORGANIZATION)
        .bind(enabled)
        .execute(pool)
        .await?;
    Ok(())
}

async fn environment(
    pool: &PgPool,
    id: &str,
    state: &str,
    systemd_workspace: bool,
    image: &str,
) -> Result<()> {
    recorded_environment(pool, id, state, systemd_workspace, image, None).await
}

async fn recorded_environment(
    pool: &PgPool,
    id: &str,
    state: &str,
    systemd_workspace: bool,
    image: &str,
    profile: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, desired_state, \
         project_spec, systemd_workspace, systemd_runtime_profile) \
         VALUES ($1, $2, $3, 'sandbox', $2, $4, 'started', jsonb_build_object('image', $5::text), \
         $6, $7)",
    )
    .bind(id)
    .bind(ORGANIZATION)
    .bind(MEMBER)
    .bind(state)
    .bind(image)
    .bind(systemd_workspace)
    .bind(profile)
    .execute(pool)
    .await?;
    Ok(())
}

async fn bring_up(pool: &PgPool, images: &RuntimeImages, user: &str) -> Result<(), &'static str> {
    bring_up_on(pool, images, user, "commodity").await
}

async fn bring_up_on(
    pool: &PgPool,
    images: &RuntimeImages,
    user: &str,
    runtime_profile: &str,
) -> Result<(), &'static str> {
    require_bring_up_with(
        pool,
        images,
        &caller(user),
        ORGANIZATION,
        BringUp {
            systemd_workspace: true,
            image: &pinned(),
            isolation_tier: "standard",
            runtime_profile,
        },
    )
    .await
    .map_err(|error| match error {
        AppError::Coded { code, .. } => code,
        _ => "uncoded",
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_bring_up_needs_the_opt_in_and_only_a_member_learns_of_it() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(OUTSIDER).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        let images = offering();

        // Off by default: a member is told why.
        ensure!(bring_up(pool, &images, MEMBER).await == Err("systemd_workspace_not_enabled"));
        // On `standard` none is needed: its Pod is not loosened.
        ensure!(bring_up_on(pool, &images, MEMBER, "standard").await == Ok(()));
        // Anyone else gets the refusal for an organization they are not in.
        ensure!(bring_up(pool, &images, OUTSIDER).await == Err("org_not_found"));

        opt_in(pool, true).await?;
        ensure!(bring_up(pool, &images, MEMBER).await == Ok(()));
        ensure!(bring_up(pool, &images, OUTSIDER).await == Err("org_not_found"));
        // The deployment's checks come first, whatever the flag.
        ensure!(
            bring_up(pool, &RuntimeImages::example(), MEMBER).await
                == Err("systemd_workspace_not_offered")
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_after_the_opt_in_goes_off_only_a_bring_up_is_stopped() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        environment(pool, "systemd-running", "running", true, &pinned()).await?;
        environment(pool, "systemd-starting", "starting", true, &pinned()).await?;
        environment(pool, "systemd-creating", "creating", true, &pinned()).await?;
        environment(pool, "plain-starting", "starting", false, &pinned()).await?;
        let images = offering();

        opt_in(pool, true).await?;
        ensure!(
            crate::worker::systemd_stop::refused_environment_ids(pool, &images, "commodity")
                .await?
                .is_empty()
        );

        // The flag goes off: a restart or replacement under way is stopped,
        // and the running one keeps running until its next bring-up.
        opt_in(pool, false).await?;
        let refused =
            crate::worker::systemd_stop::refused_environment_ids(pool, &images, "commodity")
                .await?;
        ensure!(
            refused == ["systemd-creating", "systemd-starting"],
            "{refused:?}"
        );

        // A `standard` deployment reads each one's recorded profile, never
        // its current disk: one created on `standard` is not stopped with the
        // flag off, whatever disk the deployment boots now (a republish); one
        // created on `commodity`, or before the record (read as `commodity`),
        // is.
        recorded_environment(
            pool,
            "standard-starting",
            "starting",
            true,
            &pinned(),
            Some("standard"),
        )
        .await?;
        recorded_environment(
            pool,
            "commodity-starting",
            "starting",
            true,
            &pinned(),
            Some("commodity"),
        )
        .await?;
        let refused =
            crate::worker::systemd_stop::refused_environment_ids(pool, &images, "standard").await?;
        ensure!(
            refused == ["commodity-starting", "systemd-creating", "systemd-starting"],
            "{refused:?}"
        );
        // A `commodity` deployment renders every one on `commodity`.
        let refused =
            crate::worker::systemd_stop::refused_environment_ids(pool, &images, "commodity")
                .await?;
        ensure!(
            refused
                == [
                    "commodity-starting",
                    "standard-starting",
                    "systemd-creating",
                    "systemd-starting"
                ],
            "{refused:?}"
        );
        sqlx::query(
            "DELETE FROM environments WHERE id IN ('standard-starting', 'commodity-starting')",
        )
        .execute(pool)
        .await?;

        // The deployment stops offering it, the flag on: the same.
        opt_in(pool, true).await?;
        let refused = crate::worker::systemd_stop::refused_environment_ids(
            pool,
            &RuntimeImages::example(),
            "commodity",
        )
        .await?;
        ensure!(
            refused == ["systemd-creating", "systemd-starting"],
            "{refused:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_fork_takes_its_source_record() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        environment(pool, "plain-source", "stopped", false, "python:3.12").await?;
        environment(pool, "systemd-source", "stopped", true, &pinned()).await?;
        for (snapshot, source) in [
            ("plain-snapshot", "plain-source"),
            ("systemd-snapshot", "systemd-source"),
        ] {
            sqlx::query(
                "INSERT INTO hosted_snapshots (id, org_id, created_by, source_environment_id, \
                 name, state, size_bytes) VALUES ($1, $2, $3, $4, $1, 'ready', 1)",
            )
            .bind(snapshot)
            .bind(ORGANIZATION)
            .bind(MEMBER)
            .bind(source)
            .execute(pool)
            .await?;
        }
        let fork = |snapshot| CreateKind {
            image: "",
            isolation_tier: "standard",
            runtime_profile: "commodity",
            source_snapshot_id: Some(snapshot),
            placed_on_host: false,
        };
        // A plain source forks plain, whatever image the fork names.
        let image = pinned();
        let plain = admit_create(
            pool,
            &caller(MEMBER),
            ORGANIZATION,
            CreateKind {
                image: &image,
                ..fork("plain-snapshot")
            },
        )
        .await;
        ensure!(matches!(plain, Ok(None)), "{plain:?}");
        // A systemd source forks systemd, so it passes the bring-up checks
        // afresh: this test deployment does not offer systemd workspaces.
        let systemd = admit_create(
            pool,
            &caller(MEMBER),
            ORGANIZATION,
            fork("systemd-snapshot"),
        )
        .await;
        ensure!(
            matches!(
                systemd,
                Err(AppError::Coded {
                    code: "systemd_workspace_not_offered",
                    ..
                })
            ),
            "{systemd:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
