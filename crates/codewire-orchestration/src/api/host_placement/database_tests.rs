//! What `resolve_host` admits against a real schema (#3609 slice 2): a host
//! by name or ID; who may place on it; offline, revoked and owner-left
//! hosts; and its VM count, which holds a slot while a VM may exist.

use codewire_server_core::AppError;

use super::*;
use crate::test_database_support::TestDatabase;

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn code(error: AppError) -> String {
    match error {
        AppError::Coded { code, .. } => code.to_owned(),
        other => format!("{other:?}"),
    }
}

fn small() -> HostRequest<'static> {
    HostRequest {
        isolation_tier: "standard",
        image: "",
        repositories: 0,
        secrets: false,
        credentials: false,
        network: false,
        network_policy: false,
        source_snapshot: false,
        cpu_millicores: 1000,
        memory_mib: 2048,
        disk_gib: 10,
    }
}

/// An organization with its owner, a member and a second member, a preset,
/// and the owner's host `box`: online, providing, room for one VM.
async fn fixture(db: &TestDatabase) -> anyhow::Result<String> {
    db.organization("place-org").await?;
    for (user, role) in [
        ("place-owner", "owner"),
        ("place-alice", "member"),
        ("place-bob", "member"),
    ] {
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(&db.pool)
            .await?;
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, 'place-org', $2, $3)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user)
        .bind(role)
        .execute(&db.pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
         VALUES ('place-preset', 'place-org', 'Preset', 'ready', '{}'::jsonb)",
    )
    .execute(&db.pool)
    .await?;
    Ok(sqlx::query_scalar(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
         public_key, provide, max_vms, last_seen_at) VALUES ('place-org', 'place-owner', 'box', \
         'linux-x86_64-kvm', $1, decode(repeat('09', 32), 'hex'), true, 1, now()) RETURNING id",
    )
    .bind(HOST_LIFECYCLE_CAPABILITY)
    .fetch_one(&db.pool)
    .await?)
}

async fn resolve(db: &TestDatabase, user: &str, host: &str) -> AppResult<String> {
    let mut transaction = db.pool.begin().await.unwrap();
    let resolved = resolve_host(
        &mut transaction,
        "place-org",
        &session(user),
        host,
        &small(),
    )
    .await;
    transaction.rollback().await.unwrap();
    resolved
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_is_admitted_only_for_those_who_may_use_it_while_it_can_run() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = fixture(&db).await?;

        // The owner, by name or by ID.
        anyhow::ensure!(resolve(&db, "place-owner", "box").await.unwrap() == host_id);
        anyhow::ensure!(resolve(&db, "place-owner", &host_id).await.unwrap() == host_id);
        anyhow::ensure!(code(resolve(&db, "place-owner", "other").await.unwrap_err()) == "host_not_found");

        // A member needs a grant: a named one, or the organization's.
        anyhow::ensure!(code(resolve(&db, "place-alice", "box").await.unwrap_err()) == "host_not_found");
        sqlx::query("INSERT INTO host_grants (host_id, user_id) VALUES ($1, 'place-alice')")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(resolve(&db, "place-alice", "box").await.is_ok());
        anyhow::ensure!(code(resolve(&db, "place-bob", "box").await.unwrap_err()) == "host_not_found");
        sqlx::query("UPDATE hosts SET organization_grant = true WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(resolve(&db, "place-bob", "box").await.is_ok());

        // Offline: last heard from longer ago than the online window.
        sqlx::query("UPDATE hosts SET last_seen_at = now() - interval '1 minute' WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(code(resolve(&db, "place-owner", "box").await.unwrap_err()) == "host_offline");
        sqlx::query("UPDATE hosts SET last_seen_at = now() WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;

        // The owner left the organization: their grants stop working.
        sqlx::query("DELETE FROM org_members WHERE org_id = 'place-org' AND user_id = 'place-owner'")
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(code(resolve(&db, "place-bob", "box").await.unwrap_err()) == "host_owner_left");
        sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, 'place-org', 'place-owner', 'owner')")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&db.pool)
            .await?;

        // Revoked.
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(code(resolve(&db, "place-owner", "box").await.unwrap_err()) == "host_revoked");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_holds_up_to_its_vm_count_while_its_vms_may_exist() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = fixture(&db).await?;
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, \
             runtime_backend, host_id, cpu_millicores, memory_mb, disk_gb) VALUES \
             ('place-env', 'place-org', 'place-owner', 'sandbox', 'place-preset', '{}'::jsonb, \
              'host', $1, 1000, 2048, 10)",
        )
        .bind(&host_id)
        .execute(&db.pool)
        .await?;
        let error = resolve(&db, "place-owner", "box").await.unwrap_err();
        anyhow::ensure!(format!("{error}").contains("VM limit"), "{error}");
        anyhow::ensure!(code(error) == "host_full");
        let full = || async { code(resolve(&db, "place-owner", "box").await.unwrap_err()) };
        let set = |sql: &'static str| {
            let pool = db.pool.clone();
            async move { sqlx::query(sql).execute(&pool).await.map(|_| ()) }
        };

        // In error with no VM reported, the slot is free; with a VM still
        // there, or while it's being destroyed, it isn't.
        set("UPDATE environments SET state = 'error' WHERE id = 'place-env'").await?;
        anyhow::ensure!(resolve(&db, "place-owner", "box").await.unwrap() == host_id);
        sqlx::query(
            "INSERT INTO host_environments (host_id, environment_id, local_environment_id, \
             generation, state) VALUES ($1, 'place-env', gen_random_uuid(), 1, 'stopped')",
        )
        .bind(&host_id)
        .execute(&db.pool)
        .await?;
        anyhow::ensure!(full().await == "host_full");
        set("UPDATE environments SET state = 'destroying' WHERE id = 'place-env'").await?;
        anyhow::ensure!(full().await == "host_full");
        set("UPDATE host_environments SET state = 'absent' WHERE environment_id = 'place-env'")
            .await?;
        anyhow::ensure!(full().await == "host_full");

        set("UPDATE environments SET state = 'destroyed' WHERE id = 'place-env'").await?;
        anyhow::ensure!(resolve(&db, "place-owner", "box").await.unwrap() == host_id);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_request_id_returns_its_creators_environment_and_no_one_elses() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        fixture(&db).await?;
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, \
             create_request_id) VALUES ('place-retried', 'place-org', 'place-alice', 'sandbox', \
             'place-preset', '{}'::jsonb, 'req-0123456789abcdef')",
        )
        .execute(&db.pool)
        .await?;
        let lookup = |user: &'static str, request: &'static str| {
            let pool = db.pool.clone();
            async move {
                super::super::create::created_by_request(
                    &pool,
                    &session(user),
                    "place-org",
                    request,
                )
                .await
            }
        };
        let found = lookup("place-alice", "req-0123456789abcdef").await.unwrap();
        anyhow::ensure!(
            found.map(|environment| environment.id).as_deref() == Some("place-retried")
        );
        anyhow::ensure!(
            code(
                lookup("place-bob", "req-0123456789abcdef")
                    .await
                    .unwrap_err()
            ) == "request_id_in_use"
        );
        anyhow::ensure!(
            lookup("place-alice", "req-unused-0123456789")
                .await
                .unwrap()
                .is_none()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
