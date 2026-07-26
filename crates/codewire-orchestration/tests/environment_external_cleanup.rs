//! DB-backed acceptance for the durable environment external-cleanup marker.

use codewire_orchestration::lifecycle::{PgLifecycleStore, Service};
use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, unresolved_organization_mutation_leases,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

struct Fixture {
    user_id: String,
    org_id: String,
    preset_id: String,
    env_id: String,
}

async fn pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset — skipping environment external cleanup DB flow");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect environment external cleanup test database"),
    )
}

async fn seed(pool: &PgPool, state: &str) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        user_id: format!("u_envcleanup_{suffix}"),
        org_id: format!("org_envcleanup_{suffix}"),
        preset_id: format!("preset_envcleanup_{suffix}"),
        env_id: format!("env_envcleanup_{suffix}"),
    };
    sqlx::query(
        r#"INSERT INTO users (id, email, name, email_verified, is_admin)
           VALUES ($1, $2, 'Environment cleanup test', true, false)"#,
    )
    .bind(&fixture.user_id)
    .bind(format!("{suffix}@example.test"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, created_by)
           VALUES ($1, 'Environment cleanup test', $2, $3)"#,
    )
    .bind(&fixture.org_id)
    .bind(format!("envcleanup-{suffix}"))
    .bind(&fixture.user_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environment_presets (id, org_id, name, slug)
           VALUES ($1, $2, 'Environment cleanup preset', $3)"#,
    )
    .bind(&fixture.preset_id)
    .bind(&fixture.org_id)
    .bind(format!("envcleanup-preset-{suffix}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id)
           VALUES ($1, $2, $3, 'sandbox', $4, 'destroyed', $5)"#,
    )
    .bind(&fixture.env_id)
    .bind(&fixture.org_id)
    .bind(&fixture.user_id)
    .bind(state)
    .bind(&fixture.preset_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO sandbox_environment_backend
               (environment_id, namespace, sandbox_claim_name, pod_name)
           VALUES ($1, 'test-sandboxes', $2, $2)"#,
    )
    .bind(&fixture.env_id)
    .bind(format!("sandbox-{}", fixture.env_id))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO sandbox_running_sessions
               (environment_id, organization_id, runtime_uid, runtime_name,
                runtime_namespace, cpu_millicores, memory_mib, disk_gib,
                started_at, last_observed_at)
           VALUES ($1, $2, $3, $3, 'test-sandboxes', 1000, 1024, 10, NOW(), NOW())"#,
    )
    .bind(&fixture.env_id)
    .bind(&fixture.org_id)
    .bind(format!("runtime-{suffix}"))
    .execute(pool)
    .await
    .unwrap();
    fixture
}

async fn cleanup(pool: &PgPool, fixture: &Fixture) {
    let _ = sqlx::query("DELETE FROM organization_mutation_leases WHERE organization_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM environments WHERE id = $1")
        .bind(&fixture.env_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM environment_presets WHERE id = $1")
        .bind(&fixture.preset_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&fixture.user_id)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn normal_destroy_closes_sessions_removes_backend_and_marks_atomically() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, false)
        .await
        .unwrap();

    let proof: (String, bool, bool) = sqlx::query_as(
        r#"SELECT state, destroyed_at IS NOT NULL,
                  external_cleanup_completed_at IS NOT NULL
           FROM environments WHERE id = $1"#,
    )
    .bind(&fixture.env_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(proof, ("destroyed".into(), true, true));
    let backend_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(&fixture.env_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(backend_count, 0);
    let open_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sandbox_running_sessions WHERE environment_id = $1 AND ended_at IS NULL",
    )
    .bind(&fixture.env_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(open_sessions, 0);
    assert!(matches!(
        acquire_environment_runtime_mutation_lease(&pool, &fixture.org_id, &fixture.env_id).await,
        Err(AppError::Conflict(_))
    ));
    assert!(
        unresolved_organization_mutation_leases(&pool, &fixture.org_id)
            .await
            .unwrap()
            .is_empty(),
        "a post-cleanup admission rejection must release its lease"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn historical_destroyed_row_is_verified_not_backfilled_by_assumption() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroyed").await;
    let before: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT external_cleanup_completed_at FROM environments WHERE id = $1")
            .bind(&fixture.env_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(before.is_none());

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, true)
        .await
        .unwrap();
    let after: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT external_cleanup_completed_at FROM environments WHERE id = $1")
            .bind(&fixture.env_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(after.is_some());

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn runtime_lease_and_port_discovery_each_block_the_marker() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    let lease_id = format!("organization-mutation/{}", Uuid::new_v4());
    sqlx::query(
        r#"INSERT INTO organization_mutation_leases
               (id, organization_id, mutation_class, deadline_at)
           VALUES ($1, $2, 'environment_runtime_dispatch', NOW() + INTERVAL '60 seconds')"#,
    )
    .bind(&lease_id)
    .bind(&fixture.org_id)
    .execute(&pool)
    .await
    .unwrap();

    let service = Service::<PgLifecycleStore>::for_pool(pool.clone());
    assert!(
        service
            .complete_external_cleanup(&fixture.env_id, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("preconditions")
    );
    sqlx::query(
        r#"UPDATE organization_mutation_leases
           SET state = 'released', released_at = NOW(), updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(&lease_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environment_ports
               (environment_id, port, label, access, dns_record_id)
           VALUES ($1, 8080, 'web', 'creator', 'retained-provider-id')"#,
    )
    .bind(&fixture.env_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        service
            .complete_external_cleanup(&fixture.env_id, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("preconditions")
    );
    sqlx::query("UPDATE environment_ports SET dns_record_id = NULL WHERE environment_id = $1")
        .bind(&fixture.env_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        service
            .complete_external_cleanup(&fixture.env_id, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("preconditions")
    );
    sqlx::query("DELETE FROM environment_ports WHERE environment_id = $1")
        .bind(&fixture.env_id)
        .execute(&pool)
        .await
        .unwrap();
    service
        .complete_external_cleanup(&fixture.env_id, false)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}
