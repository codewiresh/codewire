//! DB-backed acceptance for the durable environment external-cleanup marker.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use codewire_orchestration::lifecycle::{PgLifecycleStore, RuntimeAbsenceProof, Service};
use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    OrganizationMutationClass, OrganizationMutationLease,
    acquire_environment_runtime_mutation_lease, acquire_organization_mutation_lease,
    mark_organization_mutation_resolution_required, release_organization_mutation_lease,
    unresolved_organization_mutation_leases,
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
        r#"INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
           VALUES ($1, $2, 'Environment cleanup preset', $3,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&fixture.preset_id)
    .bind(&fixture.org_id)
    .bind(format!("envcleanup-preset-{suffix}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
           VALUES ($1, $2, $3, 'sandbox', $4, 'destroyed', $5,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
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
    let _ = sqlx::query("DELETE FROM environments WHERE org_id = $1")
        .bind(&fixture.org_id)
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

/// Open a destroy attempt's runtime absence proof, as the destroy activity does
/// before its first cleanup step.
async fn proof(pool: &PgPool) -> RuntimeAbsenceProof {
    RuntimeAbsenceProof::begin(pool)
        .await
        .expect("read runtime absence proof start")
}

/// Another Sandbox in the fixture's organization that is still running.
async fn seed_running_environment(pool: &PgPool, fixture: &Fixture, name: &str) -> String {
    let env_id = format!("{}_{name}", fixture.env_id);
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
           VALUES ($1, $2, $3, 'sandbox', 'running', 'started', $4,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&env_id)
    .bind(&fixture.org_id)
    .bind(&fixture.user_id)
    .bind(&fixture.preset_id)
    .execute(pool)
    .await
    .unwrap();
    env_id
}

/// Record Sandbox delete intent, as the destroy activity does before cleanup.
async fn begin_destroy(pool: &PgPool, env_id: &str) {
    sqlx::query(
        "UPDATE environments SET state = 'destroying', desired_state = 'destroyed' WHERE id = $1",
    )
    .bind(env_id)
    .execute(pool)
    .await
    .unwrap();
}

/// Admit a runtime dispatch on `env_id` and record its outcome as unknown,
/// like a StopSession whose daemon did not acknowledge within its bound.
async fn ambiguous_dispatch(pool: &PgPool, org_id: &str, env_id: &str) -> String {
    let lease = acquire_environment_runtime_mutation_lease(pool, org_id, env_id)
        .await
        .unwrap();
    assert_eq!(lease.environment_id.as_deref(), Some(env_id));
    mark_ambiguous(pool, &lease.id).await;
    lease.id
}

async fn mark_ambiguous(pool: &PgPool, lease_id: &str) {
    mark_organization_mutation_resolution_required(
        pool,
        lease_id,
        "environment_runtime_dispatch_ambiguous",
    )
    .await
    .unwrap();
}

async fn lease(pool: &PgPool, lease_id: &str) -> OrganizationMutationLease {
    sqlx::query_as("SELECT * FROM organization_mutation_leases WHERE id = $1")
        .bind(lease_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cleanup_marked(pool: &PgPool, env_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT state = 'destroyed' AND external_cleanup_completed_at IS NOT NULL
           FROM environments WHERE id = $1",
    )
    .bind(env_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_cleanup_refused(pool: &PgPool, env_id: &str, proof: RuntimeAbsenceProof) {
    let error = Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(env_id, false, proof)
        .await
        .expect_err("external cleanup marker must stay blocked");
    assert!(error.to_string().contains("preconditions"), "{error:#}");
    assert!(!cleanup_marked(pool, env_id).await);
}

#[tokio::test]
async fn normal_destroy_closes_sessions_removes_backend_and_marks_atomically() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
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
        .complete_external_cleanup(&fixture.env_id, true, proof(&pool).await)
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
            .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
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
            .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
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
            .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
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
        .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

/// A live workspace binding of `env_id` for the Pod `pod_uid`.
async fn insert_live_binding(pool: &PgPool, env_id: &str, pod_uid: &str) {
    sqlx::query(
        r#"INSERT INTO sandbox_workspace_bindings
               (pod_uid, environment_id, namespace, pod_name, claim_uid, sandbox_uid,
                operation_generation, managed_credential_clients, credential_scope)
           VALUES ($1, $2, 'test-sandboxes', $3, $4, $5, 1, '', 'pod')"#,
    )
    .bind(pod_uid)
    .bind(env_id)
    .bind(format!("sandbox-{env_id}"))
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .unwrap();
}

/// Design §10: destroy releases the workspace binding once its Pod is observed
/// absent, so the marker refuses while any binding of the environment is
/// still live. Another environment's live binding never blocks it, and the
/// released row is kept, never deleted.
#[tokio::test]
async fn a_live_workspace_binding_blocks_the_marker() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    let other = seed_running_environment(&pool, &fixture, "other").await;
    let pod = Uuid::new_v4().to_string();
    let other_pod = Uuid::new_v4().to_string();
    insert_live_binding(&pool, &fixture.env_id, &pod).await;
    insert_live_binding(&pool, &other, &other_pod).await;

    assert_cleanup_refused(&pool, &fixture.env_id, proof(&pool).await).await;

    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
          WHERE pod_uid = $1",
    )
    .bind(&pod)
    .execute(&pool)
    .await
    .unwrap();
    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
        .await
        .expect("a released binding and another environment's live one must not block");
    assert!(cleanup_marked(&pool, &fixture.env_id).await);
    let mut rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT pod_uid, released_at IS NULL FROM sandbox_workspace_bindings \
          WHERE environment_id = ANY($1)",
    )
    .bind(vec![fixture.env_id.clone(), other.clone()])
    .fetch_all(&pool)
    .await
    .unwrap();
    rows.sort();
    let mut expected = vec![(pod, false), (other_pod, true)];
    expected.sort();
    assert_eq!(rows, expected);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn ambiguous_dispatch_on_another_environment_does_not_block_cleanup() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    // Sandbox A keeps running with one dispatch whose outcome is unknown and
    // one still in flight. Neither can change the Sandbox being deleted.
    let other = seed_running_environment(&pool, &fixture, "other").await;
    let ambiguous = ambiguous_dispatch(&pool, &fixture.org_id, &other).await;
    let in_flight = acquire_environment_runtime_mutation_lease(&pool, &fixture.org_id, &other)
        .await
        .unwrap();

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
        .await
        .expect("another Sandbox's runtime dispatches must not block this delete");
    assert!(cleanup_marked(&pool, &fixture.env_id).await);

    // This proof says nothing about Sandbox A, so its evidence is untouched.
    assert_eq!(lease(&pool, &ambiguous).await.state, "resolution_required");
    assert_eq!(lease(&pool, &in_flight.id).await.state, "active");
    release_organization_mutation_lease(&pool, &in_flight.id)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn own_ambiguous_dispatch_is_resolved_once_runtime_absence_is_proven() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    let target = seed_running_environment(&pool, &fixture, "target").await;
    // The Dev failure: closing a terminal recorded an ambiguous StopSession,
    // then the same Sandbox was deleted.
    let ambiguous = ambiguous_dispatch(&pool, &fixture.org_id, &target).await;
    begin_destroy(&pool, &target).await;

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&target, false, proof(&pool).await)
        .await
        .expect("a proof that began after the ambiguity settled covers it");
    assert!(cleanup_marked(&pool, &target).await);
    let resolved = lease(&pool, &ambiguous).await;
    assert_eq!(resolved.state, "resolved");
    assert!(resolved.resolved_at.is_some());
    assert_eq!(
        resolved.recovery_code.as_deref(),
        Some("environment_runtime_dispatch_ambiguous"),
        "resolution keeps the original ambiguity evidence"
    );
    assert!(
        unresolved_organization_mutation_leases(&pool, &fixture.org_id)
            .await
            .unwrap()
            .is_empty(),
        "the destroyed Sandbox leaves no unresolved runtime lease behind"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn ambiguity_that_settles_during_the_proof_waits_for_the_next_attempt() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    let target = seed_running_environment(&pool, &fixture, "target").await;
    // Admitted before the delete; its outcome became unknown only after this
    // attempt had started removing the runtime, so it may have acted since.
    let in_flight = acquire_environment_runtime_mutation_lease(&pool, &fixture.org_id, &target)
        .await
        .unwrap();
    begin_destroy(&pool, &target).await;
    let first_attempt = proof(&pool).await;
    mark_ambiguous(&pool, &in_flight.id).await;

    assert_cleanup_refused(&pool, &target, first_attempt).await;
    assert_eq!(
        lease(&pool, &in_flight.id).await.state,
        "resolution_required"
    );

    // The retry proves absence again after the ambiguity settled.
    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&target, false, proof(&pool).await)
        .await
        .expect("a later attempt covers the settled ambiguity");
    assert!(cleanup_marked(&pool, &target).await);
    assert_eq!(lease(&pool, &in_flight.id).await.state, "resolved");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn in_flight_dispatch_on_the_same_environment_still_blocks_cleanup() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    let target = seed_running_environment(&pool, &fixture, "target").await;
    let in_flight = acquire_environment_runtime_mutation_lease(&pool, &fixture.org_id, &target)
        .await
        .unwrap();
    begin_destroy(&pool, &target).await;

    assert_cleanup_refused(&pool, &target, proof(&pool).await).await;
    // Lease expiry alone is never proof that the dispatch stopped acting.
    sqlx::query(
        r#"UPDATE organization_mutation_leases
           SET admitted_at = NOW() - INTERVAL '2 minutes',
               deadline_at = NOW() - INTERVAL '1 minute'
           WHERE id = $1"#,
    )
    .bind(&in_flight.id)
    .execute(&pool)
    .await
    .unwrap();
    assert_cleanup_refused(&pool, &target, proof(&pool).await).await;
    assert_eq!(
        lease(&pool, &in_flight.id).await.state,
        "active",
        "cleanup never settles a dispatch that is still running"
    );

    // Only the dispatch's own known outcome releases it.
    release_organization_mutation_lease(&pool, &in_flight.id)
        .await
        .unwrap();
    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&target, false, proof(&pool).await)
        .await
        .unwrap();
    assert_eq!(lease(&pool, &in_flight.id).await.state, "released");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn organization_wide_ambiguity_blocks_only_until_a_later_proof() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool, "destroying").await;
    // Environment creation, and every lease admitted before leases recorded
    // their environment, may target any environment of the organization.
    let organization_wide = acquire_organization_mutation_lease(
        &pool,
        &fixture.org_id,
        OrganizationMutationClass::EnvironmentRuntimeDispatch,
    )
    .await
    .unwrap();
    assert_eq!(organization_wide.environment_id, None);
    let first_attempt = proof(&pool).await;
    mark_ambiguous(&pool, &organization_wide.id).await;

    assert_cleanup_refused(&pool, &fixture.env_id, first_attempt).await;

    Service::<PgLifecycleStore>::for_pool(pool.clone())
        .complete_external_cleanup(&fixture.env_id, false, proof(&pool).await)
        .await
        .expect("a proof that began after the ambiguity settled covers this Sandbox");
    assert!(cleanup_marked(&pool, &fixture.env_id).await);
    // It may concern another environment, so only organization deletion,
    // after proving every environment, may resolve it.
    assert_eq!(
        lease(&pool, &organization_wide.id).await.state,
        "resolution_required"
    );

    cleanup(&pool, &fixture).await;
}
