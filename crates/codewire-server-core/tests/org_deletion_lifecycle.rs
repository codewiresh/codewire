//! DB-backed organization-deletion lifecycle bridge acceptance.
//!
//! The database capability gate runs this suite with `DATABASE_URL` and
//! rejects the skip sentinel or an unexpected executed-test count.

use std::time::Duration;

use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, OrganizationDeletionOperation, OrganizationDeletionPhase,
    OrganizationMutationClass, OrganizationRuntimeMutationError,
    OrganizationTenantSecretMutationError, acquire_organization_mutation_lease,
    advance_organization_deletion_phase, begin_organization_deletion,
    finalize_organization_deletion_database, mark_organization_deletion_failed,
    mark_organization_deletion_started, mark_organization_mutation_resolution_required,
    pending_organization_deletion_operations, record_organization_deletion_start_attempt,
    release_organization_mutation_lease, require_organization_mutation_barrier_drained,
    resolve_organization_mutation_lease, run_organization_billing_mutation,
    run_organization_database_mutation, run_organization_runtime_mutation,
    run_organization_tenant_secret_mutation, unresolved_organization_mutation_leases,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

struct Fixture {
    owner: AuthUser,
    alternate_owner: AuthUser,
    member: AuthUser,
    org_id: String,
    api_key_id: String,
}

async fn pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset — skipping organization deletion lifecycle DB flow");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("connect organization deletion lifecycle test database"),
    )
}

async fn seed(pool: &PgPool) -> Fixture {
    let namespace = Uuid::new_v4().simple().to_string();
    let owner_id = format!("u_orgdel_{namespace}_owner");
    let alternate_owner_id = format!("u_orgdel_{namespace}_alternate_owner");
    let member_id = format!("u_orgdel_{namespace}_member");
    let org_id = format!("org_orgdel_{namespace}");
    let api_key_id = format!("ak_orgdel_{namespace}");

    for (id, label) in [
        (&owner_id, "owner"),
        (&alternate_owner_id, "alternate-owner"),
        (&member_id, "member"),
    ] {
        sqlx::query(
            r#"INSERT INTO users (id, email, name, email_verified, is_admin)
               VALUES ($1, $2, $3, true, false)"#,
        )
        .bind(id)
        .bind(format!("{namespace}-{label}@example.test"))
        .bind(format!("Org deletion {label}"))
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, created_by)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(&org_id)
    .bind(format!("Org deletion {namespace}"))
    .bind(format!("orgdel-{namespace}"))
    .bind(&owner_id)
    .execute(pool)
    .await
    .unwrap();
    for (id, user_id, role) in [
        (format!("om_orgdel_{namespace}_owner"), &owner_id, "owner"),
        (
            format!("om_orgdel_{namespace}_alternate_owner"),
            &alternate_owner_id,
            "owner",
        ),
        (
            format!("om_orgdel_{namespace}_member"),
            &member_id,
            "member",
        ),
    ] {
        sqlx::query(
            r#"INSERT INTO org_members (id, org_id, user_id, role)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(id)
        .bind(&org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query(
        r#"INSERT INTO api_keys
               (id, user_id, org_id, name, key_hash, key_prefix, scopes)
           VALUES ($1, $2, $3, 'org deletion fixture', $4, 'cw_test', ARRAY[]::text[])"#,
    )
    .bind(&api_key_id)
    .bind(&owner_id)
    .bind(&org_id)
    .bind(format!("hash-{namespace}"))
    .execute(pool)
    .await
    .unwrap();

    Fixture {
        owner: AuthUser {
            user_id: owner_id,
            org_id: None,
            is_admin: false,
            via_api_key: false,
        },
        alternate_owner: AuthUser {
            user_id: alternate_owner_id,
            org_id: None,
            is_admin: false,
            via_api_key: false,
        },
        member: AuthUser {
            user_id: member_id,
            org_id: None,
            is_admin: false,
            via_api_key: false,
        },
        org_id,
        api_key_id,
    }
}

async fn cleanup(pool: &PgPool, fixture: &Fixture) {
    let _ = sqlx::query("DELETE FROM api_keys WHERE org_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM org_invitations WHERE org_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM org_members WHERE org_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM organization_deletion_operations WHERE organization_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM organization_mutation_leases WHERE organization_id = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM audit_logs WHERE metadata->>'organization_id' = $1")
        .bind(&fixture.org_id)
        .execute(pool)
        .await;
    for user_id in [
        &fixture.owner.user_id,
        &fixture.alternate_owner.user_id,
        &fixture.member.user_id,
    ] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }
}

async fn complete_billing_phase(pool: &PgPool, operation: &OrganizationDeletionOperation) {
    sqlx::query(
        r#"INSERT INTO organization_deletion_billing_phases
               (operation_id, organization_id, generation, state,
                final_usage_completed_at, checkout_sessions_expired_at,
                subscriptions_verified_at, completed_at)
           VALUES ($1, $2, $3, 'completed', NOW(), NOW(), NOW(), NOW())"#,
    )
    .bind(&operation.id)
    .bind(&operation.organization_id)
    .bind(operation.generation)
    .execute(pool)
    .await
    .unwrap();
}

async fn advance_to_control_plane_reconciled(
    pool: &PgPool,
    operation: &OrganizationDeletionOperation,
) {
    mark_organization_deletion_started(pool, &operation.id, operation.generation)
        .await
        .unwrap();
    advance_organization_deletion_phase(
        pool,
        &operation.id,
        operation.generation,
        OrganizationDeletionPhase::EnvironmentsDestroyed,
    )
    .await
    .unwrap();
    complete_billing_phase(pool, operation).await;
    for phase in [
        OrganizationDeletionPhase::BillingFinalized,
        OrganizationDeletionPhase::TenantSecretsRemoved,
        OrganizationDeletionPhase::ControlPlaneReconciled,
    ] {
        advance_organization_deletion_phase(pool, &operation.id, operation.generation, phase)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn default_active_rows_remain_backward_compatible() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    let lifecycle: (String, i64, Option<String>) = sqlx::query_as(
        r#"SELECT deletion_state, deletion_generation, deletion_operation_id
           FROM organizations WHERE id = $1"#,
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, ("active".to_string(), 0, None));
    let lease = acquire_organization_mutation_lease(
        &pool,
        &fixture.org_id,
        OrganizationMutationClass::ControlPlaneDatabase,
    )
    .await
    .expect("default-active organization admits a mutation");
    assert_eq!(lease.state, "active");
    let released = release_organization_mutation_lease(&pool, &lease.id)
        .await
        .unwrap();
    assert_eq!(released.state, "released");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn begin_is_owner_only_idempotent_and_recoverable() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    assert!(matches!(
        begin_organization_deletion(&pool, &fixture.member, &fixture.org_id).await,
        Err(AppError::Forbidden)
    ));
    let cross_org_key = AuthUser {
        user_id: fixture.owner.user_id.clone(),
        org_id: Some("org_other".to_string()),
        is_admin: false,
        via_api_key: true,
    };
    assert!(matches!(
        begin_organization_deletion(&pool, &cross_org_key, &fixture.org_id).await,
        Err(AppError::NotFound(_))
    ));

    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();
    let repeated = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(operation.id, repeated.id);
    assert_eq!(operation.generation, 1);
    assert_eq!(operation.state, "pending_start");

    let disabled: bool =
        sqlx::query_scalar("SELECT disabled_at IS NOT NULL FROM api_keys WHERE id = $1")
            .bind(&fixture.api_key_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(disabled);
    let audit_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM audit_logs
           WHERE action = 'org.deletion_requested'
             AND metadata->>'organization_id' = $1"#,
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1")
            .bind(&fixture.org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        member_count, 3,
        "owner/recovery membership must be retained"
    );
    assert!(matches!(
        acquire_organization_mutation_lease(
            &pool,
            &fixture.org_id,
            OrganizationMutationClass::ControlPlaneDatabase,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_write_blocked",
            ..
        })
    ));
    let pending = pending_organization_deletion_operations(&pool, 100)
        .await
        .unwrap();
    assert!(pending.iter().any(|candidate| candidate.id == operation.id));

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn failed_generation_retries_forward_and_rejects_stale_work() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let first = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();

    let attempted = record_organization_deletion_start_attempt(&pool, &first.id, 1)
        .await
        .unwrap();
    assert_eq!(attempted.start_attempts, 1);
    let started = mark_organization_deletion_started(&pool, &first.id, 1)
        .await
        .unwrap();
    let started_again = mark_organization_deletion_started(&pool, &first.id, 1)
        .await
        .unwrap();
    assert_eq!(started.started_at, started_again.started_at);

    let failed = mark_organization_deletion_failed(&pool, &first.id, 1, "temporal_failed")
        .await
        .unwrap();
    assert_eq!(failed.state, "failed");
    let failed_again = mark_organization_deletion_failed(&pool, &first.id, 1, "temporal_failed")
        .await
        .unwrap();
    assert_eq!(failed_again.state, "failed");
    let failed_differently =
        mark_organization_deletion_failed(&pool, &first.id, 1, "different_failure")
            .await
            .unwrap();
    assert_eq!(
        failed_differently.failure_code.as_deref(),
        Some("temporal_failed")
    );
    let organization_failure: Option<String> =
        sqlx::query_scalar("SELECT deletion_failure_code FROM organizations WHERE id = $1")
            .bind(&fixture.org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(organization_failure.as_deref(), Some("temporal_failed"));
    assert!(matches!(
        acquire_organization_mutation_lease(
            &pool,
            &fixture.org_id,
            OrganizationMutationClass::ControlPlaneDatabase,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_write_blocked",
            ..
        })
    ));

    let retry = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(retry.generation, 2);
    assert_ne!(retry.id, first.id);
    assert!(matches!(
        mark_organization_deletion_started(&pool, &first.id, 1).await,
        Err(AppError::Coded {
            code: "organization_deletion_stale_generation",
            ..
        })
    ));

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn completed_operation_cannot_be_rewritten_as_failed() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();

    sqlx::query(
        r#"UPDATE organization_deletion_operations
           SET state = 'completed', completed_at = NOW(), updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(&operation.id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(matches!(
        mark_organization_deletion_failed(
            &pool,
            &operation.id,
            operation.generation,
            "late_failure",
        )
        .await,
        Err(AppError::Coded {
            code: "organization_deletion_stale_generation",
            ..
        })
    ));

    let operation_evidence: (String, Option<String>) = sqlx::query_as(
        "SELECT state, failure_code FROM organization_deletion_operations WHERE id = $1",
    )
    .bind(&operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let organization_evidence: (String, Option<String>) = sqlx::query_as(
        "SELECT deletion_state, deletion_failure_code FROM organizations WHERE id = $1",
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(operation_evidence, ("completed".to_string(), None));
    assert_eq!(organization_evidence, ("deleting".to_string(), None));

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn phase_evidence_rejects_provider_and_error_bodies() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();

    let provider_body = "provider response: credential=secret";
    assert!(
        sqlx::query("UPDATE organizations SET deletion_phase = $2 WHERE id = $1")
            .bind(&fixture.org_id)
            .bind(provider_body)
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE organization_deletion_operations SET phase = $2 WHERE id = $1")
            .bind(&operation.id)
            .bind(provider_body)
            .execute(&pool)
            .await
            .is_err()
    );

    let phases: (String, String) = sqlx::query_as(
        r#"SELECT org.deletion_phase, op.phase
           FROM organizations org
           JOIN organization_deletion_operations op ON op.id = org.deletion_operation_id
           WHERE org.id = $1"#,
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        phases,
        ("write_fenced".to_string(), "write_fenced".to_string())
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn pre_fence_lease_admission_serializes_the_deletion_fence_across_pools() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    let mut admission = pool.begin().await.unwrap();
    let state: String =
        sqlx::query_scalar("SELECT deletion_state FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(&fixture.org_id)
            .fetch_one(&mut *admission)
            .await
            .unwrap();
    assert_eq!(state, "active");

    let task_pool = pool.clone();
    let task_owner = fixture.owner.clone();
    let task_org_id = fixture.org_id.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = entered_tx.send(());
        begin_organization_deletion(&task_pool, &task_owner, &task_org_id).await
    });
    entered_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !task.is_finished(),
        "deletion must wait for the admission transaction"
    );

    let lease_id = format!("organization-mutation/{}", Uuid::new_v4());
    sqlx::query(
        r#"INSERT INTO organization_mutation_leases
               (id, organization_id, mutation_class, deadline_at)
           VALUES ($1, $2, 'control_plane_database', NOW() + INTERVAL '30 seconds')"#,
    )
    .bind(&lease_id)
    .bind(&fixture.org_id)
    .execute(&mut *admission)
    .await
    .unwrap();
    admission.commit().await.unwrap();
    let operation = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("deletion resumes after admission commit")
        .unwrap()
        .unwrap();
    assert_eq!(operation.state, "pending_start");
    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, lease_id);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn database_mutation_lease_releases_connections_between_phases() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset — skipping organization deletion lifecycle DB flow");
            return;
        }
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect single-connection organization deletion test pool");
    let fixture = seed(&pool).await;

    let organization_id = fixture.org_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        run_organization_database_mutation(&pool, &fixture.org_id, async {
            let observed: String = sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1")
                .bind(&organization_id)
                .fetch_one(&pool)
                .await
                .map_err(AppError::from)?;
            Ok(observed)
        }),
    )
    .await
    .expect("a one-connection pool must not self-deadlock")
    .unwrap();
    assert_eq!(result, fixture.org_id);

    let cancelled = tokio::time::timeout(
        Duration::from_millis(25),
        run_organization_database_mutation(&pool, &fixture.org_id, async {
            std::future::pending::<Result<(), AppError>>().await
        }),
    )
    .await;
    assert!(cancelled.is_err(), "test mutation should be cancelled");

    let active_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM organization_mutation_leases WHERE organization_id = $1 AND state = 'active'",
    )
    .bind(&fixture.org_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(active_ids.len(), 1, "cancellation must retain evidence");
    release_organization_mutation_lease(&pool, &active_ids[0])
        .await
        .unwrap();

    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_mutation_leases WHERE organization_id = $1 AND state = 'active'",
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 0);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn runtime_mutation_lease_distinguishes_known_ambiguous_and_cancelled_outcomes() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    let value = run_organization_runtime_mutation(&pool, &fixture.org_id, async {
        Ok::<_, OrganizationRuntimeMutationError>("attached")
    })
    .await
    .unwrap();
    assert_eq!(value, "attached");
    assert!(
        unresolved_organization_mutation_leases(&pool, &fixture.org_id)
            .await
            .unwrap()
            .is_empty(),
        "a successful attachment must release its lease"
    );

    let known = run_organization_runtime_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(AppError::Conflict("known runtime rejection".into()).into())
    })
    .await;
    assert!(matches!(known, Err(AppError::Conflict(_))));
    assert!(
        unresolved_organization_mutation_leases(&pool, &fixture.org_id)
            .await
            .unwrap()
            .is_empty(),
        "a known rejection must release its lease"
    );

    let ambiguous = run_organization_runtime_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(OrganizationRuntimeMutationError::ambiguous(
            AppError::ServiceUnavailable("runtime dispatch response was lost".into()),
        ))
    })
    .await;
    assert!(matches!(ambiguous, Err(AppError::ServiceUnavailable(_))));
    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].state, "resolution_required");
    assert_eq!(
        unresolved[0].recovery_code.as_deref(),
        Some("environment_runtime_dispatch_ambiguous")
    );
    resolve_organization_mutation_lease(&pool, &unresolved[0].id)
        .await
        .unwrap();

    let task_pool = pool.clone();
    let task_org_id = fixture.org_id.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        run_organization_runtime_mutation(&task_pool, &task_org_id, async move {
            entered_tx
                .send(())
                .expect("runtime mutation entry receiver remains available");
            std::future::pending::<Result<(), OrganizationRuntimeMutationError>>().await
        })
        .await
    });
    entered_rx
        .await
        .expect("runtime mutation acquires its lease before cancellation");
    task.abort();
    assert!(
        task.await
            .expect_err("runtime mutation task must be cancelled")
            .is_cancelled(),
        "test mutation should be cancelled after lease acquisition"
    );
    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].state, "active");
    release_organization_mutation_lease(&pool, &unresolved[0].id)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn expired_lease_requires_explicit_class_recovery() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let lease = acquire_organization_mutation_lease(
        &pool,
        &fixture.org_id,
        OrganizationMutationClass::TenantSecretProvider,
    )
    .await
    .unwrap();

    sqlx::query(
        r#"UPDATE organization_mutation_leases
           SET admitted_at = NOW() - INTERVAL '2 minutes',
               deadline_at = NOW() - INTERVAL '1 minute'
           WHERE id = $1"#,
    )
    .bind(&lease.id)
    .execute(&pool)
    .await
    .unwrap();
    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1, "age alone is never absence evidence");
    assert_eq!(unresolved[0].state, "active");
    assert!(matches!(
        require_organization_mutation_barrier_drained(&pool, &fixture.org_id).await,
        Err(AppError::Coded {
            code: "organization_mutation_barrier_not_drained",
            ..
        })
    ));

    let ambiguous = mark_organization_mutation_resolution_required(
        &pool,
        &lease.id,
        "provider_timeout_ambiguous",
    )
    .await
    .unwrap();
    assert_eq!(ambiguous.state, "resolution_required");
    assert!(matches!(
        mark_organization_mutation_resolution_required(
            &pool,
            &lease.id,
            "different_recovery_evidence",
        )
        .await,
        Err(AppError::Coded {
            code: "organization_mutation_lease_conflict",
            ..
        })
    ));

    let resolved = resolve_organization_mutation_lease(&pool, &lease.id)
        .await
        .unwrap();
    assert_eq!(resolved.state, "resolved");
    assert!(
        unresolved_organization_mutation_leases(&pool, &fixture.org_id)
            .await
            .unwrap()
            .is_empty()
    );
    require_organization_mutation_barrier_drained(&pool, &fixture.org_id)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn billing_provider_outcomes_release_or_retain_exact_evidence() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    let value = run_organization_billing_mutation(&pool, &fixture.org_id, async {
        Ok::<_, OrganizationBillingMutationError>(7_u8)
    })
    .await
    .unwrap();
    assert_eq!(value, 7);

    let known = run_organization_billing_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(OrganizationBillingMutationError::known(
            AppError::BadRequest("known provider rejection".into()),
        ))
    })
    .await;
    assert!(matches!(known, Err(AppError::BadRequest(_))));

    let ambiguous = run_organization_billing_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(OrganizationBillingMutationError::ambiguous(
            AppError::ServiceUnavailable("ambiguous provider response".into()),
        ))
    })
    .await;
    assert!(matches!(ambiguous, Err(AppError::ServiceUnavailable(_))));

    let all: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"SELECT mutation_class, state, recovery_code
           FROM organization_mutation_leases
           WHERE organization_id = $1 AND mutation_class = 'billing_provider'
           ORDER BY admitted_at, id"#,
    )
    .bind(&fixture.org_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0], ("billing_provider".into(), "released".into(), None));
    assert_eq!(all[1], ("billing_provider".into(), "released".into(), None));
    assert_eq!(
        all[2],
        (
            "billing_provider".into(),
            "resolution_required".into(),
            Some("billing_provider_ambiguous".into()),
        )
    );
    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    resolve_organization_mutation_lease(&pool, &unresolved[0].id)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn tenant_secret_provider_outcomes_release_or_retain_exact_evidence() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;

    let value = run_organization_tenant_secret_mutation(&pool, &fixture.org_id, async {
        Ok::<_, OrganizationTenantSecretMutationError>(11_u8)
    })
    .await
    .unwrap();
    assert_eq!(value, 11);

    let known = run_organization_tenant_secret_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(OrganizationTenantSecretMutationError::known(
            AppError::NotFound("known secret rejection".into()),
        ))
    })
    .await;
    assert!(matches!(known, Err(AppError::NotFound(_))));

    let ambiguous = run_organization_tenant_secret_mutation(&pool, &fixture.org_id, async {
        Err::<(), _>(OrganizationTenantSecretMutationError::ambiguous(
            AppError::ServiceUnavailable("ambiguous secret response".into()),
        ))
    })
    .await;
    assert!(matches!(ambiguous, Err(AppError::ServiceUnavailable(_))));

    let all: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"SELECT mutation_class, state, recovery_code
           FROM organization_mutation_leases
           WHERE organization_id = $1 AND mutation_class = 'tenant_secret_provider'
           ORDER BY admitted_at, id"#,
    )
    .bind(&fixture.org_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        all,
        vec![
            ("tenant_secret_provider".into(), "released".into(), None),
            ("tenant_secret_provider".into(), "released".into(), None),
            (
                "tenant_secret_provider".into(),
                "resolution_required".into(),
                Some("tenant_secret_provider_ambiguous".into()),
            ),
        ]
    );

    let unresolved = unresolved_organization_mutation_leases(&pool, &fixture.org_id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    resolve_organization_mutation_lease(&pool, &unresolved[0].id)
        .await
        .unwrap();

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn nullable_requester_does_not_erase_operation_provenance() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let requester_id = fixture.alternate_owner.user_id.clone();
    let operation = begin_organization_deletion(&pool, &fixture.alternate_owner, &fixture.org_id)
        .await
        .unwrap();

    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&fixture.org_id)
        .bind(&requester_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&requester_id)
        .execute(&pool)
        .await
        .unwrap();

    let organization_requester: Option<String> =
        sqlx::query_scalar("SELECT deletion_requested_by FROM organizations WHERE id = $1")
            .bind(&fixture.org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let operation_requester: String = sqlx::query_scalar(
        "SELECT requested_by FROM organization_deletion_operations WHERE id = $1",
    )
    .bind(&operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(organization_requester, None);
    assert_eq!(operation_requester, requester_id);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn operation_and_audit_survive_the_final_org_boundary() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let lease = acquire_organization_mutation_lease(
        &pool,
        &fixture.org_id,
        OrganizationMutationClass::ControlPlaneDatabase,
    )
    .await
    .unwrap();
    release_organization_mutation_lease(&pool, &lease.id)
        .await
        .unwrap();
    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();

    sqlx::query("DELETE FROM api_keys WHERE org_id = $1")
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM org_members WHERE org_id = $1")
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();

    let operation_survives: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_deletion_operations WHERE id = $1)",
    )
    .bind(&operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let audit_survives: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(SELECT 1 FROM audit_logs
           WHERE action = 'org.deletion_requested'
             AND metadata->>'organization_id' = $1)"#,
    )
    .bind(&fixture.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(operation_survives);
    assert!(audit_survives);
    let lease_survives: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_mutation_leases WHERE id = $1)",
    )
    .bind(&lease.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(lease_survives);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn workflow_phases_are_forward_only_and_idempotent() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();
    mark_organization_deletion_started(&pool, &operation.id, operation.generation)
        .await
        .unwrap();

    assert!(matches!(
        advance_organization_deletion_phase(
            &pool,
            &operation.id,
            operation.generation,
            OrganizationDeletionPhase::BillingFinalized,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_deletion_stale_generation",
            ..
        })
    ));
    let advanced = advance_organization_deletion_phase(
        &pool,
        &operation.id,
        operation.generation,
        OrganizationDeletionPhase::EnvironmentsDestroyed,
    )
    .await
    .unwrap();
    let replayed = advance_organization_deletion_phase(
        &pool,
        &operation.id,
        operation.generation,
        OrganizationDeletionPhase::EnvironmentsDestroyed,
    )
    .await
    .unwrap();
    assert_eq!(advanced.phase, "environments_destroyed");
    assert_eq!(replayed.phase, advanced.phase);
    assert!(matches!(
        advance_organization_deletion_phase(
            &pool,
            &operation.id,
            operation.generation,
            OrganizationDeletionPhase::BillingFinalized,
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    complete_billing_phase(&pool, &operation).await;
    let billing_advanced = advance_organization_deletion_phase(
        &pool,
        &operation.id,
        operation.generation,
        OrganizationDeletionPhase::BillingFinalized,
    )
    .await
    .unwrap();
    assert_eq!(billing_advanced.phase, "billing_finalized");
    assert!(matches!(
        advance_organization_deletion_phase(
            &pool,
            &operation.id,
            operation.generation,
            OrganizationDeletionPhase::WriteFenced,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_deletion_stale_generation",
            ..
        })
    ));
    assert!(matches!(
        advance_organization_deletion_phase(
            &pool,
            &operation.id,
            operation.generation,
            OrganizationDeletionPhase::Completed,
        )
        .await,
        Err(AppError::BadRequest(_))
    ));

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn finalizer_refuses_active_and_resolution_required_leases_for_every_class() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let mut leases = Vec::new();
    for class in [
        OrganizationMutationClass::ControlPlaneDatabase,
        OrganizationMutationClass::EnvironmentRuntimeDispatch,
        OrganizationMutationClass::TenantSecretProvider,
        OrganizationMutationClass::BillingProvider,
    ] {
        leases.push(
            acquire_organization_mutation_lease(&pool, &fixture.org_id, class)
                .await
                .unwrap(),
        );
    }
    let operation = begin_organization_deletion(&pool, &fixture.owner, &fixture.org_id)
        .await
        .unwrap();
    advance_to_control_plane_reconciled(&pool, &operation).await;

    assert!(matches!(
        finalize_organization_deletion_database(
            &pool,
            &operation.id,
            &fixture.org_id,
            operation.generation,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_mutation_barrier_not_drained",
            ..
        })
    ));
    for lease in &leases {
        mark_organization_mutation_resolution_required(
            &pool,
            &lease.id,
            "injected_ambiguous_mutation",
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        finalize_organization_deletion_database(
            &pool,
            &operation.id,
            &fixture.org_id,
            operation.generation,
        )
        .await,
        Err(AppError::Coded {
            code: "organization_mutation_barrier_not_drained",
            ..
        })
    ));
    for lease in &leases {
        resolve_organization_mutation_lease(&pool, &lease.id)
            .await
            .unwrap();
    }
    let completed = finalize_organization_deletion_database(
        &pool,
        &operation.id,
        &fixture.org_id,
        operation.generation,
    )
    .await
    .unwrap();
    assert_eq!(completed.state, "completed");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn configured_finalizer_is_dependency_ordered_idempotent_and_value_blind() {
    let Some(pool) = pool().await else { return };
    let fixture = seed(&pool).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let preset_id = format!("preset_orgdel_{suffix}");
    let environment_id = format!("env_orgdel_{suffix}");
    let project_id = format!("project_orgdel_{suffix}");

    sqlx::query(
        r#"INSERT INTO environment_presets (id, org_id, name, project_spec)
           VALUES ($1, $2, 'deletion fixture',
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&preset_id)
    .bind(&fixture.org_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id,
                external_cleanup_completed_at, project_spec)
           VALUES ($1, $2, $3, 'sandbox', 'destroyed', 'destroyed', $4, NOW(),
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&environment_id)
    .bind(&fixture.org_id)
    .bind(&fixture.owner.user_id)
    .bind(&preset_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO repo_configs (id, org_id, repo_url, project_spec, created_by)
           VALUES ($1, $2, 'https://example.test/repo.git',
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb, $3)"#,
    )
    .bind(format!("repo_orgdel_{suffix}"))
    .bind(&fixture.org_id)
    .bind(&fixture.owner.user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO environment_quotas (org_id) VALUES ($1)")
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO environment_usage_billing (org_id, billing_period_start) VALUES ($1, NOW())",
    )
    .bind(&fixture.org_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO environment_usage_billing_tiers (org_id, billing_period_start, runtime_tier) VALUES ($1, NOW(), 'confidential')",
    )
    .bind(&fixture.org_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO secret_projects (id, org_id, name) VALUES ($1, $2, 'fixture')")
        .bind(&project_id)
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO org_invitations
               (id, org_id, email, role, invited_by, token_hash, expires_at)
           VALUES ($1, $2, 'invitee@example.test', 'member', $3, $4,
                   NOW() + INTERVAL '1 day')"#,
    )
    .bind(format!("invite_orgdel_{suffix}"))
    .bind(&fixture.org_id)
    .bind(&fixture.owner.user_id)
    .bind("11".repeat(32))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tenant_secret_deks \
         (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
         VALUES ($1, 'org', $2, 'openbao-transit', 'tenant-dek', 1, \
                 'vault:v1:generated')",
    )
    .bind(format!("dek-orgdel-{suffix}"))
    .bind(&fixture.org_id)
    .execute(&pool)
    .await
    .unwrap();
    for path in [
        format!("/org-secrets/{}", fixture.org_id),
        format!("/projects/{}/{}", fixture.org_id, project_id),
    ] {
        sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, storage_contract_version) \
             VALUES ($1, 'CANARY', $2, 'org', $3, \
                     decode(repeat('11', 16), 'hex'), decode(repeat('22', 12), 'hex'), 1)",
        )
        .bind(path)
        .bind(format!("dek-orgdel-{suffix}"))
        .bind(&fixture.org_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let requester_id = fixture.alternate_owner.user_id.clone();
    let operation = begin_organization_deletion(&pool, &fixture.alternate_owner, &fixture.org_id)
        .await
        .unwrap();
    advance_to_control_plane_reconciled(&pool, &operation).await;
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&fixture.org_id)
        .bind(&requester_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&requester_id)
        .execute(&pool)
        .await
        .unwrap();

    let completed = finalize_organization_deletion_database(
        &pool,
        &operation.id,
        &fixture.org_id,
        operation.generation,
    )
    .await
    .unwrap();
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.phase, "completed");
    assert_eq!(completed.requested_by, requester_id);

    for table in [
        "organizations",
        "repo_configs",
        "environments",
        "environment_presets",
        "api_keys",
        "environment_quotas",
        "environment_usage_billing",
        "environment_usage_billing_tiers",
        "secret_projects",
        "org_invitations",
        "org_members",
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {} = $1",
            if table == "organizations" {
                "id"
            } else {
                "org_id"
            }
        ))
        .bind(&fixture.org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "{table} retained organization rows");
    }
    let secret_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM tenant_secrets
           WHERE path = $1 OR left(path, char_length($2) + 1) = $2 || '/'"#,
    )
    .bind(format!("/org-secrets/{}", fixture.org_id))
    .bind(format!("/projects/{}", fixture.org_id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(secret_count, 0);
    let audit_user: Option<String> = sqlx::query_scalar(
        r#"SELECT user_id FROM audit_logs
           WHERE action = 'org.deleted' AND metadata->>'operation_id' = $1"#,
    )
    .bind(&operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_user, None);

    let replayed = finalize_organization_deletion_database(
        &pool,
        &operation.id,
        &fixture.org_id,
        operation.generation,
    )
    .await
    .unwrap();
    assert_eq!(
        replayed, completed,
        "lost commit response retry must converge"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
async fn schema_guard_enumerates_org_preset_and_environment_dependencies() {
    let Some(pool) = pool().await else { return };

    async fn referencing_tables(pool: &PgPool, target: &str) -> Vec<String> {
        sqlx::query_scalar(
            r#"SELECT conrelid::regclass::text || ':' ||
                      CASE confdeltype
                        WHEN 'a' THEN 'no_action'
                        WHEN 'c' THEN 'cascade'
                        WHEN 'n' THEN 'set_null'
                        WHEN 'r' THEN 'restrict'
                        WHEN 'd' THEN 'set_default'
                      END
               FROM pg_constraint
               WHERE contype = 'f' AND confrelid = to_regclass($1)
               ORDER BY conrelid::regclass::text"#,
        )
        .bind(target)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    assert_eq!(
        referencing_tables(&pool, "organizations").await,
        vec![
            "admin_invoice_credits:cascade",
            "api_keys:no_action",
            "billing_external_operations:cascade",
            "environment_presets:no_action",
            "environment_quotas:no_action",
            "environment_resize_operations:cascade",
            "environment_subscriptions:cascade",
            "environment_usage_billing:no_action",
            "environment_usage_billing_tiers:no_action",
            "environments:no_action",
            "org_invitations:cascade",
            "org_members:cascade",
            "org_subscriptions:cascade",
            "repo_configs:no_action",
            "sandbox_running_sessions:cascade",
            "secret_projects:no_action",
            "stripe_invoices:cascade",
        ]
    );
    assert_eq!(
        referencing_tables(&pool, "environment_presets").await,
        vec!["environments:no_action", "sandbox_template_config:cascade"]
    );
    assert_eq!(
        referencing_tables(&pool, "environments").await,
        vec![
            "confidential_storage_keys:cascade",
            "environment_access:cascade",
            "environment_lifecycle_journal:cascade",
            "environment_logs:cascade",
            "environment_operation_generation_claims:cascade",
            "environment_ports:cascade",
            "environment_resize_operations:cascade",
            "environment_sessions:cascade",
            "sandbox_environment_backend:cascade",
            "sandbox_running_sessions:cascade",
        ]
    );
}
