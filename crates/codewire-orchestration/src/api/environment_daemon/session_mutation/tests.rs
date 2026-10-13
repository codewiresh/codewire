use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_server_core::connect_error::ConnectErrorDetail;
use codewire_server_core::org_deletion::{
    begin_organization_deletion, require_organization_mutation_barrier_drained,
    resolve_organization_mutation_lease, unresolved_organization_mutation_leases,
};
use tokio::sync::oneshot;

use super::*;

const SESSION_ID: &str = "session-42772c73-839b-42a9-b42b-0d2978fa4052";
const PRIVATE_SENTINEL: &str = "private-command-env-token-output-must-not-be-recorded";

fn running_record() -> v1::SessionRecord {
    v1::SessionRecord {
        session_id: SESSION_ID.into(),
        state: v1::SessionLifecycleState::Running as i32,
        created_at: Some(Default::default()),
        started_at: Some(Default::default()),
        command: vec![PRIVATE_SENTINEL.into()],
        ..Default::default()
    }
}

#[test]
fn acknowledgements_require_identity_and_completed_mutation() {
    assert!(
        Acknowledgement::Launch
            .validate(Some(running_record()))
            .is_ok()
    );
    assert!(
        Acknowledgement::Restart(SESSION_ID.into())
            .validate(Some(running_record()))
            .is_ok()
    );
    assert!(Acknowledgement::Launch.validate(None).is_err());
    let mut missing_creation = running_record();
    missing_creation.created_at = None;
    assert!(
        Acknowledgement::Launch
            .validate(Some(missing_creation))
            .is_err()
    );
    let mut interrupted = running_record();
    interrupted.state = v1::SessionLifecycleState::Interrupted as i32;
    interrupted.finished_at = Some(Default::default());
    assert!(
        Acknowledgement::Stop(SESSION_ID.into())
            .validate(Some(interrupted))
            .is_err()
    );
    for invalid in ["", "session-../file", "untrusted", "session-not-a-uuid"] {
        let mut record = running_record();
        record.session_id = invalid.into();
        assert!(Acknowledgement::Launch.validate(Some(record)).is_err());
    }
    assert!(
        Acknowledgement::Restart("another-session".into())
            .validate(Some(running_record()))
            .is_err()
    );
    for state in [0, 1, 3, 99] {
        let mut record = running_record();
        record.state = state;
        assert!(Acknowledgement::Launch.validate(Some(record)).is_err());
    }
    let mut failed = running_record();
    failed.state = v1::SessionLifecycleState::Failed as i32;
    failed.started_at = None;
    failed.finished_at = Some(Default::default());
    assert!(
        Acknowledgement::Launch
            .validate(Some(failed.clone()))
            .is_ok()
    );
    assert!(
        Acknowledgement::Stop(SESSION_ID.into())
            .validate(Some(failed))
            .is_err()
    );
    assert!(
        Acknowledgement::Stop(SESSION_ID.into())
            .validate(Some(running_record()))
            .is_err()
    );
    for state in [
        v1::SessionLifecycleState::Stopped,
        v1::SessionLifecycleState::Exited,
    ] {
        let mut record = running_record();
        record.state = state as i32;
        record.finished_at = Some(Default::default());
        assert!(
            Acknowledgement::Stop("different-session".into())
                .validate(Some(record.clone()))
                .is_err()
        );
        assert!(
            Acknowledgement::Stop(SESSION_ID.into())
                .validate(Some(record.clone()))
                .is_ok()
        );
        record.finished_at = None;
        assert!(
            Acknowledgement::Stop(SESSION_ID.into())
                .validate(Some(record))
                .is_err()
        );
    }
}

#[test]
fn ambiguous_dispatch_has_no_retry_advice_or_private_status() {
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::Cancelled,
        tonic::Code::Internal,
        tonic::Code::FailedPrecondition,
    ] {
        let OrganizationRuntimeMutationError::Ambiguous(error) =
            classify_dispatch_error(tonic::Status::new(code, PRIVATE_SENTINEL))
        else {
            panic!("post-dispatch outcome was treated as known");
        };
        let rendered = crate::connect::rendered_workspace_error(&error, Some("synthetic-request"));
        assert!(!format!("{rendered:?}").contains(PRIVATE_SENTINEL));
        assert!(
            !rendered
                .details
                .iter()
                .any(|detail| matches!(detail, ConnectErrorDetail::RetryInfo(_)))
        );
    }
    for code in [
        tonic::Code::InvalidArgument,
        tonic::Code::NotFound,
        tonic::Code::Unauthenticated,
        tonic::Code::PermissionDenied,
    ] {
        let OrganizationRuntimeMutationError::Known(error) =
            classify_dispatch_error(tonic::Status::new(code, PRIVATE_SENTINEL))
        else {
            panic!("proven pre-mutation rejection was not known");
        };
        assert!(!format!("{error:?}").contains(PRIVATE_SENTINEL));
    }
}

#[test]
fn a_refused_session_store_is_a_known_precondition_not_an_unknown_outcome() {
    // The daemon refuses its store before any launch, restart or stop runs.
    let OrganizationRuntimeMutationError::Known(error) =
        classify_dispatch_error(tonic::Status::new(tonic::Code::DataLoss, PRIVATE_SENTINEL))
    else {
        panic!("a refused session store was treated as an ambiguous outcome");
    };
    let rendered = crate::connect::rendered_workspace_error(&error, Some("synthetic-request"));
    let rendered = format!("{rendered:?}");
    assert!(!rendered.contains(PRIVATE_SENTINEL));
    assert!(!rendered.contains("outcome is unknown"));
    assert!(matches!(
        &error,
        AppError::Precondition(message) if message.as_ref()
            == "environment session store is refused; run `cw env daemon status` for the reason"
    ));
}

#[test]
fn setup_readiness_is_required_only_before_launch_and_restart() {
    assert!(Acknowledgement::Launch.requires_setup_ready());
    assert!(Acknowledgement::Restart(SESSION_ID.into()).requires_setup_ready());
    assert!(!Acknowledgement::Stop(SESSION_ID.into()).requires_setup_ready());
    assert!(require_setup_ready(Ok(Some((true, None)))).is_ok());
    for setup in [
        None,
        Some((false, None)),
        Some((true, Some("claimed".into()))),
        Some((true, Some("running".into()))),
        Some((true, Some("reaping".into()))),
        Some((true, Some(String::new()))),
    ] {
        assert!(matches!(
            require_setup_ready(Ok(setup)),
            Err(OrganizationRuntimeMutationError::Known(
                AppError::Precondition(_)
            ))
        ));
    }
}

#[test]
fn local_setup_query_failure_is_known_without_retry_or_private_detail() {
    let Err(OrganizationRuntimeMutationError::Known(error)) =
        require_setup_ready(Err(sqlx::Error::Protocol(PRIVATE_SENTINEL.into())))
    else {
        panic!("a local query failure before dispatch must be known");
    };
    let rendered = crate::connect::rendered_workspace_error(&error, Some("synthetic-request"));
    assert!(!format!("{rendered:?}").contains(PRIVATE_SENTINEL));
    assert!(
        !rendered
            .details
            .iter()
            .any(|detail| matches!(detail, ConnectErrorDetail::RetryInfo(_)))
    );
}

#[tokio::test]
async fn stalled_setup_read_expires_known_without_polling_dispatch() {
    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = dispatched.clone();
    let dispatch = async move {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, OrganizationRuntimeMutationError>(())
    };
    let result = async {
        // The read is permanently pending, so this exercises timeout rather
        // than relying on a scheduler race or a live database connection.
        check_setup_readiness(std::future::pending(), Duration::ZERO).await?;
        dispatch.await
    }
    .await;
    let Err(OrganizationRuntimeMutationError::Known(error)) = result else {
        panic!("an expired local read before dispatch must be known");
    };
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    let rendered = crate::connect::rendered_workspace_error(&error, Some("synthetic-request"));
    assert!(!format!("{rendered:?}").contains("outcome is unknown"));
    assert!(
        !rendered
            .details
            .iter()
            .any(|detail| matches!(detail, ConnectErrorDetail::RetryInfo(_)))
    );
}

struct Fixture {
    pool: PgPool,
    id: String,
}

fn fixture_id() -> String {
    // Reused as the organization route slug: the full UUID remains unique,
    // while this prefix keeps the fixture within the canonical 48-byte bound.
    format!("session-{}", Uuid::new_v4())
}

#[test]
fn database_fixture_identity_obeys_the_canonical_route_slug_contract() {
    let id = fixture_id();
    assert!(codewire_server_core::organization_slug::valid_organization_slug(&id));
    assert!(Uuid::parse_str(id.strip_prefix("session-").unwrap()).is_ok());
    assert_ne!(id, fixture_id());
    let rejected = format!("session-admission-{}", Uuid::new_v4());
    assert!(!codewire_server_core::organization_slug::valid_organization_slug(&rejected));
}

impl Fixture {
    async fn seed() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("durable session admission tests require the disposable test database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect disposable database");
        let id = fixture_id();
        sqlx::query("INSERT INTO users (id, email, name, email_verified) VALUES ($1, $2, 'Session admission test', true)")
            .bind(&id).bind(format!("{id}@example.test")).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, 'Session admission test', $1, $1)")
            .bind(&id).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $1, $1, 'owner')",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO environment_presets (id, org_id, name, slug, project_spec) VALUES ($1, $1, 'Session admission test', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
            .bind(&id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO environments (id, org_id, created_by, type, state, desired_state, preset_id, project_spec) VALUES ($1, $1, $1, 'sandbox', 'running', 'started', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
            .bind(&id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO sandbox_environment_backend (environment_id, namespace, setup_complete) VALUES ($1, 'synthetic-session-admission', true)")
            .bind(&id).execute(&pool).await.unwrap();
        Self { pool, id }
    }

    async fn cleanup(self) {
        sqlx::query("DELETE FROM audit_logs WHERE metadata->>'organization_id' = $1")
            .bind(&self.id)
            .execute(&self.pool)
            .await
            .unwrap();
        for table in [
            "organization_mutation_leases",
            "environments",
            "environment_presets",
            "org_members",
            "organizations",
            "organization_deletion_operations",
            "users",
        ] {
            let column = if matches!(
                table,
                "organization_mutation_leases" | "organization_deletion_operations"
            ) {
                "organization_id"
            } else {
                "id"
            };
            sqlx::query(&format!("DELETE FROM {table} WHERE {column} = $1"))
                .bind(&self.id)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        self.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_setup_readiness_rejects_launch_restart_without_dispatch_and_preserves_stop() {
    let fixture = Fixture::seed().await;
    for (complete, owner) in [
        (false, None),
        (true, Some("claimed")),
        (true, Some("running")),
        (true, Some("reaping")),
    ] {
        sqlx::query(
            "UPDATE sandbox_environment_backend SET setup_complete = $2, \
               setup_owner_generation = CASE WHEN $3::text IS NULL THEN NULL ELSE 1 END, \
               setup_owner_activity_id = CASE WHEN $3::text IS NULL THEN NULL ELSE 'synthetic-setup' END, \
               setup_owner_attempt = CASE WHEN $3::text IS NULL THEN NULL ELSE 1 END, \
               setup_owner_phase = CASE WHEN $3::text IS NULL THEN NULL ELSE 0 END, \
               setup_owner_status = $3, \
               setup_owner_pod_uid = CASE WHEN $3::text IN ('running', 'reaping') THEN 'synthetic-pod' ELSE NULL END \
             WHERE environment_id = $1",
        )
        .bind(&fixture.id).bind(complete).bind(owner)
        .execute(&fixture.pool).await.unwrap();
        assert_setup_rejects_without_dispatch(&fixture).await;
    }
    sqlx::query("DELETE FROM sandbox_environment_backend WHERE environment_id = $1")
        .bind(&fixture.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_setup_rejects_without_dispatch(&fixture).await;

    sqlx::query("INSERT INTO sandbox_environment_backend (environment_id, namespace, setup_complete) VALUES ($1, 'synthetic-session-admission', true)")
        .bind(&fixture.id).execute(&fixture.pool).await.unwrap();
    for acknowledgement in [
        Acknowledgement::Launch,
        Acknowledgement::Restart(SESSION_ID.into()),
    ] {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let observed = dispatched.clone();
        let record = run(
            &fixture.pool,
            &fixture.id,
            &fixture.id,
            acknowledgement,
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(Some(running_record()))
            },
        )
        .await
        .unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        assert!(
            unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
    fixture.cleanup().await;
}

async fn assert_setup_rejects_without_dispatch(fixture: &Fixture) {
    for acknowledgement in [
        Acknowledgement::Launch,
        Acknowledgement::Restart(SESSION_ID.into()),
    ] {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let observed = dispatched.clone();
        let error = run(
            &fixture.pool,
            &fixture.id,
            &fixture.id,
            acknowledgement,
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(Some(running_record()))
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::Precondition(_)));
        assert!(!format!("{error:?}").contains("outcome is unknown"));
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(
            unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
    // A blocked setup must not prevent stopping an already existing shell.
    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = dispatched.clone();
    let record = run(
        &fixture.pool,
        &fixture.id,
        &fixture.id,
        Acknowledgement::Stop(SESSION_ID.into()),
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            let mut stopped = running_record();
            stopped.state = v1::SessionLifecycleState::Stopped as i32;
            stopped.finished_at = Some(Default::default());
            Ok(Some(stopped))
        },
    )
    .await
    .unwrap();
    assert_eq!(record.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    assert!(
        unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_deletion_wins_without_dispatch_or_stranded_lease() {
    let fixture = Fixture::seed().await;
    for (column, value) in [("state", "destroying"), ("desired_state", "destroyed")] {
        sqlx::query(&format!(
            "UPDATE environments SET {column} = $2 WHERE id = $1"
        ))
        .bind(&fixture.id)
        .bind(value)
        .execute(&fixture.pool)
        .await
        .unwrap();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let observed = dispatched.clone();
        assert!(
            run(
                &fixture.pool,
                &fixture.id,
                &fixture.id,
                Acknowledgement::Launch,
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(running_record()))
                }
            )
            .await
            .is_err()
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(
            unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query(
            "UPDATE environments SET state = 'running', desired_state = 'started' WHERE id = $1",
        )
        .bind(&fixture.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    }
    let owner = codewire_server_core::auth::AuthUser {
        user_id: fixture.id.clone(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    begin_organization_deletion(&fixture.pool, &owner, &fixture.id)
        .await
        .unwrap();
    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = dispatched.clone();
    assert!(
        run(
            &fixture.pool,
            &fixture.id,
            &fixture.id,
            Acknowledgement::Launch,
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(Some(running_record()))
            }
        )
        .await
        .is_err()
    );
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    assert!(
        unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
            .await
            .unwrap()
            .is_empty()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_caller_disconnect_does_not_cancel_or_repeat_admitted_dispatch() {
    let fixture = Fixture::seed().await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (reply_tx, reply_rx) = oneshot::channel();
    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = dispatched.clone();
    let pool = fixture.pool.clone();
    let id = fixture.id.clone();
    let caller = tokio::spawn(async move {
        run(&pool, &id, &id, Acknowledgement::Launch, async move {
            observed.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(()).unwrap();
            reply_rx.await.unwrap();
            Ok(Some(running_record()))
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        require_organization_mutation_barrier_drained(&fixture.pool, &fixture.id)
            .await
            .is_err()
    );
    let unresolved = unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].state, "active");
    reply_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
                .await
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    // The acknowledged record is still Running: settlement does not own the
    // shell or require an attachment, session exit, or compensating Stop.
    require_organization_mutation_barrier_drained(&fixture.pool, &fixture.id)
        .await
        .unwrap();
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_lost_or_invalid_acknowledgement_retains_value_blind_evidence() {
    let fixture = Fixture::seed().await;
    let mut wrong = running_record();
    wrong.session_id = format!("session-{}", Uuid::new_v4());
    let mut invalid = running_record();
    invalid.state = 99;
    for response in [
        Err(tonic::Status::unavailable(PRIVATE_SENTINEL)),
        Err(tonic::Status::failed_precondition(PRIVATE_SENTINEL)),
        Ok(None),
        Ok(Some(wrong)),
        Ok(Some(invalid)),
    ] {
        assert!(
            run(
                &fixture.pool,
                &fixture.id,
                &fixture.id,
                Acknowledgement::Restart(SESSION_ID.into()),
                async move { response }
            )
            .await
            .is_err()
        );
        let unresolved = unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
            .await
            .unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].state, "resolution_required");
        assert_eq!(
            unresolved[0].recovery_code.as_deref(),
            Some("environment_runtime_dispatch_ambiguous")
        );
        assert!(!format!("{unresolved:?}").contains(PRIVATE_SENTINEL));
        resolve_organization_mutation_lease(&fixture.pool, &unresolved[0].id)
            .await
            .unwrap();
    }
    assert!(
        run(
            &fixture.pool,
            &fixture.id,
            &fixture.id,
            Acknowledgement::Launch,
            async { Err(tonic::Status::invalid_argument(PRIVATE_SENTINEL)) }
        )
        .await
        .is_err()
    );
    assert!(
        unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
            .await
            .unwrap()
            .is_empty()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_owner_timeout_is_bounded_and_never_releases_uncertainty() {
    let fixture = Fixture::seed().await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let pool = fixture.pool.clone();
    let id = fixture.id.clone();
    let task = tokio::spawn(async move {
        run_with_timeout(
            &pool,
            &id,
            &id,
            Acknowledgement::Launch,
            async move {
                entered_tx.send(()).unwrap();
                std::future::pending().await
            },
            Duration::from_secs(1),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let unresolved = unresolved_organization_mutation_leases(&fixture.pool, &fixture.id)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].state, "active");
    assert!(
        require_organization_mutation_barrier_drained(&fixture.pool, &fixture.id)
            .await
            .is_err()
    );
    fixture.cleanup().await;
}
