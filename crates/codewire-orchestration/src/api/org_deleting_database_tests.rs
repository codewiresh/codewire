//! An organization whose deletion has started or failed admits no new stream
//! into its environments, and says why only to a caller its access check
//! admits (`docs/dev/AUTH-POLICY.md`, #3586). The preview proxy's half is in
//! `preview::authorization::database_tests` and the coordinator's in its own
//! crate; this walks the runtime target lookup every daemon-reaching surface
//! shares (terminal, SSH proxy, the desktop viewer, exec, file, attach,
//! repair, runtime update) and log-follow.

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::error::AppError;
use codewire_server_core::org::ORGANIZATION_DELETING;

use super::ApiState;
use super::logs::open_environment_log_stream;
use super::proxy::{
    resolve_running_sandbox_target, resolve_running_sandbox_target_for_repair,
    resolve_running_sandbox_target_for_role,
};
use super::runtime_lease_test_support::LeaseFixture;

const DELETING: (StatusCode, &str) = (StatusCode::CONFLICT, ORGANIZATION_DELETING);

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_string(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn set_deletion(fixture: &LeaseFixture, state: &str) {
    let sql = match state {
        "deleting" => {
            "UPDATE organizations SET deletion_state = 'deleting', deletion_generation = 1, \
             deletion_operation_id = 'synthetic-operation', \
             deletion_workflow_id = 'synthetic-workflow', deletion_requested_at = NOW(), \
             deletion_phase = 'synthetic_phase', deletion_failure_code = NULL WHERE id = $1"
        }
        "delete_failed" => {
            "UPDATE organizations SET deletion_state = 'delete_failed', deletion_generation = 1, \
             deletion_operation_id = 'synthetic-operation', \
             deletion_workflow_id = 'synthetic-workflow', deletion_requested_at = NOW(), \
             deletion_phase = 'synthetic_phase', deletion_failure_code = 'synthetic_failure' \
             WHERE id = $1"
        }
        other => panic!("no deletion state {other}"),
    };
    sqlx::query(sql)
        .bind(&fixture.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
}

/// What each runtime-target admission answers `user`, in the order the
/// surfaces list them: operator (terminal, SSH proxy, exec, file, attach,
/// runtime update), viewer (the SSH proxy's check), repair.
async fn runtime_answers(
    state: &ApiState,
    fixture: &LeaseFixture,
    user: &AuthUser,
) -> Vec<Option<(StatusCode, &'static str)>> {
    let id = &fixture.id;
    vec![
        resolve_running_sandbox_target(state, user, id, id)
            .await
            .err(),
        resolve_running_sandbox_target_for_role(state, user, id, id, "viewer")
            .await
            .err(),
        resolve_running_sandbox_target_for_repair(state, user, id, id)
            .await
            .err(),
    ]
}

fn log_code(result: Result<impl Sized, AppError>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        Err(AppError::Coded { code, .. }) => Some(code),
        Err(other) => panic!("unexpected log stream error: {other:?}"),
    }
}

async fn log_answers(
    state: &ApiState,
    fixture: &LeaseFixture,
    user: &AuthUser,
) -> (Option<&'static str>, Option<&'static str>) {
    let id = &fixture.id;
    let follow = log_code(open_environment_log_stream(state, user, id, id, "", true).await);
    let backfill = log_code(open_environment_log_stream(state, user, id, id, "", false).await);
    (follow, backfill)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_organization_being_deleted_admits_no_new_stream() {
    // The fixture's user owns the organization and created its running
    // Sandbox; all three share the fixture's id.
    let fixture = LeaseFixture::seed("synthetic-org-deleting").await;
    let state = super::test_state::offline(fixture.pool.clone()).await;
    let owner = session(&fixture.id);
    let stranger = session(&format!("{}-stranger", fixture.id));

    for answer in runtime_answers(&state, &fixture, &owner).await {
        assert_ne!(answer, Some(DELETING), "an active organization refused");
    }
    assert_eq!(log_answers(&state, &fixture, &owner).await, (None, None));

    for deletion in ["deleting", "delete_failed"] {
        set_deletion(&fixture, deletion).await;
        assert_eq!(
            runtime_answers(&state, &fixture, &owner).await,
            vec![Some(DELETING); 3],
            "{deletion}: a member opened a runtime stream"
        );
        assert_eq!(
            log_answers(&state, &fixture, &owner).await,
            (Some("organization_deleting"), None),
            "{deletion}: only the follow is a stream; a backfill is a read"
        );

        // The access check answers first, so a stranger learns nothing of
        // the deletion.
        for answer in runtime_answers(&state, &fixture, &stranger).await {
            assert_eq!(
                answer,
                Some((StatusCode::NOT_FOUND, "organization not found")),
                "{deletion}: a stranger's answer changed"
            );
        }
        let (follow, backfill) = log_answers(&state, &fixture, &stranger).await;
        assert_eq!(
            follow, backfill,
            "{deletion}: a stranger told of the deletion"
        );
        assert_ne!(follow, Some("organization_deleting"));
    }

    fixture.cleanup().await;
}
