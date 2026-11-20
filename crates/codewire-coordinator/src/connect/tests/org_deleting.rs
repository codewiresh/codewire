//! A tailnet client session into an organization whose deletion has started
//! or failed is refused at the hello, an open one ends at its next re-check,
//! and the reason reaches only a caller the access check admits
//! (`docs/dev/AUTH-POLICY.md`, #3586; `account-access.md`,
//! `access-org-deleting`).

use super::*;

async fn set_deletion(pool: &sqlx::PgPool, org_id: &str, deletion: &str, failure: Option<&str>) {
    sqlx::query(
        "UPDATE organizations SET deletion_state = $2, deletion_generation = 1, \
         deletion_operation_id = 'synthetic-operation', \
         deletion_workflow_id = 'synthetic-workflow', deletion_requested_at = NOW(), \
         deletion_phase = 'synthetic_phase', deletion_failure_code = $3 WHERE id = $1",
    )
    .bind(org_id)
    .bind(deletion)
    .bind(failure)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn a_client_session_into_an_organization_being_deleted_is_refused_and_an_open_one_ends() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping coordinator organization deletion");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let fixtures = seed_production_auth_fixtures(&pool).await;
    let recheck = std::time::Duration::from_millis(100);
    let (addr, server) = start_production_auth_app_with_recheck(pool.clone(), recheck).await;
    let mut stream = h2c_client_with_protocol_and_headers(
        addr,
        Protocol::Connect,
        session_headers(&fixtures.session_token),
    )
    .coordinate()
    .await
    .unwrap();
    stream
        .send(request(Hello {
            org_id: fixtures.org_a.clone(),
            environment_id: fixtures.env_a.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(matches!(
        next_response(&mut stream).await.msg,
        Some(coordinate_response::Msg::DerpMap(_))
    ));

    set_deletion(&pool, &fixtures.org_a, "deleting", None).await;
    let end = stream_end_before(&mut stream, recheck * 30).await;
    server.abort();
    let Some(Err(error)) = end else {
        panic!("a session into an organization being deleted stayed open: {end:?}");
    };
    assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);

    // The other organization stays a non-member's: its answer must not change
    // when its deletion starts too.
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&fixtures.org_b)
        .bind(&fixtures.user_id)
        .execute(&pool)
        .await
        .unwrap();
    for (deletion, failure) in [
        ("deleting", None),
        ("delete_failed", Some("synthetic_failure")),
    ] {
        set_deletion(&pool, &fixtures.org_a, deletion, failure).await;
        set_deletion(&pool, &fixtures.org_b, deletion, failure).await;
        let member = production_auth_outcome(
            pool.clone(),
            Protocol::Connect,
            session_headers(&fixtures.session_token),
            &fixtures.org_a,
            fixtures.env_a,
        )
        .await;
        assert!(
            matches!(
                &member,
                ProductionAuthOutcome::Error {
                    code: connectrpc::ErrorCode::FailedPrecondition,
                    message: Some(message),
                    ..
                } if message == codewire_server_core::org::ORGANIZATION_DELETING
            ),
            "{deletion}: {member:?}"
        );
        let stranger = production_auth_outcome(
            pool.clone(),
            Protocol::Connect,
            session_headers(&fixtures.session_token),
            &fixtures.org_b,
            fixtures.env_b,
        )
        .await;
        assert!(
            matches!(
                &stranger,
                ProductionAuthOutcome::Error {
                    code: connectrpc::ErrorCode::NotFound,
                    message: Some(message),
                    ..
                } if message == "organization not found"
            ),
            "{deletion}: a non-member was answered {stranger:?}"
        );
    }
    clean_production_auth_fixtures(&pool, &fixtures).await;
}
