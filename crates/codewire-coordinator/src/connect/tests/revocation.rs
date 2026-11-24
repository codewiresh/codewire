//! A client's tailnet session ends when the credential it joined with is
//! lost, and joining again with that credential is refused at the hello
//! (#3586, step 3; `docs/journeys/account-access.md`, `access-tailnet`).

use super::*;

/// The revocation bound: within seconds normally, 30 s at most.
const REVOCATION_BOUND: std::time::Duration = std::time::Duration::from_secs(35);

#[tokio::test]
async fn a_client_session_ends_when_its_credential_is_revoked_and_cannot_rejoin_with_it() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping coordinator client revocation");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let fixtures = seed_production_auth_fixtures(&pool).await;
    let state = CoordinatorState::new(
        pool.clone(),
        "protocol-parity-secret".into(),
        crate::test_derp_map(),
    );
    // Only this app reads the log: each listener holds a pooled connection.
    let listener = state.spawn_revocation_listener();
    let (addr, server) = start_production_state(state, pool.clone(), PEER_RECHECK_INTERVAL).await;
    let headers = headers_with_bearer(&fixtures.oidc_token);
    let mut stream = h2c_client_with_protocol_and_headers(addr, Protocol::Connect, headers.clone())
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
    let first = tokio::time::timeout(
        PRODUCTION_AUTH_HANG_GUARD,
        stream.message::<CoordinateResponse>(),
    )
    .await
    .expect("the session answers")
    .expect("the session is admitted")
    .expect("a first message");
    assert!(matches!(
        first.to_owned_message().msg,
        Some(coordinate_response::Msg::DerpMap(_))
    ));

    sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash = $1")
        .bind(hash_oauth_token(&fixtures.oidc_token))
        .execute(&pool)
        .await
        .unwrap();
    let ended = tokio::time::timeout(REVOCATION_BOUND, async {
        loop {
            match stream.message::<CoordinateResponse>().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("the session closed without saying why"),
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("the session ended within the bound");
    assert_eq!(ended.code, connectrpc::ErrorCode::PermissionDenied);
    assert_eq!(ended.message.as_deref(), Some("access revoked"));

    // The session tells the client before it writes the event.
    let mut surface = None;
    for _ in 0..50 {
        surface = sqlx::query_scalar::<_, Option<String>>(
            "SELECT metadata->>'surface' FROM audit_logs \
             WHERE action = 'stream.revoked' AND user_id = $1",
        )
        .bind(&fixtures.user_id)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .flatten();
        if surface.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(surface.as_deref(), Some("tailnet"));
    server.abort();
    listener.abort();

    let rejoin = production_auth_outcome(
        pool.clone(),
        Protocol::Connect,
        headers,
        &fixtures.org_a,
        fixtures.env_a,
    )
    .await;
    assert!(
        matches!(
            rejoin,
            ProductionAuthOutcome::Error {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ),
        "{rejoin:?}"
    );
}

/// The organization's deletion starting ends its members' sessions through
/// the fence, well before the coordinator's own re-check would, and says the
/// organization is being deleted (#3586).
#[tokio::test]
async fn a_client_session_ends_saying_why_when_its_organizations_deletion_starts() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping coordinator organization deletion");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let fixtures = seed_production_auth_fixtures(&pool).await;
    let state = CoordinatorState::new(
        pool.clone(),
        "protocol-parity-secret".into(),
        crate::test_derp_map(),
    );
    let listener = state.spawn_revocation_listener();
    // The re-check is far off, so only the fence can end the session in time.
    let (addr, server) =
        start_production_state(state, pool.clone(), std::time::Duration::from_secs(600)).await;
    let mut stream = h2c_client_with_protocol_and_headers(
        addr,
        Protocol::Connect,
        headers_with_bearer(&fixtures.oidc_token),
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
    let first = tokio::time::timeout(
        PRODUCTION_AUTH_HANG_GUARD,
        stream.message::<CoordinateResponse>(),
    )
    .await
    .expect("the session answers")
    .expect("the session is admitted")
    .expect("a first message");
    assert!(matches!(
        first.to_owned_message().msg,
        Some(coordinate_response::Msg::DerpMap(_))
    ));

    sqlx::query(
        "UPDATE organizations SET deletion_state = 'deleting', deletion_generation = 1, \
         deletion_operation_id = 'synthetic-operation', deletion_workflow_id = 'synthetic-workflow', \
         deletion_requested_at = NOW(), deletion_phase = 'synthetic_phase' WHERE id = $1",
    )
    .bind(&fixtures.org_a)
    .execute(&pool)
    .await
    .unwrap();
    let ended = tokio::time::timeout(REVOCATION_BOUND, async {
        loop {
            match stream.message::<CoordinateResponse>().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("the session closed without saying why"),
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("the session ended within the bound");
    assert_eq!(ended.code, connectrpc::ErrorCode::FailedPrecondition);
    assert_eq!(
        ended.message.as_deref(),
        Some(codewire_server_core::org::ORGANIZATION_DELETING)
    );
    server.abort();
    listener.abort();
}
