//! A provider 401 forces a refresh of a Codex sign-in only when it was last
//! refreshed ten minutes ago or more, by the time stored with it, and a
//! failed forced refresh returns the provider's 401 (#4974).

use super::*;

/// An access token valid for an hour, and the one a refresh returns.
fn tokens() -> (String, String) {
    let now = current_unix_time().unwrap();
    (
        jwt(json!({ "exp": now + 3_600 })),
        jwt(json!({ "exp": now + 7_200 })),
    )
}

fn refresh_reply(access_token: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "access_token": access_token,
        "refresh_token": "synthetic-new-refresh-token",
        "token_type": "bearer"
    }))
    .unwrap()
}

/// Store `access_token` as a sign-in refreshed just now.
fn store_young_sign_in(state: &OAuthTestState, access_token: &str) {
    let now = current_unix_time().unwrap();
    let mut material = oauth_material_at(access_token, now).into_bytes();
    let observed = state
        .authority
        .get_credential(&state.credential_id)
        .unwrap()
        .metadata;
    state
        .authority
        .rotate_credential_material(
            &state.credential_id,
            observed.revocation_generation,
            ProtectedValue::new(std::mem::take(&mut *material)).unwrap(),
            Some(state.hard_deadline),
            observed.account_hint,
        )
        .unwrap();
    state.material_generation.fetch_add(1, Ordering::AcqRel);
}

/// Another broker over the same credential store, as another environment's
/// broker or this one after a restart: its own upstream and counters.
fn second_broker(
    state: &OAuthTestState,
    unauthorized_access_tokens: BTreeSet<String>,
    refresh_response: Vec<u8>,
    expected_access_token: String,
) -> (
    OpenAiBroker<OAuthTestLeaseProvider, OAuthSyntheticUpstream>,
    Arc<AtomicUsize>,
) {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let start_count = Arc::new(AtomicUsize::new(0));
    let broker = OpenAiBroker::new(
        OAuthTestLeaseProvider {
            authority: Arc::clone(&state.authority),
            environment_id: state.environment_id.clone(),
            credential_id: state.credential_id.clone(),
            material_generation: Arc::clone(&state.material_generation),
            refresh_active: Arc::new(AtomicBool::new(false)),
            begin_count: Arc::new(AtomicUsize::new(0)),
            start_count: Arc::clone(&start_count),
            start_control: None,
            fail_start: false,
            recovered_material: std::sync::Mutex::new(None),
            commit_started: Arc::new(AtomicBool::new(false)),
            commit_delay: Duration::ZERO,
            commit_count: Arc::new(AtomicUsize::new(0)),
            abort_count: Arc::new(AtomicUsize::new(0)),
            failure_count: Arc::new(AtomicUsize::new(0)),
            lease_count: Arc::new(AtomicUsize::new(0)),
            commit_return_gate: Arc::new(CommitReturnGate::default()),
            rate_limit_waits: Arc::new(std::sync::Mutex::new(None)),
            begin_control: None,
            deny_login: Arc::new(AtomicBool::new(false)),
            refuse_commit: false,
            return_refused_permit: false,
            refuse_failure: false,
        },
        OAuthSyntheticUpstream {
            refresh_status: StatusCode::OK,
            refresh_response: Arc::new(refresh_response),
            refresh_headers: HeaderMap::new(),
            refresh_body_started: Arc::new(AtomicUsize::new(0)),
            refresh_delay: Duration::ZERO,
            refresh_body_delay: Duration::ZERO,
            refresh_error: None,
            start_count,
            refresh_control: None,
            unauthorized_control: None,
            expected_access_token: Arc::new(expected_access_token),
            unauthorized_access_tokens: Arc::new(unauthorized_access_tokens),
            refresh_count: Arc::clone(&refreshes),
            response_count: Arc::new(AtomicUsize::new(0)),
            response_headers: HeaderMap::new(),
            response_status: StatusCode::OK,
            response_body_started: Arc::new(AtomicUsize::new(0)),
            reflect_authorization: false,
        },
    )
    .unwrap();
    (broker, refreshes)
}

async fn send(
    broker: &OpenAiBroker<OAuthTestLeaseProvider, OAuthSyntheticUpstream>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (status, headers, mut body) = broker.execute(request()).await.unwrap().into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend(chunk.unwrap());
    }
    (status, headers, bytes)
}

/// The provider's own 401, as the synthetic upstream answers a rejected token.
fn assert_providers_401(status: StatusCode, headers: &HeaderMap, body: &[u8]) {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get("x-openai-authorization-error")
            .and_then(|value| value.to_str().ok()),
        Some("token_expired")
    );
    assert_eq!(body, b"synthetic unauthorized");
}

/// Fails on main before #4974: a 401 always forced a refresh.
#[tokio::test]
async fn a_young_sign_ins_401_is_returned_and_refreshes_nothing() {
    let (initial, refreshed) = tokens();
    let (broker, state) = oauth_broker_with_initial_token(
        initial.clone(),
        BTreeSet::from([initial.clone()]),
        StatusCode::OK,
        refresh_reply(&refreshed),
        refreshed,
        Duration::ZERO,
    );
    store_young_sign_in(&state, &initial);
    let (status, headers, body) = send(&broker).await;
    assert_providers_401(status, &headers, &body);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_old_sign_ins_401_forces_one_exchange_and_one_retry() {
    let (initial, refreshed) = tokens();
    let (broker, state) = oauth_broker_with_initial_token(
        initial.clone(),
        BTreeSet::from([initial]),
        StatusCode::OK,
        refresh_reply(&refreshed),
        refreshed,
        Duration::ZERO,
    );
    let (status, _, _) = send(&broker).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
    assert_eq!(state.response_count.load(Ordering::Relaxed), 2);
}

/// The bound is the sign-in's stored refresh time, not a count in one
/// broker's memory: a second broker over the same store, after the first
/// forced a refresh moments ago, refreshes nothing.
#[tokio::test]
async fn a_second_broker_over_the_same_store_refreshes_nothing() {
    let (initial, refreshed) = tokens();
    let rejected = BTreeSet::from([initial.clone(), refreshed.clone()]);
    let (first, state) = oauth_broker_with_initial_token(
        initial,
        rejected.clone(),
        StatusCode::OK,
        refresh_reply(&refreshed),
        refreshed.clone(),
        Duration::ZERO,
    );
    let (status, headers, body) = send(&first).await;
    assert_providers_401(status, &headers, &body);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);

    let (second, second_refreshes) =
        second_broker(&state, rejected, refresh_reply(&refreshed), refreshed);
    let (status, headers, body) = send(&second).await;
    assert_providers_401(status, &headers, &body);
    assert_eq!(second_refreshes.load(Ordering::Relaxed), 0);
}

/// A refused or uncertain forced refresh answers the provider's first 401,
/// from the copy held while it ran, and the request is not sent again.
#[tokio::test]
async fn a_failed_forced_refresh_returns_the_providers_401() {
    for (refresh_status, refresh_body) in [
        (
            StatusCode::BAD_REQUEST,
            br#"{"error":{"code":"refresh_token_expired"}}"#.to_vec(),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            b"synthetic outage".to_vec(),
        ),
    ] {
        let (initial, refreshed) = tokens();
        let (broker, state) = oauth_broker_with_initial_token(
            initial.clone(),
            BTreeSet::from([initial]),
            refresh_status,
            refresh_body,
            refreshed,
            Duration::ZERO,
        );
        let (status, headers, body) = send(&broker).await;
        assert_providers_401(status, &headers, &body);
        assert_eq!(
            state.refresh_count.load(Ordering::Relaxed),
            1,
            "{refresh_status}"
        );
        assert_eq!(
            state.response_count.load(Ordering::Relaxed),
            1,
            "{refresh_status}"
        );
    }
}

/// The authority refusing to begin the forced refresh is the request's
/// denial, not the provider's 401: the provider never saw that refresh. A
/// refused re-lease is the same, in
/// `oauth_unauthorized_retry_does_not_replay_under_a_newly_bound_credential`.
#[tokio::test]
async fn a_forced_refresh_the_authority_refuses_to_begin_is_a_denial() {
    let (initial, refreshed) = tokens();
    let (broker, state) = oauth_broker_with_initial_token(
        initial.clone(),
        BTreeSet::from([initial]),
        StatusCode::OK,
        refresh_reply(&refreshed),
        refreshed,
        Duration::ZERO,
    );
    // The test authority begins a refresh only of the material generation it
    // last published.
    state.material_generation.fetch_add(1, Ordering::AcqRel);
    let result = broker.execute(request()).await;
    assert!(matches!(result, Err(BrokerRequestError::Denied)));
    assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
}
