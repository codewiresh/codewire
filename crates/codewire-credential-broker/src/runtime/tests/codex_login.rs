//! The sealed Codex login through the shared broker: sealing, its validity
//! minimum, and the one serialized refresh it shares with proxied requests.
//! The placement's delivery predicate has its own database tests.

use codewire_workload_secrets::{CodexLoginContext, OpenedCodexLogin, ProjectionRecipient};

use super::*;

fn login_request(recipient: &ProjectionRecipient) -> v1::CodexLoginRequest {
    v1::CodexLoginRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        // The broker's whole window: no test here is about the deadline, and
        // a stalled CI slot spent a 10 s one before the seal (PR run 24711).
        deadline_unix_ms: current_unix_time_ms().unwrap() + MAX_CODEX_LOGIN_LIFETIME_MS,
    }
}

/// Bounds a wait on a login or proxied request, so a hang fails instead of
/// stalling the run. It is never the expected duration, and it outlasts the
/// login's own window.
const HANG: Duration = Duration::from_secs(60);

fn open(
    state: &OAuthTestState,
    recipient: ProjectionRecipient,
    request: &v1::CodexLoginRequest,
    sealed: &[u8],
) -> OpenedCodexLogin {
    let context = CodexLoginContext {
        environment_id: *Uuid::parse_str(state.environment_id.as_str())
            .unwrap()
            .as_bytes(),
        environment_generation: 11,
        request_id: *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
        deadline_unix_ms: request.deadline_unix_ms,
    };
    recipient
        .open_codex_login(sealed, &context, current_unix_time_ms().unwrap())
        .unwrap()
}

fn refresh_response(access_token: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "access_token": access_token,
        "refresh_token": "synthetic-new-refresh-token",
        "token_type": "bearer"
    }))
    .unwrap()
}

#[tokio::test]
async fn a_token_valid_for_thirty_minutes_is_sealed_without_a_refresh() {
    let now = current_unix_time().unwrap();
    let token = jwt(json!({ "iat": now, "exp": now + 7_200 }));
    let (broker, state) = oauth_broker_with_initial_token(
        token.clone(),
        BTreeSet::new(),
        StatusCode::OK,
        Vec::new(),
        token.clone(),
        Duration::ZERO,
    );
    let recipient = ProjectionRecipient::new();
    let request = login_request(&recipient);
    let sealed = broker.codex_login(request.clone()).await.unwrap();
    for secret in [token.as_str(), "synthetic-old-refresh-token"] {
        assert!(
            !sealed
                .windows(secret.len())
                .any(|part| part == secret.as_bytes())
        );
    }
    let opened = open(&state, recipient, &request, &sealed);
    assert_eq!(opened.login.access_token(), token);
    assert_eq!(opened.login.account_id(), "account-work");
    assert!(opened.login.refreshed_at_unix() > 0);
    assert_eq!(opened.binding.credential_id, state.credential_id.as_str());
    assert_eq!(opened.binding.material_generation, 1);
    assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_logins_and_proxied_requests_share_exactly_one_refresh() {
    let refreshed = jwt(json!({
        "exp": current_unix_time().expect("current time") + 3_600
    }));
    let (broker, state) = oauth_broker(
        StatusCode::OK,
        refresh_response(&refreshed),
        refreshed.clone(),
        Duration::from_millis(250),
    );
    let broker = Arc::new(broker);
    let logins = (0..4)
        .map(|_| {
            let recipient = ProjectionRecipient::new();
            let request = login_request(&recipient);
            let broker = Arc::clone(&broker);
            let sent = request.clone();
            (
                recipient,
                request,
                tokio::spawn(async move { broker.codex_login(sent).await }),
            )
        })
        .collect::<Vec<_>>();
    let proxied = (0..2)
        .map(|_| {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.execute(request()).await })
        })
        .collect::<Vec<_>>();
    for (recipient, request, task) in logins {
        let sealed = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let opened = open(&state, recipient, &request, &sealed);
        assert_eq!(opened.login.access_token(), refreshed);
        assert_eq!(opened.binding.material_generation, 2);
    }
    for task in proxied {
        let response = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (_, _, mut body) = response.into_parts();
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend(chunk.unwrap());
        }
        assert_eq!(output, b"synthetic response");
    }
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
    assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
    assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
    assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.response_count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn only_a_login_refreshes_a_token_that_expires_within_thirty_minutes() {
    let now = current_unix_time().unwrap();
    // One hour of lifetime, ten minutes left: inside the login's thirty-minute
    // minimum (half the lifetime), outside a proxied request's five minutes.
    let initial = jwt(json!({ "iat": now - 3_000, "exp": now + 600 }));
    let refreshed = jwt(json!({ "iat": now, "exp": now + 3_600 }));
    let (broker, state) = oauth_broker_with_initial_token(
        initial.clone(),
        BTreeSet::new(),
        StatusCode::OK,
        refresh_response(&refreshed),
        initial.clone(),
        Duration::ZERO,
    );
    let response = broker.execute(request()).await.unwrap();
    let (_, _, mut body) = response.into_parts();
    while let Some(chunk) = body.next().await {
        chunk.unwrap();
    }
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);

    let recipient = ProjectionRecipient::new();
    let request = login_request(&recipient);
    let sealed = broker.codex_login(request.clone()).await.unwrap();
    let opened = open(&state, recipient, &request, &sealed);
    assert_eq!(opened.login.access_token(), refreshed);
    assert_eq!(opened.binding.material_generation, 2);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
    // The delivered token comes from the lease taken after the commit.
    assert_eq!(state.material_generation.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn deadline_window_refusals_name_their_cause_without_secrets() {
    let (broker, state) = oauth_broker(StatusCode::OK, Vec::new(), String::new(), Duration::ZERO);
    let (log, _capture) = crate::timing::tests::TimingLog::install();
    let recipient = ProjectionRecipient::new();
    for (offset, reason) in [(-1_i64, "deadline_passed"), (3_600_000, "deadline_too_far")] {
        let mut request = login_request(&recipient);
        request.deadline_unix_ms = current_unix_time_ms()
            .unwrap()
            .checked_add_signed(offset)
            .unwrap();
        assert_eq!(
            broker.codex_login(request).await.unwrap_err(),
            BrokerRequestError::AuthorityUnavailable
        );
        let lines = log.lines();
        let line = lines.last().unwrap();
        crate::timing::tests::assert_secret_free(line);
        assert_eq!(line["fields"]["event"], "codex_login_refused");
        assert_eq!(line["fields"]["reason"], reason);
    }
    assert_eq!(log.lines().len(), 2);
    assert_eq!(state.lease_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn denied_or_malformed_requests_neither_lease_nor_refresh() {
    let (broker, state) = oauth_broker(StatusCode::OK, Vec::new(), String::new(), Duration::ZERO);
    let recipient = ProjectionRecipient::new();
    let valid = login_request(&recipient);
    let mut cases = Vec::new();
    for (change, expected) in [
        ("request id", BrokerRequestError::InvalidRequest),
        ("nil request id", BrokerRequestError::InvalidRequest),
        ("short recipient", BrokerRequestError::InvalidRequest),
        ("low-order recipient", BrokerRequestError::InvalidRequest),
        ("expired", BrokerRequestError::AuthorityUnavailable),
        ("too long", BrokerRequestError::AuthorityUnavailable),
    ] {
        let mut request = valid.clone();
        match change {
            "request id" => request.request_id = "not-a-uuid".into(),
            "nil request id" => request.request_id = Uuid::nil().to_string(),
            "short recipient" => request.recipient_public_key.truncate(31),
            "low-order recipient" => request.recipient_public_key = vec![0; 32],
            "expired" => request.deadline_unix_ms = current_unix_time_ms().unwrap() - 1,
            "too long" => {
                // Far past the window, however long the cases before it take.
                request.deadline_unix_ms = current_unix_time_ms().unwrap()
                    + codewire_workload_secrets::MAX_CODEX_LOGIN_LIFETIME_MS
                    + 3_600_000
            }
            _ => unreachable!(),
        }
        cases.push((change, request, expected));
    }
    for (change, request, expected) in cases {
        assert_eq!(
            broker.codex_login(request).await.unwrap_err(),
            expected,
            "{change}"
        );
    }
    broker.leases.deny_login.store(true, Ordering::Release);
    // A request made now, so only the denial can refuse it.
    assert_eq!(
        broker
            .codex_login(login_request(&recipient))
            .await
            .unwrap_err(),
        BrokerRequestError::Denied
    );
    assert_eq!(state.lease_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);

    // A placement without the delivery predicate denies through the default.
    let (broker, lease_count) = broker_with_lease_count();
    let recipient = ProjectionRecipient::new();
    assert_eq!(
        broker
            .codex_login(login_request(&recipient))
            .await
            .unwrap_err(),
        BrokerRequestError::Denied
    );
    assert_eq!(lease_count.load(Ordering::Relaxed), 0);
}
