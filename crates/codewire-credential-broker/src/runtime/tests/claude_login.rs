//! The sealed Claude login's request checks in the shared broker. Delivery,
//! its predicate and its refresh have database tests at the platform
//! placement (platform/tests/claude_sign_in.rs).

use codewire_workload_secrets::ProjectionRecipient;

use super::*;

fn login_request(recipient: &ProjectionRecipient) -> v1::ClaudeLoginRequest {
    v1::ClaudeLoginRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        deadline_unix_ms: current_unix_time_ms().unwrap() + 10_000,
    }
}

#[tokio::test]
async fn claude_deadline_refusals_name_their_cause_without_secrets() {
    let (broker, state) = oauth_broker(StatusCode::OK, Vec::new(), String::new(), Duration::ZERO);
    let (log, _capture) = crate::timing::tests::TimingLog::install();
    let recipient = ProjectionRecipient::new();
    for (offset, reason) in [(-1_i64, "deadline_passed"), (45_000, "deadline_too_far")] {
        let mut request = login_request(&recipient);
        request.deadline_unix_ms = current_unix_time_ms()
            .unwrap()
            .checked_add_signed(offset)
            .unwrap();
        assert_eq!(
            broker.claude_login(request).await.unwrap_err(),
            BrokerRequestError::AuthorityUnavailable
        );
        let lines = log.lines();
        let line = lines.last().unwrap();
        crate::timing::tests::assert_secret_free(line);
        assert_eq!(line["fields"]["event"], "claude_login_refused");
        assert_eq!(line["fields"]["reason"], reason);
    }
    assert_eq!(log.lines().len(), 2);
    assert_eq!(state.lease_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn malformed_claude_requests_never_lease_and_other_placements_deny() {
    let (broker, state) = oauth_broker(StatusCode::OK, Vec::new(), String::new(), Duration::ZERO);
    let recipient = ProjectionRecipient::new();
    let valid = login_request(&recipient);
    for change in [
        "request id",
        "nil request id",
        "short recipient",
        "low-order recipient",
    ] {
        let mut request = valid.clone();
        match change {
            "request id" => request.request_id = "not-a-uuid".into(),
            "nil request id" => request.request_id = Uuid::nil().to_string(),
            "short recipient" => request.recipient_public_key.truncate(31),
            "low-order recipient" => request.recipient_public_key = vec![0; 32],
            _ => unreachable!(),
        }
        assert_eq!(
            broker.claude_login(request).await.unwrap_err(),
            BrokerRequestError::InvalidRequest,
            "{change}"
        );
    }
    // This placement implements the Codex login predicate only: a Claude
    // login is denied through the trait default, before any lease.
    assert_eq!(
        broker.claude_login(valid).await.unwrap_err(),
        BrokerRequestError::Denied
    );
    assert_eq!(state.lease_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
    assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
}
