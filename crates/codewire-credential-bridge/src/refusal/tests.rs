use axum::body::to_bytes;
use codewire_access::REFUSAL_HEADER;

use super::*;

use v1::CredentialBridgeFailureReason as Reason;
use v1::CredentialBridgeRefusal as Wire;

#[test]
fn an_older_brokers_bare_denial_stays_a_403() {
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::Unspecified as i32),
        Some(Refusal::Denied)
    );
    assert_eq!(
        from_failure(Reason::Unavailable as i32, Wire::Unspecified as i32),
        Some(Refusal::CredentialUnavailable)
    );
    for reason in [Reason::UpstreamFailed, Reason::ResponseTooLarge] {
        assert_eq!(
            from_failure(reason as i32, Wire::Unspecified as i32),
            Some(Refusal::UpstreamFailed(UpstreamFailure::Failed))
        );
    }
}

#[test]
fn a_refusal_the_broker_names_wins_over_its_reason() {
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::CredentialRevoked as i32),
        Some(Refusal::CredentialRevoked)
    );
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::CredentialUnavailable as i32),
        Some(Refusal::CredentialUnavailable)
    );
    // #5555: the hosted refusal arrives as itself, never as the policy's.
    for (wire, refusal) in [
        (Wire::NameNotAllowed, Refusal::NameNotAllowed),
        (
            Wire::SelectedCredentialOnly,
            Refusal::SelectedCredentialOnly,
        ),
    ] {
        assert_eq!(
            from_failure(Reason::Denied as i32, wire as i32),
            Some(refusal)
        );
    }
}

#[test]
fn a_refusal_from_a_newer_broker_reads_as_unavailable() {
    assert_eq!(
        from_failure(Reason::Denied as i32, 999),
        Some(Refusal::Unavailable)
    );
}

#[test]
fn a_failure_without_a_valid_reason_is_an_invalid_frame() {
    assert_eq!(
        from_failure(Reason::Unspecified as i32, Wire::CredentialRevoked as i32),
        None
    );
    assert_eq!(from_failure(999, Wire::Unspecified as i32), None);
}

#[tokio::test]
async fn a_refusal_answers_with_its_status_headers_and_plain_body() {
    let response = refusal_response(
        Refusal::CredentialRevoked,
        Some(RefusalProvider::Anthropic),
        Some("api.anthropic.com"),
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let headers = response.headers();
    assert_eq!(headers[REFUSAL_HEADER], "credential_revoked");
    assert_eq!(headers["content-type"], "text/plain; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-store");
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(body.starts_with(
        b"Codewire: the Anthropic credential this environment uses was revoked.\nFix: "
    ));
}
