use axum::body::to_bytes;
use codewire_access::REFUSAL_HEADER;

use super::*;

use v1::CredentialBridgeFailureReason as Reason;
use v1::CredentialBridgeRefusal as Wire;

#[test]
fn an_older_brokers_bare_denial_stays_a_403() {
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::Unspecified as i32, 0),
        Some(Refusal::Denied)
    );
    assert_eq!(
        from_failure(Reason::Unavailable as i32, Wire::Unspecified as i32, 0),
        Some(Refusal::CredentialUnavailable)
    );
    for reason in [Reason::UpstreamFailed, Reason::ResponseTooLarge] {
        assert_eq!(
            from_failure(reason as i32, Wire::Unspecified as i32, 0),
            Some(Refusal::UpstreamFailed(UpstreamFailure::Failed))
        );
    }
}

#[test]
fn a_refusal_the_broker_names_wins_over_its_reason() {
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::CredentialRevoked as i32, 0),
        Some(Refusal::CredentialRevoked)
    );
    assert_eq!(
        from_failure(Reason::Denied as i32, Wire::CredentialUnavailable as i32, 0),
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
            from_failure(Reason::Denied as i32, wire as i32, 0),
            Some(refusal)
        );
    }
}

#[test]
fn a_refusal_from_a_newer_broker_reads_as_unavailable() {
    assert_eq!(
        from_failure(Reason::Denied as i32, 999, 0),
        Some(Refusal::Unavailable)
    );
}

#[test]
fn a_failure_without_a_valid_reason_is_an_invalid_frame() {
    assert_eq!(
        from_failure(
            Reason::Unspecified as i32,
            Wire::CredentialRevoked as i32,
            0
        ),
        None
    );
    assert_eq!(from_failure(999, Wire::Unspecified as i32, 0), None);
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

/// A rate limit arrives as its own 429 only with a wait in 60 to 600
/// seconds; none, or one out of range, reads as unavailable, as an older
/// broker's or a bad value would (#4975).
#[test]
fn a_rate_limited_refresh_is_its_own_429_only_with_a_bounded_wait() {
    let rate_limited = Wire::CredentialRefreshRateLimited as i32;
    assert_eq!(
        from_failure(Reason::Unavailable as i32, rate_limited, 120),
        Some(Refusal::CredentialRefreshRateLimited {
            retry_after_seconds: 120
        })
    );
    for out_of_range in [0, 59, 601, u32::MAX] {
        assert_eq!(
            from_failure(Reason::Unavailable as i32, rate_limited, out_of_range),
            Some(Refusal::CredentialUnavailable),
            "{out_of_range}"
        );
    }
    // An older broker sends its reason alone.
    assert_eq!(
        from_failure(Reason::Unavailable as i32, Wire::Unspecified as i32, 120),
        Some(Refusal::CredentialUnavailable)
    );
}

/// The 429 carries the wait as `Retry-After` and the reason, and its body
/// names only the provider and the wait (#4975).
#[tokio::test]
async fn a_rate_limited_refresh_answers_429_with_retry_after() {
    let response = refusal_response(
        Refusal::CredentialRefreshRateLimited {
            retry_after_seconds: 240,
        },
        Some(RefusalProvider::Anthropic),
        Some("api.anthropic.com"),
    );
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "240");
    assert_eq!(
        response.headers()[REFUSAL_HEADER],
        "credential_refresh_rate_limited"
    );
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("the Anthropic credential"), "{body}");
    assert!(body.contains("240 seconds"), "{body}");
}

/// A Sandbox whose creator left its organization, or whose creator's account
/// is disabled, answers every credential request with its own 403 and the
/// spec's one sentence (#6406).
#[tokio::test]
async fn a_departed_or_disabled_creator_answers_its_own_403() {
    for (wire, refusal, code, sentence) in [
        (
            Wire::CredentialOwnerDeparted,
            Refusal::CredentialOwnerDeparted,
            "credential_owner_departed",
            "Codewire: this Sandbox's creator is no longer in its organization, so its credentials aren't used.\n",
        ),
        (
            Wire::CredentialOwnerDisabled,
            Refusal::CredentialOwnerDisabled,
            "credential_owner_disabled",
            "Codewire: this Sandbox's creator's account is disabled, so its credentials aren't used.\n",
        ),
    ] {
        assert_eq!(
            from_failure(Reason::Denied as i32, wire as i32, 0),
            Some(refusal)
        );
        let response = refusal_response(
            refusal,
            Some(RefusalProvider::Anthropic),
            Some("api.anthropic.com"),
        );
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[REFUSAL_HEADER], code);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(body, sentence.as_bytes());
    }
}
