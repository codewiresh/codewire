//! The IdP's abuse counters (#3297 item 13), for the System alerts on
//! sign-in failure and sign-up bursts. Labels are finite outcome classes
//! only: who signed in or up is never a label, as `codewire_server_core::
//! metrics` requires.

use axum::http::StatusCode;
use codewire_server_core::metrics::{IntCounter, IntCounterVec, counter, counter_vec};
use std::sync::OnceLock;

static SIGN_IN_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();
static SIGN_UPS_ADMITTED: OnceLock<IntCounter> = OnceLock::new();
static SIGN_UP_REFUSALS: OnceLock<IntCounterVec> = OnceLock::new();

pub(crate) fn sign_in_failures() -> &'static IntCounterVec {
    SIGN_IN_FAILURES.get_or_init(|| {
        counter_vec(
            "codewire_idp_sign_in_failures_total",
            "Email and password sign-ins refused, by reason.",
            &["reason"],
        )
    })
}

pub(crate) fn sign_ups_admitted() -> &'static IntCounter {
    SIGN_UPS_ADMITTED.get_or_init(|| {
        counter(
            "codewire_idp_sign_ups_admitted_total",
            "Sign-ups that passed their own checks and the sign-up limits.",
        )
    })
}

pub(crate) fn sign_up_refusals() -> &'static IntCounterVec {
    SIGN_UP_REFUSALS.get_or_init(|| {
        counter_vec(
            "codewire_idp_sign_up_refusals_total",
            "Sign-ups refused by their own checks (fields, human verification, reason, \
             invitation), by reason. The sign-up limits' refusals are in \
             codewire_rate_limit_refusals_total.",
            &["reason"],
        )
    })
}

/// Every reason [`sign_in_reason`] and [`sign_up_reason`] can give, so
/// [`expose`] can show each series before its first count.
const SIGN_IN_REASONS: [&str; 3] = ["credentials", "locked", "refused"];
const SIGN_UP_REASONS: [&str; 3] = ["invalid", "invite_only", "unavailable"];

/// Exposes the IdP's abuse series and its rate limits' series at zero before
/// anything is counted (#3297 item 13). A series that first appears at 1 has
/// no earlier sample, so an alert's `increase()` misses that first count.
pub fn expose() {
    for reason in SIGN_IN_REASONS {
        sign_in_failures().with_label_values(&[reason]);
    }
    sign_ups_admitted();
    for reason in SIGN_UP_REASONS {
        sign_up_refusals().with_label_values(&[reason]);
    }
    // Every limit the IdP takes: the unreadable-limit alert reads them all.
    use codewire_server_core::rate_limit::{
        ADMIN_ACCOUNT_DELETE, MAIL_PASSWORD_RESET, MAIL_VERIFICATION, OPERATOR_FEEDBACK_NOTICE,
        OPERATOR_NOTICE, SIGNUP, SIGNUP_ADDRESS, expose_limits,
    };
    expose_limits(&[
        &SIGNUP,
        &SIGNUP_ADDRESS,
        &MAIL_PASSWORD_RESET,
        &MAIL_VERIFICATION,
        &ADMIN_ACCOUNT_DELETE,
        &OPERATOR_NOTICE,
        &OPERATOR_FEEDBACK_NOTICE,
    ]);
}

/// Why a sign-in failed, from its answer: wrong or unknown credentials, a
/// locked account, or an account that may not sign in (unverified, disabled).
fn sign_in_reason(status: StatusCode) -> Option<&'static str> {
    match status {
        StatusCode::UNAUTHORIZED => Some("credentials"),
        StatusCode::TOO_MANY_REQUESTS => Some("locked"),
        StatusCode::FORBIDDEN => Some("refused"),
        _ => None,
    }
}

/// Why a sign-up's own checks refused it, from its answer: a field or the
/// human-verification challenge was wrong, the server admits only invitations,
/// or a check could not run.
fn sign_up_reason(status: StatusCode) -> &'static str {
    match status {
        StatusCode::FORBIDDEN => "invite_only",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        _ => "invalid",
    }
}

/// Counts a sign-in that answered `status`, if it failed.
pub(crate) fn sign_in_answered(status: StatusCode) {
    if let Some(reason) = sign_in_reason(status) {
        sign_in_failures().with_label_values(&[reason]).inc();
    }
}

/// Counts a sign-up its own checks refused with `status`.
pub(crate) fn sign_up_refused(status: StatusCode) {
    sign_up_refusals()
        .with_label_values(&[sign_up_reason(status)])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_sign_in_counts_once_under_its_reason_and_a_success_not_at_all() {
        let count = |reason| sign_in_failures().with_label_values(&[reason]).get();
        let before = [count("credentials"), count("locked"), count("refused")];
        sign_in_answered(StatusCode::UNAUTHORIZED);
        sign_in_answered(StatusCode::TOO_MANY_REQUESTS);
        sign_in_answered(StatusCode::FORBIDDEN);
        sign_in_answered(StatusCode::OK);
        let after = [count("credentials"), count("locked"), count("refused")];
        // Other tests in this binary only add, so each grew by at least one.
        for (before, after) in before.iter().zip(after) {
            assert!(after > *before, "{before} -> {after}");
        }
        assert_eq!(sign_in_reason(StatusCode::OK), None);
    }

    #[test]
    fn a_refused_sign_up_counts_under_a_finite_reason() {
        assert_eq!(sign_up_reason(StatusCode::BAD_REQUEST), "invalid");
        assert_eq!(sign_up_reason(StatusCode::UNPROCESSABLE_ENTITY), "invalid");
        assert_eq!(sign_up_reason(StatusCode::FORBIDDEN), "invite_only");
        assert_eq!(
            sign_up_reason(StatusCode::SERVICE_UNAVAILABLE),
            "unavailable"
        );
        let before = sign_up_refusals().with_label_values(&["invalid"]).get();
        sign_up_refused(StatusCode::BAD_REQUEST);
        assert!(sign_up_refusals().with_label_values(&["invalid"]).get() > before);
    }

    #[test]
    fn every_reason_a_sign_in_or_sign_up_can_give_is_exposed() {
        // `tests/abuse_metrics_exposed.rs` proves the exposed series are
        // served at zero; this proves no answer maps outside them.
        for code in 100..600 {
            let status = StatusCode::from_u16(code).unwrap();
            if let Some(reason) = sign_in_reason(status) {
                assert!(SIGN_IN_REASONS.contains(&reason), "{reason}");
            }
            assert!(SIGN_UP_REASONS.contains(&sign_up_reason(status)));
        }
    }
}
