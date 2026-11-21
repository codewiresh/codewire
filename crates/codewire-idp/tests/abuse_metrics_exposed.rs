// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

//! The IdP's abuse series are served at zero before anything is counted, so
//! the System abuse alerts' `increase()` sees the first count after a restart
//! (#3297 item 13). Its own binary: nothing else in this process counts.

use axum::body::{Body, to_bytes};
use axum::http::Request;
use tower::ServiceExt;

#[tokio::test]
async fn every_abuse_series_is_served_at_zero_before_its_first_count() {
    codewire_idp::expose_abuse_metrics();
    let response = codewire_server_core::metrics::router("idp")
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let rendered = String::from_utf8(body.to_vec()).unwrap();

    let mut expected = vec!["codewire_idp_sign_ups_admitted_total".to_string()];
    for reason in ["credentials", "locked", "refused"] {
        expected.push(format!(
            "codewire_idp_sign_in_failures_total{{reason=\"{reason}\"}}"
        ));
    }
    for reason in ["invalid", "invite_only", "unavailable"] {
        expected.push(format!(
            "codewire_idp_sign_up_refusals_total{{reason=\"{reason}\"}}"
        ));
    }
    for limit in [
        "signup",
        "signup_address",
        "mail_password_reset",
        "mail_verification",
        "admin_account_delete",
        "operator_notice",
        "operator_feedback_notice",
    ] {
        for metric in [
            "codewire_rate_limit_refusals_total",
            "codewire_rate_limit_unavailable_total",
        ] {
            expected.push(format!("{metric}{{limit=\"{limit}\"}}"));
        }
    }
    for series in expected {
        let line = format!("{series} 0");
        assert!(
            rendered.lines().any(|served| served == line),
            "{line} in {rendered}"
        );
    }
}
