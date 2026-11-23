use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;

use super::*;

const ENVIRONMENT: &str = "0d9b4c3e-6b1e-4f43-9c1f-6f6f1c1d2e3f";

fn disco(byte: u8) -> String {
    format!("discokey:{}", format!("{byte:02x}").repeat(32))
}

/// A coordinator stand-in that records each lookup's request body and answers
/// `status` with `binding`. Anything but a POST to the lookup is 404.
async fn coordinator(
    status: StatusCode,
    binding: &'static str,
) -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new()
        .fallback(
            move |State(seen): State<Arc<Mutex<Vec<serde_json::Value>>>>,
                  method: Method,
                  uri: Uri,
                  body: axum::body::Bytes| async move {
                if method != Method::POST || uri.path() != CHECK_DISCO_KEY_PATH {
                    return StatusCode::NOT_FOUND.into_response();
                }
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                (status, Json(serde_json::json!({ "binding": binding }))).into_response()
            },
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), seen)
}

/// #5962: each coordinator answer maps to how the key is seen, and the
/// request carries the key's 32 bytes and the asking environment.
#[tokio::test]
async fn each_answer_is_how_the_key_is_seen() {
    for (binding, seen) in [
        ("DISCO_KEY_BINDING_BOUND_HERE", DiscoKeySeen::Here),
        ("DISCO_KEY_BINDING_BOUND_ELSEWHERE", DiscoKeySeen::Elsewhere),
        ("DISCO_KEY_BINDING_UNBOUND", DiscoKeySeen::Unbound),
    ] {
        let (base, bodies) = coordinator(StatusCode::OK, binding).await;
        let admission = HttpDiscoKeyAdmission::new(Some(&base)).unwrap();
        assert_eq!(admission.check(&disco(0xab), ENVIRONMENT).await, Ok(seen));
        let body = bodies.lock().unwrap().pop().unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "discoKey": base64::engine::general_purpose::STANDARD.encode([0xab; 32]),
                "environmentId": ENVIRONMENT,
            })
        );
    }
}

/// #5962: anything but a known answer is unavailable, never an admission:
/// no URL, a refused or failed call, an unknown answer, an unreachable
/// coordinator, or a malformed key.
#[tokio::test]
async fn anything_but_a_known_answer_is_unavailable() {
    let unconfigured = HttpDiscoKeyAdmission::new(None).unwrap();
    assert_eq!(
        unconfigured.check(&disco(1), ENVIRONMENT).await,
        Err(AdmissionUnavailable)
    );
    for (status, binding) in [
        (StatusCode::BAD_REQUEST, "DISCO_KEY_BINDING_BOUND_HERE"),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "DISCO_KEY_BINDING_BOUND_HERE",
        ),
        (StatusCode::OK, "DISCO_KEY_BINDING_UNSPECIFIED"),
        (StatusCode::OK, ""),
    ] {
        let (base, _) = coordinator(status, binding).await;
        let admission = HttpDiscoKeyAdmission::new(Some(&base)).unwrap();
        assert_eq!(
            admission.check(&disco(1), ENVIRONMENT).await,
            Err(AdmissionUnavailable),
            "{status} {binding:?}"
        );
    }
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let unreachable = HttpDiscoKeyAdmission::new(Some(&format!("http://{address}"))).unwrap();
    assert_eq!(
        unreachable.check(&disco(1), ENVIRONMENT).await,
        Err(AdmissionUnavailable)
    );
    let (base, bodies) = coordinator(StatusCode::OK, "DISCO_KEY_BINDING_BOUND_HERE").await;
    let admission = HttpDiscoKeyAdmission::new(Some(&base)).unwrap();
    assert_eq!(
        admission.check("discokey:zz", ENVIRONMENT).await,
        Err(AdmissionUnavailable)
    );
    assert!(bodies.lock().unwrap().is_empty());
}

#[test]
fn a_url_with_credentials_or_another_scheme_is_refused() {
    assert!(HttpDiscoKeyAdmission::new(Some("ftp://coordinator:8097")).is_err());
    assert!(HttpDiscoKeyAdmission::new(Some("http://user:secret@coordinator:8097")).is_err());
    assert!(
        HttpDiscoKeyAdmission::new(Some("  "))
            .unwrap()
            .endpoint
            .is_none()
    );
}
