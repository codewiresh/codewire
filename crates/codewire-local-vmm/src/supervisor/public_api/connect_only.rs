//! The public routes are Connect over HTTP only: a request in any other
//! protocol is refused before it reaches a service.

use axum::extract::Request as AxumRequest;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response as AxumResponse};
use http::{HeaderValue, Method, StatusCode as HttpStatus, header};

const ACCEPT_POST: &str =
    "application/connect+json, application/connect+proto, application/json, application/proto";

pub(super) async fn enforce_connect_only(request: AxumRequest, next: Next) -> AxumResponse {
    let admitted = match *request.method() {
        Method::GET => true,
        Method::POST => {
            let mut values = request.headers().get_all(header::CONTENT_TYPE).iter();
            let first = values.next();
            values.next().is_none() && first.is_some_and(connect_content_type)
        }
        _ => false,
    };
    if admitted {
        return next.run(request).await;
    }
    let mut response = HttpStatus::UNSUPPORTED_MEDIA_TYPE.into_response();
    response.headers_mut().insert(
        http::HeaderName::from_static("accept-post"),
        HeaderValue::from_static(ACCEPT_POST),
    );
    response
}

pub(super) fn connect_content_type(value: &HeaderValue) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    let essence = value.split(';').next().unwrap_or_default().trim();
    [
        "application/connect+json",
        "application/connect+proto",
        "application/json",
        "application/proto",
    ]
    .iter()
    .any(|allowed| essence.eq_ignore_ascii_case(allowed))
}
