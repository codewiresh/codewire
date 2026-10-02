//! The fixed answer a selected capability gives while its credential cannot be
//! used: its refresh failed, or it was revoked or expired. Only the owner can
//! restore it, from Codewire Settings, so the route says that instead of a
//! bare failure. The body is a constant: it carries no credential, provider
//! response, account or identifier, and no provider is contacted.

use bytes::Bytes;
use codewire_access::CapabilitySlot;
use futures::stream;
use http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::BrokerHttpResponse;

/// Stable machine-readable code in the OpenAI-shaped error bodies.
pub(crate) const RECONNECT_REQUIRED_CODE: &str = "credential_reconnect_required";

/// 403 is final for stock OpenAI, Anthropic and Codex clients: none retries
/// it, so the message is shown at once rather than after backoff, and none
/// mistakes it for its own login having expired, as it would a 401.
pub(crate) fn reconnect_required_response(slot: &CapabilitySlot) -> BrokerHttpResponse {
    let body = match slot.as_str() {
        "codex" => openai_error("Codex needs Reconnect in Codewire Settings → Credentials."),
        "openai" => openai_error(
            "The OpenAI API key needs replacing: rotate it in Codewire Settings → Credentials.",
        ),
        "anthropic" => serde_json::json!({
            "type": "error",
            "error": {
                "type": "permission_error",
                "message": "The Anthropic API key needs replacing: rotate it in Codewire Settings → Credentials.",
            },
        }),
        "github" => serde_json::json!({
            "message": "GitHub needs Reconnect in Codewire Settings → Credentials.",
        }),
        _ => serde_json::json!({
            "message": "This credential needs Reconnect in Codewire Settings → Credentials.",
        }),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let body = Bytes::from(body.to_string());
    BrokerHttpResponse::new(
        StatusCode::FORBIDDEN,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}

fn openai_error(message: &str) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "message": message,
            "type": "codewire_credential_unavailable",
            "code": RECONNECT_REQUIRED_CODE,
            "param": null,
        },
    })
}
