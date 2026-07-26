use std::time::Duration;

/// Total request budget for legacy request/response JSON calls.
pub(crate) const LEGACY_JSON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Lifetime class for legacy CLI HTTP requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyHttpCall {
    /// Product or identity request/response call, including body decoding.
    BoundedJson,
}

pub(crate) fn apply_legacy_http_policy(
    request: reqwest::RequestBuilder,
    class: LegacyHttpCall,
    json_timeout: Duration,
) -> reqwest::RequestBuilder {
    match class {
        LegacyHttpCall::BoundedJson => request.timeout(json_timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_json_calls_receive_a_total_timeout() {
        let timeout = Duration::from_millis(25);
        let request = apply_legacy_http_policy(
            reqwest::Client::new().get("http://127.0.0.1/"),
            LegacyHttpCall::BoundedJson,
            timeout,
        )
        .build()
        .unwrap();
        assert_eq!(request.timeout().copied(), Some(timeout));
    }
}
