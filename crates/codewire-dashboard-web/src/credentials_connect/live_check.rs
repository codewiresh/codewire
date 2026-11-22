//! Whether a credentials page load may run the live GitHub check.

/// The longest referrer read. A browser's referrer for a dashboard page is
/// far shorter; anything longer is refused before it is parsed (#5938).
const MAX_REFERRER_BYTES: usize = 2048;

/// Whether this credentials page load may run the live GitHub check: never
/// for a navigation another site started, so a link elsewhere cannot make
/// the dashboard call GitHub or renew a token (#2712). A request without
/// fetch metadata (no browser, or an old one) is the person's own.
pub(crate) fn live_check_allowed(headers: &axum::http::HeaderMap, public_origin: &str) -> bool {
    match headers
        .get("sec-fetch-site")
        .map(|value| value.to_str().unwrap_or("unreadable"))
    {
        None | Some("same-origin" | "same-site" | "none") => true,
        Some("cross-site") => false,
        // Anything else counts only with a referrer from this dashboard.
        Some(_) => headers
            .get(axum::http::header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(http_origin)
            .is_some_and(|referrer| Some(referrer) == http_origin(public_origin)),
    }
}

/// The origin of an http or https URL. Anything else, or anything longer
/// than the bound, is None without being parsed (#5938).
fn http_origin(value: &str) -> Option<String> {
    if !parseable(value) {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// Whether a value is short enough and starts with `http://` or `https://`,
/// in any case. Nothing else reaches the URL parser.
fn parseable(value: &str) -> bool {
    let starts = |prefix: &str| {
        value
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    };
    value.len() <= MAX_REFERRER_BYTES && (starts("http://") || starts("https://"))
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    const ORIGIN: &str = "https://codewire.sh";

    fn cross_origin_with_referrer(referrer: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-origin"));
        headers.insert(
            axum::http::header::REFERER,
            HeaderValue::from_str(referrer).unwrap(),
        );
        headers
    }

    #[test]
    fn only_a_bounded_http_or_https_value_reaches_the_parser() {
        for parsed in [
            "https://codewire.sh/settings/",
            "http://codewire.sh/",
            "HTTPS://codewire.sh/",
        ] {
            assert!(parseable(parsed), "{parsed}");
        }
        let nested = format!("{}https://codewire.sh/", "blob:".repeat(10_000));
        let long = format!("https://codewire.sh/{}", "a".repeat(MAX_REFERRER_BYTES));
        for refused in [
            nested.as_str(),
            long.as_str(),
            "blob:https://codewire.sh/",
            "file:///settings/",
            "data:text/plain,x",
            " https://codewire.sh/",
            "https:codewire.sh/",
            "",
        ] {
            assert!(!parseable(refused), "{refused:.40}");
            assert_eq!(http_origin(refused), None, "{refused:.40}");
        }
    }

    #[test]
    fn a_referrer_that_is_not_a_bounded_http_url_never_allows_the_check() {
        let nested = format!("{}https://codewire.sh/", "blob:".repeat(10_000));
        let long = format!("https://codewire.sh/{}", "a".repeat(MAX_REFERRER_BYTES));
        for refused in [nested.as_str(), long.as_str(), "blob:https://codewire.sh/"] {
            assert!(
                !live_check_allowed(&cross_origin_with_referrer(refused), ORIGIN),
                "{refused:.40}"
            );
        }
        assert!(live_check_allowed(
            &cross_origin_with_referrer("https://codewire.sh/settings/"),
            ORIGIN
        ));
    }
}
