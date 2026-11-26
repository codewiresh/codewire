use http::{HeaderMap, HeaderValue};

use super::*;

const OURS: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
}

fn placeholder(presented: Presented) -> Option<String> {
    match presented {
        Presented::Placeholder(placeholder) => Some(placeholder.as_str().to_owned()),
        _ => None,
    }
}

/// Each swap shape yields the placeholder, scheme case aside.
#[test]
fn every_swap_shape_presents_the_placeholder() {
    let basic = STANDARD.encode(format!("user:{OURS}"));
    for (name, value) in [
        ("authorization", OURS.to_owned()),
        ("authorization", format!("Bearer {OURS}")),
        ("authorization", format!("bearer {OURS}")),
        ("authorization", format!("Token {OURS}")),
        ("authorization", format!("Basic {basic}")),
        ("x-api-key", OURS.to_owned()),
    ] {
        assert_eq!(
            placeholder(Presented::of(&headers(&[(name, value.clone())]))).as_deref(),
            Some(OURS),
            "{name}: {value}"
        );
    }
}

/// A value that is not exactly a placeholder in a swap shape is foreign: a
/// user's own key, a placeholder inside a longer value or under another
/// scheme, one in a header the rule doesn't swap, or no credential at all.
#[test]
fn anything_but_a_swap_shape_is_foreign() {
    for pairs in [
        vec![],
        vec![("authorization", "Bearer sk-ant-users-own-key".to_owned())],
        vec![("x-api-key", "sk-ant-users-own-key".to_owned())],
        vec![("authorization", format!("Bearer {OURS}x"))],
        vec![("authorization", format!("Bearer {OURS} trailing"))],
        vec![("authorization", format!("Digest {OURS}"))],
        vec![("authorization", format!("Bearer  {OURS}"))],
        vec![("authorization", format!("Token  {OURS}"))],
        vec![("x-api-key", format!(" {OURS}"))],
        vec![("cookie", format!("session={OURS}"))],
        vec![("proxy-authorization", format!("Bearer {OURS}"))],
        vec![("authorization", "Basic !!!".to_owned())],
        vec![("x-other", OURS.to_owned())],
    ] {
        assert!(
            matches!(Presented::of(&headers(&pairs)), Presented::Foreign),
            "{pairs:?}"
        );
    }
}

/// A placeholder beside any other credential header, or twice, is refused.
#[test]
fn a_placeholder_with_another_credential_is_a_conflict() {
    for pairs in [
        vec![
            ("authorization", format!("Bearer {OURS}")),
            ("x-api-key", "sk-ant-users-own-key".to_owned()),
        ],
        vec![
            ("x-api-key", OURS.to_owned()),
            ("cookie", "session=1".to_owned()),
        ],
        vec![
            ("x-api-key", OURS.to_owned()),
            ("proxy-authorization", "Basic dTpw".to_owned()),
        ],
        vec![
            ("authorization", format!("Bearer {OURS}")),
            ("authorization", "Bearer other".to_owned()),
        ],
        vec![
            ("authorization", format!("Bearer {OURS}")),
            ("x-api-key", OURS.to_owned()),
        ],
    ] {
        assert!(
            matches!(Presented::of(&headers(&pairs)), Presented::Conflict),
            "{pairs:?}"
        );
    }
}

/// Framing goes, as do the headers `connection` names; credentials,
/// `accept-encoding` and cookies stay.
#[test]
fn forwarding_strips_framing_only() {
    let kept = without_framing(&headers(&[
        ("host", "api.anthropic.com".into()),
        ("content-length", "2".into()),
        ("connection", "keep-alive, x-hop".into()),
        ("x-hop", "1".into()),
        ("transfer-encoding", "chunked".into()),
        ("authorization", "Bearer sk-ant-users-own-key".into()),
        ("accept-encoding", "gzip".into()),
        ("set-cookie", "a=b".into()),
        ("anthropic-version", "2023-06-01".into()),
    ]));
    let mut names: Vec<_> = kept.keys().map(|name| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "accept-encoding",
            "anthropic-version",
            "authorization",
            "set-cookie"
        ]
    );
}

const THEIRS: &str = "cwp1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

/// The cache remembers this environment's placeholder for
/// `PLACEHOLDER_FRESH_FOR` only. After that a foreign value costs a lease
/// again, so a rebind is seen within the window. Forcing the freshness check
/// to always hold fails this test.
#[tokio::test(start_paused = true)]
async fn the_placeholder_cache_forgets_after_its_window() {
    let cache = PlaceholderCache::default();
    let slot = CapabilitySlot::parse("anthropic").unwrap();
    let ours = CredentialPlaceholder::parse(OURS).unwrap();
    let theirs = CredentialPlaceholder::parse(THEIRS).unwrap();
    cache.remember(&slot, Some(&ours));
    assert!(cache.known_foreign(&slot, &theirs));
    assert!(!cache.known_foreign(&slot, &ours));
    tokio::time::advance(PLACEHOLDER_FRESH_FOR - Duration::from_secs(1)).await;
    assert!(cache.known_foreign(&slot, &theirs));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!cache.known_foreign(&slot, &theirs));
}

/// A forwarded reply is bounded: past `max_bytes` the stream ends with
/// `ResponseTooLarge` instead of passing more bytes.
#[tokio::test]
async fn a_forwarded_reply_past_its_bound_is_refused() {
    use futures::StreamExt as _;
    let upstream: BrokerUpstreamBody = Box::pin(futures::stream::iter([
        Ok(bytes::Bytes::from_static(b"abcd")),
        Ok(bytes::Bytes::from_static(b"efgh")),
    ]));
    let mut body = forwarded_body(upstream, 6);
    assert_eq!(body.next().await.unwrap().unwrap(), &b"abcd"[..]);
    assert!(matches!(
        body.next().await,
        Some(Err(BrokerRequestError::ResponseTooLarge))
    ));
}

/// Swap carriers are scoped per route: Gemini accepts `x-goog-api-key` alone
/// and refuses `cwp1_` in any other credential header; non-Gemini routes never
/// swap `x-goog-api-key` and refuse `cwp1_` placed there (#6555).
#[test]
fn gemini_swap_carrier_is_scoped_per_route_and_fails_closed() {
    let basic = STANDARD.encode(format!("user:{OURS}"));
    // Gemini swaps exact `x-goog-api-key` placeholder alone.
    assert_eq!(
        placeholder(Presented::of_for(
            &headers(&[("x-goog-api-key", OURS.to_owned())]),
            SwapCarrier::GeminiApiKey,
        ))
        .as_deref(),
        Some(OURS)
    );
    // Non-Gemini routes never accept `x-goog-api-key` as a swap trigger and
    // refuse a `cwp1_` placeholder in it, while counting a foreign value as a
    // conflict beside a standard placeholder.
    assert!(matches!(
        Presented::of(&headers(&[("x-goog-api-key", OURS.to_owned())])),
        Presented::DisallowedPlaceholder
    ));
    assert!(matches!(
        Presented::of(&headers(&[
            ("x-api-key", OURS.to_owned()),
            ("x-goog-api-key", "foreign-key".to_owned()),
        ])),
        Presented::Conflict
    ));
    // Gemini refuses any `cwp1_` placeholder in a disallowed credential header
    // or malformed `x-goog-api-key` (never forwarded).
    for pairs in [
        vec![("authorization", format!("Bearer {OURS}"))],
        vec![("authorization", format!("Basic {basic}"))],
        vec![("x-api-key", OURS.to_owned())],
        vec![("cookie", format!("session={OURS}"))],
        vec![("proxy-authorization", format!("Bearer {OURS}"))],
        vec![("x-goog-api-key", format!("Bearer {OURS}"))],
        vec![("x-goog-api-key", format!(" {OURS}"))],
    ] {
        assert!(
            matches!(
                Presented::of_for(&headers(&pairs), SwapCarrier::GeminiApiKey),
                Presented::DisallowedPlaceholder
            ),
            "{pairs:?}"
        );
    }
    // Gemini refuses a placeholder beside another credential header as Conflict.
    for pairs in [
        vec![
            ("x-goog-api-key", OURS.to_owned()),
            ("authorization", "Bearer user-key".to_owned()),
        ],
        vec![
            ("x-goog-api-key", OURS.to_owned()),
            ("x-api-key", "user-key".to_owned()),
        ],
        vec![
            ("x-goog-api-key", OURS.to_owned()),
            ("cookie", "s=1".to_owned()),
        ],
        vec![
            ("x-goog-api-key", OURS.to_owned()),
            ("x-goog-api-key", "second".to_owned()),
        ],
    ] {
        assert!(
            matches!(
                Presented::of_for(&headers(&pairs), SwapCarrier::GeminiApiKey),
                Presented::Conflict
            ),
            "{pairs:?}"
        );
    }
    // Foreign credentials without `cwp1_` follow the untouched-forward rule.
    for pairs in [
        vec![],
        vec![("x-goog-api-key", "user-own-key".to_owned())],
        vec![("authorization", "Bearer user-own-token".to_owned())],
    ] {
        assert!(
            matches!(
                Presented::of_for(&headers(&pairs), SwapCarrier::GeminiApiKey),
                Presented::Foreign
            ),
            "{pairs:?}"
        );
    }
}

/// Raw and percent-decoded query parameters carrying `cwp1_` fail closed, and
/// `key` / `access_token` query parameters conflict with a swapped Gemini header.
#[test]
fn gemini_query_placeholder_and_conflict_checks_decode_percent_escapes() {
    for raw in [
        format!("key={OURS}"),
        format!("key=cwp1%5F{}", &OURS[5..]),
        format!("alt=sse&other=%63wp1%5F{}", &OURS[5..]),
        "cwp1%5Fname=1".to_string(),
    ] {
        assert!(query_carries_placeholder_tag(Some(&raw)), "{raw}");
    }
    for clean in [None, Some(""), Some("alt=sse"), Some("key=user-key")] {
        assert!(!query_carries_placeholder_tag(clean), "{clean:?}");
    }
    for conflict in [
        "key=user-key",
        "alt=sse&key=user-key",
        "access_token=ya29.user",
        "%6bey=user-key",
        "access%5Ftoken=tok",
        "KEY=user-key",
    ] {
        assert!(
            query_has_google_credential_param(Some(conflict)),
            "{conflict}"
        );
    }
    for ok in [None, Some(""), Some("alt=sse"), Some("apikey=1")] {
        assert!(!query_has_google_credential_param(ok), "{ok:?}");
    }
}
