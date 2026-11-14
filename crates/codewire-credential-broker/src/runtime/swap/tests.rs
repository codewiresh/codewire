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
        ("authorization", format!("bearer  {OURS}")),
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
