//! Registered credential navigation proof using the shared synthetic harness.
use super::*;

const PATH: &str = "/settings/credentials/";
const CREATE: &str = "/settings/credentials/_actions/profiles/create";

#[tokio::test]
async fn github_native_authorize_records_only_fresh_verified_navigation() {
    let (upstream, calls) = fixture("success").await;
    let mut cfg = config(&upstream.origin);
    cfg.github_app_slug = "codewire-synthetic".into();
    cfg.github_app_client_id = "Iv1.kindsynthetic".into();
    let dashboard = serve(crate::app(cfg)).await;
    for suffix in [
        String::new(),
        format!("&creation_draft={DRAFT}"),
        format!("&creation_draft={DRAFT}&creation_draft={DRAFT}"),
    ] {
        let csrf = crate::security::new_csrf_token();
        let response = client()
            .post(format!(
                "{}/settings/credentials/_actions/github/authorize?org=synthetic{suffix}",
                dashboard.origin
            ))
            .headers(authority(&csrf))
            .form(&[("_csrf", csrf.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target =
            url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(target.origin().ascii_serialization(), "https://github.com");
        assert_eq!(target.path(), "/login/oauth/authorize");
        let pairs: Vec<_> = target.query_pairs().collect();
        assert_eq!(pairs.len(), 3);
        assert!(
            pairs
                .iter()
                .any(|(key, value)| key == "client_id" && value == "Iv1.kindsynthetic")
        );
        assert!(pairs.iter().any(|(key, value)| key == "redirect_uri"
            && value == &format!("{ORIGIN}/api/v1/github/oauth/callback")));
        let state = &pairs.iter().find(|(key, _)| key == "state").unwrap().1;
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("Path=/api/v1/github/oauth/;"));
        assert!(cookie.contains("HttpOnly; SameSite=Lax; Max-Age=600; Secure"));
        let state_cookie = cookie.split(';').next().unwrap();
        let mut headers = authority("unused");
        headers.insert(
            header::COOKIE,
            format!("codewire.session_token=synthetic-session; {state_cookie}")
                .parse()
                .unwrap(),
        );
        let continuation = crate::security::github_app_authorization_continuation(
            &headers,
            state,
            &crate::security::canonical_cookie(&headers).unwrap(),
        )
        .unwrap();
        let nav = continuation.navigation.unwrap();
        assert_eq!(nav.organization_id, ORG);
        assert_eq!(
            nav.draft_id.as_deref(),
            (suffix == format!("&creation_draft={DRAFT}")).then_some(DRAFT)
        );
        assert!(continuation.credential_id.is_none() && continuation.expected_generation.is_none());
    }
    assert!(!calls.lock().unwrap().iter().any(|(path, _)| mutation(path)));
}

#[tokio::test]
async fn reconnect_authorization_survives_only_optional_navigation_lookup_failure() {
    for mode in ["success", "optional lookup fails"] {
        let (upstream, calls) = fixture(mode).await;
        let mut cfg = config(&upstream.origin);
        cfg.github_app_slug = "codewire-synthetic".into();
        cfg.github_app_client_id = "Iv1.kindsynthetic".into();
        let dashboard = serve(crate::app(cfg)).await;
        let csrf = crate::security::new_csrf_token();
        let response = client().post(format!("{}/settings/credentials/_actions/github/authorize?org=synthetic&creation_draft={DRAFT}", dashboard.origin)).headers(authority(&csrf)).form(&[("_csrf", csrf.as_str()), ("credential_id", PROJECT), ("expected_revocation_generation", "7"), ("confirm_reconnect", "yes")]).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target =
            url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(target.origin().ascii_serialization(), "https://github.com");
        let state = target
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut headers = authority("unused");
        headers.insert(
            header::COOKIE,
            format!("codewire.session_token=synthetic-session; {cookie}")
                .parse()
                .unwrap(),
        );
        let continuation = crate::security::github_app_authorization_continuation(
            &headers,
            &state,
            &crate::security::canonical_cookie(&headers).unwrap(),
        )
        .unwrap();
        assert_eq!(continuation.credential_id.as_deref(), Some(PROJECT));
        assert_eq!(continuation.expected_generation, Some(7));
        assert_eq!(continuation.navigation.is_some(), mode == "success");
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(path, _)| path == "/api/auth/get-session")
                .count(),
            2
        );
        assert_eq!(
            calls
                .iter()
                .filter(|(path, _)| path.ends_with("/GetCredential"))
                .count(),
            1
        );
        assert!(!calls.iter().any(|(path, _)| mutation(path)));
    }
}

#[tokio::test]
async fn github_callbacks_drop_bad_navigation_without_changing_authorization_or_reconnect() {
    use crate::security::{GitHubAppNavigation, github_app_authorization_cookie};
    const CALLBACK: &str = "/api/v1/github/oauth/callback";
    let session = HeaderValue::from_static("codewire.session_token=synthetic-session");
    for mode in [
        "success",
        "renamed",
        "no membership",
        "mutation denied",
        "mutation unauthenticated",
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        for reconnect in [false, true] {
            for nav_valid in [false, true] {
                for result in ["success", "cancel", "bad code", "bad state"] {
                    let state = crate::security::new_csrf_token();
                    let navigation = GitHubAppNavigation {
                        organization_id: ORG.into(),
                        draft_id: Some(DRAFT.into()),
                    };
                    let cookie = github_app_authorization_cookie(
                        ORIGIN,
                        &state,
                        &session,
                        reconnect.then_some(PROJECT),
                        reconnect.then_some(7),
                        Some(&navigation),
                    )
                    .unwrap();
                    let pair = cookie.split(';').next().unwrap();
                    let pair = if nav_valid {
                        pair.to_owned()
                    } else {
                        format!("{}.not-base64!", pair.split_once('.').unwrap().0)
                    };
                    let mut headers = authority("unused");
                    headers.insert(
                        header::COOKIE,
                        format!("codewire.session_token=synthetic-session; {pair}")
                            .parse()
                            .unwrap(),
                    );
                    let callback_state = if result == "bad state" {
                        crate::security::new_csrf_token()
                    } else {
                        state
                    };
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("state", &callback_state)
                        .append_pair(
                            "code",
                            if result == "bad code" {
                                "invalid?code"
                            } else {
                                "synthetic-callback-code"
                            },
                        )
                        .append_pair(
                            "error",
                            if result == "cancel" {
                                "access_denied"
                            } else {
                                ""
                            },
                        )
                        .append_pair("org", "attacker-org")
                        .append_pair("return_to", "https://foreign.invalid")
                        .finish();
                    let before = calls.lock().unwrap().len();
                    let response = client()
                        .get(format!("{}{CALLBACK}?{query}", dashboard.origin))
                        .headers(headers)
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::SEE_OTHER);
                    assert_eq!(
                        response.headers()[header::CACHE_CONTROL],
                        "no-store, max-age=0"
                    );
                    assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
                    assert!(
                        response.headers()[header::SET_COOKIE]
                            .to_str()
                            .unwrap()
                            .contains("Max-Age=0")
                    );
                    let target = response.headers()[header::LOCATION].to_str().unwrap();
                    let path = target.split_once('?').unwrap().0;
                    let navigation = if path == PATH {
                        target.to_owned()
                    } else {
                        url::form_urlencoded::parse(target.split_once('?').unwrap().1.as_bytes())
                            .find(|(key, _)| key == "return_to")
                            .unwrap()
                            .1
                            .into_owned()
                    };
                    let preserved = nav_valid && mode != "no membership" && result != "bad state";
                    assert_eq!(navigation.contains("creation_draft="), preserved);
                    assert_eq!(navigation.contains("org="), preserved);
                    if preserved {
                        assert!(navigation.contains(if mode == "renamed" {
                            "org=renamed"
                        } else {
                            "org=synthetic"
                        }));
                    }
                    assert!(
                        !target.contains("synthetic-callback-code")
                            && !target.contains("attacker-org")
                            && !target.contains("foreign.invalid")
                            && !target.contains("synthetic-session")
                    );
                    let writes: Vec<_> = calls.lock().unwrap()[before..]
                        .iter()
                        .filter(|(path, _)| mutation(path))
                        .cloned()
                        .collect();
                    assert_eq!(writes.len(), usize::from(result == "success"));
                    if let Some((path, bytes)) = writes.first() {
                        assert!(path.ends_with("/CompleteGithubAppAuthorization"));
                        let mut input = bytes.as_slice();
                        let request = codewire_proto::codewire::v1::CompleteGithubAppAuthorizationRequest::decode(&mut input).unwrap();
                        assert_eq!(
                            request.credential_id.as_deref(),
                            reconnect.then_some(PROJECT)
                        );
                        assert_eq!(
                            request.expected_revocation_generation,
                            reconnect.then_some(7)
                        );
                        assert!(
                            !String::from_utf8_lossy(bytes).contains(DRAFT)
                                && !String::from_utf8_lossy(bytes).contains(ORG)
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn credential_page_has_explicit_return_and_page_owned_native_actions_only() {
    let (upstream, _) = fixture("success").await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    for suffix in [
        String::new(),
        format!("&creation_draft={DRAFT}"),
        format!("&creation_draft={DRAFT}&creation_draft={DRAFT}"),
    ] {
        let response = client()
            .get(format!("{}{PATH}?org=synthetic{suffix}", dashboard.origin))
            .headers(authority("unused"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = response.text().await.unwrap().replace("&#38;", "&amp;");
        let exact = suffix == format!("&creation_draft={DRAFT}");
        assert_eq!(html.contains("Return to Create Sandbox"), exact);
        if exact {
            assert!(html.contains(&format!("href=\"/synthetic/new/?creation_draft={DRAFT}\"")));
            for field in html
                .split('"')
                .filter(|field| field.starts_with("/settings/credentials/_actions/"))
            {
                assert!(
                    field.ends_with(&format!("?org=synthetic&amp;creation_draft={DRAFT}")),
                    "native action lost navigation: {field}"
                );
            }
            assert!(!html.contains(&format!(
                "/settings/?org=synthetic&amp;creation_draft={DRAFT}"
            )));
        } else {
            assert!(!html.contains("creation_draft="));
        }
        assert!(!html.contains(PRIVATE_MARKER) && !html.contains("synthetic-session"));
    }
}

#[tokio::test]
async fn profile_native_and_hx_success_validation_and_upstream_failure_keep_navigation_not_payload()
{
    for mode in ["success", "mutation denied", "mutation unauthenticated"] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        for htmx in [false, true] {
            let mut payloads = Vec::new();
            for suffix in [
                String::new(),
                format!("&creation_draft={DRAFT}"),
                format!("&creation_draft={DRAFT}&creation_draft={DRAFT}"),
            ] {
                let exact = suffix == format!("&creation_draft={DRAFT}");
                for valid in [false, true] {
                    let csrf = crate::security::new_csrf_token();
                    let mut headers = authority(&csrf);
                    if htmx {
                        headers.insert("hx-request", "true".parse().unwrap());
                    }
                    let before = calls.lock().unwrap().len();
                    let response = client()
                        .post(format!(
                            "{}{CREATE}?org=synthetic{suffix}",
                            dashboard.origin
                        ))
                        .headers(headers)
                        .form(&[
                            ("_csrf", csrf.as_str()),
                            ("name", if valid { "synthetic-profile" } else { "" }),
                            ("codex", ""),
                            ("openai", ""),
                            ("github", ""),
                            ("anthropic", ""),
                            ("ssh", ""),
                        ])
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        if htmx {
                            StatusCode::OK
                        } else {
                            StatusCode::SEE_OTHER
                        }
                    );
                    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                    let target = response.headers()[if htmx { "hx-redirect" } else { "location" }]
                        .to_str()
                        .unwrap();
                    // Authentication targets encode the route as their next
                    // query; compare the decoded value, not raw encoding.
                    let path = target.split_once('?').map_or(target, |(path, _)| path);
                    let navigation = if path == PATH {
                        target.to_owned()
                    } else {
                        url::form_urlencoded::parse(target.split_once('?').unwrap().1.as_bytes())
                            .find(|(key, _)| key == "return_to")
                            .unwrap()
                            .1
                            .into_owned()
                    };
                    assert_eq!(navigation.contains("creation_draft="), exact);
                    assert!(navigation.contains("org=synthetic"));
                    if !valid {
                        assert!(
                            target.contains("error=profile-invalid")
                                && target.contains("dialog=create-profile")
                        );
                    }
                    if valid && mode == "success" {
                        assert!(target.contains("message=profile-created"));
                    }
                    assert!(
                        !target.contains(PRIVATE_MARKER) && !target.contains("synthetic-session")
                    );
                    assert!(!response.text().await.unwrap().contains(PRIVATE_MARKER));
                    let new_calls = calls.lock().unwrap()[before..].to_vec();
                    let writes: Vec<_> = new_calls
                        .into_iter()
                        .filter(|(path, _)| mutation(path))
                        .collect();
                    assert_eq!(writes.len(), usize::from(valid));
                    if valid {
                        assert!(writes[0].0.ends_with("/CreateAccessProfile"));
                        payloads.push(writes[0].1.clone());
                    }
                }
            }
            assert!(
                payloads.windows(2).all(|pair| pair[0] == pair[1]),
                "navigation changed profile payload"
            );
        }
    }
}

#[tokio::test]
async fn navigation_does_not_change_credentials_authentication_or_mutation_fences() {
    for mode in [
        "foreign origin",
        "bad csrf",
        "unauthenticated",
        "two factor",
        "no membership",
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        for htmx in [false, true] {
            for suffix in [
                String::new(),
                format!("&creation_draft={DRAFT}"),
                format!("&creation_draft={DRAFT}&creation_draft={DRAFT}"),
            ] {
                let csrf = crate::security::new_csrf_token();
                let mut headers = authority(&csrf);
                if mode == "foreign origin" {
                    headers.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
                }
                if htmx {
                    headers.insert("hx-request", "true".parse().unwrap());
                }
                let response = client()
                    .post(format!(
                        "{}{CREATE}?org=synthetic{suffix}",
                        dashboard.origin
                    ))
                    .headers(headers)
                    .form(&[
                        (
                            "_csrf",
                            if mode == "bad csrf" {
                                "bad-token"
                            } else {
                                csrf.as_str()
                            },
                        ),
                        ("name", "synthetic-profile"),
                        ("codex", ""),
                        ("openai", ""),
                        ("github", ""),
                        ("anthropic", ""),
                        ("ssh", ""),
                    ])
                    .send()
                    .await
                    .unwrap();
                let expected = match mode {
                    "foreign origin" | "bad csrf" => StatusCode::FORBIDDEN,
                    _ if htmx => StatusCode::OK,
                    _ => StatusCode::SEE_OTHER,
                };
                assert_eq!(response.status(), expected, "changed fence for {mode}");
                if mode == "no membership" {
                    let target = response.headers()[if htmx { "hx-redirect" } else { "location" }]
                        .to_str()
                        .unwrap();
                    assert!(target.contains("message=profile-created"));
                }
                if matches!(mode, "unauthenticated" | "two factor") {
                    let target = response.headers()[if htmx { "hx-redirect" } else { "location" }]
                        .to_str()
                        .unwrap();
                    let continuation =
                        url::form_urlencoded::parse(target.split_once('?').unwrap().1.as_bytes())
                            .find(|(key, _)| key == "return_to")
                            .unwrap()
                            .1
                            .into_owned();
                    assert_eq!(
                        continuation.contains("creation_draft="),
                        suffix == format!("&creation_draft={DRAFT}")
                    );
                }
                assert!(!response.text().await.unwrap().contains(PRIVATE_MARKER));
            }
        }
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.iter().filter(|(path, _)| mutation(path)).count(),
            if mode == "no membership" { 6 } else { 0 }
        );
        // Profile mutations are current-user operations, even when a stale
        // organization name is retained solely as navigation context.
        assert!(
            !calls
                .iter()
                .any(|(path, _)| path.ends_with("/ListOrganizations"))
        );
    }
}
