//! Registered credential navigation proof using the shared synthetic harness.
use super::*;

const PATH: &str = "/settings/credentials/";
const CREATE: &str = "/settings/credentials/_actions/profiles/create";
const RENAME: &str = "/settings/credentials/_actions/profiles/rename";

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
                    let cookies: Vec<_> = response
                        .headers()
                        .get_all(header::SET_COOKIE)
                        .iter()
                        .map(|value| value.to_str().unwrap().to_owned())
                        .collect();
                    assert!(cookies.iter().any(|cookie| {
                        cookie.starts_with("codewire_github_app_authorization=")
                            && cookie.contains("Max-Age=0")
                    }));
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
                    assert!(!navigation.contains("org="));
                    // The organization the signed navigation named becomes the
                    // remembered one; the callback URL never selects it.
                    let remembered = format!(
                        "codewire_current_org={};",
                        if mode == "renamed" {
                            "renamed"
                        } else {
                            "synthetic"
                        }
                    );
                    assert_eq!(
                        cookies.iter().any(|cookie| cookie.starts_with(&remembered)),
                        preserved
                    );
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
        let query = suffix.trim_start_matches('&');
        let response = client()
            .get(format!(
                "{}{PATH}{}{query}",
                dashboard.origin,
                if query.is_empty() { "" } else { "?" }
            ))
            .headers(remembered_authority("unused"))
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
                    field.ends_with(&format!("?creation_draft={DRAFT}")),
                    "native action lost navigation: {field}"
                );
            }
            // Only the organization switcher's relative links name one.
            assert!(!html.replace("href=\"?org=", "").contains("org="));
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
                    // An action posted from an older page may still name its
                    // organization; the page it returns to does not.
                    assert!(!navigation.contains("org="));
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

#[tokio::test]
async fn profile_rename_sends_only_the_observed_view_and_new_label() {
    let dialog = format!("dialog=profile-{PROJECT}-rename");
    for (mode, expected, name, outcome, writes) in [
        (
            "success",
            "work",
            "  personal  ",
            "message=profile-renamed",
            1,
        ),
        (
            "success",
            "work",
            "Not a profile name",
            "error=profile-invalid",
            0,
        ),
        ("success", "work", "", "error=profile-invalid", 0),
        // The observed name is validated like the new one.
        ("success", "Work", "personal", "error=profile-invalid", 0),
        ("success", "", "personal", "error=profile-invalid", 0),
        (
            "mutation conflict",
            "work",
            "personal",
            "error=profile-rename-conflict",
            1,
        ),
        (
            "mutation denied",
            "work",
            "personal",
            "error=request-failed",
            1,
        ),
        // An acknowledgement that published a revision is not a rename.
        (
            "rename advances revision",
            "work",
            "personal",
            "error=request-failed",
            1,
        ),
        ("mutation unauthenticated", "work", "personal", "/login", 1),
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        let csrf = crate::security::new_csrf_token();
        let response = client()
            .post(format!(
                "{}{RENAME}?creation_draft={DRAFT}",
                dashboard.origin
            ))
            .headers(authority(&csrf))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("profile_id", PROJECT),
                ("expected_revision", "9"),
                ("expected_name", expected),
                ("name", name),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "{mode} {expected} {name}"
        );
        let target = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            target.contains(outcome),
            "{mode} {expected} {name}: {target}"
        );
        if outcome.starts_with("error=") {
            assert!(target.starts_with(&format!("{PATH}?creation_draft={DRAFT}&")));
            assert!(target.ends_with(&format!("&{dialog}")), "{target}");
        } else if outcome.starts_with("message=") {
            assert_eq!(
                target,
                format!("{PATH}?creation_draft={DRAFT}&message=profile-renamed")
            );
        } else {
            // The login continuation keeps the page and its draft.
            let continuation =
                url::form_urlencoded::parse(target.split_once('?').unwrap().1.as_bytes())
                    .find(|(key, _)| key == "return_to")
                    .unwrap()
                    .1
                    .into_owned();
            assert_eq!(continuation, format!("{PATH}?creation_draft={DRAFT}"));
        }
        let calls = calls.lock().unwrap();
        let sent: Vec<_> = calls.iter().filter(|(path, _)| mutation(path)).collect();
        assert_eq!(sent.len(), writes, "{mode} {expected} {name}");
        if let Some((path, bytes)) = sent.first() {
            assert!(path.ends_with("/codewire.v1.AccessProfileService/RenameAccessProfile"));
            let mut input = bytes.as_slice();
            let request =
                codewire_proto::codewire::v1::RenameAccessProfileRequest::decode(&mut input)
                    .unwrap();
            assert_eq!(request.access_profile_id, PROJECT);
            assert_eq!(request.expected_revision, 9);
            assert_eq!(request.expected_name, "work");
            assert_eq!(request.name, "personal");
            assert!(!String::from_utf8_lossy(bytes).contains(DRAFT));
        }
        // Rename never edits identities or falls back to another mutation.
        assert!(
            !calls
                .iter()
                .any(|(path, _)| path.ends_with("/UpdateAccessProfile")
                    || path.ends_with("/GetAccessProfile"))
        );
    }
    for (mode, expected) in [
        ("foreign origin", StatusCode::FORBIDDEN),
        ("bad csrf", StatusCode::FORBIDDEN),
    ] {
        let (upstream, calls) = fixture("success").await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        let csrf = crate::security::new_csrf_token();
        let mut headers = authority(&csrf);
        if mode == "foreign origin" {
            headers.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
        }
        let response = client()
            .post(format!("{}{RENAME}", dashboard.origin))
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
                ("profile_id", PROJECT),
                ("expected_revision", "9"),
                ("expected_name", "work"),
                ("name", "personal"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{mode}");
        assert!(!calls.lock().unwrap().iter().any(|(path, _)| mutation(path)));
    }
}

/// A signed-in browser whose remembered organization is the synthetic one.
fn remembered_authority(csrf: &str) -> HeaderMap {
    let mut headers = authority(csrf);
    headers.insert(
        header::COOKIE,
        format!(
            "codewire.session_token=synthetic-session; codewire_ssr_csrf={csrf}; codewire_current_org=synthetic"
        )
        .parse()
        .unwrap(),
    );
    headers
}

const ADDITION_NAME: &str = "Synthetic \"plan\" <one>";
const RETAINED_NAME: &str = "value=\"Synthetic &#34;plan&#34; &#60;one&#62;\"";
const ADDITIONS: [&str; 5] = [
    "add-openai-api-key",
    "add-anthropic-api-key",
    "add-claude-subscription-token",
    "generate-ssh",
    "import-ssh",
];

/// One addition's action and fields. Every secret field carries the private
/// marker; an unusable submission has a past expiry or a malformed token.
fn addition(dialog: &str, usable: bool) -> (&'static str, Vec<(&'static str, String)>) {
    let expiry = if usable { "" } else { "2000-01-01T00:00" };
    let (action, mut fields) = match dialog {
        "add-openai-api-key" | "add-anthropic-api-key" => (
            "api-key/add",
            vec![
                ("provider", dialog.split('-').nth(1).unwrap().into()),
                ("value", PRIVATE_MARKER.into()),
                ("expiration_utc", expiry.into()),
            ],
        ),
        "add-claude-subscription-token" => (
            "claude-subscription-token/add",
            vec![(
                "token",
                if usable {
                    PRIVATE_MARKER.into()
                } else {
                    format!("{PRIVATE_MARKER} pasted with spaces")
                },
            )],
        ),
        "generate-ssh" => ("ssh/generate", vec![("expiration_utc", expiry.into())]),
        "import-ssh" => (
            "ssh/import",
            vec![
                ("private_key", PRIVATE_MARKER.into()),
                ("passphrase", PRIVATE_MARKER.into()),
                ("expiration_utc", expiry.into()),
            ],
        ),
        _ => unreachable!("{dialog}"),
    };
    fields.push(("name", ADDITION_NAME.into()));
    (action, fields)
}

async fn submit_addition(
    origin: &str,
    dialog: &str,
    usable: bool,
) -> (StatusCode, HeaderMap, String) {
    let csrf = crate::security::new_csrf_token();
    let (action, mut fields) = addition(dialog, usable);
    fields.push(("_csrf", csrf.clone()));
    let response = client()
        .post(format!(
            "{origin}{PATH}_actions/credentials/{action}?org=synthetic"
        ))
        .headers(authority(&csrf))
        .form(&fields)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (status, headers, response.text().await.unwrap())
}

fn assert_rejected_in_place(dialog: &str, headers: &HeaderMap, html: &str, message: &str) {
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    // Still the Credentials page: its GitHub authorization keeps working.
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("form-action 'self' https://github.com")
    );
    assert_eq!(html.matches("data-dialog-auto-open").count(), 1, "{dialog}");
    assert!(html.contains(&format!(
        "id=\"{dialog}\" aria-labelledby=\"{dialog}-title\" data-dialog-auto-open"
    )));
    assert_eq!(html.matches(RETAINED_NAME).count(), 1, "{dialog}");
    let message = message.replace('\'', "&#39;");
    assert!(
        html.contains(&format!("role=\"alert\">{message}</p>")),
        "{dialog}"
    );
    assert!(!html.contains(PRIVATE_MARKER), "{dialog} echoed a secret");
    assert!(!html.contains("synthetic-session"));
}

#[tokio::test]
async fn unusable_additions_reopen_their_dialog_with_the_name_and_no_secret() {
    let (upstream, calls) = fixture("success").await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    for dialog in ADDITIONS {
        let (status, headers, html) = submit_addition(&dashboard.origin, dialog, false).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{dialog}");
        let message = if dialog == "add-claude-subscription-token" {
            "That doesn't look like a Claude subscription token. Run claude setup-token and paste the whole token."
        } else {
            "The credential submission is invalid."
        };
        assert_rejected_in_place(dialog, &headers, &html, message);
    }
    assert!(!calls.lock().unwrap().iter().any(|(path, _)| mutation(path)));
}

#[tokio::test]
async fn service_rejections_keep_the_name_and_uncertain_outcomes_redirect_without_it() {
    for mode in [
        "mutation conflict",
        "mutation denied",
        "mutation unavailable",
        "mutation unauthenticated",
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        for dialog in ADDITIONS {
            let (status, headers, html) = submit_addition(&dashboard.origin, dialog, true).await;
            match mode {
                "mutation conflict" | "mutation denied" => {
                    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{mode} {dialog}");
                    let message = if mode == "mutation conflict" {
                        "The credential changed. Reload and try again."
                    } else {
                        "The credential change could not be completed. Try again."
                    };
                    assert_rejected_in_place(dialog, &headers, &html, message);
                }
                _ => {
                    // A possibly saved submission, or an ended session, is
                    // never answered in place where a reload resends it.
                    assert_eq!(status, StatusCode::SEE_OTHER, "{mode} {dialog}");
                    let target = headers[header::LOCATION].to_str().unwrap();
                    if mode == "mutation unavailable" {
                        assert_eq!(
                            target,
                            format!("{PATH}?error=credential-uncertain&dialog={dialog}")
                        );
                    } else {
                        assert!(target.starts_with("/login?"), "{target}");
                    }
                    assert!(!target.contains("Synthetic") && !target.contains(PRIVATE_MARKER));
                    assert!(!html.contains(PRIVATE_MARKER));
                }
            }
        }
        let calls = calls.lock().unwrap();
        let writes: Vec<_> = calls.iter().filter(|(path, _)| mutation(path)).collect();
        assert_eq!(writes.len(), ADDITIONS.len(), "{mode}");
    }
}
