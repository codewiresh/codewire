use super::*;

#[test]
fn return_targets_keep_only_same_origin_paths_and_bounded_request_ids() {
    let target = ReturnTarget::sanitized("request-id", "/device?user_code=ABCD-EFGH");
    assert_eq!(target.auth_request_id.as_deref(), Some("request-id"));
    assert_eq!(target.completion(), "/api/oidc/callback?id=request-id");

    let target = ReturnTarget::sanitized("", "/device?user_code=ABCD-EFGH");
    assert_eq!(target.completion(), "/device?user_code=ABCD-EFGH");

    for unsafe_path in [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example",
        "/x\nLocation: https://evil.example",
        "dashboard",
    ] {
        assert_eq!(safe_return_to(unsafe_path), None, "{unsafe_path:?}");
    }
    assert_eq!(clean_auth_request_id(&"a".repeat(257)), None);
    assert_eq!(clean_auth_request_id("a\u{7}"), None);
    assert_eq!(ReturnTarget::default().completion(), "/dashboard/");
}

#[test]
fn refusals_land_on_login_with_a_fixed_code_and_the_target() {
    let target = ReturnTarget::sanitized("request-id", "");
    let response = login_with_refusal(Refusal::LinkRequired, &target, Vec::new());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/login?oauth_error=link_required&authRequestID=request-id"
    );
}

#[test]
fn pkce_challenges_are_s256_of_the_verifier() {
    // RFC 7636 Appendix B.
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let verifier = pkce_verifier();
    assert_eq!(verifier.len(), 43);
    assert!(
        verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn oauth_cookies_are_http_only_lax_scoped_and_secure_on_https() {
    let value = cookie(STATE_COOKIE, "abc", STATE_COOKIE_PATH, 600, true);
    assert_eq!(
        value,
        "codewire_oauth_state=abc; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
    );
    let cleared = clear_cookie(STATE_COOKIE, STATE_COOKIE_PATH, false);
    assert_eq!(
        cleared,
        "codewire_oauth_state=; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

#[test]
fn a_cookie_sent_twice_is_not_trusted() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("codewire_oauth_state=one; other=x"),
    );
    assert_eq!(unique_cookie(&headers, STATE_COOKIE), Some("one"));
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("codewire_oauth_state=two"),
    );
    assert_eq!(unique_cookie(&headers, STATE_COOKIE), None);
}
