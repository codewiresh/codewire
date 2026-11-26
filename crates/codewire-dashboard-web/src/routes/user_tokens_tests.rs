//! The API keys page's User tokens group (#5688): what it lists, and where a
//! revoke sends the browser.
use askama::Template;
use axum::http::{HeaderMap, header};

use super::*;
use crate::account_user_tokens::{Inventory, UserTokenMetadata};
use crate::templates::SettingsApiKeysTemplate;
use crate::view::{DashboardView, PersonalApiKeysPageView};

fn render(user_tokens: &UserTokensView) -> String {
    let page = PersonalApiKeysPageView {
        account_id: "account-1".into(),
        csrf_token: "csrf".into(),
        ..Default::default()
    };
    SettingsApiKeysTemplate {
        view: &DashboardView::default(),
        page: &page,
        user_tokens,
    }
    .render()
    .expect("render API keys")
}

fn metadata(id: &str, expires_at: Option<&str>, last_used_at: Option<&str>) -> UserTokenMetadata {
    UserTokenMetadata {
        id: id.into(),
        created_at: "2026-11-20T09:00:00Z".into(),
        expires_at: expires_at.map(Into::into),
        last_used_at: last_used_at.map(Into::into),
    }
}

fn time(value: &str) -> String {
    super::super::settings::display_time(Some(value))
}

#[test]
fn each_token_shows_its_dates_and_one_that_never_expires_is_marked() {
    let view = view(
        Inventory {
            account_id: "account-1".into(),
            tokens: vec![
                metadata(
                    "token-a",
                    Some("2026-12-20T09:00:00Z"),
                    Some("2026-11-25T08:00:00Z"),
                ),
                metadata("token-b", None, None),
            ],
            next_cursor: None,
        },
        None,
    );
    assert_eq!(view.tokens[0].expires, time("2026-12-20T09:00:00Z"));
    assert_eq!(view.tokens[0].last_used, time("2026-11-25T08:00:00Z"));
    assert_eq!(view.tokens[1].expires, "");
    assert_eq!(view.tokens[1].last_used, "");

    let body = render(&view);
    let created = time("2026-11-20T09:00:00Z");
    assert!(body.contains(&format!(
        "<code>token-a</code><p>Created {created} · Expires {} · Last used {}</p>",
        view.tokens[0].expires, view.tokens[0].last_used
    )));
    assert!(body.contains(&format!(
        r#"User token <span class="cw-status cw-status--quiet cw-status--sentence" data-tone="warning">Never expires</span></h3><code>token-b</code><p>Created {created} · Never used</p>"#
    )));
    assert_eq!(body.matches("Never expires").count(), 1);
    assert!(body.contains(r#"action="/settings/api-keys/_actions/user-tokens/revoke""#));
    assert!(body.contains(r#"<input type="hidden" name="_csrf" value="csrf"><input type="hidden" name="account_id" value="account-1"><input type="hidden" name="token_id" value="token-b">"#));
    assert!(body.contains("Anything using <code>token-a</code> stops working at once."));
    assert!(!body.contains(r#"aria-label="User token pages""#));
}

#[test]
fn an_empty_list_says_so_and_an_outage_offers_no_revoke() {
    let body = render(&UserTokensView {
        available: true,
        ..Default::default()
    });
    assert!(body.contains("You have no user tokens."));

    let body = render(&UserTokensView::default());
    assert!(body.contains("User tokens are unavailable. Reload to try again."));
    assert!(!body.contains("/_actions/user-tokens/revoke"));
    assert!(!body.contains("You have no user tokens."));
}

#[test]
fn the_group_is_withheld_while_a_new_key_is_shown_once() {
    let page = PersonalApiKeysPageView {
        one_time_key: "cw_once".into(),
        ..Default::default()
    };
    let body = SettingsApiKeysTemplate {
        view: &DashboardView::default(),
        page: &page,
        user_tokens: &UserTokensView {
            available: true,
            ..Default::default()
        },
    }
    .render()
    .expect("render API keys");
    assert!(!body.contains(r#"id="user-tokens""#));
}

#[test]
fn a_full_page_links_to_the_next_and_a_later_page_back_to_the_first() {
    let view = view(
        Inventory {
            account_id: "account-1".into(),
            tokens: vec![metadata("token-a", None, None)],
            next_cursor: Some("token-a".into()),
        },
        Some("token-0"),
    );
    assert_eq!(
        view.next_url,
        "/settings/api-keys/?token_cursor=token-a#user-tokens"
    );
    let body = render(&view);
    assert!(body.contains(r#"<a href="/settings/api-keys/#user-tokens">First page</a>"#));
    assert!(body.contains(
        r#"<a href="/settings/api-keys/?token_cursor=token-a#user-tokens">Next page</a>"#
    ));
}

#[test]
fn a_revoke_returns_to_the_group_with_its_outcome() {
    let headers = HeaderMap::new();
    let location = |revoked| {
        let response = private(revocation_response(&headers, revoked));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        location(Ok(())),
        "/settings/api-keys/?message=user-token-revoked#user-tokens"
    );
    assert_eq!(
        location(Err(Failure::NoLongerAvailable)),
        "/settings/api-keys/?error=user-token-no-longer-available#user-tokens"
    );
    assert_eq!(
        location(Err(Failure::Forbidden)),
        "/settings/api-keys/?error=user-token-controls-unavailable#user-tokens"
    );
    assert_eq!(
        location(Err(Failure::UnknownOutcome)),
        "/settings/api-keys/?error=user-token-outcome-unknown#user-tokens"
    );
    assert!(location(Err(Failure::Unauthorized)).starts_with("/login"));
}

#[test]
fn only_the_groups_own_codes_show_in_it() {
    assert_eq!(
        approved_message("user-token-revoked"),
        "User token revoked."
    );
    assert_eq!(approved_message("key-deleted"), "");
    assert_eq!(approved_error("no-longer-available"), "");
    for code in [
        "invalid-user-token-page",
        "user-token-account-changed",
        "user-token-controls-unavailable",
        "user-token-no-longer-available",
        "user-token-outcome-unknown",
    ] {
        assert!(!approved_error(code).is_empty(), "{code}");
    }
    let body = render(&UserTokensView {
        available: true,
        message: approved_message("user-token-revoked").into(),
        ..Default::default()
    });
    assert!(body.contains(
        r#"<p class="cw-alert cw-alert--success" role="status">User token revoked.</p>"#
    ));
}
