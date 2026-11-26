//! Metadata-only adapter for Settings' list and revoke of the account's user
//! tokens (#5688; docs/dev/AUTH-POLICY.md, "User tokens and the CLI"). The
//! same boundary as the session controls: the browser-session cookie only,
//! never a token value, and never an upstream diagnostic.
use std::collections::BTreeSet;

use axum::http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::account_sessions::{Failure, bounded_json, valid_id, valid_time};
use crate::state::AppState;

const PAGE_LIMIT: usize = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserTokenMetadata {
    pub(crate) id: String,
    pub(crate) created_at: String,
    /// Absent for a token that never expires.
    pub(crate) expires_at: Option<String>,
    pub(crate) last_used_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inventory {
    pub(crate) account_id: String,
    pub(crate) tokens: Vec<UserTokenMetadata>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoked {
    revoked: bool,
}

/// Settings' User tokens section.
#[derive(Default)]
pub(crate) struct UserTokensView {
    pub(crate) available: bool,
    pub(crate) tokens: Vec<UserTokenRowView>,
    pub(crate) later_page: bool,
    pub(crate) next_url: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

pub(crate) struct UserTokenRowView {
    pub(crate) id: String,
    pub(crate) created: String,
    /// Empty for a token that never expires.
    pub(crate) expires: String,
    /// Empty for a token never used.
    pub(crate) last_used: String,
}

impl Inventory {
    fn validate(&self, account_id: &str, cursor: Option<&str>) -> bool {
        if self.account_id != account_id || !valid_id(account_id) || self.tokens.len() > PAGE_LIMIT
        {
            return false;
        }
        let mut ids = BTreeSet::new();
        let mut previous = cursor.unwrap_or("");
        for token in &self.tokens {
            if !valid_id(&token.id)
                || token.id.as_str() <= previous
                || !ids.insert(token.id.as_str())
                || !valid_time(&token.created_at)
                || token
                    .expires_at
                    .as_deref()
                    .is_some_and(|time| !valid_time(time))
                || token
                    .last_used_at
                    .as_deref()
                    .is_some_and(|time| !valid_time(time))
            {
                return false;
            }
            previous = &token.id;
        }
        match &self.next_cursor {
            None => true,
            Some(next) => self.tokens.len() == PAGE_LIMIT && valid_id(next) && next == previous,
        }
    }
}

pub(crate) async fn inventory(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    cursor: Option<&str>,
) -> Result<Inventory, Failure> {
    if !valid_id(account_id) || cursor.is_some_and(|id| !valid_id(id)) {
        return Err(Failure::Unavailable);
    }
    let mut url = reqwest::Url::parse(&format!(
        "{}/api/auth/user-tokens",
        state.identity_origin_string
    ))
    .map_err(|_| Failure::Unavailable)?;
    url.query_pairs_mut().append_pair("account_id", account_id);
    if let Some(cursor) = cursor {
        url.query_pairs_mut().append_pair("cursor", cursor);
    }
    let response = state
        .account_http
        .get(url)
        .headers(crate::transport::trace_context())
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(Failure::Unauthorized),
        StatusCode::FORBIDDEN => return Err(Failure::Forbidden),
        _ => return Err(Failure::Unavailable),
    }
    let inventory: Inventory = bounded_json(response)
        .await
        .map_err(|_| Failure::Unavailable)?;
    if !inventory.validate(account_id, cursor) {
        return Err(Failure::Unavailable);
    }
    Ok(inventory)
}

pub(crate) async fn revoke(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    token_id: &str,
) -> Result<(), Failure> {
    if !valid_id(account_id) || !valid_id(token_id) {
        return Err(Failure::NoLongerAvailable);
    }
    #[derive(Serialize)]
    struct Request<'a> {
        account_id: &'a str,
        token_id: &'a str,
    }
    let origin = reqwest::Url::parse(&state.public_origin)
        .map_err(|_| Failure::UnknownOutcome)?
        .origin()
        .ascii_serialization();
    let response = state
        .account_http
        .post(format!(
            "{}/api/auth/user-tokens/revoke",
            state.identity_origin_string
        ))
        .headers(crate::transport::trace_context())
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, origin)
        .json(&Request {
            account_id,
            token_id,
        })
        .send()
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(Failure::Unauthorized),
        StatusCode::FORBIDDEN => return Err(Failure::Forbidden),
        StatusCode::NOT_FOUND => return Err(Failure::NoLongerAvailable),
        _ => return Err(Failure::UnknownOutcome),
    }
    let acknowledgement: Revoked = bounded_json(response)
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    if !acknowledgement.revoked {
        return Err(Failure::UnknownOutcome);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(id: &str) -> UserTokenMetadata {
        UserTokenMetadata {
            id: id.into(),
            created_at: "2026-11-25T10:00:00Z".into(),
            expires_at: None,
            last_used_at: None,
        }
    }

    fn inventory(tokens: Vec<UserTokenMetadata>, next_cursor: Option<&str>) -> Inventory {
        Inventory {
            account_id: "account-1".into(),
            tokens,
            next_cursor: next_cursor.map(Into::into),
        }
    }

    #[test]
    fn an_inventory_is_accepted_only_for_its_account_in_order() {
        assert!(inventory(vec![token("a"), token("b")], None).validate("account-1", None));
        assert!(!inventory(vec![token("a")], None).validate("account-2", None));
        assert!(!inventory(vec![token("b"), token("a")], None).validate("account-1", None));
        assert!(!inventory(vec![token("a"), token("a")], None).validate("account-1", None));
        assert!(!inventory(vec![token("a")], None).validate("account-1", Some("a")));
    }

    #[test]
    fn an_inventory_with_a_bad_time_or_id_is_refused() {
        let mut bad_expiry = token("a");
        bad_expiry.expires_at = Some("tomorrow".into());
        assert!(!inventory(vec![bad_expiry], None).validate("account-1", None));
        let mut bad_use = token("a");
        bad_use.last_used_at = Some("2026-11-25T10:00:00+01:00".into());
        assert!(!inventory(vec![bad_use], None).validate("account-1", None));
        assert!(!inventory(vec![token("a b")], None).validate("account-1", None));
    }

    #[test]
    fn a_next_cursor_needs_a_full_page_ending_at_it() {
        let page: Vec<_> = (0..PAGE_LIMIT)
            .map(|n| token(&format!("t{n:03}")))
            .collect();
        let last = page.last().unwrap().id.clone();
        assert!(inventory(page, Some(&last)).validate("account-1", None));
        assert!(!inventory(vec![token("a")], Some("a")).validate("account-1", None));
        let page: Vec<_> = (0..PAGE_LIMIT)
            .map(|n| token(&format!("t{n:03}")))
            .collect();
        assert!(!inventory(page, Some("t000")).validate("account-1", None));
    }
}
