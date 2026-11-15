//! `/admin/feedback/`: what people sent with `cw feedback`, newest first, for
//! platform admins only (#4061).

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use super::{admin_connect_error, admin_context};
use crate::{
    admin_connect::{self, FeedbackFilter},
    response::render_page,
    state::AppState,
    templates::AdminFeedbackTemplate,
};

const FEEDBACK_PATH: &str = "/admin/feedback/";

#[derive(Debug, Default, Deserialize)]
pub(in crate::routes) struct FeedbackQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    sender: String,
    /// A `next_page_token` from an earlier page with the same sender filter.
    #[serde(default)]
    page: String,
}

pub(in crate::routes) async fn list(
    State(state): State<AppState>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = FEEDBACK_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let filter = sender_filter(&query.sender);
    let page_token = if valid_page_token(&query.page) {
        query.page
    } else {
        String::new()
    };
    let page = match admin_connect::feedback(&state, cookie, page_token.clone(), filter).await {
        Ok(page) => page,
        Err(error) => return admin_connect_error(error, &continuation, &headers),
    };
    let first_page_url = if page_token.is_empty() {
        String::new()
    } else {
        feedback_url(filter, "")
    };
    let next_page_url = if page.next_page_token.is_empty() {
        String::new()
    } else {
        feedback_url(filter, &page.next_page_token)
    };
    render_page(AdminFeedbackTemplate {
        view: &dashboard,
        rows: &page.rows,
        filter,
        later_page: !page_token.is_empty(),
        first_page_url: &first_page_url,
        next_page_url: &next_page_url,
    })
}

fn sender_filter(value: &str) -> FeedbackFilter {
    match value {
        "signed-in" => FeedbackFilter::SignedIn,
        "anonymous" => FeedbackFilter::Anonymous,
        _ => FeedbackFilter::All,
    }
}

/// The list's tokens are `<microseconds>.<feedback id>`; anything else is
/// dropped here and the list starts at the newest.
fn valid_page_token(value: &str) -> bool {
    value.split_once('.').is_some_and(|(micros, id)| {
        (1..=20).contains(&micros.len())
            && micros.bytes().all(|byte| byte.is_ascii_digit())
            && (1..=64).contains(&id.len())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn feedback_url(filter: FeedbackFilter, page_token: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    match filter {
        FeedbackFilter::All => {}
        FeedbackFilter::SignedIn => {
            query.append_pair("sender", "signed-in");
        }
        FeedbackFilter::Anonymous => {
            query.append_pair("sender", "anonymous");
        }
    }
    if !page_token.is_empty() {
        query.append_pair("page", page_token);
    }
    let query = query.finish();
    if query.is_empty() {
        FEEDBACK_PATH.to_owned()
    } else {
        format!("{FEEDBACK_PATH}?{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sender_filter_is_an_exact_allowlist() {
        assert_eq!(sender_filter("signed-in"), FeedbackFilter::SignedIn);
        assert_eq!(sender_filter("anonymous"), FeedbackFilter::Anonymous);
        for other in ["", "all", "Signed-in", "<script>"] {
            assert_eq!(sender_filter(other), FeedbackFilter::All, "{other}");
        }
    }

    #[test]
    fn only_tokens_shaped_like_the_lists_own_reach_the_server() {
        assert!(valid_page_token(
            "1763107200123456.0b8f6c2e-5d1a-4f7e-9a3b-2c4d6e8f0a1b"
        ));
        for garbage in [
            "",
            "123",
            ".abc",
            "123.",
            "12a.abc",
            "123.a b",
            "123.<script>",
            "1.2.3",
            &format!("1.{}", "a".repeat(65)),
        ] {
            assert!(!valid_page_token(garbage), "{garbage}");
        }
    }

    #[test]
    fn page_links_keep_the_filter_and_encode_the_token() {
        assert_eq!(feedback_url(FeedbackFilter::All, ""), "/admin/feedback/");
        assert_eq!(
            feedback_url(FeedbackFilter::Anonymous, "17.ab-cd"),
            "/admin/feedback/?sender=anonymous&page=17.ab-cd"
        );
        assert_eq!(
            feedback_url(FeedbackFilter::SignedIn, ""),
            "/admin/feedback/?sender=signed-in"
        );
    }
}
