//! Owner-scoped, metadata-only GitHub picker. The browser calls this BFF, never
//! the provider or credential service directly. The authenticated owner selects
//! their current GitHub singleton implicitly.

use std::{collections::BTreeSet, time::Duration};

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use codewire_proto::codewire::v1::{
    GithubRepository, GithubRepositoryServiceClient, ListGithubRepositoriesRequest,
    ListGithubRepositoriesResponse,
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};
use serde::Deserialize;

use crate::{response::render_template, state::AppState, transport::BrowserTransport};

const PAGE_SIZE: i32 = 50;
const MAX_PAGE_TOKEN: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(35);

// No Debug: form authority is not a diagnostic source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    page_token: String,
}

#[derive(Template)]
#[template(path = "github-repositories.html")]
struct RepositoriesTemplate<'a> {
    repositories: &'a [GithubRepository],
    next_page_token: &'a str,
    error: &'a str,
}

pub(super) async fn repositories(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Submission>,
) -> Response {
    let (_, _, cookie) = match super::organization_governance::action_context(
        &state,
        &headers,
        &slug,
        &form.csrf,
        format!("/{slug}/new/"),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request = match request(&form) {
        Ok(request) => request,
        Err(()) => {
            return error_fragment(
                StatusCode::UNPROCESSABLE_ENTITY,
                "The repository list is out of date. Reload repositories.",
            );
        }
    };
    let client = GithubRepositoryServiceClient::new(
        BrowserTransport {
            http: state.credential_http.clone(),
            cookie: Some(cookie),
            origin: Some(
                HeaderValue::from_str(&state.public_origin)
                    .expect("validated dashboard public origin"),
            ),
        },
        ClientConfig::new(state.credential_origin.clone())
            .with_default_timeout(TIMEOUT)
            .with_default_max_message_size(256 * 1024),
    );
    let result = client.list_github_repositories(request).await;
    match result {
        Ok(response) => {
            let response = response.into_owned();
            if !valid_response(&response, &form.page_token) {
                return error_fragment(
                    StatusCode::BAD_GATEWAY,
                    "The repository service returned an invalid response. Try again later.",
                );
            }
            render_template(
                StatusCode::OK,
                RepositoriesTemplate {
                    repositories: &response.repositories,
                    next_page_token: &response.next_page_token,
                    error: "",
                },
            )
        }
        Err(error) => {
            let (status, message) = error_message(&error);
            error_fragment(status, message)
        }
    }
}

fn request(form: &Submission) -> Result<ListGithubRepositoriesRequest, ()> {
    if !valid_page_token(&form.page_token) {
        return Err(());
    }
    Ok(ListGithubRepositoriesRequest {
        page_size: PAGE_SIZE,
        page_token: form.page_token.clone(),
        ..Default::default()
    })
}

/// Mirror the service's opaque continuation shape so a malformed browser value
/// never reaches it: `v2.<page>.<size>.<64 lowercase hex>`. The service still
/// recomputes the owner/connection binding on every request.
fn valid_page_token(token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    let fields: Vec<_> = token.split('.').collect();
    token.len() <= MAX_PAGE_TOKEN
        && fields.len() == 4
        && fields[0] == "v2"
        && [fields[1], fields[2]].iter().all(|field| {
            !field.is_empty() && field.len() <= 10 && field.bytes().all(|b| b.is_ascii_digit())
        })
        && fields[3].len() == 64
        && fields[3]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_response(response: &ListGithubRepositoriesResponse, previous: &str) -> bool {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    response.repositories.len() <= PAGE_SIZE as usize
        && valid_page_token(&response.next_page_token)
        && (response.next_page_token.is_empty() || response.next_page_token != previous)
        && response.repositories.iter().all(|repository| {
            valid_repository(repository)
                && ids.insert(&repository.repository_id)
                && names.insert(repository.full_name.to_ascii_lowercase())
        })
}

fn valid_repository(repository: &GithubRepository) -> bool {
    let Some((owner, name)) = repository.full_name.split_once('/') else {
        return false;
    };
    let id = repository.repository_id.parse::<u64>().ok();
    id.is_some_and(|id| id > 0 && id.to_string() == repository.repository_id)
        && !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && !owner.contains("--")
        && !name.is_empty()
        && name.len() <= 100
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        && repository.clone_url == format!("https://github.com/{}.git", repository.full_name)
        && repository.default_branch.len() <= 512
        && !repository.default_branch.starts_with('-')
        && repository.default_branch.trim() == repository.default_branch
        && !repository.default_branch.chars().any(char::is_control)
}

fn error_message(error: &ConnectError) -> (StatusCode, &'static str) {
    match error.code {
        ErrorCode::Unauthenticated => (
            StatusCode::FORBIDDEN,
            "Your session no longer permits this request. Sign in again.",
        ),
        // GitHub still rejected the connection after one bounded refresh.
        ErrorCode::PermissionDenied | ErrorCode::FailedPrecondition => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Reconnect required. Reconnect GitHub in Settings to browse repositories.",
        ),
        ErrorCode::Aborted | ErrorCode::NotFound => (
            StatusCode::CONFLICT,
            "Your GitHub connection changed. Reload repositories.",
        ),
        ErrorCode::ResourceExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "GitHub repository requests are temporarily limited. Wait before trying again.",
        ),
        ErrorCode::InvalidArgument => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "The repository list is out of date. Reload repositories.",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Repository access unavailable. Try again later or enter a custom Git URL.",
        ),
    }
}

fn error_fragment(status: StatusCode, error: &str) -> Response {
    render_template(
        status,
        RepositoriesTemplate {
            repositories: &[],
            next_page_token: "",
            error,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> GithubRepository {
        GithubRepository {
            repository_id: "123".into(),
            full_name: "owner/repo".into(),
            default_branch: "main".into(),
            clone_url: "https://github.com/owner/repo.git".into(),
            is_private: true,
            ..Default::default()
        }
    }

    #[test]
    fn request_uses_owner_scope_and_rejects_invalid_cursors() {
        let mut form = Submission {
            csrf: "synthetic".into(),
            page_token: String::new(),
        };
        let request = request(&form).unwrap();
        assert_eq!(request.page_size, PAGE_SIZE);
        assert!(request.page_token.is_empty());
        form.page_token = "not-a-cursor".into();
        assert!(super::request(&form).is_err());
        form.page_token = format!("v2.2.50.{}", "a".repeat(64));
        assert_eq!(super::request(&form).unwrap().page_token, form.page_token);
        for invalid in [
            format!("v1.2.50.{}", "a".repeat(64)),
            format!("v2.2.50.{}", "A".repeat(64)),
            format!("v2..50.{}", "a".repeat(64)),
            format!("v2.2.50.{}", "a".repeat(63)),
            format!("v2.2.50.{}.extra", "a".repeat(64)),
        ] {
            form.page_token = invalid;
            assert!(super::request(&form).is_err(), "{}", form.page_token);
        }
    }

    #[test]
    fn response_rejects_urls_duplicates_oversize_pages_and_repeated_cursors() {
        let mut page = ListGithubRepositoriesResponse {
            repositories: vec![repo()],
            ..Default::default()
        };
        assert!(valid_response(&page, ""));
        for url in [
            "https://example.test/owner/repo.git",
            "https://token@github.com/owner/repo.git",
            "https://github.com/owner/repo.git?token=secret",
        ] {
            page.repositories[0].clone_url = url.into();
            assert!(!valid_response(&page, ""));
        }
        page.repositories = vec![repo(), repo()];
        assert!(!valid_response(&page, ""));
        page.repositories = vec![repo(); 51];
        assert!(!valid_response(&page, ""));
        page.repositories = vec![repo()];
        page.next_page_token = "same".into();
        assert!(!valid_response(&page, "same"));
    }

    #[test]
    fn renders_selectable_metadata_and_closed_errors_only() {
        let html = RepositoriesTemplate {
            repositories: &[repo()],
            next_page_token: "next",
            error: "",
        }
        .render()
        .unwrap();
        assert!(html.contains("owner/repo"));
        assert!(html.contains("Private"));
        assert!(html.contains("data-github-next"));
        let error = ConnectError::unavailable("gho_private-provider-output");
        assert!(!error_message(&error).1.contains("gho_"));
    }

    #[test]
    fn repository_fields_are_escaped_and_invalid_metadata_fails_closed() {
        let mut repository = repo();
        repository.default_branch = "main\"><script>alert(1)</script>".into();
        let html = RepositoriesTemplate {
            repositories: &[repository.clone()],
            next_page_token: "",
            error: "",
        }
        .render()
        .unwrap();
        assert!(!html.contains("<script>"));
        assert!(!html.contains("main\"><"));
        for branch in ["-main", " main", "main\n", "main\0"] {
            repository.default_branch = branch.into();
            assert!(!valid_repository(&repository));
        }
        repository = repo();
        repository.repository_id = "0123".into();
        assert!(!valid_repository(&repository));
        repository = repo();
        repository.full_name = "owner/repo/extra".into();
        assert!(!valid_repository(&repository));
    }
}
