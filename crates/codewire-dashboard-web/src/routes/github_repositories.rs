//! Owner-scoped, metadata-only GitHub picker. The browser calls this BFF, never
//! the provider or credential service directly. Selection stays at the exact
//! profile revision already present in the Create Sandbox form.

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

use crate::{
    environment_source_forms::{SourceSubmission, exact_reference},
    response::render_template,
    state::AppState,
    transport::BrowserTransport,
};

const PAGE_SIZE: i32 = 50;
const MAX_PAGE_TOKEN: usize = 2048;
const TIMEOUT: Duration = Duration::from_secs(35);

// No Debug: form authority is not a diagnostic source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    #[serde(rename = "_csrf")]
    csrf: String,
    credential_profile: String,
    #[serde(default)]
    page_token: String,
}

#[derive(Template)]
#[template(path = "github-repositories.html")]
struct RepositoriesTemplate<'a> {
    profile: &'a str,
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
                "",
                "Choose a current credential profile with a GitHub connection before browsing repositories.",
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
                    &form.credential_profile,
                    "The repository service returned an invalid response. Try again later.",
                );
            }
            render_template(
                StatusCode::OK,
                RepositoriesTemplate {
                    profile: &form.credential_profile,
                    repositories: &response.repositories,
                    next_page_token: &response.next_page_token,
                    error: "",
                },
            )
        }
        Err(error) => {
            let (status, message) = error_message(&error);
            error_fragment(status, &form.credential_profile, message)
        }
    }
}

fn request(form: &Submission) -> Result<ListGithubRepositoriesRequest, ()> {
    if form.credential_profile.len() > 128 || !valid_page_token(&form.page_token) {
        return Err(());
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("credential_profile", &form.credential_profile)
        .finish();
    let source = SourceSubmission::parse(encoded.as_bytes())?;
    let profile = source.selection.credentials.as_option().ok_or(())?;
    Ok(ListGithubRepositoriesRequest {
        profile_id: exact_reference(&profile.profile)?.into(),
        profile_revision: source.selection.profile_revision.ok_or(())?,
        page_size: PAGE_SIZE,
        page_token: form.page_token.clone(),
        ..Default::default()
    })
}

fn valid_page_token(token: &str) -> bool {
    token.len() <= MAX_PAGE_TOKEN && !token.chars().any(char::is_control)
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
            "Your session no longer permits this request. Sign in again and check the selected profile.",
        ),
        ErrorCode::PermissionDenied => (
            StatusCode::FORBIDDEN,
            "Repository access was denied. Check the selected GitHub connection and its repository permissions in Settings.",
        ),
        ErrorCode::Aborted | ErrorCode::NotFound => (
            StatusCode::CONFLICT,
            "The selected profile or GitHub connection changed. Reload and select its current revision.",
        ),
        ErrorCode::FailedPrecondition => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "This profile needs an active GitHub connection. Connect GitHub and add it to the profile in Settings.",
        ),
        ErrorCode::ResourceExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "GitHub repository requests are temporarily limited. Wait before trying again.",
        ),
        ErrorCode::InvalidArgument => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "The repository request is no longer valid. Close the picker and start again.",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub repositories are temporarily unavailable. Try again later or enter a custom Git URL.",
        ),
    }
}

fn error_fragment(status: StatusCode, profile: &str, error: &str) -> Response {
    render_template(
        status,
        RepositoriesTemplate {
            profile,
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
    fn request_keeps_exact_profile_revision_and_rejects_ambiguous_inputs() {
        let mut form = Submission {
            csrf: "synthetic".into(),
            credential_profile: "00000000-0000-4000-8000-000000000001@7".into(),
            page_token: String::new(),
        };
        let request = request(&form).unwrap();
        assert_eq!(request.profile_id, "00000000-0000-4000-8000-000000000001");
        assert_eq!(request.profile_revision, 7);
        for invalid in [
            "",
            "name@7",
            "00000000-0000-4000-8000-000000000001@0",
            "00000000-0000-4000-8000-000000000001@7@8",
        ] {
            form.credential_profile = invalid.into();
            assert!(super::request(&form).is_err());
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
            profile: "profile@7",
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
            profile: "profile@7",
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
