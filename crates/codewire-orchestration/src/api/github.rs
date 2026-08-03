//! Shared GitHub account state for GitHubService and the permanent browser
//! OAuth redirect/callback routes.

use std::borrow::Cow;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use serde::Deserialize;
use sqlx::Row;
use url::Url;

use super::ApiState;
use crate::worker::github::{GitHubAppConfig, get_github_token_for_user};

const GITHUB_USER_AGENT: &str = concat!("codewire-orchestration/", env!("CARGO_PKG_VERSION"));

fn github_client(timeout: std::time::Duration) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().timeout(timeout).build()
}

fn github_get(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client
        .get(url)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
}

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct GitHubConfig {
    pub client_id: String,
    pub app_slug: String,
}

#[derive(Debug)]
pub struct GitHubStatus {
    pub connected: bool,
    pub username: String,
    pub installation_id: Option<i64>,
    pub connected_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepo {
    pub full_name: String,
    pub html_url: String,
    pub clone_url: String,
    pub description: String,
    pub language: String,
    pub private: bool,
    pub default_branch: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRepoApi {
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    clone_url: String,
    description: Option<String>,
    language: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    default_branch: String,
    #[serde(default)]
    updated_at: String,
}

#[derive(Debug, Default)]
pub struct ListGitHubReposQuery {
    pub page: i32,
    pub per_page: i32,
    pub search: String,
}

/// Status record shared by browser OAuth and Connect operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitHubStatusRecord {
    pub connected: bool,
    pub username: String,
    pub installation_id: Option<i64>,
    pub connected_at: Option<DateTime<Utc>>,
}

/// Token write parameters shared by browser OAuth and Connect operations.
#[derive(Debug, Clone)]
pub(crate) struct SaveGitHubTokenParams {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub installation_id: Option<i64>,
    pub github_username: String,
}

/// Query string for `GET /api/v1/github/oauth/authorize`.
#[derive(Debug, Default, Deserialize)]
pub struct GitHubOAuthAuthorizeQuery {
    #[serde(default)]
    pub return_url: String,
}

/// Query string for `GET /api/v1/github/oauth/callback`.
#[derive(Debug, Default, Deserialize)]
pub struct GitHubOAuthCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct GitHubOAuthTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    refresh_token_expires_in: i64,
}

#[derive(Debug, Deserialize, Default)]
struct GitHubUserResponse {
    #[serde(default)]
    login: String,
}

/// Mirrors Go's `nilIfEmpty`: empty string → SQL NULL.
fn nil_if_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

fn normalized_repo_pagination(query: &ListGitHubReposQuery) -> (i32, i32) {
    let page = if query.page < 1 { 1 } else { query.page };
    let mut per_page = if query.per_page < 1 {
        30
    } else {
        query.per_page
    };
    if per_page > 100 {
        per_page = 100;
    }
    (page, per_page)
}

fn account_user_id(user: &AuthUser) -> AppResult<&str> {
    user.require_account_credential()?;
    Ok(&user.user_id)
}

fn github_repos_url(page: i32, per_page: i32) -> String {
    format!(
        "https://api.github.com/user/repos?sort=pushed&per_page={per_page}&page={page}&affiliation=owner,collaborator,organization_member"
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn generate_oauth_state() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generate oauth state: {e}"))?;
    Ok(hex_lower(&bytes))
}

fn github_callback_url(frontend_url: &str) -> String {
    format!(
        "{}/api/v1/github/oauth/callback",
        frontend_url.trim_end_matches('/')
    )
}

fn github_authorize_url(client_id: &str, callback_url: &str, state: &str) -> String {
    let mut url = Url::parse("https://github.com/login/oauth/authorize")
        .expect("static GitHub authorize URL parses");
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", callback_url)
        .append_pair("state", state);
    url.to_string()
}

fn default_return_url(frontend_url: &str) -> String {
    // Match Go exactly: cfg.FrontendURL + "/dashboard".
    format!("{frontend_url}/dashboard")
}

fn return_url_or_default(return_url: &str, frontend_url: &str) -> String {
    if return_url.is_empty() {
        default_return_url(frontend_url)
    } else {
        return_url.to_string()
    }
}

fn append_github_connected(return_url: &str) -> String {
    let sep = if return_url.contains('?') { '&' } else { '?' };
    format!("{return_url}{sep}github=connected")
}

fn redirect(status: StatusCode, location: String) -> Response {
    (status, [(LOCATION, location)]).into_response()
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{message}\n"),
    )
        .into_response()
}

fn parse_github_repos(data: &[u8], search: &str) -> Result<Vec<GitHubRepo>, serde_json::Error> {
    let search = search.to_lowercase();
    let gh_repos: Vec<GitHubRepoApi> = serde_json::from_slice(data)?;
    Ok(gh_repos
        .into_iter()
        .filter(|r| search.is_empty() || r.full_name.to_lowercase().contains(&search))
        .map(|r| GitHubRepo {
            full_name: r.full_name,
            html_url: r.html_url,
            clone_url: r.clone_url,
            description: r.description.unwrap_or_default(),
            language: r.language.unwrap_or_default(),
            private: r.private,
            default_branch: r.default_branch,
            updated_at: r.updated_at,
        })
        .collect())
}

fn truncate_str(s: &str, max_len: usize) -> Cow<'_, str> {
    if s.len() <= max_len {
        return Cow::Borrowed(s);
    }
    let mut cut = max_len;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    Cow::Owned(s[..cut].to_string())
}

async fn forge_get(client: &reqwest::Client, url: &str, token: &str) -> anyhow::Result<Vec<u8>> {
    let resp = github_get(client, url)
        .header("Accept", "application/json")
        .bearer_auth(token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if status.as_u16() >= 400 {
        anyhow::bail!(
            "forge API returned {}: {}",
            status.as_u16(),
            truncate_str(&String::from_utf8_lossy(&body), 200)
        );
    }
    Ok(body.to_vec())
}

async fn exchange_github_code(
    cfg: &GitHubAppConfig,
    code: &str,
) -> anyhow::Result<GitHubOAuthTokenResponse> {
    let client = github_client(std::time::Duration::from_secs(15))?;
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code", code),
        ])
        .send()
        .await?;
    let body = resp.bytes().await?;
    let token: GitHubOAuthTokenResponse =
        serde_json::from_slice(&body).map_err(|e| anyhow::anyhow!("parse token response: {e}"))?;
    if token.access_token.is_empty() {
        anyhow::bail!(
            "no access_token in response: {}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(token)
}

async fn fetch_github_username(token: &str) -> anyhow::Result<String> {
    let client = github_client(std::time::Duration::from_secs(10))?;
    let user = github_get(&client, "https://api.github.com/user")
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .json::<GitHubUserResponse>()
        .await?;
    Ok(user.login)
}

// ── Shared service layer ─────────────────────────────────────────────────

pub(crate) fn get_github_config_core(state: &ApiState, user: &AuthUser) -> AppResult<GitHubConfig> {
    account_user_id(user)?;
    Ok(GitHubConfig {
        client_id: state.github_cfg.client_id.clone(),
        app_slug: state.github_cfg.app_slug.clone(),
    })
}

pub(crate) async fn get_github_status_core(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<GitHubStatusRecord> {
    let user_id = account_user_id(user)?;
    let row = sqlx::query(
        "SELECT github_username, installation_id, created_at \
         FROM user_github_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query GitHub status");
        AppError::InternalMsg("failed to query GitHub status".into())
    })?;

    let Some(row) = row else {
        return Ok(GitHubStatusRecord {
            connected: false,
            username: String::new(),
            installation_id: None,
            connected_at: None,
        });
    };

    Ok(GitHubStatusRecord {
        connected: true,
        username: row
            .try_get::<Option<String>, _>("github_username")
            .map_err(AppError::from)?
            .unwrap_or_default(),
        installation_id: row.try_get("installation_id").map_err(AppError::from)?,
        connected_at: row.try_get("created_at").map_err(AppError::from)?,
    })
}

pub(crate) async fn list_github_repos_core(
    state: &ApiState,
    user: &AuthUser,
    query: ListGitHubReposQuery,
) -> AppResult<Vec<GitHubRepo>> {
    let user_id = account_user_id(user)?;
    let token = get_github_token_for_user(&state.pool, &state.github_cfg, user_id).await;
    if token.is_empty() {
        return Err(AppError::Precondition(Cow::Borrowed(
            "GitHub not connected",
        )));
    }

    let (page, per_page) = normalized_repo_pagination(&query);
    let url = github_repos_url(page, per_page);
    let client = github_client(std::time::Duration::from_secs(15))
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;
    let data = forge_get(&client, &url, &token).await.map_err(|e| {
        tracing::error!(error = %e, "github repos: fetch failed");
        AppError::Upstream(Cow::Borrowed("failed to fetch repos from GitHub"))
    })?;
    parse_github_repos(&data, &query.search).map_err(|e| {
        tracing::error!(error = %e, "github repos: parse failed");
        AppError::InternalMsg(Cow::Borrowed("failed to parse GitHub response"))
    })
}

pub(crate) async fn save_github_token_core(
    state: &ApiState,
    user: &AuthUser,
    params: SaveGitHubTokenParams,
) -> AppResult<()> {
    let user_id = account_user_id(user)?;
    let token_type = if params.token_type.is_empty() {
        "bearer"
    } else {
        params.token_type.as_str()
    };

    sqlx::query(
        r#"INSERT INTO user_github_tokens
            (user_id, access_token, refresh_token, token_type, expires_at,
             refresh_token_expires_at, installation_id, github_username, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
           ON CONFLICT (user_id) DO UPDATE SET
             access_token = EXCLUDED.access_token,
             refresh_token = EXCLUDED.refresh_token,
             token_type = EXCLUDED.token_type,
             expires_at = EXCLUDED.expires_at,
             refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
             installation_id = EXCLUDED.installation_id,
             github_username = EXCLUDED.github_username,
             updated_at = NOW()"#,
    )
    .bind(user_id)
    .bind(&params.access_token)
    .bind(nil_if_empty(&params.refresh_token))
    .bind(token_type)
    .bind(params.expires_at)
    .bind(params.refresh_token_expires_at)
    .bind(params.installation_id)
    .bind(nil_if_empty(&params.github_username))
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, user = %user_id, "save github token");
        AppError::InternalMsg("failed to save token".into())
    })?;
    Ok(())
}

pub(crate) async fn delete_github_token_core(state: &ApiState, user: &AuthUser) -> AppResult<()> {
    let user_id = account_user_id(user)?;
    sqlx::query("DELETE FROM user_github_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to delete token");
            AppError::InternalMsg("failed to delete token".into())
        })?;
    Ok(())
}

/// `GET /github/oauth/authorize` — starts the browser OAuth flow. Mirrors the
/// Go raw handler: generate a one-time state row, then 307 to GitHub.
pub async fn github_oauth_authorize(
    State(state): State<ApiState>,
    user: AuthUser,
    Query(query): Query<GitHubOAuthAuthorizeQuery>,
) -> AppResult<Response> {
    if state.github_cfg.client_id.is_empty() {
        return Ok(plain_error(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"GitHub App not configured"}"#,
        ));
    }

    let oauth_state = match generate_oauth_state() {
        Ok(state) => state,
        Err(e) => {
            tracing::error!(error = %e, "github oauth: generate state");
            return Ok(plain_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to generate state"}"#,
            ));
        }
    };
    let return_url = return_url_or_default(&query.return_url, &state.frontend_url);
    let expires_at = Utc::now() + chrono::Duration::minutes(10);

    if let Err(e) = sqlx::query(
        "INSERT INTO github_oauth_states (state, user_id, return_url, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&oauth_state)
    .bind(&user.user_id)
    .bind(&return_url)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "github oauth: store state");
        return Ok(plain_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"failed to store state"}"#,
        ));
    }

    let callback_url = github_callback_url(&state.frontend_url);
    let location = github_authorize_url(&state.github_cfg.client_id, &callback_url, &oauth_state);
    Ok(redirect(StatusCode::TEMPORARY_REDIRECT, location))
}

/// `GET /github/oauth/callback` — consumes the one-time state, exchanges the
/// GitHub code, stores the user token, and 302s back to the original page.
pub async fn github_oauth_callback(
    State(state): State<ApiState>,
    Query(query): Query<GitHubOAuthCallbackQuery>,
) -> AppResult<Response> {
    let Some(code) = query.code.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(plain_error(
            StatusCode::BAD_REQUEST,
            "missing code or state",
        ));
    };
    let Some(oauth_state) = query.state.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(plain_error(
            StatusCode::BAD_REQUEST,
            "missing code or state",
        ));
    };

    let state_row = sqlx::query(
        "DELETE FROM github_oauth_states WHERE state = $1 \
         RETURNING user_id, return_url, expires_at",
    )
    .bind(oauth_state)
    .fetch_optional(&state.pool)
    .await;

    let Some(row) = (match state_row {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, "github oauth: consume state failed");
            None
        }
    }) else {
        return Ok(plain_error(
            StatusCode::BAD_REQUEST,
            "invalid or expired state",
        ));
    };

    let user_id: String = row.try_get("user_id").map_err(AppError::from)?;
    let return_url: String = row.try_get("return_url").map_err(AppError::from)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(AppError::from)?;
    if Utc::now() > expires_at {
        return Ok(plain_error(StatusCode::BAD_REQUEST, "state expired"));
    }

    let token = match exchange_github_code(&state.github_cfg, code).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "github oauth exchange");
            return Ok(plain_error(
                StatusCode::BAD_GATEWAY,
                "failed to exchange code",
            ));
        }
    };

    let username = match fetch_github_username(&token.access_token).await {
        Ok(username) => username,
        Err(e) => {
            tracing::warn!(error = %e, "github oauth: failed to fetch username");
            String::new()
        }
    };

    let expires_at =
        (token.expires_in > 0).then(|| Utc::now() + chrono::Duration::seconds(token.expires_in));
    let refresh_expires_at = (token.refresh_token_expires_in > 0)
        .then(|| Utc::now() + chrono::Duration::seconds(token.refresh_token_expires_in));
    if let Err(e) = sqlx::query(
        r#"INSERT INTO user_github_tokens
            (user_id, access_token, refresh_token, token_type, expires_at,
             refresh_token_expires_at, github_username, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (user_id) DO UPDATE SET
             access_token = EXCLUDED.access_token,
             refresh_token = EXCLUDED.refresh_token,
             token_type = EXCLUDED.token_type,
             expires_at = EXCLUDED.expires_at,
             refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
             github_username = EXCLUDED.github_username,
             updated_at = NOW()"#,
    )
    .bind(&user_id)
    .bind(&token.access_token)
    .bind(nil_if_empty(&token.refresh_token))
    .bind("bearer")
    .bind(expires_at)
    .bind(refresh_expires_at)
    .bind(username)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "github oauth: save token");
        return Ok(plain_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to save token",
        ));
    }

    Ok(redirect(
        StatusCode::FOUND,
        append_github_connected(&return_url),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_client_identifies_codewire_to_github() {
        let client = github_client(std::time::Duration::from_secs(1)).unwrap();
        let request = github_get(&client, "https://api.github.com/user/repos")
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(GITHUB_USER_AGENT)
        );
    }

    #[test]
    fn nil_if_empty_maps_blank_to_none() {
        assert_eq!(nil_if_empty(""), None);
        assert_eq!(nil_if_empty("x"), Some("x"));
    }

    #[test]
    fn repo_query_defaults_and_clamps_like_go() {
        assert_eq!(
            normalized_repo_pagination(&ListGitHubReposQuery::default()),
            (1, 30)
        );
        assert_eq!(
            normalized_repo_pagination(&ListGitHubReposQuery {
                page: -5,
                per_page: -1,
                search: String::new(),
            }),
            (1, 30)
        );
        assert_eq!(
            normalized_repo_pagination(&ListGitHubReposQuery {
                page: 4,
                per_page: 500,
                search: String::new(),
            }),
            (4, 100)
        );
        assert_eq!(
            github_repos_url(2, 50),
            "https://api.github.com/user/repos?sort=pushed&per_page=50&page=2&affiliation=owner,collaborator,organization_member"
        );
    }

    #[test]
    fn oauth_state_is_go_compatible_hex() {
        let state = generate_oauth_state().unwrap();

        assert_eq!(state.len(), 64);
        assert!(state.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(state, state.to_ascii_lowercase());
    }

    #[test]
    fn oauth_callback_and_authorize_urls_match_go_shape() {
        let callback = github_callback_url("https://codewire.sh/");
        assert_eq!(callback, "https://codewire.sh/api/v1/github/oauth/callback");

        let auth_url = github_authorize_url("Iv1.client", &callback, "state 1");
        assert_eq!(
            auth_url,
            "https://github.com/login/oauth/authorize?client_id=Iv1.client&redirect_uri=https%3A%2F%2Fcodewire.sh%2Fapi%2Fv1%2Fgithub%2Foauth%2Fcallback&state=state+1"
        );
    }

    #[test]
    fn oauth_return_url_defaults_and_connected_redirect_match_go() {
        assert_eq!(
            return_url_or_default("", "https://codewire.sh"),
            "https://codewire.sh/dashboard"
        );
        assert_eq!(
            return_url_or_default("https://codewire.sh/settings", "https://ignored"),
            "https://codewire.sh/settings"
        );
        assert_eq!(
            append_github_connected("https://codewire.sh/settings"),
            "https://codewire.sh/settings?github=connected"
        );
        assert_eq!(
            append_github_connected("https://codewire.sh/settings?tab=github"),
            "https://codewire.sh/settings?tab=github&github=connected"
        );
    }

    #[test]
    fn oauth_token_response_defaults_like_go_json_decode() {
        let token: GitHubOAuthTokenResponse =
            serde_json::from_str(r#"{"access_token":"gho_token"}"#).unwrap();

        assert_eq!(token.access_token, "gho_token");
        assert_eq!(token.refresh_token, "");
        assert_eq!(token.expires_in, 0);
        assert_eq!(token.refresh_token_expires_in, 0);
    }

    #[test]
    fn github_repos_parse_filters_and_omits_null_optionals() {
        let data = br#"[
          {
            "full_name": "codewiresh/codewire",
            "html_url": "https://github.com/codewiresh/codewire",
            "clone_url": "https://github.com/codewiresh/codewire.git",
            "description": null,
            "language": "Rust",
            "private": true,
            "default_branch": "main",
            "updated_at": "2026-06-26T10:00:00Z"
          },
          {
            "full_name": "other/repo",
            "html_url": "https://github.com/other/repo",
            "clone_url": "https://github.com/other/repo.git",
            "description": "old",
            "language": null,
            "private": false,
            "default_branch": "main",
            "updated_at": "2026-06-25T10:00:00Z"
          }
        ]"#;

        let repos = parse_github_repos(data, "CODEWIRE").unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].full_name, "codewiresh/codewire");
        assert_eq!(repos[0].description, "");
        assert_eq!(repos[0].language, "Rust");
    }
}
