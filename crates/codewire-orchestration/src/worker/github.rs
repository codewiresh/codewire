//! GitHub App user-token lookup/refresh for gh CLI injection.

use serde::Deserialize;
use sqlx::PgPool;
use sqlx::Row;

#[derive(Debug, Clone, Default)]
pub struct GitHubAppConfig {
    pub client_id: String,
    pub client_secret: String,
    /// GitHub App public slug (Go: cfg.GitHubAppSlug); surfaced by the
    /// `GET /github/config` read handler, not used by token resolution.
    pub app_slug: String,
}

impl GitHubAppConfig {
    pub fn from_env() -> Self {
        Self {
            client_id: std::env::var("GITHUB_APP_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("GITHUB_APP_CLIENT_SECRET").unwrap_or_default(),
            app_slug: std::env::var("GITHUB_APP_SLUG").unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct GhTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    refresh_token_expires_in: i64,
}

/// Mirrors `getGitHubTokenForUser`: stored token if fresh (5-minute
/// buffer), refreshed otherwise; "" when nothing usable.
pub async fn get_github_token_for_user(
    pool: &PgPool,
    cfg: &GitHubAppConfig,
    user_id: &str,
) -> String {
    let row = match sqlx::query(
        "SELECT access_token, refresh_token, expires_at FROM user_github_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return String::new(),
    };

    let access_token: String = row.try_get("access_token").unwrap_or_default();
    let refresh_token: Option<String> = row.try_get("refresh_token").unwrap_or(None);
    let expires_at: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("expires_at").unwrap_or(None);

    match expires_at {
        None => return access_token,
        Some(exp) if chrono::Utc::now() < exp - chrono::Duration::minutes(5) => {
            return access_token;
        }
        Some(_) => {}
    }

    // Token expired — try refresh.
    let refresh_token = match refresh_token {
        Some(t) if !t.is_empty() && !cfg.client_secret.is_empty() => t,
        _ => return String::new(),
    };

    let new_token = match refresh_github_app_token(cfg, &refresh_token).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "github-ssh: token refresh failed");
            return String::new();
        }
    };

    let new_expires_at = (new_token.expires_in > 0)
        .then(|| chrono::Utc::now() + chrono::Duration::seconds(new_token.expires_in));
    let new_refresh_expires_at = (new_token.refresh_token_expires_in > 0).then(|| {
        chrono::Utc::now() + chrono::Duration::seconds(new_token.refresh_token_expires_in)
    });
    let new_refresh =
        (!new_token.refresh_token.is_empty()).then(|| new_token.refresh_token.clone());

    let _ = sqlx::query(
        r#"UPDATE user_github_tokens
           SET access_token = $1, refresh_token = $2, expires_at = $3, refresh_token_expires_at = $4, updated_at = NOW()
           WHERE user_id = $5"#,
    )
    .bind(&new_token.access_token)
    .bind(new_refresh)
    .bind(new_expires_at)
    .bind(new_refresh_expires_at)
    .bind(user_id)
    .execute(pool)
    .await;

    new_token.access_token
}

async fn refresh_github_app_token(
    cfg: &GitHubAppConfig,
    refresh_token: &str,
) -> anyhow::Result<GhTokenResponse> {
    let data = format!(
        "client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}",
        cfg.client_id, cfg.client_secret, refresh_token
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(data)
        .send()
        .await?;
    let token: GhTokenResponse = resp.json().await?;
    if token.access_token.is_empty() {
        anyhow::bail!("empty access token in refresh response");
    }
    Ok(token)
}

/// Mirrors `getGitHubUsernameForUser`.
pub async fn get_github_username_for_user(pool: &PgPool, user_id: &str) -> String {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT github_username FROM user_github_tokens WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    row.and_then(|(u,)| u).unwrap_or_default()
}
