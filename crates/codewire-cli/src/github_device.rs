use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Third-party GitHub device-flow response. GitHub OAuth remains a permanent
/// raw-HTTP redirect/device-flow integration, outside Codewire's RPC surface.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct GitHubDeviceCodeResponse {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) expires_in: i32,
    pub(crate) interval: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct GitHubTokenResponse {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) refresh_token: String,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) expires_in: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) refresh_token_expires_in: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) error_description: String,
}

pub(crate) async fn request_github_device_code(
    client_id: &str,
) -> anyhow::Result<GitHubDeviceCodeResponse> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?
        .post("https://github.com/login/device/code")
        .header("Accept", "application/json")
        .form(&[("client_id", client_id), ("scope", "")])
        .send()
        .await?;
    let body = response.text().await?;
    let device_code: GitHubDeviceCodeResponse =
        serde_json::from_str(&body).context("parse device code response")?;
    if device_code.device_code.trim().is_empty() {
        anyhow::bail!("no device_code in response: {body}");
    }
    Ok(device_code)
}

pub(crate) async fn poll_github_token(
    client_id: &str,
    device_code: &str,
    interval_seconds: i32,
) -> anyhow::Result<GitHubTokenResponse> {
    let mut interval = interval_seconds.max(5);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    loop {
        tokio::time::sleep(Duration::from_secs(interval as u64)).await;
        let response = client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await?;
        let body = response.text().await?;
        let token: GitHubTokenResponse =
            serde_json::from_str(&body).context("parse token response")?;

        match token.error.as_str() {
            "" if !token.access_token.trim().is_empty() => return Ok(token),
            "" => anyhow::bail!("unexpected empty response: {body}"),
            "authorization_pending" => {}
            "slow_down" => interval += 5,
            "expired_token" => anyhow::bail!("device code expired - please try again"),
            "access_denied" => anyhow::bail!("authorization denied by user"),
            other => anyhow::bail!("github error: {} - {}", other, token.error_description),
        }
    }
}

pub(crate) async fn fetch_github_username(access_token: &str) -> anyhow::Result<String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "codewire-cli")
        .send()
        .await?;
    let user = response.json::<GitHubUserResponse>().await?;
    Ok(user.login)
}

pub(crate) async fn fetch_github_installation_id(
    access_token: &str,
    app_slug: &str,
) -> anyhow::Result<Option<i64>> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get("https://api.github.com/user/installations")
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "codewire-cli")
        .send()
        .await?;
    let installations = response.json::<GitHubInstallationsResponse>().await?;
    Ok(installations
        .installations
        .into_iter()
        .find(|installation| installation.app_slug == app_slug)
        .map(|installation| installation.id))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GitHubUserResponse {
    login: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GitHubInstallationsResponse {
    installations: Vec<GitHubInstallationResponse>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GitHubInstallationResponse {
    id: i64,
    app_slug: String,
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_device_code_json_matches_github_field_shape() {
        let response: GitHubDeviceCodeResponse = serde_json::from_value(serde_json::json!({
            "device_code": "device",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5
        }))
        .unwrap();

        assert_eq!(response.device_code, "device");
        assert_eq!(response.user_code, "ABCD-EFGH");
        assert_eq!(response.interval, 5);
    }
}
