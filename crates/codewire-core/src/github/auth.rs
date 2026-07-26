//! GitHub App authentication (device flow)
//!
//! Users install the GitHub App and select repos. The app requests a
//! device code, displays it for the user to enter on github.com, then
//! polls for the token. Tokens auto-refresh when expired.

use crate::CoreError;
use crate::platform::{HttpClient, SecureStorage};

/// Keychain key for GitHub tokens
const GITHUB_TOKEN_KEY: &str = "codewire:github:token";

fn github_client_id() -> String {
    std::env::var("GITHUB_APP_CLIENT_ID").unwrap_or_else(|_| {
        option_env!("GITHUB_APP_CLIENT_ID")
            .unwrap_or_default()
            .to_string()
    })
}

fn github_app_slug() -> String {
    std::env::var("GITHUB_APP_SLUG").unwrap_or_else(|_| {
        option_env!("GITHUB_APP_SLUG")
            .unwrap_or_default()
            .to_string()
    })
}

/// Response from GitHub's device code endpoint
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(serde::Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<u64>,
}

/// Error response from GitHub token polling endpoint
#[derive(serde::Deserialize)]
struct GitHubErrorResponse {
    error: String,
}

/// GitHub App user-to-server token
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GitHubToken {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds) when access_token expires
    #[serde(default)]
    pub expires_at: u64,
    /// Unix timestamp (seconds) when refresh_token expires
    #[serde(default)]
    pub refresh_token_expires_at: Option<u64>,
    /// Installation ID for our GitHub App on the user's account
    #[serde(default)]
    pub installation_id: Option<u64>,
}

impl GitHubToken {
    /// Check if the access token is expired (5-min buffer)
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // legacy token, no expiry
        }
        let now = chrono::Utc::now().timestamp() as u64;
        self.expires_at < now + 300
    }

    /// Check if the refresh token is still valid
    pub fn can_refresh(&self) -> bool {
        match (self.refresh_token.as_ref(), self.refresh_token_expires_at) {
            (Some(_), Some(expires_at)) => {
                let now = chrono::Utc::now().timestamp() as u64;
                expires_at > now
            }
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// GitHub device flow authentication manager
pub struct GitHubAuthManager<H: HttpClient, S: SecureStorage> {
    http_client: H,
    secure_storage: S,
}

impl<H: HttpClient, S: SecureStorage> GitHubAuthManager<H, S> {
    pub fn new(http_client: H, secure_storage: S) -> Self {
        Self {
            http_client,
            secure_storage,
        }
    }

    /// Request a device code from GitHub for the user to enter on github.com
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse, CoreError> {
        let client_id = github_client_id();
        if client_id.is_empty() {
            return Err(CoreError::InvalidConfig {
                message: "GITHUB_APP_CLIENT_ID is not set".to_string(),
            });
        }

        let response = self
            .http_client
            .post_form(
                "https://github.com/login/device/code",
                &[("Accept", "application/json")],
                &[("client_id", &client_id), ("scope", "")],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!("GitHub device code request failed: {}", response.text()),
            });
        }

        response
            .json::<DeviceCodeResponse>()
            .map_err(|e| CoreError::AuthFailed {
                message: format!("Failed to parse device code response: {}", e),
            })
    }

    /// Poll GitHub for the access token after user enters the device code.
    /// Blocks until the user authorizes, the code expires, or access is denied.
    pub async fn poll_for_token(
        &self,
        device_code: &str,
        initial_interval: u64,
    ) -> Result<GitHubToken, CoreError> {
        let client_id = github_client_id();
        let grant_type = "urn:ietf:params:oauth:grant-type:device_code".to_string();
        let device_code_owned = device_code.to_string();
        let mut interval = initial_interval;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

            let response = self
                .http_client
                .post_form(
                    "https://github.com/login/oauth/access_token",
                    &[("Accept", "application/json")],
                    &[
                        ("client_id", &client_id),
                        ("device_code", &device_code_owned),
                        ("grant_type", &grant_type),
                    ],
                )
                .await?;

            let body = response.text();

            // Try parsing as a successful token response first
            if let Ok(token_resp) = serde_json::from_str::<GitHubTokenResponse>(&body) {
                let now = chrono::Utc::now().timestamp() as u64;
                return Ok(GitHubToken {
                    access_token: token_resp.access_token,
                    token_type: token_resp.token_type,
                    refresh_token: token_resp.refresh_token,
                    expires_at: now + token_resp.expires_in.unwrap_or(28800),
                    refresh_token_expires_at: token_resp.refresh_token_expires_in.map(|s| now + s),
                    installation_id: None,
                });
            }

            // Parse as error response
            if let Ok(err_resp) = serde_json::from_str::<GitHubErrorResponse>(&body) {
                match err_resp.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        interval += 5;
                        continue;
                    }
                    "expired_token" => {
                        return Err(CoreError::AuthFailed {
                            message: "Device code expired. Please try again.".to_string(),
                        });
                    }
                    "access_denied" => {
                        return Err(CoreError::AuthFailed {
                            message: "Authorization was denied by the user.".to_string(),
                        });
                    }
                    other => {
                        return Err(CoreError::AuthFailed {
                            message: format!("GitHub device flow error: {}", other),
                        });
                    }
                }
            }

            return Err(CoreError::AuthFailed {
                message: format!("Unexpected response from GitHub: {}", body),
            });
        }
    }

    /// Store GitHub token in secure storage
    pub fn store_token(&self, token: &GitHubToken) -> Result<(), CoreError> {
        let token_json = serde_json::to_string(token).map_err(|e| CoreError::Keychain {
            message: format!("Failed to serialize GitHub token: {}", e),
        })?;
        self.secure_storage.store(GITHUB_TOKEN_KEY, &token_json)
    }

    /// Retrieve GitHub token from secure storage
    pub fn get_token(&self) -> Result<Option<GitHubToken>, CoreError> {
        match self.secure_storage.retrieve(GITHUB_TOKEN_KEY)? {
            Some(json_str) => {
                let token: GitHubToken =
                    serde_json::from_str(&json_str).map_err(|e| CoreError::Keychain {
                        message: format!("Failed to parse stored GitHub token: {}", e),
                    })?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    /// Refresh an expired access token using the refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<GitHubToken, CoreError> {
        let client_id = github_client_id();
        let refresh_token_owned = refresh_token.to_string();
        let response = self
            .http_client
            .post_form(
                "https://github.com/login/oauth/access_token",
                &[("Accept", "application/json")],
                &[
                    ("client_id", &client_id),
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token_owned),
                ],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!("GitHub token refresh failed: {}", response.text()),
            });
        }

        let resp: GitHubTokenResponse = response.json().map_err(|e| CoreError::AuthFailed {
            message: format!("Failed to parse GitHub refresh response: {}", e),
        })?;

        let now = chrono::Utc::now().timestamp() as u64;
        Ok(GitHubToken {
            access_token: resp.access_token,
            token_type: resp.token_type,
            refresh_token: resp.refresh_token,
            expires_at: now + resp.expires_in.unwrap_or(28800),
            refresh_token_expires_at: resp.refresh_token_expires_in.map(|s| now + s),
            installation_id: None, // caller copies from previous token
        })
    }

    /// Get the URL for installing the GitHub App on the user's account
    pub fn installation_url() -> Result<String, CoreError> {
        let app_slug = github_app_slug();
        if app_slug.is_empty() {
            return Err(CoreError::InvalidConfig {
                message: "GITHUB_APP_SLUG is not set".to_string(),
            });
        }
        Ok(format!(
            "https://github.com/apps/{}/installations/new",
            app_slug
        ))
    }

    /// Poll until the user installs the GitHub App, then return the installation ID.
    /// Opens the installation page and retries every `interval` seconds.
    pub async fn wait_for_installation(
        &self,
        access_token: &str,
        interval: u64,
    ) -> Result<u64, CoreError> {
        loop {
            match self.fetch_installation_id(access_token).await {
                Ok(id) => return Ok(id),
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                }
            }
        }
    }

    /// Fetch the installation ID for our GitHub App from the user's account
    pub async fn fetch_installation_id(&self, access_token: &str) -> Result<u64, CoreError> {
        let response = self
            .http_client
            .get(
                "https://api.github.com/user/installations",
                &[
                    ("Authorization", &format!("token {}", access_token)),
                    ("User-Agent", "codewire-desktop"),
                    ("Accept", "application/vnd.github+json"),
                ],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!("Failed to fetch installations: {}", response.text()),
            });
        }

        let body: serde_json::Value = response.json().map_err(|e| CoreError::AuthFailed {
            message: format!("Failed to parse installations response: {}", e),
        })?;

        let app_slug = github_app_slug();
        let installations =
            body["installations"]
                .as_array()
                .ok_or_else(|| CoreError::AuthFailed {
                    message: "Unexpected installations response format".to_string(),
                })?;

        // Find our app's installation by slug, or fall back to first
        let installation_id = installations
            .iter()
            .find(|inst| inst["app_slug"].as_str() == Some(&app_slug))
            .or_else(|| installations.first())
            .and_then(|inst| inst["id"].as_u64())
            .ok_or_else(|| CoreError::AuthFailed {
                message: "No GitHub App installation found. Please install the app first."
                    .to_string(),
            })?;

        Ok(installation_id)
    }

    /// Get a valid (non-expired) token, refreshing if needed
    pub async fn get_valid_token(&self) -> Result<Option<GitHubToken>, CoreError> {
        let token = match self.get_token()? {
            Some(t) => t,
            None => return Ok(None),
        };

        if !token.is_expired() {
            return Ok(Some(token));
        }

        if token.can_refresh() {
            let refresh_tok = token.refresh_token.as_ref().unwrap();
            match self.refresh_token(refresh_tok).await {
                Ok(mut new_token) => {
                    new_token.installation_id = token.installation_id;
                    self.store_token(&new_token)?;
                    return Ok(Some(new_token));
                }
                Err(e) => {
                    tracing::warn!("GitHub token refresh failed: {}", e);
                }
            }
        }

        self.delete_token()?;
        Ok(None)
    }

    /// Delete GitHub token from secure storage
    pub fn delete_token(&self) -> Result<(), CoreError> {
        let _ = self.secure_storage.delete(GITHUB_TOKEN_KEY);
        Ok(())
    }
}
