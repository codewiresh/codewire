//! GitHub API client
//!
//! Lists repositories from a GitHub App installation. Only returns
//! repos the user explicitly granted access to.

use crate::CoreError;
use crate::platform::HttpClient;

/// A GitHub repository
#[derive(Clone, Debug, serde::Deserialize)]
pub struct GitHubRepo {
    pub full_name: String,
    pub clone_url: String,
    pub ssh_url: String,
    pub description: Option<String>,
    pub private: bool,
    pub updated_at: String,
}

/// GitHub API client scoped to an app installation
pub struct GitHubClient<H: HttpClient> {
    token: String,
    installation_id: u64,
    http_client: H,
}

impl<H: HttpClient> GitHubClient<H> {
    pub fn new(token: String, installation_id: u64, http_client: H) -> Self {
        Self {
            token,
            installation_id,
            http_client,
        }
    }

    /// List repositories the user granted to this GitHub App installation
    pub async fn list_repos(&self) -> Result<Vec<GitHubRepo>, CoreError> {
        let url = format!(
            "https://api.github.com/user/installations/{}/repositories?per_page=100",
            self.installation_id,
        );

        let response = self
            .http_client
            .get(
                &url,
                &[
                    ("Authorization", &format!("token {}", self.token)),
                    ("User-Agent", "codewire-desktop"),
                    ("Accept", "application/vnd.github+json"),
                ],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!(
                    "GitHub API failed ({}): {}",
                    response.status,
                    response.text()
                ),
            });
        }

        // Response: { "total_count": N, "repositories": [...] }
        let body: serde_json::Value = response.json().map_err(|e| CoreError::Serialization {
            message: format!("Failed to parse GitHub repos: {}", e),
        })?;

        let repos_array =
            body["repositories"]
                .as_array()
                .ok_or_else(|| CoreError::Serialization {
                    message: "Missing 'repositories' array in response".to_string(),
                })?;

        let repos: Vec<GitHubRepo> = repos_array
            .iter()
            .filter_map(|r| serde_json::from_value(r.clone()).ok())
            .collect();

        Ok(repos)
    }
}
