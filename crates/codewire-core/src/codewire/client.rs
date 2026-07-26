//! Codewire platform API client
//!
//! Fetches resources from the Codewire Go server API,
//! authenticated with a Bearer session token. Generic over HttpClient trait.

use crate::CoreError;
use crate::platform::HttpClient;
use codewire_api_types::{CreateOrgRequest, Environment, OrgWithRole, Organization};

/// API URL for the Rust server.
/// In production, Caddy proxies /api/v1/* from CODEWIRE_URL to the Rust server.
/// For local dev, set CODEWIRE_API_URL to point directly at the Rust server.
#[cfg(not(target_arch = "wasm32"))]
fn api_url() -> String {
    std::env::var("CODEWIRE_API_URL")
        .or_else(|_| std::env::var("CODEWIRE_URL"))
        .unwrap_or_else(|_| "https://codewire.sh".to_string())
}

/// Client for the Codewire platform API
pub struct CodewireClient<H: HttpClient> {
    access_token: String,
    base_url: String,
    http_client: H,
}

impl<H: HttpClient> CodewireClient<H> {
    /// Create a new client with a Bearer token and explicit base URL.
    /// Works on all targets (native + WASM).
    pub fn new_with_url(access_token: String, base_url: String, http_client: H) -> Self {
        Self {
            access_token,
            base_url,
            http_client,
        }
    }

    /// Create a new client with a Bearer token.
    /// Base URL is resolved from CODEWIRE_API_URL / CODEWIRE_URL env vars.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(access_token: String, http_client: H) -> Self {
        Self::new_with_url(access_token, api_url(), http_client)
    }

    /// List organizations the authenticated user has access to.
    pub async fn list_organizations(&self) -> Result<Vec<OrgWithRole>, CoreError> {
        let url = format!("{}/api/v1/organizations", self.base_url);
        let auth_header = format!("Bearer {}", self.access_token);
        let headers = [("Authorization", auth_header.as_str())];

        let response = self.http_client.get(&url, &headers).await?;

        if !response.is_success() {
            return Err(CoreError::Api {
                message: format!(
                    "Organization list failed ({}): {}",
                    response.status,
                    response.text()
                ),
            });
        }

        response.json().map_err(|e| CoreError::Api {
            message: format!("Failed to parse organization list: {}", e),
        })
    }

    /// List environments for an organization.
    pub async fn list_environments(&self, org_id: &str) -> Result<Vec<Environment>, CoreError> {
        let url = format!(
            "{}/api/v1/organizations/{}/environments",
            self.base_url, org_id
        );
        let auth_header = format!("Bearer {}", self.access_token);
        let headers = [("Authorization", auth_header.as_str())];

        let response = self.http_client.get(&url, &headers).await?;

        if !response.is_success() {
            return Err(CoreError::Api {
                message: format!(
                    "Environment list failed for org {} ({}): {}",
                    org_id,
                    response.status,
                    response.text()
                ),
            });
        }

        response.json().map_err(|e| CoreError::Api {
            message: format!("Failed to parse environment list: {}", e),
        })
    }

    /// Create a new organization
    pub async fn create_organization(
        &self,
        name: &str,
        slug: &str,
    ) -> Result<Organization, CoreError> {
        let url = format!("{}/api/v1/organizations", self.base_url);
        let auth_header = format!("Bearer {}", self.access_token);
        let headers = [("Authorization", auth_header.as_str())];

        let body = serde_json::to_vec(&CreateOrgRequest {
            name: name.to_string(),
            slug: slug.to_string(),
        })
        .map_err(|e| CoreError::Serialization {
            message: format!("Failed to serialize create org request: {}", e),
        })?;

        let response = self.http_client.post_json(&url, &headers, &body).await?;

        if !response.is_success() {
            return Err(CoreError::Api {
                message: format!(
                    "Create organization failed ({}): {}",
                    response.status,
                    response.text()
                ),
            });
        }

        response.json().map_err(|e| CoreError::Api {
            message: format!("Failed to parse created organization: {}", e),
        })
    }
}
