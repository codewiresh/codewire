//! Codewire platform OAuth authentication
//!
//! PKCE OAuth flow against the Codewire OIDC provider.
//! Generic over platform traits (HttpClient, SecureStorage, OAuthCallbackHandler).

use crate::CoreError;
use crate::platform::{HttpClient, OAuthCallbackHandler, SecureStorage};
use sha2::{Digest, Sha256};

/// OAuth token information
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when token expires
    pub expires_at: u64,
}

impl TokenInfo {
    /// Check if token is expired or will expire soon (within 5 minutes)
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        self.expires_at < now + 300 // 5 minute buffer
    }
}

/// Port for OAuth callback server (shared with desktop auth)
const CALLBACK_PORT: u16 = 9876;
const CALLBACK_PATH: &str = "/callback";

/// Keychain key for Codewire platform tokens
const PLATFORM_TOKEN_KEY: &str = "codewire:platform:token";

/// Default Codewire platform URL
const DEFAULT_CODEWIRE_URL: &str = "https://codewire.sh";

/// OAuth client ID for the desktop app
const CLIENT_ID: &str = "codewire-desktop";

fn codewire_url() -> String {
    std::env::var("CODEWIRE_URL").unwrap_or_else(|_| DEFAULT_CODEWIRE_URL.to_string())
}

/// Codewire platform authentication manager, generic over platform traits
pub struct CodewireAuthManager<H: HttpClient, S: SecureStorage, O: OAuthCallbackHandler> {
    http_client: H,
    secure_storage: S,
    oauth_handler: O,
    /// Stored PKCE verifier for pending auth
    pending_verifier: Option<String>,
}

impl<H: HttpClient, S: SecureStorage, O: OAuthCallbackHandler> CodewireAuthManager<H, S, O> {
    pub fn new(http_client: H, secure_storage: S, oauth_handler: O) -> Self {
        Self {
            http_client,
            secure_storage,
            oauth_handler,
            pending_verifier: None,
        }
    }

    /// Start PKCE OAuth flow against Codewire platform.
    /// Returns the authorization URL to open in browser.
    pub fn start_auth_flow(&mut self) -> Result<String, CoreError> {
        let base_url = codewire_url();
        let auth_url = format!("{}/api/oauth/authorize", base_url);
        let redirect_uri = format!("http://localhost:{}{}", CALLBACK_PORT, CALLBACK_PATH);

        // Generate a simple PKCE code verifier (43-128 chars, unreserved chars)
        let verifier = uuid::Uuid::new_v4().to_string().replace('-', "")
            + &uuid::Uuid::new_v4().to_string().replace('-', "");

        self.pending_verifier = Some(verifier.clone());

        // S256 challenge: BASE64URL(SHA256(verifier))
        let challenge = {
            let hash = Sha256::digest(verifier.as_bytes());
            base64url_encode(&hash)
        };

        // Build authorization URL
        let state = uuid::Uuid::new_v4().to_string();
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            auth_url,
            urlencoded(CLIENT_ID),
            urlencoded(&redirect_uri),
            urlencoded("openid profile email offline_access"),
            urlencoded(&state),
            urlencoded(&challenge),
        );

        Ok(url)
    }

    /// Open browser for Codewire authentication
    pub fn open_browser_for_auth(&mut self) -> Result<(), CoreError> {
        let auth_url = self.start_auth_flow()?;
        self.oauth_handler.open_browser(&auth_url)
    }

    /// Wait for OAuth callback and return the authorization code
    pub async fn wait_for_callback(&self) -> Result<String, CoreError> {
        self.oauth_handler.wait_for_callback().await
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(&mut self, code: &str) -> Result<TokenInfo, CoreError> {
        let verifier = self
            .pending_verifier
            .take()
            .ok_or_else(|| CoreError::AuthFailed {
                message: "No pending PKCE verifier".to_string(),
            })?;

        let base_url = codewire_url();
        let token_url = format!("{}/api/oauth/token", base_url);
        let redirect_uri = format!("http://localhost:{}{}", CALLBACK_PORT, CALLBACK_PATH);

        let response = self
            .http_client
            .post_form(
                &token_url,
                &[],
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", &redirect_uri),
                    ("client_id", CLIENT_ID),
                    ("code_verifier", &verifier),
                ],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!("Token exchange failed: {}", response.text()),
            });
        }

        let token_response: TokenResponseJson =
            response.json().map_err(|e| CoreError::AuthFailed {
                message: format!("Failed to parse token response: {}", e),
            })?;

        let expires_at =
            chrono::Utc::now().timestamp() as u64 + token_response.expires_in.unwrap_or(3600);

        Ok(TokenInfo {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at,
        })
    }

    /// Refresh an access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenInfo, CoreError> {
        let base_url = codewire_url();
        let token_url = format!("{}/api/oauth/token", base_url);

        let response = self
            .http_client
            .post_form(
                &token_url,
                &[],
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", CLIENT_ID),
                ],
            )
            .await?;

        if !response.is_success() {
            return Err(CoreError::AuthFailed {
                message: format!("Token refresh failed: {}", response.text()),
            });
        }

        let token_response: TokenResponseJson =
            response.json().map_err(|e| CoreError::AuthFailed {
                message: format!("Failed to parse token response: {}", e),
            })?;

        let expires_at =
            chrono::Utc::now().timestamp() as u64 + token_response.expires_in.unwrap_or(3600);

        Ok(TokenInfo {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at,
        })
    }

    /// Store Codewire platform token in secure storage
    pub fn store_token(&self, token: &TokenInfo) -> Result<(), CoreError> {
        let token_json = serde_json::json!({
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at,
        });
        self.secure_storage
            .store(PLATFORM_TOKEN_KEY, &token_json.to_string())
    }

    /// Retrieve Codewire platform token from secure storage
    pub fn get_token(&self) -> Result<Option<TokenInfo>, CoreError> {
        match self.secure_storage.retrieve(PLATFORM_TOKEN_KEY)? {
            Some(password) => {
                let json: serde_json::Value =
                    serde_json::from_str(&password).map_err(|e| CoreError::Keychain {
                        message: format!("Failed to parse stored token: {}", e),
                    })?;

                Ok(Some(TokenInfo {
                    access_token: json["access_token"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
                    expires_at: json["expires_at"].as_u64().unwrap_or(0),
                }))
            }
            None => Ok(None),
        }
    }

    /// Delete Codewire platform token from secure storage
    pub fn delete_token(&self) -> Result<(), CoreError> {
        let _ = self.secure_storage.delete(PLATFORM_TOKEN_KEY);
        Ok(())
    }
}

/// JSON response from token endpoint
#[derive(serde::Deserialize)]
struct TokenResponseJson {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

/// Base64url-encode without padding (RFC 7636)
fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(data)
}

/// Simple percent-encoding for URL parameters
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace(':', "%3A")
}
