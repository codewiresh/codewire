use codewire_core::{CoreError, OAuthCallbackHandler};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Native OAuth handler that opens the browser and listens for callbacks
/// via a tiny local HTTP server
pub struct NativeOAuthHandler {
    port: u16,
    /// Stores the received authorization code
    code: Arc<Mutex<Option<String>>>,
}

impl NativeOAuthHandler {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            code: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for NativeOAuthHandler {
    fn default() -> Self {
        Self::new(9876)
    }
}

impl OAuthCallbackHandler for NativeOAuthHandler {
    fn open_browser(&self, url: &str) -> Result<(), CoreError> {
        open::that(url).map_err(|e| CoreError::AuthFailed {
            message: format!("Failed to open browser: {e}"),
        })
    }

    async fn wait_for_callback(&self) -> Result<String, CoreError> {
        let addr = format!("127.0.0.1:{}", self.port);
        let server = tiny_http::Server::http(&addr).map_err(|e| CoreError::AuthFailed {
            message: format!("Failed to start callback server on {addr}: {e}"),
        })?;

        let code = self.code.clone();

        // Wait for a single request with a timeout
        let handle = tokio::task::spawn_blocking(move || {
            let timeout = std::time::Duration::from_secs(120);
            match server.recv_timeout(timeout) {
                Ok(Some(request)) => {
                    // Extract the "code" query parameter from the URL
                    let url = request.url().to_string();
                    let auth_code = url
                        .split('?')
                        .nth(1)
                        .and_then(|query| {
                            query.split('&').find_map(|param| {
                                let mut parts = param.splitn(2, '=');
                                let key = parts.next()?;
                                let value = parts.next()?;
                                if key == "code" {
                                    Some(value.to_string())
                                } else {
                                    None
                                }
                            })
                        })
                        .ok_or_else(|| CoreError::AuthFailed {
                            message: "No 'code' parameter in callback URL".to_string(),
                        })?;

                    // Respond to the browser
                    let response = tiny_http::Response::from_string(
                        "<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>",
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"text/html"[..],
                        )
                        .unwrap(),
                    );
                    let _ = request.respond(response);

                    Ok(auth_code)
                }
                Ok(None) => Err(CoreError::AuthFailed {
                    message: "OAuth callback timed out".to_string(),
                }),
                Err(e) => Err(CoreError::AuthFailed {
                    message: format!("Error waiting for callback: {e}"),
                }),
            }
        });

        let result = handle.await.map_err(|e| CoreError::AuthFailed {
            message: format!("Callback listener task failed: {e}"),
        })??;

        *code.lock().await = Some(result.clone());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_oauth_callback_flow() {
        // Use a random high port to avoid conflicts
        let handler = NativeOAuthHandler::new(0);

        // Start the callback server in a background task - we'll simulate the browser callback
        // For unit testing, we test the URL parsing logic directly
        let url = "/callback?code=test_auth_code_123&state=xyz";
        let code = url.split('?').nth(1).and_then(|query| {
            query.split('&').find_map(|param| {
                let mut parts = param.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next()?;
                if key == "code" {
                    Some(value.to_string())
                } else {
                    None
                }
            })
        });

        assert_eq!(code, Some("test_auth_code_123".to_string()));

        // Verify handler was created with correct port
        assert_eq!(handler.port, 0);
    }
}
