//! NATS client helper.
//!
//! Wraps `async_nats::connect` with retry-aware defaults. Returns `None`
//! when `nats_url` is unset, so services that don't need NATS just skip
//! initialization. If `NATS_TOKEN` is configured, the token is passed through
//! to the server.

use async_nats::ConnectOptions;

/// Connects to NATS at `url`, returning `Ok(None)` if `url` is `None`.
pub async fn connect(
    url: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<Option<async_nats::Client>> {
    let Some(url) = url else {
        return Ok(None);
    };
    let mut options = ConnectOptions::new().connection_timeout(std::time::Duration::from_secs(5));
    if let Some(token) = token {
        options = options.token(token.to_string());
    }
    let client = options.connect(url).await?;
    Ok(Some(client))
}
