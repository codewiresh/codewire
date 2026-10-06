//! Projected identities for the hosted credential relay's private broker calls.
//!
//! Projected tokens are forwarded only as authentication metadata; the broker
//! verifies their exact Pod identities and original expiries. No token claims
//! are trusted here.

use axum::http::StatusCode;
use tokio::io::AsyncReadExt;
use tonic::metadata::MetadataValue;
use zeroize::Zeroizing;

const WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";
const MAX_TOKEN_BYTES: usize = 16 * 1024;

fn canonical_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn credential_metadata(
    gateway: &str,
    workspace: &[u8],
) -> Result<tonic::metadata::MetadataMap, StatusCode> {
    let authorization = Zeroizing::new(format!("Bearer {gateway}"));
    let mut gateway_value = MetadataValue::try_from(authorization.as_str())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    gateway_value.set_sensitive(true);
    let mut workspace_value = MetadataValue::from_bytes(workspace);
    workspace_value.set_sensitive(true);
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", gateway_value);
    metadata.insert_bin(WORKSPACE_AUTHORIZATION, workspace_value);
    Ok(metadata)
}

pub(crate) async fn read_gateway_token(
    path: &std::path::Path,
) -> Result<Zeroizing<String>, StatusCode> {
    // Kubernetes atomically rotates a projected volume using symlinks. The
    // configured path is trusted; every fresh RPC rereads its current target.
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // A raced FIFO must not strand a blocking file-open operation after the
    // request's admission deadline or owner cancellation. Projected symlinks
    // remain supported; validate the opened object, not a pathname precheck.
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut token = Zeroizing::new(String::with_capacity(2048));
    file.take((MAX_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut token)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !canonical_token(token.as_bytes()) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(token)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod tls_test_support;
