//! Fixed-purpose projected token, not a configurable material reader.
use std::path::Path;

use tokio::io::AsyncReadExt;
use tonic::{
    Status,
    metadata::{Binary, MetadataValue},
};
use zeroize::Zeroizing;

pub(crate) const WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Tonic's binary MetadataValue Debug decodes its bytes even when sensitive.
/// Keep a redacting owner until the private RPC response boundary instead.
pub(crate) struct WorkspaceAuthorization(MetadataValue<Binary>);

impl std::fmt::Debug for WorkspaceAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkspaceAuthorization([REDACTED])")
    }
}

impl WorkspaceAuthorization {
    pub(crate) fn into_metadata(self) -> MetadataValue<Binary> {
        self.0
    }
}

pub(super) async fn read_workspace_authorization(
    path: &Path,
) -> Result<WorkspaceAuthorization, Status> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // Kubernetes rotates projected tokens through symlinks. Validate the open
    // descriptor; NONBLOCK prevents a replaced FIFO from stranding an opener.
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path).await.map_err(|_| unavailable())?;
    let metadata = file.metadata().await.map_err(|_| unavailable())?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err(unavailable());
    }
    let mut value = Zeroizing::new(b"Bearer ".to_vec());
    file.take(MAX_TOKEN_BYTES as u64 + 1)
        .read_to_end(&mut value)
        .await
        .map_err(|_| unavailable())?;
    let token = &value[7..];
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(unavailable());
    }
    let mut value = MetadataValue::from_bytes(&value);
    value.set_sensitive(true);
    Ok(WorkspaceAuthorization(value))
}

pub(super) fn unavailable() -> Status {
    Status::unavailable("hosted credential bridge is unavailable")
}

#[cfg(test)]
mod tests;
