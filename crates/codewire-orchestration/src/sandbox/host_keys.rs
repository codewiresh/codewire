//! The SSH host keys workspace daemons record at bind (design L4), read for
//! the environment's current operation generation only. Clients trust exactly
//! that key, and orchestration's own SSH checks pin to it.

use async_trait::async_trait;
use sqlx::PgPool;

/// The recorded host keys: the key of an environment's current operation
/// generation, with that generation, or none.
#[async_trait]
pub trait HostKeyStore: Send + Sync {
    async fn current_host_key(
        &self,
        environment_id: &str,
    ) -> Result<Option<(i64, String)>, sqlx::Error>;
}

/// The host keys workspace daemons record over `WorkspaceBindingService`.
pub struct RecordedHostKeys<'a>(pub &'a PgPool);

#[async_trait]
impl HostKeyStore for RecordedHostKeys<'_> {
    async fn current_host_key(
        &self,
        environment_id: &str,
    ) -> Result<Option<(i64, String)>, sqlx::Error> {
        crate::workspace_binding::current_host_key(self.0, environment_id).await
    }
}
