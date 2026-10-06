//! The SSH host keys workspace daemons record at bind (design L4), read only
//! for the Pod the environment is currently bound to. Clients trust exactly
//! that key, and orchestration's own SSH checks pin to it.

use async_trait::async_trait;
use sqlx::PgPool;

/// The recorded host keys: the key the environment's currently bound Pod
/// recorded, with the generation it was recorded at, or none.
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
