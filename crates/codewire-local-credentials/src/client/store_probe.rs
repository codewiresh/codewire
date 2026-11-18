//! Whether the authority's store accepts a write now.

use tonic::Status;

use super::LocalCredentialClient;
use crate::control::v1;

impl LocalCredentialClient {
    /// The authority writes a canary to the store that holds credentials and
    /// deletes it again. An error is the store's own refusal or a lost
    /// connection; an authority older than
    /// [`crate::AuthorityFeature::StoreProbe`] answers Unimplemented.
    pub async fn probe_protected_store(&mut self) -> Result<(), Status> {
        self.inner
            .probe_protected_store(v1::ProbeProtectedStoreRequest {})
            .await?;
        Ok(())
    }
}
