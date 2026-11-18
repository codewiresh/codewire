//! Asking the authority to revoke a credential at its provider (#4717).

use codewire_access::CredentialId;
use tonic::Status;

use super::{LocalCredentialClient, credential_from_proto, credential_selector};
use crate::CredentialRecord;

impl LocalCredentialClient {
    /// Revokes, then asks the credential's provider to revoke its token too
    /// ([`crate::AuthorityFeature::ProviderRevocation`]). The answer is unset
    /// when the credential was not active.
    pub async fn revoke_credential_at_provider(
        &mut self,
        id: &CredentialId,
    ) -> Result<(CredentialRecord, Option<crate::LocalProviderRevocation>), Status> {
        let response = self
            .inner
            .revoke_credential_at_provider(credential_selector(id))
            .await?
            .into_inner();
        let credential = response
            .credential
            .ok_or_else(|| Status::internal("authority omitted the revoked credential"))?;
        Ok((
            credential_from_proto(credential)?,
            response.provider_revocation,
        ))
    }
}
