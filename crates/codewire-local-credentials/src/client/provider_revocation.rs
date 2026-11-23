//! Asking the authority to revoke a credential at its provider (#4717).

use codewire_access::CredentialId;
use tonic::Status;

use super::{LocalCredentialClient, credential_from_proto, credential_selector};
use crate::CredentialRecord;
use crate::control::v1;

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

    /// Revokes an active credential, asks its provider as
    /// [`Self::revoke_credential_at_provider`] does, and deletes it, as one
    /// step the store refuses before any change while a profile or a local
    /// VM's profile revision selects it
    /// ([`crate::AuthorityFeature::DeleteGate`], #6128). The answer is unset
    /// when nothing was asked. An error after the revoke leaves the
    /// credential revoked, and [`Self::delete_credential`] finishes it.
    pub async fn delete_credential_revoking_first(
        &mut self,
        id: &CredentialId,
    ) -> Result<Option<crate::LocalProviderRevocation>, Status> {
        Ok(self
            .inner
            .delete_credential(delete_request(id, true))
            .await?
            .into_inner()
            .provider_revocation)
    }
}

pub(super) fn delete_request(id: &CredentialId, revoke_first: bool) -> v1::DeleteCredentialRequest {
    v1::DeleteCredentialRequest {
        credential_id: id.to_string(),
        revoke_first,
    }
}
