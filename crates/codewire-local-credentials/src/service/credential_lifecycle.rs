//! The authority's credential revoke and delete handlers, and the RPC
//! service's `Clone`, kept out of service.rs, which is past its size limit.

use std::sync::Arc;

use codewire_protected_store::ProtectedStore;
use tonic::{Response, Status};

use super::{AuthorityRpc, credential_id, credential_to_proto, run_blocking};
use crate::LocalCredentialAuthority;
use crate::control::v1;

pub(super) async fn revoke<S: ProtectedStore + 'static>(
    authority: &Arc<LocalCredentialAuthority<S>>,
    selector: v1::CredentialSelector,
) -> Result<Response<v1::Credential>, Status> {
    let id = credential_id(selector.credential_id)?;
    let authority = Arc::clone(authority);
    let record = run_blocking(move || authority.revoke_credential(&id)).await?;
    Ok(Response::new(credential_to_proto(record)))
}

pub(super) async fn revoke_at_provider<S: ProtectedStore + 'static>(
    revocations: &super::provider_revocation::ProviderRevocations<S>,
    selector: v1::CredentialSelector,
) -> Result<Response<v1::RevokeCredentialAtProviderResponse>, Status> {
    let id = credential_id(selector.credential_id)?;
    let (record, provider_revocation) = revocations
        .revoke_at_provider(id)
        .await
        .map_err(super::status_for_error)?;
    Ok(Response::new(v1::RevokeCredentialAtProviderResponse {
        credential: Some(credential_to_proto(record)),
        provider_revocation,
    }))
}

/// With `revoke_first`, the store's revoke for a delete runs first and
/// refuses before any change while the credential is in use; its provider is
/// asked; then the delete finishes (#6128). A failure after the revoke
/// leaves the credential revoked and pending delete, and a plain delete
/// finishes it.
pub(super) async fn delete<S: ProtectedStore + 'static>(
    authority: &Arc<LocalCredentialAuthority<S>>,
    revocations: &super::provider_revocation::ProviderRevocations<S>,
    request: v1::DeleteCredentialRequest,
) -> Result<Response<v1::DeleteCredentialResponse>, Status> {
    let id = credential_id(request.credential_id)?;
    let provider_revocation = if request.revoke_first {
        let (_, reported) = revocations
            .revoke_for_delete(id.clone())
            .await
            .map_err(super::status_for_error)?;
        reported
    } else {
        None
    };
    let authority = Arc::clone(authority);
    run_blocking(move || authority.delete_credential(&id)).await?;
    Ok(Response::new(v1::DeleteCredentialResponse {
        provider_revocation,
    }))
}

impl<S: ProtectedStore> Clone for AuthorityRpc<S> {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            brokers: Arc::clone(&self.brokers),
            repositories: Arc::clone(&self.repositories),
            revocations: Arc::clone(&self.revocations),
            broker_audit: Arc::clone(&self.broker_audit),
            shutdown: self.shutdown.clone(),
            ssh_enrollment_workers: self.ssh_enrollment_workers.clone(),
        }
    }
}
