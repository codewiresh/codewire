//! A bound local secret's part of a projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder,
//! derived under the local authority's application-secret key, in place of
//! its value, which is never read from the protected store. The key is
//! loaded only when a winner is bound, so a projection of plain secrets is
//! exactly what it was. A bound secret whose placeholder can't be derived
//! refuses the projection by name and is never projected raw.

use codewire_access::{
    ApplicationSecretKey, EnvironmentId, PlaceholderPrefix, SecretKind, SecretPlaceholder,
    SecretSlot,
};
use codewire_protected_store::ProtectedStore;
use codewire_workload_secrets::ProjectionContext;
use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{InternalWorkloadSecret, WinnerSet};
use crate::{LocalCredentialAuthority, LocalCredentialError};

/// The application-secret key and the authority's ID, loaded once for one
/// projection when its first bound winner needs them.
pub(super) struct BoundValues<'a, S: ProtectedStore> {
    authority: &'a LocalCredentialAuthority<S>,
    connection: &'a Connection,
    context: &'a ProjectionContext,
    loaded: Option<Option<(String, ApplicationSecretKey)>>,
}

impl<'a, S: ProtectedStore> BoundValues<'a, S> {
    pub(super) fn new(
        authority: &'a LocalCredentialAuthority<S>,
        connection: &'a Connection,
        context: &'a ProjectionContext,
    ) -> Self {
        Self {
            authority,
            connection,
            context,
            loaded: None,
        }
    }

    /// `secret`'s placeholder, stored as `key` in `set`, as the value the
    /// projection carries for it.
    pub(super) fn placeholder(
        &mut self,
        key: &str,
        set: WinnerSet,
        secret: &InternalWorkloadSecret,
    ) -> Result<Zeroizing<Vec<u8>>, LocalCredentialError> {
        let refused = || LocalCredentialError::BoundSecretUnprojectable(key.to_owned());
        let binding = secret.metadata.binding.as_ref().ok_or_else(refused)?;
        let binding_id = secret
            .binding_id
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let prefix = binding
            .prefix
            .as_deref()
            .map(PlaceholderPrefix::parse)
            .transpose()
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let environment =
            EnvironmentId::parse(Uuid::from_bytes(self.context.environment_id).to_string())
                .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
        let (authority_id, application_key) = self.loaded().ok_or_else(refused)?;
        let slot = match set {
            WinnerSet::User => SecretSlot::new(SecretKind::Local, authority_id, key),
            WinnerSet::Project(project) => {
                SecretSlot::new(SecretKind::Project, &project.to_string(), key)
            }
        }
        .map_err(|_| refused())?;
        let placeholder = SecretPlaceholder::derive(
            application_key,
            &environment,
            &slot,
            binding_id.as_bytes(),
            secret.metadata.binding_generation,
            prefix.as_ref(),
        );
        Ok(Zeroizing::new(placeholder.as_str().as_bytes().to_vec()))
    }

    /// The key and ID, loaded on first use. A key that can't be loaded gives
    /// none, and each bound secret is then refused by name.
    fn loaded(&mut self) -> Option<&(String, ApplicationSecretKey)> {
        self.loaded
            .get_or_insert_with(|| self.authority.application_secret_key(self.connection).ok())
            .as_ref()
    }
}
