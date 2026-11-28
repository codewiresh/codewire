//! A bound local secret's part of a projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder,
//! derived under the local authority's application-secret key, in place of
//! its value, which is never read from the protected store. The key is
//! loaded only when a winner is bound, so a projection of plain secrets is
//! exactly what it was. A bound secret whose placeholder can't be derived
//! refuses the projection by name and is never projected raw. A plain one
//! the boot recorded bound projects the placeholder its record derives, and
//! one ever bound, for a boot that recorded nothing, is refused by name.

use codewire_access::{
    ApplicationSecretKey, EnvironmentId, FirstBindSecret, PlaceholderPrefix, SecretKind,
    SecretPlaceholder, SecretSlot, local_project_path, local_user_path,
};
use codewire_protected_store::ProtectedStore;
use codewire_workload_secrets::ProjectionContext;
use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{InternalWorkloadSecret, WinnerSet};
use crate::placeholder::authority_id;
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
        let environment = self.environment()?;
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

    /// What a plain winner, `secret` stored as `key` in `set`, projects in
    /// its value's place: the placeholder `record` derives when the boot
    /// recorded it bound, or `None` for its value. With no record, one whose
    /// `binding_id` shows it was ever bound has nothing to derive a
    /// placeholder from and is refused by name.
    pub(super) fn recorded(
        &mut self,
        key: &str,
        set: WinnerSet,
        secret: &InternalWorkloadSecret,
        record: Option<&[FirstBindSecret]>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, LocalCredentialError> {
        let record = match record {
            None if secret.binding_id.is_some() => {
                return Err(LocalCredentialError::BoundSecretUnrecorded(key.to_owned()));
            }
            None => return Ok(None),
            Some([]) => return Ok(None),
            Some(record) => record,
        };
        let path = set_path(self.connection, set)?;
        let Some(recorded) = record.iter().find(|secret| secret.is(&path, key)) else {
            return Ok(None);
        };
        let refused = || LocalCredentialError::BoundSecretUnprojectable(key.to_owned());
        let environment = self.environment()?;
        let (_, application_key) = self.loaded().ok_or_else(refused)?;
        let placeholder = recorded
            .placeholder(application_key, &environment)
            .ok_or_else(refused)?;
        Ok(Some(Zeroizing::new(
            placeholder.as_str().as_bytes().to_vec(),
        )))
    }

    fn environment(&self) -> Result<EnvironmentId, LocalCredentialError> {
        EnvironmentId::parse(Uuid::from_bytes(self.context.environment_id).to_string())
            .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }

    /// The key and ID, loaded on first use. A key that can't be loaded gives
    /// none, and each bound secret is then refused by name.
    fn loaded(&mut self) -> Option<&(String, ApplicationSecretKey)> {
        self.loaded
            .get_or_insert_with(|| self.authority.application_secret_key(self.connection).ok())
            .as_ref()
    }
}

/// The path a boot records `set` by: the owner's personal set under this
/// authority's ID, or a local project by its UUID.
pub(super) fn set_path(
    connection: &Connection,
    set: WinnerSet,
) -> Result<String, LocalCredentialError> {
    Ok(match set {
        WinnerSet::User => local_user_path(&authority_id(connection)?),
        WinnerSet::Project(project) => local_project_path(&project.to_string()),
    })
}
