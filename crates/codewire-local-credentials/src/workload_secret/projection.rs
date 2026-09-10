//! Exact local source reader for an authenticated launch. No raw-value getter
//! is added to the metadata API. The trusted transport owner supplies the
//! canonical selected IDs and rechecks the environment operation before and
//! after this blocking operation; a sandbox never supplies an arbitrary scope.

use std::collections::{BTreeMap, BTreeSet};

use codewire_protected_store::ProtectedStore;
use codewire_workload_secrets::{
    EnvironmentProjection, MAX_ENVIRONMENT_PROJECTION_BYTES, MAX_WORKLOAD_SECRETS,
    ProjectionCompositionPlan, ProjectionContext, ProjectionContributor, ProjectionSourceInventory,
    WorkloadSecretSource, seal_environment_projection, seal_environment_projection_fragment,
};
use rusqlite::{Connection, params};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    InternalWorkloadSecret, SecretScope, load_secret_by_id, require_project, validate_secret_key,
    validate_secret_value,
};
use crate::{
    LocalCredentialAuthority, LocalCredentialError, MaterialState, database_error, unix_millis,
};

/// Resolved local source identities for one launch, not display-name lookups.
/// The caller resolves complete cross-origin precedence before material reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalLaunchSecretSelection {
    pub project_id: Option<Uuid>,
    pub user: bool,
    /// Keys won by a higher-precedence selected source or ordinary environment
    /// configuration. Suppression happens before any protected-store access.
    pub overridden_keys: BTreeSet<String>,
    /// Active managed provider configuration must never be overwritten by an
    /// application value. This comes from the selected provider routes, not
    /// inference from a key name or value.
    pub reserved_keys: BTreeSet<String>,
}

impl LocalLaunchSecretSelection {
    pub(crate) fn validate(&self) -> Result<(), LocalCredentialError> {
        if self.project_id.is_some_and(|id| id.is_nil())
            || self.overridden_keys.len() > MAX_WORKLOAD_SECRETS
            || self.reserved_keys.len() > MAX_WORKLOAD_SECRETS
        {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        for key in self.overridden_keys.iter().chain(&self.reserved_keys) {
            validate_secret_key(key)?;
        }
        Ok(())
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Capture complete selected local names under the authority lock, without
    /// consulting protected material. Empty selected scopes remain present and
    /// overridden names are retained: global precedence is resolved only after
    /// the other authenticated producer supplies its complete inventory.
    pub fn inventory_workload_projection(
        &self,
        selection: &LocalLaunchSecretSelection,
    ) -> Result<Vec<ProjectionSourceInventory>, LocalCredentialError> {
        selection.validate()?;
        let connection = self.connection()?;
        Ok(capture_local_sources(&connection, selection)?.inventories)
    }

    /// Seal this authority's part of one mixed-origin launch. The transport
    /// owner authenticates the complete selection and other producer; supplied
    /// inventories alone are not authority. This method always contributes as
    /// Local and compares its complete current inventory before any value read.
    ///
    /// Here `selection.overridden_keys` contains ordinary environment names
    /// only, never caller-computed cross-authority winners. The shared plan
    /// derives those winners from the complete ranked inventories. Same-name
    /// value rotation before this lock is allowed; names and current winning
    /// material cannot change during the locked read and seal.
    pub fn seal_workload_projection_fragment(
        &self,
        selection: &LocalLaunchSecretSelection,
        context: &ProjectionContext,
        recipient: [u8; 32],
        request_id: [u8; 16],
        inventories: &[ProjectionSourceInventory],
    ) -> Result<Vec<u8>, LocalCredentialError> {
        selection.validate()?;
        validate_launch(context, recipient)?;
        if inventories.len() > 3 {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        let connection = self.connection()?;
        let mut capture = capture_local_sources(&connection, selection)?;
        if !capture.inventories.iter().eq(inventories
            .iter()
            .filter(|inventory| inventory.contributor == ProjectionContributor::Local))
        {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        let plan = ProjectionCompositionPlan::new(
            context,
            request_id,
            recipient,
            inventories,
            &selection.overridden_keys,
            &selection.reserved_keys,
            unix_millis()?,
        )
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
        let winning_keys = plan.winning_keys(ProjectionContributor::Local);
        capture.winners.retain(|key, _| winning_keys.contains(key));
        if !capture.winners.keys().eq(winning_keys.iter()) {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        let projection = self.read_projection_values(capture.winners, context)?;
        seal_environment_projection_fragment(
            projection,
            context,
            recipient,
            ProjectionContributor::Local,
            &plan,
            unix_millis()?,
        )
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }

    /// Seal only the values selected by an already-authorized local launch.
    /// Local storage has one owner; the authenticated caller additionally owns
    /// environment lifecycle admission and the complete selection fingerprint.
    /// This method cannot establish either from unchecked request fields.
    ///
    /// Metadata selection and protected reads hold the same authority lock, so
    /// rotation/deletion cannot change the winner halfway through assembly.
    /// Missing/denied winning material fails the whole projection; a lower
    /// precedence source is never a fallback. Provider entries are not queried.
    pub fn seal_workload_projection(
        &self,
        selection: &LocalLaunchSecretSelection,
        context: &ProjectionContext,
        recipient: [u8; 32],
    ) -> Result<Vec<u8>, LocalCredentialError> {
        selection.validate()?;
        validate_launch(context, recipient)?;
        let connection = self.connection()?;
        let mut winners = capture_local_sources(&connection, selection)?.winners;
        winners.retain(|key, _| !selection.overridden_keys.contains(key));
        let projection = self.read_projection_values(winners, context)?;
        // Protected-store I/O is blocking and may outlast the original request.
        // Re-read time; never turn an expired result into a fresh lifetime.
        seal_environment_projection(projection, context, recipient, unix_millis()?)
            .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }

    // Both callers retain their original connection guard through this read
    // and the final seal. This helper never reopens or releases that lock.
    fn read_projection_values(
        &self,
        winners: BTreeMap<String, InternalWorkloadSecret>,
        context: &ProjectionContext,
    ) -> Result<EnvironmentProjection, LocalCredentialError> {
        let mut values = Vec::with_capacity(winners.len());
        let mut encoded_bytes = 4_usize;
        for (key, secret) in winners {
            context
                .validate_at(unix_millis()?)
                .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
            if secret.material_state != MaterialState::Ready {
                return Err(LocalCredentialError::WorkloadSecretMaterialMissing);
            }
            let value = self
                .protected_store
                .get(&secret.protected_entry_id)?
                .ok_or(LocalCredentialError::WorkloadSecretMaterialMissing)?;
            validate_secret_value(value.expose_secret())?;
            encoded_bytes = encoded_bytes
                .checked_add(8 + key.len() + value.expose_secret().len())
                .filter(|size| *size <= MAX_ENVIRONMENT_PROJECTION_BYTES)
                .ok_or(LocalCredentialError::InvalidWorkloadSecret)?;
            values.push((key, Zeroizing::new(value.expose_secret().to_vec())));
        }
        EnvironmentProjection::from_entries(values)
            .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }
}

fn validate_launch(
    context: &ProjectionContext,
    recipient: [u8; 32],
) -> Result<(), LocalCredentialError> {
    codewire_workload_secrets::validate_projection_recipient(recipient)
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
    context
        .validate_at(unix_millis()?)
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
}

struct LocalSourceCapture {
    inventories: Vec<ProjectionSourceInventory>,
    winners: BTreeMap<String, InternalWorkloadSecret>,
}

fn capture_local_sources(
    connection: &Connection,
    selection: &LocalLaunchSecretSelection,
) -> Result<LocalSourceCapture, LocalCredentialError> {
    let mut scopes = Vec::with_capacity(2);
    if let Some(id) = &selection.project_id {
        require_project(connection, id)?;
        scopes.push((
            SecretScope::Project(id),
            WorkloadSecretSource::Project,
            format!("local:project:{id}"),
        ));
    }
    if selection.user {
        scopes.push((
            SecretScope::User,
            WorkloadSecretSource::User,
            "local:user".into(),
        ));
    }
    let mut capture = LocalSourceCapture {
        inventories: Vec::with_capacity(scopes.len()),
        winners: BTreeMap::new(),
    };
    for (scope, source, source_identity) in scopes {
        let mut keys = BTreeSet::new();
        for secret in selected_metadata(connection, scope)? {
            let key = &secret.metadata.key;
            if selection.reserved_keys.contains(key)
                || (capture.winners.len() >= MAX_WORKLOAD_SECRETS
                    && !capture.winners.contains_key(key))
            {
                return Err(LocalCredentialError::InvalidWorkloadSecret);
            }
            keys.insert(key.clone());
            capture.winners.insert(key.clone(), secret);
        }
        capture.inventories.push(ProjectionSourceInventory {
            contributor: ProjectionContributor::Local,
            source,
            source_identity,
            keys,
        });
    }
    Ok(capture)
}

// Bound metadata enumeration itself, including non-ready winners, before any
// protected read. Public paginated inventory is not the launch-time API.
fn selected_metadata(
    connection: &Connection,
    scope: SecretScope<'_>,
) -> Result<Vec<InternalWorkloadSecret>, LocalCredentialError> {
    let mut statement = connection.prepare(
        "SELECT id FROM workload_secrets WHERE scope_kind = ?1 AND scope_id = ?2 ORDER BY key, id LIMIT ?3"
    ).map_err(database_error)?;
    let ids = statement
        .query_map(
            params![scope.kind(), scope.id(), (MAX_WORKLOAD_SECRETS + 1) as i64],
            |row| row.get::<_, String>(0),
        )
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    if ids.len() > MAX_WORKLOAD_SECRETS {
        return Err(LocalCredentialError::InvalidWorkloadSecret);
    }
    ids.into_iter()
        .map(|id| load_secret_by_id(connection, super::parse_uuid(&id)?))
        .collect()
}

#[cfg(test)]
mod tests;
