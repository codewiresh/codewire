//! Exact local source reader for an authenticated launch. No raw-value getter
//! is added to the metadata API. The trusted transport owner supplies the
//! canonical selected IDs and rechecks the environment operation before and
//! after this blocking operation; a sandbox never supplies an arbitrary scope.

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::FirstBindSecret;
use codewire_protected_store::ProtectedStore;
use codewire_workload_secrets::{
    EnvironmentProjection, MAX_ENVIRONMENT_PROJECTION_BYTES, MAX_WORKLOAD_SECRETS,
    ProjectionCompositionPlan, ProjectionContext, ProjectionContributor, ProjectionSourceInventory,
    WorkloadSecretSource, seal_environment_projection, seal_environment_projection_fragment,
};
use rusqlite::{Connection, params};
use uuid::Uuid;
use zeroize::Zeroizing;

mod bound;
mod record;

pub(crate) use record::BoundSecretLease;
pub use record::BoundSecretLeaseRefusal;

use super::{
    InternalWorkloadSecret, SecretScope, load_secret_by_id, require_project, snapshot,
    validate_secret_key, validate_secret_value,
};
use crate::material::MaterialStore;
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
        Ok(snapshot(&connection, |connection| {
            capture_local_sources(connection, selection)
        })?
        .inventories)
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
    ///
    /// `record` is what the boot recorded of its bound secrets, `None` for one
    /// that recorded nothing (#4003, [`Self::seal_workload_projection`]).
    pub fn seal_workload_projection_fragment(
        &self,
        selection: &LocalLaunchSecretSelection,
        record: Option<&[FirstBindSecret]>,
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
        let connection = self.material_connection()?;
        let material = MaterialStore::new(&connection, &self.protected_store);
        let mut capture = snapshot(&connection, |connection| {
            capture_local_sources(connection, selection)
        })?;
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
        let projection =
            self.read_projection_values(&material, capture.winners, context, record)?;
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
    /// Selection and protected reads both run on the material connection, which
    /// secret writers also hold, so rotation/deletion cannot change the winner
    /// halfway through assembly (#5413). The selection is captured once, as a
    /// launch-time snapshot: a metadata change after it applies to the next
    /// launch.
    /// Missing/denied winning material fails the whole projection; a lower
    /// precedence source is never a fallback. Provider entries are not queried.
    ///
    /// A plain winner is projected raw only when the boot's `record` didn't
    /// record it bound (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md,
    /// "Projection"): one it recorded bound keeps the placeholder the record
    /// derives, and with no record one that was ever bound is refused.
    pub fn seal_workload_projection(
        &self,
        selection: &LocalLaunchSecretSelection,
        record: Option<&[FirstBindSecret]>,
        context: &ProjectionContext,
        recipient: [u8; 32],
    ) -> Result<Vec<u8>, LocalCredentialError> {
        selection.validate()?;
        validate_launch(context, recipient)?;
        let connection = self.material_connection()?;
        let material = MaterialStore::new(&connection, &self.protected_store);
        let mut winners = snapshot(&connection, |connection| {
            capture_local_sources(connection, selection)
        })?
        .winners;
        winners.retain(|key, _| !selection.overridden_keys.contains(key));
        let projection = self.read_projection_values(&material, winners, context, record)?;
        // Protected-store I/O is blocking and may outlast the original request.
        // Re-read time; never turn an expired result into a fresh lifetime.
        seal_environment_projection(projection, context, recipient, unix_millis()?)
            .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Both callers hold the material connection through this read and the
    /// final seal, outside any transaction. Any winner whose material can't
    /// be read fails the whole projection: it never seals a partial set. A
    /// bound winner's value is never read: its placeholder takes its place
    /// (#4003), or it refuses the projection by name. Nor is a plain one's
    /// that `record` recorded bound, or that was ever bound with no record.
    fn read_projection_values(
        &self,
        material: &MaterialStore<'_, S>,
        winners: BTreeMap<String, Winner>,
        context: &ProjectionContext,
        record: Option<&[FirstBindSecret]>,
    ) -> Result<EnvironmentProjection, LocalCredentialError> {
        let mut bound = bound::BoundValues::new(self, material.connection(), context);
        let mut values = Vec::with_capacity(winners.len());
        let mut encoded_bytes = 4_usize;
        for (key, Winner { set, secret }) in winners {
            context
                .validate_at(unix_millis()?)
                .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
            let value = match &secret.metadata.binding {
                Some(_) => bound.placeholder(&key, set, &secret)?,
                None => match bound.recorded(&key, set, &secret, record)? {
                    Some(placeholder) => placeholder,
                    None => read_value(material, &secret)?,
                },
            };
            encoded_bytes = encoded_bytes
                .checked_add(8 + key.len() + value.len())
                .filter(|size| *size <= MAX_ENVIRONMENT_PROJECTION_BYTES)
                .ok_or(LocalCredentialError::InvalidWorkloadSecret)?;
            values.push((key, value));
        }
        EnvironmentProjection::from_entries(values)
            .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
    }
}

/// A plain winner's value from the protected store.
fn read_value<S: ProtectedStore>(
    material: &MaterialStore<'_, S>,
    secret: &InternalWorkloadSecret,
) -> Result<Zeroizing<Vec<u8>>, LocalCredentialError> {
    if secret.material_state != MaterialState::Ready {
        return Err(LocalCredentialError::WorkloadSecretMaterialMissing);
    }
    let value = material
        .get(&secret.protected_entry_id)?
        .ok_or(LocalCredentialError::WorkloadSecretMaterialMissing)?;
    validate_secret_value(value.expose_secret())?;
    Ok(Zeroizing::new(value.expose_secret().to_vec()))
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
    winners: BTreeMap<String, Winner>,
}

/// The set a winning secret is stored in, which names its slot.
#[derive(Clone, Copy)]
enum WinnerSet {
    /// The owner's personal secrets: kind `local`.
    User,
    Project(Uuid),
}

struct Winner {
    set: WinnerSet,
    secret: InternalWorkloadSecret,
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
            WinnerSet::Project(*id),
            WorkloadSecretSource::Project,
            format!("local:project:{id}"),
        ));
    }
    if selection.user {
        scopes.push((
            SecretScope::User,
            WinnerSet::User,
            WorkloadSecretSource::User,
            "local:user".into(),
        ));
    }
    let mut capture = LocalSourceCapture {
        inventories: Vec::with_capacity(scopes.len()),
        winners: BTreeMap::new(),
    };
    for (scope, set, source, source_identity) in scopes {
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
            capture.winners.insert(key.clone(), Winner { set, secret });
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
