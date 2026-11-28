//! Writing a local secret together with its binding (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound application secrets").
//! The rules are the platform store's: a new value keeps the binding, the
//! changes that could send the value somewhere new need it entered again,
//! and the binding's generation moves with everything but its hosts. A
//! local store has no deployment, so it reserves the provider hosts only.

pub use codewire_access::BindingWrite;
use codewire_access::{
    HostBinding, ReservedHosts, StoredBinding, change_moves_generation, change_needs_value,
};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use rusqlite::params;
use uuid::Uuid;

use super::{
    InternalWorkloadSecret, SecretScope, load_secret_by_id, load_secret_by_key, require_project,
    set_secret, to_i64, validate_secret_key, validate_secret_value,
};
use crate::material::MaterialStore;
use crate::{
    LocalCredentialAuthority, LocalCredentialError, WorkloadSecretMetadata, database_error,
    unix_millis,
};

/// The binding columns a write leaves the row with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WrittenBinding {
    binding: Option<StoredBinding>,
    binding_id: Option<Uuid>,
    pub(super) generation: u64,
}

impl WrittenBinding {
    pub(super) fn json(&self) -> Result<Option<String>, LocalCredentialError> {
        self.binding
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| LocalCredentialError::CorruptMetadata)
    }

    pub(super) fn id(&self) -> Option<String> {
        self.binding_id.map(|id| id.to_string())
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Set a personal secret's value, or with `None` only change its
    /// binding, and apply `binding`. A bind is refused unless `host_bound`
    /// ([`codewire_access::HOST_BOUND_SECRETS`]).
    pub fn write_user_workload_secret(
        &self,
        key: &str,
        value: Option<ProtectedValue>,
        binding: BindingWrite,
        host_bound: bool,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let write = SecretWrite::checked(key, value, binding, host_bound)?;
        self.with_secret_material(|material| write.apply(material, SecretScope::User))
    }

    /// [`Self::write_user_workload_secret`] for a project's secret.
    pub fn write_project_workload_secret(
        &self,
        project_id: Uuid,
        key: &str,
        value: Option<ProtectedValue>,
        binding: BindingWrite,
        host_bound: bool,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let write = SecretWrite::checked(key, value, binding, host_bound)?;
        self.with_secret_material(|material| {
            require_project(material.connection(), &project_id)?;
            write.apply(material, SecretScope::Project(&project_id))
        })
    }
}

/// One write, its key and value checked before the store is touched.
struct SecretWrite<'a> {
    key: &'a str,
    value: Option<ProtectedValue>,
    binding: BindingWrite,
}

impl<'a> SecretWrite<'a> {
    fn checked(
        key: &'a str,
        value: Option<ProtectedValue>,
        binding: BindingWrite,
        host_bound: bool,
    ) -> Result<Self, LocalCredentialError> {
        validate_secret_key(key)?;
        if let Some(value) = &value {
            validate_secret_value(value.expose_secret())?;
        }
        if !host_bound && matches!(binding, BindingWrite::Bind(_)) {
            return Err(LocalCredentialError::HostBoundSecretsUnavailable);
        }
        Ok(Self {
            key,
            value,
            binding,
        })
    }

    fn apply<S: ProtectedStore>(
        self,
        material: &MaterialStore<'_, S>,
        scope: SecretScope<'_>,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let connection = material.connection();
        let current = load_secret_by_key(connection, scope, self.key)?;
        let written = plan(
            current.as_ref(),
            self.value.as_ref().map(ProtectedValue::expose_secret),
            &self.binding,
        )?;
        match (self.value, current) {
            (Some(value), _) => set_secret(material, scope, self.key, value, &written),
            (None, Some(current)) => rebind(connection, &current, &written),
            // `plan` needs a value for a secret that isn't there.
            (None, None) => Err(LocalCredentialError::InvalidWorkloadSecret),
        }
    }
}

/// The binding columns `write` leaves, or why it is refused: the platform
/// store's rules (`write_secret_at_path`).
fn plan(
    current: Option<&InternalWorkloadSecret>,
    value: Option<&[u8]>,
    write: &BindingWrite,
) -> Result<WrittenBinding, LocalCredentialError> {
    // Read back under no reserved names but the provider hosts, as every
    // local binding is checked.
    let reserved = ReservedHosts::default();
    let stored_before = current.and_then(|current| current.metadata.binding.as_ref());
    let before = stored_before
        .map(|stored| stored.parse(&reserved))
        .transpose()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let (after, preset) = match write {
        BindingWrite::Keep => (
            before.clone(),
            stored_before.and_then(|stored| stored.preset.clone()),
        ),
        BindingWrite::Bind(stored) => (Some(stored.parse(&reserved)?), stored.preset.clone()),
        BindingWrite::Plain => (None, None),
    };
    match value {
        Some(value) => {
            if let Some(after) = &after {
                after.validate_value(value)?;
            }
        }
        None => {
            if before.is_none() && after.is_none() {
                return Err(LocalCredentialError::InvalidWorkloadSecret);
            }
            if before.is_none() || change_needs_value(before.as_ref(), after.as_ref()) {
                return Err(LocalCredentialError::SecretValueRequired(change_words(
                    before.as_ref(),
                    after.as_ref(),
                )));
            }
        }
    }
    let generation = current.map_or(0, |current| current.metadata.binding_generation);
    Ok(WrittenBinding {
        binding_id: match (&after, current.and_then(|current| current.binding_id)) {
            (Some(_), None) => Some(Uuid::new_v4()),
            (_, kept) => kept,
        },
        generation: if change_moves_generation(before.as_ref(), after.as_ref()) {
            generation
                .checked_add(1)
                .ok_or(LocalCredentialError::CorruptMetadata)?
        } else {
            generation
        },
        binding: after.as_ref().map(|after| StoredBinding {
            preset,
            ..StoredBinding::from(after)
        }),
    })
}

/// The change, in the words of [`LocalCredentialError::SecretValueRequired`].
fn change_words(before: Option<&HostBinding>, after: Option<&HostBinding>) -> &'static str {
    match (before, after) {
        (None, Some(_)) => "binding a secret to hosts",
        (Some(_), None) => "making a secret plain",
        (Some(before), Some(after)) if before.presentation() != after.presentation() => {
            "changing how a secret is sent"
        }
        _ => "adding a host",
    }
}

/// A change to the binding alone, which keeps the value.
fn rebind(
    connection: &rusqlite::Connection,
    current: &InternalWorkloadSecret,
    written: &WrittenBinding,
) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
    let transaction = crate::immediate(connection)?;
    let changed = transaction
        .execute(
            "UPDATE workload_secrets
             SET binding = ?2, binding_id = ?3, binding_generation = ?4, updated_at_unix_ms = ?5
             WHERE id = ?1 AND material_state = 'ready' AND binding_generation = ?6",
            params![
                current.id.to_string(),
                written.json()?,
                written.id(),
                to_i64(written.generation)?,
                to_i64(unix_millis()?)?,
                to_i64(current.metadata.binding_generation)?,
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::WorkloadSecretNotFound);
    }
    transaction.commit().map_err(database_error)?;
    Ok(load_secret_by_id(connection, current.id)?.metadata)
}

#[cfg(test)]
mod tests;
