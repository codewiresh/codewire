//! A local VM's boot record of its bound secrets, and a front-door lease's
//! reread of one (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the
//! front door" and "The swap").
//!
//! The record is read from exactly the local sources the boot's projection
//! selects: each winner that is bound, by its set's path and key, with its
//! binding's identity, prefix and hosts, and never its value. The boot keeps
//! it for its life, and every lease is checked against it.
//!
//! A lease names a recorded secret by its path and key. It is refused unless
//! the channel's own record holds that secret and its own selection holds the
//! set, then rereads the row: a deleted secret, one plain now or of another
//! binding, and a host the binding or the record no longer names are each
//! refused by name. Its value is read only for a lease that passed.

use codewire_access::{
    EnvironmentId, EpochBoundSecret, FirstBindSecret, ReservedHosts, StoredBinding, local_user_path,
};
use codewire_protected_store::ProtectedStore;
use zeroize::Zeroizing;

use super::bound::set_path;
use super::{LocalLaunchSecretSelection, Winner, WinnerSet, capture_local_sources, read_value};
use crate::material::MaterialStore;
use crate::placeholder::authority_id;
use crate::workload_secret::{SecretScope, load_secret_by_key, snapshot};
use crate::{LocalCredentialAuthority, LocalCredentialError};

/// Why a bound secret's lease was refused by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundSecretLeaseRefusal {
    /// The binding no longer names the host, or the record never did.
    NotBoundToHost,
    /// Another `binding_id` or generation than the record's, or plain now.
    BindingChanged,
    Deleted,
}

/// A lease that passed: the secret's binding now, its value's version, and
/// the value when the lease asked for it.
pub struct BoundSecretLease {
    pub binding: StoredBinding,
    pub value_version: u64,
    pub value: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for BoundSecretLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundSecretLease")
            .field("binding", &self.binding)
            .field("value_version", &self.value_version)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// What a boot of `selection` records of its bound secrets: each winning
    /// key of its local sources (after the environment's own keys) that is
    /// bound, in key order. Nothing here reads a value.
    pub fn record_boot_bound_secrets(
        &self,
        selection: &LocalLaunchSecretSelection,
    ) -> Result<Vec<FirstBindSecret>, LocalCredentialError> {
        selection.validate()?;
        let connection = self.connection()?;
        let mut winners = snapshot(&connection, |connection| {
            capture_local_sources(connection, selection)
        })?
        .winners;
        winners.retain(|key, _| !selection.overridden_keys.contains(key));
        let mut record = Vec::new();
        for (key, Winner { set, secret }) in winners {
            let Some(binding) = &secret.metadata.binding else {
                continue;
            };
            let parsed = binding
                .parse(&ReservedHosts::default())
                .map_err(|_| LocalCredentialError::CorruptMetadata)?;
            let binding_id = secret
                .binding_id
                .ok_or(LocalCredentialError::CorruptMetadata)?;
            let mut hosts: Vec<String> = parsed
                .hosts()
                .map(|host| host.as_str().to_owned())
                .collect();
            hosts.sort();
            record.push(FirstBindSecret {
                path: set_path(&connection, set)?,
                key,
                binding_id: binding_id.to_string(),
                binding_generation: secret.metadata.binding_generation,
                prefix: parsed.prefix().map(|prefix| prefix.as_str().to_owned()),
                hosts,
            });
        }
        Ok(record)
    }

    /// A channel's grants: each secret its boot's `record` holds whose set
    /// `selection` selects and whose key the environment doesn't set itself,
    /// with the placeholder its record derives in `environment`, the one its
    /// projection carries. `None` when there are some and the
    /// application-secret key can't be loaded: no placeholder can then be
    /// told from another value.
    pub(crate) fn bound_secret_grants(
        &self,
        selection: &LocalLaunchSecretSelection,
        record: &[FirstBindSecret],
        environment: &EnvironmentId,
    ) -> Result<Option<Vec<EpochBoundSecret>>, LocalCredentialError> {
        selection.validate()?;
        let connection = self.connection()?;
        let mut selected = Vec::new();
        for secret in record {
            if !selection.overridden_keys.contains(&secret.key)
                && selected_set(&connection, selection, &secret.path).is_ok()
            {
                selected.push(secret.clone());
            }
        }
        if selected.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let Ok((_, key)) = self.application_secret_key(&connection) else {
            return Ok(None);
        };
        Ok(Some(
            selected
                .into_iter()
                .filter_map(|record| {
                    // A record that derives none had its projection refused
                    // by name for the same reason; it is never served.
                    let placeholder = record.placeholder(&key, environment)?;
                    Some(EpochBoundSecret {
                        record,
                        placeholder,
                    })
                })
                .collect(),
        ))
    }

    /// One lease of `recorded`, a secret the channel's boot recorded, for a
    /// request to `host`, under the channel's `selection`; with `value`, its
    /// value too. `Err` is a lease denied without a name: the record or the
    /// selection doesn't hold the secret, or the store failed.
    pub(crate) fn lease_bound_secret(
        &self,
        selection: &LocalLaunchSecretSelection,
        recorded: &FirstBindSecret,
        host: &str,
        value: bool,
    ) -> Result<Result<BoundSecretLease, BoundSecretLeaseRefusal>, LocalCredentialError> {
        selection.validate()?;
        if selection.overridden_keys.contains(&recorded.key) {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        let connection = if value {
            self.material_connection()?
        } else {
            self.connection()?
        };
        let set = selected_set(&connection, selection, &recorded.path)?;
        if !recorded.names(host) {
            return Ok(Err(BoundSecretLeaseRefusal::NotBoundToHost));
        }
        let scope = match &set {
            WinnerSet::User => SecretScope::User,
            WinnerSet::Project(project) => SecretScope::Project(project),
        };
        let Some(secret) = snapshot(&connection, |connection| {
            load_secret_by_key(connection, scope, &recorded.key)
        })?
        else {
            return Ok(Err(BoundSecretLeaseRefusal::Deleted));
        };
        let (Some(binding), Some(binding_id)) = (&secret.metadata.binding, secret.binding_id)
        else {
            return Ok(Err(BoundSecretLeaseRefusal::BindingChanged));
        };
        if binding_id.to_string() != recorded.binding_id
            || secret.metadata.binding_generation != recorded.binding_generation
        {
            return Ok(Err(BoundSecretLeaseRefusal::BindingChanged));
        }
        let parsed = binding
            .parse(&ReservedHosts::default())
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        if !parsed.names(host) {
            return Ok(Err(BoundSecretLeaseRefusal::NotBoundToHost));
        }
        let value = if value {
            let material = MaterialStore::new(&connection, &self.protected_store);
            Some(read_value(&material, &secret)?)
        } else {
            None
        };
        Ok(Ok(BoundSecretLease {
            binding: binding.clone(),
            value_version: secret.material_generation,
            value,
        }))
    }
}

/// The set `path` names, when `selection` selects it: the owner's personal
/// set under this authority's ID, or the selected local project.
fn selected_set(
    connection: &rusqlite::Connection,
    selection: &LocalLaunchSecretSelection,
    path: &str,
) -> Result<WinnerSet, LocalCredentialError> {
    if selection.user && path == local_user_path(&authority_id(connection)?) {
        return Ok(WinnerSet::User);
    }
    match selection.project_id {
        Some(project) if path == codewire_access::local_project_path(&project.to_string()) => {
            Ok(WinnerSet::Project(project))
        }
        _ => Err(LocalCredentialError::InvalidWorkloadSecret),
    }
}
