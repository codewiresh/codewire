//! Each environment binding's credential placeholders (#3999).
//!
//! A placeholder is derived, never stored: [`CredentialPlaceholder::derive`]
//! under one 32-byte key the authority keeps as an entry of its protected
//! store, beside credential material and never in its metadata database.
//! Every binding's placeholders are the same after the authority restarts,
//! and nothing an environment can read is an input to the key. They follow
//! the binding's profile revision, not the VM generation, so a VM checkpoint
//! restored in place keeps them (see `codewire_access`'s placeholder docs).
//!
//! The key belongs to one authority root. Its entry is named by the root's
//! ID, a random value the root's metadata keeps, because an operating-system
//! store (Secret Service, the login Keychain) is shared by every authority
//! root of the OS user, such as another HOME's or another credential root's:
//! each root creates, reads and moves only its own key. The ID is not a
//! secret and is never an input to a placeholder.
//!
//! [`LocalCredentialAuthority::environment_credential_placeholder`] creates
//! the key on its first use, and this authority process keeps it once
//! loaded. A lease never reads or writes the store for it: a lease derives
//! its placeholder from a key already loaded, and one admitted before that,
//! or while the key cannot be loaded, carries none and is otherwise the
//! same. The broker's swap rule compares a front-door request's placeholder
//! with its lease's (#4722); a placeholder never decides whether a lease is
//! admitted.
//!
//! A key that is lost, or replaced because its entry is corrupt, changes
//! every placeholder the root derives, for every binding. That is safe:
//! a placeholder only names a credential to the broker that compares it, so
//! a stale one matches nothing and fails closed.

use std::sync::{Mutex, OnceLock, PoisonError};

use codewire_access::{
    CapabilitySlot, CredentialId, CredentialPlaceholder, DerivedGrant, EnvironmentAccessBinding,
    EnvironmentId, PLACEHOLDER_KEY_BYTES, PlaceholderKey,
};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedValue,
};
use rand::RngCore as _;
use rusqlite::{Connection, OptionalExtension as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::control::v1;
use crate::{
    CredentialOperationAdmission, CredentialOperationLease, CredentialOperationLeaseRequest,
    LocalCredentialAuthority, LocalCredentialError, MaterialState,
    check_selected_environment_binding, database_error, deny_generic_ssh_lease,
    load_internal_credential,
};

/// The `authority_metadata` row that holds this root's ID: 32 lowercase hex
/// characters, created the first time the root needs its key.
const AUTHORITY_ID_KEY: &str = "authority_id";
const AUTHORITY_ID_LENGTH: usize = 32;

/// The authority's placeholder key once this process has loaded it. Leases
/// read only `loaded`; `loading` serializes reading and creating the entry,
/// so two first uses create one key.
#[derive(Default)]
pub(crate) struct PlaceholderKeySlot {
    loaded: OnceLock<PlaceholderKey>,
    loading: Mutex<()>,
}

/// The protected-store entry of this root's placeholder key, or none while
/// the root has no ID, and so has never had a key.
pub(crate) fn recorded_placeholder_key_entry(
    connection: &Connection,
) -> Result<Option<ProtectedEntryId>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT value FROM authority_metadata WHERE key = ?1",
            [AUTHORITY_ID_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|authority_id| placeholder_key_entry_for(&authority_id))
        .transpose()
}

/// This root's key entry, giving the root its ID first if it has none. The
/// caller holds the database, and the authority lock keeps every other
/// process off this root, so a root only ever gets one ID.
fn placeholder_key_entry(
    connection: &Connection,
) -> Result<ProtectedEntryId, LocalCredentialError> {
    if let Some(entry) = recorded_placeholder_key_entry(connection)? {
        return Ok(entry);
    }
    let authority_id = Uuid::new_v4().simple().to_string();
    connection
        .execute(
            "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)",
            [AUTHORITY_ID_KEY, authority_id.as_str()],
        )
        .map_err(database_error)?;
    placeholder_key_entry_for(&authority_id)
}

fn placeholder_key_entry_for(authority_id: &str) -> Result<ProtectedEntryId, LocalCredentialError> {
    if authority_id.len() != AUTHORITY_ID_LENGTH
        || !authority_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    ProtectedEntryId::parse(format!("local/authority/{authority_id}/placeholder-key-v1"))
        .map_err(|_| LocalCredentialError::CorruptMetadata)
}

/// The derivation's revision input for `grant`: its binding's profile
/// revision, or zero for a grant no profile selects. Never the VM
/// generation, so a VM checkpoint restored in place keeps its placeholders.
fn binding_revision(grant: &DerivedGrant) -> u64 {
    grant.profile.as_ref().map_or(0, |profile| profile.revision)
}

/// A lease's admission and the placeholder it carries, when there is one.
type LeaseAdmission = (CredentialOperationAdmission, Option<CredentialPlaceholder>);

impl CredentialOperationLease {
    /// This environment generation's placeholder for the leased credential,
    /// or none when the admitting authority had not loaded its placeholder
    /// key, or predates placeholders.
    pub fn placeholder(&self) -> Option<&CredentialPlaceholder> {
        self.placeholder.as_ref()
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// The placeholder an environment generation's leases of `credential_id`
    /// in `slot` carry, without leasing anything, for any generation.
    ///
    /// It applies each check of the generation's broker channel lease that
    /// does not need the lease's operation and route, through the same
    /// admission code, in the same order and with a lease's errors:
    /// `selected` is the binding the generation was started with (`None` when
    /// it has none) and must still be the environment's binding; that binding
    /// must derive a grant for `slot`, here one that selects exactly
    /// `credential_id`; the credential must be usable now; and an SSH key is
    /// refused, as every lease refuses one. Two lease checks need the
    /// operation and do not apply: that the grant permits it, and that a
    /// Codex login lease is for the owner's own sign-in.
    ///
    /// Loads the placeholder key, creating it on first use, and fails with
    /// the store's error when it cannot. That can wait on the protected store
    /// (an unlock, a slow keyring), so call it on a blocking thread.
    pub fn environment_credential_placeholder(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
        credential_id: &CredentialId,
        selected: Option<&EnvironmentAccessBinding>,
    ) -> Result<CredentialPlaceholder, LocalCredentialError> {
        let (entry, revision) = {
            let connection = self.connection()?;
            check_selected_environment_binding(&connection, environment_id, selected)?;
            let (grant, record) = self.admit_environment_slot_at(
                &connection,
                environment_id,
                environment_generation,
                slot,
                None,
            )?;
            deny_generic_ssh_lease(&record.public.metadata)?;
            if grant.credential_id != *credential_id {
                return Err(LocalCredentialError::CredentialOperationLeaseDenied);
            }
            (
                placeholder_key_entry(&connection)?,
                binding_revision(&grant),
            )
        };
        // The database is released first: loading may wait on the store, and
        // a lease needs the database but never the store for its placeholder.
        let key = self.load_placeholder_key(&entry)?;
        Ok(CredentialPlaceholder::derive(
            key,
            environment_id,
            revision,
            slot,
            credential_id,
        ))
    }

    /// This environment's placeholders for each of `slots` its `selected`
    /// binding grants at `environment_generation`, in `slots` order: what a
    /// boot that intercepts its agent hosts puts in its seed (#3999). Each
    /// goes through [`Self::environment_credential_placeholder`], so it is
    /// exactly what that generation's leases carry. A slot whose credential's
    /// lifecycle withholds it gets [`Self::withheld_slot_placeholder`]'s;
    /// any other slot without a grant has none. Call it on a blocking thread.
    pub fn environment_slot_placeholders(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        selected: &EnvironmentAccessBinding,
        slots: &[CapabilitySlot],
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, LocalCredentialError> {
        // The binding is checked first, whatever the slots: a stale binding
        // or an empty request is refused, never answered with no values.
        let grants = self.evaluate_selected_environment_grants(
            environment_id,
            environment_generation,
            Some(selected),
        )?;
        let mut placeholders = Vec::new();
        for slot in slots {
            let Some(grant) = grants.iter().find(|grant| grant.capability_slot == *slot) else {
                if let Some(placeholder) = self.withheld_slot_placeholder(
                    environment_id,
                    environment_generation,
                    slot,
                    selected,
                )? {
                    placeholders.push((slot.clone(), placeholder));
                }
                continue;
            };
            let placeholder = self.environment_credential_placeholder(
                environment_id,
                environment_generation,
                slot,
                &grant.credential_id,
                Some(selected),
            )?;
            placeholders.push((slot.clone(), placeholder));
        }
        Ok(placeholders)
    }

    /// The placeholder `slot`'s leases carry once its withheld credential
    /// (revoked, expired or needing reconnect) is reconnected in place, or
    /// `None` when nothing withholds the slot (#6600). A boot that starts
    /// while it is withheld needs it in its seed; its leases stay refused
    /// with the reason until the reconnect. Not an admission: it reads no
    /// material and refuses an SSH key as a lease does, and
    /// [`Self::environment_credential_placeholder`] stays for granted slots.
    fn withheld_slot_placeholder(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
        selected: &EnvironmentAccessBinding,
    ) -> Result<Option<CredentialPlaceholder>, LocalCredentialError> {
        let (entry, credential_id) = {
            let connection = self.connection()?;
            check_selected_environment_binding(&connection, environment_id, Some(selected))?;
            let Some(withheld) = self.withheld_environment_slot_at(
                &connection,
                environment_id,
                environment_generation,
                slot,
            )?
            else {
                return Ok(None);
            };
            let record = load_internal_credential(
                &connection,
                &withheld.credential,
                Some(MaterialState::Ready),
            )?;
            deny_generic_ssh_lease(&record.public.metadata)?;
            (placeholder_key_entry(&connection)?, withheld.credential)
        };
        let key = self.load_placeholder_key(&entry)?;
        Ok(Some(CredentialPlaceholder::derive(
            key,
            environment_id,
            selected.profile_revision,
            slot,
            &credential_id,
        )))
    }

    /// Load this root's placeholder key now, creating it on first use, so
    /// that every lease admitted from here on carries its placeholder
    /// (#3999). The broker of a boot that intercepts its agent hosts needs
    /// that from its first lease, and nothing else is sure to load the key:
    /// a sign-in's placeholder travels in its login, so its boot asks
    /// [`Self::environment_slot_placeholders`] for none, and after this
    /// authority restarts no boot has asked yet. Fails with the store's error
    /// when the key cannot be loaded. Call it on a blocking thread.
    pub(crate) fn load_root_placeholder_key(&self) -> Result<(), LocalCredentialError> {
        // The database is released before loading, as for a placeholder.
        let entry = {
            let connection = self.connection()?;
            placeholder_key_entry(&connection)?
        };
        self.load_placeholder_key(&entry).map(drop)
    }

    /// [`Self::admit_environment_credential_operation`] and the admitted
    /// credential's placeholder, which the lease carries when there is one.
    pub(crate) fn admit_environment_credential_lease(
        &self,
        request: &CredentialOperationLeaseRequest,
    ) -> Result<LeaseAdmission, LocalCredentialError> {
        let admission = self.admit_environment_credential_operation(request)?;
        let placeholder = self.loaded_placeholder(request, &admission);
        Ok((admission, placeholder))
    }

    /// [`Self::admit_selected_environment_credential_operation`] and the
    /// admitted credential's placeholder, which the lease carries when there
    /// is one.
    pub(crate) fn admit_selected_environment_credential_lease(
        &self,
        request: &CredentialOperationLeaseRequest,
        expected: Option<&EnvironmentAccessBinding>,
    ) -> Result<LeaseAdmission, LocalCredentialError> {
        let admission = self.admit_selected_environment_credential_operation(request, expected)?;
        let placeholder = self.loaded_placeholder(request, &admission);
        Ok((admission, placeholder))
    }

    /// The admitted credential's placeholder from a key already loaded: no
    /// store access and no failure, so it cannot fail or delay the lease.
    fn loaded_placeholder(
        &self,
        request: &CredentialOperationLeaseRequest,
        admission: &CredentialOperationAdmission,
    ) -> Option<CredentialPlaceholder> {
        self.placeholder_key.loaded.get().map(|key| {
            CredentialPlaceholder::derive(
                key,
                &request.environment_id,
                binding_revision(&admission.grant),
                &request.capability_slot,
                &admission.grant.credential_id,
            )
        })
    }

    /// The placeholder key, read from `entry` or created there on first use,
    /// then kept for this process. A failure keeps nothing, so the next call
    /// tries again.
    fn load_placeholder_key(
        &self,
        entry: &ProtectedEntryId,
    ) -> Result<&PlaceholderKey, LocalCredentialError> {
        let slot = &self.placeholder_key;
        if let Some(key) = slot.loaded.get() {
            return Ok(key);
        }
        // Holds no data, so a panic elsewhere leaves nothing inconsistent.
        let _loading = slot.loading.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(key) = slot.loaded.get() {
            return Ok(key);
        }
        let key = read_or_create_placeholder_key(&self.protected_store, entry)?;
        Ok(slot.loaded.get_or_init(|| key))
    }
}

/// The stored key, or a new random one written to the store and read back,
/// so the key used is always the one every later start loads. A corrupt
/// entry, of the wrong length or reported corrupt by the store, is replaced
/// like an absent one: otherwise every later call would fail.
fn read_or_create_placeholder_key(
    store: &impl ProtectedStore,
    entry: &ProtectedEntryId,
) -> Result<PlaceholderKey, LocalCredentialError> {
    let stored = match store.get(entry) {
        Ok(stored) => stored,
        Err(ProtectedStoreError::CorruptEntry) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(key) = stored.and_then(|value| stored_placeholder_key(&value).ok()) {
        return Ok(key);
    }
    let mut bytes = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| ProtectedStoreError::Unavailable)?;
    store.put(entry, &ProtectedValue::from_slice(&*bytes)?)?;
    let stored = store.get(entry)?.ok_or(ProtectedStoreError::Unavailable)?;
    stored_placeholder_key(&stored)
}

fn stored_placeholder_key(value: &ProtectedValue) -> Result<PlaceholderKey, LocalCredentialError> {
    PlaceholderKey::from_slice(value.expose_secret())
        .map_err(|_| ProtectedStoreError::CorruptEntry.into())
}

/// A lease response's placeholder, or none. An authority with none sends an
/// empty one, which is also how a response from an authority that predates
/// placeholders decodes; any other value that is not a `cwp1_` placeholder,
/// a later version's for example, is none too, because a placeholder never
/// fails a lease.
pub(crate) fn lease_response_placeholder(
    response: &v1::BrokerLeaseResponse,
) -> Option<CredentialPlaceholder> {
    CredentialPlaceholder::parse(&response.placeholder).ok()
}

/// How long an intercepting boot's ensure waits for the placeholder key: the
/// protected store may wait on an unlock or a slow keyring, and this stays
/// well inside the 90 s a renewal's successor has to start.
const PLACEHOLDER_KEY_LOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Load the authority's placeholder key for a boot that has `boot_secrets`,
/// which only a boot that intercepts its agent hosts has: its broker's leases
/// carry placeholders only from a key this process has loaded (#3999). The
/// ensure calls it before its entries lock, so a slow store holds no other
/// environment's ensure. Past [`PLACEHOLDER_KEY_LOAD_TIMEOUT`] the ensure
/// fails with a named reason, and so does the start, rather than hanging; the
/// load goes on in its thread, and a later ensure finds the key loaded.
pub(crate) async fn load_key_for_boot<S: ProtectedStore + 'static>(
    authority: &std::sync::Arc<LocalCredentialAuthority<S>>,
    boot_secrets: &crate::BrokerBootSecrets,
) -> Result<(), tonic::Status> {
    if boot_secrets.is_empty() {
        return Ok(());
    }
    let authority = std::sync::Arc::clone(authority);
    tokio::time::timeout(
        PLACEHOLDER_KEY_LOAD_TIMEOUT,
        crate::service::run_blocking(move || authority.load_root_placeholder_key()),
    )
    .await
    .map_err(|_| {
        tonic::Status::deadline_exceeded("the placeholder key could not be loaded in time")
    })?
}

#[cfg(test)]
mod tests;
