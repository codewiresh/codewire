//! Names-only precedence for one mixed-origin launch. This is consistency
//! metadata, not source authorization, a value snapshot, or a new generation.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::{
    MAX_WORKLOAD_SECRETS, ProjectionContext, ProjectionContributor, ProjectionError,
    WorkloadSecretSource, resolve_workload_secret_metadata, validate_projection_recipient,
    validate_workload_secret_key,
};

/// One already-selected source's complete bounded inventory. The source ID is
/// its exact authority-owned scope ID/path, never a display-name lookup.
/// Each producer must recapture its own sources under its existing lock before
/// reading material; a caller-supplied inventory alone grants no access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionSourceInventory {
    pub contributor: ProjectionContributor,
    pub source: WorkloadSecretSource,
    pub source_identity: String,
    pub keys: BTreeSet<String>,
}

/// Derived once from complete inventories, and recomputed by each producer
/// before sealing. Only the existing receiving launcher may combine values.
#[derive(Debug, PartialEq, Eq)]
pub struct ProjectionCompositionPlan {
    digest: [u8; 32],
    context: ProjectionContext,
    recipient: [u8; 32],
    local_keys: BTreeSet<String>,
    platform_keys: BTreeSet<String>,
}

impl ProjectionCompositionPlan {
    /// Inventories are ordered Organization, Project, User, with at most one
    /// exact source per rank. Both contributors remain required even when all
    /// of one contributor's keys lose precedence or its selected source is empty.
    pub fn new(
        context: &ProjectionContext,
        request_id: [u8; 16],
        recipient: [u8; 32],
        inventories: &[ProjectionSourceInventory],
        ordinary_keys: &BTreeSet<String>,
        reserved_keys: &BTreeSet<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ProjectionError> {
        context.validate_at(now_unix_ms)?;
        validate_projection_recipient(recipient)?;
        if request_id == [0; 16]
            || inventories.is_empty()
            || inventories.len() > 3
            || ordinary_keys.len() > MAX_WORKLOAD_SECRETS
            || reserved_keys.len() > MAX_WORKLOAD_SECRETS
            || !ordinary_keys.is_disjoint(reserved_keys)
        {
            return Err(ProjectionError::InvalidValues);
        }
        for name in ordinary_keys.iter().chain(reserved_keys) {
            validate_workload_secret_key(name).map_err(|_| ProjectionError::InvalidValues)?;
        }
        let mut previous = None;
        let mut owners = BTreeMap::new();
        let mut contributors = BTreeSet::new();
        let mut names = Vec::new();
        for inventory in inventories {
            if previous.is_some_and(|source| source >= inventory.source)
                || inventory.source == WorkloadSecretSource::ExplicitEnvironment
                || (inventory.source == WorkloadSecretSource::Organization
                    && inventory.contributor != ProjectionContributor::Platform)
                || inventory.source_identity.is_empty()
                || inventory.source_identity.len() > 512
                || inventory.source_identity.trim() != inventory.source_identity
                || inventory.source_identity.chars().any(char::is_control)
                || inventory.keys.len() > MAX_WORKLOAD_SECRETS
                || !inventory.keys.is_disjoint(reserved_keys)
            {
                return Err(ProjectionError::InvalidValues);
            }
            previous = Some(inventory.source);
            owners.insert(inventory.source, inventory.contributor);
            contributors.insert(inventory.contributor);
            names.extend(
                inventory
                    .keys
                    .iter()
                    .map(|key| (inventory.source, key.as_str())),
            );
        }
        if contributors
            != BTreeSet::from([
                ProjectionContributor::Local,
                ProjectionContributor::Platform,
            ])
        {
            return Err(ProjectionError::InvalidValues);
        }
        names.extend(
            ordinary_keys
                .iter()
                .map(|key| (WorkloadSecretSource::ExplicitEnvironment, key.as_str())),
        );
        let winners =
            resolve_workload_secret_metadata(names).map_err(|_| ProjectionError::InvalidValues)?;
        let mut local_keys = BTreeSet::new();
        let mut platform_keys = BTreeSet::new();
        for winner in winners {
            if winner.source == WorkloadSecretSource::ExplicitEnvironment {
                continue;
            }
            match owners
                .get(&winner.source)
                .ok_or(ProjectionError::InvalidValues)?
            {
                ProjectionContributor::Local => {
                    local_keys.insert(winner.key);
                }
                ProjectionContributor::Platform => {
                    platform_keys.insert(winner.key);
                }
            }
        }

        let mut hash = Sha256::new();
        hash.update(b"codewire/mixed-environment-projection-plan/v1\0");
        hash.update(request_id);
        hash.update(context.environment_id);
        hash.update(context.operation_generation.to_be_bytes());
        hash.update(context.selection_sha256);
        hash.update(context.deadline_unix_ms.to_be_bytes());
        hash.update(recipient);
        hash.update([inventories.len() as u8]);
        for inventory in inventories {
            hash.update([match inventory.contributor {
                ProjectionContributor::Local => 0,
                ProjectionContributor::Platform => 1,
            }]);
            hash.update([match inventory.source {
                WorkloadSecretSource::Organization => 0,
                WorkloadSecretSource::Project => 1,
                WorkloadSecretSource::User => 2,
                WorkloadSecretSource::ExplicitEnvironment => {
                    return Err(ProjectionError::InvalidValues);
                }
            }]);
            field(&mut hash, inventory.source_identity.as_bytes());
            hash_names(&mut hash, &inventory.keys);
        }
        hash_names(&mut hash, ordinary_keys);
        hash_names(&mut hash, reserved_keys);
        // Bind derived winners explicitly too. They cannot be a caller-selected
        // subset that silently discards another selected source's higher rank.
        hash_names(&mut hash, &local_keys);
        hash_names(&mut hash, &platform_keys);
        Ok(Self {
            digest: hash.finalize().into(),
            context: context.clone(),
            recipient,
            local_keys,
            platform_keys,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn winning_keys(&self, contributor: ProjectionContributor) -> &BTreeSet<String> {
        match contributor {
            ProjectionContributor::Local => &self.local_keys,
            ProjectionContributor::Platform => &self.platform_keys,
        }
    }

    pub fn winning_keys_digest(&self) -> [u8; 32] {
        composition_winning_keys_digest(&self.local_keys, &self.platform_keys)
    }

    pub(crate) fn validate_context(
        &self,
        context: &ProjectionContext,
        recipient: [u8; 32],
    ) -> Result<(), ProjectionError> {
        if &self.context == context && self.recipient == recipient {
            Ok(())
        } else {
            Err(ProjectionError::InvalidContext)
        }
    }
}

pub(crate) fn composition_winning_keys_digest(
    local: &BTreeSet<String>,
    platform: &BTreeSet<String>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"codewire/mixed-environment-projection-winners/v1\0");
    hash_names(&mut hash, local);
    hash_names(&mut hash, platform);
    hash.finalize().into()
}

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}

fn hash_names(hash: &mut Sha256, names: &BTreeSet<String>) {
    hash.update((names.len() as u32).to_be_bytes());
    for name in names {
        field(hash, name.as_bytes());
    }
}

#[cfg(test)]
mod tests;
