//! Access profiles and environment bindings between the authority's records
//! and the wire.

use super::*;

/// Parse entries. Every profile includes the store's one GitHub connection, so
/// a legacy client's `github` entry is accepted and its credential ID discarded.
pub(super) fn profile_entries(
    entries: Vec<v1::AccessProfileEntry>,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, Status> {
    let mut parsed = BTreeMap::new();
    let mut github = false;
    for entry in entries {
        let slot = CapabilitySlot::parse(entry.capability_slot).map_err(status_for_access_error)?;
        let credential =
            CredentialId::parse(entry.credential_id).map_err(status_for_access_error)?;
        if slot == CapabilitySlot::github() {
            if std::mem::replace(&mut github, true) {
                return Err(Status::invalid_argument(
                    "duplicate access profile capability slot",
                ));
            }
            continue;
        }
        if parsed.insert(slot, credential).is_some() {
            return Err(Status::invalid_argument(
                "duplicate access profile capability slot",
            ));
        }
    }
    Ok(parsed)
}

pub(super) fn profile_record_to_proto(record: AccessProfileRecord) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.created_at_unix_ms,
        record.updated_at_unix_ms,
        record.is_default,
    )
}

pub(super) fn profile_revision_to_proto(
    record: AccessProfileRevisionRecord,
) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.profile_created_at_unix_ms,
        record.revision_created_at_unix_ms,
        record.is_default,
    )
}

fn profile_to_proto(
    profile: codewire_access::AccessProfile,
    profile_created_at_unix_ms: u64,
    revision_created_at_unix_ms: u64,
    is_default: bool,
) -> v1::AccessProfileRevision {
    v1::AccessProfileRevision {
        id: profile.id.to_string(),
        name: profile.name.to_string(),
        revision: profile.revision,
        entries: profile
            .entries
            .into_iter()
            .map(|(slot, credential)| v1::AccessProfileEntry {
                capability_slot: slot.to_string(),
                credential_id: credential.to_string(),
            })
            .collect(),
        profile_created_at_unix_ms,
        revision_created_at_unix_ms,
        is_default,
    }
}

pub(super) fn environment_binding_to_proto(
    record: EnvironmentAccessBindingRecord,
) -> v1::EnvironmentAccessBinding {
    v1::EnvironmentAccessBinding {
        environment_id: record.binding.environment_id.to_string(),
        profile_id: record.binding.profile_id.to_string(),
        profile_revision: record.binding.profile_revision,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
    }
}
