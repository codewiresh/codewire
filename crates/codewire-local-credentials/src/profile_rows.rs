//! Profile rows: one revision written, and a profile or one of its revisions
//! read with its entries.

use super::*;

pub(crate) fn insert_profile_revision(
    transaction: &rusqlite::Transaction<'_>,
    profile: &AccessProfile,
    now: u64,
) -> Result<(), LocalCredentialError> {
    transaction
        .execute(
            "INSERT INTO profile_revisions(profile_id, revision, created_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            params![
                profile.id.as_str(),
                i64::try_from(profile.revision)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    for (slot, credential_id) in &profile.entries {
        transaction
            .execute(
                "INSERT INTO profile_entries(profile_id, revision, capability_slot, credential_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    profile.id.as_str(),
                    i64::try_from(profile.revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    slot.as_str(),
                    credential_id.as_str()
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

pub(crate) fn load_profile(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<AccessProfileRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT owner_id, name, current_revision, created_at_unix_ms, updated_at_unix_ms
             FROM profiles WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::ProfileNotFound)?;
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let revision = u64::try_from(raw.2).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let entries = load_profile_entries(connection, id, revision)?;
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRecord {
        is_default: profile_is_default(connection, id)?,
        profile,
        created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        updated_at_unix_ms: u64::try_from(raw.4)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

pub(crate) fn profile_is_default(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM default_profiles WHERE profile_id = ?1)",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

pub(crate) fn profile_exists(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = ?1)",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

pub(crate) fn load_profile_revision(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<AccessProfileRevisionRecord, LocalCredentialError> {
    if revision == 0 {
        return Err(LocalCredentialError::ProfileRevisionNotFound);
    }
    let raw = connection
        .query_row(
            "SELECT p.owner_id, p.name, p.created_at_unix_ms, r.created_at_unix_ms
             FROM profiles p
             JOIN profile_revisions r ON r.profile_id = p.id
             WHERE p.id = ?1 AND r.revision = ?2",
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some(raw) = raw else {
        return if profile_exists(connection, id)? {
            Err(LocalCredentialError::ProfileRevisionNotFound)
        } else {
            Err(LocalCredentialError::ProfileNotFound)
        };
    };
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries: load_profile_entries(connection, id, revision)?,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRevisionRecord {
        is_default: profile_is_default(connection, id)?,
        profile,
        profile_created_at_unix_ms: u64::try_from(raw.2)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision_created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

fn load_profile_entries(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT capability_slot, credential_id FROM profile_entries
             WHERE profile_id = ?1 AND revision = ?2 ORDER BY capability_slot",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map(
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(database_error)?;
    let mut entries = BTreeMap::new();
    for row in rows {
        let (slot, credential_id) = row.map_err(database_error)?;
        let slot =
            CapabilitySlot::parse(slot).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let credential_id = CredentialId::parse(credential_id)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        if entries.insert(slot, credential_id).is_some() {
            return Err(LocalCredentialError::CorruptMetadata);
        }
    }
    Ok(entries)
}
