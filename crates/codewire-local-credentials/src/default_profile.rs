//! The store's default profile (#4717): the profile a local `cw create` uses
//! when it names none, as a cloud account has one.

use super::*;

/// The store's default profile, as a cloud account has one (#4717): `cw
/// create` uses it when no profile is named, and it cannot be deleted. A store
/// upgraded from version 5 starts without one, so an upgrade never widens what
/// an unchanged `cw create --local` hands a VM (#4717).
pub(crate) const DEFAULT_PROFILE_SCHEMA: &str = "
    CREATE TABLE default_profiles(
      owner_id TEXT PRIMARY KEY NOT NULL,
      profile_id TEXT NOT NULL UNIQUE,
      FOREIGN KEY(profile_id) REFERENCES profiles(id)
    ) STRICT;";

/// Make `profile` the default when it is the owner's only profile, inside the
/// transaction that created it. The store's first profile becomes the
/// default, as in the cloud. A later profile never does, even in an upgraded
/// store with no default: that would widen what an unnamed `cw create
/// --local` gets (#4717).
pub(crate) fn make_first_profile_default(
    transaction: &rusqlite::Transaction<'_>,
    owner_id: &OwnerId,
    profile: &AccessProfileId,
) -> Result<(), LocalCredentialError> {
    transaction
        .execute(
            "INSERT INTO default_profiles(owner_id, profile_id)
             SELECT ?1, ?2
             WHERE NOT EXISTS (SELECT 1 FROM default_profiles WHERE owner_id = ?1)
               AND (SELECT COUNT(*) FROM profiles WHERE owner_id = ?1) = 1",
            params![owner_id.as_str(), profile.as_str()],
        )
        .map_err(database_error)?;
    Ok(())
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Make one profile the default, replacing the previous one. Setting the
    /// current default again changes nothing. There is no way to clear it.
    pub fn set_default_profile(
        &self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if !profile_exists(&transaction, id)? {
            return Err(LocalCredentialError::ProfileNotFound);
        }
        transaction
            .execute(
                "INSERT INTO default_profiles(owner_id, profile_id) VALUES (?1, ?2)
                 ON CONFLICT(owner_id) DO UPDATE SET profile_id = excluded.profile_id",
                params![self.owner_id.as_str(), id.as_str()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        load_profile(&connection, id)
    }

    /// The store's default profile: the store's first profile, or the one
    /// last set; none in an upgraded store until one is set.
    pub fn default_profile(&self) -> Result<Option<AccessProfileRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let id = connection
            .query_row(
                "SELECT profile_id FROM default_profiles WHERE owner_id = ?1",
                [self.owner_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?;
        id.map(|id| {
            let id =
                AccessProfileId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
            load_profile(&connection, &id)
        })
        .transpose()
    }
}

/// Version 5 to 6: the store's default profile. The table starts empty: an
/// upgraded store that has profiles has no default until the user sets one.
pub(crate) fn upgrade_default_profile_schema(
    connection: &Connection,
) -> Result<(), LocalCredentialError> {
    let transaction = crate::immediate(connection)?;
    transaction
        .execute_batch(DEFAULT_PROFILE_SCHEMA)
        .map_err(database_error)?;
    transaction
        .pragma_update(
            None,
            "user_version",
            DEFAULT_PROFILE_DATABASE_SCHEMA_VERSION,
        )
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}
