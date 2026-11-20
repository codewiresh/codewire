//! A profile's revision history: one revision, or a page of them (#4717).
//! Revisions are immutable, so a page is read in three statements under the owner's shared lock: the
//! current read that proves ownership, the page of revisions, and every
//! entry of that page at once.

use std::collections::BTreeMap;

use codewire_access::{AccessProfile, AccessProfileId, CapabilitySlot, CredentialId, Owner};

use super::{
    Error, PlatformAccessProfileStore, database_error, generation, load_default, load_profile,
    lock_owner, positive,
};

impl PlatformAccessProfileStore {
    /// Historical entries remain metadata-only references, even after an unbound
    /// retired credential is deleted. Runtime admission revalidates every entry.
    pub async fn get_revision(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfile, Error> {
        generation(revision)?;
        self.read_revision(owner, id, Some(revision)).await
    }

    /// One page of a profile's revisions, newest first, each with when it was
    /// made in Unix milliseconds, and whether the profile is the owner's
    /// default, read in one transaction. `before` continues a page: only
    /// revisions older than it. Another owner's profile is `NotFound`.
    pub async fn list_revisions(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        before: Option<u64>,
        limit: u32,
    ) -> Result<(Vec<(AccessProfile, i64)>, bool), Error> {
        if limit == 0 || limit > 1000 {
            return Err(Error::InvalidInput);
        }
        let before = before.map(generation).transpose()?;
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        // The current read proves the owner holds the profile and gives the
        // name, which is not part of a revision.
        let current = load_profile(&mut tx, owner, id, None, false).await?;
        let page: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT revision, (extract(epoch FROM created_at) * 1000)::bigint \
             FROM platform_access_profile_revisions \
             WHERE profile_id=$1 AND ($2::bigint IS NULL OR revision<$2) \
             ORDER BY revision DESC LIMIT $3",
        )
        .bind(id.as_str())
        .bind(before)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let numbers: Vec<i64> = page.iter().map(|(revision, _)| *revision).collect();
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT revision, capability_slot, credential_id \
             FROM platform_access_profile_entries \
             WHERE profile_id=$1 AND revision = ANY($2)",
        )
        .bind(id.as_str())
        .bind(&numbers)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut entries: BTreeMap<i64, BTreeMap<CapabilitySlot, CredentialId>> = BTreeMap::new();
        for (revision, slot, credential) in rows {
            entries.entry(revision).or_default().insert(
                CapabilitySlot::parse(slot).map_err(|_| Error::CorruptRecord)?,
                CredentialId::parse(credential).map_err(|_| Error::CorruptRecord)?,
            );
        }
        let revisions = page
            .into_iter()
            .map(|(revision, created_at_unix_ms)| {
                let profile = AccessProfile {
                    revision: positive(revision)?,
                    entries: entries.remove(&revision).unwrap_or_default(),
                    ..current.clone()
                };
                Ok((profile, created_at_unix_ms))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let is_default = load_default(&mut tx, owner, false).await?.as_ref() == Some(id);
        tx.commit().await.map_err(database_error)?;
        Ok((revisions, is_default))
    }
}
