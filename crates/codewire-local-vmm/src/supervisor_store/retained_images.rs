//! The retained-image record's `supervisor_metadata` row (#4262). Since
//! schema 12 the table is read by key and keeps rows it does not know, so an
//! older supervisor of this schema ignores the row and leaves it in place;
//! the record needs no schema change. The supervisor decodes and bounds it
//! (`supervisor::retained_images`).

use super::*;

const RETAINED_IMAGES_KEY: &str = "retained_images";

impl SupervisorStore {
    pub(crate) fn retained_images(&self) -> Result<Option<String>, SupervisorStoreError> {
        metadata_value(&self.connection, RETAINED_IMAGES_KEY)
    }

    /// Replace the record, or remove its row with `None`.
    pub(crate) fn put_retained_images(
        &self,
        encoded: Option<&str>,
    ) -> Result<(), SupervisorStoreError> {
        self.writable()?;
        match encoded {
            None => {
                self.connection.execute(
                    "DELETE FROM supervisor_metadata WHERE key = ?1",
                    [RETAINED_IMAGES_KEY],
                )?;
            }
            Some(encoded) => {
                self.connection.execute(
                    "INSERT INTO supervisor_metadata(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![RETAINED_IMAGES_KEY, encoded],
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn test_root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        (parent, root)
    }

    #[test]
    fn the_record_survives_a_reopen_and_an_absent_row_reads_as_none() {
        let (_parent, root) = test_root();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        assert_eq!(store.retained_images().unwrap(), None);
        store.put_retained_images(Some("{\"images\":[]}")).unwrap();
        drop(store);

        let (store, _) = SupervisorStore::open(&root).unwrap();
        assert_eq!(
            store.retained_images().unwrap().as_deref(),
            Some("{\"images\":[]}")
        );
        store.put_retained_images(None).unwrap();
        assert_eq!(store.retained_images().unwrap(), None);
    }

    #[test]
    fn a_store_holding_the_row_still_opens_as_schema_12() {
        // What an older supervisor of this schema does with the row: it opens
        // the store, validates it and reads only the keys it knows.
        let (_parent, root) = test_root();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        store
            .put_retained_images(Some("not a record this binary knows"))
            .unwrap();
        drop(store);

        let (store, _) = SupervisorStore::open(&root).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, DATABASE_SCHEMA_VERSION);
        validate_schema(&store.connection).unwrap();
    }
}
