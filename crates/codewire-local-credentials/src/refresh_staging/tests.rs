use codewire_protected_store::ProtectedStorePersistence;

use super::testing::{RefreshedLease, refresh_through};
use super::*;
use crate::BrokerLeaseChannelError;
use crate::tests::TestProtectedStore;

/// A child's store as #5294 opens it: reads pass through, `put` and `delete`
/// refuse, and the one write is a started refresh's, when this store can
/// stage at all.
#[derive(Clone)]
struct ReadOnlyChild {
    inner: TestProtectedStore,
    stages: bool,
}

impl ProtectedStore for ReadOnlyChild {
    fn persistence(&self) -> codewire_protected_store::ProtectedStorePersistence {
        self.inner.persistence()
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.inner.get(id)
    }

    fn put(&self, _: &ProtectedEntryId, _: &ProtectedValue) -> Result<(), ProtectedStoreError> {
        Err(ProtectedStoreError::AccessDenied)
    }

    fn delete(&self, _: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        Err(ProtectedStoreError::AccessDenied)
    }
}

impl RefreshStagingStore for ReadOnlyChild {
    fn can_stage_refresh(&self) -> bool {
        self.stages
    }

    fn stage_refresh(
        &self,
        write: RefreshStagingWrite,
        material: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        if !self.stages {
            return Err(ProtectedStoreError::AccessDenied);
        }
        write.stage(&self.inner, material)
    }
}

#[tokio::test]
async fn a_read_only_child_stages_its_started_refresh_and_the_authority_promotes_it() {
    let temp = tempfile::tempdir().unwrap();
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let child = ReadOnlyChild {
        inner: store.clone(),
        stages: true,
    };
    let refreshed = refresh_through(
        &temp.path().join("authority"),
        store.clone(),
        child,
        b"synthetic-rotated-oauth-bundle",
    )
    .await
    .unwrap();
    assert_eq!(
        refreshed,
        RefreshedLease {
            material_generation: 2,
            material: b"synthetic-rotated-oauth-bundle".to_vec(),
        }
    );
}

#[tokio::test]
async fn a_child_that_cannot_stage_refuses_the_refresh_before_start() {
    let temp = tempfile::tempdir().unwrap();
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let child = ReadOnlyChild {
        inner: store.clone(),
        stages: false,
    };
    assert_eq!(
        refresh_through(
            &temp.path().join("authority"),
            store.clone(),
            child,
            b"must-never-be-asked-for",
        )
        .await,
        Err(BrokerLeaseChannelError::StoreReadOnly)
    );
    // Only the enrolled generation exists: nothing was staged, and the
    // authority never recorded a Start (a lease after it still answers 1).
    assert_eq!(store.entry_count(), 1);
    assert_eq!(
        store.entry_values(),
        vec![b"synthetic-old-oauth-bundle".to_vec()]
    );
}
