//! Hosted disk snapshots (#3046) through the canonical generated client.

use crate::*;

impl CodewireClient {
    pub async fn create_snapshot(
        &self,
        request: CreateSnapshotRequest,
    ) -> Result<CreateSnapshotResponse, ClientError> {
        self.snapshots
            .create_snapshot_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_snapshots(
        &self,
        request: ListSnapshotsRequest,
    ) -> Result<ListSnapshotsResponse, ClientError> {
        self.snapshots
            .list_snapshots_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_snapshot(
        &self,
        request: GetSnapshotRequest,
    ) -> Result<GetSnapshotResponse, ClientError> {
        self.snapshots
            .get_snapshot_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_snapshot(
        &self,
        request: DeleteSnapshotRequest,
    ) -> Result<DeleteSnapshotResponse, ClientError> {
        self.snapshots
            .delete_snapshot_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
