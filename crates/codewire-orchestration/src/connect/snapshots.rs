//! Connect-RPC adapter for hosted disk snapshots.

use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::{DateTime, Utc};
use codewire_proto::codewire::v1::{
    CreateSnapshotRequest, CreateSnapshotResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    GetSnapshotRequest, GetSnapshotResponse, ListSnapshotsRequest, ListSnapshotsResponse, Snapshot,
    SnapshotService, SnapshotState,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::snapshots::{
    SnapshotRow, create_snapshot_core, delete_snapshot_core, get_snapshot_core, list_snapshots_core,
};

pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(SnapshotConnectService { state }))
}

struct SnapshotConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl SnapshotService for SnapshotConnectService {
    async fn create_snapshot(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateSnapshotRequest>,
    ) -> ServiceResult<CreateSnapshotResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let row = create_snapshot_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.name,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateSnapshotResponse {
            snapshot: Some(proto_snapshot(row)).into(),
            ..Default::default()
        })
    }

    async fn list_snapshots(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListSnapshotsRequest>,
    ) -> ServiceResult<ListSnapshotsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let rows = list_snapshots_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListSnapshotsResponse {
            snapshots: rows.into_iter().map(proto_snapshot).collect(),
            ..Default::default()
        })
    }

    async fn get_snapshot(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetSnapshotRequest>,
    ) -> ServiceResult<GetSnapshotResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let row = get_snapshot_core(&self.state, &user, request.org_id, request.snapshot_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetSnapshotResponse {
            snapshot: Some(proto_snapshot(row)).into(),
            ..Default::default()
        })
    }

    async fn delete_snapshot(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteSnapshotRequest>,
    ) -> ServiceResult<DeleteSnapshotResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let row = delete_snapshot_core(&self.state, &user, request.org_id, request.snapshot_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteSnapshotResponse {
            snapshot: Some(proto_snapshot(row)).into(),
            ..Default::default()
        })
    }
}

fn proto_state(state: &str) -> SnapshotState {
    match state {
        "capturing" => SnapshotState::Capturing,
        "ready" => SnapshotState::Ready,
        "failed" => SnapshotState::Failed,
        "deleting" => SnapshotState::Deleting,
        _ => SnapshotState::Unspecified,
    }
}

fn proto_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn proto_snapshot(row: SnapshotRow) -> Snapshot {
    Snapshot {
        id: row.id,
        org_id: row.org_id,
        name: row.name,
        source_environment_id: row.source_environment_id,
        state: proto_state(&row.state).into(),
        failure_code: row.failure_code,
        size_bytes: row.size_bytes,
        created_at: Some(proto_timestamp(row.created_at)).into(),
        last_used_at: Some(proto_timestamp(row.last_used_at)).into(),
        ..Default::default()
    }
}
