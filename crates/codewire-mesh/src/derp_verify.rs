//! DERP client admission lookup (#2844).
//!
//! The public DERP relay serves only node keys a coordinator registered. Mesh
//! answers for its own members through the internal
//! `codewire.internal.v1.DerpAdmissionService`, on a separate cluster-local
//! listener that no edge route reaches.

use std::sync::Arc;

use codewire_proto::codewire::internal::v1::{
    CheckNodeKeyRequest, CheckNodeKeyResponse, DerpAdmissionService,
};
use codewire_tailnet::node::NodePublic;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};

use crate::mesh_coordinate::MeshCoordinateState;

/// The DERP admission listener's generated Connect service.
pub(crate) fn router(state: MeshCoordinateState) -> axum::Router {
    codewire_server_core::connect::connect_router(
        connectrpc::Router::new().add_service(Arc::new(DerpAdmission { state })),
    )
}

struct DerpAdmission {
    state: MeshCoordinateState,
}

#[allow(refining_impl_trait)]
impl DerpAdmissionService for DerpAdmission {
    async fn check_node_key(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckNodeKeyRequest>,
    ) -> ServiceResult<CheckNodeKeyResponse> {
        let raw: [u8; 32] = request
            .view()
            .node_key
            .as_ref()
            .try_into()
            .map_err(|_| ConnectError::invalid_argument("node_key must be 32 bytes"))?;
        connectrpc::Response::ok(CheckNodeKeyResponse {
            registered: self.state.knows_key(&NodePublic::from_raw(raw)),
            ..Default::default()
        })
    }
}
