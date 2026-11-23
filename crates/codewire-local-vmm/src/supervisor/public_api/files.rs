//! The public `FileService` route of the native supervisor and its backend.

use super::*;

/// The public file routes, Connect over HTTP only, with the `WriteFiles` body
/// budget inside the protocol gate.
pub(super) fn router(supervisor: SupervisorRpc) -> axum::Router {
    let files = connectrpc::ConnectRpcService::new(codewire_daemon_bridge::file::router(
        LocalFileBackend { supervisor },
    ));
    let files = axum::Router::new().route_service(PUBLIC_FILE_ROUTE, files);
    codewire_daemon_bridge::file::write_files_admission(files, owner)
        .layer(axum::middleware::from_fn(enforce_connect_only))
}

/// The one caller of the local supervisor: its owner, whom the Unix peer UID
/// already authorized.
fn owner(_request: &axum::extract::Request) -> Option<String> {
    Some("owner".to_owned())
}

#[derive(Clone)]
struct LocalFileBackend {
    supervisor: SupervisorRpc,
}

#[async_trait]
impl FileBackend for LocalFileBackend {
    fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        Ok(())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_bridge_validation("file", &violations)
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_file_error(error)
    }

    fn invalid_file_type(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::invalid_argument("local file path is not a regular file")
    }

    async fn daemon(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        self.supervisor
            .public_bridge_daemon_client(org_id, environment_id)
            .await
    }
}
