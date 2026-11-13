//! Platform authorization and daemon-discovery backend for the shared public
//! durable-session bridge.
//!
//! The public wire behavior lives in `codewire-daemon-bridge`. This module
//! retains platform identity, organization authorization, Kubernetes target
//! resolution, and environment-scoped daemon credential issuance.

use std::borrow::Cow;

use async_trait::async_trait;
use codewire_daemon_bridge::session::{
    EnvironmentSessionAttachment as BridgeAttachment, EnvironmentSessionBackend, FieldViolation,
};
use codewire_daemon_proto::daemon::v1;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::{AppError, ValidationIssue};
use connectrpc::RequestContext;

use crate::api::ApiState;
use crate::api::environment_daemon::{
    EnvironmentDaemonSessionAttachment, attach_environment_daemon_session_core,
    get_environment_daemon_session_core, launch_environment_daemon_session_core,
    list_environment_daemon_sessions_core, read_environment_daemon_session_output_core,
    restart_environment_daemon_session_core, send_environment_daemon_session_input_core,
    stop_environment_daemon_session_core,
};
use crate::connect::{rendered_workspace_error, workspace_rpc_error};

/// Registers the public durable-session service. This has no REST sibling:
/// sessions use one generated RPC contract. The direct h2c leg speaks Connect;
/// the secure first-party public edge speaks native gRPC so request streaming
/// remains full duplex through Cloudflare and ingress-nginx.
pub fn router(state: ApiState) -> connectrpc::Router {
    codewire_daemon_bridge::session::router(PlatformSessionBackend { state })
}

#[derive(Clone)]
struct PlatformSessionBackend {
    state: ApiState,
}

struct PlatformSessionAttachment {
    inner: EnvironmentDaemonSessionAttachment,
    request_id: Option<String>,
}

#[async_trait]
impl EnvironmentSessionBackend for PlatformSessionBackend {
    type Attachment = PlatformSessionAttachment;

    fn server_restart(
        &self,
        restart: codewire_daemon_bridge::drain::Restart,
    ) -> Option<codewire_daemon_bridge::drain::RestartSignal> {
        Some(self.state.drain.signal(restart))
    }

    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        auth_user(ctx).map(|_| ())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        render_session_error(
            &AppError::Validation {
                errors: violations
                    .into_iter()
                    .map(|violation| ValidationIssue {
                        path: Cow::Borrowed(violation.path),
                        message: Cow::Borrowed(violation.message),
                    })
                    .collect(),
            },
            request_id,
        )
    }

    fn invalid_daemon_frame(&self, request_id: Option<&str>) -> connectrpc::ConnectError {
        render_session_error(
            &AppError::InternalMsg("environment daemon emitted an invalid session frame".into()),
            request_id,
        )
    }

    async fn launch(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        launch_environment_daemon_session_core(&self.state, &user, org_id, environment_id, request)
            .await
            .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn list(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<v1::SessionRecord>, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        list_environment_daemon_sessions_core(&self.state, &user, org_id, environment_id)
            .await
            .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn get(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        get_environment_daemon_session_core(&self.state, &user, org_id, environment_id, session_id)
            .await
            .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn stop(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        stop_environment_daemon_session_core(&self.state, &user, org_id, environment_id, session_id)
            .await
            .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn restart(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        restart_environment_daemon_session_core(
            &self.state,
            &user,
            org_id,
            environment_id,
            session_id,
            expected_launch_generation,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn send_input(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::SendSessionInputRequest,
    ) -> Result<(), connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        send_environment_daemon_session_input_core(
            &self.state,
            &user,
            org_id,
            environment_id,
            request,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn read_output(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        read_environment_daemon_session_output_core(
            &self.state,
            &user,
            org_id,
            environment_id,
            request,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, ctx))
    }

    async fn attach(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        start: v1::AttachSessionRequest,
    ) -> Result<Self::Attachment, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        let inner = attach_environment_daemon_session_core(
            &self.state,
            &user,
            org_id,
            environment_id,
            start,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, ctx))?;
        Ok(PlatformSessionAttachment {
            inner,
            request_id: request_id(ctx).map(str::to_owned),
        })
    }
}

#[async_trait]
impl BridgeAttachment for PlatformSessionAttachment {
    async fn send_input(
        &self,
        message: v1::SessionAttachMessage,
    ) -> Result<(), connectrpc::ConnectError> {
        self.inner
            .send_input(message)
            .await
            .map_err(|error| render_session_error(&error, self.request_id.as_deref()))
    }

    async fn next_output(
        &mut self,
    ) -> Result<Option<v1::SessionAttachMessage>, connectrpc::ConnectError> {
        self.inner
            .next_output()
            .await
            .map_err(|error| render_session_error(&error, self.request_id.as_deref()))
    }

    async fn session(
        &mut self,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
        self.inner
            .session(session_id)
            .await
            .map_err(|error| render_session_error(&error, self.request_id.as_deref()))
    }
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn render_session_error(error: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    wire_error(&rendered_workspace_error(error, request_id))
}
