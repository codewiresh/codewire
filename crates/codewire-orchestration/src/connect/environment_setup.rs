//! Connect-RPC adapter for the first-party environment-creation setup UX.
//!
//! REST and Connect both call the service functions in [`crate::api::prepare`]
//! and [`crate::api::terminal`]. The content-negotiated prepare handler is
//! represented by EnvironmentService.WatchEnvironmentCreate, while the
//! terminal WebSocket remains raw HTTP.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::console::v1::{
    DetectRepoRequest, DetectRepoResponse, EnvironmentSetupService,
    GetEnvironmentCreateOptionsRequest, GetEnvironmentCreateOptionsResponse, GitHubConnection,
    IssueTerminalTicketRequest, IssueTerminalTicketResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::detect::parse_repo_url;
use crate::api::prepare::{
    DetectRequest, EnvironmentCreateGitHubStatus, detect_environment_repo_core,
    get_environment_create_options_core,
};
use crate::api::terminal::issue_terminal_ticket_core;
use crate::connect::environment::proto_detection;
use crate::connect::presets::proto_preset;
use crate::connect::secrets::proto_secret_project;

/// Registers the three EnvironmentSetupService RPCs on their generated routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EnvironmentSetupConnectService { state }))
}

struct EnvironmentSetupConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl EnvironmentSetupService for EnvironmentSetupConnectService {
    async fn get_environment_create_options(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentCreateOptionsRequest>,
    ) -> ServiceResult<GetEnvironmentCreateOptionsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let options = get_environment_create_options_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let presets = options
            .presets
            .into_iter()
            .map(proto_preset)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let secret_projects = options
            .secret_projects
            .into_iter()
            .map(proto_secret_project)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetEnvironmentCreateOptionsResponse {
            github_status: Some(
                proto_github_connection(options.github_status)
                    .map_err(|error| rpc_app_error(&error, &ctx))?,
            )
            .into(),
            presets,
            secret_projects,
            ..Default::default()
        })
    }

    async fn detect_repo(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DetectRepoRequest>,
    ) -> ServiceResult<DetectRepoResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let invalid_repo_url = parse_repo_url(&request.repo_url).is_err();
        let result = detect_environment_repo_core(
            &self.state,
            &user,
            DetectRequest {
                repo_url: request.repo_url,
                branch: request.branch,
                // Connect deliberately exposes no caller-supplied raw-token
                // field. The shared core resolves stored credentials.
                github_token: String::new(),
            },
        )
        .await
        .map_err(|error| {
            let error = detect_repo_validation(error, invalid_repo_url);
            rpc_app_error(&error, &ctx)
        })?;
        connectrpc::Response::ok(DetectRepoResponse {
            result: Some(proto_detection(result)).into(),
            ..Default::default()
        })
    }

    async fn issue_terminal_ticket(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, IssueTerminalTicketRequest>,
    ) -> ServiceResult<IssueTerminalTicketResponse> {
        let user = auth_user(&ctx)?.clone();
        let ticket = issue_terminal_ticket_core(&self.state, &user)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(IssueTerminalTicketResponse {
            ticket,
            ..Default::default()
        })
    }
}

fn detect_repo_validation(error: AppError, invalid_repo_url: bool) -> AppError {
    if invalid_repo_url && matches!(error, AppError::BadRequest(_)) {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/repo_url"),
                message: Cow::Borrowed("must be a valid forge repository URL"),
            }],
        }
    } else {
        error
    }
}

fn proto_github_connection(status: EnvironmentCreateGitHubStatus) -> AppResult<GitHubConnection> {
    let connected_at = status
        .connected_at
        .map(|value| proto_timestamp(&value))
        .transpose()?;
    Ok(GitHubConnection {
        connected: status.connected,
        username: status.username,
        installation_id: status.installation_id,
        connected_at: connected_at.into(),
        ..Default::default()
    })
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, timestamp = value, "environment setup timestamp invalid");
        AppError::InternalMsg("failed to map GitHub connection timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

#[cfg(test)]
mod tests {
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    use super::*;

    #[test]
    fn invalid_repo_url_names_the_proto_field() {
        let error = detect_repo_validation(
            AppError::BadRequest("invalid repo URL: URL must contain owner/repo".into()),
            true,
        );
        let rendered = ConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("missing BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "repo_url");
        assert!(!detail.field_violations[0].description.is_empty());
    }

    #[test]
    fn detection_availability_failures_keep_canonical_codes() {
        for error in [
            AppError::ServiceUnavailable("AI detection is not configured".into()),
            AppError::Upstream("failed to fetch repo".into()),
        ] {
            let rendered = ConnectError::from_app_error(&error, None);
            assert_eq!(rendered.code, ConnectCode::Unavailable);
        }
    }

    #[test]
    fn github_connection_mapping_preserves_presence_and_timestamp() {
        let disconnected = proto_github_connection(EnvironmentCreateGitHubStatus::default())
            .expect("map disconnected GitHub status");
        assert!(!disconnected.connected);
        assert!(disconnected.installation_id.is_none());
        assert!(disconnected.connected_at.is_unset());

        let connected = proto_github_connection(EnvironmentCreateGitHubStatus {
            connected: true,
            username: "octocat".into(),
            installation_id: Some(42),
            connected_at: Some("2026-07-20T11:00:00.123456Z".into()),
        })
        .expect("map connected GitHub status");
        assert_eq!(connected.username, "octocat");
        assert_eq!(connected.installation_id, Some(42));
        assert_eq!(
            connected.connected_at.as_option().unwrap().nanos,
            123_456_000
        );
    }
}
