//! Connect-RPC adapter for the account-global GitHub connection.
//!
//! This module maps shared GitHub service functions to protobuf and Connect
//! errors; browser OAuth redirects remain raw HTTP.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::Timestamp;
use buffa_types::google::protobuf::__buffa::view::TimestampView;
use chrono::{DateTime, Utc};
use codewire_proto::codewire::console::v1::{
    DeleteGitHubTokenRequest, DeleteGitHubTokenResponse, GetGitHubConfigRequest,
    GetGitHubConfigResponse, GetGitHubStatusRequest, GetGitHubStatusResponse, GitHubRepo,
    GitHubService, ListGitHubReposRequest, ListGitHubReposResponse, SaveGitHubTokenRequest,
    SaveGitHubTokenResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::github::{
    self, ListGitHubReposQuery, SaveGitHubTokenParams, delete_github_token_core,
    get_github_config_core, get_github_status_core, list_github_repos_core, save_github_token_core,
};

const PROTO_TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const PROTO_TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;

/// Registers the five GitHubService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(GitHubConnectService { state }))
}

struct GitHubConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl GitHubService for GitHubConnectService {
    async fn get_git_hub_config(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetGitHubConfigRequest>,
    ) -> ServiceResult<GetGitHubConfigResponse> {
        let user = auth_user(&ctx)?.clone();
        let config = get_github_config_core(&self.state, &user)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetGitHubConfigResponse {
            client_id: config.client_id,
            app_slug: config.app_slug,
            ..Default::default()
        })
    }

    async fn get_git_hub_status(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetGitHubStatusRequest>,
    ) -> ServiceResult<GetGitHubStatusResponse> {
        let user = auth_user(&ctx)?.clone();
        let status = get_github_status_core(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetGitHubStatusResponse {
            connected: status.connected,
            username: status.username,
            installation_id: status.installation_id,
            connected_at: status.connected_at.map(proto_timestamp).into(),
            ..Default::default()
        })
    }

    async fn list_git_hub_repos(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListGitHubReposRequest>,
    ) -> ServiceResult<ListGitHubReposResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let repos = list_github_repos_core(
            &self.state,
            &user,
            ListGitHubReposQuery {
                page: request.page,
                per_page: request.per_page,
                search: request.search.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let repos = repos
            .into_iter()
            .map(proto_repo)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListGitHubReposResponse {
            repos,
            ..Default::default()
        })
    }

    async fn save_git_hub_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SaveGitHubTokenRequest>,
    ) -> ServiceResult<SaveGitHubTokenResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let params = SaveGitHubTokenParams {
            access_token: request.access_token.to_owned(),
            refresh_token: request.refresh_token.to_owned(),
            token_type: request.token_type.to_owned(),
            expires_at: request_timestamp("expires_at", request.expires_at.as_option())
                .map_err(|error| rpc_app_error(&error, &ctx))?,
            refresh_token_expires_at: request_timestamp(
                "refresh_token_expires_at",
                request.refresh_token_expires_at.as_option(),
            )
            .map_err(|error| rpc_app_error(&error, &ctx))?,
            installation_id: request.installation_id,
            github_username: request.github_username.to_owned(),
        };
        save_github_token_core(&self.state, &user, params)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(SaveGitHubTokenResponse::default())
    }

    async fn delete_git_hub_token(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, DeleteGitHubTokenRequest>,
    ) -> ServiceResult<DeleteGitHubTokenResponse> {
        let user = auth_user(&ctx)?.clone();
        delete_github_token_core(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteGitHubTokenResponse::default())
    }
}

fn request_timestamp(
    field: &'static str,
    value: Option<&TimestampView<'_>>,
) -> AppResult<Option<DateTime<Utc>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !(0..=999_999_999).contains(&value.nanos)
        || !(PROTO_TIMESTAMP_MIN_SECONDS..=PROTO_TIMESTAMP_MAX_SECONDS).contains(&value.seconds)
    {
        return Err(AppError::BadRequest(Cow::Owned(format!(
            "{field} must be a valid protobuf Timestamp"
        ))));
    }
    DateTime::from_timestamp(value.seconds, value.nanos as u32)
        .map(Some)
        .ok_or_else(|| {
            AppError::BadRequest(Cow::Owned(format!(
                "{field} must be a valid protobuf Timestamp"
            )))
        })
}

fn proto_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn proto_repo(record: github::GitHubRepo) -> AppResult<GitHubRepo> {
    let updated_at = DateTime::parse_from_rfc3339(&record.updated_at)
        .map_err(|error| {
            tracing::error!(%error, updated_at = %record.updated_at, "github repo timestamp invalid");
            AppError::InternalMsg(Cow::Borrowed("failed to parse GitHub response"))
        })?
        .with_timezone(&Utc);
    Ok(GitHubRepo {
        full_name: record.full_name,
        html_url: record.html_url,
        clone_url: record.clone_url,
        description: record.description,
        language: record.language,
        private: record.private,
        default_branch: record.default_branch,
        updated_at: Some(proto_timestamp(updated_at)).into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp_view(seconds: i64, nanos: i32) -> TimestampView<'static> {
        TimestampView {
            seconds,
            nanos,
            ..Default::default()
        }
    }

    #[test]
    fn request_timestamp_accepts_proto_boundaries_and_rejects_invalid_values() {
        let valid = timestamp_view(1_735_689_600, 123_456_789);
        assert_eq!(
            request_timestamp("expires_at", Some(&valid))
                .unwrap()
                .unwrap()
                .timestamp_subsec_nanos(),
            123_456_789
        );
        assert!(request_timestamp("expires_at", None).unwrap().is_none());

        for invalid in [
            timestamp_view(0, -1),
            timestamp_view(0, 1_000_000_000),
            timestamp_view(PROTO_TIMESTAMP_MIN_SECONDS - 1, 0),
            timestamp_view(PROTO_TIMESTAMP_MAX_SECONDS + 1, 0),
        ] {
            assert!(matches!(
                request_timestamp("expires_at", Some(&invalid)),
                Err(AppError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn repo_mapping_uses_wkt_timestamp_and_preserves_fields() {
        let mapped = proto_repo(github::GitHubRepo {
            full_name: "codewiresh/codewire".into(),
            html_url: "https://github.com/codewiresh/codewire".into(),
            clone_url: "https://github.com/codewiresh/codewire.git".into(),
            description: "control plane".into(),
            language: "Rust".into(),
            private: true,
            default_branch: "main".into(),
            updated_at: "2026-07-18T00:00:00.123456Z".into(),
        })
        .unwrap();
        assert_eq!(mapped.full_name, "codewiresh/codewire");
        assert_eq!(mapped.language, "Rust");
        assert!(mapped.private);
        let updated_at = mapped.updated_at.as_option().unwrap();
        assert_eq!(updated_at.seconds, 1_784_332_800);
        assert_eq!(updated_at.nanos, 123_456_000);
    }
}
