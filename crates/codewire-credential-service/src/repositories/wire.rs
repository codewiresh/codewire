use std::sync::Arc;

use codewire_proto::codewire::v1::{
    GithubRepositoryService, ListGithubRepositoriesRequest, ListGithubRepositoriesResponse,
};
use codewire_server_core::connect::{credential_mutation_authority, wire_error};
use codewire_server_core::connect_error::{
    ConnectCode, ConnectError, ConnectErrorDetail, ERROR_INFO_DOMAIN, ErrorInfo,
};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use super::{Error, GithubRepositoryOwner};

pub(super) fn router(owner: Arc<GithubRepositoryOwner>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(Service { owner }))
}

struct Service {
    owner: Arc<GithubRepositoryOwner>,
}

#[allow(refining_impl_trait)]
impl GithubRepositoryService for Service {
    async fn list_github_repositories(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListGithubRepositoriesRequest>,
    ) -> ServiceResult<ListGithubRepositoriesResponse> {
        let authority = credential_mutation_authority(&ctx)?.clone();
        let result = self
            .owner
            .list(authority, request.to_owned_message())
            .await
            .map_err(error)?;
        Ok(connectrpc::Response::new(result).with_header("cache-control", "private, no-store"))
    }
}

pub(super) fn error(error: Error) -> connectrpc::ConnectError {
    let (code, reason, message) = match error {
        Error::InvalidInput => (
            ConnectCode::InvalidArgument,
            "GITHUB_REPOSITORIES_INVALID",
            "invalid GitHub repository selection or page",
        ),
        Error::Denied => (
            ConnectCode::Unauthenticated,
            "GITHUB_AUTHORITY_EXPIRED",
            "original account authority is no longer valid",
        ),
        Error::NotFound => (
            ConnectCode::NotFound,
            "GITHUB_PROFILE_NOT_FOUND",
            "selected profile is unavailable",
        ),
        Error::ProfileChanged => (
            ConnectCode::Aborted,
            "GITHUB_PROFILE_CHANGED",
            "selected profile revision changed",
        ),
        Error::NotConnected => (
            ConnectCode::FailedPrecondition,
            "GITHUB_NOT_CONNECTED",
            "selected profile has no active GitHub connection",
        ),
        Error::CredentialChanged => (
            ConnectCode::Aborted,
            "GITHUB_CREDENTIAL_CHANGED",
            "GitHub connection changed; reload repositories",
        ),
        Error::ProviderDenied => (
            ConnectCode::PermissionDenied,
            "GITHUB_ACCESS_DENIED",
            "GitHub repository access was denied",
        ),
        Error::RateLimited => (
            ConnectCode::ResourceExhausted,
            "GITHUB_RATE_LIMITED",
            "GitHub repository requests are rate limited",
        ),
        Error::Unavailable => (
            ConnectCode::Unavailable,
            "GITHUB_REPOSITORIES_UNAVAILABLE",
            "GitHub repositories are temporarily unavailable",
        ),
        Error::Cancelled => (
            ConnectCode::Canceled,
            "GITHUB_REPOSITORIES_CANCELLED",
            "repository request cancelled",
        ),
        Error::Expired => (
            ConnectCode::DeadlineExceeded,
            "GITHUB_REPOSITORIES_EXPIRED",
            "repository request deadline elapsed",
        ),
    };
    wire_error(&ConnectError {
        code,
        message: message.to_owned(),
        details: vec![ConnectErrorDetail::ErrorInfo(ErrorInfo {
            reason: reason.to_owned(),
            domain: ERROR_INFO_DOMAIN.to_owned(),
            metadata: Default::default(),
        })],
    })
}
