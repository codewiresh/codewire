//! Generated Connect adapter for personal profile metadata and explicit consent.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileEntry, AccessProfileService, CreateAccessProfileRequest,
    CreateAccessProfileResponse, DeleteAccessProfileRequest, DeleteAccessProfileResponse,
    EnvironmentAccessProfileBinding, GetAccessProfileRequest, GetAccessProfileResponse,
    GetEnvironmentAccessProfileRequest, GetEnvironmentAccessProfileResponse,
    ListAccessProfilesRequest, ListAccessProfilesResponse, RenameAccessProfileRequest,
    RenameAccessProfileResponse, UpdateAccessProfileRequest, UpdateAccessProfileResponse,
    get_access_profile_request,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::access_profiles::{AccessProfiles, ProfileSelector, profile_entries};

/// Bounds each response's admission, including pool acquisition and waits.
const PROFILE_REQUEST_BOUND: Duration = Duration::from_secs(5);

/// Mount with the ordinary authenticated Connect layer. The service additionally
/// rejects organization API keys for every account-scoped method.
pub fn router(pool: PgPool) -> connectrpc::Router {
    router_with_bounds(pool, None)
}

/// [`router`] with `bound` in place of both the response bound and the
/// profile store's statement ceiling, five seconds each by default. A test
/// whose subject is neither lengthens them into a hang guard, so a stalled CI
/// slot cannot spend them (#3310). Production mounts [`router`].
pub fn router_with_bounds(pool: PgPool, bound: Option<Duration>) -> connectrpc::Router {
    let profiles = AccessProfiles::new(pool);
    let (profiles, request_bound) = match bound {
        Some(bound) => (profiles.with_statement_timeout(bound), bound),
        None => (profiles, PROFILE_REQUEST_BOUND),
    };
    connectrpc::Router::new().add_service(Arc::new(ProfileConnectService {
        profiles,
        request_bound,
    }))
}

struct ProfileConnectService {
    profiles: AccessProfiles,
    request_bound: Duration,
}

#[allow(refining_impl_trait)]
impl AccessProfileService for ProfileConnectService {
    async fn list_access_profiles(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAccessProfilesRequest>,
    ) -> ServiceResult<ListAccessProfilesResponse> {
        let user = account_user(&ctx)?;
        let request = request.view();
        let (profiles, next_page_token) = bounded(
            &ctx,
            self.request_bound,
            self.profiles
                .list(&user, request.page_size, request.page_token),
        )
        .await?;
        connectrpc::Response::ok(ListAccessProfilesResponse {
            access_profiles: profiles.into_iter().map(proto_profile).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAccessProfileRequest>,
    ) -> ServiceResult<GetAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.to_owned_message();
        let selector = match &request.selector {
            Some(get_access_profile_request::Selector::AccessProfileId(id)) => {
                ProfileSelector::Id(id)
            }
            Some(get_access_profile_request::Selector::Name(name)) => ProfileSelector::Name(name),
            None => {
                return Err(rpc_app_error(
                    &AppError::BadRequest("one profile selector is required".into()),
                    &ctx,
                ));
            }
        };
        let profile = bounded(
            &ctx,
            self.request_bound,
            self.profiles.get(&user, selector, request.revision),
        )
        .await?;
        connectrpc::Response::ok(GetAccessProfileResponse {
            access_profile: Some(proto_profile(profile)).into(),
            ..Default::default()
        })
    }

    async fn create_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateAccessProfileRequest>,
    ) -> ServiceResult<CreateAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.to_owned_message();
        let entries = profile_entries(
            request
                .entries
                .iter()
                .map(|entry| (entry.capability_slot.as_str(), entry.credential_id.as_str())),
        )
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let profile = bounded(
            &ctx,
            self.request_bound,
            self.profiles.create(&user, &request.name, entries),
        )
        .await?;
        connectrpc::Response::ok(CreateAccessProfileResponse {
            access_profile: Some(proto_profile(profile)).into(),
            ..Default::default()
        })
    }

    async fn update_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateAccessProfileRequest>,
    ) -> ServiceResult<UpdateAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.to_owned_message();
        let entries = profile_entries(
            request
                .entries
                .iter()
                .map(|entry| (entry.capability_slot.as_str(), entry.credential_id.as_str())),
        )
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let profile = bounded(
            &ctx,
            self.request_bound,
            self.profiles.update(
                &user,
                &request.access_profile_id,
                request.expected_revision,
                entries,
            ),
        )
        .await?;
        connectrpc::Response::ok(UpdateAccessProfileResponse {
            access_profile: Some(proto_profile(profile)).into(),
            ..Default::default()
        })
    }

    async fn rename_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RenameAccessProfileRequest>,
    ) -> ServiceResult<RenameAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.view();
        let profile = bounded(
            &ctx,
            self.request_bound,
            self.profiles.rename(
                &user,
                request.access_profile_id,
                request.expected_revision,
                request.expected_name,
                request.name,
            ),
        )
        .await?;
        connectrpc::Response::ok(RenameAccessProfileResponse {
            access_profile: Some(proto_profile(profile)).into(),
            ..Default::default()
        })
    }

    async fn delete_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteAccessProfileRequest>,
    ) -> ServiceResult<DeleteAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.view();
        bounded(
            &ctx,
            self.request_bound,
            self.profiles
                .delete(&user, request.access_profile_id, request.expected_revision),
        )
        .await?;
        connectrpc::Response::ok(DeleteAccessProfileResponse::default())
    }

    async fn get_environment_access_profile(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentAccessProfileRequest>,
    ) -> ServiceResult<GetEnvironmentAccessProfileResponse> {
        let user = account_user(&ctx)?;
        let request = request.view();
        let metadata = bounded(
            &ctx,
            self.request_bound,
            self.profiles.get_binding(&user, request.environment_id),
        )
        .await?;
        let confirmed = metadata
            .personal_owner_confirmed_by
            .as_ref()
            .is_some_and(|owner| owner.as_str() == user.user_id);
        connectrpc::Response::ok(GetEnvironmentAccessProfileResponse {
            binding: Some(proto_binding(metadata.binding)).into(),
            personal_credentials_confirmed: confirmed,
            ..Default::default()
        })
    }
}

fn account_user(ctx: &RequestContext) -> Result<AuthUser, connectrpc::ConnectError> {
    let user = auth_user(ctx)?.clone();
    user.require_account_credential()
        .map_err(|error| rpc_app_error(&error, ctx))?;
    Ok(user)
}

async fn bounded<T>(
    ctx: &RequestContext,
    bound: Duration,
    operation: impl Future<Output = AppResult<T>>,
) -> Result<T, connectrpc::ConnectError> {
    // Bound overall response admission, including pool acquisition and waits.
    // Dropping SQLx's future does not cancel its PostgreSQL statement: the
    // shared profile transaction initializer separately bounds server statement
    // and idle ownership. Network loss can still obscure cleanup/COMMIT ACKs.
    // An already-accepted COMMIT may succeed without its reply; callers must
    // inspect the current revision/binding, never blindly retry its CAS.
    tokio::time::timeout(bound, operation)
        .await
        .map_err(|_| {
            rpc_app_error(
                &AppError::ServiceUnavailable("access profile service unavailable".into()),
                ctx,
            )
        })?
        .map_err(|error| rpc_app_error(&error, ctx))
}

fn proto_profile(profile: codewire_access::AccessProfile) -> AccessProfile {
    AccessProfile {
        id: profile.id.as_str().to_owned(),
        name: profile.name.as_str().to_owned(),
        revision: profile.revision,
        entries: profile
            .entries
            .into_iter()
            .map(|(slot, id)| AccessProfileEntry {
                capability_slot: slot.as_str().to_owned(),
                credential_id: id.as_str().to_owned(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn proto_binding(
    binding: codewire_access::EnvironmentAccessBinding,
) -> EnvironmentAccessProfileBinding {
    EnvironmentAccessProfileBinding {
        environment_id: binding.environment_id.as_str().to_owned(),
        access_profile_id: binding.profile_id.as_str().to_owned(),
        access_profile_revision: binding.profile_revision,
        ..Default::default()
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    #[test]
    fn production_response_bound_is_five_seconds() {
        assert_eq!(PROFILE_REQUEST_BOUND, Duration::from_secs(5));
    }
}
