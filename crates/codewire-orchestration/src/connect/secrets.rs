//! Connect-RPC adapter for organization, user, and project secrets.
//!
//! This module maps shared secret service logic to protobuf, validates
//! pagination, and renders Connect errors. It never logs request bodies or
//! secret values.

use std::borrow::Cow;
use std::sync::Arc;

use buffa::MessageField;
use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::v1::{
    CreateSecretProjectRequest, CreateSecretProjectResponse, DeleteProjectSecretRequest,
    DeleteProjectSecretResponse, DeleteSecretProjectRequest, DeleteSecretProjectResponse,
    DeleteSecretRequest, DeleteSecretResponse, DeleteUserSecretRequest, DeleteUserSecretResponse,
    ListProjectSecretsRequest, ListProjectSecretsResponse, ListSecretProjectsRequest,
    ListSecretProjectsResponse, ListSecretsRequest, ListSecretsResponse, ListUserSecretsRequest,
    ListUserSecretsResponse, PreviewWorkloadSecretResolutionRequest,
    PreviewWorkloadSecretResolutionResponse, RenameProjectSecretRequest,
    RenameProjectSecretResponse, RenameSecretRequest, RenameSecretResponse,
    RenameUserSecretRequest, RenameUserSecretResponse,
    ResolvedWorkloadSecretMetadata as ProtoResolvedWorkloadSecretMetadata,
    SecretMetadata as ProtoSecretMetadata, SecretProject as ProtoSecretProject, SecretService,
    SetProjectSecretRequest, SetProjectSecretResponse, SetSecretRequest, SetSecretResponse,
    SetUserSecretRequest, SetUserSecretResponse, WorkloadSecretSource as ProtoWorkloadSecretSource,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_KEY_BYTES, MAX_WORKLOAD_SECRET_VALUE_BYTES, ResolvedWorkloadSecretMetadata,
    WorkloadSecretSource, validate_workload_secret_value,
};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::secret_projects::{
    SecretProject, create_secret_project_core, delete_project_secret_core,
    delete_secret_project_core, list_project_secrets_core, list_secret_projects_core,
    rename_project_secret_core, set_project_secret_core,
};
use crate::api::secrets::{
    SecretMetadata, delete_secret_core, delete_user_secret_core, list_secrets_core,
    list_user_secrets_core, preview_workload_secret_resolution_core, rename_secret_core,
    rename_user_secret_core, set_secret_core, set_user_secret_core,
};

/// Registers every SecretService RPC on its generated Connect route.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(SecretConnectService { state }))
}

struct SecretConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl SecretService for SecretConnectService {
    async fn list_secrets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListSecretsRequest>,
    ) -> ServiceResult<ListSecretsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let response = list_secrets_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListSecretsResponse {
            secrets: response
                .secrets
                .into_iter()
                .map(proto_secret_metadata)
                .collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn set_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetSecretRequest>,
    ) -> ServiceResult<SetSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        set_secret_core(
            &self.state,
            &user,
            request.org_id,
            request.key,
            request.value,
        )
        .await
        .map_err(|error| {
            let error = secret_write_validation(error, request.key, request.value);
            rpc_app_error(&error, &ctx)
        })?;
        connectrpc::Response::ok(SetSecretResponse::default())
    }

    async fn delete_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteSecretRequest>,
    ) -> ServiceResult<DeleteSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_secret_core(&self.state, &user, request.org_id, request.key)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteSecretResponse::default())
    }

    async fn rename_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RenameSecretRequest>,
    ) -> ServiceResult<RenameSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        rename_secret_core(
            &self.state,
            &user,
            request.org_id,
            request.key,
            request.new_key,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RenameSecretResponse::default())
    }

    async fn list_user_secrets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListUserSecretsRequest>,
    ) -> ServiceResult<ListUserSecretsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let response = list_user_secrets_core(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListUserSecretsResponse {
            secrets: response
                .secrets
                .into_iter()
                .map(proto_secret_metadata)
                .collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn set_user_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetUserSecretRequest>,
    ) -> ServiceResult<SetUserSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        set_user_secret_core(&self.state, &user, request.key, request.value)
            .await
            .map_err(|error| {
                let error = secret_write_validation(error, request.key, request.value);
                rpc_app_error(&error, &ctx)
            })?;
        connectrpc::Response::ok(SetUserSecretResponse::default())
    }

    async fn delete_user_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteUserSecretRequest>,
    ) -> ServiceResult<DeleteUserSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_user_secret_core(&self.state, &user, request.key)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteUserSecretResponse::default())
    }

    async fn rename_user_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RenameUserSecretRequest>,
    ) -> ServiceResult<RenameUserSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        rename_user_secret_core(&self.state, &user, request.key, request.new_key)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RenameUserSecretResponse::default())
    }

    async fn list_secret_projects(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListSecretProjectsRequest>,
    ) -> ServiceResult<ListSecretProjectsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let projects = list_secret_projects_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_secret_project)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListSecretProjectsResponse {
            secret_projects: projects,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_secret_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateSecretProjectRequest>,
    ) -> ServiceResult<CreateSecretProjectResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let project = create_secret_project_core(&self.state, &user, request.org_id, request.name)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateSecretProjectResponse {
            secret_project: Some(
                proto_secret_project(project).map_err(|error| rpc_app_error(&error, &ctx))?,
            )
            .into(),
            ..Default::default()
        })
    }

    async fn delete_secret_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteSecretProjectRequest>,
    ) -> ServiceResult<DeleteSecretProjectResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_secret_project_core(
            &self.state,
            &user,
            request.org_id,
            request.secret_project_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteSecretProjectResponse::default())
    }

    async fn list_project_secrets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListProjectSecretsRequest>,
    ) -> ServiceResult<ListProjectSecretsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let response = list_project_secrets_core(
            &self.state,
            &user,
            request.org_id,
            request.secret_project_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListProjectSecretsResponse {
            secrets: response
                .secrets
                .into_iter()
                .map(proto_secret_metadata)
                .collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn set_project_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetProjectSecretRequest>,
    ) -> ServiceResult<SetProjectSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        set_project_secret_core(
            &self.state,
            &user,
            request.org_id,
            request.secret_project_id,
            request.key,
            request.value,
        )
        .await
        .map_err(|error| {
            let error = secret_write_validation(error, request.key, request.value);
            rpc_app_error(&error, &ctx)
        })?;
        connectrpc::Response::ok(SetProjectSecretResponse::default())
    }

    async fn delete_project_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteProjectSecretRequest>,
    ) -> ServiceResult<DeleteProjectSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_project_secret_core(
            &self.state,
            &user,
            request.org_id,
            request.secret_project_id,
            request.key,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteProjectSecretResponse::default())
    }

    async fn rename_project_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RenameProjectSecretRequest>,
    ) -> ServiceResult<RenameProjectSecretResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        rename_project_secret_core(
            &self.state,
            &user,
            request.org_id,
            request.secret_project_id,
            request.key,
            request.new_key,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RenameProjectSecretResponse::default())
    }

    async fn preview_workload_secret_resolution(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PreviewWorkloadSecretResolutionRequest>,
    ) -> ServiceResult<PreviewWorkloadSecretResolutionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let explicit_environment_keys = request
            .explicit_environment_keys
            .iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>();
        let secrets = preview_workload_secret_resolution_core(
            &self.state,
            &user,
            request.org_id,
            request.organization,
            (!request.secret_project_id.is_empty()).then_some(request.secret_project_id),
            request.user,
            &explicit_environment_keys,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(PreviewWorkloadSecretResolutionResponse {
            secrets: secrets
                .into_iter()
                .map(proto_resolved_workload_secret_metadata)
                .collect(),
            ..Default::default()
        })
    }
}

fn proto_resolved_workload_secret_metadata(
    secret: ResolvedWorkloadSecretMetadata,
) -> ProtoResolvedWorkloadSecretMetadata {
    ProtoResolvedWorkloadSecretMetadata {
        key: secret.key,
        source: proto_workload_secret_source(secret.source).into(),
        overridden_sources: secret
            .overridden_sources
            .into_iter()
            .map(|source| proto_workload_secret_source(source).into())
            .collect(),
        ..Default::default()
    }
}

fn proto_workload_secret_source(source: WorkloadSecretSource) -> ProtoWorkloadSecretSource {
    match source {
        WorkloadSecretSource::Organization => ProtoWorkloadSecretSource::Organization,
        WorkloadSecretSource::Project => ProtoWorkloadSecretSource::Project,
        WorkloadSecretSource::User => ProtoWorkloadSecretSource::User,
        WorkloadSecretSource::ExplicitEnvironment => ProtoWorkloadSecretSource::ExplicitEnvironment,
    }
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn secret_key_validation(error: AppError, key: &str) -> AppError {
    if matches!(error, AppError::BadRequest(_)) && !crate::worker::secrets::is_valid_secret_key(key)
    {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/key"),
                message: Cow::Owned(format!(
                    "secret key must be 1 to {MAX_WORKLOAD_SECRET_KEY_BYTES} bytes, start with an ASCII letter or underscore, and contain only ASCII letters, digits, or underscores"
                )),
            }],
        }
    } else {
        error
    }
}

fn secret_write_validation(error: AppError, key: &str, value: &str) -> AppError {
    let error = secret_key_validation(error, key);
    if matches!(error, AppError::BadRequest(_))
        && validate_workload_secret_value(value.as_bytes()).is_err()
    {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/value"),
                message: Cow::Owned(format!(
                    "secret value must be non-empty UTF-8 without NUL bytes and at most {MAX_WORKLOAD_SECRET_VALUE_BYTES} bytes"
                )),
            }],
        }
    } else {
        error
    }
}

fn optional_proto_timestamp(value: &str) -> MessageField<Timestamp, buffa::Inline<Timestamp>> {
    if value.is_empty() {
        return None.into();
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32))
        .into()
}

fn required_proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, created_at = value, "secret-project timestamp invalid");
        AppError::InternalMsg("failed to map secret project timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

fn proto_secret_metadata(secret: SecretMetadata) -> ProtoSecretMetadata {
    ProtoSecretMetadata {
        key: secret.key,
        created_at: optional_proto_timestamp(&secret.created_at),
        updated_at: optional_proto_timestamp(&secret.updated_at),
        ..Default::default()
    }
}

pub(crate) fn proto_secret_project(project: SecretProject) -> AppResult<ProtoSecretProject> {
    Ok(ProtoSecretProject {
        id: project.id,
        org_id: project.org_id,
        name: project.name,
        secret_count: project.secret_count,
        created_at: Some(required_proto_timestamp(&project.created_at)?).into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use codewire_proto::codewire::v1::{
        SetProjectSecretRequest, SetSecretRequest, SetUserSecretRequest,
    };

    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    #[test]
    fn generated_debug_redacts_every_secret_value() {
        let marker = "do-not-print-this-secret";
        for rendered in [
            format!(
                "{:?}",
                SetSecretRequest {
                    value: marker.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                SetUserSecretRequest {
                    value: marker.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                SetProjectSecretRequest {
                    value: marker.into(),
                    ..Default::default()
                }
            ),
        ] {
            assert!(!rendered.contains(marker), "secret leaked through Debug");
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[test]
    fn metadata_timestamps_are_best_effort_and_projects_are_strict() {
        assert!(optional_proto_timestamp("").is_unset());
        assert!(optional_proto_timestamp("not-a-time").is_unset());
        assert!(optional_proto_timestamp("2026-07-18T04:00:00.123456Z").is_set());
        assert!(required_proto_timestamp("not-a-time").is_err());
    }

    #[test]
    fn workload_secret_preview_mapping_contains_only_keys_and_precedence() {
        let proto = proto_resolved_workload_secret_metadata(ResolvedWorkloadSecretMetadata {
            key: "TOKEN".into(),
            source: WorkloadSecretSource::ExplicitEnvironment,
            overridden_sources: vec![
                WorkloadSecretSource::Organization,
                WorkloadSecretSource::Project,
                WorkloadSecretSource::User,
            ],
        });
        assert_eq!(
            proto.source.as_known(),
            Some(ProtoWorkloadSecretSource::ExplicitEnvironment)
        );
        assert_eq!(
            proto
                .overridden_sources
                .iter()
                .filter_map(|source| source.as_known())
                .collect::<Vec<_>>(),
            [
                ProtoWorkloadSecretSource::Organization,
                ProtoWorkloadSecretSource::Project,
                ProtoWorkloadSecretSource::User,
            ]
        );
        let json = serde_json::to_value(proto).unwrap();
        assert_eq!(json["key"], "TOKEN");
        assert!(json.get("value").is_none());
    }

    #[test]
    fn pagination_rejects_unknown_tokens() {
        assert!(validate_pagination("").is_ok());
        assert!(matches!(
            validate_pagination("future"),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn invalid_secret_keys_name_the_key_proto_field() {
        for key in [
            "1DIGIT_FIRST".to_owned(),
            "unsafe/path".to_owned(),
            "A".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES + 1),
        ] {
            let error =
                secret_key_validation(AppError::BadRequest("invalid secret key".into()), &key);
            let rendered = ConnectError::from_app_error(&error, None);
            assert_eq!(rendered.code, ConnectCode::InvalidArgument);
            let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
                panic!("missing BadRequest detail");
            };
            assert_eq!(detail.field_violations[0].field, "key");
            assert!(
                detail.field_violations[0]
                    .description
                    .contains("start with an ASCII letter or underscore")
            );
        }
    }

    #[test]
    fn invalid_secret_value_names_the_value_proto_field_without_rendering_it() {
        let marker = "synthetic-value-must-not-render\0";
        let error = secret_write_validation(
            AppError::BadRequest("invalid secret value".into()),
            "SAFE_KEY",
            marker,
        );
        let rendered = ConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("missing BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "value");
        assert!(!detail.field_violations[0].description.contains(marker));
        assert!(!format!("{error:?}").contains(marker));
    }
}
