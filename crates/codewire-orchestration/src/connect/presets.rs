//! Connect-RPC adapter for organization and official presets.
//!
//! This module maps the shared preset service logic to protobuf, validates
//! pagination, and renders Connect errors.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::v1::{
    CreatePresetRequest, CreatePresetResponse, DeletePresetRequest, DeletePresetResponse,
    GetPresetRequest, GetPresetResponse, ListPresetsRequest, ListPresetsResponse, Preset,
    PresetService, UpdatePresetRequest, UpdatePresetResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::environments::{coded, coded_owned};
use crate::api::prepare::PresetWire;
use crate::api::presets::{
    CreatePresetBody, UpdatePresetBody, create_preset_core, delete_preset_core, get_preset_core,
    list_presets_core, update_preset_core,
};

/// Registers all five PresetService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(PresetConnectService { state }))
}

struct PresetConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl PresetService for PresetConnectService {
    async fn list_presets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListPresetsRequest>,
    ) -> ServiceResult<ListPresetsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let presets = list_presets_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_preset)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListPresetsResponse {
            presets,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePresetRequest>,
    ) -> ServiceResult<CreatePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let name_missing = request.name.trim().is_empty();
        let org_id = request.org_id.clone();
        let body = create_body(request).map_err(|error| rpc_app_error(&error, &ctx))?;
        let preset = create_preset_core(&self.state, &user, &org_id, body)
            .await
            .map_err(|error| {
                let error = create_preset_validation(error, name_missing);
                rpc_app_error(&error, &ctx)
            })?;
        connectrpc::Response::ok(CreatePresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn get_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPresetRequest>,
    ) -> ServiceResult<GetPresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let preset = get_preset_core(&self.state, &user, request.org_id, request.preset_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetPresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn update_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdatePresetRequest>,
    ) -> ServiceResult<UpdatePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let org_id = request.org_id.clone();
        let preset_id = request.preset_id.clone();
        let body = update_body(request).map_err(|error| rpc_app_error(&error, &ctx))?;
        let preset = update_preset_core(&self.state, &user, &org_id, &preset_id, body)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdatePresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn delete_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeletePresetRequest>,
    ) -> ServiceResult<DeletePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_preset_core(&self.state, &user, request.org_id, request.preset_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeletePresetResponse::default())
    }
}

fn create_body(request: CreatePresetRequest) -> AppResult<CreatePresetBody> {
    let project_spec = request.project_spec.into_option().ok_or_else(|| {
        coded(
            axum::http::StatusCode::BAD_REQUEST,
            "project_spec_required",
            "project_spec is required",
        )
    })?;
    Ok(CreatePresetBody {
        name: request.name,
        slug: request.slug,
        description: request.description,
        default_ttl_seconds: request.default_ttl_seconds,
        project_spec: decode_project_spec(project_spec)?,
    })
}

fn update_body(request: UpdatePresetRequest) -> AppResult<UpdatePresetBody> {
    Ok(UpdatePresetBody {
        name: request.name,
        description: request.description,
        slug: request.slug,
        default_ttl_seconds: request.default_ttl_seconds,
        project_spec: request
            .project_spec
            .into_option()
            .map(decode_project_spec)
            .transpose()?,
    })
}

fn decode_project_spec(
    project_spec: codewire_proto::codewire::v1::ProjectSpec,
) -> AppResult<codewire_project::ProjectSpec> {
    codewire_project_proto::from_proto(project_spec).map_err(|error| {
        coded_owned(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_project_spec",
            error.to_string(),
        )
    })
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn create_preset_validation(error: AppError, name_missing: bool) -> AppError {
    if name_missing
        && matches!(
            &error,
            AppError::Coded {
                code: "name_required",
                ..
            }
        )
    {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/name"),
                message: Cow::Borrowed("name is required"),
            }],
        }
    } else {
        error
    }
}

pub(crate) fn proto_preset(preset: PresetWire) -> AppResult<Preset> {
    Ok(Preset {
        id: preset.id,
        org_id: preset.org_id,
        name: preset.name,
        slug: preset.slug,
        language: preset.language,
        official: preset.official,
        description: preset.description,
        build_status: preset.build_status,
        build_error: preset.build_error,
        default_ttl_seconds: preset.default_ttl_seconds,
        created_at: Some(proto_timestamp(&preset.created_at)?).into(),
        project_spec: Some(codewire_project_proto::to_proto(preset.project_spec)).into(),
        ..Default::default()
    })
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, created_at = value, "preset timestamp invalid");
        AppError::InternalMsg("failed to map preset timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    #[test]
    fn create_mapping_requires_one_canonical_project_spec() {
        let error = create_body(CreatePresetRequest::default()).unwrap_err();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "project_spec_required",
                ..
            }
        ));

        let body = create_body(CreatePresetRequest {
            name: "Default".into(),
            project_spec: Some(codewire_project_proto::to_proto(
                codewire_project::ProjectSpec::default(),
            ))
            .into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(body.name, "Default");
        assert_eq!(body.project_spec, codewire_project::ProjectSpec::default());
    }

    #[test]
    fn update_mapping_preserves_absent_and_present_whole_project_spec() {
        let absent = update_body(UpdatePresetRequest::default()).unwrap();
        assert!(absent.slug.is_none());
        assert!(absent.project_spec.is_none());

        let mut spec = codewire_project::ProjectSpec::default();
        spec.environment.insert("RUST_LOG".into(), "debug".into());
        let present = update_body(UpdatePresetRequest {
            slug: Some(String::new()),
            project_spec: Some(codewire_project_proto::to_proto(spec.clone())).into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(present.slug.as_deref(), Some(""));
        assert_eq!(present.project_spec, Some(spec));
    }

    #[test]
    fn preset_mapping_keeps_presence_and_proto_json_names() {
        let preset = proto_preset(PresetWire {
            id: "preset_123".into(),
            org_id: Some("org_123".into()),
            name: "Rust".into(),
            slug: Some("rust".into()),
            language: Some("rust".into()),
            official: false,
            description: None,
            build_status: "ready".into(),
            build_error: None,
            default_ttl_seconds: Some(3_600),
            project_spec: codewire_project::ProjectSpec {
                environment: [("RUST_LOG".into(), "info".into())].into_iter().collect(),
                ..Default::default()
            },
            created_at: "2026-07-18T03:10:02Z".into(),
        })
        .unwrap();
        let json = serde_json::to_value(preset).unwrap();
        assert_eq!(json["orgId"], "org_123");
        assert_eq!(json["projectSpec"]["environment"]["RUST_LOG"], "info");
        assert_eq!(json["createdAt"], "2026-07-18T03:10:02Z");
        assert!(json.get("description").is_none());
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
    fn missing_preset_name_names_the_name_proto_field() {
        let error = create_preset_validation(
            AppError::Coded {
                status: axum::http::StatusCode::BAD_REQUEST,
                code: "name_required",
                detail: "name is required".into(),
            },
            true,
        );
        let rendered = ConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("missing BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "name");
        assert!(!detail.field_violations[0].description.is_empty());
    }
}
