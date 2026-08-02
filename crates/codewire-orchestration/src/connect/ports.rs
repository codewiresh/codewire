//! Connect-RPC adapter for environment ports.
//!
//! This module maps shared port service logic to protobuf, validates
//! pagination, and renders Connect errors.

use std::borrow::Cow;
use std::sync::Arc;

use buffa::EnumValue;
use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::v1::{
    CreatePortRequest, CreatePortResponse, DeletePortRequest, DeletePortResponse, ListPortsRequest,
    ListPortsResponse, Port as ProtoPort, PortAccess, PortService,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::environments::EnvironmentPort;
use crate::api::ports::{CreatePortBody, create_port_core, delete_port_core, list_ports_core};

/// Registers all three PortService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(PortConnectService { state }))
}

struct PortConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl PortService for PortConnectService {
    async fn list_ports(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListPortsRequest>,
    ) -> ServiceResult<ListPortsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let ports = list_ports_core(&self.state, &user, request.org_id, request.environment_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_port)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;

        connectrpc::Response::ok(ListPortsResponse {
            ports,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_port(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePortRequest>,
    ) -> ServiceResult<CreatePortResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let port_out_of_range = !(1..=65_535).contains(&request.port);
        let body = CreatePortBody {
            port: request.port,
            label: request.label.to_owned(),
            access: api_access(request.access),
        };
        let port = create_port_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            body,
        )
        .await
        .map_err(|error| {
            let error = create_port_validation(error, port_out_of_range);
            rpc_app_error(&error, &ctx)
        })?;

        connectrpc::Response::ok(CreatePortResponse {
            port: Some(proto_port(port).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn delete_port(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeletePortRequest>,
    ) -> ServiceResult<DeletePortResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_port_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.port_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;

        connectrpc::Response::ok(DeletePortResponse::default())
    }
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn create_port_validation(error: AppError, port_out_of_range: bool) -> AppError {
    if port_out_of_range && matches!(error, AppError::BadRequest(_)) {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/port"),
                message: Cow::Borrowed("port must be between 1 and 65535"),
            }],
        }
    } else {
        error
    }
}

fn api_access(access: EnumValue<PortAccess>) -> String {
    match access.as_known() {
        Some(PortAccess::Unspecified) => String::new(),
        Some(PortAccess::Public) => "public".into(),
        Some(PortAccess::OrgMembers) => "org_members".into(),
        Some(PortAccess::Creator) => "creator".into(),
        None => format!("unknown-enum-value-{}", access.to_i32()),
    }
}

fn proto_port(port: EnvironmentPort) -> AppResult<ProtoPort> {
    Ok(ProtoPort {
        id: port.id,
        environment_id: port.environment_id,
        port: port.port,
        label: port.label,
        access: proto_access(&port.access)?.into(),
        preview_url: (!port.preview_url.is_empty()).then_some(port.preview_url),
        created_at: Some(proto_timestamp(&port.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_access(access: &str) -> AppResult<PortAccess> {
    match access {
        "public" => Ok(PortAccess::Public),
        "org_members" => Ok(PortAccess::OrgMembers),
        "creator" => Ok(PortAccess::Creator),
        unexpected => {
            tracing::error!(access = unexpected, "stored port access is invalid");
            Err(AppError::InternalMsg("failed to map port access".into()))
        }
    }
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, created_at = value, "port timestamp invalid");
        AppError::InternalMsg("failed to map port timestamp".into())
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
    fn access_mapping_preserves_default_and_closed_vocabulary() {
        assert_eq!(api_access(PortAccess::Unspecified.into()), "");
        assert_eq!(api_access(PortAccess::Public.into()), "public");
        assert_eq!(api_access(PortAccess::OrgMembers.into()), "org_members");
        assert_eq!(api_access(PortAccess::Creator.into()), "creator");
        assert_eq!(api_access(EnumValue::Unknown(99)), "unknown-enum-value-99");

        assert_eq!(proto_access("public").unwrap(), PortAccess::Public);
        assert_eq!(proto_access("org_members").unwrap(), PortAccess::OrgMembers);
        assert_eq!(proto_access("creator").unwrap(), PortAccess::Creator);
        assert!(proto_access("future").is_err());
    }

    #[test]
    fn pagination_rejection_uses_invalid_argument() {
        assert!(validate_pagination("").is_ok());
        let error = validate_pagination("future").expect_err("token must be rejected");
        let rendered = ConnectError::from_app_error(&error, Some("req-port"));
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
    }

    #[test]
    fn range_validation_names_the_port_proto_field() {
        let error = create_port_validation(
            AppError::BadRequest("port must be between 1 and 65535".into()),
            true,
        );
        let rendered = ConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("missing BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "port");
        assert!(!detail.field_violations[0].description.is_empty());
    }

    #[test]
    fn shared_coded_errors_keep_error_info_reasons() {
        for (code, reason, expected) in [
            (
                "port_reserved",
                "PORT_RESERVED",
                ConnectCode::InvalidArgument,
            ),
            (
                "invalid_access",
                "INVALID_ACCESS",
                ConnectCode::InvalidArgument,
            ),
            ("port_conflict", "PORT_CONFLICT", ConnectCode::AlreadyExists),
            ("port_not_found", "PORT_NOT_FOUND", ConnectCode::NotFound),
        ] {
            let status = match code {
                "port_reserved" | "invalid_access" => axum::http::StatusCode::BAD_REQUEST,
                "port_conflict" => axum::http::StatusCode::CONFLICT,
                "port_not_found" => axum::http::StatusCode::NOT_FOUND,
                _ => unreachable!(),
            };
            let error = AppError::Coded {
                status,
                code,
                detail: "port contract error".into(),
            };
            let rendered = ConnectError::from_app_error(&error, Some("req-port"));
            assert_eq!(rendered.code, expected);
            let ConnectErrorDetail::ErrorInfo(info) = &rendered.details[0] else {
                panic!("{code} did not render ErrorInfo");
            };
            assert_eq!(info.reason, reason);
        }
    }

    #[test]
    fn proto_mapping_preserves_optional_preview_and_timestamp() {
        let port = proto_port(EnvironmentPort {
            id: "port_1".into(),
            environment_id: "env_1".into(),
            port: 8080,
            label: "web".into(),
            access: "public".into(),
            preview_url: String::new(),
            created_at: "2025-01-01T00:00:00Z".into(),
        })
        .unwrap();

        assert_eq!(port.access, PortAccess::Public);
        assert!(port.preview_url.is_none());
        assert_eq!(port.created_at.as_option().unwrap().seconds, 1_735_689_600);
    }
}
