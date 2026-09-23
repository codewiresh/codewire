//! Connect-RPC adapter for the organization-scoped API-key service.
//!
//! This module maps `crate::api::api_keys::service` to Connect requests,
//! pagination, errors, and protobuf.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::NaiveDateTime;
use codewire_proto::codewire::v1::{
    ApiKey, ApiKeyService, CreateApiKeyRequest, CreateApiKeyResponse, DeleteApiKeyRequest,
    DeleteApiKeyResponse, ListApiKeysRequest, ListApiKeysResponse, UpdateApiKeyRequest,
    UpdateApiKeyResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::api::api_keys::service::{
    self, ApiKeyRecord, CreateApiKeyParams, MAX_API_KEY_EXPIRES_IN_DAYS, UpdateApiKeyParams,
};

/// Registers the four ApiKeyService RPCs on their generated Connect routes.
pub fn router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(ApiKeyConnectService { pool }))
}

struct ApiKeyConnectService {
    pool: PgPool,
}

#[allow(refining_impl_trait)]
impl ApiKeyService for ApiKeyConnectService {
    async fn list_api_keys(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListApiKeysRequest>,
    ) -> ServiceResult<ListApiKeysResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();

        validate_pagination(request.page_size, request.page_token)
            .map_err(|err| rpc_app_error(&err, &ctx))?;

        let api_keys = service::list(&self.pool, &user, request.org_id)
            .await
            .map_err(|err| rpc_app_error(&err, &ctx))?;

        connectrpc::Response::ok(ListApiKeysResponse {
            api_keys: api_keys.into_iter().map(proto_api_key).collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_api_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateApiKeyRequest>,
    ) -> ServiceResult<CreateApiKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_create(request.name, request.expires_in_days)
            .map_err(|err| rpc_app_error(&err, &ctx))?;

        let created = service::create(
            &self.pool,
            &user,
            request.org_id,
            CreateApiKeyParams {
                name: request.name.to_owned(),
                scopes: Some(
                    request
                        .scopes
                        .iter()
                        .map(|scope| (*scope).to_owned())
                        .collect(),
                ),
                expires_in_days: request.expires_in_days,
            },
        )
        .await
        .map_err(|err| rpc_app_error(&err, &ctx))?;

        connectrpc::Response::ok(CreateApiKeyResponse {
            api_key: Some(proto_api_key(created.record)).into(),
            key: created.raw_key,
            ..Default::default()
        })
    }

    async fn update_api_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateApiKeyRequest>,
    ) -> ServiceResult<UpdateApiKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_update(request.disabled).map_err(|err| rpc_app_error(&err, &ctx))?;

        let api_key = service::update(
            &self.pool,
            &user,
            request.org_id,
            request.key_id,
            UpdateApiKeyParams {
                disabled: request.disabled,
            },
        )
        .await
        .map_err(|err| rpc_app_error(&err, &ctx))?;

        connectrpc::Response::ok(UpdateApiKeyResponse {
            api_key: Some(proto_api_key(api_key)).into(),
            ..Default::default()
        })
    }

    async fn delete_api_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteApiKeyRequest>,
    ) -> ServiceResult<DeleteApiKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();

        service::delete(&self.pool, &user, request.org_id, request.key_id)
            .await
            .map_err(|err| rpc_app_error(&err, &ctx))?;

        connectrpc::Response::ok(DeleteApiKeyResponse::default())
    }
}

fn validate_create(name: &str, expires_in_days: Option<i32>) -> Result<(), AppError> {
    let mut errors = Vec::new();
    if !service::name_is_valid(name) {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/name"),
            message: Cow::Borrowed("must not be blank"),
        });
    }
    if !service::expires_in_days_is_valid(expires_in_days) {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/expires_in_days"),
            message: Cow::Owned(format!(
                "must be between 1 and {MAX_API_KEY_EXPIRES_IN_DAYS}"
            )),
        });
    }
    validation_result(errors)
}

fn validate_update(disabled: Option<bool>) -> Result<(), AppError> {
    let errors = if service::disabled_is_present(disabled) {
        Vec::new()
    } else {
        vec![ValidationIssue {
            path: Cow::Borrowed("/disabled"),
            message: Cow::Borrowed("is required"),
        }]
    };
    validation_result(errors)
}

fn validate_pagination(_page_size: i32, page_token: &str) -> Result<(), AppError> {
    if !page_token.is_empty() {
        return Err(AppError::BadRequest("unrecognized page_token".into()));
    }
    Ok(())
}

fn validation_result(errors: Vec<ValidationIssue>) -> Result<(), AppError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn proto_timestamp(value: NaiveDateTime) -> Timestamp {
    let value = value.and_utc();
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn optional_proto_timestamp(
    value: Option<NaiveDateTime>,
) -> buffa::MessageField<Timestamp, buffa::Inline<Timestamp>> {
    value.map(proto_timestamp).into()
}

fn proto_api_key(record: ApiKeyRecord) -> ApiKey {
    ApiKey {
        id: record.id,
        user_id: record.user_id,
        org_id: record.org_id,
        name: record.name,
        key_prefix: record.key_prefix,
        scopes: record.scopes,
        last_used_at: optional_proto_timestamp(record.last_used_at),
        expires_at: optional_proto_timestamp(record.expires_at),
        disabled_at: optional_proto_timestamp(record.disabled_at),
        created_at: Some(proto_timestamp(record.created_at)).into(),
        created_by_name: record.created_by_name,
        created_by_email: record.created_by_email,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use codewire_server_core::connect_error::ConnectErrorDetail;
    use codewire_server_core::{ConnectCode, ConnectError};

    use super::*;

    fn rendered_validation(err: AppError) -> ConnectError {
        ConnectError::from_app_error(&err, Some("req_test"))
    }

    #[test]
    fn create_validation_uses_connect_bad_request_fields() {
        let err = validate_create(" \t", Some(0)).expect_err("both fields are invalid");
        let rendered = rendered_validation(err);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("expected BadRequest detail");
        };
        assert_eq!(detail.field_violations.len(), 2);
        assert_eq!(detail.field_violations[0].field, "name");
        assert_eq!(detail.field_violations[1].field, "expires_in_days");
    }

    #[test]
    fn update_validation_requires_presence_but_accepts_false() {
        let err = validate_update(None).expect_err("missing disabled must fail");
        let rendered = rendered_validation(err);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("expected BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "disabled");
        assert!(validate_update(Some(false)).is_ok());
        assert!(validate_update(Some(true)).is_ok());
    }

    #[test]
    fn timestamp_mapping_preserves_database_microseconds() {
        let value = NaiveDate::from_ymd_opt(2026, 7, 11)
            .unwrap()
            .and_hms_micro_opt(12, 34, 56, 123_456)
            .unwrap();
        let timestamp = proto_timestamp(value);
        assert_eq!(timestamp.nanos, 123_456_000);
        assert_eq!(timestamp.seconds, value.and_utc().timestamp());
    }

    #[test]
    fn valid_create_semantics_pass_through() {
        assert!(validate_create("deploy", None).is_ok());
        assert!(validate_create("deploy", Some(1)).is_ok());
        assert!(validate_create("deploy", Some(MAX_API_KEY_EXPIRES_IN_DAYS)).is_ok());
    }

    #[test]
    fn pagination_rejects_tokens_and_never_caps_the_complete_list() {
        let err = validate_pagination(10, "opaque")
            .expect_err("tokens are not recognized before real pagination exists");
        let rendered = ConnectError::from_app_error(&err, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        assert_eq!(rendered.message, "unrecognized page_token");

        for page_size in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
            assert!(validate_pagination(page_size, "").is_ok());
        }
    }
}
