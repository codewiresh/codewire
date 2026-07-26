//! `/organizations/{org_id}/api-keys` CRUD (#38).
//!
//! These are huma handlers on the Go side, so the error envelope is the
//! bare `{status,title,detail}` shape (no `code`/`hint`) — reproduced
//! here with [`AppError::NotFound`]/`BadRequest` and, for the
//! admin-only delete gate, `AppError::Coded` with an empty code (Go's
//! `huma.Error403Forbidden`).
//!
//! Org membership is resolved with `user_org_role` directly (not the
//! environments' `require_org_member`, whose 404 carries an
//! `org_not_found` code the huma handlers don't emit).

pub(crate) mod service;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use self::service::{ApiKeyRecord, CreateApiKeyParams, UpdateApiKeyParams};
use super::ApiState;
use super::environments::format_time;

#[cfg(test)]
use self::service::{MAX_API_KEY_EXPIRES_IN_DAYS, api_key_expires_at};
#[cfg(test)]
use codewire_server_core::AppError;

// ── Wire types ───────────────────────────────────────────────────────────

/// Mirrors `api.APIKey`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub org_id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by_email: String,
}

/// Mirrors `api.CreateAPIKeyResponse` (APIKey flattened + the one-time
/// raw key).
#[derive(Debug, Serialize, JsonSchema)]
pub struct CreateApiKeyResponse {
    #[serde(flatten)]
    pub api_key: ApiKey,
    pub key: String,
}

/// Mirrors `api.CreateAPIKeyBody`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CreateApiKeyBody {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub expires_in_days: Option<i32>,
}

/// Mirrors `api.UpdateAPIKeyBody`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UpdateApiKeyBody {
    #[serde(default)]
    pub disabled: Option<bool>,
}

// ── REST mapping ─────────────────────────────────────────────────────────

fn rest_api_key(record: ApiKeyRecord) -> ApiKey {
    ApiKey {
        id: record.id,
        user_id: record.user_id,
        org_id: record.org_id,
        name: record.name,
        key_prefix: record.key_prefix,
        scopes: record.scopes,
        last_used_at: record.last_used_at.map(format_time),
        expires_at: record.expires_at.map(format_time),
        disabled_at: record.disabled_at.map(format_time),
        created_at: format_time(record.created_at),
        created_by_name: record.created_by_name,
        created_by_email: record.created_by_email,
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `POST /organizations/{org_id}/api-keys` — mirrors `createAPIKey`.
pub async fn create_api_key(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(body): ValidatedJson<CreateApiKeyBody>,
) -> AppResult<(StatusCode, Json<CreateApiKeyResponse>)> {
    let created = service::create(
        &state.pool,
        &user,
        &org_id,
        CreateApiKeyParams {
            name: body.name,
            scopes: body.scopes,
            expires_in_days: body.expires_in_days,
        },
    )
    .await?;

    let resp = CreateApiKeyResponse {
        api_key: rest_api_key(created.record),
        key: created.raw_key,
    };

    Ok((StatusCode::CREATED, Json(resp)))
}

/// `GET /organizations/{org_id}/api-keys` — mirrors `listAPIKeys`.
pub async fn list_api_keys(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<ApiKey>>> {
    let keys = service::list(&state.pool, &user, &org_id)
        .await?
        .into_iter()
        .map(rest_api_key)
        .collect();

    Ok(Json(keys))
}

/// `PATCH /organizations/{org_id}/api-keys/{key_id}` — mirrors
/// `updateAPIKey` (disable/enable).
pub async fn update_api_key(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, key_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<UpdateApiKeyBody>,
) -> AppResult<Json<ApiKey>> {
    let key = service::update(
        &state.pool,
        &user,
        &org_id,
        &key_id,
        UpdateApiKeyParams {
            disabled: body.disabled,
        },
    )
    .await?;
    Ok(Json(rest_api_key(key)))
}

/// `DELETE /organizations/{org_id}/api-keys/{key_id}` — mirrors
/// `deleteAPIKey` (owner/admin only).
pub async fn delete_api_key(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, key_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    service::delete(&state.pool, &user, &org_id, &key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    fn sample() -> ApiKey {
        ApiKey {
            id: "ak_1".into(),
            user_id: "usr_1".into(),
            org_id: "org_1".into(),
            name: "ci".into(),
            key_prefix: "abcd1234".into(),
            scopes: vec![],
            last_used_at: None,
            expires_at: None,
            disabled_at: None,
            created_at: "2026-06-13T00:00:00Z".into(),
            created_by_name: String::new(),
            created_by_email: String::new(),
        }
    }

    #[test]
    fn api_key_omits_empty_optionals_like_go() {
        let v = serde_json::to_value(sample()).unwrap();
        let obj = v.as_object().unwrap();
        // scopes (no omitempty) and created_at are always present.
        assert_eq!(v["scopes"], serde_json::json!([]));
        assert_eq!(v["created_at"], "2026-06-13T00:00:00Z");
        // Empty/None fields are absent, matching Go's omitempty tags.
        for k in [
            "last_used_at",
            "expires_at",
            "disabled_at",
            "created_by_name",
            "created_by_email",
        ] {
            assert!(obj.get(k).is_none(), "{k} should be omitted when empty");
        }
    }

    #[test]
    fn create_response_flattens_api_key_and_adds_key() {
        let resp = CreateApiKeyResponse {
            api_key: sample(),
            key: "cw_secret".into(),
        };
        let v = serde_json::to_value(&resp).unwrap();
        // Flattened: APIKey fields sit at the top level alongside `key`.
        assert_eq!(v["id"], "ak_1");
        assert_eq!(v["key"], "cw_secret");
        assert_eq!(v["key_prefix"], "abcd1234");
    }

    #[test]
    fn create_api_key_body_keeps_name_handler_required() {
        let schema = serde_json::to_value(schemars::schema_for!(CreateApiKeyBody)).unwrap();
        assert!(
            schema.get("required").is_none(),
            "Go does not mark name required in the schema; the handler returns 400 when it is blank"
        );

        let parsed = validate_value::<CreateApiKeyBody>(serde_json::json!({}))
            .expect("missing fields default");
        assert_eq!(parsed.name, "");
        assert_eq!(parsed.scopes, None);
        assert_eq!(parsed.expires_in_days, None);
    }

    #[test]
    fn create_api_key_validation_rejects_type_errors() {
        let err = validate_value::<CreateApiKeyBody>(serde_json::json!({
            "name": "deploy",
            "scopes": "read"
        }))
        .expect_err("type-invalid scopes should be rejected before the handler");

        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/scopes");
        assert!(errors[0].message.contains("array"));
    }

    #[test]
    fn api_key_expiry_accepts_omitted_and_bounded_days() {
        assert_eq!(api_key_expires_at(None).unwrap(), None);
        assert!(api_key_expires_at(Some(1)).unwrap().is_some());
        assert!(
            api_key_expires_at(Some(MAX_API_KEY_EXPIRES_IN_DAYS))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn api_key_expiry_rejects_non_positive_and_huge_days() {
        for days in [0, -1, MAX_API_KEY_EXPIRES_IN_DAYS + 1, 100_000_000] {
            let Err(AppError::BadRequest(detail)) = api_key_expires_at(Some(days)) else {
                panic!("expected bad request for {days}");
            };
            assert!(
                detail.contains("expires_in_days must be between"),
                "unexpected detail for {days}: {detail}"
            );
        }
    }

    #[test]
    fn update_api_key_body_keeps_disabled_handler_required() {
        let parsed = validate_value::<UpdateApiKeyBody>(serde_json::json!({}))
            .expect("missing disabled defaults");
        assert_eq!(parsed.disabled, None);
    }

    #[test]
    fn update_api_key_validation_rejects_type_errors() {
        let err = validate_value::<UpdateApiKeyBody>(serde_json::json!({
            "disabled": "true"
        }))
        .expect_err("type-invalid disabled should be rejected before the handler");

        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/disabled");
        assert!(errors[0].message.contains("boolean"));
    }
}
