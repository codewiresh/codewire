//! `/git-credentials` CRUD (#38).
//!
//! User-scoped git credentials for non-GitHub forges: the credential
//! metadata (name/host/auth_type/username) lives in `user_git_credentials`;
//! the password/token is stored in the tenant `SecretStore` at
//! `/users/{user_id}` under the host-derived key `GIT_TOKEN_<HOST>`.
//!
//! Wire-parity notes (byte-for-byte with the Go huma handlers):
//! - huma single-object success bodies carried the `$schema` link on the Go
//!   side (accepted drift). The list endpoint is a bare array,
//!   `[]` when empty (Go `make([]GitCredential, 0)`). Errors are the bare
//!   `{status,title,detail}` envelope via `AppError`.
//! - `created_at`/`updated_at` are Go `time.Time` JSON fields (RFC3339Nano,
//!   trailing-zero-trimmed), NOT the seconds-precision `format_time` used by
//!   the login/ssh-key ports — `format_time_go` reproduces Go's
//!   `time.Time.MarshalJSON` exactly.
//! - `username` is `*string` `json:",omitempty"`: omitted only when the
//!   pointer is nil → `Option<String>` skipped when `None`.
//! - Rust now owns request validation for this route family. Missing
//!   required create fields and type-invalid create/update fields are
//!   rejected by `ValidatedJson` with the stable Rust 422 envelope before
//!   handler DB/secret-store work. Semantic host/auth-type errors still
//!   return the handler's 400s.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiState;
use super::account::service::{
    self, CreateGitCredentialParams, GitCredentialRecord, UpdateGitCredentialParams,
};

// ── Wire types ───────────────────────────────────────────────────────────

/// Mirrors `api.GitCredential`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct GitCredential {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub host: String,
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Mirrors `CreateGitCredentialInput.Body`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct CreateGitCredentialBody {
    pub name: String,
    pub host: String,
    pub auth_type: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
}

/// Mirrors `UpdateGitCredentialInput.Body` (all optional).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct UpdateGitCredentialBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Reproduces Go's `time.Time.MarshalJSON` (RFC3339Nano): up to 9 fractional
/// digits with trailing zeros (and a bare `.`) trimmed, `Z` for UTC.
fn format_time_go(dt: chrono::DateTime<chrono::Utc>) -> String {
    let s = dt.format("%Y-%m-%dT%H:%M:%S%.9f").to_string();
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    format!("{trimmed}Z")
}

fn rest_git_credential(record: GitCredentialRecord) -> GitCredential {
    GitCredential {
        id: record.id,
        user_id: record.user_id,
        name: record.name,
        host: record.host,
        auth_type: record.auth_type,
        username: record.username,
        created_at: format_time_go(record.created_at),
        updated_at: format_time_go(record.updated_at),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `GET /api/v1/git-credentials` — mirrors `listGitCredentials`.
pub async fn list_git_credentials(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<Vec<GitCredential>>> {
    Ok(Json(
        service::list_git_credentials(&state, &user)
            .await?
            .into_iter()
            .map(rest_git_credential)
            .collect(),
    ))
}

/// `POST /api/v1/git-credentials` — mirrors `createGitCredential` (201).
pub async fn create_git_credential(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<CreateGitCredentialBody>,
) -> AppResult<(StatusCode, Json<GitCredential>)> {
    Ok((
        StatusCode::CREATED,
        Json(rest_git_credential(
            service::create_git_credential(
                &state,
                &user,
                CreateGitCredentialParams {
                    name: body.name,
                    host: body.host,
                    auth_type: body.auth_type,
                    username: body.username,
                    password: body.password,
                },
            )
            .await?,
        )),
    ))
}

/// `PUT /api/v1/git-credentials/{credentialId}` — mirrors `updateGitCredential`.
pub async fn update_git_credential(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(credential_id): Path<String>,
    ValidatedJson(body): ValidatedJson<UpdateGitCredentialBody>,
) -> AppResult<Json<GitCredential>> {
    Ok(Json(rest_git_credential(
        service::update_git_credential(
            &state,
            &user,
            &credential_id,
            UpdateGitCredentialParams {
                name: body.name,
                username: body.username,
                password: body.password,
            },
        )
        .await?,
    )))
}

/// `DELETE /api/v1/git-credentials/{credentialId}` — mirrors `deleteGitCredential` (204).
pub async fn delete_git_credential(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(credential_id): Path<String>,
) -> AppResult<StatusCode> {
    service::delete_git_credential(&state, &user, &credential_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn format_time_go_trims_like_rfc3339nano() {
        use chrono::{TimeZone, Timelike};
        // Whole second → no fractional part (Go omits it).
        let whole = chrono::Utc.with_ymd_and_hms(2026, 6, 20, 12, 0, 0).unwrap();
        assert_eq!(format_time_go(whole), "2026-06-20T12:00:00Z");
        // Sub-second → trailing zeros trimmed.
        let frac = chrono::Utc
            .with_ymd_and_hms(2026, 6, 20, 12, 0, 0)
            .unwrap()
            .with_nanosecond(123_000_000)
            .unwrap();
        assert_eq!(format_time_go(frac), "2026-06-20T12:00:00.123Z");
    }

    #[test]
    fn credential_omits_username_when_none() {
        let v = serde_json::to_value(GitCredential {
            id: "gc_1".into(),
            user_id: "u1".into(),
            name: "gitea".into(),
            host: "git.example.com".into(),
            auth_type: "basic".into(),
            username: None,
            created_at: "2026-06-20T12:00:00Z".into(),
            updated_at: "2026-06-20T12:00:00Z".into(),
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("username"), "omitempty when None");
        for k in [
            "id",
            "user_id",
            "name",
            "host",
            "auth_type",
            "created_at",
            "updated_at",
        ] {
            assert!(obj.contains_key(k), "{k} present");
        }
    }

    #[test]
    fn create_git_credential_schema_requires_create_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CreateGitCredentialBody)).unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["name", "host", "auth_type", "password"]),
            "create requires presence of the Go-required fields; username stays optional"
        );
    }

    #[test]
    fn create_git_credential_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateGitCredentialBody>(serde_json::json!({
                "name": "gitea",
                "host": "git.example.com",
                "auth_type": "basic"
            }))
        else {
            panic!("expected missing password to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("password"));
    }

    #[test]
    fn create_git_credential_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateGitCredentialBody>(serde_json::json!({
                "name": "gitea",
                "host": "git.example.com",
                "auth_type": "basic",
                "username": 7,
                "password": "token"
            }))
        else {
            panic!("expected type-invalid username to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/username");
        assert!(errors[0].message.contains("string"));
    }

    #[test]
    fn update_git_credential_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdateGitCredentialBody>(serde_json::json!({
                "password": false
            }))
        else {
            panic!("expected type-invalid password to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/password");
        assert!(errors[0].message.contains("string"));
    }
}
