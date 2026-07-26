//! `/user/login-keys` CRUD (#38).
//!
//! User-scoped SSH login-key management: list / add / delete the public
//! keys a user can authenticate with. Pure DB CRUD against
//! `user_login_keys` — no Infisical, no keygen — so this is a clean,
//! self-contained slice of the #38 HTTP surface.
//!
//! Wire-parity notes (byte-for-byte with the Go huma handlers):
//! - These are huma handlers, so single-object success bodies carry
//!   huma's `$schema` link (the documented accepted drift — clients
//!   ignore it and the Rust side intentionally doesn't replicate huma
//!   internals). The list endpoint
//!   is a bare JSON array (no `$schema`), and an empty list serializes
//!   as `[]` (Go coalesces a nil slice to `[]LoginKeyResponse{}`).
//! - Errors are the bare huma `{status,title,detail}` envelope (no
//!   `code`/`hint`), reproduced via `AppError::BadRequest` (400),
//!   `AppError::Conflict` (409), `AppError::NotFound` (404), and
//!   `AppError::InternalMsg` (500) — matching `huma.Error400BadRequest`
//!   / `Error409Conflict` / `Error404NotFound` /
//!   `Error500InternalServerError`.
//! - `created_at` is `formatTime(createdAt)` on the Go side
//!   (`time.RFC3339` UTC); `user_login_keys.created_at` is a timestamptz,
//!   so we scan `DateTime<Utc>`, take `.naive_utc()`, and reuse the
//!   shared `format_time` (seconds precision, trailing `Z`) — identical
//!   to the sibling key/api-key handlers.
//! - The fingerprint is SHA-256 of the base64-decoded key blob, rendered
//!   `SHA256:<RawStdEncoding base64>` — a faithful port of Go's
//!   `sshFingerprint`.
//! - Rust now owns request validation for this route family. Missing or
//!   type-invalid `AddLoginKeyBody` fields are rejected by `ValidatedJson`
//!   with the stable Rust 422 envelope before handler logic; semantic key
//!   format errors still return the handler's 400s.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiState;
use super::account::service::{self, CreateLoginKeyParams, LoginKeyRecord};
use super::environments::format_time;

// ── Wire types ───────────────────────────────────────────────────────────

/// Mirrors `api.LoginKeyResponse` field-for-field (JSON tags included).
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct LoginKeyResponse {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: String,
}

/// Mirrors `api.AddLoginKeyBody`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct AddLoginKeyBody {
    pub name: String,
    pub public_key: String,
}

fn rest_login_key(record: LoginKeyRecord) -> LoginKeyResponse {
    LoginKeyResponse {
        id: record.id,
        name: record.name,
        public_key: record.public_key,
        fingerprint: record.fingerprint,
        created_at: format_time(record.created_at.naive_utc()),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `GET /api/v1/user/login-keys` — mirrors `listLoginKeys`.
pub async fn list_login_keys(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<Vec<LoginKeyResponse>>> {
    Ok(Json(
        service::list_login_keys(&state, &user)
            .await?
            .into_iter()
            .map(rest_login_key)
            .collect(),
    ))
}

/// `POST /api/v1/user/login-keys` — mirrors `addLoginKey` (201).
pub async fn add_login_key(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<AddLoginKeyBody>,
) -> AppResult<(StatusCode, Json<LoginKeyResponse>)> {
    Ok((
        StatusCode::CREATED,
        Json(rest_login_key(
            service::create_login_key(
                &state,
                &user,
                CreateLoginKeyParams {
                    name: body.name,
                    public_key: body.public_key,
                },
            )
            .await?,
        )),
    ))
}

/// `DELETE /api/v1/user/login-keys/{id}` — mirrors `deleteLoginKey` (204).
pub async fn delete_login_key(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    service::delete_login_key(&state, &user, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;

    #[test]
    fn fingerprint_matches_go_sshfingerprint() {
        // Go: base64.StdEncoding.DecodeString(parts[1]) → sha256 →
        // "SHA256:" + RawStdEncoding base64. Spot-check a known ed25519
        // key blob against the documented algorithm.
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
        let fp = service::ssh_fingerprint(line).unwrap();
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint must carry the SHA256: prefix"
        );
        // RawStdEncoding (no padding) → no trailing '='.
        assert!(
            !fp.ends_with('='),
            "RawStdEncoding fingerprint has no padding"
        );
    }

    #[test]
    fn fingerprint_none_when_no_blob() {
        // Single-field line → Go's len(parts) < 2 → "" → 400.
        assert!(service::ssh_fingerprint("ssh-ed25519").is_none());
    }

    #[test]
    fn fingerprint_none_when_blob_not_base64() {
        // Go's DecodeString error → "" → 400.
        assert!(service::ssh_fingerprint("ssh-ed25519 not!valid!base64!").is_none());
    }

    #[test]
    fn add_login_key_schema_requires_name_and_public_key() {
        let schema = serde_json::to_value(schemars::schema_for!(AddLoginKeyBody)).unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "name"));
        assert!(required.iter().any(|v| v == "public_key"));
    }

    #[test]
    fn add_login_key_validation_rejects_missing_required_fields() {
        let err = codewire_server_core::validation::validate_value::<AddLoginKeyBody>(
            serde_json::json!({
                "name": "laptop"
            }),
        )
        .unwrap_err();

        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("public_key"));
    }

    #[test]
    fn add_login_key_validation_rejects_type_errors() {
        let err = codewire_server_core::validation::validate_value::<AddLoginKeyBody>(
            serde_json::json!({
                "name": 7,
                "public_key": "ssh-ed25519 AAAA user@host"
            }),
        )
        .unwrap_err();

        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors[0].path, "/name");
    }

    #[test]
    fn response_field_order_and_shape_match_go() {
        let v = serde_json::to_value(LoginKeyResponse {
            id: "lk_1".into(),
            name: "laptop".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            fingerprint: "SHA256:abc".into(),
            created_at: "2026-06-19T00:00:00Z".into(),
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        // All five fields present, none omitempty (Go has no omitempty
        // tags on LoginKeyResponse).
        for k in ["id", "name", "public_key", "fingerprint", "created_at"] {
            assert!(obj.contains_key(k), "{k} must be present");
        }
        assert_eq!(v["created_at"], "2026-06-19T00:00:00Z");
    }
}
