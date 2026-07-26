//! `/user/ssh-key` + `/user/git-identity` (#38).
//!
//! User-scoped SSH-key + git-identity management:
//! - `GET  /api/v1/user/ssh-key` returns the user's public key + fingerprint,
//!   **lazy-generating** an Ed25519 keypair on first access (a side-effecting
//!   GET — replicated faithfully). The private key is stored in the tenant
//!   secret store at `/users/{user_id}` under `SSH_PRIVATE_KEY`; only the
//!   public key + fingerprint live in `user_ssh_keys`.
//! - `POST /api/v1/user/ssh-key/regenerate` replaces the keypair and stamps
//!   `regenerated_at`.
//! - `GET/PUT /api/v1/user/git-identity` read/write the resolved git author
//!   name + email on `users` (pure DB — no secret store).
//!
//! Wire-parity notes (byte-for-byte with the Go huma handlers):
//! - huma single-object success bodies carried the `$schema` link on the Go
//!   side (accepted drift). Errors are the bare huma
//!   `{status,title,detail}` envelope via `AppError`.
//! - `created_at` / `regenerated_at` use the shared `format_time`
//!   (`time.RFC3339` seconds UTC, trailing `Z`); `regenerated_at` is
//!   `omitempty` (`Option`, skipped when `None`) — matching Go's
//!   `*string \`json:"regenerated_at,omitempty"\``.
//! - The public key is OpenSSH `authorized_keys` form with a trailing newline,
//!   matching Go's `ssh.MarshalAuthorizedKey`; the fingerprint is the shared
//!   `SHA256:…` no-pad form (`login_keys::ssh_fingerprint`), matching
//!   `ssh.FingerprintSHA256`.

use axum::Json;
use axum::extract::State;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiState;
use super::account::service::{self, GitIdentityRecord, SshKeyRecord, UpdateGitIdentityParams};
use super::environments::format_time;

// ── Wire types ───────────────────────────────────────────────────────────

/// Mirrors `api.SSHKeyResponse`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SSHKeyResponse {
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regenerated_at: Option<String>,
}

/// Mirrors `api.GitIdentityResponse`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct GitIdentityResponse {
    pub git_name: String,
    pub git_email: String,
}

/// Mirrors `api.UpdateGitIdentityBody` (both nullable — `null` clears).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct UpdateGitIdentityBody {
    #[serde(default)]
    pub git_name: Option<String>,
    #[serde(default)]
    pub git_email: Option<String>,
}

fn rest_ssh_key(record: SshKeyRecord) -> SSHKeyResponse {
    SSHKeyResponse {
        public_key: record.public_key,
        fingerprint: record.fingerprint,
        created_at: format_time(record.created_at),
        regenerated_at: record.regenerated_at.map(format_time),
    }
}

fn rest_git_identity(record: GitIdentityRecord) -> GitIdentityResponse {
    GitIdentityResponse {
        git_name: record.git_name,
        git_email: record.git_email,
    }
}

// ── SSH-key handlers ─────────────────────────────────────────────────────

/// `GET /api/v1/user/ssh-key` — mirrors `getSSHKey` (lazy-generates if absent).
pub async fn get_ssh_key(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<SSHKeyResponse>> {
    // REST intentionally preserves the old lazy-create GET. Connect exposes
    // that mutation as EnsureSshKey and keeps GetSshKey pure.
    Ok(Json(rest_ssh_key(
        service::ensure_ssh_key(&state, &user).await?,
    )))
}

/// `POST /api/v1/user/ssh-key/regenerate` — mirrors `regenerateSSHKey`.
pub async fn regenerate_ssh_key(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<SSHKeyResponse>> {
    Ok(Json(rest_ssh_key(
        service::regenerate_ssh_key(&state, &user).await?,
    )))
}

// ── Git-identity handlers ────────────────────────────────────────────────

/// `GET /api/v1/user/git-identity` — mirrors `getGitIdentity`.
pub async fn get_git_identity(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<GitIdentityResponse>> {
    Ok(Json(rest_git_identity(
        service::get_git_identity(&state, &user).await?,
    )))
}

/// `PUT /api/v1/user/git-identity` — mirrors `updateGitIdentity`.
pub async fn update_git_identity(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<UpdateGitIdentityBody>,
) -> AppResult<Json<GitIdentityResponse>> {
    Ok(Json(rest_git_identity(
        service::update_git_identity(
            &state,
            &user,
            UpdateGitIdentityParams {
                git_name: body.git_name,
                git_email: body.git_email,
            },
        )
        .await?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn ssh_key_response_omits_regenerated_at_when_none() {
        let v = serde_json::to_value(SSHKeyResponse {
            public_key: "ssh-ed25519 AAAA\n".into(),
            fingerprint: "SHA256:abc".into(),
            created_at: "2026-06-20T00:00:00Z".into(),
            regenerated_at: None,
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("regenerated_at"), "omitempty when None");
        for k in ["public_key", "fingerprint", "created_at"] {
            assert!(obj.contains_key(k), "{k} present");
        }
    }

    #[test]
    fn update_git_identity_validation_accepts_partial_and_null_fields() {
        let empty =
            validate_value::<UpdateGitIdentityBody>(serde_json::json!({})).expect("empty update");
        assert_eq!(empty.git_name, None);
        assert_eq!(empty.git_email, None);

        let cleared = validate_value::<UpdateGitIdentityBody>(serde_json::json!({
            "git_name": null,
            "git_email": null
        }))
        .expect("null clears are valid");
        assert_eq!(cleared.git_name, None);
        assert_eq!(cleared.git_email, None);
    }

    #[test]
    fn update_git_identity_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdateGitIdentityBody>(serde_json::json!({
                "git_name": 7
            }))
        else {
            panic!("expected type-invalid git_name to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/git_name");
        assert!(errors[0].message.contains("string"));
    }
}
