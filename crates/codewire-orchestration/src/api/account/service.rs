//! Shared account service layer for AccountService.
//!
//! Transport adapters own wire validation and response formatting. Database,
//! secret-store, authorization, key generation, and lifecycle behavior live
//! here so every Connect procedure uses the same policy and persistence.

use base64::Engine;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use sha2::{Digest, Sha256};
use sqlx::Row;

use super::super::ApiState;

#[derive(Debug, Clone)]
pub(crate) struct LoginKeyRecord {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub(crate) struct CreateLoginKeyParams {
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SshKeyRecord {
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: chrono::NaiveDateTime,
    pub regenerated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitIdentityRecord {
    pub git_name: String,
    pub git_email: String,
}

#[derive(Debug, Clone)]
pub(crate) struct UpdateGitIdentityParams {
    pub git_name: Option<String>,
    pub git_email: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct GitCredentialRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub host: String,
    pub auth_type: String,
    pub username: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub(crate) struct CreateGitCredentialParams {
    pub name: String,
    pub host: String,
    pub auth_type: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct UpdateGitCredentialParams {
    pub name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

fn account_user_id(user: &AuthUser) -> AppResult<&str> {
    user.require_account_credential()?;
    Ok(&user.user_id)
}

/// SHA-256 of the base64-decoded public-key blob in OpenSSH fingerprint form.
pub(crate) fn ssh_fingerprint(public_key_line: &str) -> Option<String> {
    let mut fields = public_key_line.split_whitespace();
    let _algorithm = fields.next()?;
    let blob = fields.next()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    let hash = Sha256::digest(decoded);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash)
    ))
}

pub(crate) async fn list_login_keys(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<Vec<LoginKeyRecord>> {
    let user_id = account_user_id(user)?;
    let rows = sqlx::query(
        r#"SELECT id, name, public_key, fingerprint, created_at
           FROM user_login_keys WHERE user_id = $1 ORDER BY created_at"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "list login keys failed");
        AppError::InternalMsg("failed to list login keys".into())
    })?;

    // Preserve the legacy handler's skip-on-row-scan-error behavior.
    Ok(rows
        .iter()
        .filter_map(|row| {
            Some(LoginKeyRecord {
                id: row.try_get("id").ok()?,
                name: row.try_get("name").ok()?,
                public_key: row.try_get("public_key").ok()?,
                fingerprint: row.try_get("fingerprint").ok()?,
                created_at: row.try_get("created_at").ok()?,
            })
        })
        .collect())
}

pub(crate) async fn create_login_key(
    state: &ApiState,
    user: &AuthUser,
    params: CreateLoginKeyParams,
) -> AppResult<LoginKeyRecord> {
    let user_id = account_user_id(user)?;
    let public_key = params.public_key.trim();
    if !public_key.starts_with("ssh-") && !public_key.starts_with("ecdsa-") {
        return Err(AppError::BadRequest("invalid SSH public key format".into()));
    }

    let Some(fingerprint) = ssh_fingerprint(public_key) else {
        return Err(AppError::BadRequest(
            "could not compute key fingerprint — check key format".into(),
        ));
    };

    let exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1 FROM user_login_keys
             WHERE user_id = $1 AND fingerprint = $2
           )"#,
    )
    .bind(user_id)
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "check duplicate login key failed");
        AppError::InternalMsg("failed to check for duplicate key".into())
    })?;
    if exists {
        return Err(AppError::Conflict(
            "key with this fingerprint already exists".into(),
        ));
    }

    let row = sqlx::query(
        r#"INSERT INTO user_login_keys (user_id, name, public_key, fingerprint)
           VALUES ($1, $2, $3, $4)
           RETURNING id, created_at"#,
    )
    .bind(user_id)
    .bind(&params.name)
    .bind(public_key)
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "insert login key failed");
        AppError::InternalMsg("failed to add login key".into())
    })?;

    Ok(LoginKeyRecord {
        id: row.try_get("id").map_err(AppError::from)?,
        name: params.name,
        public_key: public_key.to_owned(),
        fingerprint,
        created_at: row.try_get("created_at").map_err(AppError::from)?,
    })
}

pub(crate) async fn delete_login_key(state: &ApiState, user: &AuthUser, id: &str) -> AppResult<()> {
    let user_id = account_user_id(user)?;
    let result = sqlx::query("DELETE FROM user_login_keys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "delete login key failed");
            AppError::InternalMsg("failed to delete login key".into())
        })?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("login key not found".into()));
    }
    Ok(())
}

fn generate_ssh_keypair() -> AppResult<(String, String, String)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| {
        tracing::error!(%error, "ssh-key: rng failed");
        AppError::InternalMsg("failed to generate ssh key".into())
    })?;
    let private_key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let public_line = private_key.public_key().to_openssh().map_err(|error| {
        tracing::error!(%error, "ssh-key: encode public key failed");
        AppError::InternalMsg("failed to generate ssh key".into())
    })?;
    let private_pem = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|error| {
            tracing::error!(%error, "ssh-key: encode private key failed");
            AppError::InternalMsg("failed to generate ssh key".into())
        })?
        .to_string();
    let fingerprint = ssh_fingerprint(&public_line).ok_or_else(|| {
        tracing::error!("ssh-key: fingerprint of generated key failed");
        AppError::InternalMsg("failed to generate ssh key".into())
    })?;
    Ok((format!("{public_line}\n"), private_pem, fingerprint))
}

fn user_secret_path(user_id: &str) -> String {
    format!("/users/{user_id}")
}

async fn store_private_key(state: &ApiState, user_id: &str, private_key: &str) -> AppResult<()> {
    state
        .secrets
        .create_folder_at_path("/users", user_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, "ssh-key: create folder failed");
            AppError::InternalMsg("failed to store ssh key".into())
        })?;
    state
        .secrets
        .set_secret_at_path(&user_secret_path(user_id), "SSH_PRIVATE_KEY", private_key)
        .await
        .map_err(|error| {
            tracing::error!(%error, "ssh-key: store private key failed");
            AppError::InternalMsg("failed to store ssh key".into())
        })?;
    Ok(())
}

async fn load_ssh_key(state: &ApiState, user_id: &str) -> AppResult<Option<SshKeyRecord>> {
    let row = sqlx::query(
        r#"SELECT public_key, key_fingerprint, created_at, regenerated_at
           FROM user_ssh_keys WHERE user_id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "ssh-key: load failed");
        AppError::InternalMsg("failed to load ssh key".into())
    })?;

    row.map(|row| {
        Ok(SshKeyRecord {
            public_key: row.try_get("public_key").map_err(AppError::from)?,
            fingerprint: row.try_get("key_fingerprint").map_err(AppError::from)?,
            created_at: row.try_get("created_at").map_err(AppError::from)?,
            regenerated_at: row.try_get("regenerated_at").map_err(AppError::from)?,
        })
    })
    .transpose()
}

async fn generate_and_store_ssh_key(state: &ApiState, user_id: &str) -> AppResult<SshKeyRecord> {
    let (public_key, private_key, fingerprint) = generate_ssh_keypair()?;
    store_private_key(state, user_id, &private_key).await?;

    let row = sqlx::query(
        r#"INSERT INTO user_ssh_keys (user_id, public_key, key_fingerprint, created_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (user_id) DO UPDATE
           SET public_key = $2, key_fingerprint = $3
           RETURNING created_at"#,
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "ssh-key: insert failed");
        AppError::InternalMsg("failed to store ssh key".into())
    })?;

    Ok(SshKeyRecord {
        public_key,
        fingerprint,
        created_at: row.try_get("created_at").map_err(AppError::from)?,
        regenerated_at: None,
    })
}

pub(crate) async fn get_ssh_key(state: &ApiState, user: &AuthUser) -> AppResult<SshKeyRecord> {
    let user_id = account_user_id(user)?;
    load_ssh_key(state, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("ssh key not found".into()))
}

pub(crate) async fn ensure_ssh_key(state: &ApiState, user: &AuthUser) -> AppResult<SshKeyRecord> {
    let user_id = account_user_id(user)?;
    if let Some(existing) = load_ssh_key(state, user_id).await? {
        return Ok(existing);
    }
    generate_and_store_ssh_key(state, user_id).await
}

pub(crate) async fn regenerate_ssh_key(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<SshKeyRecord> {
    let user_id = account_user_id(user)?;
    let (public_key, private_key, fingerprint) = generate_ssh_keypair()?;
    store_private_key(state, user_id, &private_key).await?;

    let row = sqlx::query(
        r#"INSERT INTO user_ssh_keys (
             user_id, public_key, key_fingerprint, created_at, regenerated_at
           )
           VALUES ($1, $2, $3, NOW(), NOW())
           ON CONFLICT (user_id) DO UPDATE
           SET public_key = $2, key_fingerprint = $3, regenerated_at = NOW()
           RETURNING created_at, regenerated_at"#,
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "ssh-key: upsert failed");
        AppError::InternalMsg("failed to store ssh key".into())
    })?;

    Ok(SshKeyRecord {
        public_key,
        fingerprint,
        created_at: row.try_get("created_at").map_err(AppError::from)?,
        regenerated_at: row.try_get("regenerated_at").map_err(AppError::from)?,
    })
}

struct GitIdentityRow {
    git_name: Option<String>,
    git_email: Option<String>,
    name: Option<String>,
    email: String,
}

async fn load_git_identity(state: &ApiState, user_id: &str) -> AppResult<GitIdentityRow> {
    let row = sqlx::query("SELECT git_name, git_email, name, email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "git-identity: load user failed");
            AppError::InternalMsg("failed to load user".into())
        })?;
    Ok(GitIdentityRow {
        git_name: row.try_get("git_name").map_err(AppError::from)?,
        git_email: row.try_get("git_email").map_err(AppError::from)?,
        name: row.try_get("name").map_err(AppError::from)?,
        email: row.try_get("email").map_err(AppError::from)?,
    })
}

fn resolve_git_name(git_name: Option<&str>, account_name: Option<&str>, email: &str) -> String {
    if let Some(name) = git_name
        && !name.is_empty()
    {
        return name.to_owned();
    }
    if let Some(name) = account_name
        && !name.is_empty()
    {
        return name.to_owned();
    }
    email
        .split_once('@')
        .map_or_else(|| email.to_owned(), |(prefix, _)| prefix.to_owned())
}

fn resolve_git_email(git_email: Option<&str>, account_email: &str) -> String {
    match git_email {
        Some(email) if !email.is_empty() => email.to_owned(),
        _ => account_email.to_owned(),
    }
}

fn resolved_git_identity(row: GitIdentityRow) -> GitIdentityRecord {
    GitIdentityRecord {
        git_name: resolve_git_name(row.git_name.as_deref(), row.name.as_deref(), &row.email),
        git_email: resolve_git_email(row.git_email.as_deref(), &row.email),
    }
}

pub(crate) async fn get_git_identity(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<GitIdentityRecord> {
    let user_id = account_user_id(user)?;
    Ok(resolved_git_identity(
        load_git_identity(state, user_id).await?,
    ))
}

pub(crate) async fn update_git_identity(
    state: &ApiState,
    user: &AuthUser,
    params: UpdateGitIdentityParams,
) -> AppResult<GitIdentityRecord> {
    let user_id = account_user_id(user)?;
    sqlx::query("UPDATE users SET git_name = $1, git_email = $2 WHERE id = $3")
        .bind(&params.git_name)
        .bind(&params.git_email)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "git-identity: update failed");
            AppError::InternalMsg("failed to update git identity".into())
        })?;

    Ok(resolved_git_identity(
        load_git_identity(state, user_id).await?,
    ))
}

fn normalize_host_key(host: &str) -> String {
    let mut key = String::from("GIT_TOKEN_");
    for character in host.to_uppercase().chars() {
        if character.is_ascii_uppercase() || character.is_ascii_digit() {
            key.push(character);
        } else {
            key.push('_');
        }
    }
    key
}

const GIT_CREDENTIAL_SELECT_COLS: &str =
    "id, user_id, name, host, auth_type, username, created_at, updated_at";

fn row_to_git_credential(row: &sqlx::postgres::PgRow) -> Result<GitCredentialRecord, AppError> {
    Ok(GitCredentialRecord {
        id: row.try_get("id").map_err(AppError::from)?,
        user_id: row.try_get("user_id").map_err(AppError::from)?,
        name: row.try_get("name").map_err(AppError::from)?,
        host: row.try_get("host").map_err(AppError::from)?,
        auth_type: row.try_get("auth_type").map_err(AppError::from)?,
        username: row.try_get("username").map_err(AppError::from)?,
        created_at: row.try_get("created_at").map_err(AppError::from)?,
        updated_at: row.try_get("updated_at").map_err(AppError::from)?,
    })
}

pub(crate) async fn list_git_credentials(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<Vec<GitCredentialRecord>> {
    let user_id = account_user_id(user)?;
    let rows = sqlx::query(&format!(
        "SELECT {GIT_CREDENTIAL_SELECT_COLS} FROM user_git_credentials \
         WHERE user_id = $1 ORDER BY created_at"
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "git-credentials: list failed");
        AppError::InternalMsg("failed to list credentials".into())
    })?;

    // Preserve the legacy handler's skip-on-row-scan-error behavior.
    Ok(rows
        .iter()
        .filter_map(|row| row_to_git_credential(row).ok())
        .collect())
}

pub(crate) async fn create_git_credential(
    state: &ApiState,
    user: &AuthUser,
    params: CreateGitCredentialParams,
) -> AppResult<GitCredentialRecord> {
    let user_id = account_user_id(user)?;
    let host = params.host.trim().to_lowercase();
    if host.is_empty() {
        return Err(AppError::BadRequest("host is required".into()));
    }
    if host == "github.com" {
        return Err(AppError::BadRequest(
            "use GitHub OAuth for github.com (Settings > GitHub)".into(),
        ));
    }
    if params.auth_type != "basic" {
        return Err(AppError::BadRequest("auth_type must be 'basic'".into()));
    }

    let username = (!params.username.is_empty()).then(|| params.username.clone());
    let row = sqlx::query(&format!(
        "INSERT INTO user_git_credentials (user_id, name, host, auth_type, username) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {GIT_CREDENTIAL_SELECT_COLS}"
    ))
    .bind(user_id)
    .bind(&params.name)
    .bind(&host)
    .bind(&params.auth_type)
    .bind(&username)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        let message = error.to_string();
        if message.contains("unique") || message.contains("duplicate") {
            return AppError::Conflict("credential already exists for this host".into());
        }
        tracing::error!(%error, "git-credentials: insert failed");
        AppError::InternalMsg("failed to create credential".into())
    })?;
    let credential = row_to_git_credential(&row)?;

    if let Err(error) = state.secrets.create_folder_at_path("/users", user_id).await {
        tracing::warn!(%error, "git-credentials: folder creation (may already exist)");
    }
    if let Err(error) = state
        .secrets
        .set_secret_at_path(
            &user_secret_path(user_id),
            &normalize_host_key(&host),
            &params.password,
        )
        .await
    {
        let _ = sqlx::query("DELETE FROM user_git_credentials WHERE id = $1")
            .bind(&credential.id)
            .execute(&state.pool)
            .await;
        tracing::error!(%error, "git-credentials: secret set failed");
        return Err(AppError::InternalMsg(
            "failed to store credential secret".into(),
        ));
    }

    Ok(credential)
}

pub(crate) async fn update_git_credential(
    state: &ApiState,
    user: &AuthUser,
    credential_id: &str,
    params: UpdateGitCredentialParams,
) -> AppResult<GitCredentialRecord> {
    let user_id = account_user_id(user)?;
    let existing = sqlx::query(&format!(
        "SELECT {GIT_CREDENTIAL_SELECT_COLS} FROM user_git_credentials \
         WHERE id = $1 AND user_id = $2"
    ))
    .bind(credential_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "git-credentials: load failed");
        AppError::InternalMsg("failed to update credential".into())
    })?
    .ok_or_else(|| AppError::NotFound("credential not found".into()))?;
    let host: String = existing.try_get("host").map_err(AppError::from)?;

    if let Some(password) = params.password.as_deref()
        && !password.is_empty()
    {
        state
            .secrets
            .set_secret_at_path(
                &user_secret_path(user_id),
                &normalize_host_key(&host),
                password,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "git-credentials: secret update failed");
                AppError::InternalMsg("failed to update credential secret".into())
            })?;
    }

    let row = sqlx::query(&format!(
        "UPDATE user_git_credentials \
         SET name = COALESCE($1, name), username = COALESCE($2, username), \
             updated_at = NOW() \
         WHERE id = $3 AND user_id = $4 RETURNING {GIT_CREDENTIAL_SELECT_COLS}"
    ))
    .bind(&params.name)
    .bind(&params.username)
    .bind(credential_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "git-credentials: update failed");
        AppError::InternalMsg("failed to update credential".into())
    })?;
    row_to_git_credential(&row)
}

pub(crate) async fn delete_git_credential(
    state: &ApiState,
    user: &AuthUser,
    credential_id: &str,
) -> AppResult<()> {
    let user_id = account_user_id(user)?;
    let host: String =
        sqlx::query_scalar("SELECT host FROM user_git_credentials WHERE id = $1 AND user_id = $2")
            .bind(credential_id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|error| {
                tracing::error!(%error, "git-credentials: load-for-delete failed");
                AppError::InternalMsg("failed to delete credential".into())
            })?
            .ok_or_else(|| AppError::NotFound("credential not found".into()))?;

    sqlx::query("DELETE FROM user_git_credentials WHERE id = $1 AND user_id = $2")
        .bind(credential_id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "git-credentials: delete failed");
            AppError::InternalMsg("failed to delete credential".into())
        })?;

    if let Err(error) = state
        .secrets
        .delete_secret_at_path(&user_secret_path(user_id), &normalize_host_key(&host))
        .await
    {
        tracing::warn!(%error, host, "git-credentials: secret delete failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_openssh_shape() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
        let fingerprint = ssh_fingerprint(line).expect("valid fingerprint");
        assert!(fingerprint.starts_with("SHA256:"));
        assert!(!fingerprint.ends_with('='));
        assert!(ssh_fingerprint("ssh-ed25519").is_none());
        assert!(ssh_fingerprint("ssh-ed25519 not!base64!").is_none());
    }

    #[test]
    fn generated_keypair_is_valid_openssh_and_self_consistent() {
        let (public_key, private_key, fingerprint) = generate_ssh_keypair().unwrap();
        assert!(public_key.starts_with("ssh-ed25519 "));
        assert!(public_key.ends_with('\n'));
        assert!(private_key.contains("OPENSSH PRIVATE KEY"));
        assert_eq!(
            ssh_fingerprint(public_key.trim_end()).as_deref(),
            Some(fingerprint.as_str())
        );
    }

    #[test]
    fn git_identity_resolution_matches_account_fallbacks() {
        assert_eq!(
            resolve_git_name(Some("Explicit"), Some("Account"), "u@example.com"),
            "Explicit"
        );
        assert_eq!(
            resolve_git_name(None, Some("Account"), "u@example.com"),
            "Account"
        );
        assert_eq!(resolve_git_name(Some(""), Some(""), "u@example.com"), "u");
        assert_eq!(
            resolve_git_email(Some("git@example.com"), "account@example.com"),
            "git@example.com"
        );
        assert_eq!(
            resolve_git_email(None, "account@example.com"),
            "account@example.com"
        );
    }

    #[test]
    fn secret_paths_and_host_keys_remain_wire_compatible() {
        assert_eq!(user_secret_path("usr_123"), "/users/usr_123");
        assert_eq!(
            normalize_host_key("gitea-1.dev:8443"),
            "GIT_TOKEN_GITEA_1_DEV_8443"
        );
    }
}
