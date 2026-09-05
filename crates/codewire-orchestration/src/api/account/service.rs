//! Shared account service layer for AccountService.
//!
//! Transport adapters own wire validation and response formatting. Database,
//! authorization and persistence behavior live here so every Connect procedure
//! uses the same policy.

use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use sqlx::Row;

use super::super::ApiState;

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

fn account_user_id(user: &AuthUser) -> AppResult<&str> {
    user.require_account_credential()?;
    Ok(&user.user_id)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn account_service_cannot_write_workload_secret_credentials() {
        let source = include_str!("service.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .expect("account service keeps tests after production code")
            .0;

        for forbidden in [
            "create_folder_at_path",
            "set_secret_at_path",
            "/users/",
            "SSH_PRIVATE_KEY",
            "GIT_TOKEN_",
        ] {
            assert!(
                !production.contains(forbidden),
                "account service regained a workload-secret writer: {forbidden}"
            );
        }
    }
}
