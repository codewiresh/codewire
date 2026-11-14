//! The server's first admin, made by setup (#4121): `codewire-idp
//! create-admin --email <address>` with the password on stdin. Setup runs it
//! before the server takes any sign-up, and a second run makes no second
//! admin. With mail the admin verifies the address before signing in, like any
//! account (#4481); without mail, setup itself vouches for it (`bootstrap`).

use chrono::Duration;
use codewire_email::EmailClient;
use codewire_server_core::account_deletion::DELETED_USER_ID;
use serde_json::json;
use sqlx::PgPool;

use crate::auth_session::{hash_password, hex_id, validate_password};
use crate::email_password::{
    VerificationPurpose, create_verification_in_transaction, send_verification_email,
};

/// Serializes admin creation, so two setup runs cannot both find no admin
/// ("cwadmin1").
const CREATE_ADMIN_LOCK_ID: i64 = 0x6377_6164_6d69_6e31;

/// What `create_admin` did.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateAdmin {
    /// The admin was made; with mail, its verification link was sent.
    Created { verification_sent: bool },
    /// The server already has an admin; nothing changed.
    AdminExists,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateAdminError {
    #[error("the admin's email must be an address")]
    InvalidEmail,
    #[error("{0}")]
    WeakPassword(String),
    #[error("an account already has this email")]
    EmailTaken,
    #[error("the admin could not be stored: {0}")]
    Database(#[from] sqlx::Error),
    #[error("the admin could not be stored: {0}")]
    Store(String),
    #[error("the admin was made, but its verification email could not be sent: {0}")]
    Mail(anyhow::Error),
}

/// Whether the server has an admin yet. An invite-only server takes no
/// sign-up until it has one.
pub async fn admin_exists<'e, E>(executor: E) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE COALESCE(is_admin, false) AND id <> $1)",
    )
    .bind(DELETED_USER_ID)
    .fetch_one(executor)
    .await
}

/// Makes the server's admin at `email`, unless it has one.
pub async fn create_admin(
    pool: &PgPool,
    email: &str,
    password: &str,
    mail: &EmailClient,
    frontend_url: &str,
) -> Result<CreateAdmin, CreateAdminError> {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(CreateAdminError::InvalidEmail);
    }
    validate_password(password).map_err(CreateAdminError::WeakPassword)?;
    let hash =
        hash_password(password).map_err(|error| CreateAdminError::Store(error.to_string()))?;

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CREATE_ADMIN_LOCK_ID)
        .execute(&mut *tx)
        .await?;
    if admin_exists(&mut *tx).await? {
        return Ok(CreateAdmin::AdminExists);
    }
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))")
            .bind(email)
            .fetch_one(&mut *tx)
            .await?;
    if taken {
        return Err(CreateAdminError::EmailTaken);
    }

    let mail_configured = mail.is_configured();
    let user_id = hex_id();
    sqlx::query(
        "INSERT INTO users \
             (id, email, email_verified, enabled, is_admin, email_vouched_by, created_at, updated_at) \
         VALUES ($1, $2, false, true, true, $3, NOW(), NOW())",
    )
    .bind(&user_id)
    .bind(email)
    .bind((!mail_configured).then_some("bootstrap"))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id, password, created_at, updated_at) \
         VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW())",
    )
    .bind(hex_id())
    .bind(&user_id)
    .bind(email)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    let token = if mail_configured {
        Some(
            create_verification_in_transaction(
                &mut tx,
                email,
                VerificationPurpose::EmailVerification,
                Duration::hours(24),
            )
            .await
            .map_err(|error| CreateAdminError::Store(error.to_string()))?,
        )
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity) \
         VALUES ($1, NOW(), 'admin.created', $2, $3, 'info')",
    )
    .bind(hex_id())
    .bind(&user_id)
    .bind(json!({ "email": email, "vouched_by": (!mail_configured).then_some("bootstrap") }))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let verification_sent = token.is_some();
    if let Some(token) = token {
        let verify_url = format!(
            "{}/verify-email?token={token}",
            frontend_url.trim_end_matches('/')
        );
        send_verification_email(mail, email, &verify_url)
            .await
            .map_err(CreateAdminError::Mail)?;
    }
    Ok(CreateAdmin::Created { verification_sent })
}
