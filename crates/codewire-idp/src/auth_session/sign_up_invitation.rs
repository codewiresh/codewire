//! Sign-up by organization invitation (#4121): on every server, the
//! invitation a link names admits a sign-up at exactly its address. A link
//! carries one of two tokens: the CreateInvitation token an admin copies, or
//! the `invitation_link` token an invitation email carries (#3840). Accepting
//! the invitation stays with orchestration's AcceptInvitation; sign-up only
//! reads it.

use axum::http::StatusCode;
use codewire_server_core::{
    AppError,
    auth::{hash_oauth_token, verification_token_hash},
};

use crate::email_password::VerificationPurpose;

/// What an invite-only server answers a sign-up it does not admit. A missing,
/// wrong, used, revoked or expired invitation, and one for another address,
/// all get these words, so a guess learns nothing.
pub const INVITE_ONLY_REFUSAL: &str = "This server is invite-only; ask its admin for an invite.";

/// What any other server answers a sign-up whose invitation does not admit
/// it, whatever the reason, in the invitation page's words.
pub const INVITATION_REFUSAL: &str = "This invitation is no longer valid. Ask for a new one.";

/// On a server with no mail the admin's copied link is the approval, so it
/// admits a sign-up for a day after it was issued.
pub(super) const NO_MAIL_INVITATION_HOURS: i32 = 24;

/// An invitation `token` names that admits a sign-up at `email`: named by its
/// CreateInvitation token (`$1`) or by an unexpired `invitation_link` (`$5`),
/// pending, unexpired, for that address compared with `lower()` as
/// AcceptInvitation compares, and on a server with no mail issued within the
/// last day.
const LIVE_INVITATION: &str = "SELECT id FROM org_invitations \
     WHERE (token_hash = $1 \
            OR id IN (SELECT identifier FROM verifications \
                       WHERE purpose = 'invitation_link' AND token_hash = $5 \
                         AND expires_at > NOW())) \
       AND status = 'pending' \
       AND expires_at > NOW() \
       AND lower(email) = lower($2) \
       AND ($3 OR created_at > NOW() - make_interval(hours => $4))";

fn link_hash(token: &str) -> String {
    verification_token_hash(VerificationPurpose::InvitationLink.as_str(), token)
}

/// Whether `token` names a live invitation for `email`, read without a lock.
/// It decides only whether sign-up skips Turnstile; the sign-up's
/// transaction reads the invitation again before admitting anyone.
pub(super) async fn invitation_is_live(
    pool: &sqlx::PgPool,
    token: &str,
    email: &str,
    mail_configured: bool,
) -> Result<bool, AppError> {
    if token.is_empty() {
        return Ok(false);
    }
    let id: Option<String> = sqlx::query_scalar(LIVE_INVITATION)
        .bind(hash_oauth_token(token))
        .bind(email)
        .bind(mail_configured)
        .bind(NO_MAIL_INVITATION_HOURS)
        .bind(link_hash(token))
        .fetch_optional(pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to check a sign-up invitation");
            AppError::InternalMsg("Failed to create account".into())
        })?;
    Ok(id.is_some())
}

/// The invitation a sign-up presented, once checked. The audit names its id,
/// never its token.
#[derive(Debug)]
pub(super) struct SignUpInvitation {
    pub(super) id: String,
}

/// Reads the invitation `token` names in the sign-up's own transaction, `FOR
/// SHARE`, so a revoke or an acceptance that commits first refuses the
/// sign-up and one that comes later waits for it. The invitation must be
/// pending, unexpired and addressed to `email`, compared with `lower()` as
/// AcceptInvitation compares; on a server with no mail it must also have been
/// issued within the last day.
pub(super) async fn invitation_for_sign_up(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
    email: &str,
    mail_configured: bool,
    invite_only: bool,
) -> Result<SignUpInvitation, AppError> {
    let refusal = || {
        if invite_only {
            invite_only_refusal()
        } else {
            invitation_refusal()
        }
    };
    if token.is_empty() {
        return Err(refusal());
    }
    let id: Option<String> = sqlx::query_scalar(&format!("{LIVE_INVITATION} FOR SHARE"))
        .bind(hash_oauth_token(token))
        .bind(email)
        .bind(mail_configured)
        .bind(NO_MAIL_INVITATION_HOURS)
        .bind(link_hash(token))
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to read a sign-up invitation");
            AppError::InternalMsg("Failed to create account".into())
        })?;
    id.map(|id| SignUpInvitation { id }).ok_or_else(refusal)
}

/// Whether an account already has this address, in any case. Sign-up never
/// takes over or verifies an existing account; that person signs in.
pub(super) async fn address_taken(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))")
        .bind(email)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to check a sign-up address");
            AppError::InternalMsg("Failed to create account".into())
        })
}

pub(super) fn invite_only_refusal() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "invite_only",
        detail: INVITE_ONLY_REFUSAL.into(),
    }
}

fn invitation_refusal() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "invitation_invalid",
        detail: INVITATION_REFUSAL.into(),
    }
}
