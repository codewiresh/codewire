//! The invitation email's link (#4121, #3840). The invitation sender mints a
//! token when the email is sent; only its purpose-bound hash is stored, in
//! `verifications` with the invitation id as its identifier, and the email
//! carries `{frontend}/accept-invite#t=<token>`: in the fragment, which never
//! leaves the browser, so no proxy or access log records it (cw-daemon and
//! cw-security, #3840).
//!
//! The token names the invitation for that page and admits one sign-up at
//! exactly the invited address, which is still verified by email before it
//! signs in. It never accepts the invitation, signs anyone in or links a
//! provider. It lives only while its invitation is pending: it expires with
//! the invitation, a new email replaces it, and migration 0036's trigger
//! deletes it once the invitation is accepted, revoked, expired or deleted.

use codewire_server_core::{AppError, auth::verification_token_hash};
use sqlx::{Postgres, Transaction};

use crate::auth_session::{hex_id, hex_token};
use crate::email_password::VerificationPurpose;

/// Mints the link for `invitation_id` in `tx`, replacing any earlier one, so a
/// forwarded older email stops working. The link expires with the
/// invitation. `None` when the invitation is no longer pending or has
/// expired: there is nothing to link to.
pub async fn mint_invitation_link(
    tx: &mut Transaction<'_, Postgres>,
    invitation_id: &str,
) -> Result<Option<String>, AppError> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, invitation_id, "failed to mint an invitation link");
        AppError::InternalMsg("Failed to send the invitation".into())
    };
    let purpose = VerificationPurpose::InvitationLink.as_str();
    sqlx::query("DELETE FROM verifications WHERE purpose = $1 AND identifier = $2")
        .bind(purpose)
        .bind(invitation_id)
        .execute(&mut **tx)
        .await
        .map_err(failed)?;
    let token = hex_token();
    let minted = sqlx::query(
        "INSERT INTO verifications \
             (id, identifier, purpose, token_hash, expires_at, created_at, updated_at) \
         SELECT $1, id, $2, $3, expires_at, NOW(), NOW() FROM org_invitations \
          WHERE id = $4 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(hex_id())
    .bind(purpose)
    .bind(verification_token_hash(purpose, &token))
    .bind(invitation_id)
    .execute(&mut **tx)
    .await
    .map_err(failed)?;
    Ok((minted.rows_affected() == 1).then_some(token))
}
