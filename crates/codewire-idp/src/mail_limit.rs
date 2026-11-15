//! The per-recipient email throttle (#3297 item 11). A stranger who knows an
//! address can ask the IdP to mail it: a password reset from "Forgot
//! password", a verification link by repeating a sign-up or from the "Check
//! your email" page. Each kind of mail counts against its recipient,
//! [`rate_limit::MAIL_PASSWORD_RESET`] or [`rate_limit::MAIL_VERIFICATION`],
//! three an hour unless an admin sets another count, so no one can mail-bomb
//! an address through Codewire.
//!
//! A mail past the count is not sent, and the person is told what they would
//! have been told anyway: the responses never say whether a mail went, so they
//! say nothing about the address either. The account's audit log records
//! `mail.throttled`, which is how an administrator sees what the person can't.
//! When the count can't be read, nothing is sent either (#3256).

use codewire_server_core::rate_limit::{self, Limit};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::auth_session::{hex_lower, log_audit};

/// A kind of mail the IdP sends to an address someone else may have typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mail {
    /// A reset link, or for a GitHub- or Google-only account how it signs in.
    PasswordReset,
    /// A link that verifies the address.
    Verification,
}

impl Mail {
    fn limit(self) -> &'static Limit {
        match self {
            Mail::PasswordReset => &rate_limit::MAIL_PASSWORD_RESET,
            Mail::Verification => &rate_limit::MAIL_VERIFICATION,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mail::PasswordReset => "password_reset",
            Mail::Verification => "verification",
        }
    }
}

/// The recipient as counted: a SHA-256 of the trimmed, lowercased address, so
/// one address counts once however it is typed and no key holds it.
fn recipient_key(address: &str) -> String {
    hex_lower(&Sha256::digest(address.trim().to_lowercase().as_bytes()))
}

/// Counts one `mail` to `address`, the email of account `user_id`, and says
/// whether it may be sent. Past the count, or when the count can't be read,
/// it may not, and the account's audit log says so.
pub(crate) async fn may_send(pool: &PgPool, mail: Mail, address: &str, user_id: &str) -> bool {
    let limit = mail.limit();
    let decision = async {
        let mut connection = pool.acquire().await?;
        rate_limit::take(&mut connection, limit, &recipient_key(address)).await
    }
    .await;
    let reason = match decision {
        Ok(decision) if decision.allowed => return true,
        Ok(_) => "limit",
        Err(error) => {
            tracing::error!(%error, limit = limit.name, "mail limit unavailable");
            "unavailable"
        }
    };
    tracing::warn!(%user_id, limit = limit.name, reason, "mail not sent");
    log_audit(
        pool,
        "mail.throttled",
        user_id,
        "",
        "",
        json!({ "mail": mail.name(), "reason": reason }),
        "warn",
    )
    .await;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_counts_once_however_it_is_typed_and_is_never_kept() {
        let key = recipient_key("Person@Example.test");
        assert_eq!(key, recipient_key("  person@example.TEST "));
        assert_ne!(key, recipient_key("someone@example.test"));
        assert_eq!(key.len(), 64);
        assert!(!key.contains("example"));
    }
}
