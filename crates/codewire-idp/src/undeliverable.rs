//! A verification email to an address SES suppressed (#4548): the IdP asks
//! before it would send nothing useful, and says so instead of "Sent". The
//! rules are in docs/dev/AUTH-POLICY.md, "An address SES won't deliver to".
//! Only an address the IdP holds for its own account is asked about, never
//! one a request names, and only the outcome is shown.

use axum::http::StatusCode;
use codewire_email::{EmailClient, Suppression};
use codewire_server_core::AppError;

/// The refusals' codes, which the dashboard turns into its own words: the
/// account holder's one outcome, and the admin's two.
pub(crate) const UNDELIVERABLE: &str = "email_undeliverable";
pub(crate) const BOUNCED: &str = "email_bounced";
pub(crate) const MARKED_AS_SPAM: &str = "email_marked_as_spam";

/// Who asked for the email, which decides what the refusal says.
#[derive(Clone, Copy)]
pub(crate) enum Asker {
    /// The account holder, who is told one outcome: the fix is the same,
    /// and it doesn't tell anyone their complaint is on record.
    Owner,
    /// An admin, who is told which one, for support.
    Admin,
}

/// Asks SES about `address`, counting what it answered.
pub(crate) async fn lookup(email: &EmailClient, address: &str) -> Suppression {
    let suppression = email.suppression(address).await;
    let outcome = match suppression {
        Suppression::Bounced => "bounced",
        Suppression::Complained => "complained",
        Suppression::NotSuppressed => "not_suppressed",
        Suppression::Unknown => "unknown",
    };
    crate::abuse_metrics::suppression_lookups()
        .with_label_values(&[outcome])
        .inc();
    suppression
}

/// Whether to skip a verification email to `address`: `Some` with the
/// refusal to answer, counted, when SES suppressed it; `None` to send as
/// before, an unknown answer included.
pub(crate) async fn refusal(email: &EmailClient, address: &str, asker: Asker) -> Option<AppError> {
    if !email.is_configured() {
        return None;
    }
    let suppression = lookup(email, address).await;
    let reason = suppression.reason()?;
    crate::abuse_metrics::mail_suppressed()
        .with_label_values(&[reason])
        .inc();
    let (code, detail) = match (asker, suppression) {
        (Asker::Owner, _) => (UNDELIVERABLE, "Email to that address can't be delivered."),
        (Asker::Admin, Suppression::Complained) => {
            (MARKED_AS_SPAM, "Email to that address was marked as spam.")
        }
        (Asker::Admin, _) => (BOUNCED, "Email to that address bounced."),
    };
    Some(AppError::Coded {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code,
        detail: detail.into(),
    })
}
