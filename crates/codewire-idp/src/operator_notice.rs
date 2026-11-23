//! The operator's sign-up notice (#5358). AUTH-POLICY's "The operator's
//! sign-up notice" has the rules: `CODEWIRE_OPERATOR_EMAIL` gets one short
//! email per new person, when an email sign-up's address is first verified or
//! a GitHub or Google sign-up is created. It names the address, the method,
//! the time and whether the person waits for review, links to Admin → Manage
//! account access, and carries nothing the person wrote and no token.
//!
//! The notices share [`rate_limit::OPERATOR_NOTICE`], ten an hour across every
//! replica. The eleventh sends one "more people are waiting" notice instead,
//! and the rest of the hour sends nothing. A notice is sent in its own task
//! after the sign-up has committed, so a failed send, a full limit or a
//! database error is only logged.

use chrono::{DateTime, Utc};
use codewire_email::{Email, EmailClient};
use codewire_server_core::rate_limit;
use sqlx::PgPool;

use crate::oauth::Provider;

pub use codewire_email::{OPERATOR_EMAIL_ENV, parse_operator_email};

/// The one subject the site-wide notice limit counts under.
const SITE: &str = "all";

/// How a person signed up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Email,
    Provider(Provider),
}

impl Method {
    fn label(self) -> &'static str {
        match self {
            Method::Email => "email",
            Method::Provider(provider) => provider.label(),
        }
    }
}

/// A new person, as the operator's notice describes them.
#[derive(Clone, Debug)]
pub(crate) struct SignUp {
    pub address: String,
    pub method: Method,
    /// An access request that waits for an admin, rather than an account
    /// that can sign in now.
    pub waiting: bool,
    pub at: DateTime<Utc>,
}

/// Sends the operator's notice of `sign_up` in its own task, when the server
/// has an operator address and mail. It never waits for the send and never
/// fails the caller.
pub(crate) fn notify(
    pool: &PgPool,
    email: &EmailClient,
    frontend_url: &str,
    operator: Option<&str>,
    sign_up: SignUp,
) {
    let Some(operator) = operator else {
        return;
    };
    if !email.is_configured() {
        return;
    }
    let pool = pool.clone();
    let email = email.clone();
    let operator = operator.to_owned();
    let accounts_url = accounts_url(frontend_url);
    tokio::spawn(async move {
        if let Err(error) = send(&pool, &email, &operator, &accounts_url, &sign_up).await {
            tracing::warn!(%error, "operator sign-up notice not sent");
        }
    });
}

/// Counts the notice, then sends it, the one "more people are waiting"
/// notice, or nothing.
async fn send(
    pool: &PgPool,
    email: &EmailClient,
    operator: &str,
    accounts_url: &str,
    sign_up: &SignUp,
) -> anyhow::Result<()> {
    let mut connection = pool.acquire().await?;
    let decision =
        rate_limit::take_fixed(&mut connection, &rate_limit::OPERATOR_NOTICE, SITE).await?;
    let notice = if decision.allowed {
        sign_up_notice(sign_up, accounts_url)
    } else if decision.count == decision.max + 1 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM users \
              WHERE NOT enabled AND email_verified AND access_reason IS NOT NULL",
        )
        .fetch_one(&mut *connection)
        .await?;
        more_waiting_notice(waiting, decision.resets_at, accounts_url)
    } else {
        return Ok(());
    };
    drop(connection);
    email.send(operator, &notice).await
}

/// Admin → Manage account access on the dashboard at `frontend_url`.
fn accounts_url(frontend_url: &str) -> String {
    format!("{}/admin/accounts/", frontend_url.trim_end_matches('/'))
}

/// `text` up to its first control character, so a value can't add a header
/// line or break a subject.
fn one_line(text: &str) -> &str {
    text.split(char::is_control).next().unwrap_or_default()
}

const REASON: &str =
    "You got this email because this address is the operator address of a Codewire server.";

/// The notice of one new person.
pub(crate) fn sign_up_notice(sign_up: &SignUp, accounts_url: &str) -> Email {
    let address = one_line(&sign_up.address);
    let (subject, heading, next) = if sign_up.waiting {
        (
            format!("Codewire: access request from {address}"),
            "Someone asked for access to Codewire",
            "They wait for an admin to enable their account.",
        )
    } else {
        (
            format!("Codewire: new sign-up, {address}"),
            "Someone signed up for Codewire",
            "They can sign in now.",
        )
    };
    Email::new(subject, heading)
        .details([
            ("Address".to_owned(), address.to_owned()),
            (
                "Signed up with".to_owned(),
                sign_up.method.label().to_owned(),
            ),
            (
                "When".to_owned(),
                format!("{} UTC", sign_up.at.format("%Y-%m-%d %H:%M:%S")),
            ),
        ])
        .paragraph(next)
        .button("Manage account access", accounts_url)
        .reason(REASON)
}

/// The one notice past the hour's count.
pub(crate) fn more_waiting_notice(
    waiting: i64,
    resumes_at: DateTime<Utc>,
    accounts_url: &str,
) -> Email {
    let waiting = match waiting {
        1 => "1 account waits".to_owned(),
        n => format!("{n} accounts wait"),
    };
    Email::new(
        "Codewire: more people are waiting",
        "More people signed up this hour",
    )
    .paragraph(format!(
        "{waiting} for review now. Notices stop until {} UTC; Manage account access lists everyone.",
        resumes_at.format("%H:%M")
    ))
    .button("Manage account access", accounts_url)
    .reason(REASON)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-18T17:05:09Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn an_access_request_names_who_how_when_and_the_review_page() {
        let notice = sign_up_notice(
            &SignUp {
                address: "ada@example.com".into(),
                method: Method::Email,
                waiting: true,
                at: at(),
            },
            &accounts_url("https://codewire.sh/"),
        );
        assert_eq!(
            notice.subject,
            "Codewire: access request from ada@example.com"
        );
        let text = notice.text();
        for expected in [
            "Address: ada@example.com",
            "Signed up with: email",
            "When: 2026-11-18 17:05:09 UTC",
            "They wait for an admin to enable their account.",
            "https://codewire.sh/admin/accounts/",
        ] {
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn a_provider_sign_up_says_so_and_that_it_can_sign_in() {
        let notice = sign_up_notice(
            &SignUp {
                address: "ada@example.com".into(),
                method: Method::Provider(Provider::GitHub),
                waiting: false,
                at: at(),
            },
            "https://codewire.sh/admin/accounts/",
        );
        assert_eq!(notice.subject, "Codewire: new sign-up, ada@example.com");
        let text = notice.text();
        assert!(text.contains("Signed up with: GitHub"));
        assert!(text.contains("They can sign in now."));
    }

    #[test]
    fn markup_and_line_breaks_in_an_address_stay_inert() {
        let notice = sign_up_notice(
            &SignUp {
                address: "<b>ada</b>@example.com\r\nBcc: mallory@example.com".into(),
                method: Method::Email,
                waiting: true,
                at: at(),
            },
            "https://codewire.sh/admin/accounts/",
        );
        assert_eq!(
            notice.subject,
            "Codewire: access request from <b>ada</b>@example.com"
        );
        let html = notice.html();
        assert!(!html.contains("<b>ada</b>"), "{html}");
        assert!(
            html.contains("&lt;b&gt;ada&lt;/b&gt;@example.com"),
            "{html}"
        );
        assert!(!notice.text().contains("mallory"));
        assert!(!html.contains("mallory"));
    }

    #[test]
    fn past_the_count_one_notice_says_how_many_wait_and_when_notices_resume() {
        let notice = more_waiting_notice(14, at(), "https://codewire.sh/admin/accounts/");
        assert_eq!(notice.subject, "Codewire: more people are waiting");
        let text = notice.text();
        assert!(text.contains("14 accounts wait for review now."), "{text}");
        assert!(text.contains("Notices stop until 17:05 UTC"), "{text}");
        assert!(text.contains("https://codewire.sh/admin/accounts/"));
        assert!(
            more_waiting_notice(1, at(), "u")
                .text()
                .contains("1 account waits")
        );
    }
}
