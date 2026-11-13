//! Organization invitation email (#3847).
//!
//! CreateInvitation, in orchestration, writes one `org_invitation_emails`
//! row in the invitation's own transaction. idp holds the transactional-email
//! credentials, so it sends those rows: every replica runs [`spawn`], which
//! makes a [`run_pass`] every [`POLL_INTERVAL`].
//!
//! A pass first skips the rows whose invitation is no longer pending
//! (revoked, accepted or expired). Then it claims due rows one at a time:
//! [`claim_next`] locks one with `FOR UPDATE SKIP LOCKED`, so two replicas
//! never claim the same row, leases it for [`CLAIM_LEASE`] by setting
//! `claimed_until`, and adds one to `attempts`. The send runs outside any
//! transaction, bounded by `codewire-email`'s own 8 s limit, well inside the
//! lease. [`record_result`] writes the outcome only while the row still
//! carries that attempt number, so a sender whose lease lapsed (a stalled
//! process) cannot overwrite a newer claim; a lapsed lease is claimed again
//! by a later pass. A failed attempt is retried after [`RETRY_DELAYS`]; after
//! [`MAX_ATTEMPTS`] the row is failed with a short reason the inviter sees.
//! `codewire-email` makes one HTTP attempt per send, so a transport failure
//! may still have delivered: a retry can then repeat the email, at most
//! [`MAX_ATTEMPTS`] times in all.
//!
//! The email carries no token (decided on #3840, 2026-11-12). It names the
//! inviter, organization and role and tells the invitee to sign in with this
//! address (`cw login`) and run `cw org accept <slug>`, the two commands
//! `cw login` itself points to (#4530). A forwarded email grants nothing:
//! accepting needs the invitee's verified address.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::NaiveDateTime;
use codewire_email::EmailClient;
use sqlx::PgPool;

use crate::email_password::html_text;

/// How often each replica looks for due invitation emails. A new invitation
/// is sent within about this long, which the CLI waits for.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long a claimed row is held for its sender: far beyond the send's own
/// 8 s bound, so it lapses only for a stalled or crashed replica.
pub const CLAIM_LEASE: Duration = Duration::from_secs(60);

/// The attempts an email gets before it is failed.
pub const MAX_ATTEMPTS: i32 = 3;

/// The wait after the first and the second failed attempt.
pub const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(60), Duration::from_secs(300)];

/// The most emails one pass sends; the next pass continues.
const PASS_LIMIT: usize = 20;

/// The longest reason stored for the inviter, in characters.
const REASON_LIMIT: usize = 200;

const SUBJECT: &str = "You're invited to join an organization on Codewire";

/// The reason recorded when this deployment cannot send email at all.
pub const NOT_CONFIGURED: &str = "email delivery is not configured on this server";

/// Sends one invitation email. Production sends through the IdP's
/// transactional email; tests record the email instead.
#[async_trait]
pub trait InvitationMailer: Send + Sync {
    /// Whether this deployment can send email at all. Without it, a claimed
    /// email is failed at once with [`NOT_CONFIGURED`].
    fn is_available(&self) -> bool;
    async fn send(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()>;
}

/// The production mailer: the IdP's transactional email.
pub struct EmailInvitationMailer(pub EmailClient);

#[async_trait]
impl InvitationMailer for EmailInvitationMailer {
    fn is_available(&self) -> bool {
        self.0.is_configured()
    }

    async fn send(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()> {
        self.0.send_html(to, subject, html).await
    }
}

/// A claimed outbox row: what the email shows, and the attempt that claimed
/// it, which fences its result.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct ClaimedEmail {
    pub invitation_id: String,
    pub recipient: String,
    pub org_name: String,
    pub org_slug: String,
    pub inviter: String,
    pub role: String,
    pub expires_at: NaiveDateTime,
    pub attempts: i32,
}

/// The rendered invitation email.
#[derive(Debug, PartialEq, Eq)]
pub struct RenderedEmail {
    pub subject: &'static str,
    pub html: String,
}

/// Renders the email. Every interpolated value is escaped. The subject is
/// fixed, so text the inviter chose (their name, the organization's) stays
/// out of it, as in idp's other mail.
pub fn render(email: &ClaimedEmail, sign_in_url: &str) -> RenderedEmail {
    let inviter = html_text(&email.inviter);
    let org = html_text(&email.org_name);
    let slug = html_text(&email.org_slug);
    let recipient = html_text(&email.recipient);
    let sign_in_url = html_text(sign_in_url);
    let role = role_phrase(&email.role);
    let expires = email.expires_at.format("%B %-d, %Y");
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Join {org} on Codewire</h2>
	<p>{inviter} invited you to join <strong>{org}</strong> on Codewire as {role}.</p>
	<p>To accept, sign in with this email address, {recipient}, and accept:</p>
	<pre style="padding: 12px; background: #f5f5f5; border-radius: 6px;"><code>cw login
cw org accept {slug}</code></pre>
	<p><a href="{sign_in_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Sign in to Codewire</a></p>
	<p style="color: #666; font-size: 14px;">New to Codewire? Sign up with this address and verify it first. The invitation expires on {expires} (UTC). If you weren't expecting it, you can ignore this email.</p>
</div>"#
    );
    RenderedEmail {
        subject: SUBJECT,
        html,
    }
}

fn role_phrase(role: &str) -> &'static str {
    match role {
        "owner" => "an owner",
        "admin" => "an admin",
        _ => "a member",
    }
}

/// The public sign-in page the email links to.
pub fn sign_in_url(frontend_url: &str) -> String {
    format!("{}/login", frontend_url.trim_end_matches('/'))
}

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    pub skipped: u64,
    pub sent: usize,
    pub retrying: usize,
    pub failed: usize,
    /// Results refused because another claim replaced this one.
    pub superseded: usize,
}

/// Skips the emails whose invitation is no longer pending, then claims and
/// sends due emails, at most [`PASS_LIMIT`].
pub async fn run_pass(
    pool: &PgPool,
    mailer: &dyn InvitationMailer,
    sign_in_url: &str,
) -> Result<PassReport, sqlx::Error> {
    let mut report = PassReport {
        skipped: skip_settled(pool).await?,
        ..PassReport::default()
    };
    for _ in 0..PASS_LIMIT {
        let Some(email) = claim_next(pool, CLAIM_LEASE).await? else {
            break;
        };
        let outcome = if mailer.is_available() {
            let rendered = render(&email, sign_in_url);
            match mailer
                .send(&email.recipient, rendered.subject, &rendered.html)
                .await
            {
                Ok(()) => {
                    tracing::info!(invitation_id = %email.invitation_id, attempt = email.attempts, "sent invitation email");
                    SendOutcome::Sent
                }
                Err(error) => {
                    tracing::warn!(%error, invitation_id = %email.invitation_id, attempt = email.attempts, "failed to send invitation email");
                    SendOutcome::Failed(reason(&error))
                }
            }
        } else {
            SendOutcome::NotConfigured
        };
        let recorded = record_result(pool, &email, &outcome).await?;
        match recorded {
            Recorded::Sent => report.sent += 1,
            Recorded::Retrying => report.retrying += 1,
            Recorded::Failed => report.failed += 1,
            Recorded::Superseded => {
                tracing::warn!(invitation_id = %email.invitation_id, attempt = email.attempts, "invitation email result superseded by a newer claim");
                report.superseded += 1;
            }
        }
    }
    Ok(report)
}

/// Marks skipped every unclaimed pending email whose invitation was
/// revoked, accepted or expired, and returns how many.
pub async fn skip_settled(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let skipped = sqlx::query(
        r#"UPDATE org_invitation_emails e
              SET status = 'skipped',
                  last_error = CASE i.status
                      WHEN 'accepted' THEN 'the invitation was accepted before its email was sent'
                      WHEN 'revoked' THEN 'the invitation was revoked before its email was sent'
                      ELSE 'the invitation expired before its email was sent'
                  END
             FROM org_invitations i
            WHERE i.id = e.invitation_id
              AND e.status = 'pending'
              AND (e.claimed_until IS NULL OR e.claimed_until <= now())
              AND (i.status <> 'pending' OR i.expires_at <= now())"#,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(skipped)
}

/// Claims the next due email of a pending, unexpired invitation for
/// `lease`. A row another replica holds is skipped, never waited for.
pub async fn claim_next(
    pool: &PgPool,
    lease: Duration,
) -> Result<Option<ClaimedEmail>, sqlx::Error> {
    sqlx::query_as(
        r#"WITH due AS (
               SELECT e.invitation_id
                 FROM org_invitation_emails e
                 JOIN org_invitations i ON i.id = e.invitation_id
                WHERE e.status = 'pending'
                  AND e.next_attempt_at <= now()
                  AND (e.claimed_until IS NULL OR e.claimed_until <= now())
                  AND i.status = 'pending'
                  AND i.expires_at > now()
                ORDER BY e.next_attempt_at, e.invitation_id
                LIMIT 1
                  FOR UPDATE OF e SKIP LOCKED
           )
           UPDATE org_invitation_emails e
              SET attempts = e.attempts + 1,
                  claimed_until = now() + make_interval(secs => $1)
             FROM due, org_invitations i
            WHERE e.invitation_id = due.invitation_id
              AND i.id = e.invitation_id
        RETURNING e.invitation_id, e.recipient, e.org_name, e.org_slug, e.inviter, e.role,
                  i.expires_at, e.attempts"#,
    )
    .bind(lease.as_secs_f64())
    .fetch_optional(pool)
    .await
}

/// The result of one send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Sent,
    /// The provider refused or could not be reached; the reason is already
    /// bounded and free of control characters.
    Failed(String),
    /// This deployment has no email delivery.
    NotConfigured,
}

/// What [`record_result`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    Sent,
    /// Failed, and due again after a delay.
    Retrying,
    /// Failed for good.
    Failed,
    /// Nothing: the row is no longer this claim's.
    Superseded,
}

/// Writes the outcome of `email`'s claim, only while the row is still
/// pending under that same attempt.
pub async fn record_result(
    pool: &PgPool,
    email: &ClaimedEmail,
    outcome: &SendOutcome,
) -> Result<Recorded, sqlx::Error> {
    let fence = r#" WHERE invitation_id = $1 AND attempts = $2 AND status = 'pending'"#;
    let (recorded, result) = match outcome {
        SendOutcome::Sent => (
            Recorded::Sent,
            sqlx::query(&format!(
                "UPDATE org_invitation_emails \
                 SET status = 'sent', sent_at = now(), claimed_until = NULL, last_error = NULL{fence}"
            ))
            .bind(&email.invitation_id)
            .bind(email.attempts)
            .execute(pool)
            .await?,
        ),
        SendOutcome::Failed(reason) => match retry_delay(email.attempts) {
            Some(delay) => (
                Recorded::Retrying,
                sqlx::query(&format!(
                    "UPDATE org_invitation_emails \
                     SET claimed_until = NULL, last_error = $3, \
                         next_attempt_at = now() + make_interval(secs => $4){fence}"
                ))
                .bind(&email.invitation_id)
                .bind(email.attempts)
                .bind(reason)
                .bind(delay.as_secs_f64())
                .execute(pool)
                .await?,
            ),
            None => (
                Recorded::Failed,
                failed(pool, email, reason, fence).await?,
            ),
        },
        SendOutcome::NotConfigured => (
            Recorded::Failed,
            failed(pool, email, NOT_CONFIGURED, fence).await?,
        ),
    };
    Ok(if result.rows_affected() == 1 {
        recorded
    } else {
        Recorded::Superseded
    })
}

async fn failed(
    pool: &PgPool,
    email: &ClaimedEmail,
    reason: &str,
    fence: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(&format!(
        "UPDATE org_invitation_emails \
         SET status = 'failed', claimed_until = NULL, last_error = $3{fence}"
    ))
    .bind(&email.invitation_id)
    .bind(email.attempts)
    .bind(reason)
    .execute(pool)
    .await
}

/// The wait before the next attempt after `attempts` failed ones, or `None`
/// when they are used up.
fn retry_delay(attempts: i32) -> Option<Duration> {
    if attempts >= MAX_ATTEMPTS {
        return None;
    }
    let index = usize::try_from(attempts.max(1) - 1).unwrap_or(0);
    Some(RETRY_DELAYS[index.min(RETRY_DELAYS.len() - 1)])
}

/// The reason the inviter sees: the error's own message, which
/// `codewire-email` keeps free of addresses, provider text and credentials,
/// with control characters replaced and its length bounded.
pub fn reason(error: &anyhow::Error) -> String {
    let text: String = error
        .to_string()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let text: String = text.trim().chars().take(REASON_LIMIT).collect();
    let text = text.trim_end();
    if text.is_empty() {
        "the email could not be sent".to_owned()
    } else {
        text.to_owned()
    }
}

/// Starts this replica's sender: a pass every [`POLL_INTERVAL`], for the
/// life of the process. A failed pass is logged and the next one retries.
pub fn spawn(pool: PgPool, mailer: Arc<dyn InvitationMailer>, frontend_url: &str) {
    let sign_in_url = sign_in_url(frontend_url);
    if !mailer.is_available() {
        tracing::warn!(
            "invitation email: delivery is not configured; invitations will report it as failed"
        );
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = run_pass(&pool, mailer.as_ref(), &sign_in_url).await {
                tracing::warn!(%error, "invitation email pass failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(overrides: impl FnOnce(&mut ClaimedEmail)) -> ClaimedEmail {
        let mut email = ClaimedEmail {
            invitation_id: "invitation-synthetic".into(),
            recipient: "invitee@example.test".into(),
            org_name: "Acme".into(),
            org_slug: "acme".into(),
            inviter: "Ada".into(),
            role: "admin".into(),
            expires_at: chrono::NaiveDate::from_ymd_opt(2026, 11, 19)
                .unwrap()
                .and_hms_opt(10, 0, 0)
                .unwrap(),
            attempts: 1,
        };
        overrides(&mut email);
        email
    }

    #[test]
    fn the_email_names_inviter_organization_and_role_and_how_to_accept() {
        let rendered = render(&email(|_| {}), "https://app.codewire.test/login");
        assert_eq!(
            rendered.subject,
            "You're invited to join an organization on Codewire"
        );
        for expected in [
            "Ada invited you to join <strong>Acme</strong> on Codewire as an admin.",
            "sign in with this email address, invitee@example.test, and accept:",
            "<code>cw login\ncw org accept acme</code>",
            r#"<a href="https://app.codewire.test/login""#,
            "Sign up with this address and verify it first.",
            "expires on November 19, 2026 (UTC)",
        ] {
            assert!(rendered.html.contains(expected), "{expected:?} missing");
        }
        assert!(
            render(&email(|e| e.role = "member".into()), "https://x.test/login")
                .html
                .contains("as a member.")
        );
        assert!(
            render(&email(|e| e.role = "owner".into()), "https://x.test/login")
                .html
                .contains("as an owner.")
        );
    }

    /// The email links to signing in, never to an invitation capability.
    #[test]
    fn the_email_carries_no_token_or_accept_link() {
        let html = render(&email(|_| {}), "https://app.codewire.test/login").html;
        for absent in ["token", "accept-invite", "accept?"] {
            assert!(!html.contains(absent), "{absent:?} in {html}");
        }
    }

    /// Text the inviter chose is escaped wherever it appears.
    #[test]
    fn interpolated_text_is_escaped() {
        let rendered = render(
            &email(|e| {
                e.inviter = r#"<script>alert("x")</script>"#.into();
                e.org_name = "A & B <Corp>".into();
                e.org_slug = "a\"b".into();
            }),
            "https://app.codewire.test/login",
        );
        assert!(!rendered.html.contains("<script>"));
        assert!(
            rendered
                .html
                .contains("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;")
        );
        assert!(rendered.html.contains("A &amp; B &lt;Corp&gt;"));
        assert!(rendered.html.contains("cw org accept a&quot;b"));
        assert!(!rendered.subject.contains("Corp"));
    }

    #[test]
    fn the_sign_in_link_is_the_frontend_login_page() {
        assert_eq!(
            sign_in_url("https://app.codewire.test/"),
            "https://app.codewire.test/login"
        );
    }

    #[test]
    fn retries_wait_longer_and_stop_at_the_bound() {
        assert_eq!(retry_delay(1), Some(RETRY_DELAYS[0]));
        assert_eq!(retry_delay(2), Some(RETRY_DELAYS[1]));
        assert_eq!(retry_delay(MAX_ATTEMPTS), None);
        assert_eq!(retry_delay(MAX_ATTEMPTS + 1), None);
    }

    #[test]
    fn reasons_are_bounded_single_line_text() {
        let long = anyhow::anyhow!("SES email request failed\nwith {}", "x".repeat(400));
        let stored = reason(&long);
        assert!(stored.chars().count() <= REASON_LIMIT);
        assert!(stored.starts_with("SES email request failed with x"));
        assert!(!stored.chars().any(char::is_control));
        assert_eq!(
            reason(&anyhow::anyhow!("\n\t")),
            "the email could not be sent"
        );
    }
}
