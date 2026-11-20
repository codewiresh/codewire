//! The operator's feedback email (#5466). CONFIGURATION's "Operator
//! notices" and the `feedback-operator-email` journey have the rules.
//!
//! SubmitFeedback, in orchestration, writes one `feedback_notices` row in the
//! feedback's own transaction. idp holds the transactional-email credentials
//! and the operator address, so it sends those rows: every replica runs
//! [`spawn`], which makes a [`run_pass`] every [`POLL_INTERVAL`]. Claiming,
//! the lease, the attempt fence and the retries are those of
//! [`crate::invitation_email`]. idp reads `feedback` and only claims and
//! records `feedback_notices`; it writes no feedback.
//!
//! The emails share [`rate_limit::OPERATOR_FEEDBACK_NOTICE`], ten an hour
//! across every replica, counted once per piece of feedback, on its first
//! attempt. Past it the row is skipped: the eleventh sends one "more feedback
//! is waiting" email instead, and the rest of the hour sends nothing.
//!
//! The email is plain text, from the server's fixed sender, with the subject
//! `Codewire feedback <id>`: nothing the sender typed, and no name, reaches a
//! header. Reply-To is the account's address only when it is verified and
//! one plain address, so the operator is never invited to answer an address
//! nobody proved. What the sender wrote is shown without control characters
//! (bar line breaks and tabs), Unicode line and paragraph separators, and
//! Unicode direction overrides and isolates, so it can't disguise itself,
//! and no longer than feedback's stored maximum. A failure is logged with the feedback's id and
//! `codewire-email`'s own reason, which holds no address and no provider
//! text.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use codewire_email::EmailClient;
use codewire_server_core::rate_limit;
use sqlx::PgPool;

use crate::invitation_email::reason;
use crate::operator_notice::parse_operator_email;

/// How often each replica looks for due feedback emails.
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

/// feedback's stored maximum, orchestration's `MAX_MESSAGE_BYTES` (10 KB).
pub const MAX_MESSAGE_BYTES: usize = 10 * 1024;

/// The longest one-line value (a name, an organization) the email shows.
const MAX_LINE_CHARS: usize = 200;

/// The one subject the site-wide limit counts under.
const SITE: &str = "all";

const MORE_WAITING_SUBJECT: &str = "Codewire: more feedback is waiting";

const REASON: &str =
    "You got this email because this address is the operator address of a Codewire server.";

/// Sends one plain-text email. Production sends through the IdP's
/// transactional email; tests record or fail instead.
#[async_trait]
pub trait FeedbackMailer: Send + Sync {
    /// Whether this deployment can send email at all.
    fn is_available(&self) -> bool;
    async fn send(
        &self,
        to: &str,
        reply_to: Option<&str>,
        subject: &str,
        text: &str,
    ) -> anyhow::Result<()>;
}

/// The production mailer: the IdP's transactional email.
pub struct EmailFeedbackMailer(pub EmailClient);

#[async_trait]
impl FeedbackMailer for EmailFeedbackMailer {
    fn is_available(&self) -> bool {
        self.0.is_configured()
    }

    async fn send(
        &self,
        to: &str,
        reply_to: Option<&str>,
        subject: &str,
        text: &str,
    ) -> anyhow::Result<()> {
        self.0.send_plain(to, reply_to, subject, text).await
    }
}

/// A claimed outbox row, and the attempt that claimed it, which fences its
/// result.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Claimed {
    pub feedback_id: String,
    pub attempts: i32,
}

/// One piece of feedback as the email shows it. The sender's fields are
/// `None` for anonymous feedback. Its `Debug` leaves out the reply address,
/// which is personal data.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Feedback {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub message: String,
    pub cli_version: String,
    pub os: String,
    pub arch: String,
    pub placement: Option<String>,
    pub environment_id: Option<String>,
    pub sender_email: Option<String>,
    pub sender_verified: Option<bool>,
    pub sender_name: Option<String>,
    pub organization: Option<String>,
    /// The address an anonymous sender gave for a reply, unverified.
    pub reply_email: Option<String>,
}

impl std::fmt::Debug for Feedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Feedback")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("message", &self.message)
            .field("cli_version", &self.cli_version)
            .field("os", &self.os)
            .field("arch", &self.arch)
            .field("placement", &self.placement)
            .field("environment_id", &self.environment_id)
            .field("sender_email", &self.sender_email)
            .field("sender_verified", &self.sender_verified)
            .field("sender_name", &self.sender_name)
            .field("organization", &self.organization)
            .field(
                "reply_email",
                &self.reply_email.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// The email for one piece of feedback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub subject: String,
    pub reply_to: Option<String>,
    pub text: String,
}

/// Admin → Feedback on the dashboard at the configured `frontend_url`.
pub fn feedback_url(frontend_url: &str) -> String {
    format!("{}/admin/feedback/", frontend_url.trim_end_matches('/'))
}

/// Whether `character` may change how the text around it reads: a control
/// character other than a line break or tab, a Unicode line or paragraph
/// separator, or a Unicode direction override or isolate.
fn misleading(character: char) -> bool {
    (character.is_control() && character != '\n' && character != '\t')
        || ('\u{2028}'..='\u{2029}').contains(&character)
        || ('\u{202A}'..='\u{202E}').contains(&character)
        || ('\u{2066}'..='\u{2069}').contains(&character)
}

/// The sender's message as the email shows it: without [`misleading`]
/// characters, and at most [`MAX_MESSAGE_BYTES`].
pub fn shown_message(message: &str) -> String {
    let mut shown = String::with_capacity(message.len().min(MAX_MESSAGE_BYTES));
    for character in message.chars().filter(|&c| !misleading(c)) {
        if shown.len() + character.len_utf8() > MAX_MESSAGE_BYTES {
            break;
        }
        shown.push(character);
    }
    shown
}

/// A value shown on one line: line breaks and tabs become spaces, the other
/// [`misleading`] characters are dropped, and at most [`MAX_LINE_CHARS`].
pub fn shown_line(value: &str) -> String {
    let line: String = value
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .filter(|&c| !misleading(c))
        .take(MAX_LINE_CHARS)
        .collect();
    line.trim().to_owned()
}

/// The email for `feedback`. `feedback_url` is Admin → Feedback on the
/// server's configured address.
pub fn feedback_notice(feedback: &Feedback, feedback_url: &str) -> Notice {
    let id = shown_line(&feedback.id);
    let mut reply_to = None;
    let (from, reply) = match &feedback.sender_email {
        None => match feedback.reply_email.as_deref().map(shown_line) {
            // Shown, never a Reply-To, and never mailed by Codewire: nobody
            // has checked that it is the sender's (cw-security, #5466).
            Some(address) if !address.is_empty() => (
                format!("Anonymous, reply address {address} (given with the feedback, not verified)"),
                "Nobody has checked this address; don't share account or billing details in a reply.".to_owned(),
            ),
            _ => (
                "Anonymous".to_owned(),
                "Sent without signing in, so there is no address to reply to.".to_owned(),
            ),
        },
        Some(address) => {
            let verified = feedback.sender_verified == Some(true);
            let shown = shown_line(address);
            let label = if verified { "verified" } else { "not verified" };
            let from = match feedback.sender_name.as_deref().map(shown_line) {
                Some(name) if !name.is_empty() => format!("{name} <{shown}> ({label})"),
                _ => format!("{shown} ({label})"),
            };
            let plain = parse_operator_email(Some(address))
                .ok()
                .flatten()
                .filter(|parsed| parsed == address);
            let reply = match plain {
                Some(address) if verified => {
                    let reply = format!("Reply to this email to answer them at {address}.");
                    reply_to = Some(address);
                    reply
                }
                _ if verified => {
                    "This address can't be used to reply, so this email has no Reply-To.".to_owned()
                }
                _ => "Nobody has verified this address, so this email has no Reply-To. It may not be theirs.".to_owned(),
            };
            (from, reply)
        }
    };
    let organization = feedback
        .organization
        .as_deref()
        .map(shown_line)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let mut sent_with = format!(
        "cw {}, {} {}",
        shown_line(&feedback.cli_version),
        shown_line(&feedback.os),
        shown_line(&feedback.arch)
    );
    match feedback.placement.as_deref() {
        Some("local") => sent_with.push_str(", local"),
        Some("cloud") => sent_with.push_str(", cloud"),
        _ => {}
    }
    let mut text = format!(
        "Feedback {id}\n\nFrom: {from}\nOrganization: {organization}\nSent with: {sent_with}\n"
    );
    if let Some(environment) = feedback.environment_id.as_deref() {
        text.push_str(&format!("Environment: {}\n", shown_line(environment)));
    }
    text.push_str(&format!(
        "When: {} UTC\n\n{reply}\n\nMessage:\n\n{}\n\n--\nAll feedback: {feedback_url}\n{REASON}\n",
        feedback.created_at.format("%Y-%m-%d %H:%M:%S"),
        shown_message(&feedback.message)
    ));
    Notice {
        subject: format!("Codewire feedback {id}"),
        reply_to,
        text,
    }
}

/// The one email past the hour's count: how many arrived, and the link.
pub fn more_waiting_notice(arrived: i64, feedback_url: &str) -> Notice {
    let arrived = match arrived {
        1 => "1 piece of feedback".to_owned(),
        n => format!("{n} pieces of feedback"),
    };
    Notice {
        subject: MORE_WAITING_SUBJECT.to_owned(),
        reply_to: None,
        text: format!(
            "{arrived} arrived in the last hour, more than the {} emails an hour this address gets. The rest are not emailed; all of them are on the admin page:\n\n{feedback_url}\n\n--\n{REASON}\n",
            rate_limit::OPERATOR_FEEDBACK_NOTICE.default_max
        ),
    }
}

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Skipped because this server has no operator address or no mail.
    pub unsent: u64,
    pub sent: usize,
    /// Skipped past the hour's limit.
    pub limited: usize,
    pub retrying: usize,
    pub failed: usize,
    /// Results refused because another claim replaced this one.
    pub superseded: usize,
}

/// The result of one claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    Failed,
    /// Past the hour's limit.
    Limited,
}

/// What [`record_result`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    Sent,
    /// Failed, and due again after a delay.
    Retrying,
    /// Failed for good.
    Failed,
    Skipped,
    /// Nothing: the row is no longer this claim's.
    Superseded,
}

/// Sends due feedback emails to `operator`, at most [`PASS_LIMIT`]. Without
/// an operator address or mail, every unclaimed pending row is skipped
/// instead: its feedback stays on the admin page.
pub async fn run_pass(
    pool: &PgPool,
    mailer: &dyn FeedbackMailer,
    operator: Option<&str>,
    frontend_url: &str,
) -> Result<PassReport, sqlx::Error> {
    let Some(operator) = operator.filter(|_| mailer.is_available()) else {
        return Ok(PassReport {
            unsent: skip_unsendable(pool).await?,
            ..PassReport::default()
        });
    };
    let feedback_url = feedback_url(frontend_url);
    let mut report = PassReport::default();
    for _ in 0..PASS_LIMIT {
        let Some(claimed) = claim_next(pool, CLAIM_LEASE).await? else {
            break;
        };
        let Some(outcome) = send_one(pool, mailer, operator, &feedback_url, &claimed).await? else {
            continue;
        };
        match record_result(pool, &claimed, outcome).await? {
            Recorded::Sent => report.sent += 1,
            Recorded::Skipped => report.limited += 1,
            Recorded::Retrying => report.retrying += 1,
            Recorded::Failed => report.failed += 1,
            Recorded::Superseded => {
                tracing::warn!(feedback_id = %claimed.feedback_id, attempt = claimed.attempts, "feedback email result superseded by a newer claim");
                report.superseded += 1;
            }
        }
    }
    Ok(report)
}

/// Counts a first attempt against the hour's limit, then sends the
/// feedback's email, the one "more feedback is waiting" email, or nothing.
/// `None` when the feedback was deleted since the claim, which deleted its
/// row too.
async fn send_one(
    pool: &PgPool,
    mailer: &dyn FeedbackMailer,
    operator: &str,
    feedback_url: &str,
    claimed: &Claimed,
) -> Result<Option<Outcome>, sqlx::Error> {
    if claimed.attempts == 1 {
        let mut connection = pool.acquire().await?;
        let decision =
            rate_limit::take_fixed(&mut connection, &rate_limit::OPERATOR_FEEDBACK_NOTICE, SITE)
                .await?;
        if !decision.allowed {
            if decision.count == decision.max + 1 {
                let arrived: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM feedback WHERE created_at > now() - interval '1 hour'",
                )
                .fetch_one(&mut *connection)
                .await?;
                drop(connection);
                let notice = more_waiting_notice(arrived, feedback_url);
                if let Err(error) = mailer
                    .send(operator, None, &notice.subject, &notice.text)
                    .await
                {
                    tracing::warn!(reason = %reason(&error), "feedback 'more waiting' email not sent");
                }
            }
            return Ok(Some(Outcome::Limited));
        }
    }
    let Some(feedback) = load(pool, &claimed.feedback_id).await? else {
        return Ok(None);
    };
    let notice = feedback_notice(&feedback, feedback_url);
    Ok(Some(
        match mailer
            .send(
                operator,
                notice.reply_to.as_deref(),
                &notice.subject,
                &notice.text,
            )
            .await
        {
            Ok(()) => {
                tracing::info!(feedback_id = %claimed.feedback_id, attempt = claimed.attempts, "sent feedback email");
                Outcome::Sent
            }
            Err(error) => {
                tracing::warn!(feedback_id = %claimed.feedback_id, attempt = claimed.attempts, reason = %reason(&error), "feedback email not sent");
                Outcome::Failed
            }
        },
    ))
}

/// The feedback the email shows, with its sender and organization.
pub async fn load(pool: &PgPool, feedback_id: &str) -> Result<Option<Feedback>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT f.id, f.created_at, f.message, f.cli_version, f.os, f.arch, f.placement,
                  f.environment_id, u.email AS sender_email,
                  u.email_verified AS sender_verified, u.name AS sender_name,
                  o.name AS organization, f.reply_email
             FROM feedback f
             LEFT JOIN users u ON u.id = f.user_id
             LEFT JOIN organizations o ON o.id = f.organization_id
            WHERE f.id = $1"#,
    )
    .bind(feedback_id)
    .fetch_optional(pool)
    .await
}

/// Marks skipped every unclaimed pending row, and returns how many.
pub async fn skip_unsendable(pool: &PgPool) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE feedback_notices SET status = 'skipped' \
          WHERE status = 'pending' AND (claimed_until IS NULL OR claimed_until <= now())",
    )
    .execute(pool)
    .await?
    .rows_affected())
}

/// Claims the next due row for `lease`. A row another replica holds is
/// skipped, never waited for.
pub async fn claim_next(pool: &PgPool, lease: Duration) -> Result<Option<Claimed>, sqlx::Error> {
    sqlx::query_as(
        r#"WITH due AS (
               SELECT feedback_id
                 FROM feedback_notices
                WHERE status = 'pending'
                  AND next_attempt_at <= now()
                  AND (claimed_until IS NULL OR claimed_until <= now())
                ORDER BY next_attempt_at, feedback_id
                LIMIT 1
                  FOR UPDATE SKIP LOCKED
           )
           UPDATE feedback_notices n
              SET attempts = n.attempts + 1,
                  claimed_until = now() + make_interval(secs => $1)
             FROM due
            WHERE n.feedback_id = due.feedback_id
        RETURNING n.feedback_id, n.attempts"#,
    )
    .bind(lease.as_secs_f64())
    .fetch_optional(pool)
    .await
}

/// Writes the outcome of `claimed`, only while the row is still pending
/// under that same attempt.
pub async fn record_result(
    pool: &PgPool,
    claimed: &Claimed,
    outcome: Outcome,
) -> Result<Recorded, sqlx::Error> {
    let (recorded, set, delay) = match outcome {
        Outcome::Sent => (
            Recorded::Sent,
            "status = 'sent', sent_at = now(), claimed_until = NULL",
            None,
        ),
        Outcome::Limited => (
            Recorded::Skipped,
            "status = 'skipped', claimed_until = NULL",
            None,
        ),
        Outcome::Failed => match retry_delay(claimed.attempts) {
            Some(delay) => (
                Recorded::Retrying,
                "claimed_until = NULL, next_attempt_at = now() + make_interval(secs => $3)",
                Some(delay),
            ),
            None => (
                Recorded::Failed,
                "status = 'failed', claimed_until = NULL",
                None,
            ),
        },
    };
    let sql = format!(
        "UPDATE feedback_notices SET {set} \
          WHERE feedback_id = $1 AND attempts = $2 AND status = 'pending'"
    );
    let query = sqlx::query(&sql)
        .bind(&claimed.feedback_id)
        .bind(claimed.attempts);
    let query = match delay {
        Some(delay) => query.bind(delay.as_secs_f64()),
        None => query,
    };
    Ok(if query.execute(pool).await?.rows_affected() == 1 {
        recorded
    } else {
        Recorded::Superseded
    })
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

/// Starts this replica's sender: a pass every [`POLL_INTERVAL`], for the
/// life of the process. A failed pass is logged and the next one retries.
pub fn spawn(
    pool: PgPool,
    mailer: Arc<dyn FeedbackMailer>,
    operator: Option<String>,
    frontend_url: &str,
) {
    let frontend_url = frontend_url.to_owned();
    if operator.is_none() || !mailer.is_available() {
        tracing::info!(
            "feedback email: no operator address or no mail; feedback stays on the admin page only"
        );
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) =
                run_pass(&pool, mailer.as_ref(), operator.as_deref(), &frontend_url).await
            {
                tracing::warn!(%error, "feedback email pass failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://app.codewire.test/admin/feedback/";

    fn feedback(overrides: impl FnOnce(&mut Feedback)) -> Feedback {
        let mut feedback = Feedback {
            id: "feedback-synthetic".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-11-19T11:05:15Z")
                .unwrap()
                .with_timezone(&Utc),
            message: "The CLI is great.\nBut start is slow.".into(),
            cli_version: "0.4.24".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            placement: Some("cloud".into()),
            environment_id: None,
            sender_email: Some("ada@example.test".into()),
            sender_verified: Some(true),
            sender_name: Some("Ada".into()),
            organization: Some("Acme".into()),
            reply_email: None,
        };
        overrides(&mut feedback);
        feedback
    }

    #[test]
    fn debug_output_redacts_the_reply_address() {
        let given = feedback(|f| {
            f.sender_email = None;
            f.reply_email = Some("walker@example.test".into());
        });
        let debug = format!("{given:?}");
        assert!(!debug.contains("walker@example.test"), "{debug}");
        assert!(debug.contains("feedback-synthetic"), "{debug}");
    }

    #[test]
    fn a_verified_sender_is_the_reply_to_and_every_field_is_shown() {
        let notice = feedback_notice(
            &feedback(|f| f.environment_id = Some("env-123".into())),
            URL,
        );
        assert_eq!(notice.subject, "Codewire feedback feedback-synthetic");
        assert_eq!(notice.reply_to.as_deref(), Some("ada@example.test"));
        assert_eq!(
            notice.text,
            "Feedback feedback-synthetic\n\n\
             From: Ada <ada@example.test> (verified)\n\
             Organization: Acme\n\
             Sent with: cw 0.4.24, linux x86_64, cloud\n\
             Environment: env-123\n\
             When: 2026-11-19 11:05:15 UTC\n\n\
             Reply to this email to answer them at ada@example.test.\n\n\
             Message:\n\n\
             The CLI is great.\nBut start is slow.\n\n\
             --\n\
             All feedback: https://app.codewire.test/admin/feedback/\n\
             You got this email because this address is the operator address of a Codewire server.\n"
        );
    }

    /// An anonymous sender's reply address is shown, marked and warned
    /// about, and is never the Reply-To (cw-security, #5466).
    #[test]
    fn an_anonymous_reply_address_is_shown_but_never_the_reply_to() {
        let notice = feedback_notice(
            &feedback(|f| {
                f.sender_email = None;
                f.sender_verified = None;
                f.sender_name = None;
                f.organization = None;
                f.reply_email = Some("walker@example.test\r\nBcc: eve@example.test".into());
            }),
            URL,
        );
        assert_eq!(notice.reply_to, None);
        assert!(notice.text.contains(
            "From: Anonymous, reply address walker@example.test Bcc: eve@example.test (given with the feedback, not verified)\n"
        ));
        assert!(notice.text.contains(
            "Nobody has checked this address; don't share account or billing details in a reply.\n"
        ));
        let plain = feedback_notice(
            &feedback(|f| {
                f.sender_email = None;
                f.sender_verified = None;
                f.reply_email = Some("walker@example.test".into());
            }),
            URL,
        );
        assert_eq!(plain.reply_to, None);
        assert!(
            plain.text.contains(
                "reply address walker@example.test (given with the feedback, not verified)"
            )
        );
    }

    #[test]
    fn anonymous_and_unverified_senders_get_no_reply_to() {
        let anonymous = feedback_notice(
            &feedback(|f| {
                f.sender_email = None;
                f.sender_verified = None;
                f.sender_name = None;
                f.organization = None;
                f.placement = None;
            }),
            URL,
        );
        assert_eq!(anonymous.reply_to, None);
        assert!(
            anonymous.text.contains(
                "From: Anonymous\nOrganization: none\nSent with: cw 0.4.24, linux x86_64\n"
            )
        );
        assert!(
            anonymous
                .text
                .contains("Sent without signing in, so there is no address to reply to.")
        );

        for verified in [Some(false), None] {
            let unverified = feedback_notice(&feedback(|f| f.sender_verified = verified), URL);
            assert_eq!(unverified.reply_to, None);
            assert!(
                unverified
                    .text
                    .contains("From: Ada <ada@example.test> (not verified)\n")
            );
            assert!(
                unverified
                    .text
                    .contains("so this email has no Reply-To. It may not be theirs.")
            );
        }

        // A verified address that is not one plain address is never a Reply-To.
        let odd = feedback_notice(
            &feedback(|f| f.sender_email = Some("ada@example.test, eve@example.test".into())),
            URL,
        );
        assert_eq!(odd.reply_to, None);
        assert!(odd.text.contains("can't be used to reply"));
    }

    /// Line breaks, header-shaped lines, control characters and direction
    /// overrides in the message, the name and the organization stay in the
    /// body, and no header holds anything the sender wrote.
    #[test]
    fn what_the_sender_wrote_stays_in_the_body_and_cannot_disguise_itself() {
        let hostile = "Hi\r\nBcc: eve@example.test\r\nSubject: urgent\n\tindented\u{0}\u{7}\u{1b}[31m\u{202E}gnp.exe\u{2066}x\u{2069}\u{2028}\u{2029}";
        let notice = feedback_notice(
            &feedback(|f| {
                f.message = hostile.into();
                f.sender_name = Some("Ada\r\nBcc: eve@example.test\u{202E}".into());
                f.organization = Some("Acme\nReply-To: eve@example.test".into());
            }),
            URL,
        );
        assert_eq!(notice.subject, "Codewire feedback feedback-synthetic");
        assert_eq!(notice.reply_to.as_deref(), Some("ada@example.test"));
        assert!(notice.text.contains(
            "Message:\n\nHi\nBcc: eve@example.test\nSubject: urgent\n\tindented[31mgnp.exex\n\n--\n"
        ));
        assert!(
            notice
                .text
                .contains("From: Ada Bcc: eve@example.test <ada@example.test> (verified)\n")
        );
        assert!(
            notice
                .text
                .contains("Organization: Acme Reply-To: eve@example.test\n")
        );
        for removed in [
            '\u{2028}', '\u{2029}', '\r', '\0', '\u{7}', '\u{1b}', '\u{202E}', '\u{2066}',
            '\u{2069}',
        ] {
            assert!(!notice.text.contains(removed), "{removed:?} kept");
        }
    }

    #[test]
    fn the_message_shown_is_capped_at_the_stored_maximum() {
        let long = "é".repeat(MAX_MESSAGE_BYTES);
        let shown = shown_message(&long);
        assert!(shown.len() <= MAX_MESSAGE_BYTES);
        assert_eq!(shown.len(), MAX_MESSAGE_BYTES);
        assert!(shown.chars().all(|c| c == 'é'));
        assert_eq!(shown_line(&"x".repeat(500)).len(), MAX_LINE_CHARS);
    }

    #[test]
    fn the_more_waiting_email_holds_only_the_count_and_the_link() {
        let notice = more_waiting_notice(11, URL);
        assert_eq!(notice.subject, "Codewire: more feedback is waiting");
        assert_eq!(notice.reply_to, None);
        assert_eq!(
            notice.text,
            "11 pieces of feedback arrived in the last hour, more than the 10 emails an hour this address gets. The rest are not emailed; all of them are on the admin page:\n\n\
             https://app.codewire.test/admin/feedback/\n\n--\n\
             You got this email because this address is the operator address of a Codewire server.\n"
        );
        assert!(
            more_waiting_notice(1, URL)
                .text
                .starts_with("1 piece of feedback arrived")
        );
    }

    #[test]
    fn the_admin_link_comes_from_the_configured_address() {
        assert_eq!(feedback_url("https://app.codewire.test/"), URL);
        assert_eq!(feedback_url("https://app.codewire.test"), URL);
    }

    #[test]
    fn retries_are_bounded() {
        assert_eq!(retry_delay(1), Some(Duration::from_secs(60)));
        assert_eq!(retry_delay(2), Some(Duration::from_secs(300)));
        assert_eq!(retry_delay(3), None);
    }
}
