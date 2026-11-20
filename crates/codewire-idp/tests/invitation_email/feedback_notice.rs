//! Synthetic database proof for the operator's feedback email (#5466), the
//! second outbox idp sends: each queued piece of feedback is emailed once to
//! the operator, with the sender's verified address as Reply-To and none for
//! anonymous feedback; past ten an hour one "more feedback is waiting" email
//! goes and the rest are skipped; a failing provider is retried a bounded
//! number of times and leaves the feedback stored; without an operator
//! address or mail nothing is sent; feedback deleted with its account is
//! never emailed.

use std::sync::Mutex;

use async_trait::async_trait;
use codewire_idp::feedback_notice::{FeedbackMailer, MAX_ATTEMPTS, PassReport, run_pass};

use super::{FRONTEND, TestDatabase};

const OPERATOR: &str = "operator@example.test";

/// One email as the mailer was given it: to, Reply-To, subject, text.
type Sent = (String, Option<String>, String, String);

/// Records each email; fails every send while `failing`.
#[derive(Default)]
struct Mailer {
    available: bool,
    failing: bool,
    sent: Mutex<Vec<Sent>>,
}

impl Mailer {
    fn working() -> Self {
        Self {
            available: true,
            ..Self::default()
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl FeedbackMailer for Mailer {
    fn is_available(&self) -> bool {
        self.available
    }

    async fn send(
        &self,
        to: &str,
        reply_to: Option<&str>,
        subject: &str,
        text: &str,
    ) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push((
            to.into(),
            reply_to.map(str::to_owned),
            subject.into(),
            text.into(),
        ));
        if self.failing {
            anyhow::bail!("SES email request failed with HTTP 400 (MessageRejected)");
        }
        Ok(())
    }
}

impl TestDatabase {
    /// A piece of feedback from `user` (anonymous when `None`) with its
    /// queued email, as SubmitFeedback writes them.
    async fn feedback(&self, id: &str, user: Option<&str>, message: &str) {
        sqlx::query(
            "INSERT INTO feedback (id, user_id, organization_id, message, cli_version, os, arch, placement) \
             VALUES ($1, $2::text, CASE WHEN $2::text IS NULL THEN NULL ELSE 'org' END, $3, '0.4.24', 'linux', 'x86_64', 'local')",
        )
        .bind(id)
        .bind(user)
        .bind(message)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO feedback_notices (feedback_id) VALUES ($1)")
            .bind(id)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn notice(&self, id: &str) -> Option<(String, i32)> {
        sqlx::query_as("SELECT status, attempts FROM feedback_notices WHERE feedback_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .unwrap()
    }

    async fn make_notices_due(&self) {
        sqlx::query("UPDATE feedback_notices SET next_attempt_at = now() WHERE status = 'pending'")
            .execute(&self.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn feedback_is_emailed_once_with_the_verified_sender_as_reply_to() {
    let Some(db) = TestDatabase::create("feedback_sent").await else {
        return;
    };
    sqlx::raw_sql(
        "INSERT INTO users (id, email, name, email_verified) VALUES \
         ('verified', 'grace@example.test', 'Grace', true), \
         ('unverified', 'eve@example.test', 'Eve', false);",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.feedback(
        "from-verified",
        Some("verified"),
        "Hi\r\nBcc: x@example.test",
    )
    .await;
    db.feedback("from-unverified", Some("unverified"), "hello")
        .await;
    db.feedback("anonymous", None, "anonymous hello").await;
    let mailer = Mailer::working();

    let report = run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(
        report,
        PassReport {
            sent: 3,
            ..PassReport::default()
        }
    );
    let sent = mailer.sent();
    let by_subject = |id: &str| {
        sent.iter()
            .find(|email| email.2 == format!("Codewire feedback {id}"))
            .cloned()
            .unwrap()
    };
    let (to, reply_to, _, text) = by_subject("from-verified");
    assert_eq!(to, OPERATOR);
    assert_eq!(reply_to.as_deref(), Some("grace@example.test"));
    assert!(
        text.contains("From: Grace <grace@example.test> (verified)\nOrganization: Acme & Co\n")
    );
    assert!(text.contains("Sent with: cw 0.4.24, linux x86_64, local\n"));
    assert!(text.contains("Message:\n\nHi\nBcc: x@example.test\n\n"));
    assert!(text.contains("All feedback: https://app.codewire.test/admin/feedback/\n"));
    let (_, reply_to, _, text) = by_subject("from-unverified");
    assert_eq!(reply_to, None);
    assert!(text.contains("From: Eve <eve@example.test> (not verified)\n"));
    let (_, reply_to, _, text) = by_subject("anonymous");
    assert_eq!(reply_to, None);
    assert!(text.contains("From: Anonymous\nOrganization: none\n"));
    for id in ["from-verified", "from-unverified", "anonymous"] {
        assert_eq!(db.notice(id).await, Some(("sent".into(), 1)));
    }

    let again = run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(again, PassReport::default());
    assert_eq!(mailer.sent().len(), 3);
    db.drop().await;
}

#[tokio::test]
async fn past_ten_an_hour_one_more_waiting_email_goes_and_the_rest_are_skipped() {
    let Some(db) = TestDatabase::create("feedback_limit").await else {
        return;
    };
    for n in 0..12 {
        db.feedback(&format!("burst-{n:02}"), None, "burst").await;
    }
    let mailer = Mailer::working();

    let report = run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(
        report,
        PassReport {
            sent: 10,
            limited: 2,
            ..PassReport::default()
        }
    );
    let sent = mailer.sent();
    assert_eq!(sent.len(), 11, "ten emails and one more-waiting email");
    let waiting: Vec<_> = sent
        .iter()
        .filter(|email| email.2 == "Codewire: more feedback is waiting")
        .collect();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].1, None);
    assert!(
        waiting[0]
            .3
            .starts_with("12 pieces of feedback arrived in the last hour")
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored, 12, "every piece is still stored");
    let skipped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM feedback_notices WHERE status = 'skipped'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(skipped, 2);

    // The rest of the hour sends nothing at all.
    db.feedback("burst-late", None, "late").await;
    run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(mailer.sent().len(), 11);
    assert_eq!(db.notice("burst-late").await, Some(("skipped".into(), 1)));
    db.drop().await;
}

#[tokio::test]
async fn a_failing_provider_is_retried_then_failed_and_the_feedback_stays() {
    let Some(db) = TestDatabase::create("feedback_fail").await else {
        return;
    };
    db.feedback("fails", None, "hello").await;
    let mailer = Mailer {
        available: true,
        failing: true,
        ..Mailer::default()
    };
    for attempt in 1..=MAX_ATTEMPTS {
        let report = run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
            .await
            .unwrap();
        let expected = if attempt < MAX_ATTEMPTS {
            PassReport {
                retrying: 1,
                ..PassReport::default()
            }
        } else {
            PassReport {
                failed: 1,
                ..PassReport::default()
            }
        };
        assert_eq!(report, expected, "attempt {attempt}");
        db.make_notices_due().await;
    }
    assert_eq!(
        db.notice("fails").await,
        Some(("failed".into(), MAX_ATTEMPTS))
    );
    assert_eq!(mailer.sent().len(), usize::try_from(MAX_ATTEMPTS).unwrap());
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback WHERE id = 'fails'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
    db.drop().await;
}

#[tokio::test]
async fn without_an_operator_address_or_mail_nothing_is_sent() {
    let Some(db) = TestDatabase::create("feedback_unsent").await else {
        return;
    };
    db.feedback("no-operator", None, "hello").await;
    let mailer = Mailer::working();
    let report = run_pass(&db.pool, &mailer, None, FRONTEND).await.unwrap();
    assert_eq!(
        report,
        PassReport {
            unsent: 1,
            ..PassReport::default()
        }
    );
    assert_eq!(db.notice("no-operator").await, Some(("skipped".into(), 0)));

    db.feedback("no-mail", None, "hello").await;
    let unavailable = Mailer::default();
    let report = run_pass(&db.pool, &unavailable, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(report.unsent, 1);
    assert!(mailer.sent().is_empty() && unavailable.sent().is_empty());
    db.drop().await;
}

#[tokio::test]
async fn feedback_deleted_with_its_account_is_never_emailed() {
    let Some(db) = TestDatabase::create("feedback_deleted").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, email, email_verified) VALUES ('leaving', 'leaving@example.test', true)")
        .execute(&db.pool)
        .await
        .unwrap();
    db.feedback("from-leaving", Some("leaving"), "bye").await;
    sqlx::query("DELETE FROM users WHERE id = 'leaving'")
        .execute(&db.pool)
        .await
        .unwrap();
    let mailer = Mailer::working();
    let report = run_pass(&db.pool, &mailer, Some(OPERATOR), FRONTEND)
        .await
        .unwrap();
    assert_eq!(report, PassReport::default());
    assert!(mailer.sent().is_empty());
    assert_eq!(db.notice("from-leaving").await, None);
    db.drop().await;
}
