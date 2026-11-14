//! Synthetic database proof for the organization invitation email sender
//! (#3847): it sends each due email once, skips one whose invitation is no
//! longer pending, retries a failure a bounded number of times, reports an
//! unconfigured deployment, never lets two senders claim one row, and fences
//! a stale claimant's result. Each test runs in its own freshly migrated
//! database with a recording mailer; nothing is sent. The integration runner
//! rejects a missing DATABASE_URL skip.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use codewire_email::Email;
use codewire_idp::invitation_email::{
    InvitationMailer, MAX_ATTEMPTS, NOT_CONFIGURED, PassReport, Recorded, SendOutcome, claim_next,
    record_result, run_pass,
};
use sqlx::PgPool;

/// The configured frontend URL; the email's button goes to its `/login`.
const FRONTEND: &str = "https://app.codewire.test";

/// A disposable, migrated database, dropped by [`TestDatabase::drop`].
struct TestDatabase {
    admin: PgPool,
    name: String,
    pool: PgPool,
}

impl TestDatabase {
    async fn create(label: &str) -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping invitation email DB proof");
            return None;
        };
        let admin = PgPool::connect(&url).await.unwrap();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("cw_idp_invite_{label}_{}_{nanos}", std::process::id());
        sqlx::query(&format!(r#"CREATE DATABASE "{name}""#))
            .execute(&admin)
            .await
            .unwrap();
        let mut test_url = url::Url::parse(&url).unwrap();
        test_url.set_path(&name);
        codewire_server_core::migrate::ensure_schema(test_url.as_str())
            .await
            .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(test_url.as_str())
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO users (id, email, name) VALUES ('inviter', 'inviter@example.test', 'Ada'); \
             INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('org', 'Acme & Co', 'acme', 'inviter');",
        )
        .execute(&pool)
        .await
        .unwrap();
        Some(Self { admin, name, pool })
    }

    /// An invitation in `status` expiring after `expires` (an SQL interval)
    /// with its queued email.
    async fn queue(&self, id: &str, status: &str, expires: &str) {
        sqlx::query(
            "INSERT INTO org_invitations \
             (id, org_id, email, role, invited_by, token_hash, status, expires_at) \
             VALUES ($1, 'org', $1 || '@example.test', 'admin', 'inviter', \
                     encode(sha256($1::bytea), 'hex'), $2, NOW() + $3::interval)",
        )
        .bind(id)
        .bind(status)
        .bind(expires)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO org_invitation_emails \
             (invitation_id, recipient, org_id, org_name, org_slug, inviter, role) \
             VALUES ($1, $1 || '@example.test', 'org', 'Acme & Co', 'acme', 'Ada', 'admin')",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn row(&self, id: &str) -> EmailRow {
        sqlx::query_as(
            "SELECT status, attempts, last_error, claimed_until IS NOT NULL AS claimed, \
                    next_attempt_at <= now() AS due \
             FROM org_invitation_emails WHERE invitation_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    /// Makes every pending email due now, as the retry delay passing would.
    async fn make_due(&self) {
        sqlx::query(
            "UPDATE org_invitation_emails SET next_attempt_at = now() WHERE status = 'pending'",
        )
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            self.name
        ))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

/// One outbox row as the sender left it.
#[derive(sqlx::FromRow)]
struct EmailRow {
    status: String,
    attempts: i32,
    last_error: Option<String>,
    /// A claim's lease is set.
    claimed: bool,
    /// It is due for an attempt now.
    due: bool,
}

/// Records each email; fails the first `failures` sends with `error`, and
/// waits `delay` inside each send.
#[derive(Default)]
struct RecordingMailer {
    available: bool,
    failures: Mutex<usize>,
    error: String,
    delay: Duration,
    sent: Mutex<Vec<(String, Email)>>,
}

impl RecordingMailer {
    fn working() -> Self {
        Self {
            available: true,
            ..Self::default()
        }
    }

    fn failing(failures: usize, error: &str) -> Self {
        Self {
            available: true,
            failures: Mutex::new(failures),
            error: error.into(),
            ..Self::default()
        }
    }

    fn recipients(&self) -> Vec<String> {
        let mut recipients: Vec<_> = self
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(to, _)| to.clone())
            .collect();
        recipients.sort();
        recipients
    }
}

#[async_trait]
impl InvitationMailer for RecordingMailer {
    fn is_available(&self) -> bool {
        self.available
    }

    async fn send(&self, to: &str, email: &Email) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        self.sent.lock().unwrap().push((to.into(), email.clone()));
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            anyhow::bail!("{}", self.error);
        }
        Ok(())
    }
}

/// A due email is sent once, to its recipient, with the rendered tokenless
/// body, and recorded as sent; the next pass sends nothing.
#[tokio::test]
async fn a_queued_email_is_sent_once_and_recorded() {
    let Some(db) = TestDatabase::create("sent").await else {
        return;
    };
    db.queue("invitee", "pending", "7 days").await;
    let mailer = RecordingMailer::working();

    let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(
        report,
        PassReport {
            sent: 1,
            ..PassReport::default()
        }
    );
    let sent = mailer.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let (to, email) = &sent[0];
    assert_eq!(to, "invitee@example.test");
    assert_eq!(
        email.subject,
        "You're invited to join an organization on Codewire"
    );
    let (html, text) = (email.html(), email.text());
    assert!(html.contains("Ada invited you to join Acme &amp; Co on Codewire"));
    assert!(text.contains("Ada invited you to join Acme & Co on Codewire"));
    assert!(text.contains("    cw login\n    cw org accept acme\n"));
    assert!(html.contains(r#"href="https://app.codewire.test/login""#));
    assert!(text.contains(
        "sign in at https://app.codewire.test with this email address (invitee@example.test), or accept it with the CLI:"
    ));
    let token_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM org_invitations WHERE id = 'invitee'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    for part in [&html, &text] {
        assert!(!part.contains(&token_hash) && !part.contains("token"));
    }

    let EmailRow {
        status,
        attempts,
        last_error: error,
        claimed,
        ..
    } = db.row("invitee").await;
    assert_eq!(
        (status.as_str(), attempts, error, claimed),
        ("sent", 1, None, false)
    );
    let sent_at: bool = sqlx::query_scalar(
        "SELECT sent_at IS NOT NULL FROM org_invitation_emails WHERE invitation_id = 'invitee'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(sent_at);

    let again = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(again, PassReport::default());
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
    db.drop().await;
}

/// An email whose invitation was revoked, accepted or has expired is
/// skipped with the reason, and nothing is sent.
#[tokio::test]
async fn an_email_for_a_settled_invitation_is_skipped() {
    let Some(db) = TestDatabase::create("skip").await else {
        return;
    };
    db.queue("revoked", "revoked", "7 days").await;
    db.queue("accepted", "accepted", "7 days").await;
    db.queue("lapsed", "pending", "-1 minute").await;
    db.queue("pending", "pending", "7 days").await;
    let mailer = RecordingMailer::working();

    let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(report.skipped, 3);
    assert_eq!(report.sent, 1);
    assert_eq!(mailer.recipients(), ["pending@example.test"]);
    for (id, reason) in [
        (
            "revoked",
            "the invitation was revoked before its email was sent",
        ),
        (
            "accepted",
            "the invitation was accepted before its email was sent",
        ),
        ("lapsed", "the invitation expired before its email was sent"),
    ] {
        let EmailRow {
            status,
            attempts,
            last_error: error,
            claimed,
            ..
        } = db.row(id).await;
        assert_eq!(
            (status.as_str(), attempts, error.as_deref(), claimed),
            ("skipped", 0, Some(reason), false),
            "{id}"
        );
    }
    db.drop().await;
}

/// A failed send stays pending with its reason and a later due time; once it
/// succeeds the reason is cleared.
#[tokio::test]
async fn a_failed_send_is_retried_later_and_can_succeed() {
    let Some(db) = TestDatabase::create("retry").await else {
        return;
    };
    db.queue("invitee", "pending", "7 days").await;
    let mailer = RecordingMailer::failing(1, "SES email request failed with HTTP 503 (Throttling)");

    let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(report.retrying, 1);
    let EmailRow {
        status,
        attempts,
        last_error: error,
        claimed,
        due,
    } = db.row("invitee").await;
    assert_eq!(
        (status.as_str(), attempts, error.as_deref(), claimed, due),
        (
            "pending",
            1,
            Some("SES email request failed with HTTP 503 (Throttling)"),
            false,
            false
        )
    );
    // Not due yet: the next pass leaves it alone.
    assert_eq!(
        run_pass(&db.pool, &mailer, FRONTEND).await.unwrap(),
        PassReport::default()
    );

    db.make_due().await;
    let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(report.sent, 1);
    let EmailRow {
        status,
        attempts,
        last_error: error,
        ..
    } = db.row("invitee").await;
    assert_eq!((status.as_str(), attempts, error), ("sent", 2, None));
    assert_eq!(mailer.sent.lock().unwrap().len(), 2);
    db.drop().await;
}

/// After the bounded attempts the email is failed with a bounded,
/// single-line reason, and never sent again.
#[tokio::test]
async fn a_send_that_keeps_failing_is_failed_after_the_bound() {
    let Some(db) = TestDatabase::create("fail").await else {
        return;
    };
    db.queue("invitee", "pending", "7 days").await;
    let noisy = format!("refused\n{}", "x".repeat(500));
    let mailer = RecordingMailer::failing(usize::MAX, &noisy);

    for attempt in 1..=MAX_ATTEMPTS {
        db.make_due().await;
        let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
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
    }
    let EmailRow {
        status,
        attempts,
        last_error: error,
        claimed,
        ..
    } = db.row("invitee").await;
    assert_eq!(
        (status.as_str(), attempts, claimed),
        ("failed", MAX_ATTEMPTS, false)
    );
    let error = error.unwrap();
    assert!(error.starts_with("refused x"), "{error}");
    assert_eq!(error.chars().count(), 200);

    db.make_due().await;
    assert_eq!(
        run_pass(&db.pool, &mailer, FRONTEND).await.unwrap(),
        PassReport::default()
    );
    assert_eq!(mailer.sent.lock().unwrap().len(), MAX_ATTEMPTS as usize);
    db.drop().await;
}

/// A deployment without email delivery fails the email at once, saying so,
/// so the inviter shares the link instead.
#[tokio::test]
async fn an_unconfigured_deployment_reports_it_and_sends_nothing() {
    let Some(db) = TestDatabase::create("unconfigured").await else {
        return;
    };
    db.queue("invitee", "pending", "7 days").await;
    let mailer = RecordingMailer::default();

    let report = run_pass(&db.pool, &mailer, FRONTEND).await.unwrap();
    assert_eq!(report.failed, 1);
    let EmailRow {
        status,
        attempts,
        last_error: error,
        ..
    } = db.row("invitee").await;
    assert_eq!(
        (status.as_str(), attempts, error.as_deref()),
        ("failed", 1, Some(NOT_CONFIGURED))
    );
    assert!(mailer.sent.lock().unwrap().is_empty());
    db.drop().await;
}

/// Two replicas passing at once over the same due emails send each exactly
/// once: a claimed row is skipped by the other, never sent twice.
#[tokio::test]
async fn concurrent_senders_send_each_email_once() {
    let Some(db) = TestDatabase::create("concurrent").await else {
        return;
    };
    let ids: Vec<String> = (0..8).map(|n| format!("invitee{n}")).collect();
    for id in &ids {
        db.queue(id, "pending", "7 days").await;
    }
    let mailer = RecordingMailer {
        delay: Duration::from_millis(50),
        ..RecordingMailer::working()
    };

    let (first, second) = tokio::join!(
        run_pass(&db.pool, &mailer, FRONTEND),
        run_pass(&db.pool, &mailer, FRONTEND)
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(first.sent + second.sent, ids.len());
    assert!(
        first.sent > 0 && second.sent > 0,
        "both senders worked: {first:?} {second:?}"
    );
    let mut expected: Vec<String> = ids.iter().map(|id| format!("{id}@example.test")).collect();
    expected.sort();
    assert_eq!(mailer.recipients(), expected);
    let unsent: i64 =
        sqlx::query_scalar("SELECT count(*) FROM org_invitation_emails WHERE status <> 'sent'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(unsent, 0);
    db.drop().await;
}

/// A held claim is not claimed again; one whose lease lapsed is, and the
/// stale claimant's result is then refused, so it cannot overwrite the newer
/// claim's.
#[tokio::test]
async fn a_lapsed_claim_is_taken_over_and_its_result_fenced() {
    let Some(db) = TestDatabase::create("lease").await else {
        return;
    };
    db.queue("invitee", "pending", "7 days").await;

    let stale = claim_next(&db.pool, Duration::from_secs(60))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale.attempts, 1);
    assert_eq!(stale.org_slug, "acme");
    assert!(
        claim_next(&db.pool, Duration::from_secs(60))
            .await
            .unwrap()
            .is_none(),
        "a held claim is not claimed again"
    );

    sqlx::query("UPDATE org_invitation_emails SET claimed_until = now() - interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    let current = claim_next(&db.pool, Duration::from_secs(60))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.attempts, 2);

    assert_eq!(
        record_result(&db.pool, &stale, &SendOutcome::Failed("stale".into()))
            .await
            .unwrap(),
        Recorded::Superseded
    );
    assert_eq!(
        record_result(&db.pool, &current, &SendOutcome::Sent)
            .await
            .unwrap(),
        Recorded::Sent
    );
    assert_eq!(
        record_result(&db.pool, &stale, &SendOutcome::Sent)
            .await
            .unwrap(),
        Recorded::Superseded
    );
    let EmailRow {
        status,
        attempts,
        last_error: error,
        claimed,
        ..
    } = db.row("invitee").await;
    assert_eq!(
        (status.as_str(), attempts, error, claimed),
        ("sent", 2, None, false)
    );
    db.drop().await;
}
