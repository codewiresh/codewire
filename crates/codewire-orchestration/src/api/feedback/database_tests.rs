//! What `cw feedback`'s server promises (#4061): who a row records, each
//! abuse limit with its retry time, that concurrent senders cannot overshoot
//! a limit, and the admin list's order, filter and pages.

use std::sync::Arc;

use super::*;
use crate::test_database_support::TestDatabase;

fn key() -> ClientAddressKey {
    ClientAddressKey::derive("synthetic-feedback-session-secret").unwrap()
}

fn address(text: &str) -> Option<IpAddr> {
    Some(text.parse().unwrap())
}

fn feedback(message: &str) -> NewFeedback<'_> {
    NewFeedback {
        message,
        cli_version: "0.42.0",
        os: "linux",
        arch: "x86_64",
        placement: Some(Placement::Cloud),
        ..NewFeedback::default()
    }
}

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn member(db: &TestDatabase, user_id: &str, org_id: &str) -> anyhow::Result<()> {
    db.user(user_id).await?;
    db.organization(org_id).await?;
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'member')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(org_id)
    .bind(user_id)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn submit(
    db: &TestDatabase,
    user: Option<&AuthUser>,
    from: Option<IpAddr>,
    feedback: &NewFeedback<'_>,
) -> Result<StoredFeedback, SubmitFeedbackError> {
    submit_feedback(&db.pool, &key(), user, from, feedback).await
}

/// The limit that refused, and its retry delay in seconds.
fn limited(result: Result<StoredFeedback, SubmitFeedbackError>) -> (LimitScope, u64) {
    match result {
        Err(SubmitFeedbackError::Limited { scope, retry_after }) => (scope, retry_after.as_secs()),
        other => panic!("expected a limit refusal, got {other:?}"),
    }
}

/// Moves every row matching `filter` `minutes` into the past.
async fn age(db: &TestDatabase, filter: &str, minutes: i32) -> anyhow::Result<()> {
    sqlx::query(&format!(
        "UPDATE feedback SET created_at = created_at - make_interval(mins => $1) WHERE {filter}"
    ))
    .bind(minutes)
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_row_records_the_sender_and_only_what_was_attached() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        member(&db, "feedback-user", "feedback-org").await?;
        db.organization("feedback-other-org").await?;
        let user = session("feedback-user");

        let mut signed_in = feedback("signed in, with my organization");
        signed_in.org_id = Some("feedback-org");
        signed_in.environment_id = Some("env-123");
        let stored = submit(&db, Some(&user), address("203.0.113.9"), &signed_in)
            .await
            .unwrap();
        anyhow::ensure!(stored.signed_in);
        let row = sqlx::query(
            "SELECT user_id, organization_id, message, cli_version, os, arch, placement, \
                    environment_id, client_address_hash FROM feedback WHERE id = $1",
        )
        .bind(&stored.id)
        .fetch_one(&db.pool)
        .await?;
        let column = |name: &str| row.try_get::<Option<String>, _>(name);
        anyhow::ensure!(column("user_id")?.as_deref() == Some("feedback-user"));
        anyhow::ensure!(column("organization_id")?.as_deref() == Some("feedback-org"));
        anyhow::ensure!(column("message")?.as_deref() == Some("signed in, with my organization"));
        anyhow::ensure!(column("cli_version")?.as_deref() == Some("0.42.0"));
        anyhow::ensure!(column("os")?.as_deref() == Some("linux"));
        anyhow::ensure!(column("arch")?.as_deref() == Some("x86_64"));
        anyhow::ensure!(column("placement")?.as_deref() == Some("cloud"));
        anyhow::ensure!(column("environment_id")?.as_deref() == Some("env-123"));
        // The address is kept only as its keyed hash.
        anyhow::ensure!(column("client_address_hash")? == Some(key().hash("203.0.113.9".parse()?)));
        let raw: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM feedback WHERE client_address_hash LIKE '%203.0.113%'",
        )
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(raw == 0);

        // An organization the sender does not belong to is refused.
        let mut foreign = feedback("not my organization");
        foreign.org_id = Some("feedback-other-org");
        anyhow::ensure!(matches!(
            submit(&db, Some(&user), None, &foreign).await,
            Err(SubmitFeedbackError::Rejected(AppError::NotFound(_)))
        ));
        // An API key records its own organization and names no other.
        let api_key = AuthUser {
            org_id: Some("feedback-org".into()),
            via_api_key: true,
            ..session("feedback-user")
        };
        let stored = submit(&db, Some(&api_key), None, &feedback("via a key"))
            .await
            .unwrap();
        let org: Option<String> =
            sqlx::query_scalar("SELECT organization_id FROM feedback WHERE id = $1")
                .bind(&stored.id)
                .fetch_one(&db.pool)
                .await?;
        anyhow::ensure!(org.as_deref() == Some("feedback-org"));
        anyhow::ensure!(matches!(
            submit(&db, Some(&api_key), None, &foreign).await,
            Err(SubmitFeedbackError::Rejected(AppError::NotFound(_)))
        ));

        // Anonymous feedback records neither, and may not name an organization.
        let stored = submit(&db, None, None, &feedback("anonymous"))
            .await
            .unwrap();
        anyhow::ensure!(!stored.signed_in);
        let anonymous: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT user_id, organization_id, client_address_hash FROM feedback WHERE id = $1",
        )
        .bind(&stored.id)
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(anonymous == (None, None, None));
        let mut anonymous_org = feedback("anonymous with an organization");
        anonymous_org.org_id = Some("feedback-org");
        anyhow::ensure!(matches!(
            submit(&db, None, None, &anonymous_org).await,
            Err(SubmitFeedbackError::Rejected(AppError::Validation { .. }))
        ));
        // Validation runs before anything is stored.
        let oversized = "x".repeat(MAX_MESSAGE_BYTES + 1);
        anyhow::ensure!(matches!(
            submit(&db, None, None, &feedback(&oversized)).await,
            Err(SubmitFeedbackError::Rejected(AppError::Validation { .. }))
        ));
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback")
            .fetch_one(&db.pool)
            .await?;
        anyhow::ensure!(total == 3, "total {total}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_signed_in_user_sends_at_most_10_an_hour() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user("feedback-busy").await?;
        db.user("feedback-quiet").await?;
        let busy = session("feedback-busy");
        for n in 0..PER_USER_PER_HOUR {
            submit(&db, Some(&busy), address("198.51.100.1"), &feedback("hi"))
                .await
                .map_err(|error| anyhow::anyhow!("submission {n}: {error:?}"))?;
        }
        let (scope, retry) = limited(submit(&db, Some(&busy), None, &feedback("one more")).await);
        anyhow::ensure!(scope == LimitScope::User);
        anyhow::ensure!((3590..=3600).contains(&retry), "retry {retry}");
        // Another user, even from the same address, has their own allowance.
        submit(
            &db,
            Some(&session("feedback-quiet")),
            address("198.51.100.1"),
            &feedback("hi"),
        )
        .await
        .unwrap();

        // The oldest counted row decides the wait: 59 minutes old, it leaves
        // the window in about a minute.
        age(&db, "user_id = 'feedback-busy'", 59).await?;
        let (_, retry) = limited(submit(&db, Some(&busy), None, &feedback("one more")).await);
        anyhow::ensure!((50..=60).contains(&retry), "retry {retry}");
        // Once the hour has passed, a full allowance fits again.
        age(&db, "user_id = 'feedback-busy'", 2).await?;
        for n in 0..PER_USER_PER_HOUR {
            submit(&db, Some(&busy), None, &feedback("later"))
                .await
                .map_err(|error| anyhow::anyhow!("later submission {n}: {error:?}"))?;
        }
        let (scope, _) = limited(submit(&db, Some(&busy), None, &feedback("again")).await);
        anyhow::ensure!(scope == LimitScope::User);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_anonymous_senders_send_at_most_5_an_hour_per_address() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user("feedback-signed-in").await?;
        for n in 0..PER_ANONYMOUS_ADDRESS_PER_HOUR {
            submit(&db, None, address("192.0.2.7"), &feedback("hi"))
                .await
                .map_err(|error| anyhow::anyhow!("submission {n}: {error:?}"))?;
        }
        let (scope, retry) = limited(submit(&db, None, address("192.0.2.7"), &feedback("6")).await);
        anyhow::ensure!(scope == LimitScope::AnonymousAddress);
        anyhow::ensure!((3590..=3600).contains(&retry), "retry {retry}");
        // The same address as IPv4-mapped IPv6 is the same sender.
        let (scope, _) =
            limited(submit(&db, None, address("::ffff:192.0.2.7"), &feedback("6")).await);
        anyhow::ensure!(scope == LimitScope::AnonymousAddress);
        // Another address, and a signed-in sender at this one, are not limited.
        submit(&db, None, address("192.0.2.8"), &feedback("hi"))
            .await
            .unwrap();
        submit(
            &db,
            Some(&session("feedback-signed-in")),
            address("192.0.2.7"),
            &feedback("hi"),
        )
        .await
        .unwrap();
        // One IPv6 /64 is one sender.
        for host in 1..=PER_ANONYMOUS_ADDRESS_PER_HOUR {
            submit(
                &db,
                None,
                address(&format!("2001:db8:7:7::{host:x}")),
                &feedback("hi"),
            )
            .await
            .unwrap();
        }
        let (scope, _) =
            limited(submit(&db, None, address("2001:db8:7:7::ffff"), &feedback("6")).await);
        anyhow::ensure!(scope == LimitScope::AnonymousAddress);
        // Senders whose address is unknown share one allowance.
        for _ in 0..PER_ANONYMOUS_ADDRESS_PER_HOUR {
            submit(&db, None, None, &feedback("hi")).await.unwrap();
        }
        let (scope, _) = limited(submit(&db, None, None, &feedback("6")).await);
        anyhow::ensure!(scope == LimitScope::AnonymousAddress);
        // An hour later the address may send again.
        age(&db, "client_address_hash IS NOT NULL", 61).await?;
        submit(&db, None, address("192.0.2.7"), &feedback("later"))
            .await
            .unwrap();
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_everyone_together_sends_at_most_500_an_hour() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user("feedback-fresh").await?;
        // 499 recent rows from many senders, the oldest 30 minutes old.
        sqlx::query(
            "INSERT INTO feedback (created_at, message, cli_version, os, arch, client_address_hash) \
             SELECT now() - make_interval(mins => 30) + make_interval(secs => n), 'm', '1', \
                    'linux', 'x86_64', md5(n::text) || md5(n::text) \
               FROM generate_series(1, 499) AS n",
        )
        .execute(&db.pool)
        .await?;
        submit(&db, None, address("192.0.2.1"), &feedback("the 500th")).await.unwrap();
        // Any sender, signed in or not, now waits for the oldest to leave.
        let (scope, retry) = limited(
            submit(&db, Some(&session("feedback-fresh")), None, &feedback("501")).await,
        );
        anyhow::ensure!(scope == LimitScope::Global);
        anyhow::ensure!((1790..=1801).contains(&retry), "retry {retry}");
        let (scope, _) = limited(submit(&db, None, address("192.0.2.2"), &feedback("501")).await);
        anyhow::ensure!(scope == LimitScope::Global);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_concurrent_senders_never_overshoot_a_limit() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = db.pool.clone();
        let key = Arc::new(key());
        let mut senders = Vec::new();
        for _ in 0..20 {
            let (pool, key) = (pool.clone(), key.clone());
            senders.push(tokio::spawn(async move {
                submit_feedback(&pool, &key, None, address("192.0.2.99"), &feedback("burst"))
                    .await
                    .is_ok()
            }));
        }
        let mut stored = 0;
        for sender in senders {
            stored += i64::from(sender.await?);
        }
        anyhow::ensure!(stored == PER_ANONYMOUS_ADDRESS_PER_HOUR, "stored {stored}");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback")
            .fetch_one(&db.pool)
            .await?;
        anyhow::ensure!(rows == PER_ANONYMOUS_ADDRESS_PER_HOUR, "rows {rows}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_admin_list_is_newest_first_filtered_and_paged() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        member(&db, "feedback-lister", "feedback-list-org").await?;
        let user = session("feedback-lister");
        let mut ids = Vec::new();
        for n in 0..5 {
            let mut entry = feedback("message");
            let text = format!("message {n}");
            entry.message = &text;
            let stored = if n % 2 == 0 {
                entry.org_id = Some("feedback-list-org");
                submit(&db, Some(&user), None, &entry).await
            } else {
                submit(&db, None, address(&format!("192.0.2.{n}")), &entry).await
            }
            .unwrap();
            ids.push(stored.id);
            // Distinct, ordered timestamps.
            age(&db, "TRUE", 1).await?;
        }
        ids.reverse();

        let all = list_feedback(&db.pool, DEFAULT_LIST_LIMIT, "", SenderFilter::All).await?;
        anyhow::ensure!(all.feedback.iter().map(|row| &row.id).eq(ids.iter()));
        anyhow::ensure!(all.next_page_token.is_empty());
        let newest = &all.feedback[0];
        anyhow::ensure!(newest.message == "message 4");
        anyhow::ensure!(newest.user_email.as_deref() == Some("feedback-lister@example.test"));
        anyhow::ensure!(newest.organization_name.as_deref() == Some("feedback-list-org"));
        anyhow::ensure!(newest.placement.as_deref() == Some("cloud"));

        let signed_in = list_feedback(&db.pool, 50, "", SenderFilter::SignedIn).await?;
        anyhow::ensure!(signed_in.feedback.len() == 3);
        anyhow::ensure!(signed_in.feedback.iter().all(|row| row.user_id.is_some()));
        let anonymous = list_feedback(&db.pool, 50, "", SenderFilter::Anonymous).await?;
        anyhow::ensure!(anonymous.feedback.len() == 2);
        anyhow::ensure!(
            anonymous
                .feedback
                .iter()
                .all(|row| row.user_id.is_none() && row.organization_id.is_none())
        );

        // Pages of two walk the whole list once, in order.
        let mut walked = Vec::new();
        let mut token = String::new();
        loop {
            let page = list_feedback(&db.pool, 2, &token, SenderFilter::All).await?;
            walked.extend(page.feedback.into_iter().map(|row| row.id));
            if page.next_page_token.is_empty() {
                break;
            }
            token = page.next_page_token;
        }
        anyhow::ensure!(walked == ids, "{walked:?}");
        anyhow::ensure!(
            list_feedback(&db.pool, 0, "", SenderFilter::All)
                .await
                .is_err()
        );
        anyhow::ensure!(
            list_feedback(&db.pool, 201, "", SenderFilter::All)
                .await
                .is_err()
        );
        anyhow::ensure!(
            list_feedback(&db.pool, 2, "garbage", SenderFilter::All)
                .await
                .is_err()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
