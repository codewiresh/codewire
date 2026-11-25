//! The refusal subject bound against PostgreSQL (#6189; SPEC.md "Bounds"):
//! the hour's 1,001st subject goes to the overflow row, a repeated one is
//! counted once, past 1,000 overflowed subjects it says at least, a subject
//! that already folds keeps folding, a new hour starts fresh, the flush
//! moves the overflow like any fold, and a grouped read counts its subjects
//! as left out. Each case owns a disposable database.

use anyhow::{Result, ensure};
use chrono::{DateTime, DurationRound as _, TimeDelta, Utc};
use codewire_egress_policy::lease::RefusalReason;
use sqlx::PgPool;

use super::bound::SUBJECT_BOUND;
use super::read::{self, EnvironmentRef, Query};
use super::store::{self, Event};
use super::*;
use crate::lease_owner::INCARNATION_GRACE;
use crate::test_database_support::TestDatabase;

const ORG: &str = "audit-bound-org";
const ENV: &str = "550e8400-e29b-41d4-a716-446655446190";

fn refused(destination: &str) -> What {
    What::Refused(Refusal {
        destination: Some(destination.into()),
        withheld: false,
        address: None,
        port: Some(443),
        protocol: Protocol::Tcp,
        reason: RefusalReason::NameNotAllowed,
        source: RefusalSource::Network,
        policy: Some("walk-docs".into()),
        revision: Some(1),
    })
}

/// Ten minutes into the hour before this one: a whole hour that has ended.
fn last_hour() -> Result<DateTime<Utc>> {
    Ok(Utc::now().duration_trunc(TimeDelta::hours(1))? - TimeDelta::minutes(50))
}

async fn refuse(pool: &PgPool, destination: &str, at: DateTime<Utc>, count: u64) -> Result<()> {
    let mut event = Event::once(ORG, ENV, Actor::Sandbox, at, refused(destination));
    event.count = count;
    let mut connection = pool.acquire().await?;
    record(&mut connection, &event).await?;
    Ok(())
}

/// The hour's folds that are not the overflow.
async fn folds(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM sandbox_audit_pending WHERE kind = 'refused' AND action = 'refused'",
    )
    .fetch_one(pool)
    .await?)
}

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
struct Overflow {
    subject: String,
    actor_type: String,
    count: i64,
    subjects: i64,
    at_least: bool,
    hashes: i32,
}

/// The overflow rows in `table`, oldest first.
async fn overflow(pool: &PgPool, table: &str) -> Result<Vec<Overflow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT subject, actor_type, count, (detail->>'subjects')::bigint AS subjects, \
         (detail->>'at_least')::boolean AS at_least, \
         jsonb_array_length(detail->'subject_hashes') AS hashes \
         FROM {table} WHERE kind = 'refused' AND action = 'overflow' ORDER BY first_at"
    ))
    .fetch_all(pool)
    .await?)
}

/// Folds the bound's full set of subjects in the hour of `at`.
async fn fill(pool: &PgPool, at: DateTime<Utc>) -> Result<()> {
    for index in 0..SUBJECT_BOUND {
        refuse(pool, &format!("h{index}.example.com"), at, 1).await?;
    }
    Ok(())
}

macro_rules! database_case {
    ($name:ident, $pool:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let database = TestDatabase::create().await?;
            let result = async {
                database.organization(ORG).await?;
                let $pool = &database.pool;
                store::ensure_partitions($pool).await?;
                $body
                Ok(())
            }
            .await;
            database.finish(result).await
        }
    };
}

database_case!(
    db_the_hours_next_subject_overflows_and_a_repeat_counts_once,
    pool,
    {
        let at = last_hour()?;
        let bound = i64::try_from(SUBJECT_BOUND)?;
        fill(pool, at).await?;
        ensure!(folds(pool).await? == bound);
        ensure!(overflow(pool, "sandbox_audit_pending").await?.is_empty());

        // The 1,001st subject, then again: its events add, it counts once.
        refuse(pool, "past.example.com", at, 3).await?;
        refuse(pool, "past.example.com", at + TimeDelta::minutes(1), 2).await?;
        // A subject that already folds this hour keeps folding.
        refuse(pool, "h7.example.com", at, 4).await?;
        ensure!(folds(pool).await? == bound, "no row past the bound");
        let expected = Overflow {
            subject: "overflow".into(),
            actor_type: "sandbox".into(),
            count: 5,
            subjects: 1,
            at_least: false,
            hashes: 1,
        };
        let pending = overflow(pool, "sandbox_audit_pending").await?;
        ensure!(pending == [expected], "{pending:?}");
        let h7: i64 = sqlx::query_scalar(
            "SELECT count FROM sandbox_audit_pending WHERE subject LIKE 'h7.example.com|%'",
        )
        .fetch_one(pool)
        .await?;
        ensure!(h7 == 5, "{h7}");

        // This hour starts fresh: the same subject folds as its own row.
        refuse(pool, "past.example.com", Utc::now(), 1).await?;
        ensure!(folds(pool).await? == bound + 1);
        ensure!(overflow(pool, "sandbox_audit_pending").await?.len() == 1);

        // The ended hour's overflow moves with its folds.
        store::flush(pool, INCARNATION_GRACE).await?;
        let moved = overflow(pool, "sandbox_audit_events").await?;
        ensure!(moved.len() == 1 && moved[0].count == 5, "{moved:?}");
        ensure!(overflow(pool, "sandbox_audit_pending").await?.is_empty());
    }
);

database_case!(
    db_past_the_bound_of_overflowed_subjects_the_count_says_at_least,
    pool,
    {
        let at = last_hour()?;
        let bound = u64::try_from(SUBJECT_BOUND)?;
        fill(pool, at).await?;
        for index in 0..SUBJECT_BOUND {
            refuse(pool, &format!("o{index}.example.com"), at, 1).await?;
        }
        let full = overflow(pool, "sandbox_audit_pending").await?;
        ensure!(
            full.len() == 1
                && full[0].subjects == i64::try_from(bound)?
                && !full[0].at_least
                && full[0].count == i64::try_from(bound)?,
            "{full:?}"
        );
        // One already counted changes nothing but the events.
        refuse(pool, "o3.example.com", at, 1).await?;
        ensure!(!overflow(pool, "sandbox_audit_pending").await?[0].at_least);
        // One more distinct subject: at least, and the set stays bounded.
        refuse(pool, "one-more.example.com", at, 1).await?;
        let past = overflow(pool, "sandbox_audit_pending").await?;
        ensure!(
            past.len() == 1
                && past[0].subjects == i64::try_from(bound)?
                && past[0].at_least
                && past[0].hashes == i32::try_from(bound)?
                && past[0].count == i64::try_from(bound + 2)?,
            "{past:?}"
        );
    }
);

/// The read's owner, who owns every fixture organization.
const OWNER: &str = "fixture-admin";

database_case!(
    db_a_grouped_read_counts_the_overflows_subjects_as_left_out,
    pool,
    {
        sqlx::raw_sql(&format!(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ('bound-preset', '{ORG}', 'P', 'p', \
           '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO environments (id, org_id, created_by, preset_id, name, type, state, \
           desired_state, project_spec) \
         VALUES ('{ENV}', '{ORG}', '{OWNER}', 'bound-preset', 'walk-bound', 'sandbox', \
           'running', 'started', \
           '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb);"
        ))
        .execute(pool)
        .await?;
        let at = last_hour()?;
        fill(pool, at).await?;
        for destination in ["a.example.com", "b.example.com", "a.example.com"] {
            refuse(pool, destination, at, 1).await?;
        }
        let reader = codewire_server_core::auth::AuthUser {
            user_id: OWNER.into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let grouped = Query {
            org_id: ORG.into(),
            environment: EnvironmentRef::Id(ENV.into()),
            kinds: vec![Kind::Refused],
            since: None,
            until: None,
            limit: 0,
            cursor: None,
            grouped: true,
        };
        let environment = read::authorize(pool, &reader, &grouped).await?;
        let answer = read::read(pool, &reader, &grouped, environment).await?;
        ensure!(
            answer.events.len() == SUBJECT_BOUND && answer.left_out == 2,
            "{} listed, {} left out",
            answer.events.len(),
            answer.left_out
        );
    }
);
