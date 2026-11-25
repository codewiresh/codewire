//! The audit log's writer against PostgreSQL (#6189): an event that doesn't
//! fold is one row at once; a fold adds to its subject's row for the hour;
//! an exec session folds and a terminal waits open; a flush moves a closed
//! session, one whose process is gone (closed at its last heartbeat) and a
//! fold whose hour ended, and leaves the rest; expiry removes old events.
//! Each case owns a disposable database; times are set in the past rather
//! than waited for.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Result, ensure};
use chrono::{DateTime, DurationRound as _, TimeDelta, Utc};
use codewire_egress_policy::lease::RefusalReason;
use sqlx::PgPool;

use super::store::{self, Event};
use super::*;
use crate::lease_owner::INCARNATION_GRACE;
use crate::test_database_support::TestDatabase;

const ORG: &str = "audit-org";
const ENV: &str = "550e8400-e29b-41d4-a716-446655446189";
const HOLDER: i64 = 0x6189_0001;
const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

fn ana() -> Actor {
    Actor::User {
        id: "audit-user".into(),
        email: "ana@example.com".into(),
        role: Role::Member,
    }
}

fn ago(seconds: i64) -> DateTime<Utc> {
    Utc::now() - TimeDelta::seconds(seconds)
}

fn refusal(destination: &str) -> What {
    What::Refused(Refusal {
        destination: Some(destination.into()),
        withheld: false,
        address: Some("192.0.2.80".into()),
        port: Some(443),
        protocol: Protocol::Tcp,
        reason: RefusalReason::NameNotAllowed,
        source: RefusalSource::Network,
        policy: Some("walk-docs".into()),
        revision: Some(1),
    })
}

#[derive(sqlx::FromRow, Debug, PartialEq)]
struct Row {
    kind: String,
    action: String,
    count: i64,
    actor_label: Option<String>,
    client_ip: Option<String>,
    closed: bool,
}

/// Rows of `table`, oldest first.
async fn rows(pool: &PgPool, table: &str) -> Result<Vec<Row>> {
    Ok(sqlx::query_as(&format!(
        "SELECT kind, action, count, actor_label, host(client_ip) AS client_ip, \
         last_at IS NOT NULL AS closed FROM {table} ORDER BY first_at, action"
    ))
    .fetch_all(pool)
    .await?)
}

/// `owner`'s last heartbeat, `age` seconds ago.
async fn heartbeat(pool: &PgPool, owner: i64, age: u32) -> Result<()> {
    sqlx::query(
        "INSERT INTO lease_owner_heartbeats(incarnation,last_seen) \
         VALUES ($1, LOCALTIMESTAMP - make_interval(secs => $2)) \
         ON CONFLICT (incarnation) DO UPDATE SET last_seen = EXCLUDED.last_seen",
    )
    .bind(owner)
    .bind(f64::from(age))
    .execute(pool)
    .await?;
    Ok(())
}

async fn record(pool: &PgPool, event: &Event) -> Result<()> {
    let mut connection = pool.acquire().await?;
    super::record(&mut connection, event).await?;
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

database_case!(db_an_event_that_does_not_fold_is_one_row_at_once, pool, {
    let started = What::Lifecycle(Lifecycle::Started);
    record(
        pool,
        &Event::once(ORG, ENV, ana(), ago(60), started.clone()),
    )
    .await?;
    record(pool, &Event::once(ORG, ENV, ana(), ago(30), started)).await?;
    ensure!(rows(pool, "sandbox_audit_pending").await?.is_empty());
    let events = rows(pool, "sandbox_audit_events").await?;
    ensure!(events.len() == 2, "{events:?}");
    ensure!(
        events
            .iter()
            .all(|row| row.action == "started" && row.count == 1)
    );
});

database_case!(db_a_fold_adds_to_its_subjects_row_for_the_hour, pool, {
    let hour_ago = ago(3600);
    let mut event = Event::once(ORG, ENV, Actor::Sandbox, hour_ago, refusal("crates.io"));
    event.count = 5;
    record(pool, &event).await?;
    event.count = 7;
    record(pool, &event).await?;
    record(
        pool,
        &Event::once(ORG, ENV, Actor::Sandbox, hour_ago, refusal("pypi.org")),
    )
    .await?;
    let pending = rows(pool, "sandbox_audit_pending").await?;
    let mut counts: Vec<i64> = pending.iter().map(|row| row.count).collect();
    counts.sort_unstable();
    ensure!(counts == [1, 12], "{pending:?}");

    // The same subject in the current hour is another row; the flush moves
    // the ended hour's two and keeps it.
    record(
        pool,
        &Event::once(ORG, ENV, Actor::Sandbox, Utc::now(), refusal("crates.io")),
    )
    .await?;
    ensure!(store::flush(pool, INCARNATION_GRACE).await? == 2);
    ensure!(rows(pool, "sandbox_audit_events").await?.len() == 2);
    ensure!(rows(pool, "sandbox_audit_pending").await?.len() == 1);
});

database_case!(
    db_an_exec_folds_and_a_terminal_waits_open_until_it_closes,
    pool,
    {
        heartbeat(pool, HOLDER, 0).await?;
        // The current hour's start: a fold from an ended hour moves at the
        // flush, so a time a little before now fails in an hour's first
        // minutes.
        let this_hour = Utc::now().duration_trunc(TimeDelta::hours(1))?;
        let exec = Event::once(ORG, ENV, ana(), this_hour, What::Access(Surface::Exec))
            .from_address(ADDRESS);
        ensure!(store::open_session(pool, HOLDER, &exec).await?.is_none());
        ensure!(store::open_session(pool, HOLDER, &exec).await?.is_none());
        let terminal = Event::once(ORG, ENV, ana(), this_hour, What::Access(Surface::Terminal))
            .from_address(ADDRESS);
        let session = store::open_session(pool, HOLDER, &terminal)
            .await?
            .ok_or_else(|| anyhow::anyhow!("a terminal is a session"))?;
        let pending = rows(pool, "sandbox_audit_pending").await?;
        ensure!(
            pending
                == [
                    Row {
                        kind: "access".into(),
                        action: "exec".into(),
                        count: 2,
                        actor_label: Some("ana@example.com".into()),
                        client_ip: Some("203.0.113.7".into()),
                        closed: true,
                    },
                    Row {
                        kind: "access".into(),
                        action: "terminal".into(),
                        count: 1,
                        actor_label: Some("ana@example.com".into()),
                        client_ip: Some("203.0.113.7".into()),
                        closed: false,
                    },
                ],
            "{pending:?}"
        );

        // Open and its holder alive: it stays.
        store::flush(pool, INCARNATION_GRACE).await?;
        ensure!(rows(pool, "sandbox_audit_events").await?.is_empty());
        store::close_session(pool, &session, Utc::now()).await?;
        ensure!(store::flush(pool, INCARNATION_GRACE).await? == 1);
        let events = rows(pool, "sandbox_audit_events").await?;
        ensure!(events.len() == 1 && events[0].action == "terminal" && events[0].closed);
    }
);

database_case!(
    db_a_session_whose_process_is_gone_closes_at_its_last_heartbeat,
    pool,
    {
        heartbeat(pool, HOLDER, 310).await?;
        let desktop = Event::once(ORG, ENV, ana(), ago(900), What::Access(Surface::Desktop))
            .from_address(ADDRESS);
        store::open_session(pool, HOLDER, &desktop).await?;
        ensure!(store::flush(pool, INCARNATION_GRACE).await? == 1);
        let closed_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT last_at FROM sandbox_audit_events")
                .fetch_one(pool)
                .await?;
        let since = Utc::now() - closed_at;
        ensure!(
            since >= TimeDelta::seconds(305) && since <= TimeDelta::seconds(330),
            "closed {since} ago, not at the heartbeat"
        );
    }
);

database_case!(db_a_fold_keeps_the_latest_events_fields, pool, {
    // Three refusals inside one hour that has ended, `seconds` before its end.
    let hour = (Utc::now() - TimeDelta::hours(2)).duration_trunc(TimeDelta::hours(1))?;
    let at_address = |address: &str, seconds: i64| {
        let mut what = refusal("crates.io");
        if let What::Refused(refusal) = &mut what {
            refusal.address = Some(address.into());
        }
        Event::once(
            ORG,
            ENV,
            Actor::Sandbox,
            hour + TimeDelta::hours(1) - TimeDelta::seconds(seconds),
            what,
        )
    };
    record(pool, &at_address("192.0.2.80", 30)).await?;
    record(pool, &at_address("192.0.2.81", 10)).await?;
    record(pool, &at_address("192.0.2.79", 50)).await?;
    let address: Option<String> =
        sqlx::query_scalar("SELECT detail->>'address' FROM sandbox_audit_pending")
            .fetch_one(pool)
            .await?;
    ensure!(address.as_deref() == Some("192.0.2.81"), "{address:?}");
});

database_case!(db_a_lifecycle_event_cannot_open_a_session, pool, {
    let stopped = Event::once(
        ORG,
        ENV,
        Actor::Platform,
        ago(10),
        What::Lifecycle(Lifecycle::Started),
    );
    ensure!(matches!(
        store::open_session(pool, HOLDER, &stopped).await,
        Err(AuditError::NotASession)
    ));
});

database_case!(db_expiry_removes_what_began_before_the_retention, pool, {
    // The loop makes partitions only around now; a month this old is made
    // here, as the loop made it then.
    sqlx::query("SELECT codewire_ensure_sandbox_audit_partitions(now() - interval '100 days')")
        .execute(pool)
        .await?;
    let old = Event::once(
        ORG,
        ENV,
        Actor::Platform,
        ago(100 * 24 * 3600),
        What::Lifecycle(Lifecycle::Stopped {
            reason: Some(PlatformReason::Idle),
            idle_stop_seconds: Some(1800),
        }),
    );
    record(pool, &old).await?;
    record(
        pool,
        &Event::once(
            ORG,
            ENV,
            ana(),
            ago(60),
            What::Lifecycle(Lifecycle::Started),
        ),
    )
    .await?;
    ensure!(
        store::expire(pool, std::time::Duration::from_secs(24 * 3600))
            .await
            .is_err(),
        "a retention shorter than 90 days is refused"
    );
    ensure!(rows(pool, "sandbox_audit_events").await?.len() == 2);
    store::expire(pool, RETENTION).await?;
    let left = rows(pool, "sandbox_audit_events").await?;
    ensure!(left.len() == 1 && left[0].action == "started", "{left:?}");
});

database_case!(db_a_write_tells_live_watches_only_when_it_commits, pool, {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("audit_changes").await?;
    let started = Event::once(ORG, ENV, ana(), ago(5), What::Lifecycle(Lifecycle::Started));

    let mut rolled_back = pool.begin().await?;
    super::record(&mut rolled_back, &started).await?;
    rolled_back.rollback().await?;
    let mut committed = pool.begin().await?;
    super::record(&mut committed, &started).await?;
    super::record(&mut committed, &started).await?;
    committed.commit().await?;

    let notice =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.recv()).await??;
    ensure!(
        notice.payload() == format!("{ORG}:{ENV}"),
        "{}",
        notice.payload()
    );
    let more = tokio::time::timeout(std::time::Duration::from_millis(500), listener.recv()).await;
    ensure!(
        more.is_err(),
        "one notice for the committed transaction, none for the rolled back"
    );
});
