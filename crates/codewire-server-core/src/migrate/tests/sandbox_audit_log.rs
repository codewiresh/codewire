//! The Sandbox audit log (0055, #6189; SPEC.md "Sandbox audit log"): the
//! upgrade from 0054 adds two empty tables and no dated partition; their
//! checks hold; partitions are made for the month around a time, once; a
//! flush moves ended folds, closed sessions and sessions whose process is
//! gone, closed at its last heartbeat, and leaves the rest; events are never
//! updated; expiry drops whole months and older rows; the organization's
//! deletion takes its events; the rollback restores the 0054 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

/// Whether `statement` is refused by `constraint`.
async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

async fn count(pool: &PgPool, table: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await?)
}

async fn partitions(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
         WHERE i.inhparent = 'public.sandbox_audit_events'::regclass ORDER BY 1",
    )
    .fetch_all(pool)
    .await?)
}

/// One pending row: a fold when `holder` is `None`, else an open session.
fn pending(key: &str, kind: &str, first: &str, last: Option<&str>, holder: Option<i64>) -> String {
    let (pending, actor) = match holder {
        None => ("fold", "'sandbox', NULL, NULL, NULL, NULL"),
        Some(_) => (
            "session",
            "'user', 'audit-user', 'audit@example.test', 'member', '203.0.113.7'",
        ),
    };
    format!(
        "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, subject, \
         pending, pending_key, holder_incarnation, first_at, last_at, actor_type, actor_id, \
         actor_label, actor_role, client_ip) VALUES ('audit-org', 'audit-env', '{kind}', \
         '{kind}', '{key}', '{pending}', '{key}', {}, '{first}', {}, {actor})",
        holder.map_or_else(|| "NULL".to_owned(), |holder| holder.to_string()),
        last.map_or_else(|| "NULL".to_owned(), |last| format!("'{last}'")),
    )
}

async fn moved(pool: &PgPool) -> anyhow::Result<Vec<(String, Option<String>)>> {
    Ok(sqlx::query_as(
        "SELECT subject, to_char(last_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') \
         FROM sandbox_audit_events ORDER BY subject",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sandbox_audit_log_upgrade_flushes_expires_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(54).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "SET TIME ZONE 'UTC'; \
             INSERT INTO users (id, email) VALUES ('audit-user', 'audit@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('audit-org', 'Audit', 'audit', 'audit-user');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(55).run(&pool).await?;
        anyhow::ensure!(count(&pool, "organizations").await? == 1);
        anyhow::ensure!(count(&pool, "sandbox_audit_events").await? == 0);
        anyhow::ensure!(count(&pool, "sandbox_audit_pending").await? == 0);
        anyhow::ensure!(
            partitions(&pool).await?.is_empty(),
            "the migration makes no dated partition"
        );

        checks_hold(&pool).await?;
        partitions_are_made_once(&pool).await?;
        a_flush_moves_what_is_finished(&pool).await?;
        events_are_kept_and_never_updated(&pool).await?;
        expiry_drops_months_and_rows(&pool).await?;
        the_organizations_deletion_takes_its_events(&pool).await?;
        roll_back(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// An actor matches its type, an address is only on access, and a session
/// is an access event with a holder.
async fn checks_hold(pool: &PgPool) -> anyhow::Result<()> {
    anyhow::ensure!(
        refused_by(
            pool,
            "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, \
             subject, pending, pending_key, first_at, last_at, actor_type, actor_id) \
             VALUES ('audit-org', 'audit-env', 'lifecycle', 'stopped', 's', 'fold', 'k', \
             now(), now(), 'platform', 'audit-user')",
            "sandbox_audit_pending_actor_check",
        )
        .await?,
        "the platform names no one"
    );
    anyhow::ensure!(
        refused_by(
            pool,
            "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, \
             subject, pending, pending_key, first_at, last_at, actor_type, client_ip) \
             VALUES ('audit-org', 'audit-env', 'refused', 'refused', 's', 'fold', 'k', \
             now(), now(), 'sandbox', '192.0.2.1')",
            "sandbox_audit_pending_client_ip_check",
        )
        .await?,
        "only access carries a client IP"
    );
    anyhow::ensure!(
        refused_by(
            pool,
            "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, \
             subject, pending, pending_key, holder_incarnation, first_at, actor_type, \
             actor_id) VALUES ('audit-org', 'audit-env', 'lifecycle', 'started', 's', \
             'session', 'k', 7, now(), 'user', 'audit-user')",
            "sandbox_audit_pending_pending_check",
        )
        .await?,
        "only access has open sessions"
    );
    Ok(())
}

/// The month before, its own and the two after, once.
async fn partitions_are_made_once(pool: &PgPool) -> anyhow::Result<()> {
    for at in ["2026-05-23 14:00+00", "2026-05-31 23:59+00"] {
        sqlx::query("SELECT codewire_ensure_sandbox_audit_partitions($1::timestamptz)")
            .bind(at)
            .execute(pool)
            .await?;
    }
    anyhow::ensure!(
        partitions(pool).await?
            == [
                "sandbox_audit_events_2026_04",
                "sandbox_audit_events_2026_05",
                "sandbox_audit_events_2026_06",
                "sandbox_audit_events_2026_07",
            ]
    );
    Ok(())
}

/// A flush at 14:30 with a five-minute grace: incarnation 7 last wrote at
/// 13:00 and is gone, 8 wrote at 14:28 and is alive. A session of 7's from
/// February, outside the months around now, still moves.
async fn a_flush_moves_what_is_finished(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "INSERT INTO lease_owner_heartbeats VALUES (7, '2026-05-23 13:00'), \
         (8, '2026-05-23 14:28');",
    )
    .execute(pool)
    .await?;
    for statement in [
        pending(
            "fold-ended",
            "refused",
            "2026-05-23 13:05",
            Some("2026-05-23 13:40"),
            None,
        ),
        pending(
            "fold-current",
            "refused",
            "2026-05-23 14:05",
            Some("2026-05-23 14:09"),
            None,
        ),
        pending(
            "session-closed",
            "access",
            "2026-05-23 14:02",
            Some("2026-05-23 14:20"),
            Some(8),
        ),
        pending("session-gone", "access", "2026-05-23 12:02", None, Some(7)),
        pending("session-open", "access", "2026-05-23 14:10", None, Some(8)),
        pending(
            "session-february",
            "access",
            "2026-02-10 09:00",
            None,
            Some(7),
        ),
    ] {
        sqlx::query(&statement).execute(pool).await?;
    }
    let flushed: i64 = sqlx::query_scalar(
        "SELECT codewire_flush_sandbox_audit('2026-05-23 14:30+00', interval '5 minutes')",
    )
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(flushed == 4, "four rows are finished, not {flushed}");
    anyhow::ensure!(
        moved(pool).await?
            == [
                ("fold-ended".to_owned(), Some("2026-05-23 13:40".to_owned())),
                (
                    "session-closed".to_owned(),
                    Some("2026-05-23 14:20".to_owned())
                ),
                (
                    "session-february".to_owned(),
                    Some("2026-05-23 13:00".to_owned())
                ),
                (
                    "session-gone".to_owned(),
                    Some("2026-05-23 13:00".to_owned())
                ),
            ]
    );
    let waiting: Vec<String> =
        sqlx::query_scalar("SELECT subject FROM sandbox_audit_pending ORDER BY subject")
            .fetch_all(pool)
            .await?;
    anyhow::ensure!(waiting == ["fold-current", "session-open"]);
    Ok(())
}

/// A cutoff inside the 90 days is refused and removes nothing, and no event
/// is ever updated.
async fn events_are_kept_and_never_updated(pool: &PgPool) -> anyhow::Result<()> {
    let young = sqlx::query("SELECT codewire_expire_sandbox_audit(now() - interval '89 days')")
        .execute(pool)
        .await;
    anyhow::ensure!(
        matches!(&young, Err(sqlx::Error::Database(error))
            if error.code().as_deref() == Some("22023")),
        "a cutoff inside retention is refused: {young:?}"
    );
    anyhow::ensure!(count(pool, "sandbox_audit_events").await? == 4);
    let update = sqlx::query("UPDATE sandbox_audit_events SET count = 2")
        .execute(pool)
        .await;
    anyhow::ensure!(
        matches!(&update, Err(sqlx::Error::Database(error))
            if error.message() == "sandbox audit events are never updated"),
        "an update is refused: {update:?}"
    );
    Ok(())
}

/// Expiry at the start of June drops the months before it, with every event
/// and the pending rows older than the cutoff; expiry within a month deletes
/// the older rows and keeps the month.
async fn expiry_drops_months_and_rows(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("SELECT codewire_expire_sandbox_audit('2026-06-01 00:00+00')")
        .execute(pool)
        .await?;
    anyhow::ensure!(
        partitions(pool).await?
            == [
                "sandbox_audit_events_2026_06",
                "sandbox_audit_events_2026_07"
            ]
    );
    anyhow::ensure!(count(pool, "sandbox_audit_events").await? == 0);
    anyhow::ensure!(count(pool, "sandbox_audit_pending").await? == 0);

    for (key, first, last) in [
        ("jun-early", "2026-06-02 10:00", "2026-06-02 10:05"),
        ("jun-late", "2026-06-20 10:00", "2026-06-20 10:05"),
    ] {
        sqlx::query(&pending(key, "refused", first, Some(last), None))
            .execute(pool)
            .await?;
    }
    sqlx::query("SELECT codewire_flush_sandbox_audit('2026-06-21 00:00+00', interval '5 minutes')")
        .execute(pool)
        .await?;
    sqlx::query("SELECT codewire_expire_sandbox_audit('2026-06-10 00:00+00')")
        .execute(pool)
        .await?;
    anyhow::ensure!(
        moved(pool).await? == [("jun-late".to_owned(), Some("2026-06-20 10:05".to_owned()))]
    );
    anyhow::ensure!(
        partitions(pool)
            .await?
            .contains(&"sandbox_audit_events_2026_06".to_owned())
    );
    Ok(())
}

async fn the_organizations_deletion_takes_its_events(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(&pending(
        "open",
        "access",
        "2026-06-20 11:00",
        None,
        Some(8),
    ))
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM organizations WHERE id = 'audit-org'")
        .execute(pool)
        .await?;
    anyhow::ensure!(count(pool, "sandbox_audit_events").await? == 0);
    anyhow::ensure!(count(pool, "sandbox_audit_pending").await? == 0);
    Ok(())
}

/// Drop the functions, then both tables.
async fn roll_back(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "DROP FUNCTION public.codewire_expire_sandbox_audit(timestamp with time zone); \
         DROP FUNCTION public.codewire_flush_sandbox_audit(timestamp with time zone, interval); \
         DROP FUNCTION public.codewire_ensure_sandbox_audit_partitions(timestamp with time zone); \
         DROP TABLE public.sandbox_audit_pending; \
         DROP TABLE public.sandbox_audit_events; \
         DROP FUNCTION public.codewire_refuse_sandbox_audit_update();",
    )
    .execute(pool)
    .await?;
    Ok(())
}
