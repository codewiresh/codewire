//! Reads one environment's audit log (SPEC.md "Sandbox audit log", "Who
//! reads what" and "The API read"): who may, which environment, and its
//! events, a page at a time or grouped by subject.

use axum::http::StatusCode;
use chrono::{DateTime, TimeDelta, Utc};
use codewire_server_core::auth::{AuthUser, CredentialContext};
use codewire_server_core::org::user_org_role;
use codewire_server_core::rate_limit;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use super::event::Kind;
use crate::api::environments::{coded, require_environment_access, take_user_rate_limit};

/// The range a read covers when it names none.
pub const DEFAULT_RANGE: TimeDelta = TimeDelta::days(7);
/// How far back any read reaches: the events kept.
const OLDEST: TimeDelta = TimeDelta::days(90);
const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 1_000;
/// Subjects a grouped answer holds.
const MAX_GROUPS: i64 = 1_000;
/// Every read runs under this, so one can't slow orchestration's database.
const STATEMENT_TIMEOUT: &str = "SET LOCAL statement_timeout = '5s'";
/// PostgreSQL's code for a statement cancelled by its timeout.
const QUERY_CANCELED: &str = "57014";

/// The environment a read names.
pub enum EnvironmentRef {
    Id(String),
    /// Only a Sandbox that exists now has a name to read by.
    Name(String),
}

pub struct Query {
    pub org_id: String,
    pub environment: EnvironmentRef,
    pub kinds: Vec<Kind>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: u32,
    pub cursor: Option<String>,
    pub grouped: bool,
}

#[derive(sqlx::FromRow)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub deleted: bool,
}

/// One event as stored.
#[derive(sqlx::FromRow, Debug)]
pub struct StoredEvent {
    pub id: String,
    pub kind: String,
    pub action: String,
    pub first_at: DateTime<Utc>,
    pub last_at: Option<DateTime<Utc>>,
    pub count: i64,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_label: Option<String>,
    pub actor_role: Option<String>,
    pub client_ip: Option<String>,
    pub detail: serde_json::Value,
}

pub struct Page {
    pub environment: Environment,
    pub events: Vec<StoredEvent>,
    pub next_cursor: Option<String>,
    /// A grouped answer's subjects past [`MAX_GROUPS`].
    pub left_out: u64,
}

/// Every reader is told the same thing when they may not read: the
/// environment does not exist.
fn not_found() -> AppError {
    AppError::NotFound("environment not found".into())
}

/// The OAuth clients that are Codewire's own apps, with which a person signs
/// in themselves: `cw`, the desktop app and the iOS app.
const NATIVE_CLIENTS: [&str; 3] = ["codewire-cli", "codewire-desktop", "codewire-ios"];

/// A person reads the log with their own sign-in: a browser session, an API
/// key, or a token issued to one of Codewire's own apps. A token issued to any
/// other client, on a person's behalf, never reads it; a workload's
/// credentials are not user credentials at all and never reach this read.
pub fn require_reader_credential(credential: &CredentialContext) -> AppResult<()> {
    match credential {
        CredentialContext::SessionCookie { .. } | CredentialContext::ApiKey { .. } => Ok(()),
        CredentialContext::OidcAccessToken { client_id, .. }
            if NATIVE_CLIENTS.contains(&client_id.as_str()) =>
        {
            Ok(())
        }
        CredentialContext::OidcAccessToken { .. } => Err(coded(
            StatusCode::FORBIDDEN,
            "audit_reader_credential",
            "the audit log is read with your own sign-in or an API key",
        )),
    }
}

/// The environment `query` names, if `user` may read its events: an owner
/// or admin reads any of the organization's, a deleted one's included; a
/// member reads one they can open now.
pub async fn authorize(pool: &PgPool, user: &AuthUser, query: &Query) -> AppResult<Environment> {
    let Some(role) = user_org_role(pool, user, &query.org_id).await? else {
        return Err(not_found());
    };
    let environment: Option<Environment> = match &query.environment {
        EnvironmentRef::Id(id) => {
            sqlx::query_as(
                "SELECT id, name, state = 'destroyed' AS deleted FROM environments \
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(&query.org_id)
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        EnvironmentRef::Name(name) => {
            sqlx::query_as(
                "SELECT id, name, false AS deleted FROM environments \
                 WHERE org_id = $1 AND name = $2 AND state <> 'destroyed' \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&query.org_id)
            .bind(name)
            .fetch_optional(pool)
            .await?
        }
    };
    let environment = environment.ok_or_else(not_found)?;
    if role == "owner" || role == "admin" {
        return Ok(environment);
    }
    if environment.deleted {
        return Err(not_found());
    }
    require_environment_access(
        pool,
        user,
        &environment.id,
        &query.org_id,
        "operator",
        "environment not found",
    )
    .await
    .map_err(|_| not_found())?;
    Ok(environment)
}

/// A cursor names the last event of a page: when it began, in
/// microseconds, and its id.
fn parse_cursor(cursor: &str) -> AppResult<(DateTime<Utc>, String)> {
    let invalid = || AppError::BadRequest("cursor is not one this read returned".into());
    let (micros, id) = cursor.split_once('.').ok_or_else(invalid)?;
    let micros: i64 = micros.parse().map_err(|_| invalid())?;
    let at = DateTime::from_timestamp_micros(micros).ok_or_else(invalid)?;
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(invalid());
    }
    Ok((at, id.to_owned()))
}

fn cursor_after(event: &StoredEvent) -> String {
    format!("{}.{}", event.first_at.timestamp_micros(), event.id)
}

/// The columns both tables share, in the order [`StoredEvent`] reads them.
const COLUMNS: &str = "id, kind, action, first_at, last_at, count, actor_type, actor_id, \
    actor_label, actor_role, host(client_ip) AS client_ip, detail, subject";

/// Both tables' rows for one environment, kinds and range: `$1` the
/// environment, `$2` the kinds or NULL for all, `$3` and `$4` the range.
fn both_tables() -> String {
    let filter = "WHERE environment_id = $1 AND ($2::text[] IS NULL OR kind = ANY($2)) \
                  AND first_at >= $3 AND first_at < $4";
    format!(
        "SELECT {COLUMNS} FROM sandbox_audit_events {filter} \
         UNION ALL SELECT {COLUMNS} FROM sandbox_audit_pending {filter}"
    )
}

fn timed_out(error: sqlx::Error) -> AppError {
    match &error {
        sqlx::Error::Database(database) if database.code().as_deref() == Some(QUERY_CANCELED) => {
            coded(
                StatusCode::GATEWAY_TIMEOUT,
                "audit_read_timeout",
                "reading the audit log took too long; read a shorter range",
            )
        }
        _ => error.into(),
    }
}

/// The page or the grouped answer `query` asks for, from `environment`,
/// which [`authorize`] returned.
pub async fn read(
    pool: &PgPool,
    user: &AuthUser,
    query: &Query,
    environment: Environment,
) -> AppResult<Page> {
    let now = Utc::now();
    let until = query.until.unwrap_or(now);
    let since = query
        .since
        .unwrap_or(until - DEFAULT_RANGE)
        .max(now - OLDEST);
    let kinds: Option<Vec<&str>> =
        (!query.kinds.is_empty()).then(|| query.kinds.iter().map(|kind| kind.as_str()).collect());
    let limit = match query.limit {
        0 => DEFAULT_LIMIT,
        limit if limit <= MAX_LIMIT => limit,
        _ => {
            return Err(AppError::BadRequest(
                format!("limit is at most {MAX_LIMIT}").into(),
            ));
        }
    };
    if query.grouped {
        take_user_rate_limit(
            pool,
            &rate_limit::AUDIT_GROUPED_READ,
            &user.user_id,
            "grouped audit reads",
        )
        .await?;
        return grouped(pool, &environment.id, kinds, since, until)
            .await
            .map(|(events, left_out)| Page {
                environment,
                events,
                next_cursor: None,
                left_out,
            });
    }
    let cursor = query.cursor.as_deref().map(parse_cursor).transpose()?;
    let mut transaction = pool.begin().await?;
    sqlx::query(STATEMENT_TIMEOUT)
        .execute(&mut *transaction)
        .await?;
    let mut events: Vec<StoredEvent> = sqlx::query_as(&format!(
        "SELECT * FROM ({}) e \
         WHERE ($5::timestamptz IS NULL OR (first_at, id) < ($5, $6)) \
         ORDER BY first_at DESC, id DESC LIMIT $7",
        both_tables()
    ))
    .bind(&environment.id)
    .bind(&kinds)
    .bind(since)
    .bind(until)
    .bind(cursor.as_ref().map(|(at, _)| *at))
    .bind(cursor.as_ref().map(|(_, id)| id.as_str()))
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(timed_out)?;
    transaction.commit().await?;
    let next_cursor = (events.len() > usize::try_from(limit).unwrap_or(usize::MAX))
        .then(|| {
            events.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            events.last().map(cursor_after)
        })
        .flatten();
    Ok(Page {
        environment,
        events,
        next_cursor,
        left_out: 0,
    })
}

/// One event per kind and subject over the range, the most recently seen
/// first: the counts summed, the earliest start, the latest end, and the
/// latest event's fields and actor.
async fn grouped(
    pool: &PgPool,
    environment_id: &str,
    kinds: Option<Vec<&str>>,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> AppResult<(Vec<StoredEvent>, u64)> {
    #[derive(sqlx::FromRow)]
    struct Group {
        #[sqlx(flatten)]
        event: StoredEvent,
        groups: i64,
    }
    let mut transaction = pool.begin().await?;
    sqlx::query(STATEMENT_TIMEOUT)
        .execute(&mut *transaction)
        .await?;
    // Only the most recently seen groups leave the database, and the window
    // counts every group, before the limit, for `left_out`.
    let rows: Vec<Group> = sqlx::query_as(&format!(
        "SELECT g.*, count(*) OVER () AS groups FROM ( \
           SELECT DISTINCT ON (kind, subject) \
             id, kind, action, \
             min(first_at) OVER subject_rows AS first_at, \
             max(last_at) OVER subject_rows AS last_at, \
             (sum(count) OVER subject_rows)::bigint AS count, \
             actor_type, actor_id, actor_label, actor_role, client_ip, detail \
           FROM ({}) e WHERE action <> 'overflow' \
           WINDOW subject_rows AS (PARTITION BY kind, subject) \
           ORDER BY kind, subject, COALESCE(last_at, first_at) DESC, id DESC \
         ) g ORDER BY COALESCE(g.last_at, g.first_at) DESC, g.id DESC LIMIT $5",
        both_tables()
    ))
    .bind(environment_id)
    .bind(&kinds)
    .bind(since)
    .bind(until)
    .bind(MAX_GROUPS)
    .fetch_all(&mut *transaction)
    .await
    .map_err(timed_out)?;
    // An hour's overflow is counted, not listed: its subjects are left out.
    let overflowed: i64 = sqlx::query_scalar(&format!(
        "SELECT COALESCE(sum((detail->>'subjects')::bigint), 0)::bigint FROM ({}) e \
         WHERE action = 'overflow'",
        both_tables()
    ))
    .bind(environment_id)
    .bind(&kinds)
    .bind(since)
    .bind(until)
    .fetch_one(&mut *transaction)
    .await
    .map_err(timed_out)?;
    transaction.commit().await?;
    let total = rows
        .first()
        .map_or(0, |row| u64::try_from(row.groups).unwrap_or(0));
    let events: Vec<StoredEvent> = rows.into_iter().map(|row| row.event).collect();
    let left_out = total
        .saturating_sub(u64::try_from(events.len()).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(overflowed).unwrap_or(0));
    Ok((events, left_out))
}
