//! Writes the audit log's two tables (migration 0055): an event that doesn't
//! fold goes straight to `sandbox_audit_events`; a fold adds to its hour's row
//! in `sandbox_audit_pending`; a session waits there while it is open. The
//! repository check `sandbox-audit-writers` keeps every other module out.

use std::net::IpAddr;

use chrono::{DateTime, DurationRound as _, TimeDelta, Utc};
use sqlx::{Connection as _, PgConnection, PgPool};

use super::event::{Actor, Columns, Kind, What};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("encode an audit event: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("write the audit log: {0}")]
    Database(#[from] sqlx::Error),
    #[error("only an access event opens a session")]
    NotASession,
    #[error("the hour of {0} is out of range")]
    Hour(DateTime<Utc>),
}

/// One thing that happened to a Sandbox, `count` times between `first` and
/// `last`.
#[derive(Clone, Debug)]
pub struct Event {
    pub org_id: String,
    pub environment_id: String,
    pub actor: Actor,
    /// The address of the request that opened a session; access only.
    pub client_ip: Option<IpAddr>,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub count: u64,
    pub what: What,
}

impl Event {
    /// One occurrence at `at`.
    pub fn once(
        org_id: impl Into<String>,
        environment_id: impl Into<String>,
        actor: Actor,
        at: DateTime<Utc>,
        what: What,
    ) -> Self {
        Self {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            actor,
            client_ip: None,
            first: at,
            last: at,
            count: 1,
            what,
        }
    }

    pub fn from_address(mut self, client_ip: IpAddr) -> Self {
        self.client_ip = Some(client_ip);
        self
    }
}

/// The actor's four columns.
struct ActorColumns<'a> {
    kind: &'static str,
    id: Option<&'a str>,
    label: Option<&'a str>,
    role: Option<&'static str>,
}

fn actor_columns(actor: &Actor) -> ActorColumns<'_> {
    match actor {
        Actor::User { id, email, role } => ActorColumns {
            kind: "user",
            id: Some(id),
            label: Some(email),
            role: Some(role.as_str()),
        },
        Actor::ApiKey { id, name } => ActorColumns {
            kind: "api_key",
            id: Some(id),
            label: Some(name),
            role: None,
        },
        Actor::Platform => ActorColumns {
            kind: "platform",
            id: None,
            label: None,
            role: None,
        },
        Actor::Sandbox => ActorColumns {
            kind: "sandbox",
            id: None,
            label: None,
            role: None,
        },
    }
}

/// The key an access fold adds to: the same actor from the same address.
fn actor_key(event: &Event) -> String {
    let actor = actor_columns(&event.actor);
    format!(
        "{}:{}|{}",
        actor.kind,
        actor.id.unwrap_or(""),
        event
            .client_ip
            .map_or_else(String::new, |ip| ip.to_string())
    )
}

fn count(event: &Event) -> i64 {
    i64::try_from(event.count.max(1)).unwrap_or(i64::MAX)
}

/// Records `event` on `connection`, inside the caller's transaction when it
/// has one, so an event is written exactly when what it records commits.
pub async fn record(connection: &mut PgConnection, event: &Event) -> Result<(), AuditError> {
    let columns = event.what.columns(&actor_key(event))?;
    if columns.folds {
        add_to_fold(connection, event, &columns).await?;
    } else {
        insert_event(connection, event, &columns).await?;
    }
    notify(connection, &event.org_id, &event.environment_id).await
}

/// Tells live watches the environment's log changed, as part of the write's
/// own transaction: Postgres sends it only if that commits, and once however
/// many writes the transaction made for the environment.
async fn notify(
    connection: &mut PgConnection,
    org_id: &str,
    environment_id: &str,
) -> Result<(), AuditError> {
    sqlx::query("SELECT pg_notify('audit_changes', $1)")
        .bind(format!("{org_id}:{environment_id}"))
        .execute(connection)
        .await?;
    Ok(())
}

async fn insert_event(
    connection: &mut PgConnection,
    event: &Event,
    columns: &Columns,
) -> Result<(), AuditError> {
    let actor = actor_columns(&event.actor);
    sqlx::query(
        "INSERT INTO sandbox_audit_events (org_id, environment_id, kind, action, subject, \
         first_at, last_at, count, actor_type, actor_id, actor_label, actor_role, client_ip, \
         detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::inet, $14)",
    )
    .bind(&event.org_id)
    .bind(&event.environment_id)
    .bind(columns.kind.as_str())
    .bind(&columns.action)
    .bind(&columns.subject)
    .bind(event.first)
    .bind(event.last)
    .bind(count(event))
    .bind(actor.kind)
    .bind(actor.id)
    .bind(actor.label)
    .bind(actor.role)
    .bind(event.client_ip.map(|ip| ip.to_string()))
    .bind(&columns.detail)
    .execute(connection)
    .await?;
    Ok(())
}

/// Adds `event` to its subject's row for the hour it began in. The row keeps
/// the fields of the latest event, such as a refusal's latest address. A
/// refusal past the hour's subject bound adds to the hour's overflow row
/// instead ([`super::bound`]); the check and the write share one
/// transaction, a savepoint inside the caller's, so its lock covers both.
async fn add_to_fold(
    connection: &mut PgConnection,
    event: &Event,
    columns: &Columns,
) -> Result<(), AuditError> {
    let hour = event
        .first
        .duration_trunc(TimeDelta::hours(1))
        .map_err(|_| AuditError::Hour(event.first))?;
    let pending_key = format!("{}|{}", columns.subject, hour.to_rfc3339());
    let mut tx = connection.begin().await?;
    if columns.kind == Kind::Refused
        && super::bound::overflowed(&mut tx, event, columns, hour, &pending_key).await?
    {
        tx.commit().await?;
        return Ok(());
    }
    let actor = actor_columns(&event.actor);
    sqlx::query(
        "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, subject, \
         pending, pending_key, first_at, last_at, count, actor_type, actor_id, actor_label, \
         actor_role, client_ip, detail) \
         VALUES ($1, $2, $3, $4, $5, 'fold', $6, $7, $8, $9, $10, $11, $12, $13, $14::inet, $15) \
         ON CONFLICT (environment_id, kind, pending_key) DO UPDATE SET \
           count = sandbox_audit_pending.count + EXCLUDED.count, \
           first_at = LEAST(sandbox_audit_pending.first_at, EXCLUDED.first_at), \
           last_at = GREATEST(sandbox_audit_pending.last_at, EXCLUDED.last_at), \
           detail = CASE WHEN EXCLUDED.last_at >= sandbox_audit_pending.last_at \
             THEN EXCLUDED.detail ELSE sandbox_audit_pending.detail END",
    )
    .bind(&event.org_id)
    .bind(&event.environment_id)
    .bind(columns.kind.as_str())
    .bind(&columns.action)
    .bind(&columns.subject)
    .bind(&pending_key)
    .bind(event.first)
    .bind(event.last.max(event.first))
    .bind(count(event))
    .bind(actor.kind)
    .bind(actor.id)
    .bind(actor.label)
    .bind(actor.role)
    .bind(event.client_ip.map(|ip| ip.to_string()))
    .bind(&columns.detail)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// An open session's row, to close when the session ends.
#[derive(Debug)]
pub struct OpenSession {
    org_id: String,
    environment_id: String,
    key: String,
}

/// Records a session that opened at `event.first` and is still open, held by
/// this process's `incarnation`. An exec or preview session folds instead
/// and has nothing to close.
pub async fn open_session(
    pool: &PgPool,
    incarnation: i64,
    event: &Event,
) -> Result<Option<OpenSession>, AuditError> {
    let mut connection = pool.acquire().await?;
    let columns = event.what.columns(&actor_key(event))?;
    if columns.kind != Kind::Access {
        return Err(AuditError::NotASession);
    }
    if columns.folds {
        add_to_fold(&mut connection, event, &columns).await?;
        notify(&mut connection, &event.org_id, &event.environment_id).await?;
        return Ok(None);
    }
    let key = uuid::Uuid::new_v4().to_string();
    let actor = actor_columns(&event.actor);
    sqlx::query(
        "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, subject, \
         pending, pending_key, holder_incarnation, first_at, actor_type, actor_id, \
         actor_label, actor_role, client_ip, detail) \
         VALUES ($1, $2, 'access', $3, $4, 'session', $5, $6, $7, $8, $9, $10, $11, \
         $12::inet, $13)",
    )
    .bind(&event.org_id)
    .bind(&event.environment_id)
    .bind(&columns.action)
    .bind(&columns.subject)
    .bind(&key)
    .bind(incarnation)
    .bind(event.first)
    .bind(actor.kind)
    .bind(actor.id)
    .bind(actor.label)
    .bind(actor.role)
    .bind(event.client_ip.map(|ip| ip.to_string()))
    .bind(&columns.detail)
    .execute(&mut *connection)
    .await?;
    notify(&mut connection, &event.org_id, &event.environment_id).await?;
    Ok(Some(OpenSession {
        org_id: event.org_id.clone(),
        environment_id: event.environment_id.clone(),
        key,
    }))
}

/// Closes `session` at `at`. The next flush moves it into the events.
pub async fn close_session(
    pool: &PgPool,
    session: &OpenSession,
    at: DateTime<Utc>,
) -> Result<(), AuditError> {
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "UPDATE sandbox_audit_pending SET last_at = GREATEST($3, first_at) \
         WHERE environment_id = $1 AND kind = 'access' AND pending_key = $2 \
           AND pending = 'session' AND last_at IS NULL",
    )
    .bind(&session.environment_id)
    .bind(&session.key)
    .bind(at)
    .execute(&mut *connection)
    .await?;
    notify(&mut connection, &session.org_id, &session.environment_id).await
}

/// Makes the partitions around now, by the database's clock.
pub async fn ensure_partitions(pool: &PgPool) -> Result<(), AuditError> {
    sqlx::query("SELECT codewire_ensure_sandbox_audit_partitions(now())")
        .execute(pool)
        .await?;
    Ok(())
}

/// Moves what is finished into the events, and returns how many rows moved.
/// It reads the time and the heartbeats by the database's clock, as the
/// abandoned-leases sweep does, so no process's clock decides whether a
/// session's holder is gone.
pub async fn flush(pool: &PgPool, grace: std::time::Duration) -> Result<i64, AuditError> {
    Ok(
        sqlx::query_scalar("SELECT codewire_flush_sandbox_audit(now(), make_interval(secs => $1))")
            .bind(grace.as_secs_f64())
            .fetch_one(pool)
            .await?,
    )
}

/// Removes everything that began more than `retention` ago.
pub async fn expire(pool: &PgPool, retention: std::time::Duration) -> Result<(), AuditError> {
    sqlx::query("SELECT codewire_expire_sandbox_audit(now() - make_interval(secs => $1))")
        .bind(retention.as_secs_f64())
        .execute(pool)
        .await?;
    Ok(())
}
