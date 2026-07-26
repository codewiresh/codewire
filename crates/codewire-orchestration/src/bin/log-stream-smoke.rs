//! Live database and edge proof for WS06 WI-3 StreamLogs.
//!
//! Seeds a composite-cursor tie, observes two quiet-stream heartbeats, then
//! publishes live and terminal rows through PostgreSQL NOTIFY. The disposable
//! fixture rows are removed whether the proof succeeds or fails.

use std::time::Duration;

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use codewire_proto::codewire::v1::{
    EnvironmentServiceClient, StreamLogsRequest, StreamLogsResponse,
    stream_logs_response::EventView,
};
use connectrpc::client::{ClientConfig, HttpClient};
use reqwest::header::COOKIE;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

struct FixtureRows {
    cursor: String,
    tied: String,
    live: String,
    terminal: String,
    tied_at: DateTime<Utc>,
}

enum Observation {
    Log {
        id: String,
        environment_id: String,
        has_created_at: bool,
    },
    Heartbeat {
        has_sent_at: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let database_url = required_env("SMOKE_DATABASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;
    let assert_no_buffering =
        std::env::var("SMOKE_ASSERT_NO_BUFFERING_HEADER").as_deref() == Ok("1");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .context("connect to StreamLogs smoke database")?;
    let rows = FixtureRows::new();

    let result = async {
        seed_cursor_tie(&pool, &environment_id, &rows).await?;
        run_stream(
            &base_url,
            &pool,
            &org_id,
            &environment_id,
            &session_token,
            assert_no_buffering,
            &rows,
        )
        .await
    }
    .await;
    let cleanup = cleanup_rows(&pool, &rows).await;
    result?;
    cleanup?;

    println!("log-stream-smoke: cursor tie, heartbeats, NOTIFY tail, and terminal close green");
    Ok(())
}

impl FixtureRows {
    fn new() -> Self {
        let nonce = Uuid::new_v4().simple().to_string();
        Self {
            cursor: format!("log_stream_smoke_{nonce}_00_cursor"),
            tied: format!("log_stream_smoke_{nonce}_01_tied"),
            live: format!("log_stream_smoke_{nonce}_02_live"),
            terminal: format!("log_stream_smoke_{nonce}_03_terminal"),
            tied_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn ids(&self) -> [&str; 4] {
        [&self.cursor, &self.tied, &self.live, &self.terminal]
    }
}

async fn seed_cursor_tie(
    pool: &PgPool,
    environment_id: &str,
    rows: &FixtureRows,
) -> anyhow::Result<()> {
    for (id, message) in [
        (&rows.cursor, "cursor row"),
        (&rows.tied, "same-timestamp row"),
    ] {
        sqlx::query(
            r#"INSERT INTO environment_logs
               (id, environment_id, phase, status, message, metadata, created_at)
               VALUES ($1, $2, 'provision', 'running', $3,
                       '{"source":"log-stream-smoke"}'::jsonb, $4)"#,
        )
        .bind(id)
        .bind(environment_id)
        .bind(message)
        .bind(rows.tied_at)
        .execute(pool)
        .await
        .with_context(|| format!("insert StreamLogs tie fixture {id}"))?;
    }
    Ok(())
}

async fn run_stream(
    base_url: &str,
    pool: &PgPool,
    org_id: &str,
    environment_id: &str,
    session_token: &str,
    assert_no_buffering: bool,
    rows: &FixtureRows,
) -> anyhow::Result<()> {
    let config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = EnvironmentServiceClient::new(HttpClient::plaintext(), config);
    let mut stream = client
        .stream_logs(StreamLogsRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            follow: true,
            after_log_id: rows.cursor.clone().into(),
            ..Default::default()
        })
        .await
        .context("open StreamLogs")?;

    if assert_no_buffering {
        anyhow::ensure!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|value| value.to_str().ok())
                == Some("no"),
            "StreamLogs response lacks X-Accel-Buffering: no"
        );
    }

    macro_rules! next_observation {
        () => {{
            let message = tokio::time::timeout(
                Duration::from_secs(30),
                stream.message::<StreamLogsResponse>(),
            )
            .await
            .context("timed out waiting for StreamLogs event")?
            .context("receive StreamLogs event")?
            .context("StreamLogs closed before the expected event")?;
            observe(&message)?
        }};
    }

    require_log(next_observation!(), &rows.tied, environment_id)?;

    for _ in 0..2 {
        match next_observation!() {
            Observation::Heartbeat { has_sent_at } => {
                anyhow::ensure!(has_sent_at, "StreamLogs heartbeat lacks sent_at");
            }
            Observation::Log { id, .. } => {
                anyhow::bail!("quiet StreamLogs emitted unexpected log {id}")
            }
        }
    }

    insert_and_notify(
        pool,
        environment_id,
        &rows.live,
        "provision",
        "running",
        "late live row",
        rows.tied_at + chrono::Duration::seconds(1),
    )
    .await?;
    loop {
        let observation = next_observation!();
        if matches!(observation, Observation::Log { .. }) {
            require_log(observation, &rows.live, environment_id)?;
            break;
        }
    }

    insert_and_notify(
        pool,
        environment_id,
        &rows.terminal,
        "complete",
        "completed",
        "terminal row",
        rows.tied_at + chrono::Duration::seconds(2),
    )
    .await?;
    loop {
        let observation = next_observation!();
        if matches!(observation, Observation::Log { .. }) {
            require_log(observation, &rows.terminal, environment_id)?;
            break;
        }
    }

    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        stream.message::<StreamLogsResponse>(),
    )
    .await
    .context("StreamLogs did not close after terminal row")?
    .context("receive StreamLogs terminal close")?;
    anyhow::ensure!(
        ended.is_none(),
        "StreamLogs emitted an event after terminal row"
    );
    Ok(())
}

fn observe(message: &connectrpc::StreamMessage<StreamLogsResponse>) -> anyhow::Result<Observation> {
    match message
        .view()
        .event
        .clone()
        .context("StreamLogs emitted an empty event")?
    {
        EventView::Log(log) => Ok(Observation::Log {
            id: log.id.to_owned(),
            environment_id: log.environment_id.to_owned(),
            has_created_at: log.created_at.is_set(),
        }),
        EventView::Heartbeat(heartbeat) => Ok(Observation::Heartbeat {
            has_sent_at: heartbeat.sent_at.is_set(),
        }),
    }
}

fn require_log(observation: Observation, id: &str, environment_id: &str) -> anyhow::Result<()> {
    let Observation::Log {
        id: actual_id,
        environment_id: actual_environment_id,
        has_created_at,
    } = observation
    else {
        anyhow::bail!("StreamLogs emitted heartbeat where log {id} was expected")
    };
    anyhow::ensure!(
        actual_id == id,
        "StreamLogs log id = {actual_id}, want {id}"
    );
    anyhow::ensure!(
        actual_environment_id == environment_id,
        "StreamLogs environment id = {actual_environment_id}, want {environment_id}"
    );
    anyhow::ensure!(has_created_at, "StreamLogs log {id} lacks created_at");
    Ok(())
}

async fn insert_and_notify(
    pool: &PgPool,
    environment_id: &str,
    id: &str,
    phase: &str,
    status: &str,
    message: &str,
    created_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await.context("begin live log transaction")?;
    sqlx::query(
        r#"INSERT INTO environment_logs
           (id, environment_id, phase, status, message, metadata, created_at)
           VALUES ($1, $2, $3, $4, $5, NULL, $6)"#,
    )
    .bind(id)
    .bind(environment_id)
    .bind(phase)
    .bind(status)
    .bind(message)
    .bind(created_at)
    .execute(&mut *transaction)
    .await
    .with_context(|| format!("insert live StreamLogs fixture {id}"))?;
    sqlx::query("SELECT pg_notify('environment_logs', $1)")
        .bind(environment_id)
        .execute(&mut *transaction)
        .await
        .context("publish environment_logs notification")?;
    transaction
        .commit()
        .await
        .context("commit live log transaction")?;
    Ok(())
}

async fn cleanup_rows(pool: &PgPool, rows: &FixtureRows) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM environment_logs WHERE id = ANY($1)")
        .bind(rows.ids().as_slice())
        .execute(pool)
        .await
        .context("remove StreamLogs smoke fixtures")?;
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
