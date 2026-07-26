//! Postgres connection pool helper.
//!
//! Wraps `sqlx::PgPool::connect` with sensible defaults matching the Go
//! side's `pgxpool`: max 25 connections, sane timeouts, lazy connection
//! verification at startup.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Returns a connected pool for the given database URL.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(25)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(10 * 60)))
        .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .connect(url)
        .await?;
    Ok(pool)
}
