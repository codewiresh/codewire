//! The coordinator's wake of a suspended Sandbox (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"). The coordinator authorizes a hello
//! but can't reach the Sandbox's Pod; orchestration can, and listens on
//! [`CHANNEL`] for the Sandboxes to wake.

use sqlx::PgPool;

/// The database channel a wake request is sent on: its payload is the
/// environment's id.
pub const CHANNEL: &str = "environment_wakes";

/// Asks for `environment_id`'s wake when it is marked suspended, in the
/// statement that finds the mark, so nothing is sent for one that isn't.
/// Returns whether a request was sent.
pub async fn request_if_suspended(
    pool: &PgPool,
    environment_id: &str,
) -> Result<bool, sqlx::Error> {
    let sent: i64 = sqlx::query_scalar(
        "WITH sent AS ( \
           SELECT pg_catalog.pg_notify($2, id) FROM environments \
           WHERE id = $1 AND suspended_at IS NOT NULL AND state = 'running') \
         SELECT count(*) FROM sent",
    )
    .bind(environment_id)
    .bind(CHANNEL)
    .fetch_one(pool)
    .await?;
    Ok(sent > 0)
}
