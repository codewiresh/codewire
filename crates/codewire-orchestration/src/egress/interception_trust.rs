//! The interception trust each hosted Sandbox Pod's guest installed (#6200;
//! `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Hosted interception"). A guest
//! keeps its first egress session's trust for the Pod's life (#5006), so the
//! first of the Pod's first admission and first bind records whether that
//! trust carries a CA, every admission gives exactly that, and the first bind
//! stores "intercepted" only with it. A record is never changed (0052's
//! trigger), and is deleted only when the API server's complete list of Pods
//! confirms its Pod gone.

use std::collections::HashSet;
use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use sqlx::PgPool;

/// How often orchestration deletes the records of Pods that are gone.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Pods listed per page.
const LIST_PAGE: u32 = 500;

/// Records `ca_given` for `pod_uid` unless something is recorded already, and
/// answers what is recorded. Two statements in one transaction: the insert
/// waits for a concurrent first writer of the same Pod to commit, and the
/// read, under a new snapshot, then sees its row.
pub async fn record(pool: &PgPool, pod_uid: &str, ca_given: bool) -> Result<bool, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO sandbox_pod_interception_trust (pod_uid, ca_given) VALUES ($1, $2) \
         ON CONFLICT (pod_uid) DO NOTHING",
    )
    .bind(pod_uid)
    .bind(ca_given)
    .execute(&mut *transaction)
    .await?;
    let recorded = sqlx::query_scalar(
        "SELECT ca_given FROM sandbox_pod_interception_trust WHERE pod_uid = $1",
    )
    .bind(pod_uid)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(recorded)
}

/// Every Pod UID `pods` holds, from one complete, paged list. A failed page,
/// an expired continuation included, fails the whole list.
pub async fn live_pod_uids(pods: &Api<Pod>) -> Result<HashSet<String>, kube::Error> {
    let mut uids = HashSet::new();
    let mut params = ListParams::default().limit(LIST_PAGE);
    loop {
        let page = pods.list_metadata(&params).await?;
        uids.extend(page.items.into_iter().filter_map(|pod| pod.metadata.uid));
        match page.metadata.continue_ {
            Some(token) if !token.is_empty() => params = params.continue_token(&token),
            _ => return Ok(uids),
        }
    }
}

/// Deletes the records of Pods `live` does not name, written before
/// `listed_at`, the database's time when the list began: a Pod first
/// admitted after it began may be missing from the list.
pub async fn sweep(
    pool: &PgPool,
    live: &HashSet<String>,
    listed_at: chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    let live: Vec<&str> = live.iter().map(String::as_str).collect();
    Ok(sqlx::query(
        "DELETE FROM sandbox_pod_interception_trust \
          WHERE recorded_at < $2 AND NOT (pod_uid = ANY($1))",
    )
    .bind(&live)
    .bind(listed_at)
    .execute(pool)
    .await?
    .rows_affected())
}

/// One sweep: the database's time, then the complete list, then the delete.
/// A list that fails deletes nothing.
pub async fn sweep_once(pool: &PgPool, pods: &Api<Pod>) -> anyhow::Result<u64> {
    let listed_at = sqlx::query_scalar("SELECT now()").fetch_one(pool).await?;
    let live = live_pod_uids(pods).await?;
    Ok(sweep(pool, &live, listed_at).await?)
}

/// Runs [`sweep_once`] every [`SWEEP_INTERVAL`] over the sandbox namespace,
/// the one namespace where admission (`admission::guest_on_node`) and the
/// bind (§4.3) accept a Pod, so every recorded Pod that is alive is listed.
pub fn spawn_sweep(pool: PgPool, pods: Api<Pod>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match sweep_once(&pool, &pods).await {
                Ok(0) => {}
                Ok(swept) => tracing::info!(swept, "swept interception trust of gone Pods"),
                Err(error) => tracing::warn!(%error, "interception trust sweep failed"),
            }
        }
    });
}

#[cfg(test)]
#[path = "interception_trust/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "interception_trust/database_tests.rs"]
mod database_tests;
