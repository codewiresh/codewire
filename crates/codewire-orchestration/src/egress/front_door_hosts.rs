//! The names each hosted Sandbox Pod's TLS front door has a route for, as the
//! cw-egress serving it last reported at admission (#6290, migration 0069;
//! `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Hosted interception"). A Pod's
//! first bind is intercepted only when every name its selection would bind
//! is reported here, and is refused by name otherwise: a host handed to a
//! front door with no route for it fails silently, and interception is never
//! quietly off. Each admission replaces the Pod's set, since the cw-egress
//! serving it may have rolled; the row is deleted only when the API server's
//! complete list of Pods confirms its Pod gone.

use std::collections::BTreeSet;

use codewire_egress_policy::intercept::InterceptBinding;
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use sqlx::PgPool;

use super::assignment::Intercept;
use super::interception_trust::{SWEEP_INTERVAL, live_pod_uids};

/// The most names one report may hold: the table's own bound.
pub const MAX_REPORTED: usize = 64;

/// One name as it is stored and compared: `host:port`, or `*.host:port` for a
/// suffix route.
fn entry(host: &str, port: u32, suffix: bool) -> String {
    if suffix {
        format!("*.{host}:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The names a report holds, or `None` when it can't be read: more than
/// [`MAX_REPORTED`], or one that isn't a canonical interceptable name on its
/// port. An empty report, from a cw-egress older than the field, is an empty
/// set: it serves nothing.
pub fn reported<'a>(
    bindings: impl IntoIterator<Item = (&'a str, u32, bool)>,
) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for (count, (host, port, suffix)) in bindings.into_iter().enumerate() {
        if count >= MAX_REPORTED {
            return None;
        }
        let canonical = InterceptBinding::new(host, u16::try_from(port).ok()?).ok()?;
        if canonical.hostname() != host {
            return None;
        }
        names.insert(entry(host, port, suffix));
    }
    Some(names)
}

/// The names `intercepts` binds, as stored and compared: built-in names only.
/// A host a binding names (`bound`, #5043; host-bound secrets, #4003) is not
/// one of them, and isn't checked against the front door's report yet.
pub fn needed(intercepts: &[Intercept]) -> BTreeSet<String> {
    intercepts
        .iter()
        .map(|intercept| {
            entry(
                intercept.binding.hostname(),
                u32::from(intercept.binding.port()),
                intercept.suffix,
            )
        })
        .collect()
}

/// The names in `needed` that `reported` lacks, in order, by host only: the
/// public provider names the creator's own selection chose, which is all a
/// refusal may show.
pub fn missing(needed: &BTreeSet<String>, reported: &BTreeSet<String>) -> Vec<String> {
    needed
        .difference(reported)
        .map(|name| {
            name.rsplit_once(':')
                .map_or(name.as_str(), |(host, _)| host)
                .to_owned()
        })
        .collect()
}

/// Replaces `pod_uid`'s reported set.
pub async fn record(
    pool: &PgPool,
    pod_uid: &str,
    hosts: &BTreeSet<String>,
) -> Result<(), sqlx::Error> {
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    sqlx::query(
        "INSERT INTO sandbox_pod_front_door_hosts (pod_uid, hosts) VALUES ($1, $2) \
         ON CONFLICT (pod_uid) DO UPDATE SET hosts = EXCLUDED.hosts, reported_at = now()",
    )
    .bind(pod_uid)
    .bind(&hosts)
    .execute(pool)
    .await?;
    Ok(())
}

/// `pod_uid`'s reported set, or `None` before any admission reported one.
pub async fn read(pool: &PgPool, pod_uid: &str) -> Result<Option<BTreeSet<String>>, sqlx::Error> {
    let hosts: Option<Vec<String>> =
        sqlx::query_scalar("SELECT hosts FROM sandbox_pod_front_door_hosts WHERE pod_uid = $1")
            .bind(pod_uid)
            .fetch_optional(pool)
            .await?;
    Ok(hosts.map(|hosts| hosts.into_iter().collect()))
}

/// Keeps the names `pod_uid`'s first bind was refused for, on its reported
/// row, which the refusal always follows. An admission never clears them.
pub async fn record_unserved(
    pool: &PgPool,
    pod_uid: &str,
    missing: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sandbox_pod_front_door_hosts SET unserved = $2 WHERE pod_uid = $1")
        .bind(pod_uid)
        .bind(missing)
        .execute(pool)
        .await?;
    Ok(())
}

/// The names `pod_uid`'s first bind was refused for, or `None` while it
/// wasn't.
pub async fn unserved(pool: &PgPool, pod_uid: &str) -> Result<Option<Vec<String>>, sqlx::Error> {
    Ok(
        sqlx::query_scalar("SELECT unserved FROM sandbox_pod_front_door_hosts WHERE pod_uid = $1")
            .bind(pod_uid)
            .fetch_optional(pool)
            .await?
            .flatten(),
    )
}

/// One sweep: the database's time, then the complete list, then the delete
/// of every row for a Pod the list doesn't name, reported before it began.
/// A list that fails deletes nothing.
pub async fn sweep_once(pool: &PgPool, pods: &Api<Pod>) -> anyhow::Result<u64> {
    let listed_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT now()").fetch_one(pool).await?;
    let live = live_pod_uids(pods).await?;
    let live: Vec<&str> = live.iter().map(String::as_str).collect();
    Ok(sqlx::query(
        "DELETE FROM sandbox_pod_front_door_hosts \
          WHERE reported_at < $2 AND NOT (pod_uid = ANY($1))",
    )
    .bind(&live)
    .bind(listed_at)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Runs [`sweep_once`] every [`SWEEP_INTERVAL`] over the sandbox namespace.
pub fn spawn_sweep(pool: PgPool, pods: Api<Pod>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match sweep_once(&pool, &pods).await {
                Ok(0) => {}
                Ok(swept) => tracing::info!(swept, "swept front-door host reports of gone Pods"),
                Err(error) => tracing::warn!(%error, "front-door host report sweep failed"),
            }
        }
    });
}

#[cfg(test)]
#[path = "front_door_hosts/database_tests.rs"]
mod database_tests;
#[cfg(test)]
#[path = "front_door_hosts/tests.rs"]
mod tests;
