//! Credit settlement on billing's leader (#3381, #4754): one task that, on the
//! minute's tick, draws usage, settles every organization due and sends the
//! notices due; and that, the moment an organization's credit changes,
//! settles that organization and sends the notices due.
//!
//! The database notifies `credit_changes` with the organization's ID for
//! every ledger row and every change to its automatic top-up or its
//! out-of-credit mark (migration 0029). Until now billing noticed only on its
//! minute's tick, so the console and the emails trailed a change by up to a
//! minute.
//!
//! One task does both, one pass at a time. A notice email is recorded only
//! after it is sent, and a pass's own writes notify again, so two passes at
//! once could send the same email twice. With one task, the second pass finds
//! it recorded. Settling writes the ledger or the mark itself and so notifies
//! its own organization again; the next pass finds nothing to do and writes
//! nothing (a mark already set is set to the same value, which the trigger
//! ignores).
//!
//! The tick keeps running when the listener's connection is down, and the
//! task subscribes again; after every subscription it settles everyone once,
//! since notices may have been missed.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sqlx::postgres::{PgListener, PgNotification};

use crate::metering::MeteringDeps;

/// The channel migration 0029's triggers notify.
pub const CHANNEL: &str = "credit_changes";
/// Notices that arrive within this of the first are settled together.
const GATHER: Duration = Duration::from_millis(250);
/// How long a failed subscription waits before the next try.
const RESUBSCRIBE_AFTER: Duration = Duration::from_secs(5);

/// The leader's credit task. A follower holds no connection and does
/// nothing on its ticks.
pub(crate) async fn run(deps: Arc<MeteringDeps>, is_leader: Arc<AtomicBool>) {
    let mut ticker = tokio::time::interval(crate::credit::CREDIT_METERING_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // the first pass after one interval, as before
    let mut listener: Option<PgListener> = None;
    let mut subscribe_at = tokio::time::Instant::now();
    loop {
        if !is_leader.load(Ordering::SeqCst) {
            listener = None;
            ticker.tick().await;
            continue;
        }
        if listener.is_none() && tokio::time::Instant::now() >= subscribe_at {
            match subscribe(&deps).await {
                Ok(subscribed) => {
                    listener = Some(subscribed);
                    // Notices sent before this subscription were missed.
                    settle_everyone(&deps).await;
                }
                Err(error) => {
                    tracing::warn!(error = %error, "credit changes: subscribing failed");
                    subscribe_at = tokio::time::Instant::now() + RESUBSCRIBE_AFTER;
                }
            }
        }
        let first = match listener.as_mut() {
            // The tick and the first notice race; the rest of a gather does
            // not, so no notice taken off the connection is dropped.
            Some(subscribed) => tokio::select! {
                _ = ticker.tick() => None,
                notice = subscribed.try_recv() => Some(notice),
            },
            None => {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = tokio::time::sleep_until(subscribe_at) => continue,
                }
                None
            }
        };
        match first {
            None => tick(&deps).await,
            Some(Ok(Some(notice))) => {
                let subscribed = listener.as_mut().expect("a notice came from the listener");
                match gather(subscribed, notice).await {
                    Ok(due) => settle(&deps, &due).await,
                    Err(error) => {
                        tracing::warn!(error = %error, "credit changes: the listener failed");
                        listener = None;
                    }
                }
            }
            Some(Ok(None)) => {
                tracing::warn!("credit changes: the listener's connection was lost");
                listener = None;
            }
            Some(Err(error)) => {
                tracing::warn!(error = %error, "credit changes: the listener failed");
                listener = None;
            }
        }
    }
}

async fn subscribe(deps: &MeteringDeps) -> anyhow::Result<PgListener> {
    let mut listener = PgListener::connect_with(&deps.pool).await?;
    listener.listen(CHANNEL).await?;
    Ok(listener)
}

/// The first notice's organization and those of any more that arrive within
/// [`GATHER`] of it. The gather's timeout cancels a `try_recv` in flight too.
/// sqlx doesn't document that as lossless, but its socket keeps what it has
/// read in its own buffer, so a notice cut off there is decoded by the next
/// call; were one ever lost, the minute's tick still settles that
/// organization.
async fn gather(
    listener: &mut PgListener,
    first: PgNotification,
) -> anyhow::Result<BTreeSet<String>> {
    let mut due = BTreeSet::from([first.payload().to_owned()]);
    let gathered = tokio::time::Instant::now() + GATHER;
    while let Ok(notice) = tokio::time::timeout_at(gathered, listener.try_recv()).await {
        let notice = notice?
            .ok_or_else(|| anyhow::anyhow!("credit changes: the listener's connection was lost"))?;
        due.insert(notice.payload().to_owned());
    }
    Ok(due)
}

/// The minute's pass: draw usage, then top up or mark every organization
/// left without credit, then tell owners who ran low or ran out.
async fn tick(deps: &MeteringDeps) {
    match crate::credit::draw_due_usage(&deps.pool).await {
        Ok(summary) if summary.organizations > 0 || summary.failed > 0 => {
            tracing::info!(
                organizations = summary.organizations,
                failed = summary.failed,
                drawn_nano_eur = summary.drawn_nano_eur,
                "credit metering: drew usage"
            );
        }
        Ok(_) => {}
        Err(error) => tracing::error!(error = %error, "credit metering: draw failed"),
    }
    settle_everyone(deps).await;
}

/// Settles each organization, then sends the notices now due.
pub(crate) async fn settle(deps: &MeteringDeps, organizations: &BTreeSet<String>) {
    for organization_id in organizations {
        if let Err(error) = crate::credit::settle_organization(
            &deps.pool,
            &deps.stripe,
            deps.credit_enforcement,
            organization_id,
            false,
        )
        .await
        {
            tracing::error!(organization_id, %error, "credit changes: settlement failed");
        }
    }
    send_notices(deps).await;
}

async fn settle_everyone(deps: &MeteringDeps) {
    if let Err(error) =
        crate::credit::settle_due(&deps.pool, &deps.stripe, deps.credit_enforcement).await
    {
        tracing::error!(%error, "credit metering: settlement failed");
    }
    send_notices(deps).await;
}

async fn send_notices(deps: &MeteringDeps) {
    if let Err(error) =
        crate::credit::send_credit_notices(&deps.pool, &deps.email, deps.credit_enforcement).await
    {
        tracing::error!(%error, "credit metering: notices failed");
    }
}

#[cfg(test)]
mod tests;
