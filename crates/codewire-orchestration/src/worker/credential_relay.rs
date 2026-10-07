//! The credential relay (design §4): orchestration pulls each bound
//! workspace daemon's credential bridge and relays it to the isolated broker,
//! as the per-environment gateway did.
//!
//! The direction stays pull: orchestration dials the daemon over the existing
//! orchestration → workspace ingress, and no stream is ever initiated by the
//! tenant. The broker authenticates orchestration's projected relay token
//! (`CredentialRelay`, pinned to this ServiceAccount and namespace) with the
//! daemon's workspace token, and takes the environment from the workspace
//! Pod's live binding. Every authority decision stays in the broker.
//!
//! A leader-gated loop relays exactly the live bindings with a credential
//! selection: one relay per bound environment, started when its binding
//! appears and replaced when the binding names another Pod or generation. A
//! daemon bound without a selection has no bridge and refuses every epoch,
//! so its environment gets no relay. A released binding stops its
//! relay at the next pass; the broker refuses it already.
//!
//! The broker admits an epoch only once the environment is running, which
//! comes after the binding, SSH access and the Pod's readiness. Each pass
//! therefore also tells every relay whether its environment is running, and
//! a relay starts its first epoch only then. A pass runs every second and,
//! for one environment, on each of its log notifications: create logs
//! `mark_running` right after the running transition commits, so the first
//! epoch starts within a notification of it rather than a retry delay.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_gateway_proto::CREDENTIAL_RELAY_TOKEN_PATH;
use codewire_tls::ClientTlsEndpoint;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::WorkerContext;
use super::environment_auth::{WorkspaceCredentialScope, daemon_credential_for};
use crate::api::log_notifications::ENVIRONMENT_LOGS_CHANNEL;

mod budget;
mod connection;
mod epoch;

use budget::{EnvironmentBudget, Limits};
use connection::DaemonTarget;
use epoch::{BrokerEndpoint, EpochConfig};

/// Between passes over the live bindings.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
/// After a relay that failed to drain, before its environment's next one.
const RESTART_DELAY: Duration = Duration::from_secs(1);
/// Bounds one pass's read. More live bindings than this relay only the first.
const MAX_RELAYS: i64 = 4096;
/// Environment notifications queued for the loop; more are dropped, and the
/// next full pass finds what they announced.
const NOTIFICATION_BUFFER: usize = 1024;
/// Before listening again after the notification connection failed.
const LISTENER_RETRY: Duration = Duration::from_secs(1);
/// The public broker trust mounted from `codewire-credential-broker-roots`.
pub const CREDENTIAL_RELAY_BROKER_ROOTS_FILE: &str =
    "/run/codewire-credentials/broker-roots/ca.crt";

/// What every relay of this orchestration process presents.
struct RelayConfig {
    namespace: String,
    session_secret: Zeroizing<String>,
    relay_token: PathBuf,
    broker: BrokerEndpoint,
    limits: Limits,
}

/// One live binding to relay. Any change is a different relay.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    environment_id: Uuid,
    pod_uid: String,
    generation: u64,
    scope: WorkspaceCredentialScope,
}

/// A live binding, and whether the broker can admit its epochs yet. Only the
/// target identifies a relay; admissibility changes never replace one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Live {
    target: Target,
    admissible: bool,
}

type TargetRow = (String, String, i64, String, bool);

/// The live bindings of this sandbox namespace: the backend pointer names the
/// binding, it is not released, and it carries the projection selection
/// without which the bound daemon serves no bridge. `admissible` is the
/// environment half of the broker's admission scope, which refuses every
/// other state.
macro_rules! live_targets {
    ($filter:literal) => {
        concat!(
            "SELECT b.environment_id, w.pod_uid, w.operation_generation, w.credential_scope, \
                    e.state = 'running' AND e.desired_state = 'started' \
               FROM sandbox_environment_backend b \
               JOIN sandbox_workspace_bindings w \
                 ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid \
               JOIN environments e ON e.id = b.environment_id \
              WHERE b.bound_at IS NOT NULL AND w.released_at IS NULL AND w.namespace = $1 \
                AND w.projection_selection_sha256 IS NOT NULL",
            $filter,
            " ORDER BY b.environment_id LIMIT $2"
        )
    };
}
const LIVE_TARGETS: &str = live_targets!("");
/// One environment's live binding, for a pass on its notification.
const LIVE_TARGET: &str = live_targets!(" AND b.environment_id = $3");

async fn live_targets(pool: &PgPool, namespace: &str) -> anyhow::Result<Vec<Live>> {
    let rows: Vec<TargetRow> = sqlx::query_as(LIVE_TARGETS)
        .bind(namespace)
        .bind(MAX_RELAYS)
        .fetch_all(pool)
        .await?;
    if rows.len() as i64 == MAX_RELAYS {
        tracing::warn!(
            limit = MAX_RELAYS,
            "credential relay: more live bindings than relays; relaying the first"
        );
    }
    Ok(rows.into_iter().filter_map(live_from_row).collect())
}

async fn live_target(
    pool: &PgPool,
    namespace: &str,
    environment: Uuid,
) -> anyhow::Result<Option<Live>> {
    let row: Option<TargetRow> = sqlx::query_as(LIVE_TARGET)
        .bind(namespace)
        .bind(1_i64)
        .bind(environment.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(live_from_row))
}

fn live_from_row(
    (environment_id, pod_uid, generation, scope, admissible): TargetRow,
) -> Option<Live> {
    let target = Uuid::parse_str(&environment_id)
        .ok()
        .and_then(|environment| {
            Some(Target {
                environment_id: environment,
                pod_uid,
                generation: u64::try_from(generation).ok().filter(|value| *value > 0)?,
                scope: WorkspaceCredentialScope::parse(&scope)?,
            })
        });
    if target.is_none() {
        tracing::warn!(
            %environment_id,
            "credential relay: skipping a binding with an invalid environment, generation or scope"
        );
    }
    Some(Live {
        target: target?,
        admissible,
    })
}

/// Which relays a pass stops and which it starts. A changed target is both.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    stop: Vec<Uuid>,
    start: Vec<Target>,
}

fn plan<'a>(running: impl Iterator<Item = &'a Target>, desired: &[Target]) -> Plan {
    let running: HashMap<Uuid, &Target> = running
        .map(|target| (target.environment_id, target))
        .collect();
    let wanted: HashMap<Uuid, &Target> = desired
        .iter()
        .map(|target| (target.environment_id, target))
        .collect();
    let mut plan = Plan::default();
    for (environment, target) in &running {
        if wanted.get(environment) != Some(target) {
            plan.stop.push(*environment);
        }
    }
    for target in desired {
        if running.get(&target.environment_id) != Some(&target) {
            plan.start.push(target.clone());
        }
    }
    plan.stop.sort();
    plan.start.sort_by_key(|target| target.environment_id);
    plan
}

struct Running {
    target: Target,
    admissible: watch::Sender<bool>,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

/// The relays this process runs. A stopped relay is awaited by its
/// environment's next relay, so one environment never has two at once.
#[derive(Default)]
struct Relays {
    running: HashMap<Uuid, Running>,
    stopping: HashMap<Uuid, JoinHandle<()>>,
}

impl Relays {
    /// A pass over `desired`, the live bindings of every environment, or of
    /// `only` that one.
    fn reconcile(&mut self, config: &Arc<RelayConfig>, desired: &[Live], only: Option<Uuid>) {
        self.stopping.retain(|_, task| !task.is_finished());
        let targets: Vec<Target> = desired.iter().map(|live| live.target.clone()).collect();
        let plan = plan(
            self.running
                .values()
                .map(|running| &running.target)
                .filter(|target| only.is_none_or(|only| target.environment_id == only)),
            &targets,
        );
        for environment in plan.stop {
            self.stop(environment);
        }
        for target in plan.start {
            let environment = target.environment_id;
            let previous = self.stopping.remove(&environment);
            let cancellation = CancellationToken::new();
            let (admissible, admission) = watch::channel(false);
            let task = tokio::spawn(relay_environment(
                config.clone(),
                target.clone(),
                admission,
                previous,
                cancellation.clone(),
            ));
            self.running.insert(
                environment,
                Running {
                    target,
                    admissible,
                    cancellation,
                    task,
                },
            );
        }
        for live in desired {
            if let Some(running) = self.running.get(&live.target.environment_id) {
                running.admissible.send_if_modified(|current| {
                    std::mem::replace(current, live.admissible) != live.admissible
                });
            }
        }
    }

    /// Whether a notification for `environment` may change a relay: none is
    /// running for it yet, or its broker cannot admit it yet. A running,
    /// admissible environment's log lines change nothing here.
    fn awaits(&self, environment: Uuid) -> bool {
        self.running
            .get(&environment)
            .is_none_or(|running| !*running.admissible.borrow())
    }

    fn stop(&mut self, environment: Uuid) {
        if let Some(running) = self.running.remove(&environment) {
            running.cancellation.cancel();
            self.stopping.insert(environment, running.task);
        }
    }

    fn stop_all(&mut self) {
        let environments: Vec<Uuid> = self.running.keys().copied().collect();
        for environment in environments {
            self.stop(environment);
        }
    }
}

/// Relays one binding until cancelled. A relay that fails to drain is logged
/// and replaced after [`RESTART_DELAY`]; its producers were already cancelled.
async fn relay_environment(
    config: Arc<RelayConfig>,
    target: Target,
    admissible: watch::Receiver<bool>,
    previous: Option<JoinHandle<()>>,
    cancellation: CancellationToken,
) {
    if let Some(previous) = previous {
        let _ = previous.await;
    }
    let environment = target.environment_id.to_string();
    let daemon = match daemon_target(&config, &target) {
        Ok(daemon) => daemon,
        Err(error) => {
            tracing::error!(
                environment_id = %environment,
                %error,
                "credential relay: cannot authorize the workspace daemon"
            );
            return;
        }
    };
    let epochs = EpochConfig {
        environment_id: target.environment_id,
        generation: target.generation,
        daemon,
        relay_token: config.relay_token.clone(),
        broker: config.broker.clone(),
        budget: EnvironmentBudget::new(config.limits),
    };
    tracing::info!(
        event = "credential_relay_started",
        environment_id = %environment,
        generation = target.generation,
        "credential relay started for the bound workspace Pod"
    );
    while epoch::run(&epochs, admissible.clone(), cancellation.cancelled())
        .await
        .is_err()
    {
        tracing::error!(
            event = "credential_relay_drain_failed",
            environment_id = %environment,
            "credential relay did not drain; starting a fresh relay"
        );
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = tokio::time::sleep(RESTART_DELAY) => {}
        }
    }
    tracing::info!(
        event = "credential_relay_stopped",
        environment_id = %environment,
        "credential relay stopped"
    );
}

/// The bound Pod's daemon over the cluster Service, with the credential of
/// exactly that Pod. Each epoch opens its own connection to it.
fn daemon_target(config: &RelayConfig, target: &Target) -> anyhow::Result<DaemonTarget> {
    let environment = target.environment_id.to_string();
    Ok(DaemonTarget {
        endpoint: crate::api::environment_daemon::cluster_daemon_endpoint(
            &config.namespace,
            &environment,
        ),
        credential: Zeroizing::new(daemon_credential_for(
            &config.session_secret,
            &environment,
            &target.pod_uid,
            target.scope,
        )?),
    })
}

/// Runs while this process leads, relaying every live binding of its sandbox
/// namespace. Inert without the platform credential runtime.
pub async fn credential_relay_loop(ctx: Arc<WorkerContext>, is_leader: Arc<AtomicBool>) {
    let Some(runtime) = ctx.sandbox_cfg.credential_runtime.as_ref() else {
        tracing::info!("credential relay: no platform credential runtime; inert");
        return;
    };
    let broker = match ClientTlsEndpoint::new(
        runtime.broker_https_origin(),
        PathBuf::from(CREDENTIAL_RELAY_BROKER_ROOTS_FILE),
    ) {
        Ok(broker) => broker,
        Err(error) => {
            tracing::error!(%error, "credential relay: invalid broker endpoint; inert");
            return;
        }
    };
    let config = Arc::new(RelayConfig {
        namespace: ctx.sandbox_cfg.sandbox_namespace.clone(),
        session_secret: Zeroizing::new(ctx.sandbox_cfg.session_secret.clone()),
        relay_token: PathBuf::from(CREDENTIAL_RELAY_TOKEN_PATH),
        broker: BrokerEndpoint::Tls(broker),
        limits: Limits::DEFAULT,
    });
    let mut relays = Relays::default();
    let mut notifications = spawn_environment_notifications(ctx.pool.clone());
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // `None` is the periodic pass over every environment; a notification
        // passes over only its environment.
        let only = tokio::select! {
            _ = ticker.tick() => None,
            Some(environment) = notifications.recv() => Some(environment),
        };
        if !is_leader.load(Ordering::SeqCst) {
            relays.stop_all();
            continue;
        }
        let live = match only {
            None => live_targets(&ctx.pool, &config.namespace).await,
            Some(environment) if relays.awaits(environment) => {
                live_target(&ctx.pool, &config.namespace, environment)
                    .await
                    .map(|live| live.into_iter().collect())
            }
            Some(_) => continue,
        };
        match live {
            Ok(live) => relays.reconcile(&config, &live, only),
            // Keep the current relays; the broker still decides each request.
            Err(error) => tracing::warn!(%error, "credential relay: read live bindings failed"),
        }
    }
}

/// Every environment log notification's environment, from this process's own
/// listener. A log line is not a state change, so each is only a hint: the
/// loop reads the environment's live binding again before acting on it.
fn spawn_environment_notifications(pool: PgPool) -> mpsc::Receiver<Uuid> {
    let (sender, receiver) = mpsc::channel(NOTIFICATION_BUFFER);
    tokio::spawn(async move {
        loop {
            if let Err(error) = forward_notifications(&pool, &sender).await {
                tracing::warn!(%error, "credential relay: environment notifications failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    });
    receiver
}

async fn forward_notifications(pool: &PgPool, sender: &mpsc::Sender<Uuid>) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(ENVIRONMENT_LOGS_CHANNEL).await?;
    loop {
        let Some(notification) = listener.try_recv().await? else {
            anyhow::bail!("environment notification connection lost");
        };
        if let Ok(environment) = Uuid::parse_str(notification.payload()) {
            // A full queue drops the hint; the periodic pass still runs.
            let _ = sender.try_send(environment);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod database_tests;
