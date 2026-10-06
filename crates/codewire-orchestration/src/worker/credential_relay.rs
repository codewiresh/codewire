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
//! A leader-gated loop relays exactly the live bindings: one relay per bound
//! environment, started when its binding appears and replaced when the
//! binding names another Pod or generation. A released binding stops its
//! relay at the next pass; the broker refuses it already.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_gateway_proto::CREDENTIAL_RELAY_TOKEN_PATH;
use codewire_tls::ClientTlsEndpoint;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::WorkerContext;
use super::gatewayauth::{WorkspaceCredentialScope, daemon_credential_for};

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

type TargetRow = (String, String, i64, String);

/// The live bindings of this sandbox namespace: the backend pointer names the
/// binding and it is not released.
const LIVE_TARGETS: &str = "SELECT b.environment_id, w.pod_uid, w.operation_generation, \
            w.credential_scope \
       FROM sandbox_environment_backend b \
       JOIN sandbox_workspace_bindings w \
         ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid \
      WHERE b.bound_at IS NOT NULL AND w.released_at IS NULL AND w.namespace = $1 \
      ORDER BY b.environment_id \
      LIMIT $2";

async fn live_targets(pool: &PgPool, namespace: &str) -> anyhow::Result<Vec<Target>> {
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
    Ok(rows.into_iter().filter_map(target_from_row).collect())
}

fn target_from_row((environment_id, pod_uid, generation, scope): TargetRow) -> Option<Target> {
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
    target
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
    fn reconcile(&mut self, config: &Arc<RelayConfig>, desired: &[Target]) {
        self.stopping.retain(|_, task| !task.is_finished());
        let plan = plan(
            self.running.values().map(|running| &running.target),
            desired,
        );
        for environment in plan.stop {
            self.stop(environment);
        }
        for target in plan.start {
            let environment = target.environment_id;
            let previous = self.stopping.remove(&environment);
            let cancellation = CancellationToken::new();
            let task = tokio::spawn(relay_environment(
                config.clone(),
                target.clone(),
                previous,
                cancellation.clone(),
            ));
            self.running.insert(
                environment,
                Running {
                    target,
                    cancellation,
                    task,
                },
            );
        }
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
    while epoch::run(&epochs, cancellation.cancelled()).await.is_err() {
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
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            relays.stop_all();
            continue;
        }
        match live_targets(&ctx.pool, &config.namespace).await {
            Ok(targets) => relays.reconcile(&config, &targets),
            // Keep the current relays; the broker still decides each request.
            Err(error) => tracing::warn!(%error, "credential relay: read live bindings failed"),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod database_tests;
