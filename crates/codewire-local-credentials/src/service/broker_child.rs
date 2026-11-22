//! One broker child of an environment generation: its start, its admission
//! and the record of its end.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use codewire_access::EnvironmentId;
use codewire_protected_store::ProtectedStore;
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::{
    BROKER_LOCAL_START_TIMEOUT, BROKER_PLATFORM_START_TIMEOUT, BROKER_READY_STABILITY, BrokerLaunch,
};
use crate::broker_channel::{
    BrokerChannelRefreshLifetime, BrokerLeaseChannelControl, serve_broker_lease_channel_with_ready,
};
use crate::broker_log::{BrokerLog, StderrTail, exit_status};
use crate::broker_process::ProviderLookup;

pub(super) enum BrokerAttempt {
    Stopped,
    Failed,
}

/// How long a child whose lease channel has closed has to end before its end
/// is recorded.
const ENDING_GRACE: Duration = Duration::from_millis(250);

/// One admitted broker child and its lease channel. Its owner ends it with
/// [`Self::stop`].
pub(super) struct BrokerChild<S: ProtectedStore> {
    child: tokio::process::Child,
    lease_shutdown: watch::Sender<bool>,
    lease_task: tokio::task::JoinHandle<Result<(), crate::BrokerLeaseChannelError>>,
    /// The lease task already returned and must not be polled again.
    channel_ended: bool,
    /// How the lease task ended, once it has (for the broker log).
    lease_outcome: Option<&'static str>,
    pid: Option<u32>,
    stderr: Option<StderrTail>,
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    /// Its spawn plus the renewal lifetime.
    pub(super) ends_at: tokio::time::Instant,
    /// The provider hosts it reported it has no address for (#5286).
    pub(super) unresolved: BTreeSet<String>,
}

impl<S: ProtectedStore> BrokerChild<S> {
    /// Resolves when the child exits or its lease channel ends. Cancel-safe.
    pub(super) async fn ended(&mut self) {
        tokio::select! {
            _ = self.child.wait() => {}
            result = &mut self.lease_task, if !self.channel_ended => {
                self.channel_ended = true;
                self.lease_outcome = Some(lease_outcome(&result));
            }
        }
    }

    /// Why the broker ended before it was ready: the child exited, or else
    /// its lease channel closed. A child's exit closes its lease too, so both
    /// can be seen at once; the reason comes from the child's state, never
    /// from which event was noticed first (#3069).
    fn not_ready_reason(&mut self) -> &'static str {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            "ended_before_ready"
        } else {
            "lease_closed_before_ready"
        }
    }

    /// The child's exit status and the lease channel's outcome so far, for
    /// the broker log. Call before [`Self::stop`], which kills the child.
    ///
    /// A child whose lease channel has closed is given [`ENDING_GRACE`] to
    /// end first. The channel closes as the child exits, and it is usually
    /// noticed before the exit is: reading the status at once recorded
    /// `status=running` and no last word for a broker that had ended at its
    /// first step (#5238).
    async fn outcome(&mut self) -> (String, &'static str) {
        if self.channel_ended || self.lease_task.is_finished() {
            // A child still running after the grace is recorded as running.
            let _ = tokio::time::timeout(ENDING_GRACE, self.child.wait()).await;
        }
        let status = exit_status(self.child.try_wait().ok().flatten());
        let lease = if self.channel_ended {
            self.lease_outcome.unwrap_or("ended")
        } else if self.lease_task.is_finished() {
            "finished"
        } else {
            "open"
        };
        (status, lease)
    }

    pub(super) async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.lease_shutdown.send(true);
        if !self.channel_ended {
            let _ = (&mut self.lease_task).await;
        }
        // A panicked lease task drops its close guard but cannot await workers.
        // Its manager holds this independent observer until the same drain ends.
        self.lifetime.close_and_wait().await;
    }
}

/// The lease task's typed outcome; no request or credential data.
fn lease_outcome(
    result: &Result<Result<(), crate::BrokerLeaseChannelError>, tokio::task::JoinError>,
) -> &'static str {
    use crate::BrokerLeaseChannelError as E;
    match result {
        Ok(Ok(())) => "closed",
        Ok(Err(E::InvalidRequest)) => "invalid_request",
        Ok(Err(E::Denied)) => "denied",
        Ok(Err(E::Unavailable)) => "unavailable",
        Ok(Err(E::InvalidResponse)) => "invalid_response",
        Ok(Err(E::RefreshInProgress)) => "refresh_in_progress",
        Ok(Err(E::StaleRefresh)) => "stale_refresh",
        Ok(Err(E::Withheld(_))) => "withheld",
        Ok(Err(E::RateLimited { .. })) => "rate_limited",
        Err(error) if error.is_panic() => "panicked",
        Err(_) => "cancelled",
    }
}

/// Spawn one child and admit it within one start deadline: its lease channel
/// reports it ready and it stays up for the stability interval.
pub(super) async fn start_broker<S: ProtectedStore + 'static>(
    launch: Arc<BrokerLaunch<S>>,
    lookup: ProviderLookup,
    mut shutdown: watch::Receiver<bool>,
) -> Result<BrokerChild<S>, BrokerAttempt> {
    if *shutdown.borrow() {
        return Err(BrokerAttempt::Stopped);
    }
    // Capture before spawning the child. Neither handshake phase nor retry
    // within this attempt can reset this total deadline. The child's
    // lifetime also counts from here.
    let spawned_at = tokio::time::Instant::now();
    let start_deadline = spawned_at
        + if launch.platform.is_some() {
            BROKER_PLATFORM_START_TIMEOUT
        } else {
            BROKER_LOCAL_START_TIMEOUT
        };
    let Ok((authority_stream, broker_stream)) = std::os::unix::net::UnixStream::pair() else {
        return Err(BrokerAttempt::Failed);
    };
    if authority_stream.set_nonblocking(true).is_err() {
        return Err(BrokerAttempt::Failed);
    }
    let Ok(authority_stream) = UnixStream::from_std(authority_stream) else {
        return Err(BrokerAttempt::Failed);
    };
    let log = &launch.log;
    let environment = &launch.config.environment_id;
    let generation = launch.config.environment_generation;
    let Ok(child) =
        launch
            .spawner
            .spawn(&launch.config, &lookup, broker_stream, &launch.boot_secrets)
    else {
        log.record(
            "broker_spawn_failed",
            &[("environment", environment), ("generation", &generation)],
        );
        return Err(BrokerAttempt::Failed);
    };
    let mut child = child;
    let pid = child.id();
    let stderr = (child.stderr.take()).map(|err| log.tail(err, environment, generation, pid));
    log.record(
        "broker_spawned",
        &[
            ("environment", environment),
            ("generation", &generation),
            (
                "pid",
                &pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            ),
            ("lookup", &lookup.log_name()),
        ],
    );
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
    let (lease_shutdown, lease_stopped) = watch::channel(false);
    let lifetime = BrokerChannelRefreshLifetime::new_with_ssh_runtime(
        Arc::clone(&launch.authority),
        Arc::clone(&launch.ssh_runtime),
    );
    let lease_task = tokio::spawn(serve_broker_lease_channel_with_ready(
        Arc::clone(&lifetime),
        authority_stream,
        launch.config.environment_id.clone(),
        launch.config.environment_generation,
        Arc::clone(&launch.audit),
        launch.projection.clone(),
        BrokerLeaseChannelControl {
            ready: Some(ready_tx),
            shutdown: Some(lease_stopped),
            platform: launch.platform.clone(),
            platform_delegated: launch.config.platform_delegated,
            local_profile: launch.local_profile.clone(),
        },
    ));
    let mut broker = BrokerChild {
        child,
        lease_shutdown,
        lease_task,
        channel_ended: false,
        lease_outcome: None,
        pid,
        stderr,
        lifetime,
        ends_at: spawned_at + launch.renewal.lifetime,
        unresolved: BTreeSet::new(),
    };
    let mut start_timeout = Box::pin(tokio::time::sleep_until(start_deadline));
    let not_ready = tokio::select! {
        ready = &mut ready_rx => match ready {
            Ok(ready) => {
                broker.unresolved = ready.unresolved_hosts;
                None
            }
            Err(_) => Some(broker.not_ready_reason()),
        },
        () = broker.ended() => Some(broker.not_ready_reason()),
        _ = shutdown.changed() => {
            broker.stop().await;
            return Err(BrokerAttempt::Stopped);
        }
        _ = &mut start_timeout => Some("start_timeout"),
    };
    if let Some(reason) = not_ready {
        record_broker_end(
            log,
            "broker_not_ready",
            reason,
            &mut broker,
            environment,
            generation,
            spawned_at.elapsed(),
            None,
        )
        .await;
        broker.stop().await;
        return Err(BrokerAttempt::Failed);
    }
    log.record(
        "broker_ready",
        &[
            ("environment", environment),
            ("generation", &generation),
            (
                "pid",
                &pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            ),
            ("elapsed_ms", &spawned_at.elapsed().as_millis()),
            ("unresolved", &unresolved_for_log(&broker.unresolved)),
        ],
    );

    let stability = tokio::time::sleep(BROKER_READY_STABILITY);
    let unstable = tokio::select! {
        _ = stability => (tokio::time::Instant::now() >= start_deadline).then_some("start_timeout"),
        _ = &mut start_timeout => Some("start_timeout"),
        () = broker.ended() => Some("ended_while_settling"),
        _ = shutdown.changed() => {
            broker.stop().await;
            return Err(BrokerAttempt::Stopped);
        }
    };
    if let Some(reason) = unstable {
        record_broker_end(
            log,
            "broker_not_ready",
            reason,
            &mut broker,
            environment,
            generation,
            spawned_at.elapsed(),
            None,
        )
        .await;
        broker.stop().await;
        return Err(BrokerAttempt::Failed);
    }
    Ok(broker)
}

/// A ready child's unresolved hosts as one log value: `-` for none, else
/// the hosts joined by `/`, which the log's value grammar keeps and no host
/// contains.
fn unresolved_for_log(unresolved: &BTreeSet<String>) -> String {
    if unresolved.is_empty() {
        return "-".to_owned();
    }
    let hosts: Vec<&str> = unresolved.iter().map(String::as_str).collect();
    hosts.join("/")
}

/// One line for a child that ended or never became ready: its exit status and
/// lease outcome are read before the authority stops it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_broker_end<S: ProtectedStore>(
    log: &BrokerLog,
    event: &str,
    reason: &str,
    broker: &mut BrokerChild<S>,
    environment: &EnvironmentId,
    generation: u64,
    ran: Duration,
    restart_in: Option<Duration>,
) {
    let (status, lease) = broker.outcome().await;
    let exited = status != "running";
    let error = match &mut broker.stderr {
        Some(tail) => tail.exit_line(exited).await,
        None => String::new(),
    };
    let error = if error.is_empty() {
        "-".to_owned()
    } else {
        error
    };
    let pid = broker
        .pid
        .map_or_else(|| "none".to_owned(), |pid| pid.to_string());
    let restart = restart_in.map_or_else(|| "-".to_owned(), |delay| delay.as_millis().to_string());
    log.record(
        event,
        &[
            ("environment", environment),
            ("generation", &generation),
            ("pid", &pid),
            ("reason", &reason),
            ("status", &status),
            ("lease", &lease),
            ("ran_ms", &ran.as_millis()),
            ("restart_in_ms", &restart),
            ("error", &error),
        ],
    );
}
