//! The wait around the follower that `cw create` and the iOS app share
//! (#3825). A guard ends it when the environment can no longer finish setup
//! but no `failed` row says so, and after `complete` it waits for the
//! workspace daemon to be ready. Each surface words the outcomes.

use std::future::Future;
use std::time::{Duration, Instant};

use crate::{
    ClientError, CodewireClient, DesiredState, EnumValue, Environment, EnvironmentDaemonState,
    EnvironmentState, GetEnvironmentDaemonStatusRequest, GetEnvironmentRequest, IsolationTier,
    ProtoDuration,
};

use super::follow::{
    EnvironmentLogFeed, FollowEnd, FollowError, FollowPolicy, Interruption, SetupObserver,
    follow_setup, wait_with_ticks,
};
use super::{DaemonReadyRow, DaemonState, EnvironmentLogRow, daemon_ready_row};

/// The fastest the guard asks for the environment, whatever the server
/// suggests.
pub const SETUP_GUARD_INTERVAL: Duration = Duration::from_secs(5);
// The daemon wait matches the server-owned sandbox lifecycle first, then gives
// daemon setup its own post-running window. Confidential guests deliberately
// have a longer boot horizon; one fixed three-minute stopwatch reports false
// failure while the accepted server operation is still progressing.
pub const READY_TIMEOUT: Duration = Duration::from_secs(600);
pub const CONFIDENTIAL_READY_TIMEOUT: Duration = Duration::from_secs(1800);
pub const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(180);
/// The server sends no interval while a start runs, so this tick decides when
/// a client sees it finish. At 2 s, a start 1 s slower on the server could
/// return 2 s later (#3922).
pub const READY_POLL: Duration = Duration::from_millis(500);

/// What a setup wait reads about an environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentFacts {
    pub id: String,
    /// The state's token: `running`, `build_failed`, …
    pub state: String,
    pub desired_state: String,
    pub confidential: bool,
    pub error_code: Option<String>,
    pub error_reason: Option<String>,
    pub setup_error: Option<String>,
}

impl EnvironmentFacts {
    pub fn from_proto(environment: &Environment) -> Self {
        let text = |value: &str| (!value.is_empty()).then(|| value.to_owned());
        Self {
            id: environment.id.clone(),
            state: environment_state_token(&environment.state).to_owned(),
            desired_state: desired_state_token(&environment.desired_state).to_owned(),
            confidential: environment.isolation_tier.as_known()
                == Some(IsolationTier::Confidential),
            error_code: text(&environment.error_code),
            error_reason: text(&environment.error_reason),
            setup_error: text(&environment.setup_error),
        }
    }

    /// The platform ended this environment's create or start and said why
    /// (#4482), whatever state it has reached on the way out.
    pub fn platform_end(&self) -> Option<PlatformEnd> {
        match self.error_code.as_deref() {
            Some("no_capacity") => Some(PlatformEnd::NoCapacity),
            Some("container_start_failed") => Some(PlatformEnd::ContainerStartFailed),
            _ => None,
        }
    }

    /// Why setup can no longer finish, if it can't.
    pub fn setup_stop(&self) -> Option<SetupStop> {
        if let Some(end) = self.platform_end() {
            return Some(SetupStop::PlatformEnded(end));
        }
        match self.state.as_str() {
            "build_failed" | "error" | "failed" | "stopping" | "stopped" | "destroying"
            | "destroyed" => Some(SetupStop::Left),
            _ => self.setup_error.is_some().then_some(SetupStop::SetupError),
        }
    }

    /// Why a start can no longer finish, if it can't. A start is accepted
    /// while the environment is still `stopped`, with `started` desired, so
    /// only a change of intent ends it there (#3938).
    pub fn start_stop(&self) -> Option<SetupStop> {
        if let Some(end) = self.platform_end() {
            return Some(SetupStop::PlatformEnded(end));
        }
        let left = match self.state.as_str() {
            "build_failed" | "error" | "failed" | "stopping" | "destroying" | "destroyed" => true,
            "stopped" => self.desired_state != "started",
            _ => false,
        };
        left.then_some(SetupStop::Left)
    }
}

/// Why the platform ended a create or start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformEnd {
    NoCapacity,
    ContainerStartFailed,
}

/// Why setup can no longer finish, without a `failed` row to say so. The
/// details are the environment's: its state, `error_reason` and
/// `setup_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStop {
    PlatformEnded(PlatformEnd),
    /// The environment reached a state setup cannot finish from.
    Left,
    /// Setup recorded an error.
    SetupError,
}

pub fn environment_state_token(state: &EnumValue<EnvironmentState>) -> &'static str {
    match state.as_known() {
        Some(EnvironmentState::Unspecified) => "",
        Some(EnvironmentState::Pending) => "pending",
        Some(EnvironmentState::PendingBuild) => "pending_build",
        Some(EnvironmentState::Building) => "building",
        Some(EnvironmentState::BuildFailed) => "build_failed",
        Some(EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(EnvironmentState::Creating) => "creating",
        Some(EnvironmentState::Starting) => "starting",
        Some(EnvironmentState::Running) => "running",
        Some(EnvironmentState::Stopping) => "stopping",
        Some(EnvironmentState::Stopped) => "stopped",
        Some(EnvironmentState::Archiving) => "archiving",
        Some(EnvironmentState::Archived) => "archived",
        Some(EnvironmentState::Restoring) => "restoring",
        Some(EnvironmentState::Resizing) => "resizing",
        Some(EnvironmentState::Destroying) => "destroying",
        Some(EnvironmentState::Destroyed) => "destroyed",
        Some(EnvironmentState::Error) => "error",
        Some(EnvironmentState::Unknown) | None => "unknown",
    }
}

pub fn desired_state_token(state: &EnumValue<DesiredState>) -> &'static str {
    match state.as_known() {
        Some(DesiredState::Unspecified) => "",
        Some(DesiredState::Started) => "started",
        Some(DesiredState::Stopped) => "stopped",
        Some(DesiredState::Destroyed) => "destroyed",
        Some(DesiredState::Archived) => "archived",
        Some(DesiredState::Resized) => "resized",
        None => "unknown",
    }
}

pub fn daemon_state_token(state: &EnumValue<EnvironmentDaemonState>) -> &'static str {
    match state.as_known() {
        Some(EnvironmentDaemonState::Unspecified) => "unspecified",
        Some(EnvironmentDaemonState::Unsupported) => "unsupported",
        Some(EnvironmentDaemonState::Starting) => "starting",
        Some(EnvironmentDaemonState::Ready) => "ready",
        Some(EnvironmentDaemonState::Unhealthy) => "unhealthy",
        Some(EnvironmentDaemonState::UpgradeRequired) => "upgrade_required",
        None => "unknown",
    }
}

/// [`READY_TIMEOUT`], or the confidential tier's.
pub fn lifecycle_ready_timeout(confidential: bool) -> Duration {
    if confidential {
        CONFIDENTIAL_READY_TIMEOUT
    } else {
        READY_TIMEOUT
    }
}

/// The daemon wait's pace: the server's, or [`READY_POLL`].
pub fn ready_poll(server_interval: Option<Duration>) -> Duration {
    server_interval.unwrap_or(READY_POLL)
}

/// Why `GetEnvironment` gave no environment.
#[derive(Debug)]
pub enum GetEnvironmentError {
    Client(ClientError),
    /// The answer carried none.
    Missing,
}

/// The environment and the pace the server suggests for asking again.
pub async fn get_environment_facts(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> Result<(EnvironmentFacts, Option<Duration>), GetEnvironmentError> {
    let response = client
        .get_environment(GetEnvironmentRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(GetEnvironmentError::Client)?;
    let interval = response.poll_interval.into_option().and_then(std_duration);
    let environment = response
        .environment
        .into_option()
        .ok_or(GetEnvironmentError::Missing)?;
    Ok((EnvironmentFacts::from_proto(&environment), interval))
}

/// Asks for the environment at the server's pace until `stop` makes
/// something of it, and returns that. A failed request is asked again: the
/// log stream reports a connection that stays down.
pub async fn watch_environment<T>(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    mut stop: impl FnMut(&EnvironmentFacts) -> Option<T>,
) -> T {
    loop {
        let interval = match get_environment_facts(client, org_id, environment_id).await {
            Ok((facts, interval)) => {
                if let Some(stopped) = stop(&facts) {
                    return stopped;
                }
                interval.unwrap_or(SETUP_GUARD_INTERVAL)
            }
            Err(_) => SETUP_GUARD_INTERVAL,
        };
        tokio::time::sleep(interval.max(SETUP_GUARD_INTERVAL)).await;
    }
}

/// What the daemon wait last saw, for a timeout to report.
#[derive(Debug)]
pub enum DaemonObservation {
    Starting,
    StatusFailed(ClientError),
    /// The status answer carried none.
    NoStatus,
    /// The environment is in this state, not yet `running`.
    Environment(String),
}

#[derive(Debug)]
pub enum DaemonWaitError {
    GetEnvironment(GetEnvironmentError),
    PlatformEnded(Box<EnvironmentFacts>, PlatformEnd),
    /// The daemon reported a state it cannot become ready from.
    Unusable {
        state: String,
        message: String,
    },
    /// The environment reached this state, which ends the wait.
    Left(String),
    DaemonTimeout(DaemonObservation),
    LifecycleTimeout(DaemonObservation),
}

/// Waits until the environment runs and its workspace daemon reports ready.
pub async fn await_daemon_ready(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> Result<(), DaemonWaitError> {
    let lifecycle_started = Instant::now();
    let mut lifecycle_timeout = READY_TIMEOUT;
    let mut daemon_started = None;
    loop {
        let (facts, interval) = get_environment_facts(client, org_id, environment_id)
            .await
            .map_err(DaemonWaitError::GetEnvironment)?;
        lifecycle_timeout = lifecycle_timeout.max(lifecycle_ready_timeout(facts.confidential));
        if let Some(end) = facts.platform_end() {
            return Err(DaemonWaitError::PlatformEnded(Box::new(facts), end));
        }
        let observation = match facts.state.as_str() {
            "running" => {
                daemon_started.get_or_insert_with(Instant::now);
                match daemon_status(client, org_id, environment_id).await {
                    Ok((state, message)) => match state {
                        "ready" => return Ok(()),
                        "starting" | "" => DaemonObservation::Starting,
                        state => {
                            return Err(DaemonWaitError::Unusable {
                                state: state.to_owned(),
                                message,
                            });
                        }
                    },
                    Err(observation) => observation,
                }
            }
            "destroyed" | "destroying" | "failed" | "error" => {
                return Err(DaemonWaitError::Left(facts.state));
            }
            _ => DaemonObservation::Environment(facts.state),
        };
        if daemon_started.is_some_and(|started: Instant| started.elapsed() >= DAEMON_READY_TIMEOUT)
        {
            return Err(DaemonWaitError::DaemonTimeout(observation));
        }
        if daemon_started.is_none() && lifecycle_started.elapsed() >= lifecycle_timeout {
            return Err(DaemonWaitError::LifecycleTimeout(observation));
        }
        tokio::time::sleep(ready_poll(interval)).await;
    }
}

/// The daemon's state token and message.
async fn daemon_status(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> Result<(&'static str, String), DaemonObservation> {
    let response = client
        .get_environment_daemon_status(GetEnvironmentDaemonStatusRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(DaemonObservation::StatusFailed)?;
    let status = response
        .status
        .into_option()
        .ok_or(DaemonObservation::NoStatus)?;
    Ok((daemon_state_token(&status.state), status.message))
}

fn std_duration(duration: ProtoDuration) -> Option<Duration> {
    let seconds = u64::try_from(duration.seconds).ok()?;
    let nanos = u32::try_from(duration.nanos).ok()?;
    let duration = Duration::new(seconds, nanos);
    (!duration.is_zero()).then_some(duration)
}

/// A [`SetupObserver`] that also shows the wait for the workspace daemon.
pub trait SetupWaitObserver: SetupObserver {
    /// Setup is complete and the wait for the daemon begins.
    fn daemon_waiting(&mut self, now: Instant) -> Result<(), Self::Error>;
    /// The daemon is ready.
    fn daemon_ready(&mut self, now: Instant) -> Result<(), Self::Error>;
}

/// How a setup wait ended.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupEnd<F> {
    /// Setup finished and the daemon is ready.
    Ready,
    /// The observer ended the follow on a row, such as a `failed` one.
    Failed(F),
}

#[derive(Debug)]
pub enum SetupWaitError<O, G, D> {
    Follow(FollowError<O>),
    /// The guard said setup can no longer finish.
    Stopped(G),
    /// The `daemon_ready` row reported a daemon that cannot become ready.
    DaemonRow(DaemonReadyRow),
    Daemon(D),
    Observer(O),
}

/// Follows setup through `complete`, ending early when `guard` resolves,
/// then waits for the daemon: setup's own `daemon_ready` row decides when it
/// says ready or unusable, and only a daemon still starting, or a server that
/// wrote no such row, is waited for with `daemon_ready` (#3684).
pub async fn await_setup<F, O, G, D, R, E>(
    feed: &F,
    observer: &mut O,
    policy: &FollowPolicy,
    guard: G,
    daemon_ready: D,
) -> Result<SetupEnd<O::Failure>, SetupWaitError<O::Error, G::Output, E>>
where
    F: EnvironmentLogFeed,
    O: SetupWaitObserver,
    G: Future,
    D: FnOnce() -> R,
    R: Future<Output = Result<(), E>>,
{
    let mut watch = DaemonRowWatch {
        inner: observer,
        daemon: None,
    };
    let mut cursor = None;
    let followed = tokio::select! {
        biased;
        end = follow_setup(feed, &mut watch, &mut cursor, policy) => end.map_err(SetupWaitError::Follow),
        stopped = guard => Err(SetupWaitError::Stopped(stopped)),
    };
    if let FollowEnd::Failed(failure) = followed? {
        return Ok(SetupEnd::Failed(failure));
    }
    let DaemonRowWatch {
        inner: observer,
        daemon,
    } = watch;
    if let Some(row) = daemon {
        match &row.state {
            DaemonState::Ready => return Ok(SetupEnd::Ready),
            DaemonState::Starting => {}
            DaemonState::Other(token) if token.is_empty() => {}
            _ => return Err(SetupWaitError::DaemonRow(row)),
        }
    }
    observer
        .daemon_waiting(Instant::now())
        .map_err(SetupWaitError::Observer)?;
    wait_with_ticks(observer, policy.tick, daemon_ready())
        .await
        .map_err(SetupWaitError::Observer)?
        .map_err(SetupWaitError::Daemon)?;
    observer
        .daemon_ready(Instant::now())
        .map_err(SetupWaitError::Observer)?;
    Ok(SetupEnd::Ready)
}

/// Passes every row on and keeps the latest `daemon_ready` row.
struct DaemonRowWatch<'a, O> {
    inner: &'a mut O,
    daemon: Option<DaemonReadyRow>,
}

impl<O: SetupObserver> SetupObserver for DaemonRowWatch<'_, O> {
    type Failure = O::Failure;
    type Error = O::Error;

    fn row(
        &mut self,
        row: &EnvironmentLogRow,
        received: Instant,
    ) -> Result<Option<O::Failure>, O::Error> {
        if let Some(daemon) = daemon_ready_row(row) {
            self.daemon = Some(daemon);
        }
        self.inner.row(row, received)
    }

    fn interrupted(
        &mut self,
        interruption: &Interruption,
        attempt: u32,
        max_reconnects: u32,
    ) -> Result<(), O::Error> {
        self.inner
            .interrupted(interruption, attempt, max_reconnects)
    }

    fn redraw(&mut self, now: Instant) -> Result<(), O::Error> {
        self.inner.redraw(now)
    }

    fn tick_interval(&self) -> Option<Duration> {
        self.inner.tick_interval()
    }
}

#[cfg(test)]
mod tests;
