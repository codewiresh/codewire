//! The follower: one `StreamLogs` connection at a time, resumed strictly
//! after the last row handed on whenever a connection fails, closes early or
//! stops sending heartbeats, within a bounded reconnect budget.

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use super::{EnvironmentLogRow, EnvironmentLogStreamEvent, EnvironmentLogStreamFailure};
use super::{LogStreamError, LogStreamRecovery};
use crate::CodewireClient;

/// The server sends a heartbeat every 15 seconds; three missed heartbeats
/// mean the connection is gone even when the transport has not noticed.
const LOG_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Consecutive failed connections before giving up. Any row or heartbeat
/// resets the count.
const LOG_STREAM_MAX_RECONNECTS: u32 = 5;
const LOG_STREAM_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const LOG_STREAM_MAX_BACKOFF: Duration = Duration::from_secs(8);
/// The slowest an observer is asked to redraw; its own pace may be faster.
const LIVE_TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub struct FollowPolicy {
    pub idle_timeout: Duration,
    pub max_reconnects: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub tick: Duration,
}

impl Default for FollowPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: LOG_STREAM_IDLE_TIMEOUT,
            max_reconnects: LOG_STREAM_MAX_RECONNECTS,
            initial_backoff: LOG_STREAM_INITIAL_BACKOFF,
            max_backoff: LOG_STREAM_MAX_BACKOFF,
            tick: LIVE_TICK,
        }
    }
}

impl FollowPolicy {
    /// The wait before reconnect attempt `attempt` (1-based): doubling from
    /// the initial backoff, never above the maximum.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.saturating_sub(1).min(16);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

/// One item received on a log feed connection. A closed channel means the
/// server ended the stream.
pub enum LogFeedEvent {
    Log(EnvironmentLogRow),
    Heartbeat,
    Failed(EnvironmentLogStreamFailure),
}

/// One open follow connection. Dropping it stops the connection.
pub struct LogFeedConnection {
    events: mpsc::UnboundedReceiver<LogFeedEvent>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LogFeedConnection {
    pub fn new(
        events: mpsc::UnboundedReceiver<LogFeedEvent>,
        task: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self { events, task }
    }

    async fn next(&mut self) -> Option<LogFeedEvent> {
        self.events.recv().await
    }
}

impl Drop for LogFeedConnection {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Opens following log connections that resume strictly after a row id.
pub trait EnvironmentLogFeed {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection;
}

/// The platform's `StreamLogs` for one environment.
pub struct PlatformLogFeed {
    client: CodewireClient,
    org_id: String,
    environment_id: String,
}

impl PlatformLogFeed {
    pub fn new(
        client: CodewireClient,
        org_id: impl Into<String>,
        environment_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            org_id: org_id.into(),
            environment_id: environment_id.into(),
        }
    }
}

impl EnvironmentLogFeed for PlatformLogFeed {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection {
        let (sender, events) = mpsc::unbounded_channel();
        let client = self.client.clone();
        let org_id = self.org_id.clone();
        let environment_id = self.environment_id.clone();
        let task = tokio::spawn(async move {
            let result = client
                .follow_environment_log_stream(
                    &org_id,
                    &environment_id,
                    after_log_id.as_deref(),
                    |event| {
                        let event = match event {
                            EnvironmentLogStreamEvent::Log(log) => LogFeedEvent::Log(log),
                            EnvironmentLogStreamEvent::Heartbeat => LogFeedEvent::Heartbeat,
                        };
                        sender.send(event).is_ok()
                    },
                )
                .await;
            if let Err(failure) = result {
                // The follower may already have dropped this connection; then
                // nobody is left to tell.
                let _ = sender.send(LogFeedEvent::Failed(failure));
            }
        });
        LogFeedConnection::new(events, Some(task))
    }
}

/// Why a connection was given up and resumed.
#[derive(Debug)]
pub enum Interruption {
    /// The connection failed with this error.
    Stream(LogStreamError),
    /// The server closed the stream before setup finished.
    Closed,
    /// No row or heartbeat arrived for this long.
    Silent(Duration),
}

/// How a followed log stream ended.
#[derive(Debug, PartialEq, Eq)]
pub enum FollowEnd<F> {
    /// The `complete` row arrived: setup finished.
    Complete,
    /// The observer ended the follow on a row, such as a `failed` one.
    Failed(F),
}

/// Why following stopped without an end.
#[derive(Debug)]
pub enum FollowError<E> {
    /// Reconnecting cannot help.
    Fatal(LogStreamError),
    /// Every reconnect in the budget failed; `last` is the final reason.
    Lost {
        max_reconnects: u32,
        last: Interruption,
    },
    /// The observer failed.
    Observer(E),
}

/// What a follow reports to whoever shows it.
pub trait SetupObserver {
    /// What ends a follow on a row, such as a `failed` row's stage.
    type Failure;
    type Error;

    /// Takes one row, received at `received`. `Some` ends the follow with
    /// [`FollowEnd::Failed`].
    fn row(
        &mut self,
        row: &EnvironmentLogRow,
        received: Instant,
    ) -> Result<Option<Self::Failure>, Self::Error>;

    /// A connection was given up for `interruption`; reconnect `attempt` of
    /// `max_reconnects` follows after a backoff.
    fn interrupted(
        &mut self,
        interruption: &Interruption,
        attempt: u32,
        max_reconnects: u32,
    ) -> Result<(), Self::Error>;

    /// Moves anything time-based the observer shows.
    fn redraw(&mut self, now: Instant) -> Result<(), Self::Error>;

    /// How often [`SetupObserver::redraw`] should run: `None` when nothing
    /// shown moves.
    fn tick_interval(&self) -> Option<Duration>;
}

/// Follows the log feed until the `complete` row or a row the observer ends
/// on, resuming after `cursor` on every reconnect. `cursor` tracks the last
/// row handed to the observer.
pub async fn follow_setup<F, O>(
    feed: &F,
    observer: &mut O,
    cursor: &mut Option<String>,
    policy: &FollowPolicy,
) -> Result<FollowEnd<O::Failure>, FollowError<O::Error>>
where
    F: EnvironmentLogFeed,
    O: SetupObserver,
{
    let mut failures = 0u32;
    loop {
        let mut connection = feed.open(cursor.clone());
        let idle = tokio::time::sleep(policy.idle_timeout);
        tokio::pin!(idle);
        observer
            .redraw(Instant::now())
            .map_err(FollowError::Observer)?;
        let tick = observer.tick_interval().map(|tick| tick.min(policy.tick));
        let mut ticker = tokio::time::interval(tick.unwrap_or(policy.tick));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut healthy = false;
        let reason = loop {
            tokio::select! {
                event = connection.next() => match event {
                    Some(LogFeedEvent::Log(log)) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + policy.idle_timeout);
                        healthy = true;
                        failures = 0;
                        *cursor = Some(log.id.clone());
                        if let Some(failure) = observer
                            .row(&log, Instant::now())
                            .map_err(FollowError::Observer)?
                        {
                            return Ok(FollowEnd::Failed(failure));
                        }
                        if log.phase == "complete" {
                            return Ok(FollowEnd::Complete);
                        }
                    }
                    Some(LogFeedEvent::Heartbeat) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + policy.idle_timeout);
                        healthy = true;
                        failures = 0;
                    }
                    Some(LogFeedEvent::Failed(failure)) => match failure.recovery {
                        LogStreamRecovery::Fatal => {
                            return Err(FollowError::Fatal(failure.error));
                        }
                        // The call deadline rotated a connection that was
                        // delivering heartbeats: resume without a notice.
                        LogStreamRecovery::Resume if healthy => break None,
                        LogStreamRecovery::Resume | LogStreamRecovery::Retry => {
                            break Some(Interruption::Stream(failure.error));
                        }
                    },
                    None => break Some(Interruption::Closed),
                },
                () = &mut idle => break Some(Interruption::Silent(policy.idle_timeout)),
                _ = ticker.tick(), if tick.is_some() => {
                    observer.redraw(Instant::now()).map_err(FollowError::Observer)?;
                }
            }
        };
        drop(connection);
        let Some(reason) = reason else {
            continue;
        };
        failures += 1;
        if failures > policy.max_reconnects {
            return Err(FollowError::Lost {
                max_reconnects: policy.max_reconnects,
                last: reason,
            });
        }
        observer
            .interrupted(&reason, failures, policy.max_reconnects)
            .map_err(FollowError::Observer)?;
        wait_with_ticks(
            observer,
            policy.tick,
            tokio::time::sleep(policy.backoff(failures)),
        )
        .await
        .map_err(FollowError::Observer)?;
    }
}

/// Awaits `future`, redrawing meanwhile at the observer's pace, and at least
/// every `max_tick`.
pub async fn wait_with_ticks<O, T>(
    observer: &mut O,
    max_tick: Duration,
    future: impl Future<Output = T>,
) -> Result<T, O::Error>
where
    O: SetupObserver,
{
    tokio::pin!(future);
    observer.redraw(Instant::now())?;
    let Some(tick) = observer.tick_interval() else {
        return Ok(future.await);
    };
    let mut ticker = tokio::time::interval(tick.min(max_tick));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = ticker.tick() => observer.redraw(Instant::now())?,
        }
    }
}
