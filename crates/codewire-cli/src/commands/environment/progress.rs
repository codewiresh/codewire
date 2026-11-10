//! Start progress for a cloud environment's `cw create`, `cw start` and
//! `cw logs ENV --setup --follow`.
//!
//! Stages come from `environment_logs` rows delivered by `StreamLogs`. The
//! follower resumes after the last row it rendered when a connection drops or
//! stops sending heartbeats, so a reconnect neither repeats nor skips a row.
//! Rows are drawn through the shared [`StatusLine`]: one live row with the
//! rotating spinner for the newest open stage on a terminal, one plain line
//! per row when redirected, and nothing for machine output. Each finished
//! stage shows its elapsed time, taken from the row's `duration_ms` metadata
//! when present and otherwise from the server `created_at` of its `started`
//! and final rows.
//!
//! # Clone progress rows (Program #2238, A5a contract, version 1)
//!
//! Orchestration reports repository clone progress as ordinary
//! `environment_logs` rows. Readers (this CLI and the dashboard) rely only on
//! the fields below and ignore every other metadata key.
//!
//! - A `progress` row is transient telemetry for a stage that is running:
//!   - `phase`: the running stage, `git_clone` for repository clones.
//!   - `status`: `progress`.
//!   - `message`: a label. The server fills the phase label when it is empty.
//!     It never carries raw tool output.
//!   - `metadata`, numbers and fixed tokens only:
//!     - `repo_index`: integer, the 1-based position of the repository in the
//!       environment's repository list.
//!     - `repo_count`: integer, the number of repositories being cloned.
//!     - `stage`: a lowercase snake_case token naming the Git stage, such as
//!       `counting_objects`, `compressing_objects`, `receiving_objects`,
//!       `resolving_deltas` or `updating_files`.
//!     - `percent`: integer from 0 to 100, within that stage.
//! - Each field is optional to a reader, which renders what is present.
//! - A `progress` row is never terminal and never a lifecycle checkpoint.
//! - Per-repository `git_clone` `started`, `completed` and `failed` rows may
//!   carry the same `repo_index` and `repo_count`. They nest under the
//!   phase-level `git_clone` rows, which carry neither.
//!
//! The fixture `tests/fixtures/environment-log-clone-progress-v1.json` in this
//! crate is the reference stream for this contract.
//!
//! # The daemon status setup read (#3684)
//!
//! Setup reads the workspace daemon's status in-cluster beside its health
//! check and reports it, before `complete`, as one row:
//!
//! - `phase`: `daemon_ready`; `status`: `completed`.
//! - `metadata.state`: the state token `cw daemon status` prints (`ready`,
//!   `starting`, `upgrade_required`, `unsupported`, `unhealthy`,
//!   `unspecified`); `metadata.message`: the daemon's message.
//!
//! `cw create` judges it with the rule it applies to the API's answer:
//! `ready` ends the create at `complete`, and a refused state fails it with
//! the same message. A daemon still starting, or a server that writes no such
//! row, is asked through the API as before. That fallback exists for version
//! skew and goes once Production writes the row (#3705).

use std::future::Future;
use std::io::Write;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use std::sync::{Arc, Mutex};

use crate::environment_client::{
    EnvironmentClient, EnvironmentLogStreamEvent, EnvironmentLogStreamFailure, LogStreamRecovery,
};
use crate::output::{Capabilities, Motion, OutputMode, Status, StatusLine};
use crate::presentation::{Environment, EnvironmentDaemonStatus, EnvironmentLog};

/// The server sends a heartbeat every 15 seconds; three missed heartbeats
/// mean the connection is gone even when the transport has not noticed.
const LOG_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Consecutive failed connections before giving up. Any row or heartbeat
/// resets the count.
const LOG_STREAM_MAX_RECONNECTS: u32 = 5;
const LOG_STREAM_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const LOG_STREAM_MAX_BACKOFF: Duration = Duration::from_secs(8);
/// The slowest the live row redraws; the spinner sets the actual pace.
const LIVE_TICK: Duration = Duration::from_secs(1);
const SETUP_GUARD_INTERVAL: Duration = Duration::from_secs(5);
const DAEMON_STAGE_KEY: &str = "cli:daemon_ready";
const DAEMON_WAIT_LABEL: &str = "Waiting for the workspace daemon";
const DAEMON_READY_LABEL: &str = "Workspace daemon ready";

#[derive(Clone, Copy, Debug)]
pub(crate) struct FollowPolicy {
    pub(crate) idle_timeout: Duration,
    pub(crate) max_reconnects: u32,
    pub(crate) initial_backoff: Duration,
    pub(crate) max_backoff: Duration,
    pub(crate) tick: Duration,
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
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.saturating_sub(1).min(16);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

/// One item received on a log feed connection. A closed channel means the
/// server ended the stream.
pub(crate) enum LogFeedEvent {
    Log(EnvironmentLog),
    Heartbeat,
    Failed(EnvironmentLogStreamFailure),
}

/// One open follow connection. Dropping it stops the connection.
pub(crate) struct LogFeedConnection {
    events: mpsc::UnboundedReceiver<LogFeedEvent>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LogFeedConnection {
    pub(crate) fn new(
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
pub(crate) trait EnvironmentLogFeed {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection;
}

pub(crate) struct PlatformLogFeed<'a> {
    pub(crate) client: &'a EnvironmentClient,
    pub(crate) org_id: &'a str,
    pub(crate) environment_id: &'a str,
}

impl EnvironmentLogFeed for PlatformLogFeed<'_> {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection {
        let (sender, events) = mpsc::unbounded_channel();
        let client = self.client.clone();
        let org_id = self.org_id.to_owned();
        let environment_id = self.environment_id.to_owned();
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
                let _ = sender.send(LogFeedEvent::Failed(failure));
            }
        });
        LogFeedConnection::new(events, Some(task))
    }
}

/// How a followed log stream ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FollowEnd {
    /// The `complete` row arrived: setup finished.
    Complete,
    /// A `failed` row arrived.
    Failed(StageFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StageFailure {
    pub(crate) phase: String,
    /// The label of the stage that failed, from its `started` row.
    pub(crate) stage: String,
    pub(crate) message: String,
}

impl StageFailure {
    pub(crate) fn into_error(self, environment_id: &str) -> anyhow::Error {
        let detail = if self.message.is_empty() || self.message == self.stage {
            String::new()
        } else {
            format!(": {}", self.message)
        };
        anyhow::anyhow!(
            "environment {environment_id} failed at stage {:?}{detail} (see `cw logs {environment_id} --setup`)",
            self.stage
        )
    }
}

struct OpenStage {
    key: String,
    label: String,
    /// Indent depth: 0 for a phase, 1 for a per-repository stage.
    depth: usize,
    started_at: Option<DateTime<Utc>>,
    /// Local instant the stage was first seen; the live row ticks from it so
    /// a skewed local clock cannot distort it.
    anchor: Instant,
    detail: Option<String>,
}

/// A writer whose bytes stay readable after the progress view that wrote
/// them, for rendering rows into a string.
#[derive(Clone, Default)]
pub(crate) struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

impl CapturedOutput {
    pub(crate) fn text(&self) -> String {
        let bytes = self.0.lock().map(|bytes| bytes.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Write for CapturedOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("captured output lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Renders environment log rows as start progress through the shared
/// [`StatusLine`]: one live row for the newest open stage on a terminal,
/// plain lines when redirected, nothing for machine output.
pub(crate) struct StartProgress<W: Write> {
    status: StatusLine<W>,
    /// The time the status line reads; set from each call's `now`, so the
    /// stage clocks follow the instants the caller observed.
    now: Arc<Mutex<Instant>>,
    live: bool,
    began: Instant,
    idle_label: &'static str,
    open: Vec<OpenStage>,
    /// The Pod whose start timing rows are on screen, so their header is
    /// drawn once per Pod.
    pod_breakdown: Option<String>,
    /// The daemon status setup read in-cluster: its latest `daemon_ready` row.
    daemon: Option<EnvironmentDaemonStatus>,
}

impl<W: Write> StartProgress<W> {
    /// Progress drawn as `caps` allows: a live row on a terminal, one plain
    /// line per row elsewhere, nothing in machine mode.
    pub(crate) fn new(
        out: W,
        caps: &Capabilities,
        began: Instant,
        idle_label: &'static str,
    ) -> Self {
        let now = Arc::new(Mutex::new(began));
        let clock = Arc::clone(&now);
        Self {
            status: StatusLine::with_clock(out, caps, move || {
                clock
                    .lock()
                    .map(|now| *now)
                    .unwrap_or_else(|_| Instant::now())
            }),
            now,
            live: caps.live && !caps.is_machine(),
            began,
            idle_label,
            open: Vec::new(),
            pod_breakdown: None,
            daemon: None,
        }
    }

    /// How often [`StartProgress::redraw`] should run: `None` when nothing
    /// on screen moves.
    pub(crate) fn tick_interval(&self) -> Option<Duration> {
        self.status.tick_interval()
    }

    /// Renders one row. Returns the failure when the row is a `failed` row.
    pub(crate) fn apply(
        &mut self,
        event: &EnvironmentLog,
        received: Instant,
    ) -> std::io::Result<Option<StageFailure>> {
        self.set_now(received);
        if let Some(daemon) = daemon_ready_status(event) {
            self.daemon = Some(daemon);
        }
        let repo = repository_scope(event.metadata.as_ref());
        let key = stage_key(&event.phase, repo);
        let pod_timing = pod_timing_uid(event);
        let depth = if pod_timing.is_some() {
            pod_timing_depth(&event.phase)
        } else {
            usize::from(repo.is_some())
        };
        let label = display_label(event);
        let mut failure = None;
        // Pod start timing is measured after access is ready, and its time
        // is part of "SSH access ready", so it sits under a header of its
        // own instead of reading as further stages.
        if let Some(pod_uid) = pod_timing
            && self.pod_breakdown.as_deref() != Some(pod_uid)
        {
            self.pod_breakdown = Some(pod_uid.to_owned());
            self.status
                .record(0, None, pod_breakdown_header(event), None)?;
        }
        match event.status.as_str() {
            "started" => {
                if !self.live {
                    self.status
                        .record(depth, Some(Status::Active), &label, None)?;
                }
                self.open.retain(|stage| stage.key != key);
                self.open.push(OpenStage {
                    key,
                    label,
                    depth,
                    started_at: parse_log_time(&event.created_at),
                    anchor: received,
                    detail: None,
                });
            }
            "progress" => {
                let position = self.progress_stage(&key, &event.phase);
                let nested = position.is_some_and(|index| self.open[index].depth > 0);
                let detail =
                    format_clone_progress(event.metadata.as_ref(), !nested).or_else(|| {
                        let message = terminal_text(&event.message);
                        (!message.is_empty() && message != label).then_some(message)
                    });
                let stage_label =
                    position.map_or_else(|| label.clone(), |index| self.open[index].label.clone());
                if self.live {
                    let index = match position {
                        Some(index) => index,
                        None => {
                            self.open.push(OpenStage {
                                key,
                                label: stage_label,
                                depth,
                                started_at: parse_log_time(&event.created_at),
                                anchor: received,
                                detail: None,
                            });
                            self.open.len() - 1
                        }
                    };
                    self.open[index].detail = detail;
                } else {
                    // Progress lines always sit under the stage they report on.
                    let text = match detail {
                        Some(detail) => format!("{stage_label}: {detail}"),
                        None => stage_label,
                    };
                    self.status.record(1, None, &text, None)?;
                }
            }
            "completed" | "warning" | "failed" => {
                let stage = self
                    .open
                    .iter()
                    .rposition(|stage| stage.key == key)
                    .map(|index| self.open.remove(index));
                let elapsed = stage_elapsed(event, stage.as_ref());
                let stage_label = stage.as_ref().map(|stage| stage.label.clone());
                let message = terminal_text(&event.message);
                match event.status.as_str() {
                    "completed" => {
                        self.status.record(
                            depth,
                            Some(Status::Done),
                            &label,
                            elapsed.as_deref(),
                        )?;
                    }
                    "warning" => {
                        let text = labelled(stage_label.as_deref(), &message, &label);
                        self.status.record(
                            depth,
                            Some(Status::Attention),
                            &text,
                            elapsed.as_deref(),
                        )?;
                    }
                    _ => {
                        let text = labelled(stage_label.as_deref(), &message, &label);
                        self.status.record(
                            depth,
                            Some(Status::Failed),
                            &text,
                            elapsed.as_deref(),
                        )?;
                        failure = Some(StageFailure {
                            phase: event.phase.clone(),
                            stage: stage_label.unwrap_or_else(|| humanize_phase(&event.phase)),
                            message,
                        });
                    }
                }
            }
            _ => self.status.record(depth, None, &label, None)?,
        }
        if event.phase == "complete" {
            self.open.retain(|stage| stage.key.starts_with("cli:"));
        }
        self.refresh()?;
        Ok(failure)
    }

    /// Opens a stage the CLI itself waits on, such as daemon readiness.
    pub(crate) fn begin_local_stage(
        &mut self,
        key: &str,
        label: &str,
        now: Instant,
    ) -> std::io::Result<()> {
        self.set_now(now);
        if !self.live {
            self.status.record(0, Some(Status::Active), label, None)?;
        }
        self.open.retain(|stage| stage.key != key);
        self.open.push(OpenStage {
            key: key.to_owned(),
            label: label.to_owned(),
            depth: 0,
            started_at: None,
            anchor: now,
            detail: None,
        });
        self.refresh()
    }

    pub(crate) fn complete_local_stage(
        &mut self,
        key: &str,
        label: &str,
        now: Instant,
    ) -> std::io::Result<()> {
        self.set_now(now);
        let elapsed = self
            .open
            .iter()
            .rposition(|stage| stage.key == key)
            .map(|index| self.open.remove(index))
            .map(|stage| format_duration(now.saturating_duration_since(stage.anchor), true));
        self.status
            .record(0, Some(Status::Done), label, elapsed.as_deref())?;
        self.refresh()
    }

    /// Ends the open stage `key`, or the newest one, with a failure line
    /// naming it, when the outcome came from outside the log rows (a lost
    /// stream, a setup guard or an unready daemon). Returns its label.
    pub(crate) fn fail_open_stage(
        &mut self,
        key: Option<&str>,
        now: Instant,
    ) -> std::io::Result<Option<String>> {
        self.set_now(now);
        let position = match key {
            Some(key) => self.open.iter().rposition(|stage| stage.key == key),
            None => self.open.len().checked_sub(1),
        };
        let Some(stage) = position.map(|index| self.open.remove(index)) else {
            return Ok(None);
        };
        let elapsed = format_duration(now.saturating_duration_since(stage.anchor), true);
        self.status.record(
            stage.depth,
            Some(Status::Failed),
            &stage.label,
            Some(&elapsed),
        )?;
        self.refresh()?;
        Ok(Some(stage.label))
    }

    /// Writes a permanent notice line.
    pub(crate) fn note(&mut self, text: &str) -> std::io::Result<()> {
        self.set_now(Instant::now());
        self.status.record(0, Some(Status::Attention), text, None)
    }

    /// Draws the live row, advancing its spinner and elapsed time. Plain
    /// output has no live row.
    pub(crate) fn redraw(&mut self, now: Instant) -> std::io::Result<()> {
        self.set_now(now);
        self.refresh()
    }

    /// Removes the live row so later output starts on a clean line.
    pub(crate) fn finish(&mut self) -> std::io::Result<()> {
        self.status.clear()
    }

    fn set_now(&self, now: Instant) {
        if let Ok(mut current) = self.now.lock() {
            *current = now;
        }
    }

    /// Shows the newest open stage, or the idle label, on the live row.
    fn refresh(&mut self) -> std::io::Result<()> {
        if !self.live {
            return Ok(());
        }
        match self.open.last() {
            Some(stage) => self
                .status
                .show(&stage.label, stage.detail.as_deref(), stage.anchor),
            None => self.status.show(self.idle_label, None, self.began),
        }
    }

    fn progress_stage(&self, key: &str, phase: &str) -> Option<usize> {
        self.open
            .iter()
            .rposition(|stage| stage.key == key)
            .or_else(|| self.open.iter().rposition(|stage| stage.key == phase))
    }
}

/// Follows the log feed until the `complete` row or a `failed` row, resuming
/// after `cursor` on every reconnect. `cursor` tracks the last rendered row.
pub(crate) async fn follow_start_progress<F, W>(
    feed: &F,
    view: &mut StartProgress<W>,
    cursor: &mut Option<String>,
    policy: &FollowPolicy,
) -> anyhow::Result<FollowEnd>
where
    F: EnvironmentLogFeed,
    W: Write,
{
    let mut failures = 0u32;
    loop {
        let mut connection = feed.open(cursor.clone());
        let idle = tokio::time::sleep(policy.idle_timeout);
        tokio::pin!(idle);
        view.redraw(Instant::now())?;
        let tick = view.tick_interval().map(|tick| tick.min(policy.tick));
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
                        if let Some(failure) = view.apply(&log, Instant::now())? {
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
                            return Err(failure.error.context("follow environment logs"));
                        }
                        // The call deadline rotated a connection that was
                        // delivering heartbeats: resume without a notice.
                        LogStreamRecovery::Resume if healthy => break None,
                        LogStreamRecovery::Resume | LogStreamRecovery::Retry => {
                            break Some(format!("{:#}", failure.error));
                        }
                    },
                    None => break Some("the stream closed before setup finished".to_owned()),
                },
                () = &mut idle => {
                    break Some(format!(
                        "no heartbeat for {}",
                        format_duration(policy.idle_timeout, false)
                    ));
                }
                _ = ticker.tick(), if tick.is_some() => view.redraw(Instant::now())?,
            }
        };
        drop(connection);
        let Some(reason) = reason else {
            continue;
        };
        failures += 1;
        if failures > policy.max_reconnects {
            anyhow::bail!(
                "lost the environment log stream after {} reconnect attempts: {reason}",
                policy.max_reconnects
            );
        }
        view.note(&format!(
            "Log stream interrupted ({reason}); resuming, attempt {failures} of {}",
            policy.max_reconnects
        ))?;
        wait_with_ticks(
            view,
            policy.tick,
            tokio::time::sleep(policy.backoff(failures)),
        )
        .await?;
    }
}

/// Awaits `future`, redrawing the live row meanwhile at the spinner's pace,
/// and at least every `max_tick`.
pub(crate) async fn wait_with_ticks<W, T>(
    view: &mut StartProgress<W>,
    max_tick: Duration,
    future: impl Future<Output = T>,
) -> anyhow::Result<T>
where
    W: Write,
{
    tokio::pin!(future);
    view.redraw(Instant::now())?;
    let Some(tick) = view.tick_interval() else {
        return Ok(future.await);
    };
    let mut ticker = tokio::time::interval(tick.min(max_tick));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = ticker.tick() => view.redraw(Instant::now())?,
        }
    }
}

/// `cw create`: every setup stage through `complete`, then daemon
/// readiness. Fails on a `failed` row or when `setup_guard` reports that the
/// environment can no longer finish setup.
pub(crate) async fn await_environment_setup<F, W, D, R>(
    feed: &F,
    view: &mut StartProgress<W>,
    policy: &FollowPolicy,
    environment_id: &str,
    setup_guard: impl Future<Output = anyhow::Error>,
    daemon_ready: D,
) -> anyhow::Result<()>
where
    F: EnvironmentLogFeed,
    W: Write,
    D: FnOnce() -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let mut cursor = None;
    let followed = {
        let follow = follow_start_progress(feed, view, &mut cursor, policy);
        tokio::select! {
            biased;
            end = follow => end,
            error = setup_guard => Err(error),
        }
    };
    match followed {
        Ok(FollowEnd::Complete) => {}
        Ok(FollowEnd::Failed(failure)) => {
            view.finish()?;
            return Err(failure.into_error(environment_id));
        }
        Err(error) => {
            let stage = view.fail_open_stage(None, Instant::now())?;
            view.finish()?;
            return Err(stage_error(error, stage));
        }
    }
    // Setup read the daemon's status in-cluster (#3684): the same rule as the
    // API's answer decides, and only a daemon still starting, or a server
    // that wrote no row, is asked again.
    if let Some(daemon) = view.daemon.clone() {
        match super::environment_daemon_readiness(&daemon) {
            Ok(true) => {
                view.finish()?;
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => {
                view.finish()?;
                return Err(error);
            }
        }
    }
    await_daemon_ready(view, policy, daemon_ready()).await
}

/// The daemon status in a setup `daemon_ready` row (#3684), whose metadata
/// carries the CLI's state token and the daemon's message.
fn daemon_ready_status(event: &EnvironmentLog) -> Option<EnvironmentDaemonStatus> {
    if event.phase != "daemon_ready" {
        return None;
    }
    let metadata = event.metadata.as_ref()?;
    let state = metadata.get("state")?.as_str()?;
    Some(EnvironmentDaemonStatus {
        state: state.to_owned(),
        message: metadata
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or_default()
            .to_owned(),
        ..Default::default()
    })
}

/// `cw start`: shows the rows the start produces after `cursor` while
/// waiting for daemon readiness. Fails on a `failed` row. With a
/// `start_guard`, the start also waits for its `complete` row, written once
/// the startup script has finished, and fails when the guard reports that the
/// environment left the start (#3938). Losing the log stream only loses the
/// display; readiness still decides the outcome.
pub(crate) async fn await_environment_start<F, W>(
    feed: &F,
    view: &mut StartProgress<W>,
    policy: &FollowPolicy,
    environment_id: &str,
    cursor: Option<String>,
    start_guard: Option<impl Future<Output = anyhow::Error>>,
    daemon_ready: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()>
where
    F: EnvironmentLogFeed,
    W: Write,
{
    enum Ended {
        Followed(anyhow::Result<FollowEnd>),
        Left(anyhow::Error),
        Ready,
    }
    view.begin_local_stage(DAEMON_STAGE_KEY, DAEMON_WAIT_LABEL, Instant::now())?;
    let until_complete = start_guard.is_some();
    let start_guard = async move {
        match start_guard {
            Some(guard) => guard.await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(daemon_ready);
    tokio::pin!(start_guard);
    let mut cursor = cursor;
    let mut daemon = None;
    let ended = {
        let follow = follow_start_progress(feed, view, &mut cursor, policy);
        tokio::pin!(follow);
        loop {
            tokio::select! {
                biased;
                end = &mut follow => break Ended::Followed(end),
                error = &mut start_guard => break Ended::Left(error),
                ready = &mut daemon_ready, if daemon.is_none() => {
                    let failed = ready.is_err();
                    daemon = Some(ready);
                    // A ready daemon ends the wait only for a server whose
                    // start writes no `complete` row.
                    if failed || !until_complete {
                        break Ended::Ready;
                    }
                }
            }
        }
    };
    let ready = match daemon {
        Some(Err(error)) => {
            let stage = view.fail_open_stage(Some(DAEMON_STAGE_KEY), Instant::now())?;
            view.finish()?;
            return Err(stage_error(error, stage));
        }
        Some(Ok(())) => true,
        None => false,
    };
    match ended {
        Ended::Ready => {}
        Ended::Left(error) => {
            let stage = view.fail_open_stage(None, Instant::now())?;
            view.finish()?;
            return Err(stage_error(error, stage));
        }
        Ended::Followed(Ok(FollowEnd::Failed(failure))) => {
            view.finish()?;
            return Err(failure.into_error(environment_id));
        }
        Ended::Followed(Ok(FollowEnd::Complete)) => {
            if !ready {
                finish_daemon_wait(view, policy, &mut daemon_ready).await?;
            }
        }
        Ended::Followed(Err(error)) => {
            view.note(&format!("Start progress is unavailable: {error:#}"))?;
            if !ready {
                finish_daemon_wait(view, policy, &mut daemon_ready).await?;
            }
        }
    }
    view.complete_local_stage(DAEMON_STAGE_KEY, DAEMON_READY_LABEL, Instant::now())?;
    view.finish()?;
    Ok(())
}

async fn finish_daemon_wait<W: Write>(
    view: &mut StartProgress<W>,
    policy: &FollowPolicy,
    daemon_ready: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    if let Err(error) = wait_with_ticks(view, policy.tick, daemon_ready).await? {
        let stage = view.fail_open_stage(Some(DAEMON_STAGE_KEY), Instant::now())?;
        view.finish()?;
        return Err(stage_error(error, stage));
    }
    Ok(())
}

/// A failure that came from outside the log rows names the stage that was
/// running when it happened.
fn stage_error(error: anyhow::Error, stage: Option<String>) -> anyhow::Error {
    match stage {
        Some(stage) => error.context(format!("stopped at stage {stage:?}")),
        None => error,
    }
}

/// Waits for daemon readiness as its own stage.
pub(crate) async fn await_daemon_ready<W: Write>(
    view: &mut StartProgress<W>,
    policy: &FollowPolicy,
    daemon_ready: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    view.begin_local_stage(DAEMON_STAGE_KEY, DAEMON_WAIT_LABEL, Instant::now())?;
    finish_daemon_wait(view, policy, daemon_ready).await?;
    view.complete_local_stage(DAEMON_STAGE_KEY, DAEMON_READY_LABEL, Instant::now())?;
    view.finish()?;
    Ok(())
}

/// Resolves only when the environment can no longer finish setup: it left
/// the start path, or setup recorded an error without a `failed` row.
pub(crate) async fn watch_setup_failure(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Error {
    loop {
        let interval = match client
            .get_environment_with_poll_interval(org_id, environment_id)
            .await
        {
            Ok((environment, interval)) => {
                if let Some(error) = setup_failure(&environment) {
                    return error;
                }
                interval.unwrap_or(SETUP_GUARD_INTERVAL)
            }
            // The log stream reports persistent connection failures itself.
            Err(_) => SETUP_GUARD_INTERVAL,
        };
        tokio::time::sleep(interval.max(SETUP_GUARD_INTERVAL)).await;
    }
}

/// Resolves only when a start can no longer finish: the environment was
/// stopped or removed, or failed, after the start was accepted (#3938).
pub(crate) async fn watch_start_failure(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Error {
    loop {
        let interval = match client
            .get_environment_with_poll_interval(org_id, environment_id)
            .await
        {
            Ok((environment, interval)) => {
                if let Some(error) = start_failure(&environment) {
                    return error;
                }
                interval.unwrap_or(SETUP_GUARD_INTERVAL)
            }
            // The log stream reports persistent connection failures itself.
            Err(_) => SETUP_GUARD_INTERVAL,
        };
        tokio::time::sleep(interval.max(SETUP_GUARD_INTERVAL)).await;
    }
}

/// A start is accepted while the environment is still `stopped`, with
/// `started` desired, so only a change of intent ends it there.
pub(crate) fn start_failure(environment: &Environment) -> Option<anyhow::Error> {
    if let Some(failure) = no_capacity_failure(environment) {
        return Some(failure);
    }
    let left = match environment.state.as_str() {
        "build_failed" | "error" | "failed" | "stopping" | "destroying" | "destroyed" => true,
        "stopped" => environment.desired_state != "started",
        _ => false,
    };
    if !left {
        return None;
    }
    let reason = environment
        .error_reason
        .as_deref()
        .map(terminal_text)
        .filter(|reason| !reason.is_empty())
        .map(|reason| format!(": {reason}"))
        .unwrap_or_default();
    Some(anyhow::anyhow!(
        "environment {} became {} before its start finished{reason}",
        environment.id,
        environment.state
    ))
}

/// The message when the cluster had no room for this environment. It is written
/// for the user, whatever state the environment has reached on the way out.
pub(crate) fn no_capacity_failure(environment: &Environment) -> Option<anyhow::Error> {
    if environment.error_code.as_deref() != Some("no_capacity") {
        return None;
    }
    let message = environment
        .error_reason
        .as_deref()
        .map(terminal_text)
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "No capacity right now. Try again shortly.".to_owned());
    Some(anyhow::anyhow!(message))
}

pub(crate) fn setup_failure(environment: &Environment) -> Option<anyhow::Error> {
    if let Some(failure) = no_capacity_failure(environment) {
        return Some(failure);
    }
    let id = &environment.id;
    match environment.state.as_str() {
        "build_failed" | "error" | "failed" | "stopping" | "stopped" | "destroying"
        | "destroyed" => {
            let reason = environment
                .error_reason
                .as_deref()
                .map(terminal_text)
                .filter(|reason| !reason.is_empty())
                .map(|reason| format!(": {reason}"))
                .unwrap_or_default();
            Some(anyhow::anyhow!(
                "environment {id} became {} before setup completed{reason}",
                environment.state
            ))
        }
        _ => environment
            .setup_error
            .as_deref()
            .map(terminal_text)
            .filter(|error| !error.is_empty())
            .map(|error| {
                anyhow::anyhow!(
                    "environment {id} setup failed: {error} (see `cw logs {id} --setup`)"
                )
            }),
    }
}

/// The id of the newest row, so a follow shows only rows written after it.
pub(crate) fn last_log_id(logs: &[EnvironmentLog]) -> Option<String> {
    logs.last().map(|log| log.id.clone())
}

/// Renders stored rows as plain lines, styled as `caps` allows but never
/// as a live row.
pub(crate) fn format_environment_logs_plain(
    logs: &[EnvironmentLog],
    caps: &Capabilities,
) -> String {
    let now = Instant::now();
    let captured = CapturedOutput::default();
    {
        let mut view = StartProgress::new(captured.clone(), &without_live_row(*caps), now, "");
        for log in logs {
            // Writing to memory cannot fail.
            let _ = view.apply(log, now);
        }
    }
    captured.text()
}

/// The same presentation with one plain line per event instead of a live
/// row.
pub(crate) fn without_live_row(caps: Capabilities) -> Capabilities {
    Capabilities {
        live: false,
        motion: Motion::Off,
        ..caps
    }
}

/// Text-mode progress capabilities of this process: a live row when stderr
/// is a terminal.
pub(crate) fn text_progress_capabilities() -> Capabilities {
    Capabilities::from_process(OutputMode::Text)
}

/// Parsed A5a clone progress metadata. Every field is optional.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CloneProgress {
    pub(crate) repo_index: Option<u64>,
    pub(crate) repo_count: Option<u64>,
    pub(crate) stage: Option<String>,
    pub(crate) percent: Option<u64>,
}

pub(crate) fn parse_clone_progress(metadata: Option<&Value>) -> CloneProgress {
    let field = |name: &str| metadata.and_then(|metadata| metadata.get(name));
    CloneProgress {
        repo_index: field("repo_index").and_then(metadata_count),
        repo_count: field("repo_count").and_then(metadata_count),
        stage: field("stage")
            .and_then(Value::as_str)
            .map(|stage| terminal_text(&stage.replace('_', " ")))
            .filter(|stage| !stage.is_empty())
            .map(|stage| stage.chars().take(40).collect()),
        percent: field("percent")
            .and_then(metadata_count)
            .map(|percent| percent.min(100)),
    }
}

/// `repository 1/2, receiving objects 45%`. The repository position is left
/// out when the row belongs to a per-repository stage that already names it.
pub(crate) fn format_clone_progress(
    metadata: Option<&Value>,
    include_repository: bool,
) -> Option<String> {
    let progress = parse_clone_progress(metadata);
    let repository = match (progress.repo_index, progress.repo_count) {
        _ if !include_repository => None,
        (Some(index), Some(count)) if count > 1 => Some(format!("repository {index}/{count}")),
        (Some(index), None) => Some(format!("repository {index}")),
        _ => None,
    };
    let stage = match (progress.stage, progress.percent) {
        (Some(stage), Some(percent)) => Some(format!("{stage} {percent}%")),
        (Some(stage), None) => Some(stage),
        (None, Some(percent)) => Some(format!("{percent}%")),
        (None, None) => None,
    };
    match (repository, stage) {
        (Some(repository), Some(stage)) => Some(format!("{repository}, {stage}")),
        (Some(text), None) | (None, Some(text)) => Some(text),
        (None, None) => None,
    }
}

/// A non-negative whole number from row metadata. Metadata crosses Connect
/// as `google.protobuf.Struct`, whose numbers are doubles, so `3` arrives as
/// `3.0`.
fn metadata_count(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
            .filter(|number| *number < u64::MAX as f64)
            .map(|number| number as u64)
    })
}

/// `repo_index` when the row is scoped to one repository.
fn repository_scope(metadata: Option<&Value>) -> Option<u64> {
    metadata
        .and_then(|metadata| metadata.get("repo_index"))
        .and_then(metadata_count)
}

/// Heads the Pod start timing rows (`pod_scheduled` and the rest).
/// Heads the Pod start timing rows (`pod_scheduled` and the rest). A warm
/// pool member booted before this create claimed it, so its start is not
/// part of this create's time.
fn pod_breakdown_header(event: &EnvironmentLog) -> &'static str {
    let warm = event
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("start_path"))
        .and_then(Value::as_str)
        == Some("warm");
    if warm {
        "Warm pool member, started before this create:"
    } else {
        "SSH access ready included:"
    }
}

/// The Pod a completed Pod start timing row describes. The server writes
/// these rows after the fact with the Pod's UID in their metadata; no other
/// row carries one.
fn pod_timing_uid(event: &EnvironmentLog) -> Option<&str> {
    if event.status != "completed" || !event.phase.starts_with("pod_") {
        return None;
    }
    event
        .metadata
        .as_ref()?
        .get("pod_uid")?
        .as_str()
        .filter(|uid| !uid.is_empty())
}

/// Where a Pod start timing row sits under the header. The server writes
/// each condition stage before the finer stages that split it, so those
/// parts go one level further in, under their whole.
fn pod_timing_depth(phase: &str) -> usize {
    match phase {
        // Parts of `pod_scheduled`.
        "pod_volume_provisioned" | "pod_volume_bound"
        // Parts of `pod_running`.
        | "pod_sandbox_ready" | "pod_workspace_started" | "pod_dind_started" => 2,
        _ => 1,
    }
}

fn stage_key(phase: &str, repository: Option<u64>) -> String {
    match repository {
        Some(index) => format!("{phase}#{index}"),
        None => phase.to_owned(),
    }
}

/// The row's label. The server substitutes the raw phase name for an unknown
/// phase with no message, so that case is humanized here.
fn display_label(event: &EnvironmentLog) -> String {
    let message = terminal_text(&event.message);
    if message.is_empty() || message == event.phase {
        humanize_phase(&event.phase)
    } else {
        message
    }
}

fn labelled(stage: Option<&str>, message: &str, fallback: &str) -> String {
    match stage {
        Some(stage) if !message.is_empty() && message != stage => format!("{stage}: {message}"),
        Some(stage) if message.is_empty() => stage.to_owned(),
        _ if message.is_empty() => fallback.to_owned(),
        _ => message.to_owned(),
    }
}

/// Stage duration from `duration_ms` metadata, else from the `started` row's
/// server timestamp.
fn stage_elapsed(event: &EnvironmentLog, stage: Option<&OpenStage>) -> Option<String> {
    if let Some(millis) = event
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("duration_ms"))
        .and_then(metadata_count)
    {
        return Some(format_duration(Duration::from_millis(millis), true));
    }
    let started = stage?.started_at?;
    let ended = parse_log_time(&event.created_at)?;
    let seconds = (ended - started).num_seconds().max(0);
    Some(format_duration(
        Duration::from_secs(seconds.unsigned_abs()),
        false,
    ))
}

/// `0.2s` (sub-second precision only when known and under ten seconds),
/// `21s`, `1m 05s`, `2h 03m`.
pub(crate) fn format_duration(duration: Duration, precise: bool) -> String {
    let seconds = duration.as_secs();
    if precise && duration < Duration::from_secs(10) {
        format!("{:.1}s", duration.as_secs_f64())
    } else if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn parse_log_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn humanize_phase(phase: &str) -> String {
    let text = terminal_text(&phase.replace('_', " "));
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Unnamed stage".to_owned(),
    }
}

/// Server-provided text with control characters (including escape sequences
/// and newlines) replaced, so a row cannot drive the terminal.
pub(crate) fn terminal_text(text: &str) -> String {
    let replaced: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    replaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests;
