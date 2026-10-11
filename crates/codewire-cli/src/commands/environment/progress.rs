//! Live start progress for `cw env create`, `cw env start` and
//! `cw env logs --follow`.
//!
//! Stages come from `environment_logs` rows delivered by `StreamLogs`. The
//! follower resumes after the last row it rendered when a connection drops or
//! stops sending heartbeats, so a reconnect neither repeats nor skips a row.
//! The renderer keeps one live status line on a terminal and writes one plain
//! line per row everywhere else. Each finished stage shows its elapsed time,
//! taken from the row's `duration_ms` metadata when present and otherwise from
//! the server `created_at` of its `started` and final rows.
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

use std::future::Future;
use std::io::Write;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::environment_client::{
    EnvironmentClient, EnvironmentLogStreamEvent, EnvironmentLogStreamFailure, LogStreamRecovery,
};
use crate::presentation::{Environment, EnvironmentLog};

/// The server sends a heartbeat every 15 seconds; three missed heartbeats
/// mean the connection is gone even when the transport has not noticed.
const LOG_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Consecutive failed connections before giving up. Any row or heartbeat
/// resets the count.
const LOG_STREAM_MAX_RECONNECTS: u32 = 5;
const LOG_STREAM_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const LOG_STREAM_MAX_BACKOFF: Duration = Duration::from_secs(8);
const LIVE_TICK: Duration = Duration::from_secs(1);
const SETUP_GUARD_INTERVAL: Duration = Duration::from_secs(5);
const LIVE_LINE_MAX_CHARS: usize = 160;
const DAEMON_STAGE_KEY: &str = "cli:daemon_ready";
const DAEMON_WAIT_LABEL: &str = "Waiting for the workspace daemon";
const DAEMON_READY_LABEL: &str = "Workspace daemon ready";

/// Clears the current terminal line.
const CLEAR_LINE: &str = "\r\x1b[2K";
/// Turn terminal auto-wrap off while drawing the live line so a line wider
/// than the terminal is clipped instead of wrapped, which `CLEAR_LINE` could
/// not fully erase.
const WRAP_OFF: &str = "\x1b[?7l";
const WRAP_ON: &str = "\x1b[?7h";

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
            "environment {environment_id} failed at stage {:?}{detail} (see `cw env logs {environment_id}`)",
            self.stage
        )
    }
}

struct OpenStage {
    key: String,
    label: String,
    nested: bool,
    started_at: Option<DateTime<Utc>>,
    /// Local instant the stage was first seen; the live line ticks from it so
    /// a skewed local clock cannot distort it.
    anchor: Instant,
    detail: Option<String>,
}

/// Renders environment log rows as start progress.
pub(crate) struct StartProgress<W: Write> {
    out: W,
    live: bool,
    began: Instant,
    idle_label: &'static str,
    open: Vec<OpenStage>,
    live_drawn: bool,
}

impl<W: Write> StartProgress<W> {
    /// `live` draws one updating status line (a terminal); otherwise every
    /// row becomes one plain line.
    pub(crate) fn new(out: W, live: bool, began: Instant, idle_label: &'static str) -> Self {
        Self {
            out,
            live,
            began,
            idle_label,
            open: Vec::new(),
            live_drawn: false,
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live
    }

    pub(crate) fn total_elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.began)
    }

    #[cfg(test)]
    pub(crate) fn into_inner(self) -> W {
        self.out
    }

    /// Renders one row. Returns the failure when the row is a `failed` row.
    pub(crate) fn apply(
        &mut self,
        event: &EnvironmentLog,
        received: Instant,
    ) -> std::io::Result<Option<StageFailure>> {
        let repo = repository_scope(event.metadata.as_ref());
        let key = stage_key(&event.phase, repo);
        let indent = if repo.is_some() { "    " } else { "  " };
        let label = display_label(event);
        let mut failure = None;
        match event.status.as_str() {
            "started" => {
                if !self.live {
                    self.line(&format!("{indent}◌ {label}..."))?;
                }
                self.open.retain(|stage| stage.key != key);
                self.open.push(OpenStage {
                    key,
                    label,
                    nested: repo.is_some(),
                    started_at: parse_log_time(&event.created_at),
                    anchor: received,
                    detail: None,
                });
            }
            "progress" => {
                let position = self.progress_stage(&key, &event.phase);
                let nested = position.is_some_and(|index| self.open[index].nested);
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
                                nested: repo.is_some(),
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
                    match detail {
                        Some(detail) => self.line(&format!("    · {stage_label}: {detail}"))?,
                        None => self.line(&format!("    · {stage_label}"))?,
                    }
                }
            }
            "completed" | "warning" | "failed" => {
                let stage = self
                    .open
                    .iter()
                    .rposition(|stage| stage.key == key)
                    .map(|index| self.open.remove(index));
                let elapsed = stage_elapsed(event, stage.as_ref())
                    .map(|elapsed| format!("  {elapsed}"))
                    .unwrap_or_default();
                let stage_label = stage.as_ref().map(|stage| stage.label.clone());
                let message = terminal_text(&event.message);
                match event.status.as_str() {
                    "completed" => self.line(&format!("{indent}✓ {label}{elapsed}"))?,
                    "warning" => {
                        let text = labelled(stage_label.as_deref(), &message, &label);
                        self.line(&format!("{indent}! {text}{elapsed}"))?;
                    }
                    _ => {
                        let text = labelled(stage_label.as_deref(), &message, &label);
                        self.line(&format!("{indent}✗ {text}{elapsed}"))?;
                        failure = Some(StageFailure {
                            phase: event.phase.clone(),
                            stage: stage_label.unwrap_or_else(|| humanize_phase(&event.phase)),
                            message,
                        });
                    }
                }
            }
            _ => self.line(&format!("{indent}· {label}"))?,
        }
        if event.phase == "complete" {
            self.open.retain(|stage| stage.key.starts_with("cli:"));
        }
        self.redraw(received)?;
        Ok(failure)
    }

    /// Opens a stage the CLI itself waits on, such as daemon readiness.
    pub(crate) fn begin_local_stage(
        &mut self,
        key: &str,
        label: &str,
        now: Instant,
    ) -> std::io::Result<()> {
        if !self.live {
            self.line(&format!("  ◌ {label}..."))?;
        }
        self.open.retain(|stage| stage.key != key);
        self.open.push(OpenStage {
            key: key.to_owned(),
            label: label.to_owned(),
            nested: false,
            started_at: None,
            anchor: now,
            detail: None,
        });
        self.redraw(now)
    }

    pub(crate) fn complete_local_stage(
        &mut self,
        key: &str,
        label: &str,
        now: Instant,
    ) -> std::io::Result<()> {
        let elapsed = self
            .open
            .iter()
            .rposition(|stage| stage.key == key)
            .map(|index| self.open.remove(index))
            .map(|stage| {
                format!(
                    "  {}",
                    format_duration(now.saturating_duration_since(stage.anchor), true)
                )
            })
            .unwrap_or_default();
        self.line(&format!("  ✓ {label}{elapsed}"))?;
        self.redraw(now)
    }

    /// Sets or clears the detail shown beside an open local stage on the live
    /// line, such as what a booting guest is doing. Plain output omits it.
    pub(crate) fn set_local_detail(
        &mut self,
        key: &str,
        detail: Option<&str>,
        now: Instant,
    ) -> std::io::Result<()> {
        let Some(stage) = self.open.iter_mut().rev().find(|stage| stage.key == key) else {
            return Ok(());
        };
        let detail = detail.map(str::to_owned);
        if stage.detail == detail {
            return Ok(());
        }
        stage.detail = detail;
        self.redraw(now)
    }

    /// Writes a permanent notice line.
    pub(crate) fn note(&mut self, text: &str) -> std::io::Result<()> {
        self.line(&format!("  ! {}", terminal_text(text)))?;
        self.redraw(Instant::now())
    }

    /// Redraws the live status line. Plain output has none.
    pub(crate) fn redraw(&mut self, now: Instant) -> std::io::Result<()> {
        if !self.live {
            return self.out.flush();
        }
        let text = self.live_text(now);
        write!(self.out, "{CLEAR_LINE}{WRAP_OFF}{text}{WRAP_ON}")?;
        self.live_drawn = true;
        self.out.flush()
    }

    /// Removes the live status line so later output starts on a clean line.
    pub(crate) fn finish(&mut self) -> std::io::Result<()> {
        if self.live_drawn {
            write!(self.out, "{CLEAR_LINE}")?;
            self.live_drawn = false;
        }
        self.out.flush()
    }

    fn progress_stage(&self, key: &str, phase: &str) -> Option<usize> {
        self.open
            .iter()
            .rposition(|stage| stage.key == key)
            .or_else(|| self.open.iter().rposition(|stage| stage.key == phase))
    }

    fn live_text(&self, now: Instant) -> String {
        let text = match self.open.last() {
            Some(stage) => {
                let detail = stage
                    .detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default();
                format!(
                    "  ◌ {}{detail}  {}",
                    stage.label,
                    format_duration(now.saturating_duration_since(stage.anchor), false)
                )
            }
            None => format!(
                "  ◌ {}  {}",
                self.idle_label,
                format_duration(self.total_elapsed(now), false)
            ),
        };
        text.chars().take(LIVE_LINE_MAX_CHARS).collect()
    }

    fn line(&mut self, text: &str) -> std::io::Result<()> {
        if self.live_drawn {
            write!(self.out, "{CLEAR_LINE}")?;
            self.live_drawn = false;
        }
        writeln!(self.out, "{text}")
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
        let mut ticker = tokio::time::interval(policy.tick);
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
                _ = ticker.tick(), if view.is_live() => view.redraw(Instant::now())?,
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

/// Awaits `future`, redrawing the live line every `tick` meanwhile.
pub(crate) async fn wait_with_ticks<W, T>(
    view: &mut StartProgress<W>,
    tick: Duration,
    future: impl Future<Output = T>,
) -> anyhow::Result<T>
where
    W: Write,
{
    tokio::pin!(future);
    if !view.is_live() {
        return Ok(future.await);
    }
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = ticker.tick() => view.redraw(Instant::now())?,
        }
    }
}

/// `cw env create`: every setup stage through `complete`, then daemon
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
            view.finish()?;
            return Err(error);
        }
    }
    await_daemon_ready(view, policy, daemon_ready()).await
}

/// `cw env start`: shows the rows the start produces after `cursor` while
/// waiting for daemon readiness. Fails on a `failed` row. Losing the log
/// stream only loses the display; readiness still decides the outcome.
pub(crate) async fn await_environment_start<F, W>(
    feed: &F,
    view: &mut StartProgress<W>,
    policy: &FollowPolicy,
    environment_id: &str,
    cursor: Option<String>,
    daemon_ready: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()>
where
    F: EnvironmentLogFeed,
    W: Write,
{
    view.begin_local_stage(DAEMON_STAGE_KEY, DAEMON_WAIT_LABEL, Instant::now())?;
    tokio::pin!(daemon_ready);
    let mut cursor = cursor;
    let followed = {
        let follow = follow_start_progress(feed, view, &mut cursor, policy);
        tokio::select! {
            biased;
            end = follow => Some(end),
            ready = &mut daemon_ready => {
                if let Err(error) = ready {
                    view.finish()?;
                    return Err(error);
                }
                None
            }
        }
    };
    match followed {
        None => {}
        Some(Ok(FollowEnd::Failed(failure))) => {
            view.finish()?;
            return Err(failure.into_error(environment_id));
        }
        Some(Ok(FollowEnd::Complete)) => {
            finish_daemon_wait(view, policy, &mut daemon_ready).await?;
        }
        Some(Err(error)) => {
            view.note(&format!("Start progress is unavailable: {error:#}"))?;
            finish_daemon_wait(view, policy, &mut daemon_ready).await?;
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
        view.finish()?;
        return Err(error);
    }
    Ok(())
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

pub(crate) fn setup_failure(environment: &Environment) -> Option<anyhow::Error> {
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
                anyhow::anyhow!("environment {id} setup failed: {error} (see `cw env logs {id}`)")
            }),
    }
}

/// The id of the newest row, so a follow shows only rows written after it.
pub(crate) fn last_log_id(logs: &[EnvironmentLog]) -> Option<String> {
    logs.last().map(|log| log.id.clone())
}

/// Renders stored rows as plain lines.
pub(crate) fn format_environment_logs_plain(logs: &[EnvironmentLog]) -> String {
    let now = Instant::now();
    let mut view = StartProgress::new(Vec::new(), false, now, "");
    for log in logs {
        // Writing to a Vec cannot fail.
        let _ = view.apply(log, now);
    }
    String::from_utf8_lossy(&view.out).into_owned()
}

/// `true` when stderr is a terminal that can redraw a status line.
pub(crate) fn live_progress_enabled() -> bool {
    use std::io::IsTerminal as _;
    std::io::stderr().is_terminal() && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

pub(crate) fn format_env_ready_text(name: &str, total: Duration) -> String {
    format!(
        "Environment {name} is ready ({}).\n",
        format_duration(total, false)
    )
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
fn terminal_text(text: &str) -> String {
    let replaced: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    replaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests;
