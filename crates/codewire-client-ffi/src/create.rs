//! Creating an environment from the app (#3825): the create form
//! ([`form`]), and the setup steps as they arrive, through the same
//! `codewire_client` calls and setup wait `cw create` uses
//! (`codewire_client::environment_setup::await_setup`). The journey is
//! `ios-create` in `docs/journeys/ios-app.md`.
//!
//! A step is one `environment_logs` row, shaped as the dashboard's setup
//! progress shapes it: its phase, its status and its message as the label.
//! A setup that cannot finish ends with a short message saying why.

use std::convert::Infallible;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use codewire_client::CodewireClient;
use codewire_client::environment_setup::{
    DaemonReadyRow, DaemonWaitError, EnvironmentFacts, EnvironmentLogRow, FollowError,
    FollowPolicy, GetEnvironmentError, Interruption, PlatformEnd, PlatformLogFeed, SetupEnd,
    SetupObserver, SetupStop, SetupWaitError, SetupWaitObserver, await_daemon_ready, await_setup,
    watch_environment,
};
use tokio::sync::oneshot;

use crate::ShellError;

mod form;
pub use form::{
    CreateForm, CreateOptions, CreateOutcome, FieldRefusal, FormField, PortField, PresetOption,
    PreviewAccess, ProfileChoice, RepositoryField, SourceChoice, create_environment,
    create_from_form, create_options,
};

/// A step label's longest length, in characters, as on the dashboard.
const MAX_LABEL_CHARS: usize = 300;

/// The organization a call acts in.
#[derive(Clone, uniffi::Record)]
pub struct OrgTarget {
    pub server_url: String,
    pub access_token: String,
    pub org_id: String,
}

impl std::fmt::Debug for OrgTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgTarget")
            .field("server_url", &self.server_url)
            .field("access_token", &"<redacted>")
            .field("org_id", &self.org_id)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CreatedEnvironment {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StepStatus {
    Started,
    Completed,
    Failed,
    Skipped,
    /// A status this app does not know yet.
    Other {
        status: String,
    },
}

/// One setup row.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SetupStep {
    pub phase: String,
    pub status: StepStatus,
    pub label: String,
    /// RFC 3339, or empty when the server sent no time.
    pub created_at: String,
}

/// How following a setup ended.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SetupOutcome {
    /// Setup finished and the workspace daemon is ready.
    Ready,
    /// Setup cannot finish. `step` is the failed row, when one said so.
    Failed {
        message: String,
        step: Option<SetupStep>,
    },
    /// The app can no longer follow it. Setup itself may still be running.
    Lost { message: String },
    /// The app stopped following.
    Stopped,
}

/// Told the steps of a setup, on the follower's own thread.
#[uniffi::export(with_foreign)]
pub trait SetupStepObserver: Send + Sync {
    fn step(&self, step: SetupStep);
    /// Setup is complete and the wait for the workspace daemon begins.
    fn daemon_waiting(&self);
    /// The connection dropped; reconnect `attempt` of `max_reconnects` follows.
    fn reconnecting(&self, reason: String, attempt: u32, max_reconnects: u32);
    /// Called once, last.
    fn finished(&self, outcome: SetupOutcome);
}

/// Following one environment's setup.
#[derive(uniffi::Object)]
pub struct EnvironmentSetup {
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl EnvironmentSetup {
    /// Follow the environment's setup from its first row, until it is ready,
    /// fails, can no longer be followed, or [`EnvironmentSetup::stop`] is
    /// called or the handle dropped.
    #[uniffi::constructor]
    pub fn follow(
        target: OrgTarget,
        environment_id: String,
        observer: Arc<dyn SetupStepObserver>,
    ) -> Result<Arc<Self>, ShellError> {
        if environment_id.trim().is_empty() {
            return Err(ShellError::Invalid {
                message: "the environment is empty".into(),
            });
        }
        let client = client_for(&target)?;
        let runtime = runtime()?;
        let (stop, stopped) = oneshot::channel();
        std::thread::Builder::new()
            .name("codewire-setup".into())
            .spawn(move || {
                let org_id = target.org_id;
                let feed = PlatformLogFeed::new(client.clone(), &org_id, &environment_id);
                let mut relay = StepRelay(observer.as_ref());
                let guard = watch_environment(&client, &org_id, &environment_id, |facts| {
                    facts.setup_stop().map(|stop| stop_message(facts, stop))
                });
                let daemon_ready = || await_daemon_ready(&client, &org_id, &environment_id);
                let policy = FollowPolicy::default();
                let ended = runtime.block_on(async {
                    tokio::select! {
                        ended = await_setup(&feed, &mut relay, &policy, guard, daemon_ready) => Some(ended),
                        _ = stopped => None,
                    }
                });
                observer.finished(match ended {
                    Some(ended) => outcome(ended),
                    None => SetupOutcome::Stopped,
                });
            })
            .map_err(|error| ShellError::Unavailable {
                message: format!("start the setup's thread: {error}"),
            })?;
        Ok(Arc::new(Self {
            stop: Mutex::new(Some(stop)),
        }))
    }

    /// Stop following. The environment's setup carries on.
    pub fn stop(&self) {
        if let Some(stop) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            // The follower may have ended already; then it has nothing to stop.
            let _ = stop.send(());
        }
    }
}

impl Drop for EnvironmentSetup {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Hands each row to the app as a step and ends the follow on a failed one.
struct StepRelay<'a>(&'a dyn SetupStepObserver);

impl SetupObserver for StepRelay<'_> {
    type Failure = SetupStep;
    type Error = Infallible;

    fn row(
        &mut self,
        row: &EnvironmentLogRow,
        _received: Instant,
    ) -> Result<Option<SetupStep>, Infallible> {
        let step = setup_step(row);
        self.0.step(step.clone());
        Ok((step.status == StepStatus::Failed).then_some(step))
    }

    fn interrupted(
        &mut self,
        interruption: &Interruption,
        attempt: u32,
        max_reconnects: u32,
    ) -> Result<(), Infallible> {
        self.0
            .reconnecting(interruption_reason(interruption), attempt, max_reconnects);
        Ok(())
    }

    fn redraw(&mut self, _now: Instant) -> Result<(), Infallible> {
        Ok(())
    }

    fn tick_interval(&self) -> Option<Duration> {
        None
    }
}

impl SetupWaitObserver for StepRelay<'_> {
    fn daemon_waiting(&mut self, _now: Instant) -> Result<(), Infallible> {
        self.0.daemon_waiting();
        Ok(())
    }

    fn daemon_ready(&mut self, _now: Instant) -> Result<(), Infallible> {
        Ok(())
    }
}

fn setup_step(row: &EnvironmentLogRow) -> SetupStep {
    SetupStep {
        phase: row.phase.clone(),
        status: match row.status.as_str() {
            "started" => StepStatus::Started,
            "completed" => StepStatus::Completed,
            "failed" => StepStatus::Failed,
            "skipped" => StepStatus::Skipped,
            other => StepStatus::Other {
                status: other.to_owned(),
            },
        },
        label: label(&row.message),
        created_at: row.created_at.clone(),
    }
}

/// The message as one line a person can read.
fn label(message: &str) -> String {
    message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn interruption_reason(interruption: &Interruption) -> String {
    match interruption {
        Interruption::Stream(error) => error.to_string(),
        Interruption::Closed => "the server closed the stream".into(),
        Interruption::Silent(after) => format!("no word from the server for {}s", after.as_secs()),
    }
}

type SetupWait = Result<SetupEnd<SetupStep>, SetupWaitError<Infallible, String, DaemonWaitError>>;

fn outcome(ended: SetupWait) -> SetupOutcome {
    let failed = |message: String| SetupOutcome::Failed {
        message,
        step: None,
    };
    match ended {
        Ok(SetupEnd::Ready) => SetupOutcome::Ready,
        Ok(SetupEnd::Failed(step)) => SetupOutcome::Failed {
            message: step.label.clone(),
            step: Some(step),
        },
        Err(SetupWaitError::Follow(FollowError::Fatal(error))) => SetupOutcome::Lost {
            message: error.to_string(),
        },
        Err(SetupWaitError::Follow(FollowError::Lost {
            max_reconnects,
            last,
        })) => SetupOutcome::Lost {
            message: format!(
                "{} reconnects failed; the last: {}",
                max_reconnects,
                interruption_reason(&last)
            ),
        },
        Err(SetupWaitError::Stopped(message)) => failed(message),
        Err(SetupWaitError::DaemonRow(DaemonReadyRow { state, message })) => {
            failed(daemon_message(state.token(), &message))
        }
        Err(SetupWaitError::Daemon(error)) => failed(daemon_wait_message(error)),
        Err(
            SetupWaitError::Follow(FollowError::Observer(never)) | SetupWaitError::Observer(never),
        ) => match never {},
    }
}

/// Why setup can no longer finish, as one sentence.
fn stop_message(facts: &EnvironmentFacts, stop: SetupStop) -> String {
    let reason = facts
        .error_reason
        .as_deref()
        .map(label)
        .filter(|reason| !reason.is_empty());
    match stop {
        SetupStop::PlatformEnded(end) => platform_end_message(reason, end),
        SetupStop::Left => match reason {
            Some(reason) => format!(
                "The environment became {} before setup finished: {reason}",
                facts.state
            ),
            None => format!(
                "The environment became {} before setup finished",
                facts.state
            ),
        },
        SetupStop::SetupError => format!(
            "Setup failed: {}",
            facts.setup_error.as_deref().map(label).unwrap_or_default()
        ),
    }
}

fn platform_end_message(reason: Option<String>, end: PlatformEnd) -> String {
    reason.unwrap_or_else(|| {
        match end {
            PlatformEnd::NoCapacity => "No capacity right now. Try again shortly.",
            PlatformEnd::ContainerStartFailed => "The sandbox could not start.",
        }
        .to_owned()
    })
}

fn daemon_message(state: &str, message: &str) -> String {
    let message = label(message);
    if message.is_empty() {
        format!("The workspace daemon is {state}")
    } else {
        format!("The workspace daemon is {state}: {message}")
    }
}

fn daemon_wait_message(error: DaemonWaitError) -> String {
    match error {
        DaemonWaitError::GetEnvironment(GetEnvironmentError::Client(error)) => {
            error.message().to_owned()
        }
        DaemonWaitError::GetEnvironment(GetEnvironmentError::Missing) => {
            "The server answered without the environment".to_owned()
        }
        DaemonWaitError::PlatformEnded(facts, end) => platform_end_message(
            facts
                .error_reason
                .as_deref()
                .map(label)
                .filter(|reason| !reason.is_empty()),
            end,
        ),
        DaemonWaitError::Unusable { state, message } => daemon_message(&state, &message),
        DaemonWaitError::Left(state) => {
            format!("The environment became {state} before its workspace daemon was ready")
        }
        DaemonWaitError::DaemonTimeout(_) => {
            "The workspace daemon did not become ready in time".to_owned()
        }
        DaemonWaitError::LifecycleTimeout(_) => "The environment did not start in time".to_owned(),
    }
}

fn client_for(target: &OrgTarget) -> Result<CodewireClient, ShellError> {
    crate::client(
        &target.server_url,
        &target.access_token,
        &[("organization", &target.org_id)],
    )
}

fn runtime() -> Result<tokio::runtime::Runtime, ShellError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ShellError::Unavailable {
            message: format!("start a runtime: {error}"),
        })
}

/// Run a request on a thread and runtime of its own, as the shell does, so
/// the app's executor never runs network work.
async fn on_own_runtime<T, F>(name: &str, request: F) -> Result<T, ShellError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let runtime = runtime()?;
    let (answer, answered) = oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            // The app may have stopped waiting; then the answer has no reader.
            let _ = answer.send(runtime.block_on(request));
        })
        .map_err(|error| ShellError::Unavailable {
            message: format!("start the request's thread: {error}"),
        })?;
    answered.await.map_err(|_| ShellError::Unavailable {
        message: "the request's thread ended".into(),
    })
}

#[cfg(test)]
mod tests;
