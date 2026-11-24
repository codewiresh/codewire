//! `cw desktop`: an environment's graphical desktop in the computer's own
//! VNC viewer (`docs/dev/SANDBOX-DESKTOP.md`, "`cw desktop`"; journey
//! `docs/journeys/desktop.md`, `desktop-cli` and `desktop-cli-refusals`).
//!
//! The command starts the desktop through the desktop service, which the
//! control plane serves for a cloud environment and the supervisor for a
//! local VM, holds one OpenSSH local forward to it through the environment's
//! managed alias, and opens the viewer. Leaving it closes the forward and
//! leaves the desktop running.

use std::time::Duration;

use super::*;
use crate::commands::lifecycle_output::{ResultBlock, environment_command};
use crate::commands::progress::terminal_text;
use crate::error_report::with_next_step;
use crate::output::{Capabilities, OutputMode, Status, StatusLine, VmLocation};

mod forward;
mod state;
mod viewer;

use forward::{Forward, ForwardError};
use state::{Desktop, InvalidAnswer, Running};
use viewer::Opened;

/// How often the held forward asks whether its desktop still runs. Stopping
/// the desktop does not end OpenSSH, and the service has no stream to say
/// so, so a read this often is what notices it.
const STILL_RUNNING_POLL: Duration = Duration::from_secs(10);

const NO_DESKTOP_IN_IMAGE: &str =
    "this environment's image has no desktop; create the environment again on the current image";
const OLD_SERVER: &str = "this Codewire server has no desktop service yet; it needs an update";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const OLD_SUPERVISOR: &str = "your local VMs run on an older cw's supervisor, which has no desktop service; `cw upgrade --vms` moves them to this cw once they are idle";

#[derive(Debug, Args)]
pub(crate) struct DesktopArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "ID_OR_SLUG",
        help = "Organization for this command; overrides the saved default (`cw org set` changes that)"
    )]
    pub(crate) org: Option<String>,
    #[arg(
        long,
        help = "Print the address and the password instead of opening a viewer"
    )]
    pub(crate) no_open: bool,
    #[arg(
        long,
        conflicts_with_all = ["no_open", "stop"],
        help = "Say whether the desktop is running, and change nothing"
    )]
    pub(crate) status: bool,
    #[arg(
        long,
        conflicts_with = "no_open",
        help = "Stop the desktop and the programs on it"
    )]
    pub(crate) stop: bool,
}

pub(crate) async fn handle_desktop_command(
    globals: &Globals,
    args: DesktopArgs,
) -> anyhow::Result<()> {
    let globals = &globals.with_org(args.org.clone());
    let environment =
        flat::select_environment("desktop", args.environment, args.in_environment, &[])?;
    let target = DesktopTarget::resolve(globals, environment.as_deref()).await?;
    if args.status {
        say_status(&target).await
    } else if args.stop {
        stop(&target).await
    } else {
        show(&target, !args.no_open).await
    }
}

#[derive(Clone, Copy, Debug)]
enum Call {
    Start,
    Read,
    Stop,
}

/// Why a desktop call gave no desktop.
#[derive(Debug, thiserror::Error)]
enum Refused {
    #[error(transparent)]
    Cloud(#[from] codewire_client::ClientError),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    Local(#[from] codewire_local_vmm::public_client::NativePublicClientError),
    #[error(transparent)]
    Invalid(#[from] InvalidAnswer),
}

/// The environment whose desktop is asked for, and the service that answers.
enum DesktopTarget {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Local {
        name: String,
        environment_id: String,
        client: Box<codewire_local_vmm::public_client::NativePublicDesktopClient>,
    },
    Cloud {
        name: String,
        org_id: String,
        environment_id: String,
        client: Box<codewire_client::CodewireClient>,
    },
}

impl DesktopTarget {
    async fn resolve(globals: &Globals, environment: Option<&str>) -> anyhow::Result<Self> {
        match resolve_environment_session_target(globals, environment).await? {
            #[cfg(unix)]
            EnvironmentSessionTarget::Host { target, .. } => anyhow::bail!(
                "the folder {} is on this computer, which has no desktop of its own; `cw desktop` shows a local VM's or a cloud environment's",
                terminal_text(&target.name)
            ),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal {
                target,
                environment_id,
                ..
            } => {
                let environment = native_environment(&environment_id).await?.ok_or_else(|| {
                    anyhow::anyhow!("local environment {} was not found", target.name)
                })?;
                ensure_native_running(&environment)?;
                ensure_native_ssh().await?;
                anyhow::ensure!(
                    native_client().await?.supports(
                        codewire_local_vmm::supervisor_config::SupervisorFeature::Desktop
                    ),
                    OLD_SUPERVISOR
                );
                let client =
                    codewire_local_vmm::public_client::NativePublicDesktopClient::connect_or_start(
                        &native_runtime_config()?,
                        &environment_id,
                    )
                    .await?;
                Ok(Self::Local {
                    name: target.name,
                    environment_id,
                    client: Box::new(client),
                })
            }
            EnvironmentSessionTarget::Platform {
                target,
                org_id,
                environment_id,
                client,
            } => Ok(Self::Cloud {
                name: target.name,
                org_id,
                environment_id,
                client,
            }),
        }
    }

    fn name(&self) -> String {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Local { name, .. } => terminal_text(name),
            Self::Cloud { name, .. } => terminal_text(name),
        }
    }

    fn location(&self) -> VmLocation {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Local { .. } => VmLocation::Local,
            Self::Cloud { .. } => VmLocation::Cloud,
        }
    }

    /// The managed OpenSSH alias, by ID, as `cw vscode` names it.
    fn alias(&self) -> String {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Local { environment_id, .. } => format!("{LOCAL_ALIAS_PREFIX}{environment_id}"),
            Self::Cloud { environment_id, .. } => format!("{CLOUD_ALIAS_PREFIX}{environment_id}"),
        }
    }

    /// `cw desktop` for this environment, with `flag` after it when given.
    fn command(&self, flag: Option<&str>) -> String {
        let command = environment_command(self.location(), "desktop", &self.name());
        match flag {
            Some(flag) => format!("{command} {flag}"),
            None => command,
        }
    }

    /// One call of the desktop service, with its answer parsed.
    async fn ask(&self, call: Call) -> Result<Desktop, Refused> {
        let answer = match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Local { client, .. } => match call {
                Call::Start => client.start().await?,
                Call::Read => client.get().await?,
                Call::Stop => client.stop().await?,
            },
            Self::Cloud {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let (org_id, environment_id) = (org_id.clone(), environment_id.clone());
                let desktop = match call {
                    Call::Start => {
                        client
                            .start_desktop(codewire_client::desktop::StartDesktopRequest {
                                org_id,
                                environment_id,
                                ..Default::default()
                            })
                            .await?
                            .desktop
                    }
                    Call::Read => {
                        client
                            .get_desktop(codewire_client::desktop::GetDesktopRequest {
                                org_id,
                                environment_id,
                                ..Default::default()
                            })
                            .await?
                            .desktop
                    }
                    Call::Stop => {
                        client
                            .stop_desktop(codewire_client::desktop::StopDesktopRequest {
                                org_id,
                                environment_id,
                                ..Default::default()
                            })
                            .await?
                            .desktop
                    }
                };
                desktop.into_option().ok_or(InvalidAnswer)?
            }
        };
        Ok(Desktop::parse(answer)?)
    }

    /// [`Self::ask`], with a refusal told as the user can act on it: an
    /// environment that is not running names the command that starts it.
    async fn call(&self, call: Call) -> anyhow::Result<Desktop> {
        let refused = match self.ask(call).await {
            Ok(desktop) => return Ok(desktop),
            Err(refused) => refused,
        };
        Err(match refused {
            Refused::Invalid(invalid) => invalid.into(),
            Refused::Cloud(error) if error.code() == codewire_client::ErrorCode::Unimplemented => {
                anyhow::anyhow!(OLD_SERVER)
            }
            Refused::Cloud(error) => {
                let error = display_client_error(error);
                match self {
                    Self::Cloud {
                        name,
                        org_id,
                        environment_id,
                        client,
                    } => explain_by_state(client, org_id, environment_id, Some(name), error).await,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    Self::Local { .. } => error,
                }
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Refused::Local(error) => match self {
                Self::Local { environment_id, .. } => {
                    match native_environment(environment_id).await {
                        Ok(Some(environment)) => ensure_native_running(&environment)
                            .err()
                            .unwrap_or_else(|| local_refusal(error)),
                        _ => local_refusal(error),
                    }
                }
                Self::Cloud { .. } => local_refusal(error),
            },
        })
    }

    /// Why a forward to the desktop `was` ended by itself.
    async fn why_ended(&self, was: &Running) -> anyhow::Error {
        match self.call(Call::Read).await {
            Ok(now) if now.is_still(was) => with_next_step(
                anyhow::anyhow!(
                    "the connection to {} was lost; its desktop still runs",
                    self.name()
                ),
                self.command(None),
            ),
            Ok(_) => self.desktop_ended(),
            Err(error) => error,
        }
    }

    fn desktop_ended(&self) -> anyhow::Error {
        with_next_step(
            anyhow::anyhow!("the desktop of {} ended", self.name()),
            self.command(None),
        )
    }
}

/// The supervisor's refusal, in its own sentence. A supervisor that predates
/// the service has no route for it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn local_refusal(
    error: codewire_local_vmm::public_client::NativePublicClientError,
) -> anyhow::Error {
    use codewire_local_vmm::public_client::NativePublicClientError;

    match error {
        NativePublicClientError::Rpc(refused)
            if refused.code == connectrpc::ErrorCode::Unimplemented =>
        {
            anyhow::anyhow!(OLD_SUPERVISOR)
        }
        NativePublicClientError::Rpc(refused) => match refused.message.as_deref() {
            Some(sentence) if !sentence.is_empty() => anyhow::anyhow!(terminal_text(sentence)),
            _ => anyhow::anyhow!("the local VM's supervisor refused the desktop request"),
        },
        other => other.into(),
    }
}

/// Progress on stderr. A failed write is ignored throughout: progress is
/// decoration, and a closed terminal must not fail or panic the command.
struct Progress(StatusLine<std::io::Stderr>);

impl Progress {
    fn new(caps: &Capabilities) -> Self {
        Self(StatusLine::new(std::io::stderr(), caps))
    }

    /// Shows `label` as the active stage until `work` ends. The caller ends
    /// the stage with its outcome; a failure only clears it, for the error.
    async fn during<T, E>(
        &mut self,
        label: &str,
        work: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        self.0.begin(label).ok();
        tokio::pin!(work);
        let result = loop {
            let tick = self.0.tick_interval().unwrap_or(Duration::from_secs(3600));
            tokio::select! {
                result = &mut work => break result,
                () = tokio::time::sleep(tick) => {
                    self.0.tick().ok();
                }
            }
        };
        if result.is_err() {
            self.0.clear().ok();
        }
        result
    }

    fn clear(&mut self) {
        self.0.clear().ok();
    }

    fn done(&mut self, label: &str) {
        self.0.done(label).ok();
    }

    fn note(&mut self, status: Option<Status>, text: &str) {
        self.0.record(0, status, text, None).ok();
    }
}

fn text_caps() -> Capabilities {
    Capabilities::from_process(OutputMode::Text)
}

/// A running desktop in one line: `running · started 5m ago`.
fn running_since(running: &Running, separator: &str) -> String {
    match running.started_at {
        Some(at) => format!(
            "running{separator}started {}",
            time_ago_at(&at.to_rfc3339(), chrono::Utc::now())
        ),
        None => "running".to_owned(),
    }
}

async fn say_status(target: &DesktopTarget) -> anyhow::Result<()> {
    let desktop = target.call(Call::Read).await?;
    let caps = text_caps();
    let style = caps.stdout_style();
    let (state, next) = match &desktop {
        Desktop::Running(running) => (running_since(running, style.separator()), None),
        Desktop::Starting => ("starting".to_owned(), None),
        Desktop::Stopped => ("stopped".to_owned(), Some(target.command(None))),
        Desktop::Unavailable => (
            format!("unavailable{}{NO_DESKTOP_IN_IMAGE}", style.separator()),
            None,
        ),
    };
    println!("Desktop of {}: {state}", target.name());
    if let Some(next) = next {
        let style = caps.stderr_style();
        writeln!(std::io::stderr(), "{} {next}", style.status(Status::Next)).ok();
    }
    Ok(())
}

async fn stop(target: &DesktopTarget) -> anyhow::Result<()> {
    let caps = text_caps();
    let mut progress = Progress::new(&caps);
    let name = target.name();
    let stopped = progress
        .during(
            &format!("Stopping the desktop of {name}"),
            target.call(Call::Stop),
        )
        .await?;
    progress.clear();
    anyhow::ensure!(stopped != Desktop::Unavailable, NO_DESKTOP_IN_IMAGE);
    anyhow::ensure!(
        stopped == Desktop::Stopped,
        "the desktop of {name} did not stop; try again"
    );
    ResultBlock::new(Status::Done, format!("Desktop of {name} stopped")).print(&caps);
    Ok(())
}

async fn show(target: &DesktopTarget, open: bool) -> anyhow::Result<()> {
    let caps = text_caps();
    let mut progress = Progress::new(&caps);
    let name = target.name();
    let started = progress
        .during(
            &format!("Starting the desktop of {name}"),
            target.call(Call::Start),
        )
        .await?;
    let running = match started {
        Desktop::Running(running) => running,
        Desktop::Unavailable => {
            progress.clear();
            anyhow::bail!(NO_DESKTOP_IN_IMAGE)
        }
        Desktop::Stopped | Desktop::Starting => {
            progress.clear();
            anyhow::bail!("the desktop of {name} did not start; try again")
        }
    };
    progress.done(&format!("Desktop of {name} is running"));

    // The forward connects through the managed alias, so its section is
    // brought up to date first, as `cw vscode` does.
    install_default_managed_ssh_config().context("update ssh config")?;
    // From here on the user's leave is handled, never left to end `cw`
    // with OpenSSH still running in its own process group.
    let left = leave_signal();
    tokio::pin!(left);
    let mut forward = Forward::spawn(&target.alias()).await?;
    let connecting = format!("Connecting to {name}");
    let ready = tokio::select! {
        biased;
        () = &mut left => None,
        ready = progress.during(&connecting, forward.ready()) => Some(ready),
    };
    let failed = match ready {
        Some(Ok(())) => None,
        None => {
            progress.clear();
            Some(None)
        }
        // OpenSSH said why on stderr; the environment's state says the rest.
        Some(Err(ForwardError::Ended)) => Some(Some(target.why_ended(&running).await)),
        Some(Err(error)) => Some(Some(error.into())),
    };
    if let Some(failed) = failed {
        forward.close().await;
        return failed.map_or(Ok(()), Err);
    }
    progress.clear();

    println!("{}", viewer::address(forward.port()));
    let opened = if open {
        Some(viewer::open(forward.port(), &running.password).await)
    } else {
        None
    };
    let password_printed = prints_password(opened, std::io::stdout().is_terminal());
    if password_printed {
        println!("Password: {}", running.password.reveal());
    }
    match opened {
        Some(Opened::WithPassword) => progress.note(Some(Status::Done), "Opened your VNC viewer"),
        Some(Opened::AskingForPassword) => progress.note(
            Some(Status::Done),
            "Opened your VNC viewer, which asks for the password",
        ),
        Some(Opened::NoViewer) => progress.note(
            Some(Status::Attention),
            "No VNC viewer is registered on this computer; open the address in one, with the password",
        ),
        None => {}
    }
    if !password_printed && opened != Some(Opened::WithPassword) {
        let no_open = target.command(Some("--no-open"));
        progress.note(
            Some(Status::Attention),
            &format!("The password is printed only to a terminal; `{no_open}` prints it"),
        );
    }
    progress.note(
        None,
        "Ctrl-C closes this connection; the desktop keeps running",
    );

    let ended = hold(target, &mut forward, &running, left).await;
    forward.close().await;
    match ended {
        Some(error) => Err(error),
        None => {
            progress.note(
                Some(Status::Done),
                &format!("Closed the connection; the desktop of {name} keeps running"),
            );
            let style = caps.stderr_style();
            writeln!(
                std::io::stderr(),
                "{} {}",
                style.status(Status::Next),
                target.command(Some("--stop"))
            )
            .ok();
            Ok(())
        }
    }
}

/// Holds the forward until the user leaves (`None`), or it or its desktop
/// ends by itself (why).
/// Whether this start prints the viewer's password. `--no-open` asks for
/// it, a viewer that was given it needs nothing, and otherwise it goes only
/// to a terminal, so a run whose output is logged does not record it.
fn prints_password(opened: Option<Opened>, stdout_is_terminal: bool) -> bool {
    match opened {
        None => true,
        Some(Opened::WithPassword) => false,
        Some(Opened::AskingForPassword | Opened::NoViewer) => stdout_is_terminal,
    }
}

async fn hold(
    target: &DesktopTarget,
    forward: &mut Forward,
    running: &Running,
    mut left: std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Option<anyhow::Error> {
    let mut poll = tokio::time::interval_at(
        tokio::time::Instant::now() + STILL_RUNNING_POLL,
        STILL_RUNNING_POLL,
    );
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = &mut left => return None,
            () = forward.ended() => return Some(target.why_ended(running).await),
            _ = poll.tick() => {
                let asked = tokio::select! {
                    biased;
                    () = &mut left => return None,
                    asked = target.ask(Call::Read) => asked,
                };
                // A call that fails says nothing about the desktop. When the
                // environment itself is gone, OpenSSH ends and says so.
                if let Ok(now) = asked
                    && !now.is_still(running)
                {
                    return Some(target.desktop_ended());
                }
            }
        }
    }
}

/// Resolves when the user leaves: Ctrl-C, or the terminal or the session
/// going away. Handled rather than left to end the process, so the forward
/// is closed and waited for on every way out.
async fn leave_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let (Ok(mut terminate), Ok(mut hangup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            return interrupt().await;
        };
        tokio::select! {
            () = interrupt() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    interrupt().await;
}

async fn interrupt() {
    if tokio::signal::ctrl_c().await.is_err() {
        // No handler could be installed, so Ctrl-C ends the process as it
        // would any other; nothing here may read that as a leave.
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
