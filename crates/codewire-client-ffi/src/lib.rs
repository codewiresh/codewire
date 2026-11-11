//! The iOS app's connection to an environment's shell (#3825): the shell of
//! `codewire_client::hosted_shell`, the same loop `cw shell` runs, behind the
//! surface Swift calls through UniFFI. Dial, read, write, resize and close,
//! and the connection's state through [`ShellObserver`].
//!
//! Each shell runs on a thread of its own with a single-threaded runtime, so
//! the app's calls never wait on its network work. Keys typed while the
//! connection is down are dropped, as `cw shell` drops them (#3993).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use codewire_client::hosted_shell::{
    self, AttachedTerminal, HostedShellError, ShellLaunch, ShellNotice, ShellTerminal,
    TerminalKeys, TerminalOutput, TerminalSizes, Via,
};
use codewire_client::tailnet_session::TailnetPath;
use codewire_client::{ClientConfig, ClientError, CodewireClient, ErrorCode, StaticTokenProvider};
use tokio::sync::{mpsc, oneshot, watch};

uniffi::setup_scaffolding!();

/// The command a hosted shell runs: the user's login shell.
const LOGIN_SHELL: [&str; 3] = ["/bin/sh", "-c", "exec \"${SHELL:-/bin/sh}\" -l"];

/// Output chunks waiting for the app to read them.
const OUTPUT_BACKLOG: usize = 64;

/// Which environment to open a shell on, and the terminal it starts with.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ShellTarget {
    pub server_url: String,
    /// The app's current access token; refreshing it moves into Rust later.
    pub access_token: String,
    pub org_id: String,
    pub environment_id: String,
    pub term: String,
    pub columns: u16,
    pub rows: u16,
}

/// The path that carries the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ShellPath {
    DirectUdp,
    Relay,
    Derp,
    /// The tailnet, on a path that could not be read.
    Tailnet,
    Api,
}

/// What the shell's connection is doing.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ShellState {
    Connecting,
    /// `reason` says why it isn't direct UDP, when it isn't.
    Connected {
        path: ShellPath,
        reason: Option<String>,
    },
    /// The shell keeps running in the environment; this keeps reconnecting
    /// for 10 minutes after the drop.
    Reconnecting {
        reason: String,
    },
    Ended {
        exit_status: Option<i32>,
        error: Option<String>,
    },
}

/// Told every change of the shell's state, on the shell's own thread.
#[uniffi::export(with_foreign)]
pub trait ShellObserver: Send + Sync {
    fn state_changed(&self, state: ShellState);
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ShellError {
    /// The sign-in is no longer valid; the app signs in again.
    #[error("{message}")]
    Unauthenticated { message: String },
    #[error("{message}")]
    PermissionDenied { message: String },
    #[error("{message}")]
    NotFound { message: String },
    /// The server or the network.
    #[error("{message}")]
    Unavailable { message: String },
    #[error("{message}")]
    Ended { message: String },
    #[error("{message}")]
    Invalid { message: String },
}

impl From<ClientError> for ShellError {
    fn from(error: ClientError) -> Self {
        let message = error.message().to_owned();
        match error.code() {
            ErrorCode::Unauthenticated => Self::Unauthenticated { message },
            ErrorCode::PermissionDenied => Self::PermissionDenied { message },
            ErrorCode::NotFound => Self::NotFound { message },
            ErrorCode::InvalidArgument => Self::Invalid { message },
            _ => Self::Unavailable { message },
        }
    }
}

impl From<HostedShellError> for ShellError {
    fn from(error: HostedShellError) -> Self {
        match error {
            HostedShellError::Client(error) => error.into(),
            HostedShellError::Other(error) => Self::Ended {
                message: format!("{error:#}"),
            },
        }
    }
}

/// A shell on an environment.
#[derive(uniffi::Object)]
pub struct Shell {
    keys: mpsc::UnboundedSender<Vec<u8>>,
    sizes: watch::Sender<(u16, u16)>,
    output: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    connected: Arc<AtomicBool>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Shell {
    /// Open a shell on the environment and wait until it is attached.
    #[uniffi::constructor]
    pub async fn dial(
        target: ShellTarget,
        observer: Arc<dyn ShellObserver>,
    ) -> Result<Arc<Self>, ShellError> {
        let client = client_for(&target)?;
        let (keys, key_receiver) = mpsc::unbounded_channel();
        let (sizes, size_receiver) = watch::channel((target.columns, target.rows));
        let (output_sender, output) = mpsc::channel(OUTPUT_BACKLOG);
        let (stop, stopped) = oneshot::channel();
        let (attached, first_attachment) = oneshot::channel();
        let connected = Arc::new(AtomicBool::new(false));
        let terminal = ChannelTerminal {
            keys: Arc::new(tokio::sync::Mutex::new(key_receiver)),
            sizes: size_receiver,
            output: output_sender,
            connected: connected.clone(),
            observer: observer.clone(),
            attached: Some(attached),
        };
        observer.state_changed(ShellState::Connecting);
        spawn_shell(client, target, terminal, stopped, observer)?;
        first_attachment.await.unwrap_or_else(|_| {
            Err(ShellError::Ended {
                message: "the shell thread ended".into(),
            })
        })?;
        Ok(Arc::new(Self {
            keys,
            sizes,
            output: tokio::sync::Mutex::new(output),
            connected,
            stop: Mutex::new(Some(stop)),
        }))
    }

    /// The next output, in order and exactly once across reconnects; `None`
    /// once the shell has ended.
    pub async fn read(&self) -> Option<Vec<u8>> {
        self.output.lock().await.recv().await
    }

    /// Send keys to the shell. Keys sent while the connection is down are
    /// dropped.
    pub fn write(&self, data: Vec<u8>) -> Result<(), ShellError> {
        if !self.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        self.keys.send(data).map_err(|_| ended())
    }

    pub fn resize(&self, columns: u16, rows: u16) -> Result<(), ShellError> {
        self.sizes.send((columns, rows)).map_err(|_| ended())
    }

    /// Leave the shell. The environment ends it 10 minutes later unless a
    /// client attaches to it again.
    pub fn close(&self) {
        if let Some(stop) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stop.send(());
        }
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        self.close();
    }
}

fn ended() -> ShellError {
    ShellError::Ended {
        message: "the shell has ended".into(),
    }
}

fn client_for(target: &ShellTarget) -> Result<CodewireClient, ShellError> {
    for (name, value) in [
        ("server URL", &target.server_url),
        ("access token", &target.access_token),
        ("organization", &target.org_id),
        ("environment", &target.environment_id),
    ] {
        if value.trim().is_empty() {
            return Err(ShellError::Invalid {
                message: format!("the {name} is empty"),
            });
        }
    }
    let config = ClientConfig::new(&target.server_url)?;
    let token = StaticTokenProvider::new(target.access_token.clone())?;
    Ok(CodewireClient::new(config, token)?)
}

/// Run the shell on a thread of its own until it ends or the app closes it.
fn spawn_shell(
    client: CodewireClient,
    target: ShellTarget,
    mut terminal: ChannelTerminal,
    stopped: oneshot::Receiver<()>,
    observer: Arc<dyn ShellObserver>,
) -> Result<(), ShellError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ShellError::Unavailable {
            message: format!("start the shell's runtime: {error}"),
        })?;
    std::thread::Builder::new()
        .name("codewire-shell".into())
        .spawn(move || {
            let launch = ShellLaunch {
                command: LOGIN_SHELL.map(String::from).to_vec(),
                term: target.term.clone(),
                columns: target.columns,
                rows: target.rows,
            };
            let ended = runtime.block_on(async {
                tokio::select! {
                    ended = hosted_shell::run(
                        &client,
                        &target.org_id,
                        &target.environment_id,
                        launch,
                        &mut terminal,
                    ) => Some(ended),
                    _ = stopped => None,
                }
            });
            let mut failed = None;
            let state = match ended {
                Some(Ok(status)) => ShellState::Ended {
                    exit_status: Some(status),
                    error: None,
                },
                Some(Err(error)) => {
                    let error = ShellError::from(error);
                    let message = error.to_string();
                    failed = Some(error);
                    ShellState::Ended {
                        exit_status: None,
                        error: Some(message),
                    }
                }
                None => ShellState::Ended {
                    exit_status: None,
                    error: None,
                },
            };
            let first_attachment = terminal.attached.take();
            terminal.connected.store(false, Ordering::Release);
            // Reads end once the output sender is gone.
            drop(terminal);
            observer.state_changed(state);
            // A shell that ended before it attached fails `dial`, once its
            // observer has heard the end.
            if let (Some(first_attachment), Some(error)) = (first_attachment, failed) {
                let _ = first_attachment.send(Err(error));
            }
        })
        .map_err(|error| ShellError::Unavailable {
            message: format!("start the shell's thread: {error}"),
        })?;
    Ok(())
}

/// The app's end of a hosted shell, over channels.
struct ChannelTerminal {
    keys: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    sizes: watch::Receiver<(u16, u16)>,
    output: mpsc::Sender<Vec<u8>>,
    connected: Arc<AtomicBool>,
    observer: Arc<dyn ShellObserver>,
    /// Answers `dial` at the first attachment.
    attached: Option<oneshot::Sender<Result<(), ShellError>>>,
}

impl ShellTerminal for ChannelTerminal {
    type Keys = KeyReceiver;
    type Sizes = SizeWatch;
    type Output = OutputSender;

    async fn attach(
        &mut self,
    ) -> anyhow::Result<AttachedTerminal<KeyReceiver, SizeWatch, OutputSender>> {
        Ok(AttachedTerminal {
            keys: KeyReceiver(self.keys.clone().lock_owned().await),
            sizes: SizeWatch(self.sizes.clone()),
            output: OutputSender(self.output.clone()),
        })
    }

    fn notice(&mut self, notice: ShellNotice) {
        let state = match notice {
            ShellNotice::Attached(via) => {
                if !self.connected.swap(true, Ordering::AcqRel) {
                    // Keys queued before the drop was noticed are dropped too.
                    if let Ok(mut keys) = self.keys.try_lock() {
                        while keys.try_recv().is_ok() {}
                    }
                }
                if let Some(attached) = self.attached.take() {
                    let _ = attached.send(Ok(()));
                }
                connected_state(via)
            }
            ShellNotice::Reconnecting => {
                self.connected.store(false, Ordering::Release);
                ShellState::Reconnecting {
                    reason: "the connection dropped".into(),
                }
            }
        };
        self.observer.state_changed(state);
    }
}

fn connected_state(via: Via) -> ShellState {
    match via {
        Via::Tailnet(Some(report)) => ShellState::Connected {
            path: match report.path {
                TailnetPath::DirectUdp => ShellPath::DirectUdp,
                TailnetPath::PeerRelay => ShellPath::Relay,
                TailnetPath::Derp => ShellPath::Derp,
            },
            reason: report.reason,
        },
        Via::Tailnet(None) => ShellState::Connected {
            path: ShellPath::Tailnet,
            reason: None,
        },
        Via::Api {
            tailnet_unavailable,
        } => ShellState::Connected {
            path: ShellPath::Api,
            reason: Some(tailnet_unavailable),
        },
    }
}

/// The app's keys, held for one attachment.
struct KeyReceiver(tokio::sync::OwnedMutexGuard<mpsc::UnboundedReceiver<Vec<u8>>>);

impl TerminalKeys for KeyReceiver {
    async fn read(&mut self) -> Option<Vec<u8>> {
        self.0.recv().await
    }
}

struct SizeWatch(watch::Receiver<(u16, u16)>);

impl TerminalSizes for SizeWatch {
    fn current(&mut self) -> Option<(u16, u16)> {
        Some(*self.0.borrow_and_update())
    }

    async fn changed(&mut self) -> Option<(u16, u16)> {
        if self.0.changed().await.is_err() {
            // The app has let go of the shell; it can say no more.
            return std::future::pending().await;
        }
        Some(*self.0.borrow_and_update())
    }
}

struct OutputSender(mpsc::Sender<Vec<u8>>);

impl TerminalOutput for OutputSender {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.0
            .send(data.to_vec())
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "bindgen"))]
mod swift_bindings_tests;
