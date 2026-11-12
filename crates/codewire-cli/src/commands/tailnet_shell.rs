//! Plain `cw shell ENV` on a hosted environment (owner, 2026-11-01, on
//! #3827): a normal shell, like `ssh`, over the environment's tailnet: direct
//! UDP whenever it can work, then peer relay, then DERP.
//!
//! The shell is an unnamed daemon session launched with a 10-minute grace:
//! after a drop (sleep, a Wi-Fi change) this `cw shell` reattaches from its
//! output offset and nothing is lost; it ends with `exit`, and the daemon
//! ends it once no client has been attached for 10 minutes, so abandoned
//! shells don't pile up. No session name, started line or detach hint is
//! shown, and every key, Ctrl+B included, reaches the shell.
//! `cw shell --durable` keeps a named session that outlives the client.
//!
//! The connection logic is `codewire_client::hosted_shell`, shared with the
//! other clients (#3825); this is its terminal.

use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use codewire_client::hosted_shell::{
    self, AttachedTerminal, HostedShellError, InputNotice, SHELL_GRACE, ShellLaunch, ShellNotice,
    ShellTerminal, TerminalKeys, TerminalOutput, TerminalSizes,
};
use codewire_client::{ClientError, CodewireClient, ErrorCode};
use tokio::io::AsyncWriteExt as _;

use super::platform_commands::display_client_error;
use super::sessions::{login_shell_command, login_shell_env, via_line};
use crate::terminal_attach::{
    RawModeGuard, TerminalInput, WindowSizeWatch, terminal_input, terminal_size,
};

/// An attachment that lasted this long was a working connection, so the next
/// drop is a new one even if the session printed nothing.
const RECONNECT_STAYED_UP: Duration = Duration::from_secs(30);

/// Whether a failed call says nothing about the session: the server wasn't
/// reached or didn't answer in time. Any other failure is the server's answer,
/// such as access removed or the session gone, and ending there is right.
pub(crate) fn is_network_failure(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ClientError>().is_some_and(|error| {
        error.is_retryable_transport_interruption() || error.code() == ErrorCode::DeadlineExceeded
    })
}

/// Paces an attachment to a hosted session while the network is down. The
/// session runs on in the environment, so a long cut is not a reason to leave
/// it (#3895): keep trying for as long as a plain shell would, then say how to
/// come back. A failing server looks the same as a dead network from here, so
/// this still ends: only output or a connection that stayed up starts it over.
#[derive(Default)]
pub(crate) struct ReconnectPacing {
    dropped_at: Option<Instant>,
    attached_at: Option<Instant>,
    last_output_offset: u64,
    attempt: u32,
}

impl ReconnectPacing {
    /// Whether a connection has dropped and not yet come back.
    pub(crate) fn reconnecting(&self) -> bool {
        self.dropped_at.is_some()
    }

    /// The server has answered this attachment.
    pub(crate) fn attached(&mut self) {
        self.attached_at = Some(Instant::now());
    }

    /// The connection is lost at `output_offset`: how long to wait before the
    /// next try, or `None` once the time to keep trying has run out.
    pub(crate) fn lost(&mut self, output_offset: u64) -> Option<Duration> {
        let stayed_up = self
            .attached_at
            .take()
            .is_some_and(|attached| attached.elapsed() >= RECONNECT_STAYED_UP);
        if stayed_up || output_offset > self.last_output_offset {
            self.dropped_at = None;
            self.attempt = 0;
        }
        self.last_output_offset = output_offset;
        if self.dropped_at.get_or_insert_with(Instant::now).elapsed() >= SHELL_GRACE {
            return None;
        }
        if self.attempt == 0 {
            eprintln!("[cw] connection lost; reconnecting to the same session");
        }
        self.attempt += 1;
        Some(Duration::from_millis(250 * u64::from(self.attempt.min(8))))
    }
}

/// Launch the shell and run it to its end. Returns its exit status.
pub(crate) async fn run(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<i32> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (columns, rows) = interactive
        .then(terminal_size)
        .and_then(Result::ok)
        .unwrap_or((80, 24));
    let term = std::env::var("TERM")
        .ok()
        .filter(|term| !term.is_empty())
        .unwrap_or_else(|| "xterm-256color".into());
    let launch = ShellLaunch {
        command: login_shell_command(),
        env: login_shell_env(),
        term,
        columns,
        rows,
    };
    hosted_shell::run(
        client,
        org_id,
        environment_id,
        launch,
        &mut ProcessTerminal { interactive },
    )
    .await
    .map_err(display_hosted_shell_error)
}

/// A hosted shell's failure, worded as `cw` words the server's answers.
pub(crate) fn display_hosted_shell_error(error: HostedShellError) -> anyhow::Error {
    match error {
        HostedShellError::Client(error) => display_client_error(error),
        HostedShellError::Other(error) => error,
    }
}

/// This process's terminal: raw mode while attached, keys from stdin, size
/// changes, and output to stdout; notices go to stderr.
struct ProcessTerminal {
    interactive: bool,
}

impl ShellTerminal for ProcessTerminal {
    type Keys = ProcessKeys;
    type Sizes = WindowSizeWatch;
    type Output = ProcessOutput;

    async fn attach(
        &mut self,
    ) -> anyhow::Result<AttachedTerminal<ProcessKeys, WindowSizeWatch, ProcessOutput>> {
        let raw = self.interactive.then(RawModeGuard::enable).transpose()?;
        let sizes = WindowSizeWatch::new(self.interactive);
        let stdin = terminal_input().await;
        Ok(AttachedTerminal {
            keys: ProcessKeys { _raw: raw, stdin },
            sizes,
            output: ProcessOutput(tokio::io::stdout()),
        })
    }

    fn notice(&mut self, notice: ShellNotice) {
        match notice {
            ShellNotice::Attached(via) => eprintln!("{}", via_line(&via)),
            ShellNotice::Reconnecting => {
                eprintln!("[cw] connection lost; reconnecting to the same shell");
            }
            ShellNotice::Input(InputNotice::Resent(keys)) => {
                eprintln!("[cw] resent {keys} key(s) typed during the drop");
            }
            ShellNotice::Input(InputNotice::Lost(keys)) => {
                eprintln!("[cw] {keys} key(s) typed during the drop were lost");
            }
        }
    }
}

/// Keys from stdin. Dropped first, it takes the terminal out of raw mode.
struct ProcessKeys {
    _raw: Option<RawModeGuard>,
    stdin: tokio::sync::MutexGuard<'static, TerminalInput>,
}

impl TerminalKeys for ProcessKeys {
    async fn read(&mut self) -> Option<Vec<u8>> {
        let mut buffer = [0_u8; 4096];
        match self.stdin.read(&mut buffer).await {
            Ok(0) | Err(_) => None,
            Ok(read) => Some(buffer[..read].to_vec()),
        }
    }
}

impl TerminalSizes for WindowSizeWatch {
    fn current(&mut self) -> Option<(u16, u16)> {
        WindowSizeWatch::current(self)
    }

    async fn changed(&mut self) -> Option<(u16, u16)> {
        WindowSizeWatch::changed(self).await
    }
}

struct ProcessOutput(tokio::io::Stdout);

impl TerminalOutput for ProcessOutput {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.0.write_all(data).await?;
        self.0.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_network_failure_is_worth_trying_again() {
        use crate::commands::platform_commands::display_client_error;
        let failure = |code| display_client_error(ClientError::new(code, "synthetic"));
        assert!(is_network_failure(&failure(ErrorCode::Unavailable)));
        assert!(is_network_failure(&failure(ErrorCode::DeadlineExceeded)));
        assert!(is_network_failure(
            &failure(ErrorCode::DeadlineExceeded).context("read the session")
        ));
        for answer in [
            ErrorCode::PermissionDenied,
            ErrorCode::NotFound,
            ErrorCode::Unauthenticated,
            ErrorCode::Internal,
        ] {
            assert!(!is_network_failure(&failure(answer)), "{answer:?}");
        }
        assert!(!is_network_failure(&anyhow::anyhow!("not from the server")));
        // connectrpc's error for a response cut off part way.
        let cut_off = connectrpc::ConnectError::internal(
            "failed to read response body: request or response body error",
        );
        assert!(is_network_failure(&display_client_error(cut_off.into())));
    }

    #[test]
    fn a_cut_is_retried_past_the_old_three_tries_with_growing_waits() {
        let mut pacing = ReconnectPacing::default();
        assert!(!pacing.reconnecting());
        let waits: Vec<_> = (0..10).map(|_| pacing.lost(42).unwrap()).collect();
        assert!(pacing.reconnecting());
        assert_eq!(waits[0], Duration::from_millis(250));
        assert_eq!(waits[1], Duration::from_millis(500));
        assert_eq!(waits[9], Duration::from_secs(2), "capped");
    }

    #[test]
    fn trying_ends_after_the_grace_with_no_output_or_lasting_connection() {
        let mut pacing = ReconnectPacing::default();
        assert!(pacing.lost(42).is_some());
        pacing.dropped_at = Some(Instant::now() - SHELL_GRACE);
        // A connection that opens and drops at once doesn't start it over.
        pacing.attached();
        assert_eq!(pacing.lost(42), None);
    }

    #[test]
    fn output_or_a_lasting_connection_starts_the_time_over() {
        let long_ago = Instant::now() - SHELL_GRACE;

        let mut progress = ReconnectPacing::default();
        assert!(progress.lost(42).is_some());
        progress.dropped_at = Some(long_ago);
        assert!(progress.lost(43).is_some());
        assert!(progress.dropped_at.is_some_and(|at| at > long_ago));

        let mut idle = ReconnectPacing::default();
        assert!(idle.lost(42).is_some());
        idle.dropped_at = Some(long_ago);
        idle.attached_at = Some(Instant::now() - RECONNECT_STAYED_UP);
        assert!(idle.lost(42).is_some());
        assert!(idle.dropped_at.is_some_and(|at| at > long_ago));
    }
}
