//! The OpenSSH local forward `cw desktop` holds: a loopback port on this
//! computer to the desktop's VNC listener, through the environment's managed
//! alias (`docs/dev/SANDBOX-DESKTOP.md`, "`cw desktop`").

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use codewire_daemon_proto::DESKTOP_VNC_PORT;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

/// How long the forward may take to carry the desktop's greeting: OpenSSH
/// starts, reaches the environment and opens the channel.
const READY_WAIT: Duration = Duration::from_secs(45);
const READY_POLL: Duration = Duration::from_millis(250);
/// One attempt to read the greeting through the forward.
const GREETING_WAIT: Duration = Duration::from_secs(5);
/// How long OpenSSH gets to end by itself once asked.
const CLOSE_WAIT: Duration = Duration::from_secs(3);

/// What every VNC server says first.
const GREETING_PREFIX: &[u8; 4] = b"RFB ";

#[derive(Debug, thiserror::Error)]
pub(super) enum ForwardError {
    #[error("`cw desktop` connects through OpenSSH, and no `ssh` is on PATH; install OpenSSH")]
    NoSsh,
    #[error("start ssh")]
    Spawn(#[source] std::io::Error),
    #[error("find a free port on this computer")]
    Port(#[source] std::io::Error),
    /// OpenSSH ended before the desktop answered; it said why on stderr.
    #[error("the connection to the environment ended before the desktop answered")]
    Ended,
    #[error("the desktop did not answer through the connection in time")]
    NotReady,
    #[error("something other than the desktop answers on the environment's port 5901")]
    NotADesktop,
}

/// A running forward. Dropping it ends OpenSSH; [`Forward::close`] also
/// waits for it, and for the proxy command it started.
pub(super) struct Forward {
    ssh: Child,
    port: u16,
}

impl Forward {
    /// Starts OpenSSH forwarding a free loopback port to the desktop
    /// behind `alias`. [`Forward::ready`] says when the desktop answers
    /// through it.
    pub(super) async fn spawn(alias: &str) -> Result<Self, ForwardError> {
        let port = free_loopback_port().await.map_err(ForwardError::Port)?;
        let mut command = crate::process::tokio_command("ssh", &[]);
        command.args(ssh_arguments(alias, port));
        Self::start(command, port)
    }

    fn start(mut command: Command, port: u16) -> Result<Self, ForwardError> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true);
        // Its own group, so the terminal's Ctrl-C reaches `cw` alone and the
        // forward ends only when `cw` ends it. The managed alias never
        // prompts, so OpenSSH needs no terminal.
        #[cfg(unix)]
        command.process_group(0);
        let ssh = command.spawn().map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ForwardError::NoSsh,
            _ => ForwardError::Spawn(error),
        })?;
        Ok(Self { ssh, port })
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }

    /// Waits until a connection through the forward is greeted by a VNC
    /// server, which proves the whole path and not only OpenSSH's listener.
    pub(super) async fn ready(&mut self) -> Result<(), ForwardError> {
        self.ready_within(READY_WAIT).await
    }

    async fn ready_within(&mut self, within: Duration) -> Result<(), ForwardError> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if !matches!(self.ssh.try_wait(), Ok(None)) {
                return Err(ForwardError::Ended);
            }
            match tokio::time::timeout(GREETING_WAIT, greeting(self.port)).await {
                Ok(Some(greeted)) if &greeted == GREETING_PREFIX => return Ok(()),
                Ok(Some(_)) => return Err(ForwardError::NotADesktop),
                // Not listening yet, or the channel is not open yet.
                Ok(None) | Err(_) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ForwardError::NotReady);
            }
            tokio::time::sleep(READY_POLL).await;
        }
    }

    /// Resolves when OpenSSH ends by itself.
    pub(super) async fn ended(&mut self) {
        // An error here means the child cannot be waited on, which is an
        // ended forward as far as the caller can act on it.
        self.ssh.wait().await.ok();
    }

    /// Ends OpenSSH and waits for it. It is asked first, so that it ends the
    /// proxy command it started, and killed if it does not go.
    pub(super) async fn close(mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(group) = self
            .ssh
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            // A group that is already gone needs no signal.
            rustix::process::kill_process_group(group, rustix::process::Signal::TERM).ok();
            if tokio::time::timeout(CLOSE_WAIT, self.ssh.wait())
                .await
                .is_ok()
            {
                return;
            }
            rustix::process::kill_process_group(group, rustix::process::Signal::KILL).ok();
        }
        // The process is reaped by the runtime if this wait is cut short.
        self.ssh.kill().await.ok();
    }
}

/// OpenSSH's arguments for the forward alone: no command, no terminal, and
/// an exit instead of a session when the port cannot be bound. Both ends are
/// loopback addresses, spelled out so no option of the user's widens them.
fn ssh_arguments(alias: &str, port: u16) -> [String; 6] {
    [
        "-N".to_owned(),
        "-o".to_owned(),
        "ExitOnForwardFailure=yes".to_owned(),
        "-L".to_owned(),
        format!("127.0.0.1:{port}:127.0.0.1:{DESKTOP_VNC_PORT}"),
        alias.to_owned(),
    ]
}

/// A loopback port nothing listens on now. OpenSSH binds it a moment later
/// and exits if something else took it first.
async fn free_loopback_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok(listener.local_addr()?.port())
}

/// The first four bytes a connection to loopback `port` is sent, or `None`
/// when nothing accepts it or it closes first.
async fn greeting(port: u16) -> Option<[u8; 4]> {
    let mut connection = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .ok()?;
    let mut greeted = [0; 4];
    connection.read_exact(&mut greeted).await.ok()?;
    Some(greeted)
}

#[cfg(test)]
mod tests;
