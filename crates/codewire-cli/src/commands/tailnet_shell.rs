//! Plain `cw shell ENV` on a hosted environment (owner, 2026-11-01, on
//! #3827): a normal shell, as `ssh` opens one, over the environment's
//! tailnet: direct UDP whenever it can work, then peer relay, then DERP.
//!
//! The shell belongs to this connection. It survives a short blip, because
//! WireGuard roams under the open SSH connection, and it ends with `exit` or
//! when the connection is lost. `cw shell --durable` keeps a named session
//! that outlives the client instead.

use std::io::IsTerminal as _;

use codewire_client::CodewireClient;
use codewire_client::tailnet_session::{EnvironmentTailnet, InteractiveShell, ShellEvent};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::sessions::{TAILNET_DIRECT_WAIT, tailnet_path_line};
use crate::terminal_attach::{RawModeGuard, WindowSizeWatch, terminal_size};

/// Connect over the tailnet and open the shell. An error here means the
/// tailnet could not carry it, and nothing has been shown to the user yet.
pub(crate) async fn connect(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<(EnvironmentTailnet, InteractiveShell)> {
    let tailnet = EnvironmentTailnet::connect(client, org_id, environment_id).await?;
    let path = tailnet.wait_for_direct(TAILNET_DIRECT_WAIT).await.ok();
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (columns, rows) = interactive
        .then(terminal_size)
        .and_then(Result::ok)
        .unwrap_or((80, 24));
    let term = std::env::var("TERM")
        .ok()
        .filter(|term| !term.is_empty())
        .unwrap_or_else(|| "xterm-256color".into());
    let shell = tailnet
        .open_shell(&term, columns.into(), rows.into())
        .await?;
    eprintln!("{}", tailnet_path_line(path));
    Ok((tailnet, shell))
}

/// Run the shell to its end. Returns the shell's exit status.
pub(crate) async fn run(
    _tailnet: EnvironmentTailnet,
    shell: InteractiveShell,
) -> anyhow::Result<u32> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let raw = interactive.then(RawModeGuard::enable).transpose()?;
    let mut window = WindowSizeWatch::new(interactive);
    let InteractiveShell { input, mut output } = shell;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut buffer = [0_u8; 4096];
    let mut stdin_open = true;
    let mut exit = None;
    loop {
        tokio::select! {
            read = stdin.read(&mut buffer), if stdin_open => match read {
                Ok(0) | Err(_) => {
                    stdin_open = false;
                    let _ = input.close().await;
                }
                Ok(read) => input.write(&buffer[..read]).await?,
            },
            size = window.changed() => {
                if let Some((columns, rows)) = size {
                    let _ = input.resize(columns.into(), rows.into()).await;
                }
            }
            event = output.next() => match event {
                Some(ShellEvent::Stdout(data)) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Some(ShellEvent::Stderr(data)) => {
                    stderr.write_all(&data).await?;
                    stderr.flush().await?;
                }
                Some(ShellEvent::Exit(status)) => exit = Some(status),
                None => break,
            },
        }
    }
    drop(raw);
    exit.ok_or_else(|| anyhow::anyhow!("the connection to the environment was lost"))
}
