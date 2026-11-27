//! Guest-init Unix-socket relay for hosted sleep control (#5638).
//!
//! Hosted `standard` containers deny `AF_VSOCK` via seccomp so no process
//! inside the container can dial guest-host vsock channels directly. Guest
//! init listens on a private Unix socket owned by the workspace user and
//! forwards only the fixed sleep-control requests (`suspend\n`, `hibernate\n`,
//! `rebind-ok\n`) to [`HOSTED_SUSPEND_VSOCK_PORT`].

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::UnixListener;
use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

use super::create_owned_dir;
use crate::guest::lchown;
use crate::hosted_control::{
    HOSTED_HIBERNATE_REQUEST, HOSTED_REBIND_COMPLETE_REQUEST, HOSTED_SLEEP_MAX_REQUEST_LEN,
    HOSTED_SUSPEND_ACCEPTED, HOSTED_SUSPEND_EXCHANGE, HOSTED_SUSPEND_REFUSED,
    HOSTED_SUSPEND_REQUEST, HOSTED_SUSPEND_VSOCK_PORT,
};

/// Guest-side directory holding the sleep-control relay socket, owned by the
/// workspace user (`0700`) and bind-mounted read-only into the container.
pub(super) const HOSTED_SLEEP_DIR: &str = "/run/codewire/hosted/sleep";
pub(super) const HOSTED_SLEEP_SOCKET_PATH: &str = "/run/codewire/hosted/sleep/control.sock";
/// Container-side mount point for [`HOSTED_SLEEP_DIR`], matching
/// [`crate::hosted_control::HOSTED_SLEEP_CONTROL_SOCKET_PATH`].
pub(super) const CONTAINER_SLEEP_DIR: &str = "/run/codewire-hosted/sleep";

/// Starts the sleep-control relay thread for the workspace user and waits
/// until the socket exists with `0600` ownership before the container starts.
pub(super) fn start(uid: u32, gid: u32) -> Result<()> {
    create_owned_dir(Path::new(HOSTED_SLEEP_DIR), uid, gid)?;
    match fs::remove_file(HOSTED_SLEEP_SOCKET_PATH) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error).context("remove stale hosted sleep control socket");
        }
        _ => {}
    }
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
    std::thread::Builder::new()
        .name("codewire-hosted-sleep".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    // The waiting side reports the failure.
                    let _ = ready_tx.send(Err(error.into()));
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match bind_owned_socket(uid, gid) {
                    Ok(listener) => listener,
                    Err(error) => {
                        // As above.
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                // The receiver waits for exactly this one message.
                let _ = ready_tx.send(Ok(()));
                serve(listener).await;
            });
        })
        .context("spawn the hosted sleep control relay")?;
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .context("wait for the hosted sleep control relay")??;
    Ok(())
}

fn bind_owned_socket(uid: u32, gid: u32) -> Result<UnixListener> {
    let socket_path = Path::new(HOSTED_SLEEP_SOCKET_PATH);
    let listener =
        UnixListener::bind(socket_path).context("bind the hosted sleep control socket")?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .context("restrict hosted sleep control socket mode")?;
    lchown(socket_path, uid, gid)?;
    Ok(listener)
}

/// Handles one sleep-control request at a time so the container cannot fan
/// out concurrent host vsock dials.
async fn serve(listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // An accept error such as EMFILE would otherwise spin.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = tokio::time::timeout(
            HOSTED_SUSPEND_EXCHANGE,
            forward_sleep_request(stream, dial_host_suspend),
        )
        .await;
    }
}

async fn dial_host_suspend() -> io::Result<VsockStream> {
    VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, HOSTED_SUSPEND_VSOCK_PORT)).await
}

/// Reads a single newline-terminated command bounded by
/// [`HOSTED_SLEEP_MAX_REQUEST_LEN`] and returns the exact static command
/// constant if it is in the fixed 3-command allowlist (`suspend\n`,
/// `hibernate\n`, `rebind-ok\n`). Returns `None` for any unknown, incomplete,
/// or overlong input so the relay never dials the host on untrusted input.
async fn read_allowed_sleep_request<C>(client: &mut C) -> io::Result<Option<&'static [u8]>>
where
    C: AsyncRead + Unpin,
{
    let mut buf = [0_u8; HOSTED_SLEEP_MAX_REQUEST_LEN];
    let mut len = 0_usize;
    loop {
        if len >= buf.len() {
            return Ok(None);
        }
        let mut byte = [0_u8; 1];
        let read = client.read(&mut byte).await?;
        if read == 0 {
            return Ok(None);
        }
        buf[len] = byte[0];
        len += 1;
        if byte[0] == b'\n' {
            break;
        }
    }
    let line = &buf[..len];
    let allowed: Option<&'static [u8]> = if line == HOSTED_SUSPEND_REQUEST {
        Some(HOSTED_SUSPEND_REQUEST)
    } else if line == HOSTED_HIBERNATE_REQUEST {
        Some(HOSTED_HIBERNATE_REQUEST)
    } else if line == HOSTED_REBIND_COMPLETE_REQUEST {
        Some(HOSTED_REBIND_COMPLETE_REQUEST)
    } else {
        None
    };
    Ok(allowed)
}

/// Validates one fixed sleep-control request from the container and relays it
/// to the host vsock suspend listener. Any other bytes close unanswered
/// without ever dialing the host.
async fn forward_sleep_request<C, H, F, Fut>(mut client: C, dial_host: F) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = io::Result<H>>,
{
    let Some(command) = read_allowed_sleep_request(&mut client).await? else {
        return Ok(());
    };
    let mut host = dial_host().await?;
    host.write_all(command).await?;
    host.flush().await?;
    let mut answer = [0_u8; HOSTED_SUSPEND_ACCEPTED.len()];
    host.read_exact(&mut answer).await?;
    if &answer != HOSTED_SUSPEND_ACCEPTED && &answer != HOSTED_SUSPEND_REFUSED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected host sleep control reply",
        ));
    }
    client.write_all(&answer).await?;
    client.flush().await?;
    client.shutdown().await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn relay_forwards_all_allowed_sleep_requests_and_replies() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let commands: [&[u8]; 3] = [
            HOSTED_SUSPEND_REQUEST,
            HOSTED_HIBERNATE_REQUEST,
            HOSTED_REBIND_COMPLETE_REQUEST,
        ];
        for command in commands {
            for expected_reply in [HOSTED_SUSPEND_ACCEPTED, HOSTED_SUSPEND_REFUSED] {
                runtime.block_on(async move {
                    let (mut client, relay_client) = tokio::io::duplex(64);
                    let (relay_host, mut host) = tokio::io::duplex(64);
                    let relay =
                        tokio::spawn(forward_sleep_request(relay_client, move || async move {
                            Ok(relay_host)
                        }));
                    let host_task = tokio::spawn(async move {
                        let mut got = vec![0_u8; command.len()];
                        host.read_exact(&mut got).await.unwrap();
                        assert_eq!(got.as_slice(), command);
                        host.write_all(expected_reply).await.unwrap();
                        host.flush().await.unwrap();
                    });
                    client.write_all(command).await.unwrap();
                    client.flush().await.unwrap();
                    let mut reply = [0_u8; 3];
                    client.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply, expected_reply);
                    relay.await.unwrap().unwrap();
                    host_task.await.unwrap();
                });
            }
        }
    }

    #[test]
    fn relay_drops_unknown_and_overlong_requests_without_dialing_host() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for payload in [
            b"destroy\n".as_slice(),
            b"hibernate-now-please-exceeding-limit\n".as_slice(),
            b"suspend".as_slice(),
        ] {
            runtime.block_on(async move {
                let dialed = Arc::new(AtomicBool::new(false));
                let dialed_flag = Arc::clone(&dialed);
                let (mut client, relay_client) = tokio::io::duplex(64);
                let relay = tokio::spawn(forward_sleep_request(relay_client, move || async move {
                    dialed_flag.store(true, Ordering::SeqCst);
                    let (a, _b) = tokio::io::duplex(16);
                    Ok(a)
                }));
                client.write_all(payload).await.unwrap();
                client.flush().await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                client.read_to_end(&mut reply).await.unwrap();
                assert!(reply.is_empty());
                relay.await.unwrap().unwrap();
                assert!(!dialed.load(Ordering::SeqCst));
            });
        }
    }

    #[test]
    fn relay_rejects_unexpected_host_reply() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut client, relay_client) = tokio::io::duplex(64);
            let (relay_host, mut host) = tokio::io::duplex(64);
            let relay = tokio::spawn(forward_sleep_request(relay_client, move || async move {
                Ok(relay_host)
            }));
            let host_task = tokio::spawn(async move {
                let mut got = [0_u8; HOSTED_SUSPEND_REQUEST.len()];
                host.read_exact(&mut got).await.unwrap();
                host.write_all(b"??\n").await.unwrap();
                host.flush().await.unwrap();
            });
            client.write_all(HOSTED_SUSPEND_REQUEST).await.unwrap();
            client.flush().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert!(reply.is_empty());
            assert!(relay.await.unwrap().is_err());
            host_task.await.unwrap();
        });
    }
}
