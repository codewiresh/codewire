//! Guest-init Unix-socket relay for hosted sleep control (#5638).
//!
//! Hosted `standard` containers deny `AF_VSOCK` via seccomp so no process
//! inside the container can dial guest-host vsock channels directly. Guest
//! init listens on a private Unix socket owned by the workspace user, checks
//! each caller's `SO_PEERCRED` PID against root-namespace `/proc/<pid>/cgroup`
//! (`freezer:/workload`), answers `check-frozen\n` locally (`ok\n`/`no\n`)
//! without dialing the host, and forwards only the fixed sleep-control
//! requests (`suspend\n`, `hibernate\n`, `rebind-ok\n`) to
//! [`HOSTED_SUSPEND_VSOCK_PORT`].

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
    HOSTED_CHECK_FROZEN_REQUEST, HOSTED_HIBERNATE_REQUEST, HOSTED_REBIND_COMPLETE_REQUEST,
    HOSTED_SLEEP_MAX_REQUEST_LEN, HOSTED_SUSPEND_ACCEPTED, HOSTED_SUSPEND_EXCHANGE,
    HOSTED_SUSPEND_REFUSED, HOSTED_SUSPEND_REQUEST, HOSTED_SUSPEND_VSOCK_PORT,
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
        let peer_frozen = peer_in_frozen_workload(&stream);
        let _ = tokio::time::timeout(
            HOSTED_SUSPEND_EXCHANGE,
            forward_sleep_request(stream, peer_frozen, dial_host_suspend),
        )
        .await;
    }
}

/// Checks via `SO_PEERCRED` whether the connecting peer process sits inside
/// the root cgroup namespace's `/workload` freezer cgroup. Guest init runs in
/// the root cgroup namespace, so `/proc/<pid>/cgroup` exposes the true v1
/// freezer path even when `CODEWIRE_WORKSPACE_INIT=systemd` unshared a cgroup
/// namespace inside the workspace container. Fails closed on any missing cred,
/// non-positive PID, unreadable cgroup file, or non-`/workload` freezer path.
fn peer_in_frozen_workload(stream: &tokio::net::UnixStream) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    let Some(pid) = cred.pid() else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    let path = format!("/proc/{pid}/cgroup");
    cgroup_file_in_frozen_workload(Path::new(&path))
}

fn cgroup_file_in_frozen_workload(path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    cgroup_contents_in_frozen_workload(&contents)
}

fn cgroup_contents_in_frozen_workload(contents: &str) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        controllers
            .split(',')
            .any(|controller| controller == "freezer")
            && (path == "/workload"
                || path
                    .strip_prefix("/workload")
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

async fn dial_host_suspend() -> io::Result<VsockStream> {
    VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, HOSTED_SUSPEND_VSOCK_PORT)).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SleepCommand {
    /// Answered locally from `SO_PEERCRED` + root-namespace `/proc/<pid>/cgroup`;
    /// never forwarded to the host vsock listener.
    CheckFrozen,
    /// Relayed verbatim to [`HOSTED_SUSPEND_VSOCK_PORT`] only when the peer sits
    /// in `/workload`.
    Forward(&'static [u8]),
}

/// Reads a single newline-terminated command bounded by
/// [`HOSTED_SLEEP_MAX_REQUEST_LEN`] and returns the exact static command
/// variant if it is in the fixed 4-command allowlist (`check-frozen\n`,
/// `suspend\n`, `hibernate\n`, `rebind-ok\n`). Returns `None` for any unknown,
/// incomplete, or overlong input so the relay never dials the host on
/// untrusted input.
async fn read_allowed_sleep_request<C>(client: &mut C) -> io::Result<Option<SleepCommand>>
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
    let allowed = if line == HOSTED_CHECK_FROZEN_REQUEST {
        Some(SleepCommand::CheckFrozen)
    } else if line == HOSTED_SUSPEND_REQUEST {
        Some(SleepCommand::Forward(HOSTED_SUSPEND_REQUEST))
    } else if line == HOSTED_HIBERNATE_REQUEST {
        Some(SleepCommand::Forward(HOSTED_HIBERNATE_REQUEST))
    } else if line == HOSTED_REBIND_COMPLETE_REQUEST {
        Some(SleepCommand::Forward(HOSTED_REBIND_COMPLETE_REQUEST))
    } else {
        None
    };
    Ok(allowed)
}

/// Validates one fixed sleep-control request from the container.
/// `check-frozen\n` is answered locally (`ok\n`/`no\n`) without dialing the
/// host. Forwarded sleep requests (`suspend\n`, `hibernate\n`, `rebind-ok\n`)
/// are refused locally with `no\n` (without dialing the host) unless the peer
/// is verified in root-namespace `/workload`. Any unknown or overlong input
/// closes unanswered without ever dialing the host.
async fn forward_sleep_request<C, H, F, Fut>(
    mut client: C,
    peer_frozen: bool,
    dial_host: F,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = io::Result<H>>,
{
    let Some(command) = read_allowed_sleep_request(&mut client).await? else {
        return Ok(());
    };
    let forward_bytes = match command {
        SleepCommand::CheckFrozen => {
            let reply = if peer_frozen {
                HOSTED_SUSPEND_ACCEPTED
            } else {
                HOSTED_SUSPEND_REFUSED
            };
            client.write_all(reply).await?;
            client.flush().await?;
            return client.shutdown().await;
        }
        SleepCommand::Forward(bytes) => {
            if !peer_frozen {
                client.write_all(HOSTED_SUSPEND_REFUSED).await?;
                client.flush().await?;
                return client.shutdown().await;
            }
            bytes
        }
    };
    let mut host = dial_host().await?;
    host.write_all(forward_bytes).await?;
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
                    let relay = tokio::spawn(forward_sleep_request(
                        relay_client,
                        true,
                        move || async move { Ok(relay_host) },
                    ));
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
    fn relay_answers_check_frozen_locally_without_dialing_host() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (peer_frozen, expected_reply) in [
            (true, HOSTED_SUSPEND_ACCEPTED),
            (false, HOSTED_SUSPEND_REFUSED),
        ] {
            runtime.block_on(async move {
                let dialed = Arc::new(AtomicBool::new(false));
                let dialed_flag = Arc::clone(&dialed);
                let (mut client, relay_client) = tokio::io::duplex(64);
                let relay = tokio::spawn(forward_sleep_request(
                    relay_client,
                    peer_frozen,
                    move || async move {
                        dialed_flag.store(true, Ordering::SeqCst);
                        let (a, _b) = tokio::io::duplex(16);
                        Ok(a)
                    },
                ));
                client.write_all(HOSTED_CHECK_FROZEN_REQUEST).await.unwrap();
                client.flush().await.unwrap();
                let mut reply = [0_u8; 3];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, expected_reply);
                relay.await.unwrap().unwrap();
                assert!(!dialed.load(Ordering::SeqCst));
            });
        }
    }

    #[test]
    fn relay_refuses_forwarded_sleep_requests_outside_workload_without_dialing_host() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for command in [
            HOSTED_SUSPEND_REQUEST.as_slice(),
            HOSTED_HIBERNATE_REQUEST.as_slice(),
            HOSTED_REBIND_COMPLETE_REQUEST.as_slice(),
        ] {
            runtime.block_on(async move {
                let dialed = Arc::new(AtomicBool::new(false));
                let dialed_flag = Arc::clone(&dialed);
                let (mut client, relay_client) = tokio::io::duplex(64);
                let relay = tokio::spawn(forward_sleep_request(
                    relay_client,
                    false,
                    move || async move {
                        dialed_flag.store(true, Ordering::SeqCst);
                        let (a, _b) = tokio::io::duplex(16);
                        Ok(a)
                    },
                ));
                client.write_all(command).await.unwrap();
                client.flush().await.unwrap();
                let mut reply = [0_u8; 3];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, HOSTED_SUSPEND_REFUSED);
                relay.await.unwrap().unwrap();
                assert!(!dialed.load(Ordering::SeqCst));
            });
        }
    }

    #[test]
    fn cgroup_parser_accepts_only_freezer_under_workload() {
        assert!(cgroup_contents_in_frozen_workload(
            "1:cpuset,freezer,pids:/workload/workspace\n0::/workspace/init.scope\n"
        ));
        assert!(cgroup_contents_in_frozen_workload("2:freezer:/workload\n"));
        assert!(!cgroup_contents_in_frozen_workload("1:freezer:/\n"));
        assert!(!cgroup_contents_in_frozen_workload(
            "1:freezer:/workloads/x\n"
        ));
        assert!(!cgroup_contents_in_frozen_workload(
            "0::/workload/workspace\n"
        ));
        assert!(!cgroup_contents_in_frozen_workload(""));
    }

    #[test]
    fn peer_cred_check_fails_closed_for_process_outside_workload() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("sleep.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let client_task = tokio::spawn(async move {
                let _client = tokio::net::UnixStream::connect(&sock).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            });
            let (server, _) = listener.accept().await.unwrap();
            let cred = server.peer_cred().unwrap();
            assert!(cred.pid().is_some_and(|pid| pid > 0));
            // The test runner is not inside `/workload` in the root freezer hierarchy.
            assert!(!peer_in_frozen_workload(&server));
            client_task.await.unwrap();
        });
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
            b"check-frozen".as_slice(),
        ] {
            runtime.block_on(async move {
                let dialed = Arc::new(AtomicBool::new(false));
                let dialed_flag = Arc::clone(&dialed);
                let (mut client, relay_client) = tokio::io::duplex(64);
                let relay = tokio::spawn(forward_sleep_request(
                    relay_client,
                    true,
                    move || async move {
                        dialed_flag.store(true, Ordering::SeqCst);
                        let (a, _b) = tokio::io::duplex(16);
                        Ok(a)
                    },
                ));
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
            let relay = tokio::spawn(forward_sleep_request(
                relay_client,
                true,
                move || async move { Ok(relay_host) },
            ));
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
