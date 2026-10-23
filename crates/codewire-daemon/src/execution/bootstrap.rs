//! One-boot launcher channels. The socket is never mounted into the workload;
//! only the outer guest PID 1 can request the three finite startup phases.

use std::future::Future;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use codewire_workload_secrets::launcher::now_unix_ms;
use codewire_workload_secrets::{PROJECTION_REQUEST_LIFETIME_MS, ProjectionContext};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use super::*;
use crate::config::Config;
use crate::credential_bridge::CredentialBridge;

pub const BOOTSTRAP_PROJECTION_SOCKET_NAME: &str = "bootstrap-projection.sock";
pub const BOOTSTRAP_FINISH: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapPhase {
    Install = 1,
    Image = 2,
    Startup = 3,
}
impl BootstrapPhase {
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Install),
            2 => Some(Self::Image),
            3 => Some(Self::Startup),
            _ => None,
        }
    }
}

pub(crate) struct StartupProjectionIngress {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    environment_id: [u8; 16],
    generation: u64,
    selection: [u8; 32],
    bridge: CredentialBridge,
}

impl StartupProjectionIngress {
    pub(crate) fn prepare(config: &Config, bridge: CredentialBridge) -> io::Result<Option<Self>> {
        let (ProcessExecution::Runc(runc), Some(selection)) =
            (&config.process_execution, &config.launch_projection)
        else {
            return Ok(None);
        };
        let identity = config.credential_bridge.as_ref().ok_or_else(denied)?;
        validate_process_directory(&runc.process_directory)?;
        let path = runc
            .process_directory
            .join(BOOTSTRAP_PROJECTION_SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let ingress = Self {
            listener,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            environment_id: *identity.environment_id.as_bytes(),
            generation: identity.environment_generation,
            selection: selection.selection_sha256,
            bridge,
        };
        fs::set_permissions(&ingress.path, fs::Permissions::from_mode(0o600))?;
        ingress.context()?;
        Ok(Some(ingress))
    }

    fn context(&self) -> io::Result<ProjectionContext> {
        let context = ProjectionContext {
            environment_id: self.environment_id,
            operation_generation: self.generation,
            selection_sha256: self.selection,
            deadline_unix_ms: now_unix_ms()?
                .checked_add(PROJECTION_REQUEST_LIFETIME_MS)
                .ok_or_else(denied)?,
        };
        context.validate_at(now_unix_ms()?).map_err(|_| denied())?;
        Ok(context)
    }

    pub(crate) async fn serve(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        self.serve_for_peer(shutdown, 1, 0).await
    }

    async fn serve_for_peer(
        self,
        shutdown: impl Future<Output = ()>,
        expected_pid: u32,
        expected_uid: u32,
    ) -> io::Result<()> {
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        let mut used = 0_u8;
        let outcome = async {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown => return Ok(()),
                    joined = tasks.join_next(), if !tasks.is_empty() => {
                        joined.ok_or_else(denied)?.map_err(|_| denied())??;
                    }
                    accepted = self.listener.accept() => {
                        let (mut channel, _) = accepted?;
                        let peer = channel.peer_cred()?;
                        if peer.uid() != expected_uid || peer.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(expected_pid) { continue; }
                        let pid = Pid::from_raw(i32::try_from(expected_pid).map_err(|_| denied())?).ok_or_else(denied)?;
                        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).map_err(io::Error::from)?;
                        // RUSTSEC-2026-0386: an owned `OwnedFd` is outside `AsyncFd::new`'s unsound case; `register` migration is #3249.
                        #[allow(deprecated)]
                        let life = AsyncFd::new(pidfd)?;
                        let mut phase = [0];
                        tokio::select! {
                            biased;
                            _ = &mut shutdown => return Ok(()),
                            _ = life.readable() => return Err(denied()),
                            result = tokio::time::timeout(std::time::Duration::from_secs(1), channel.read_exact(&mut phase)) => { result.map_err(|_| denied())??; }
                        }
                        if phase[0] == BOOTSTRAP_FINISH {
                            // Finish is cancellation-safe and closes the entire
                            // boot-only listener; it cannot reopen a phase.
                            tasks.abort_all();
                            while tasks.join_next().await.is_some() {}
                            tokio::select! {
                                _ = &mut shutdown => return Ok(()),
                                result = tokio::time::timeout(std::time::Duration::from_secs(1), channel.write_all(&[BOOTSTRAP_FINISH])) => { result.map_err(|_| denied())??; }
                            }
                            return Ok(());
                        }
                        let phase = BootstrapPhase::from_byte(phase[0]).ok_or_else(denied)?;
                        let bit = 1 << (phase as u8 - 1);
                        if used & bit != 0 { return Err(denied()); }
                        used |= bit;
                        let context = self.context()?;
                        let bridge = self.bridge.clone();
                        tasks.spawn(async move {
                            let overrides = Default::default();
                            // Startup bootstrap records no denial; its own
                            // outcome is the daemon's start.
                            let committed = std::sync::atomic::AtomicBool::new(false);
                            tokio::select! {
                                biased;
                                _ = life.readable() => Err(denied()),
                                // Bootstrap has no per-command overrides. The
                                // broker already omits declared project keys;
                                // image defaults must remain below app values.
                                result = super::projection::relay_accepted_launch(channel, context, &bridge, true, &overrides, &committed) => result,
                            }
                        });
                    }
                }
            }
        }.await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        outcome
    }
}

impl Drop for StartupProjectionIngress {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "bootstrap environment launch denied or expired",
    )
}

#[cfg(test)]
mod tests;
