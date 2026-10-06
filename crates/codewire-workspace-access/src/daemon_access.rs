//! Workspace access served by the bound workspace daemon itself (#2460).
//!
//! The daemon runs the SSH server (with SFTP and SCP) in its own process and
//! reaches its sessions over the in-process transport, so no per-environment
//! gateway is needed. Its SSH host key is generated per binding generation,
//! never leaves the VM, and only its public line is recorded with
//! orchestration, write-once, through the Pod-bound binding exchange.

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codewire_daemon::access::WorkspaceAccessGrant;
use russh::server;
use ssh_key::{LineEnding, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::daemon::DaemonSessionClient;
use crate::host_key::generate_ed25519_key;
use crate::scp::DaemonScpRunner;
use crate::sftp::DaemonSftpRunner;
use crate::ssh::{DaemonBackedSshRunner, GatewaySshHandler, gateway_server_config};

const HOST_KEY_PREFIX: &str = "ssh_host_ed25519_g";
const HOST_KEY_MODE: u32 = 0o400;
const STATE_DIRECTORY_MODE: u32 = 0o700;

/// Owner-only host keys under the daemon's state directory, one per binding
/// generation. A daemon restarted in the same Pod reuses its generation's
/// key, so the recorded public key stays valid.
#[derive(Clone, Debug)]
pub struct HostKeyStore {
    directory: PathBuf,
}

impl HostKeyStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// This generation's key: reloaded when present, otherwise generated and
    /// written owner-read-only. Keys of other generations are removed.
    pub fn for_generation(&self, generation: u64) -> io::Result<PrivateKey> {
        ensure_private_directory(&self.directory)?;
        let path = self.path(generation);
        let key = match fs::read(&path) {
            Ok(bytes) => {
                let key = PrivateKey::from_openssh(&bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid host key"))?;
                if key.algorithm() != ssh_key::Algorithm::Ed25519 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host key must be Ed25519",
                    ));
                }
                key
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let key = generate_ed25519_key();
                let encoded = key
                    .to_openssh(LineEnding::LF)
                    .map_err(|_| io::Error::other("encode host key"))?;
                write_owner_only(&path, encoded.as_bytes())?;
                key
            }
            Err(error) => return Err(error),
        };
        self.remove_other_generations(generation)?;
        Ok(key)
    }

    fn path(&self, generation: u64) -> PathBuf {
        self.directory
            .join(format!("{HOST_KEY_PREFIX}{generation}"))
    }

    fn remove_other_generations(&self, generation: u64) -> io::Result<()> {
        let keep = format!("{HOST_KEY_PREFIX}{generation}");
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(HOST_KEY_PREFIX) && name != keep {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

/// The public key line orchestration records: `ssh-ed25519 <base64>`, with
/// no comment.
pub fn public_key_line(key: &PrivateKey) -> String {
    let mut public = key.public_key().clone();
    public.set_comment("");
    public
        .to_openssh()
        .expect("an Ed25519 public key always encodes")
}

/// One UDP peer-relay allocation orchestration made for this daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRelayAllocation {
    pub relay_generation: u32,
    pub server_disco_key: String,
    pub disco_keys: Vec<String>,
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime_ns: u64,
    pub steady_state_lifetime_ns: u64,
    pub addr_ports: Vec<String>,
}

/// Why a control-plane call failed. Value-blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneError {
    /// Permanently refused (`failed_precondition`): for example, another
    /// host key is already recorded for this generation.
    #[error("refused by the control plane")]
    Refused,
    /// Unavailable or rejected for now; try again later.
    #[error("control plane unavailable")]
    Retryable,
}

/// The daemon's Pod-bound exchange with orchestration (the workspace-binding
/// listener on 8087).
#[async_trait]
pub trait AccessControlPlane: Send + Sync + 'static {
    async fn record_host_key(&self, public_key_openssh: &str) -> Result<(), ControlPlaneError>;
    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError>;
    async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError>;
}

/// Record the host key, retrying while the control plane is unavailable.
/// A refusal is permanent: another key is recorded for this generation, so
/// SSH must not be reported ready.
pub async fn record_host_key_until_accepted(
    plane: &dyn AccessControlPlane,
    public_key_openssh: &str,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Result<(), ControlPlaneError> {
    let mut backoff = initial_backoff;
    loop {
        match plane.record_host_key(public_key_openssh).await {
            Ok(()) => return Ok(()),
            Err(ControlPlaneError::Refused) => return Err(ControlPlaneError::Refused),
            Err(ControlPlaneError::Retryable) => {
                tracing::warn!(
                    retry_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                    "SSH host key not recorded yet; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// The daemon's SSH server configuration: the gateway's policy (transport-
/// authenticated `none` auth; agent, X11 and reverse forwarding refused) with
/// this generation's host key.
pub fn daemon_ssh_server_config(host_key: PrivateKey) -> server::Config {
    let mut config = gateway_server_config();
    config.keys.push(host_key);
    config
}

/// The SSH protocol runners backed by one daemon client.
#[derive(Clone)]
pub struct DaemonSshRunners {
    pub sessions: Arc<DaemonBackedSshRunner<DaemonSessionClient>>,
    pub sftp: Arc<DaemonSftpRunner<DaemonSessionClient>>,
    pub scp: Arc<DaemonScpRunner<DaemonSessionClient>>,
}

impl DaemonSshRunners {
    pub fn new(daemon: DaemonSessionClient) -> Self {
        Self {
            sessions: Arc::new(DaemonBackedSshRunner::new(daemon.clone())),
            sftp: Arc::new(DaemonSftpRunner::new(daemon.clone())),
            scp: Arc::new(DaemonScpRunner::new(daemon)),
        }
    }

    /// Serve one SSH connection to completion.
    pub async fn serve_stream<S>(&self, config: Arc<server::Config>, stream: S, peer: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler = GatewaySshHandler::with_file_protocols(
            self.sessions.clone(),
            Some(self.sftp.clone()),
            Some(self.scp.clone()),
        );
        match server::run_stream(config, stream, handler).await {
            Ok(session) => {
                let _ = session.await;
            }
            Err(error) => {
                tracing::warn!(peer, error = %error, "workspace SSH handshake failed");
            }
        }
    }
}

/// Accept SSH connections from `listener` until shutdown.
pub async fn serve_ssh_listener(
    listener: tokio::net::TcpListener,
    config: Arc<server::Config>,
    runners: DaemonSshRunners,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let _ = stream.set_nodelay(true);
                let config = config.clone();
                let runners = runners.clone();
                tokio::spawn(async move {
                    runners.serve_stream(config, stream, &peer.to_string()).await;
                });
            }
        }
    }
}

fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => {
            if metadata.permissions().mode() & 0o777 != STATE_DIRECTORY_MODE {
                fs::set_permissions(directory, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))?;
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host key directory is not a directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))
        }
        Err(error) => Err(error),
    }
}

/// Write `bytes` to `path` owner-read-only, atomically.
fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(HOST_KEY_MODE))?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
#[path = "daemon_access/tests.rs"]
mod tests;
