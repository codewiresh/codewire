//! Supervisor admission by owner-only socket and the peer's process birth.
//!
//! Darwin exposes no socket-derived process handle, but the kernel names the
//! peer's PID (`LOCAL_PEERPID`). This pin keeps the socket's identity and
//! requires every connection's peer to be the owning user. A
//! configuration-aware caller also pins the peer's birth and executable, and
//! then requires the expected configuration digest over the protocol. It never
//! adopts or signals the peer process.
//!
//! A cw update leaves a running supervisor on the managed version that started
//! it, and on macOS the VMs stop with their supervisor. As on Linux, a peer
//! whose executable is not this cw is admitted under that executable only when
//! the managed store retains it as a version with the same digest.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use codewire_cw_release::store::Store;
use tokio::net::UnixStream;

use super::path::{SocketIdentity, current_uid};
use super::process::ProcessIdentity;
use crate::supervisor_config::NativeRuntimeConfig;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerError {
    #[error("kernel socket peer credentials are unavailable")]
    Kernel,
    #[error("native supervisor socket or owner identity changed")]
    Identity,
    #[error("retained native supervisor executable provenance is unavailable or changed")]
    Provenance,
}

/// Opaque and shared: reconnects cannot replace its socket identity or peer.
#[derive(Debug)]
pub(crate) struct SupervisorPeerPin {
    socket: PathBuf,
    socket_identity: SocketIdentity,
    peer: Option<ProcessIdentity>,
    configuration_digest: Option<[u8; 32]>,
}

impl SupervisorPeerPin {
    pub(crate) fn capture(
        stream: &UnixStream,
        socket: &Path,
        socket_identity: SocketIdentity,
        requested: Option<&NativeRuntimeConfig>,
    ) -> Result<Arc<Self>, PeerError> {
        let (peer, configuration_digest) = match requested {
            None => (None, None),
            Some(requested) => {
                let peer =
                    ProcessIdentity::capture(peer_pid(stream)?).map_err(|_| PeerError::Identity)?;
                let config = if peer.executable == requested.executable {
                    requested.clone()
                } else {
                    admit_provenance(&peer)?;
                    requested
                        .with_supervisor_executable(peer.executable.clone())
                        .map_err(|_| PeerError::Identity)?
                };
                (Some(peer), Some(config.configuration_digest()))
            }
        };
        let pin = Self {
            socket: socket.to_owned(),
            socket_identity,
            peer,
            configuration_digest,
        };
        pin.revalidate_stream(stream)?;
        Ok(Arc::new(pin))
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn configuration_digest(&self) -> Option<[u8; 32]> {
        self.configuration_digest
    }

    pub(crate) fn revalidate_stream(&self, stream: &UnixStream) -> Result<(), PeerError> {
        let credential = stream.peer_cred().map_err(|_| PeerError::Kernel)?;
        if credential.uid() != current_uid() {
            return Err(PeerError::Identity);
        }
        self.socket_identity
            .revalidate(&self.socket)
            .map_err(|_| PeerError::Identity)?;
        if let Some(peer) = &self.peer
            && (peer_pid(stream)? != peer.pid
                || ProcessIdentity::capture(peer.pid).map_err(|_| PeerError::Identity)? != *peer)
        {
            return Err(PeerError::Identity);
        }
        Ok(())
    }
}

/// The peer's executable must be a version the managed store retains, with the
/// digest the store recorded for it.
fn admit_provenance(peer: &ProcessIdentity) -> Result<(), PeerError> {
    let root = Store::locate(&peer.executable).ok_or(PeerError::Provenance)?;
    let store = Store::open(&root, Duration::from_secs(1)).map_err(|_| PeerError::Provenance)?;
    let record = store
        .verify(&peer.executable_sha256)
        .map_err(|_| PeerError::Provenance)?;
    if store.version_executable(&record.sha256) != peer.executable
        || record.sha256 != peer.executable_sha256
        || record.size != peer.executable_file.size
    {
        return Err(PeerError::Provenance);
    }
    Ok(())
}

fn peer_pid(stream: &UnixStream) -> Result<u32, PeerError> {
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: a live socket descriptor and a writable pid_t-sized buffer
    // whose length is passed.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::pid_t>() {
        return Err(PeerError::Kernel);
    }
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(PeerError::Kernel)
}
