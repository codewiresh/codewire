//! Supervisor admission by owner-only socket, not by process birth.
//!
//! Darwin exposes no socket-derived process handle. This pin keeps the
//! socket's identity and requires every connection's peer to be the owning
//! user; configuration-aware callers then require the expected configuration
//! digest over the protocol. It never adopts or signals the peer process.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixStream;

use super::path::{SocketIdentity, current_uid};
use crate::supervisor_config::NativeRuntimeConfig;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerError {
    #[error("kernel socket peer credentials are unavailable")]
    Kernel,
    #[error("native supervisor socket or owner identity changed")]
    Identity,
}

/// Opaque and shared: reconnects cannot replace its socket identity.
#[derive(Debug)]
pub(crate) struct SupervisorPeerPin {
    socket: PathBuf,
    socket_identity: SocketIdentity,
    configuration_digest: Option<[u8; 32]>,
}

impl SupervisorPeerPin {
    pub(crate) fn capture(
        stream: &UnixStream,
        socket: &Path,
        socket_identity: SocketIdentity,
        requested: Option<&NativeRuntimeConfig>,
    ) -> Result<Arc<Self>, PeerError> {
        let pin = Self {
            socket: socket.to_owned(),
            socket_identity,
            configuration_digest: requested.map(NativeRuntimeConfig::configuration_digest),
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
            .map_err(|_| PeerError::Identity)
    }
}
