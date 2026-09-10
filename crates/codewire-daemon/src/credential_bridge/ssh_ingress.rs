//! Selected agent socket ownership; signing and pending operations remain in
//! the shared bridge and its admitted authority. No provider bytes enter here.

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use super::{CredentialBridge, SocketGuard, chown_socket};
use crate::CredentialBridgeConfig;

const MAX_CONNECTIONS: usize = 8;
const SOCKET_NAME: &str = "ssh-agent.sock";

pub(super) struct SshIngress {
    listener: UnixListener,
    uid: u32,
    permits: Arc<Semaphore>,
    // An admitted stream retains exact socket ownership until it terminates,
    // including when the containing ingress serve future is dropped.
    pub(super) socket: Arc<SocketGuard>,
}

impl SshIngress {
    pub(super) fn prepare(config: &CredentialBridgeConfig) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let path = config
            .ingress_socket
            .parent()
            .ok_or_else(|| io::Error::other("SSH ingress parent is unavailable"))?
            .join(SOCKET_NAME);
        if path == config.ingress_socket {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH and HTTP ingress paths collide",
            ));
        }
        // Never unlink an occupied pathname, even a stale socket. Runtime
        // directory recovery belongs to its existing trusted placement owner.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "SSH ingress path is occupied",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let socket = Arc::new(SocketGuard {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        std::fs::set_permissions(&socket.path, std::fs::Permissions::from_mode(0o600))?;
        chown_socket(&socket.path, config.ingress_uid, config.ingress_gid)?;
        Ok(Self {
            listener,
            uid: config.ingress_uid,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            socket,
        })
    }

    // The accept loop is deliberately NOT a tracked task: its containing
    // ingress coordinator closes and waits that same owner during shutdown.
    pub(super) async fn serve(
        self,
        owner: CredentialBridge,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let bridge = owner
            .shared()
            .map_err(|_| io::Error::other("SSH ingress bridge is unavailable"))?
            .clone();
        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                () = owner.owner.shutdown.cancelled() => return Ok(()),
                accepted = self.listener.accept() => accepted,
            };
            let (stream, _) = match accepted {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(io::Error::other("SSH ingress listener failed")),
            };
            if !stream.peer_cred().is_ok_and(|peer| peer.uid() == self.uid) {
                continue;
            }
            let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                continue;
            };
            let accepting = tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                () = owner.owner.shutdown.cancelled() => return Ok(()),
                accepting = owner.owner.accepting.lock() => accepting,
            };
            if !*accepting || owner.owner.shutdown.is_cancelled() {
                return Ok(());
            }
            let bridge = bridge.clone();
            let stopped = owner.owner.shutdown.clone();
            let socket = self.socket.clone();
            drop(owner.owner.tasks.spawn(async move {
                let _permit = permit;
                let _socket = socket;
                // Peer framing, expiry and cancellation are per-connection
                // outcomes. Do not log operation inputs or response contents.
                let _ = codewire_credential_bridge::serve_ssh_agent(
                    &bridge,
                    stream,
                    stopped.cancelled_owned(),
                )
                .await;
            }));
            drop(accepting);
        }
    }
}

#[cfg(test)]
mod tests;
