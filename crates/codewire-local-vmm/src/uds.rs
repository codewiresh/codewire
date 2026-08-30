use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

use crate::linux::path::{PrivateRoot, SocketIdentity, current_uid, set_socket_private};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
// OCI setup is a bounded lifecycle operation and can legitimately include
// large guest-side verification and layer application before daemon readiness.
// The transport must not expire before the runner's setup bound; lifecycle
// progress and cancellation remain separate operation-level concerns.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(21 * 60);

pub(crate) fn bind_owner_only(
    socket: &Path,
) -> Result<
    (
        impl Stream<Item = Result<UnixStream, io::Error>> + Send + 'static,
        SocketIdentity,
    ),
    UdsError,
> {
    let parent = socket
        .parent()
        .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?;
    let name = socket
        .file_name()
        .map(Path::new)
        .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?;
    let root = PrivateRoot::open(parent)?;
    root.remove_private_socket(name)?;
    let listener = UnixListener::bind(socket).map_err(|source| UdsError::Io {
        path: socket.to_owned(),
        source,
    })?;
    let identity = set_socket_private(socket)?;
    let uid = current_uid();
    let incoming = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(credential) if credential.uid() == uid => Some(Ok(stream)),
            Ok(_) => None,
            Err(source) => Some(Err(source)),
        },
        Err(source) => Some(Err(source)),
    });
    Ok((incoming, identity))
}

/// An Axum listener that admits only connections from the supervisor owner.
///
/// Peer credentials are checked before Hyper can parse a request, so private
/// Tonic and public Connect handlers share exactly the same OS authorization
/// boundary. Rejected peers observe only a closed Unix connection.
pub(crate) struct OwnerOnlyUnixListener {
    inner: UnixListener,
    uid: u32,
}

impl axum::serve::Listener for OwnerOnlyUnixListener {
    type Io = UnixStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credential) if credential.uid() == self.uid => {
                        return (stream, address);
                    }
                    Ok(_) | Err(_) => continue,
                },
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub(crate) fn bind_owner_only_listener(
    socket: &Path,
) -> Result<(OwnerOnlyUnixListener, SocketIdentity), UdsError> {
    let parent = socket
        .parent()
        .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?;
    let name = socket
        .file_name()
        .map(Path::new)
        .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?;
    let root = PrivateRoot::open(parent)?;
    root.remove_private_socket(name)?;
    let listener = UnixListener::bind(socket).map_err(|source| UdsError::Io {
        path: socket.to_owned(),
        source,
    })?;
    let identity = set_socket_private(socket)?;
    Ok((
        OwnerOnlyUnixListener {
            inner: listener,
            uid: current_uid(),
        },
        identity,
    ))
}

pub(crate) async fn connect_owner_only(socket: &Path) -> Result<Channel, UdsError> {
    let connector = owner_only_connector(socket)?;
    let endpoint = Endpoint::from_static("http://codewire-local-control")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|_| UdsError::Connect)
}

pub(crate) fn owner_only_connector(
    socket: &Path,
) -> Result<
    impl tower::Service<
        http::Uri,
        Response = TokioIo<UnixStream>,
        Error = io::Error,
        Future: Send + 'static,
    > + Clone
    + Send
    + 'static,
    UdsError,
> {
    let socket = socket.to_owned();
    let identity = SocketIdentity::capture(&socket)?;
    Ok(tower::service_fn(move |_| {
        let socket = socket.clone();
        let identity = identity.clone();
        async move {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&socket))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Unix connect timeout"))??;
            identity
                .revalidate(&socket)
                .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "socket changed"))?;
            let credential = stream.peer_cred()?;
            if credential.uid() != current_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unix peer user mismatch",
                ));
            }
            Ok::<_, io::Error>(TokioIo::new(stream))
        }
    }))
}

pub(crate) fn remove_bound_socket(
    socket: &Path,
    identity: &SocketIdentity,
) -> Result<(), UdsError> {
    identity.revalidate(socket)?;
    let parent = PrivateRoot::open(
        socket
            .parent()
            .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?,
    )?;
    let name = socket
        .file_name()
        .map(Path::new)
        .ok_or_else(|| UdsError::InvalidPath(socket.to_owned()))?;
    parent.remove_private_socket(name)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum UdsError {
    #[error("invalid private Unix socket path: {0}")]
    InvalidPath(PathBuf),
    #[error("connect to private Unix socket failed")]
    Connect,
    #[error(transparent)]
    Path(#[from] crate::linux::path::PathError),
    #[error("Unix socket operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use axum::serve::Listener as _;
    use tokio::io::AsyncReadExt as _;
    use tower::ServiceExt as _;

    use super::*;

    fn private_socket_path() -> (tempfile::TempDir, PathBuf) {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        (parent, root.join("supervisor.sock"))
    }

    #[tokio::test]
    async fn owner_listener_rejects_peer_before_http_dispatch() {
        let (_parent, socket) = private_socket_path();
        let (mut listener, identity) = bind_owner_only_listener(&socket).unwrap();
        listener.uid = current_uid().checked_add(1).unwrap();
        let mut client = UnixStream::connect(&socket).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(50), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        remove_bound_socket(&socket, &identity).unwrap();
    }

    #[tokio::test]
    async fn owner_connector_rejects_a_replaced_socket_identity() {
        let (_parent, socket) = private_socket_path();
        let (_original_listener, original_identity) = bind_owner_only_listener(&socket).unwrap();
        let connector = owner_only_connector(&socket).unwrap();
        remove_bound_socket(&socket, &original_identity).unwrap();
        let (_replacement_listener, replacement_identity) =
            bind_owner_only_listener(&socket).unwrap();

        let error = connector
            .oneshot("http://codewire-local-control".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        remove_bound_socket(&socket, &replacement_identity).unwrap();
    }
}
