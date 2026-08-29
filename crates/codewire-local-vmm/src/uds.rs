use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

use crate::linux::path::{PrivateRoot, SocketIdentity, current_uid, set_socket_private};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

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

pub(crate) async fn connect_owner_only(socket: &Path) -> Result<Channel, UdsError> {
    let socket = socket.to_owned();
    let identity = SocketIdentity::capture(&socket)?;
    let endpoint = Endpoint::from_static("http://codewire-local-control")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    endpoint
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            let identity = identity.clone();
            async move {
                let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&socket))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "Unix connect timeout")
                    })??;
                identity.revalidate(&socket).map_err(|_| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "socket changed")
                })?;
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
        .await
        .map_err(|_| UdsError::Connect)
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
