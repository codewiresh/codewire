use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
#[cfg(target_os = "linux")]
use tokio::net::{UnixListener, unix::SocketAddr};
#[cfg(target_os = "linux")]
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

#[cfg(target_os = "macos")]
use crate::darwin::path as host_path;
#[cfg(target_os = "linux")]
use crate::linux::path as host_path;
#[cfg(target_os = "linux")]
use host_path::{PrivateRoot, set_socket_private};
use host_path::{SocketIdentity, current_uid};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
// OCI setup is a bounded lifecycle operation and can legitimately include
// large guest-side verification and layer application before daemon readiness.
// The transport must not expire before the runner's setup bound; lifecycle
// progress and cancellation remain separate operation-level concerns.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(21 * 60);

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub(crate) struct OwnerOnlyUnixListener {
    inner: UnixListener,
    uid: u32,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
    owner_only_connector_with_uid(socket, current_uid)
}

fn owner_only_connector_with_uid(
    socket: &Path,
    expected_uid: fn() -> u32,
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
            if credential.uid() != expected_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unix peer user mismatch",
                ));
            }
            Ok::<_, io::Error>(TokioIo::new(stream))
        }
    }))
}

#[cfg(target_os = "linux")]
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
    Path(#[from] host_path::PathError),
    #[error("Unix socket operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod client_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixListener;
    use tower::ServiceExt as _;

    use super::*;

    fn private_socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
        let parent = tempfile::Builder::new()
            .prefix("cw-uc-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(fs::canonicalize("/var/tmp").unwrap())
            .unwrap();
        host_path::PrivateRoot::open(parent.path()).unwrap();
        let socket = parent.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        host_path::set_socket_private(&socket).unwrap();
        (parent, socket, listener)
    }

    fn different_uid() -> u32 {
        current_uid().checked_add(1).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn native_parent_mode_acl_and_noncanonical_alias_are_rejected() {
        let (parent, socket, _listener) = private_socket();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(owner_only_connector(&socket).is_err());
        assert!(socket.exists());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let alias = PathBuf::from("/var/tmp")
            .join(parent.path().file_name().unwrap())
            .join("control.sock");
        assert_ne!(alias, socket);
        assert!(owner_only_connector(&alias).is_err());
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow readattr"])
                .arg(parent.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(owner_only_connector(&socket).is_err());
        assert!(socket.exists());
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(parent.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(owner_only_connector(&socket).is_ok());
    }

    #[tokio::test]
    async fn same_owner_connector_admits_the_kernel_peer() {
        let (_parent, socket, listener) = private_socket();
        let connector = owner_only_connector(&socket).unwrap();
        let mut stream = connector
            .oneshot("http://codewire-local-control".parse().unwrap())
            .await
            .unwrap()
            .into_inner();
        stream
            .write_all(b"private synthetic request")
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 25];
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"private synthetic request");
    }

    #[tokio::test]
    async fn mismatched_expected_server_uid_emits_no_http_bytes() {
        let (_parent, socket, listener) = private_socket();
        let connector = owner_only_connector_with_uid(&socket, different_uid).unwrap();
        // Use the actual Hyper/Tonic connector handoff, not just a pure UID
        // comparison. The real kernel peer is this owner; expected UID differs.
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                Endpoint::from_static("http://codewire-local-control")
                    .connect_with_connector(connector),
            )
            .await
            .unwrap()
            .is_err()
        );
        let (mut peer, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn captured_connector_rejects_and_preserves_replacement() {
        let (parent, socket, original_listener) = private_socket();
        let connector = owner_only_connector(&socket).unwrap();
        let original = SocketIdentity::capture(&socket).unwrap();
        fs::remove_file(&socket).unwrap();
        let replacement_listener = UnixListener::bind(&socket).unwrap();
        let replacement = host_path::set_socket_private(&socket).unwrap();
        let error = connector
            .oneshot("http://codewire-local-control".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(original.revalidate(&socket).is_err());
        replacement.revalidate(&socket).unwrap();
        drop((replacement_listener, original_listener, parent));
    }

    #[tokio::test]
    async fn unsafe_socket_alias_and_missing_endpoint_fail_closed() {
        let (parent, socket, listener) = private_socket();
        let identity = SocketIdentity::capture(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(owner_only_connector(&socket).is_err());
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = parent.path().join("alias.sock");
        std::os::unix::fs::symlink(&socket, &alias).unwrap();
        assert!(owner_only_connector(&alias).is_err());
        assert!(
            fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(owner_only_connector(&parent.path().join("missing.sock")).is_err());
        let connector = owner_only_connector(&socket).unwrap();
        drop(listener);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                connector.oneshot("http://codewire-local-control".parse().unwrap()),
            )
            .await
            .unwrap()
            .is_err()
        );
        identity.revalidate(&socket).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
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
