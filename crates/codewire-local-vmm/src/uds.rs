use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

use crate::host::path as host_path;
use crate::host::supervisor_peer::SupervisorPeerPin;
use crate::supervisor_config::NativeRuntimeConfig;
use host_path::{PrivateRoot, set_socket_private};
use host_path::{SocketIdentity, current_uid};
use std::sync::Arc;

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
    bind_owner_only_with_uid(socket, current_uid())
}

// The production entrypoint always supplies the actual owner UID. Native tests
// substitute only the expected UID, never fabricated kernel peer credentials.
pub(crate) fn bind_owner_only_with_uid(
    socket: &Path,
    uid: u32,
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
    refuse_live_socket(socket)?;
    root.remove_private_socket(name)?;
    let listener = UnixListener::bind(socket).map_err(|source| UdsError::Io {
        path: socket.to_owned(),
        source,
    })?;
    let identity = set_socket_private(socket)?;
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

impl OwnerOnlyUnixListener {
    /// This listener, counting each admitted connection in `connections`
    /// while it is open.
    pub(crate) fn tracked(self, connections: Arc<Connections>) -> TrackedListener {
        TrackedListener {
            inner: self,
            connections,
        }
    }
}

/// How many client connections a server has open, and since when none has
/// been. A supervisor exits after a quiet window with nothing to serve
/// (#3793); each cw command holds its connection until it exits.
#[derive(Debug)]
pub(crate) struct Connections {
    /// The open count, and when it last fell to zero (or the count began).
    state: std::sync::Mutex<(usize, tokio::time::Instant)>,
}

impl Connections {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new((0, tokio::time::Instant::now())),
        })
    }

    /// How long no connection has been open at `now`; `None` while one is.
    pub(crate) fn idle_for(&self, now: tokio::time::Instant) -> Option<Duration> {
        let (open, since) = *self.lock();
        (open == 0).then(|| now.saturating_duration_since(since))
    }

    pub(crate) fn opened(self: &Arc<Self>) -> ConnectionGuard {
        self.lock().0 += 1;
        ConnectionGuard(Arc::clone(self))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, tokio::time::Instant)> {
        // The count is plain data, valid whatever a panicking holder did.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One open connection; dropping it closes the count.
#[derive(Debug)]
pub(crate) struct ConnectionGuard(Arc<Connections>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.0 -= 1;
        if state.0 == 0 {
            state.1 = tokio::time::Instant::now();
        }
    }
}

/// [`OwnerOnlyUnixListener`] counting its connections in [`Connections`].
pub(crate) struct TrackedListener {
    inner: OwnerOnlyUnixListener,
    connections: Arc<Connections>,
}

impl axum::serve::Listener for TrackedListener {
    type Io = TrackedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, address) = self.inner.accept().await;
        let open = self.connections.opened();
        (
            TrackedStream {
                stream,
                _open: open,
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// An admitted connection, counted open until it is dropped.
pub(crate) struct TrackedStream {
    stream: UnixStream,
    _open: ConnectionGuard,
}

impl tokio::io::AsyncRead for TrackedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for TrackedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
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
    refuse_live_socket(socket)?;
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

pub(crate) async fn capture_supervisor_peer(
    socket: &Path,
    config: Option<&NativeRuntimeConfig>,
) -> Result<Arc<SupervisorPeerPin>, UdsError> {
    let identity = SocketIdentity::capture(socket)?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| UdsError::Connect)?
        .map_err(|source| UdsError::Io {
            path: socket.to_owned(),
            source,
        })?;
    identity.revalidate(socket)?;
    SupervisorPeerPin::capture(&stream, socket, identity, config).map_err(supervisor_peer_error)
}

fn supervisor_peer_error(error: crate::host::supervisor_peer::PeerError) -> UdsError {
    use crate::host::supervisor_peer::PeerError;
    UdsError::SupervisorPeerAdmission(match error {
        PeerError::Kernel => {
            SupervisorRefusal::Check("kernel socket-derived process identity is unavailable")
        }
        PeerError::Identity => {
            SupervisorRefusal::Check("process, socket or executable identity changed")
        }
        PeerError::Role => SupervisorRefusal::Check("role or configuration arguments do not match"),
        PeerError::Provenance => {
            SupervisorRefusal::Check("retained executable provenance is unavailable or changed")
        }
        PeerError::Unverified { pid, executable } => {
            SupervisorRefusal::Unverified { pid, executable }
        }
        #[cfg(target_os = "linux")]
        PeerError::OtherConfiguration {
            pid,
            executable,
            differences,
        } => SupervisorRefusal::OtherConfiguration {
            pid,
            executable,
            differences,
        },
        #[cfg(target_os = "linux")]
        PeerError::DeletedExecutable { pid, executable } => {
            SupervisorRefusal::DeletedExecutable { pid, executable }
        }
    })
}

pub(crate) async fn connect_supervisor_peer(
    pin: Arc<SupervisorPeerPin>,
) -> Result<Channel, UdsError> {
    Endpoint::from_static("http://codewire-local-control")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector(supervisor_peer_connector(pin))
        .await
        .map_err(|_| UdsError::Connect)
}

pub(crate) fn supervisor_peer_connector(
    pin: Arc<SupervisorPeerPin>,
) -> impl tower::Service<
    http::Uri,
    Response = TokioIo<UnixStream>,
    Error = io::Error,
    Future: Send + 'static,
> + Clone
+ Send
+ 'static {
    tower::service_fn(move |_| {
        let pin = pin.clone();
        async move {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(pin.socket()))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Unix connect timeout"))??;
            pin.revalidate_stream(&stream).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "native supervisor peer changed",
                )
            })?;
            Ok::<_, io::Error>(TokioIo::new(stream))
        }
    })
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

/// A socket left at `socket` is unlinked only when nothing answers on it,
/// so binding never takes over a live server's name (#2735).
fn refuse_live_socket(socket: &Path) -> Result<(), UdsError> {
    match std::fs::symlink_metadata(socket) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(UdsError::Io {
                path: socket.to_owned(),
                source,
            });
        }
        Ok(_) => {}
    }
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => Err(UdsError::Live(socket.to_owned())),
        Err(_) => Ok(()),
    }
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

/// Why this cw does not use the supervisor serving its state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorRefusal {
    /// A check of the peer's process, socket, role or provenance failed.
    Check(&'static str),
    /// The peer serves this root with this root's arguments, but runs an
    /// executable that no managed cw store holds, such as a development
    /// build. This cw cannot verify it, so it never uses it, and it ends no
    /// process it cannot verify: the person who started it does (#3548).
    Unverified { pid: u32, executable: PathBuf },
    /// The peer serves this root for another configuration, such as another
    /// `CW_CONFIG_DIR`. It would act with that configuration's login, so this
    /// cw never uses it; it names what differs and who holds the root (#3793).
    OtherConfiguration {
        pid: u32,
        executable: PathBuf,
        differences: Vec<ArgumentDifference>,
    },
    /// The peer's executable was deleted, so this cw cannot check it. Unlike
    /// a peer that is ending or being replaced, a retry never helps (#3793).
    DeletedExecutable { pid: u32, executable: PathBuf },
}

/// One configuration argument the serving supervisor was started with that
/// differs from this cw's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentDifference {
    pub flag: &'static str,
    /// The supervisor's value; `None` when it was started without the flag.
    pub supervisor: Option<PathBuf>,
    pub requested: PathBuf,
}

impl SupervisorRefusal {
    /// What refused, without the recovery.
    pub fn summary(&self) -> String {
        match self {
            Self::Check(reason) => format!("native supervisor admission refused: {reason}"),
            _ => format!("they {}", self.served_by().unwrap_or_default()),
        }
    }

    /// The steps that recover, when a retry alone cannot.
    pub fn recovery(&self) -> Option<String> {
        match self {
            Self::Check(_) => None,
            Self::Unverified { pid, executable } => {
                let executable = executable.display();
                Some(format!(
                    "List its VMs with `{executable} --local ls` and stop any with `{executable} --local stop NAME`, then end it with `kill {pid}`; the next cw command starts this cw's own"
                ))
            }
            Self::OtherConfiguration { pid, .. } => Some(format!(
                "Stop its VMs with the cw and configuration that started it, then end it with `kill {pid}`; the next cw command starts this cw's own"
            )),
            Self::DeletedExecutable { pid, .. } => Some(format!(
                "End it with `kill {pid}` once nothing runs in its VMs; the next cw command starts this cw's own"
            )),
        }
    }

    /// Who serves this root and why this cw does not use it, for the named
    /// refusals: "are served by …".
    fn served_by(&self) -> Option<String> {
        match self {
            Self::Check(_) => None,
            Self::Unverified { pid, executable } => Some(format!(
                "are served by a cw this one cannot verify (process {pid}, {}), not an installed cw version",
                executable.display()
            )),
            Self::OtherConfiguration {
                pid,
                executable,
                differences,
            } => {
                let differs = if differences.is_empty() {
                    "its arguments differ from this cw's".to_owned()
                } else {
                    differences
                        .iter()
                        .map(|difference| match &difference.supervisor {
                            Some(value) => format!(
                                "{} is {}, this cw uses {}",
                                difference.flag,
                                value.display(),
                                difference.requested.display()
                            ),
                            None => format!(
                                "{} is not set, this cw uses {}",
                                difference.flag,
                                difference.requested.display()
                            ),
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                };
                Some(format!(
                    "are served by a cw started with other configuration (process {pid}, {}): {differs}",
                    executable.display()
                ))
            }
            Self::DeletedExecutable { pid, executable } => Some(format!(
                "are served by process {pid}, whose executable {} was deleted or replaced, so this cw cannot check it",
                executable.display()
            )),
        }
    }
}

impl std::fmt::Display for SupervisorRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.served_by(), self.recovery()) {
            (Some(served_by), Some(recovery)) => {
                write!(formatter, "your local VMs {served_by}. {recovery}")
            }
            _ => formatter.write_str(&self.summary()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UdsError {
    #[error("{0}")]
    SupervisorPeerAdmission(SupervisorRefusal),
    #[error("invalid private Unix socket path: {0}")]
    InvalidPath(PathBuf),
    #[error("connect to private Unix socket failed")]
    Connect,
    #[error("another process already serves {0}")]
    Live(PathBuf),
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

    /// A private socket file whose socket is bound but never listens, so it
    /// refuses every connection. A dropped listener cannot prove that: on
    /// Darwin, a child another test spawns can inherit it before std marks
    /// it close-on-exec and keep it accepting.
    fn refusing_socket(path: &Path) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        // SAFETY: an all-zero sockaddr_un is a valid empty address.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < address.sun_path.len());
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: scalar arguments; the result is owned below.
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(raw >= 0);
        // SAFETY: raw is a fresh descriptor that nothing else owns.
        let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: a fully initialized sockaddr_un and its exact size.
        let bound = unsafe {
            libc::bind(
                raw,
                (&raw const address).cast(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(bound, 0);
        host_path::set_socket_private(path).unwrap();
        socket
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

    /// The original's last reference is gone before the replacement binds,
    /// so a filesystem such as ext4 hands the replacement the original's
    /// inode number (#3207). The connector's pinned identity keeps that
    /// inode allocated, so the replacement still reads as replaced.
    #[tokio::test]
    async fn captured_connector_rejects_a_replacement_after_the_original_is_gone() {
        let (parent, socket, original_listener) = private_socket();
        let connector = owner_only_connector(&socket).unwrap();
        let original = SocketIdentity::capture(&socket).unwrap();
        drop(original_listener);
        fs::remove_file(&socket).unwrap();
        let replacement_listener = UnixListener::bind(&socket).unwrap();
        let replacement = host_path::set_socket_private(&socket).unwrap();
        assert_ne!(replacement, original);
        let error = connector
            .oneshot("http://codewire-local-control".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(original.revalidate(&socket).is_err());
        replacement.revalidate(&socket).unwrap();
        drop((replacement_listener, parent));
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
        let refusing = parent.path().join("refusing.sock");
        let _refusing = refusing_socket(&refusing);
        let connector = owner_only_connector(&refusing).unwrap();
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
