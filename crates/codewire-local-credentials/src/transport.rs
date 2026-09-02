use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

#[cfg(unix)]
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};

use crate::{LocalCredentialError, ensure_private_root, validate_private_parent};

// Bump this whenever a detached authority must be replaced, including
// behavior or provider-catalog changes that leave the wire layout intact.
pub(crate) const AUTHORITY_PROTOCOL_VERSION: u32 = 5;
const AUTHORITY_SOCKET_FILE: &str = "authority.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct AuthorityRuntimeConfig {
    pub root: PathBuf,
    pub executable: PathBuf,
}

impl AuthorityRuntimeConfig {
    pub fn socket(&self) -> PathBuf {
        self.root.join(AUTHORITY_SOCKET_FILE)
    }

    pub fn validate(&self) -> Result<(), AuthorityRuntimeError> {
        if !self.root.is_absolute() || !self.executable.is_absolute() {
            return Err(AuthorityRuntimeError::InvalidConfiguration);
        }
        let executable = fs::canonicalize(&self.executable)
            .map_err(|_| AuthorityRuntimeError::InvalidConfiguration)?;
        if executable != self.executable {
            return Err(AuthorityRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }

    pub(crate) fn prepare_root(&self) -> Result<(), AuthorityRuntimeError> {
        self.validate()?;
        if !self.root.exists() {
            #[cfg(not(unix))]
            return Err(AuthorityRuntimeError::UnsupportedPlatform);

            #[cfg(unix)]
            {
                let parent = self
                    .root
                    .parent()
                    .ok_or(AuthorityRuntimeError::InvalidPrivatePath)?;
                if !parent.exists() {
                    ensure_private_root(parent).map_err(AuthorityRuntimeError::Credential)?;
                }
                validate_private_parent(&self.root).map_err(AuthorityRuntimeError::Credential)?;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(&self.root)
                    .map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?;
            }
        }
        ensure_private_root(&self.root).map_err(AuthorityRuntimeError::Credential)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl SocketIdentity {
    fn capture(path: &Path) -> Result<Self, AuthorityRuntimeError> {
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(AuthorityRuntimeError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
            let identity = Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
            };
            if !metadata.file_type().is_socket()
                || metadata.file_type().is_symlink()
                || metadata.uid() != current_uid()
                || metadata.mode() & 0o7777 != 0o600
            {
                return Err(AuthorityRuntimeError::InvalidPrivateSocket);
            }
            Ok(identity)
        }
    }

    fn revalidate(&self, path: &Path) -> Result<(), AuthorityRuntimeError> {
        if &Self::capture(path)? == self {
            Ok(())
        } else {
            Err(AuthorityRuntimeError::InvalidPrivateSocket)
        }
    }
}

pub(crate) fn bind_owner_only(
    config: &AuthorityRuntimeConfig,
) -> Result<
    (
        impl Stream<Item = Result<UnixStream, io::Error>> + Send + 'static,
        SocketIdentity,
    ),
    AuthorityRuntimeError,
> {
    bind_owner_only_for_uid(config, current_uid())
}

pub(crate) fn bind_owner_only_for_uid(
    config: &AuthorityRuntimeConfig,
    uid: u32,
) -> Result<
    (
        impl Stream<Item = Result<UnixStream, io::Error>> + Send + 'static,
        SocketIdentity,
    ),
    AuthorityRuntimeError,
> {
    config.prepare_root()?;
    let socket = config.socket();
    match fs::symlink_metadata(&socket) {
        Ok(_) => {
            SocketIdentity::capture(&socket)?;
            fs::remove_file(&socket).map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(AuthorityRuntimeError::InvalidPrivateSocket),
    }
    let listener =
        UnixListener::bind(&socket).map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
    let identity = SocketIdentity::capture(&socket)?;
    let incoming = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) => match stream.peer_cred() {
            Ok(credential) if credential.uid() == uid => Some(Ok(stream)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        },
        Err(error) => Some(Err(error)),
    });
    Ok((incoming, identity))
}

pub(crate) async fn connect_owner_only(
    config: &AuthorityRuntimeConfig,
) -> Result<Channel, AuthorityRuntimeError> {
    config.validate()?;
    let connector = owner_only_connector(config)?;
    Endpoint::from_static("http://codewire-local-credential-authority")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector(connector)
        .await
        .map_err(|_| AuthorityRuntimeError::Connect)
}

pub(crate) fn owner_only_connector(
    config: &AuthorityRuntimeConfig,
) -> Result<
    impl tower::Service<
        http::Uri,
        Response = TokioIo<UnixStream>,
        Error = io::Error,
        Future: Send + 'static,
    > + Clone
    + Send
    + 'static,
    AuthorityRuntimeError,
> {
    config.validate()?;
    let socket = config.socket();
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
            if stream.peer_cred()?.uid() != current_uid() {
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
    config: &AuthorityRuntimeConfig,
    identity: &SocketIdentity,
) -> Result<(), AuthorityRuntimeError> {
    let socket = config.socket();
    identity.revalidate(&socket)?;
    fs::remove_file(socket).map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)
}

pub(crate) fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[derive(Debug, Error)]
pub enum AuthorityRuntimeError {
    #[error("local credential authority configuration is invalid")]
    InvalidConfiguration,
    #[error("local credential authority private path is invalid")]
    InvalidPrivatePath,
    #[error("local credential authority private socket is invalid")]
    InvalidPrivateSocket,
    #[error("local credential authority is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("connect to local credential authority failed")]
    Connect,
    #[error("spawn local credential authority failed")]
    Spawn,
    #[error("local credential authority did not become ready")]
    StartTimeout,
    #[error("local credential authority protocol is incompatible")]
    ProtocolMismatch,
    #[error("local credential authority process is not confined")]
    ProcessNotConfined,
    #[error("local credential authority server failed")]
    Serve,
    #[error(transparent)]
    Credential(#[from] LocalCredentialError),
}
