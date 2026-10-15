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

use codewire_protected_store::ProtectedStoreError;

use crate::{LocalCredentialError, ensure_private_root, validate_private_parent};

// Bump this for every change an older authority lacks, including behavior or
// provider-catalog changes that leave the wire layout intact, with its
// AUTHORITY_PROTOCOL_CHANGES row. An older authority in the range keeps
// serving until a boot command finds no local VM running and replaces it.
pub(crate) const AUTHORITY_PROTOCOL_VERSION: u32 = 16;
/// The oldest authority protocol this cw works with (v0.3.388's). A running
/// authority in [minimum, current] keeps serving after a cw update.
pub(crate) const MINIMUM_AUTHORITY_PROTOCOL_VERSION: u32 = 15;
/// What each authority protocol after the minimum changed, oldest first.
/// Every protocol in (minimum, current] needs a row, so a bump says what an
/// older authority lacks; its test enforces that.
#[cfg(test)]
const AUTHORITY_PROTOCOL_CHANGES: &[(u32, &str)] = &[(
    16,
    "EvaluateEnvironmentGrants answers a platform environment's GitHub question (#2850)",
)];
const _: () = assert!(MINIMUM_AUTHORITY_PROTOCOL_VERSION <= AUTHORITY_PROTOCOL_VERSION);

/// An authority capability newer than the minimum protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityFeature {
    /// `EvaluateEnvironmentGrants` with `platform`: whether a platform
    /// environment's creator has GitHub connected. An older authority ignores
    /// the field and evaluates a local binding instead.
    PlatformGithub,
}

impl AuthorityFeature {
    pub const ALL: [Self; 1] = [Self::PlatformGithub];

    /// The protocol that introduced it.
    pub const fn since(self) -> u32 {
        match self {
            Self::PlatformGithub => 16,
        }
    }

    /// Whether an authority reporting `protocol` serves it.
    pub const fn served_by(self, protocol: u32) -> bool {
        protocol >= self.since()
    }
}
const AUTHORITY_SOCKET_FILE: &str = "authority.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest Unix socket path the kernel accepts, excluding the NUL.
#[cfg(target_os = "macos")]
pub const MAXIMUM_SOCKET_PATH_BYTES: usize = 103;
#[cfg(not(target_os = "macos"))]
pub const MAXIMUM_SOCKET_PATH_BYTES: usize = 107;

#[derive(Clone, Debug)]
pub struct AuthorityRuntimeConfig {
    /// The credential root: the authority's private state under HOME.
    pub root: PathBuf,
    pub executable: PathBuf,
    /// The short private directory that holds the authority's sockets (its
    /// endpoint and each repository SSH runtime), outside HOME so their paths
    /// fit the kernel's bound for any HOME (#2745). The caller prepares it.
    pub socket_dir: PathBuf,
}

impl AuthorityRuntimeConfig {
    pub fn socket(&self) -> PathBuf {
        self.socket_dir.join(AUTHORITY_SOCKET_FILE)
    }

    /// Where an authority from a cw before #2745 listens, inside the
    /// credential root, and where a supervisor from before #2735 (v0.3.388)
    /// dials it. A client still uses a compatible one that is running there;
    /// a new authority replaces the dead endpoint and listens there too.
    pub fn legacy_socket(&self) -> PathBuf {
        self.root.join(AUTHORITY_SOCKET_FILE)
    }

    pub fn validate(&self) -> Result<(), AuthorityRuntimeError> {
        if !self.root.is_absolute()
            || !self.executable.is_absolute()
            || !self.socket_dir.is_absolute()
        {
            return Err(AuthorityRuntimeError::InvalidConfiguration);
        }
        check_socket_path(&self.socket())?;
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

/// Refuses a socket path the kernel cannot bind, naming it, its length and
/// the limit.
pub fn check_socket_path(path: &Path) -> Result<(), AuthorityRuntimeError> {
    let length = path.as_os_str().len();
    if length > MAXIMUM_SOCKET_PATH_BYTES {
        return Err(AuthorityRuntimeError::SocketPathTooLong {
            path: path.to_owned(),
            length,
            limit: MAXIMUM_SOCKET_PATH_BYTES,
        });
    }
    Ok(())
}

/// The socket directory must be this user's private directory: a real
/// directory, mode 0700, at its canonical path.
#[cfg(unix)]
pub(crate) fn validate_socket_dir(directory: &Path) -> Result<(), AuthorityRuntimeError> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(directory).map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?
            != directory
    {
        return Err(AuthorityRuntimeError::InvalidPrivatePath);
    }
    Ok(())
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
    validate_socket_dir(&config.socket_dir)?;
    let socket = config.socket();
    let legacy = config.legacy_socket();
    // The caller holds the singleton lock, so no authority is live at either
    // endpoint: replace a dead one at each.
    for stale in [socket.clone(), legacy.clone()] {
        match fs::symlink_metadata(&stale) {
            Ok(_) => {
                SocketIdentity::capture(&stale)?;
                fs::remove_file(&stale).map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(AuthorityRuntimeError::InvalidPrivateSocket),
        }
    }
    let listener = UnixListener::bind(&socket).map_err(|source| AuthorityRuntimeError::Bind {
        path: socket.clone(),
        source,
    })?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| AuthorityRuntimeError::InvalidPrivateSocket)?;
    let identity = SocketIdentity::capture(&socket)?;
    // A supervisor from before #2735 (v0.3.388's) dials the credential root's
    // own socket, and it keeps serving its VMs after a cw update: listen
    // there too, so they keep their credentials when this cw's authority
    // replaces theirs. A root whose path is too long never had one there.
    let legacy = check_socket_path(&legacy)
        .ok()
        .and_then(|()| UnixListener::bind(&legacy).ok())
        .filter(|_| fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).is_ok());
    let accepted = futures::stream::select(
        UnixListenerStream::new(listener),
        futures::StreamExt::flatten(futures::stream::iter(legacy.map(UnixListenerStream::new))),
    );
    let incoming = accepted.filter_map(move |result| match result {
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
    connect_owner_only_with_timeout(config, REQUEST_TIMEOUT).await
}

/// A channel whose calls may each run for `timeout`. Control calls use the
/// 30 s default; repository preparation runs git first and needs longer.
pub(crate) async fn connect_owner_only_with_timeout(
    config: &AuthorityRuntimeConfig,
    timeout: Duration,
) -> Result<Channel, AuthorityRuntimeError> {
    config.validate()?;
    let connector = owner_only_connector(config)?;
    Endpoint::from_static("http://codewire-local-credential-authority")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
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

/// A starting authority that cannot use its protected store exits with one
/// of these bases plus the store error's index: 80 when it refused to move
/// values to a newly configured store, 90 when its own store failed while
/// opening (for example a locked keychain). The detached authority has no
/// diagnostic stream, so its starter decodes the reason.
const STORE_SWITCH_EXIT_BASE: i32 = 80;
const STORE_OPEN_EXIT_BASE: i32 = 90;
const STORE_ERRORS: [ProtectedStoreError; 9] = [
    ProtectedStoreError::InvalidEntryId,
    ProtectedStoreError::EmptyValue,
    ProtectedStoreError::ValueTooLarge,
    ProtectedStoreError::AccessDenied,
    ProtectedStoreError::Unavailable,
    ProtectedStoreError::TimedOut,
    ProtectedStoreError::AmbiguousEntry,
    ProtectedStoreError::CorruptEntry,
    ProtectedStoreError::UnsupportedPlatform,
];

/// The process exit status for an authority that failed to start.
pub fn authority_exit_code(error: &AuthorityRuntimeError) -> Option<i32> {
    let (base, error) = match error {
        AuthorityRuntimeError::Credential(LocalCredentialError::ProtectedStoreSwitch(error)) => {
            (STORE_SWITCH_EXIT_BASE, error)
        }
        AuthorityRuntimeError::Credential(LocalCredentialError::ProtectedStore(error)) => {
            (STORE_OPEN_EXIT_BASE, error)
        }
        _ => return None,
    };
    STORE_ERRORS
        .iter()
        .position(|candidate| candidate == error)
        .map(|index| base + index as i32)
}

/// The start failure an authority reported through its exit status. Both
/// kinds happen only after it holds the singleton lock, so they are final.
pub(crate) fn store_error_from_exit_status(
    status: std::process::ExitStatus,
) -> Option<LocalCredentialError> {
    let code = status.code()?;
    let (base, wrap): (i32, fn(ProtectedStoreError) -> LocalCredentialError) =
        if code >= STORE_OPEN_EXIT_BASE {
            (STORE_OPEN_EXIT_BASE, LocalCredentialError::ProtectedStore)
        } else {
            (
                STORE_SWITCH_EXIT_BASE,
                LocalCredentialError::ProtectedStoreSwitch,
            )
        };
    let index = usize::try_from(code.checked_sub(base)?).ok()?;
    STORE_ERRORS.get(index).copied().map(wrap)
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
    #[error(
        "the local credential authority socket path {} is {length} bytes; the limit is {limit}",
        path.display()
    )]
    SocketPathTooLong {
        path: PathBuf,
        length: usize,
        limit: usize,
    },
    #[error("could not bind the local credential authority socket {}: {source}", path.display())]
    Bind { path: PathBuf, source: io::Error },
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

#[cfg(test)]
mod exit_status_tests {
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    #[test]
    fn store_start_failures_round_trip_through_the_exit_status() {
        for error in STORE_ERRORS {
            for (failure, codes) in [
                (LocalCredentialError::ProtectedStoreSwitch(error), 80..=88),
                (LocalCredentialError::ProtectedStore(error), 90..=98),
            ] {
                let code = authority_exit_code(&AuthorityRuntimeError::Credential(failure.clone()))
                    .unwrap();
                assert!(codes.contains(&code));
                let status = std::process::ExitStatus::from_raw(code << 8);
                assert_eq!(store_error_from_exit_status(status), Some(failure));
            }
        }
        assert_eq!(authority_exit_code(&AuthorityRuntimeError::Serve), None);
        assert_eq!(
            authority_exit_code(&AuthorityRuntimeError::Credential(
                LocalCredentialError::AlreadyRunning
            )),
            None
        );
        for code in [0, 1, 79, 89, 99] {
            let status = std::process::ExitStatus::from_raw(code << 8);
            assert_eq!(store_error_from_exit_status(status), None);
        }
        // Killed by a signal: no exit code.
        let signaled = std::process::ExitStatus::from_raw(9);
        assert_eq!(store_error_from_exit_status(signaled), None);
    }

    #[test]
    fn every_authority_protocol_after_the_minimum_says_what_it_changed() {
        let protocols: Vec<u32> = AUTHORITY_PROTOCOL_CHANGES
            .iter()
            .map(|(protocol, _)| *protocol)
            .collect();
        let expected: Vec<u32> = (MINIMUM_AUTHORITY_PROTOCOL_VERSION..AUTHORITY_PROTOCOL_VERSION)
            .map(|protocol| protocol + 1)
            .collect();
        assert_eq!(
            protocols, expected,
            "an authority protocol bump needs an AUTHORITY_PROTOCOL_CHANGES row"
        );
    }

    #[test]
    fn every_authority_feature_is_newer_than_the_minimum_and_served_from_its_protocol() {
        for feature in AuthorityFeature::ALL {
            let since = feature.since();
            assert!(
                (MINIMUM_AUTHORITY_PROTOCOL_VERSION + 1..=AUTHORITY_PROTOCOL_VERSION)
                    .contains(&since),
                "{feature:?}"
            );
            assert!(
                AUTHORITY_PROTOCOL_CHANGES
                    .iter()
                    .any(|(protocol, _)| *protocol == since),
                "{feature:?}"
            );
            assert!(!feature.served_by(since - 1), "{feature:?}");
            assert!(feature.served_by(since), "{feature:?}");
            assert!(feature.served_by(AUTHORITY_PROTOCOL_VERSION), "{feature:?}");
        }
    }
}
