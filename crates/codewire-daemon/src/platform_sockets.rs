//! The platform's own Unix sockets in this process, by identity (#5608).
//!
//! A Unix-socket forward over SSH reaches any socket the workload user can,
//! except these (`SPEC.md`, "Port forwarding over SSH"). In a hosted Sandbox
//! they are served by the workload's own uid and some admit it by peer
//! credentials, so neither the kernel nor the serving uid tells them apart,
//! and the workload user owns them and can link one anywhere, so neither does
//! a name. Their device and inode do: [`bind`] records them as it binds, so
//! no platform socket is served unrecorded, and the record goes when the
//! returned [`PlatformSocket`] is dropped. A socket bound again at the same
//! identity replaces the earlier record.
//!
//! The refusal is not a boundary against someone with a shell, who reaches
//! the same sockets from inside. It keeps a forward from being the supported
//! way to carry the environment's brokered credentials to another machine
//! (#3068).

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::net::UnixListener;

/// Each live platform socket's name, with the serial of the record that
/// holds it, by `(device, inode)`.
type Records = BTreeMap<(u64, u64), (u64, &'static str)>;

static SOCKETS: Mutex<Records> = Mutex::new(BTreeMap::new());
static NEXT_SERIAL: AtomicU64 = AtomicU64::new(1);

fn sockets() -> MutexGuard<'static, Records> {
    SOCKETS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One platform socket's record, kept while the socket is served.
#[derive(Debug)]
#[must_use = "the record goes when this is dropped"]
pub struct PlatformSocket {
    device: u64,
    inode: u64,
    serial: u64,
}

impl PlatformSocket {
    fn register(device: u64, inode: u64, name: &'static str) -> Self {
        let serial = NEXT_SERIAL.fetch_add(1, Ordering::Relaxed);
        sockets().insert((device, inode), (serial, name));
        Self {
            device,
            inode,
            serial,
        }
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }
}

impl Drop for PlatformSocket {
    fn drop(&mut self) {
        let mut sockets = sockets();
        // A socket bound again at this identity holds a newer record.
        if sockets
            .get(&(self.device, self.inode))
            .is_some_and(|(serial, _)| *serial == self.serial)
        {
            sockets.remove(&(self.device, self.inode));
        }
    }
}

/// Bind a platform socket at `path` and record it as `name`, such as "the
/// credential bridge's socket". The record lasts as long as the returned
/// [`PlatformSocket`].
pub fn bind(path: &Path, name: &'static str) -> io::Result<(UnixListener, PlatformSocket)> {
    let listener = UnixListener::bind(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((
        listener,
        PlatformSocket::register(metadata.dev(), metadata.ino(), name),
    ))
}

/// The name of the platform socket at `(device, inode)`, if it is one.
pub fn named(device: u64, inode: u64) -> Option<&'static str> {
    sockets().get(&(device, inode)).map(|(_, name)| *name)
}

/// Every platform socket this process serves now: device, inode and name.
pub fn snapshot() -> Vec<(u64, u64, &'static str)> {
    sockets()
        .iter()
        .map(|((device, inode), (_, name))| (*device, *inode, *name))
        .collect()
}

/// The platform's own directories, as a refusal names them.
pub const PLATFORM_DIRECTORIES: [&str; 3] = ["/codewire", "/run/codewire", "/run/codewire-*"];

/// The one `/run/codewire-*` directory that is not the platform's: a local
/// VM's container holds the environment's Docker socket there.
const DOCKER_RUNTIME_DIRECTORY: &str = "codewire-docker";

/// The platform's own directory that `resolved`, an absolute path with no
/// `.` or `..`, lies in: `/codewire`, or `/run/codewire` and its
/// `/run/codewire-*` siblings. A forward refuses anything there whatever its
/// identity, in case a socket was ever bound without [`bind`].
pub fn platform_directory(resolved: &Path) -> Option<&'static str> {
    platform_directory_index(resolved).map(|index| PLATFORM_DIRECTORIES[index])
}

/// [`platform_directory`], as its index in [`PLATFORM_DIRECTORIES`].
pub fn platform_directory_index(resolved: &Path) -> Option<usize> {
    let mut components = resolved.components();
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    match components.next()? {
        Component::Normal(first) if first == "codewire" => Some(0),
        Component::Normal(first) if first == "run" => match components.next()? {
            Component::Normal(second) if second == "codewire" => Some(1),
            // Exactly this directory, never a prefix: where a local VM keeps
            // the environment's Docker socket, which a forward may reach.
            // Nothing of the platform's is put there; the guest's
            // `CONTAINER_DOCKER_RUNTIME_PATH` says the same (#5608).
            Component::Normal(second) if second == DOCKER_RUNTIME_DIRECTORY => None,
            Component::Normal(second)
                if second
                    .to_str()
                    .is_some_and(|second| second.starts_with("codewire-")) =>
            {
                Some(2)
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_bound_socket_is_named_until_its_record_is_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("platform.sock");
        let (listener, record) = bind(&path, "the test's socket").unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            named(metadata.dev(), metadata.ino()),
            Some("the test's socket")
        );
        drop(record);
        assert_eq!(named(metadata.dev(), metadata.ino()), None);
        drop(listener);
    }

    #[test]
    fn a_rebound_identity_keeps_the_newer_record() {
        // Two records at one identity, as when a socket is bound again: the
        // older one's drop leaves the newer one in place.
        let (device, inode) = (u64::MAX, u64::MAX - 1);
        let older = PlatformSocket::register(device, inode, "the older socket");
        let newer = PlatformSocket::register(device, inode, "the newer socket");
        drop(older);
        assert_eq!(named(device, inode), Some("the newer socket"));
        drop(newer);
        assert_eq!(named(device, inode), None);
    }

    #[test]
    fn the_platform_directories_are_matched_by_component() {
        for (path, directory) in [
            ("/codewire", Some("/codewire")),
            ("/codewire/run/daemon/mesh.sock", Some("/codewire")),
            ("/run/codewire/credentials.sock", Some("/run/codewire")),
            ("/run/codewire-runtime/init", Some("/run/codewire-*")),
            ("/run/codewire-docker/docker.sock", None),
            ("/run/codewire-docker", None),
            ("/run/codewire-dockerx/docker.sock", Some("/run/codewire-*")),
            (
                "/run/codewire-docker-data/docker.sock",
                Some("/run/codewire-*"),
            ),
            (
                "/run/codewire-host/credential.sock",
                Some("/run/codewire-*"),
            ),
            ("/run/codewire-host/poweroff.sock", Some("/run/codewire-*")),
            ("/codewire-other/x.sock", None),
            ("/run/codewirex/x.sock", None),
            ("/home/codewire/codewire/x.sock", None),
            ("/run/user/1000/codewire.sock", None),
            ("/run", None),
            ("relative/codewire", None),
        ] {
            assert_eq!(platform_directory(Path::new(path)), directory, "{path}");
        }
    }
}
