//! The client a managed agent runs: the one the workspace user's shell runs.
//! `codex` or `claude` is found on PATH as the shell finds it and followed
//! through symbolic links to the file that runs. No version is pinned and no
//! layout, owner or mode is required of the file (owner decision 2026-10-16);
//! a process running as the workspace user can replace the client. A launch
//! names the client's identity, its bytes and the version it reports, and
//! runs only while the client is still that file.
use super::{Agent, Error, Stamp, stamp};
use codewire_daemon_proto::platform_managed::{PROVIDER_BYTES, valid_provider_version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a client may take to name its version.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a client's `--version` may print.
const VERSION_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub sha256: [u8; 32],
    pub size: u64,
    pub version: String,
}
pub struct ProviderPin {
    path: PathBuf,
    file: File,
    stamp: Stamp,
    pub identity: ProviderIdentity,
}
/// Why no client was admitted. A hosted launch refuses on any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinRefusal {
    /// PATH has no executable `codex` or `claude`.
    Missing,
    /// The client is not a readable file within the size bound, did not
    /// name its version, or changed while it was read.
    Invalid,
    /// The admitted client changed right after admission.
    Changed,
}
impl PinRefusal {
    /// A hosted launch refuses on every reason; a client that changed right
    /// after admission leaves the outcome unknown.
    pub(crate) fn hosted(self) -> Error {
        match self {
            Self::Changed => Error::Unknown,
            _ => Error::Refused,
        }
    }
}
/// The file the workspace user's shell runs for `agent`: the first
/// executable `codex` or `claude` in a PATH directory, followed through every
/// symbolic link. `None` when PATH has none.
pub fn shell_client(agent: Agent) -> Option<PathBuf> {
    shell_client_on(agent, &std::env::var_os("PATH")?)
}
/// [`shell_client`] for an explicit PATH value. A relative PATH entry is
/// skipped, so the working directory never names a client.
pub fn shell_client_on(agent: Agent, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(agent.command()))
        .find(|candidate| {
            std::fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
        })
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}
/// Open `path` itself, never a link in its place, as a bounded regular file.
fn open(path: &Path) -> Result<(File, std::fs::Metadata), PinRefusal> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PinRefusal::Invalid)?;
    let m = file.metadata().map_err(|_| PinRefusal::Invalid)?;
    if !m.is_file() || !(4..=PROVIDER_BYTES).contains(&m.len()) {
        return Err(PinRefusal::Invalid);
    }
    Ok((file, m))
}
/// The SHA-256 of the whole file, which must be exactly its stated size.
fn digest(mut file: &File, m: &std::fs::Metadata) -> Result<[u8; 32], PinRefusal> {
    let mut h = Sha256::new();
    let mut total = 0_u64;
    let mut buf = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| PinRefusal::Invalid)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(PinRefusal::Invalid)?;
        if total > PROVIDER_BYTES {
            return Err(PinRefusal::Invalid);
        }
        h.update(&buf[..n]);
    }
    if total != m.len() {
        return Err(PinRefusal::Invalid);
    }
    Ok(h.finalize().into())
}
/// The version `client --version` names: the first word of its output that
/// is a version, as in `2.1.292 (Claude Code)` or `codex-cli 0.160.0`. The
/// client runs with this daemon's environment less its own credential, no
/// input, and for at most `timeout`; whatever it leaves running in its
/// process group ends with it.
fn client_version(client: &Path, timeout: Duration) -> Option<String> {
    let mut command = Command::new(client);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(crate::env::is_internal_environment_name)
        {
            command.env_remove(name);
        }
    }
    let mut child = spawn(&mut command)?;
    let output = version_output(&mut child, Instant::now() + timeout);
    // The leader is still unreaped, so its process group cannot have been
    // reused: end what remains of it, then reap the leader.
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    String::from_utf8_lossy(&output?)
        .split_whitespace()
        .find(|word| valid_provider_version(word))
        .map(str::to_owned)
}
/// A client being written, or one a concurrent fork still holds open for
/// writing until its own exec, is briefly refused with ETXTBSY; retry only
/// that, bounded.
fn spawn(command: &mut Command) -> Option<Child> {
    for _ in 0..50 {
        match command.spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => return result.ok(),
        }
    }
    None
}
/// What the client printed before it exited, or `None` when it printed too
/// much or did not exit by `deadline`. The leader is never reaped here, and
/// output a descendant still holds open is not waited for.
fn version_output(child: &mut Child, deadline: Instant) -> Option<Vec<u8>> {
    let mut stdout = child.stdout.take()?;
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return None;
    }
    let pid = libc::id_t::try_from(child.id()).ok()?;
    let mut output = Vec::new();
    let mut buf = [0; 1024];
    let mut open = true;
    loop {
        // Once the leader has exited, all it wrote is already in the pipe.
        let exited = leader_exited(pid)?;
        while open {
            match stdout.read(&mut buf) {
                Ok(0) => open = false,
                Ok(n) => {
                    output.extend_from_slice(&buf[..n]);
                    if output.len() > VERSION_BYTES {
                        return None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return None,
            }
        }
        if exited {
            return Some(output);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
/// Whether the leader exited. WNOWAIT leaves it unreaped, so its PID and
/// process group stay reserved for the group signal that follows.
fn leader_exited(pid: libc::id_t) -> Option<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return None;
    }
    Some(unsafe { info.si_pid() } != 0)
}
impl ProviderPin {
    pub fn discover(agent: Agent) -> Result<Self, Error> {
        Self::admit_shell_client(agent).map_err(PinRefusal::hosted)
    }
    /// The client the workspace user's shell runs for `agent` now, or why it
    /// is not admitted.
    pub fn admit_shell_client(agent: Agent) -> Result<Self, PinRefusal> {
        let path = shell_client(agent).ok_or(PinRefusal::Missing)?;
        Self::admit_client(&path, VERSION_TIMEOUT)
    }
    fn admit_client(path: &Path, timeout: Duration) -> Result<Self, PinRefusal> {
        let (file, m) = open(path)?;
        let sha256 = digest(&file, &m)?;
        let version = client_version(path, timeout).ok_or(PinRefusal::Invalid)?;
        let pin = Self {
            path: path.into(),
            file,
            stamp: stamp(&m),
            identity: ProviderIdentity {
                sha256,
                size: m.len(),
                version,
            },
        };
        pin.check().map_err(|_| PinRefusal::Changed)?;
        Ok(pin)
    }
    /// The client the shell runs now, which must still be the one `expected`
    /// names: a launch runs only the client it was offered.
    pub fn admit(agent: Agent, expected: &ProviderIdentity) -> Result<Self, Error> {
        let pin = Self::discover(agent)?;
        if pin.identity != *expected {
            return Err(Error::Refused);
        }
        Ok(pin)
    }
    /// The client a conversation was launched with, at the path it recorded:
    /// the same bytes `expected` names. It runs no version check, since the
    /// bytes that named the version are unchanged.
    pub fn reopen(path: &Path, expected: &ProviderIdentity) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::Refused);
        }
        let (file, m) = open(path).map_err(PinRefusal::hosted)?;
        if m.len() != expected.size
            || digest(&file, &m).map_err(PinRefusal::hosted)? != expected.sha256
        {
            return Err(Error::Refused);
        }
        let pin = Self {
            path: path.into(),
            file,
            stamp: stamp(&m),
            identity: expected.clone(),
        };
        pin.check()?;
        Ok(pin)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The held file is unchanged and its path still names it.
    pub fn check(&self) -> Result<(), Error> {
        for m in [
            self.file.metadata().map_err(|_| Error::Unknown)?,
            std::fs::symlink_metadata(&self.path).map_err(|_| Error::Unknown)?,
        ] {
            if stamp(&m) != self.stamp {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_shell_client_is_the_first_executable_on_path_followed_to_its_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let (plain, linked, real, later) = (
            root.join("plain"),
            root.join("linked"),
            root.join("versions"),
            root.join("later"),
        );
        for dir in [&plain, &linked, &real, &later] {
            std::fs::create_dir(dir).unwrap();
        }
        // Not executable, and a directory: the shell passes both by.
        write(&plain.join("claude"), "#!/bin/sh\n", 0o644);
        std::fs::create_dir(later.join("codex")).unwrap();
        // The native installer's layout: a link to a versioned file.
        write(&real.join("2.1.292"), "#!/bin/sh\n", 0o755);
        std::os::unix::fs::symlink(real.join("2.1.292"), linked.join("claude")).unwrap();
        write(&later.join("claude"), "#!/bin/sh\n", 0o755);
        let path = std::env::join_paths([PathBuf::from("relative"), plain, linked, later]).unwrap();
        assert_eq!(
            shell_client_on(Agent::Claude, &path),
            Some(real.join("2.1.292"))
        );
        assert_eq!(shell_client_on(Agent::Codex, &path), None);
    }

    #[test]
    fn a_client_is_admitted_with_the_version_it_names_and_only_its_own_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        for (name, output, version) in [
            ("claude", "2.1.292 (Claude Code)", "2.1.292"),
            ("codex", "codex-cli 0.160.0", "0.160.0"),
        ] {
            let path = root.join(name);
            let body = format!("#!/bin/sh\nprintf '%s\\n' '{output}'\n");
            write(&path, &body, 0o755);
            let pin = ProviderPin::admit_client(&path, VERSION_TIMEOUT).unwrap();
            assert_eq!(pin.path(), path);
            assert_eq!(
                pin.identity,
                ProviderIdentity {
                    sha256: Sha256::digest(body.as_bytes()).into(),
                    size: body.len() as u64,
                    version: version.into(),
                }
            );
            pin.check().unwrap();
            // The conversation's recorded client opens again while unchanged.
            let reopened = ProviderPin::reopen(&path, &pin.identity).unwrap();
            assert_eq!(reopened.identity, pin.identity);
            for other in [
                ProviderIdentity {
                    sha256: [7; 32],
                    ..pin.identity.clone()
                },
                ProviderIdentity {
                    size: pin.identity.size + 1,
                    ..pin.identity.clone()
                },
            ] {
                assert!(matches!(
                    ProviderPin::reopen(&path, &other),
                    Err(Error::Refused)
                ));
            }
            assert!(matches!(
                ProviderPin::reopen(Path::new(name), &pin.identity),
                Err(Error::Refused)
            ));
            // An update replaces the file: the held pin sees the change.
            let updated = root.join(format!("{name}.new"));
            write(&updated, &format!("{body}# updated\n"), 0o755);
            std::fs::rename(&updated, &path).unwrap();
            assert!(matches!(pin.check(), Err(Error::Unknown)));
            assert!(matches!(
                ProviderPin::reopen(&path, &pin.identity),
                Err(Error::Refused)
            ));
        }
    }

    #[test]
    fn a_client_that_names_no_version_fails_or_hangs_is_not_admitted() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        for (name, body) in [
            ("no-version", "#!/bin/sh\necho 'Claude Code'\n"),
            ("failed", "#!/bin/sh\necho 2.1.292\nexit 1\n"),
            ("hung", "#!/bin/sh\necho 2.1.292\nexec sleep 30\n"),
            ("verbose", "#!/bin/sh\nyes 2.1.292 | head -c 65536\n"),
        ] {
            let path = root.join(name);
            write(&path, body, 0o755);
            let started = Instant::now();
            assert!(
                matches!(
                    ProviderPin::admit_client(&path, Duration::from_millis(500)),
                    Err(PinRefusal::Invalid)
                ),
                "{name}"
            );
            assert!(started.elapsed() < Duration::from_secs(5), "{name}");
        }
        // Too small to be a client, and not a file.
        write(&root.join("tiny"), "#!", 0o755);
        assert!(matches!(
            ProviderPin::admit_client(&root.join("tiny"), VERSION_TIMEOUT),
            Err(PinRefusal::Invalid)
        ));
        assert!(matches!(
            ProviderPin::admit_client(&root, VERSION_TIMEOUT),
            Err(PinRefusal::Invalid)
        ));
        // A client that reads input first finds it closed and goes on.
        let reads = root.join("reads-input");
        write(&reads, "#!/bin/sh\nread line\necho 2.1.292\n", 0o755);
        let pin = ProviderPin::admit_client(&reads, Duration::from_millis(500)).unwrap();
        assert_eq!(pin.identity.version, "2.1.292");
    }

    #[test]
    fn a_version_is_read_without_waiting_for_what_the_client_left_running() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let path = root.join("claude");
        let marker = root.join("left-running");
        // A descendant keeps the output open and would outlive the client.
        write(
            &path,
            &format!(
                "#!/bin/sh\necho '2.1.292 (Claude Code)'\n(trap '' TERM; sleep 2; : > '{}') &\n",
                marker.display()
            ),
            0o755,
        );
        let started = Instant::now();
        let pin = ProviderPin::admit_client(&path, VERSION_TIMEOUT).unwrap();
        assert_eq!(pin.identity.version, "2.1.292");
        assert!(started.elapsed() < Duration::from_millis(1500));
        // The descendant ended with the client's process group.
        std::thread::sleep(Duration::from_secs(3));
        assert!(!marker.exists());
    }

    #[test]
    fn a_hosted_launch_refuses_every_reason_and_reports_a_changed_client_as_unknown() {
        for refusal in [PinRefusal::Missing, PinRefusal::Invalid] {
            assert!(matches!(refusal.hosted(), Error::Refused));
        }
        assert!(matches!(PinRefusal::Changed.hosted(), Error::Unknown));
    }
}
