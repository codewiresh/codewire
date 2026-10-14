//! Fixed original stock native clients. Neither a request nor PATH chooses a
//! program. Hash/version admission is independent of release A/B cw selection.
use super::{Agent, Error, Stamp, stamp};
use codewire_daemon_proto::platform_managed::PROVIDER_BYTES;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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
    parents: Vec<(PathBuf, File)>,
    pub identity: ProviderIdentity,
}
/// Why the image's pinned client was not admitted. Hosted launches refuse on
/// any of them; a local VM records it and runs the client on PATH instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinRefusal {
    /// This architecture has no pinned client layout.
    Architecture,
    /// The image has no client, or no package metadata, at the pinned path.
    Missing,
    /// The package is another client or another version than this cw pins.
    Version,
    /// The client, its package metadata or a parent directory is not a
    /// root-owned, single-link file or directory that only root can write.
    Ownership,
    /// The client is not a complete native executable for this architecture,
    /// or its package metadata is unreadable, or either changed while read.
    Invalid,
    /// The admitted files changed right after admission.
    Changed,
}
impl PinRefusal {
    /// A hosted launch refuses on every reason; a pin that changed right
    /// after admission leaves the outcome unknown.
    pub(crate) fn hosted(self) -> Error {
        match self {
            Self::Changed => Error::Unknown,
            _ => Error::Refused,
        }
    }
    /// One line naming the reason, for the user and the conversation record.
    pub fn reason(self, agent: Agent) -> String {
        let product = agent.product();
        let version = pinned_version(agent);
        match self {
            Self::Architecture => {
                format!("this architecture has no pinned {product} layout")
            }
            Self::Missing => format!("the image has no pinned {product}"),
            Self::Version => format!("the image's pinned {product} is not version {version}"),
            Self::Ownership => format!(
                "the image's pinned {product} or a parent directory is not root-owned and read-only"
            ),
            Self::Invalid => format!(
                "the image's pinned {product} is not a complete native executable for this architecture"
            ),
            Self::Changed => format!("the image's pinned {product} changed while it was admitted"),
        }
    }
}
/// An agent's pinned client in the workspace image.
struct Layout {
    executable: &'static str,
    package: &'static str,
    name: &'static str,
    version: &'static str,
    /// The ELF machine the executable declares: EM_X86_64 or EM_AARCH64.
    machine: u16,
}
/// The version of each agent this release pins.
pub(crate) fn pinned_version(agent: Agent) -> &'static str {
    match agent {
        Agent::Codex => "0.160.0",
        Agent::Claude => "2.1.288",
    }
}
/// The pinned client for this architecture. The Codex executable lives in
/// its architecture's vendor package, where Codex's own launcher finds it;
/// Claude Code's postinstall places its architecture's binary at one path.
fn layout(agent: Agent) -> Option<Layout> {
    let (codex, machine) = if cfg!(target_arch = "x86_64") {
        (
            "/opt/codewire/agents/npm/lib/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
            62,
        )
    } else if cfg!(target_arch = "aarch64") {
        (
            "/opt/codewire/agents/npm/lib/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex",
            183,
        )
    } else {
        return None;
    };
    let (executable, package, name) = match agent {
        Agent::Codex => (
            codex,
            "/opt/codewire/agents/npm/lib/node_modules/@openai/codex/package.json",
            "@openai/codex",
        ),
        Agent::Claude => (
            "/opt/codewire/agents/npm/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "/opt/codewire/agents/npm/lib/node_modules/@anthropic-ai/claude-code/package.json",
            "@anthropic-ai/claude-code",
        ),
    };
    Some(Layout {
        executable,
        package,
        name,
        version: pinned_version(agent),
        machine,
    })
}
fn safe(m: &std::fs::Metadata, bound: u64, exec: bool) -> Result<(), PinRefusal> {
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o6022 != 0 {
        return Err(PinRefusal::Ownership);
    }
    if m.len() < 4 || m.len() > bound || (exec && m.mode() & 0o111 == 0) {
        return Err(PinRefusal::Invalid);
    }
    Ok(())
}
/// Opening a pinned path: absent is `Missing`; anything else, such as a
/// symbolic link refused by `O_NOFOLLOW`, is not the image's own file.
fn open_refusal(error: std::io::Error) -> PinRefusal {
    if error.kind() == std::io::ErrorKind::NotFound {
        PinRefusal::Missing
    } else {
        PinRefusal::Ownership
    }
}
fn parents(path: &Path) -> Result<Vec<(PathBuf, File)>, PinRefusal> {
    let mut pins = Vec::new();
    for p in path.parent().ok_or(PinRefusal::Missing)?.ancestors() {
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)
            .map_err(open_refusal)?;
        let m = fd.metadata().map_err(|_| PinRefusal::Ownership)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(PinRefusal::Ownership);
        }
        pins.push((p.to_owned(), fd));
    }
    Ok(pins)
}
/// The client version the image's package metadata names, for a refusal its
/// owner reads; `None` when the image has no readable package metadata. It
/// admits nothing: a launch still requires the full pin.
pub(crate) fn image_client_version(agent: Agent) -> Option<String> {
    let package = layout(agent)?.package;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(package)
        .ok()?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 64 * 1024 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let version = value["version"].as_str()?;
    codewire_daemon_proto::platform_managed::valid_client_version(version)
        .then(|| version.to_owned())
}
impl ProviderPin {
    pub fn discover(agent: Agent) -> Result<Self, Error> {
        Self::admit_image_client(agent).map_err(PinRefusal::hosted)
    }
    /// The image's pinned client, or why it is not admitted. The hosted
    /// daemon and a local VM's guest both admit it here.
    pub fn admit_image_client(agent: Agent) -> Result<Self, PinRefusal> {
        let Layout {
            executable: path,
            package,
            name: expected_name,
            version,
            machine,
        } = layout(agent).ok_or(PinRefusal::Architecture)?;
        let pins = parents(Path::new(path))?;
        let package_pins = parents(Path::new(package))?;
        let mut meta = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(package)
            .map_err(open_refusal)?;
        let before = meta.metadata().map_err(|_| PinRefusal::Ownership)?;
        safe(&before, 64 * 1024, false)?;
        let mut bytes = Vec::new();
        (&mut meta)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PinRefusal::Invalid)?;
        if bytes.len() > 64 * 1024
            || stamp(&before) != stamp(&meta.metadata().map_err(|_| PinRefusal::Invalid)?)
            || stamp(&before)
                != stamp(&std::fs::symlink_metadata(package).map_err(|_| PinRefusal::Invalid)?)
        {
            return Err(PinRefusal::Invalid);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| PinRefusal::Invalid)?;
        if value["name"].as_str() != Some(expected_name)
            || value["version"].as_str() != Some(version)
        {
            return Err(PinRefusal::Version);
        }
        for (p, fd) in package_pins {
            let a = fd.metadata().map_err(|_| PinRefusal::Invalid)?;
            let b = std::fs::symlink_metadata(p).map_err(|_| PinRefusal::Invalid)?;
            if (a.dev(), a.ino(), a.mode(), a.uid()) != (b.dev(), b.ino(), b.mode(), b.uid()) {
                return Err(PinRefusal::Invalid);
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(open_refusal)?;
        let m = file.metadata().map_err(|_| PinRefusal::Ownership)?;
        safe(&m, PROVIDER_BYTES, true)?;
        let mut header = [0; 64];
        file.read_exact(&mut header)
            .map_err(|_| PinRefusal::Invalid)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01"
            || u16::from_le_bytes([header[18], header[19]]) != machine
        {
            return Err(PinRefusal::Invalid);
        }
        file.rewind().map_err(|_| PinRefusal::Invalid)?;
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
        let identity = ProviderIdentity {
            sha256: h.finalize().into(),
            size: total,
            version: version.into(),
        };
        let pin = Self {
            path: path.into(),
            file,
            stamp: stamp(&m),
            parents: pins,
            identity,
        };
        pin.check().map_err(|_| PinRefusal::Changed)?;
        Ok(pin)
    }
    pub fn admit(agent: Agent, expected: &ProviderIdentity) -> Result<Self, Error> {
        let pin = Self::discover(agent)?;
        if pin.identity != *expected {
            return Err(Error::Refused);
        }
        Ok(pin)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn check(&self) -> Result<(), Error> {
        for (p, fd) in &self.parents {
            let a = fd.metadata().map_err(|_| Error::Unknown)?;
            let b = std::fs::symlink_metadata(p).map_err(|_| Error::Unknown)?;
            if !b.is_dir()
                || b.uid() != 0
                || b.mode() & 0o022 != 0
                || (a.dev(), a.ino(), a.mode(), a.uid()) != (b.dev(), b.ino(), b.mode(), b.uid())
            {
                return Err(Error::Unknown);
            }
        }
        for m in [
            self.file.metadata().map_err(|_| Error::Unknown)?,
            std::fs::symlink_metadata(&self.path).map_err(|_| Error::Unknown)?,
        ] {
            if safe(&m, PROVIDER_BYTES, true).is_err() || stamp(&m) != self.stamp {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_architecture_pins_its_own_codex_vendor_binary_and_the_shared_claude_path() {
        let codex = layout(Agent::Codex).expect("a supported architecture");
        let claude = layout(Agent::Claude).expect("a supported architecture");
        let (triple, machine) = if cfg!(target_arch = "x86_64") {
            (
                "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
                62,
            )
        } else {
            (
                "codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex",
                183,
            )
        };
        assert!(codex.executable.ends_with(triple), "{}", codex.executable);
        assert_eq!(
            claude.executable,
            "/opt/codewire/agents/npm/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
        );
        for (agent, pinned) in [(Agent::Codex, &codex), (Agent::Claude, &claude)] {
            assert_eq!(pinned.machine, machine);
            assert_eq!(pinned.version, pinned_version(agent));
            assert!(
                pinned
                    .executable
                    .starts_with("/opt/codewire/agents/npm/lib/node_modules/")
            );
            assert_eq!(
                pinned.package,
                format!(
                    "/opt/codewire/agents/npm/lib/node_modules/{}/package.json",
                    pinned.name
                )
            );
        }
    }

    #[test]
    fn an_absent_pinned_path_is_missing_and_any_other_open_failure_is_ownership() {
        assert_eq!(
            open_refusal(std::io::Error::from(std::io::ErrorKind::NotFound)),
            PinRefusal::Missing
        );
        // O_NOFOLLOW on a symbolic link fails with ELOOP.
        assert_eq!(
            open_refusal(std::io::Error::from_raw_os_error(libc::ELOOP)),
            PinRefusal::Ownership
        );
    }

    #[test]
    fn a_refusal_names_its_reason_and_the_pinned_version() {
        assert_eq!(
            PinRefusal::Version.reason(Agent::Claude),
            "the image's pinned Claude Code is not version 2.1.288"
        );
        assert_eq!(
            PinRefusal::Missing.reason(Agent::Codex),
            "the image has no pinned Codex"
        );
        assert!(
            PinRefusal::Ownership
                .reason(Agent::Codex)
                .contains("not root-owned and read-only")
        );
    }

    #[test]
    fn a_hosted_launch_refuses_every_reason_and_reports_a_changed_pin_as_unknown() {
        for refusal in [
            PinRefusal::Architecture,
            PinRefusal::Missing,
            PinRefusal::Version,
            PinRefusal::Ownership,
            PinRefusal::Invalid,
        ] {
            assert!(matches!(refusal.hosted(), Error::Refused));
        }
        assert!(matches!(PinRefusal::Changed.hosted(), Error::Unknown));
    }
}
