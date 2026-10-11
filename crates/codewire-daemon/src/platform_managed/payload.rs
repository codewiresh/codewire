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
fn layout(agent: Agent) -> (&'static str, &'static str, &'static str) {
    match agent {
        Agent::Codex => (
            "/opt/codewire/agents/npm/lib/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
            "/opt/codewire/agents/npm/lib/node_modules/@openai/codex/package.json",
            "0.160.0",
        ),
        Agent::Claude => (
            "/opt/codewire/agents/npm/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "/opt/codewire/agents/npm/lib/node_modules/@anthropic-ai/claude-code/package.json",
            "2.1.288",
        ),
    }
}
fn safe(m: &std::fs::Metadata, bound: u64, exec: bool) -> bool {
    m.is_file()
        && m.uid() == 0
        && m.nlink() == 1
        && m.mode() & 0o6022 == 0
        && m.len() >= 4
        && m.len() <= bound
        && (!exec || m.mode() & 0o111 != 0)
}
fn parents(path: &Path) -> Result<Vec<(PathBuf, File)>, Error> {
    let mut pins = Vec::new();
    for p in path.parent().ok_or(Error::Refused)?.ancestors() {
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)
            .map_err(|_| Error::Refused)?;
        let m = fd.metadata().map_err(|_| Error::Refused)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error::Refused);
        }
        pins.push((p.to_owned(), fd));
    }
    Ok(pins)
}
impl ProviderPin {
    pub fn discover(agent: Agent) -> Result<Self, Error> {
        if !cfg!(target_arch = "x86_64") {
            return Err(Error::Refused);
        }
        let (path, package, version) = layout(agent);
        let pins = parents(Path::new(path))?;
        let package_pins = parents(Path::new(package))?;
        let mut meta = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(package)
            .map_err(|_| Error::Refused)?;
        let before = meta.metadata().map_err(|_| Error::Refused)?;
        if !safe(&before, 64 * 1024, false) {
            return Err(Error::Refused);
        }
        let mut bytes = Vec::new();
        (&mut meta)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Refused)?;
        if bytes.len() > 64 * 1024
            || stamp(&before) != stamp(&meta.metadata().map_err(|_| Error::Refused)?)
            || stamp(&before)
                != stamp(&std::fs::symlink_metadata(package).map_err(|_| Error::Refused)?)
        {
            return Err(Error::Refused);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::Refused)?;
        let expected_name = match agent {
            Agent::Codex => "@openai/codex",
            Agent::Claude => "@anthropic-ai/claude-code",
        };
        if value["name"].as_str() != Some(expected_name)
            || value["version"].as_str() != Some(version)
        {
            return Err(Error::Refused);
        }
        for (p, fd) in package_pins {
            let a = fd.metadata().map_err(|_| Error::Refused)?;
            let b = std::fs::symlink_metadata(p).map_err(|_| Error::Refused)?;
            if (a.dev(), a.ino(), a.mode(), a.uid()) != (b.dev(), b.ino(), b.mode(), b.uid()) {
                return Err(Error::Refused);
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::Refused)?;
        let m = file.metadata().map_err(|_| Error::Refused)?;
        if !safe(&m, PROVIDER_BYTES, true) {
            return Err(Error::Refused);
        }
        let mut header = [0; 64];
        file.read_exact(&mut header).map_err(|_| Error::Refused)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01"
            || u16::from_le_bytes([header[18], header[19]]) != 62
        {
            return Err(Error::Refused);
        }
        file.rewind().map_err(|_| Error::Refused)?;
        let mut h = Sha256::new();
        let mut total = 0_u64;
        let mut buf = [0; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|_| Error::Refused)?;
            if n == 0 {
                break;
            }
            total = total.checked_add(n as u64).ok_or(Error::Refused)?;
            if total > PROVIDER_BYTES {
                return Err(Error::Refused);
            }
            h.update(&buf[..n]);
        }
        if total != m.len() {
            return Err(Error::Refused);
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
        pin.check()?;
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
            if !safe(&m, PROVIDER_BYTES, true) || stamp(&m) != self.stamp {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }
}
