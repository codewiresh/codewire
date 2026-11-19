//! The deployment's extra roots for a broker-mode daemon's DERP relay
//! (#4000): the bundle the coordinator's client already trusts, mounted
//! read-only by the platform. A root here lets a certificate verify for the
//! relay the daemon dials, so the workload must not be able to add one.
//!
//! It is read once, at the daemon's start, from the fixed platform path.
//! The mount directory is opened without following a link; the file is
//! opened beneath it with `openat2`, so the kubelet's `..data` link resolves
//! only inside the mount and one that leaves it is refused. Both must be
//! owned by root or the daemon's own user and writable by no one else, and
//! the bundle is read from the descriptor that was checked. A kernel that
//! cannot open it contained (no `openat2`, or flags it does not know) reads
//! no bundle, never falls back to a plain open: a relay that needs one is
//! then refused as unverified.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{Context as _, bail};
use codewire_tailnet::platform_dial::PlatformRoots;
use rustix::fs::{Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;

/// A bundle is a few certificates; anything far larger is not one.
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;

/// The extra roots for a broker-mode daemon that is not a measured
/// workspace: none when the bundle is not mounted. Outside broker mode, and
/// for a measured workspace, which trusts the WebPKI roots only, none.
pub(crate) fn derp_extra_roots(
    broker: bool,
    measured: bool,
    mount: &Path,
    file: &str,
) -> anyhow::Result<PlatformRoots> {
    if !broker || measured {
        return Ok(Vec::new());
    }
    let directory = match rustix::fs::open(
        mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("open {}", mount.display()));
        }
    };
    platform_owned(&rustix::fs::fstat(&directory)?)
        .with_context(|| format!("the extra roots directory {}", mount.display()))?;
    let opened = rustix::fs::openat2(
        &directory,
        file,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    );
    let Some(bundle) = bundle_or_none(opened).with_context(|| {
        format!(
            "open {file} beneath {}, inside the mount only",
            mount.display()
        )
    })?
    else {
        return Ok(Vec::new());
    };
    let stat = rustix::fs::fstat(&bundle)?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() {
        bail!("the extra roots bundle {file} is not a regular file");
    }
    platform_owned(&stat).with_context(|| format!("the extra roots bundle {file}"))?;
    codewire_tls::roots_from_pem(&read_bounded(bundle)?)
        .with_context(|| format!("parse the extra roots bundle {file}"))
}

/// What a contained open's result means: the bundle; none when it is not
/// there, or when the kernel cannot open it contained (no `openat2`, or
/// flags it does not know); an error for anything else, a link that leaves
/// the mount among them.
fn bundle_or_none(opened: Result<OwnedFd, Errno>) -> Result<Option<OwnedFd>, Errno> {
    match opened {
        Ok(bundle) => Ok(Some(bundle)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::NOSYS | Errno::INVAL) => {
            tracing::warn!(
                "the kernel cannot open the DERP relay's extra roots contained to their mount; none are read, and a relay that needs them is refused as unverified"
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Owned by root or this process's user, and writable by no one else.
fn platform_owned(stat: &Stat) -> anyhow::Result<()> {
    let owner = stat.st_uid;
    if owner != 0 && owner != rustix::process::geteuid().as_raw() {
        bail!("is owned by uid {owner}, not root or the daemon's user");
    }
    if stat.st_mode & 0o022 != 0 {
        bail!("is writable by its group or by others");
    }
    Ok(())
}

fn read_bounded(file: OwnedFd) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::from(file)
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_BYTES {
        bail!("the extra roots bundle is larger than {MAX_BUNDLE_BYTES} bytes");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
