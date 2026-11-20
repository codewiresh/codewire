//! The deployment's extra roots for a broker-mode daemon's DERP relay
//! (#4000): the bundle the coordinator's client already trusts, mounted
//! read-only by the platform. A root here lets a certificate verify for the
//! relay the daemon dials, so the workload must not be able to add one.
//!
//! It is read once, at the daemon's start, from the fixed platform path,
//! and only when that path is a read-only mount of its own, as the platform's
//! ConfigMap volume is (#5523). Where nothing is mounted, as on Dev and
//! Production, a directory and file put at the path are not read, whoever
//! owns them: the path is logged as ignored and the daemon starts with no
//! extra root, so a relay that needs one is refused as unverified.
//!
//! Root with `CAP_SYS_ADMIN` in the hosted guest can mount over the path, as
//! it can restart or replace the daemon. That is within the Sandbox's own
//! trust boundary and accepted: a planted root only affects that Sandbox's
//! own relay TLS, whose traffic is encrypted end to end and whose relay is
//! dialled at a fixed in-cluster address. The mount check stops the
//! platform's trust being widened by accident, by a non-root process or a
//! stray file; it does not keep a tenant from attacking itself.
//!
//! On the platform's mount every other check is fatal, because a broken
//! platform mount should be loud. The directory is opened without following
//! a link; the file is
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
use rustix::fs::{
    AtFlags, Mode, OFlags, ResolveFlags, Stat, StatVfsMountFlags, StatxAttributes, StatxFlags,
};
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
    extra_roots_from(broker, measured, mount, file, platform_mount)
}

/// [`derp_extra_roots`], with `platform_mount` deciding whether the opened
/// directory is the platform's own mount. Tests lay a mount out in a plain
/// directory and pass the decision in.
fn extra_roots_from(
    broker: bool,
    measured: bool,
    mount: &Path,
    file: &str,
    platform_mount: impl FnOnce(&OwnedFd) -> anyhow::Result<bool>,
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
    if !platform_mount(&directory)
        .with_context(|| format!("inspect the extra roots directory {}", mount.display()))?
    {
        tracing::warn!(
            path = %mount.display(),
            "the DERP relay's extra roots path is not a read-only mount of its own; nothing there is read"
        );
        return Ok(Vec::new());
    }
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

/// Whether `directory` is the root of a mount and that mount is read-only:
/// what a ConfigMap volume is, and what a directory made in the container's
/// own filesystem is not. A kernel that does not report mount roots answers
/// no, so nothing is read.
fn platform_mount(directory: &OwnedFd) -> anyhow::Result<bool> {
    Ok(is_mount_root(directory)? && is_read_only(directory)?)
}

fn is_mount_root(directory: &OwnedFd) -> anyhow::Result<bool> {
    let stat = rustix::fs::statx(directory, "", AtFlags::EMPTY_PATH, StatxFlags::empty())
        .context("statx")?;
    Ok(stat
        .stx_attributes_mask
        .contains(StatxAttributes::MOUNT_ROOT)
        && stat.stx_attributes.contains(StatxAttributes::MOUNT_ROOT))
}

fn is_read_only(directory: &OwnedFd) -> anyhow::Result<bool> {
    Ok(rustix::fs::fstatvfs(directory)
        .context("fstatvfs")?
        .f_flag
        .contains(StatVfsMountFlags::RDONLY))
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
