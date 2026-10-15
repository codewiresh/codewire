//! Workspace paths kept on the VM's own disk (codewire.yaml `workspace.vm_only`).
//!
//! Each listed path of a read-write direct share is backed by a directory on
//! the state disk, `/state/vm-only/<sha256 of the guest path>`, bound over that
//! path inside the share. Installs and builds there run at VM-disk speed, and
//! the host's folder, if any, is hidden from the VM and left alone.
//!
//! Confinement: the paths come from the seed-bound direct-share plan. Every
//! lookup starts at the share's own mount root and opens one component at a
//! time beneath it without following symlinks or crossing a mount, so a bind
//! lands only on a directory of that share; the bind is made through the
//! opened descriptors. Only the last component is ever created, as an empty
//! directory on the share. A symlink, a file, or a missing parent at a listed
//! path is left as it is and reported on the console. The backing root is
//! root-owned, mode 0700 and outside everything the workload sees, so the
//! workload can neither swap a backing directory nor reach its parent.
//!
//! Kept binds: replacing or deleting the folder on the host (`cargo clean`,
//! `rm -rf node_modules`) invalidates the guest's dentry and the kernel then
//! detaches every mount on it. Each share mount is shared with the workload's
//! slave copy, so `Keeper::tick` binds the folder again from init's namespace
//! within a second and the bind propagates into the workload.

use std::fs;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use rustix::fs::{
    FileType as RustixFileType, Mode as RustixMode, OFlags as RustixOFlags, ResolveFlags,
    StatVfsMountFlags,
};
use rustix::io::Errno as RustixErrno;
use sha2::{Digest as _, Sha256};

use crate::DirectShareMount;

pub(super) const VM_ONLY_ROOT_PATH: &str = "/state/vm-only";
const RETIRED_NAME: &str = ".retired";
/// virtio-fs is FUSE in the guest, on Cloud Hypervisor and on VZ alike.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
const KEEPER_INTERVAL: Duration = Duration::from_secs(1);
const BENEATH: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Create the root-owned backing root and its retired-tree directory.
pub(super) fn create_layout() -> Result<()> {
    for path in [
        VM_ONLY_ROOT_PATH.to_owned(),
        format!("{VM_ONLY_ROOT_PATH}/{RETIRED_NAME}"),
    ] {
        super::create_dir(Path::new(&path), 0o700)?;
        super::lchown(Path::new(&path), 0, 0)?;
    }
    Ok(())
}

/// One read-write share with paths kept in the VM.
pub(super) struct Share {
    /// The share's mount root in init's namespace, opened just after mounting.
    root: OwnedFd,
    destination: String,
    paths: Vec<String>,
}

/// Mark a just-mounted share shared, so the workload's slave copy receives
/// later binds, and open its mount root. `workspace` is /state/workspace.
pub(super) fn admit_share(
    workspace: &OwnedFd,
    relative: &Path,
    target_path: &str,
    share: &DirectShareMount,
) -> Result<Share> {
    ensure!(
        !share.read_only() && !share.vm_only().is_empty(),
        "vm_only applies only to a read-write direct share"
    );
    super::mount_fs("none", target_path, "none", libc::MS_SHARED, "")
        .context("share the direct-share mount with the workspace")?;
    let root = rustix::fs::openat2(
        workspace,
        relative,
        RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH,
    )
    .context("open the direct-share mount root")?;
    let filesystem = rustix::fs::fstatfs(&root).context("inspect the direct-share mount")?;
    let root_stat = rustix::fs::fstat(&root).context("inspect the direct-share mount root")?;
    let workspace_stat =
        rustix::fs::fstat(workspace).context("inspect the persistent workspace")?;
    ensure!(
        filesystem.f_type as u64 == FUSE_SUPER_MAGIC && root_stat.st_dev != workspace_stat.st_dev,
        "direct-share mount root is not the virtio-fs share"
    );
    Ok(Share {
        root,
        destination: share.destination().to_owned(),
        paths: share.vm_only().to_vec(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Bound,
    /// Left as it is on the share: the reason, for the console.
    Skipped(&'static str),
}

/// Binds every kept path at boot and keeps the binds in place afterwards.
pub(super) struct Keeper {
    shares: Vec<Share>,
    uid: u32,
    gid: u32,
    last: Vec<Vec<Option<String>>>,
    next: Instant,
}

impl Keeper {
    /// Bind every kept path before the workload starts. A failure on the VM
    /// disk or of the bind itself fails the boot; a path the share content
    /// blocks is skipped and reported.
    pub(super) fn bind_at_boot(shares: Vec<Share>, uid: u32, gid: u32) -> Result<Self> {
        let mut last = Vec::with_capacity(shares.len());
        for share in &shares {
            let mut states = Vec::with_capacity(share.paths.len());
            for path in &share.paths {
                let backing = open_backing(&share.destination, path, uid, gid, true)?;
                let outcome = bind(&share.root, path, &backing).with_context(|| {
                    format!("keep {}/{path} on the VM's disk", share.destination)
                })?;
                let line = report(&share.destination, path, &Ok(outcome));
                eprintln!("{line}");
                states.push(Some(line));
            }
            last.push(states);
        }
        // Trees retired for an earlier workspace owner are rebuildable
        // caches; remove them without delaying the boot.
        thread::spawn(remove_retired);
        Ok(Self {
            shares,
            uid,
            gid,
            last,
            next: Instant::now() + KEEPER_INTERVAL,
        })
    }

    /// At most once a second, bind again any kept path whose bind the kernel
    /// detached because the host replaced or removed the folder. Never fails
    /// the running VM; a changed outcome is reported on the console.
    pub(super) fn tick(&mut self) {
        let now = Instant::now();
        if now < self.next {
            return;
        }
        self.next = now + KEEPER_INTERVAL;
        for (share, states) in self.shares.iter().zip(self.last.iter_mut()) {
            for (path, state) in share.paths.iter().zip(states.iter_mut()) {
                let outcome = open_backing(&share.destination, path, self.uid, self.gid, false)
                    .and_then(|backing| bind(&share.root, path, &backing));
                let line = report(&share.destination, path, &outcome);
                if state.as_deref() != Some(line.as_str()) {
                    eprintln!("{line}");
                    *state = Some(line);
                }
            }
        }
    }
}

fn report(destination: &str, path: &str, outcome: &Result<Outcome>) -> String {
    match outcome {
        Ok(Outcome::Bound) => format!("vm_only: {destination}/{path} is on the VM's disk"),
        Ok(Outcome::Skipped(reason)) => {
            format!("vm_only: {destination}/{path} stays shared with the host: {reason}")
        }
        Err(error) => format!("vm_only: {destination}/{path} could not be kept: {error:#}"),
    }
}

/// The backing directory's name: the guest path it serves, hashed, so every
/// name is one fixed-length component.
pub(super) fn backing_name(destination: &str, path: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{destination}/{path}").as_bytes())
    )
}

/// Open the backing directory, creating it for the workspace owner. At boot
/// (`retire`), one owned by another user (the workspace image's user changed;
/// the workload cannot chown) is retired and replaced by an empty one. The
/// workload's own permission changes never retire anything.
fn open_backing(
    destination: &str,
    path: &str,
    uid: u32,
    gid: u32,
    retire: bool,
) -> Result<OwnedFd> {
    let root = rustix::fs::open(
        VM_ONLY_ROOT_PATH,
        RustixOFlags::PATH
            | RustixOFlags::DIRECTORY
            | RustixOFlags::NOFOLLOW
            | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
    )
    .context("open the VM-disk root for kept paths")?;
    let name = backing_name(destination, path);
    for _ in 0..2 {
        let created =
            match rustix::fs::mkdirat(&root, name.as_str(), RustixMode::from_raw_mode(0o700)) {
                Ok(()) => true,
                Err(RustixErrno::EXIST) => false,
                Err(error) => return Err(error).context("create a VM-disk directory"),
            };
        let backing = rustix::fs::openat2(
            &root,
            name.as_str(),
            RustixOFlags::RDONLY
                | RustixOFlags::DIRECTORY
                | RustixOFlags::NOFOLLOW
                | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
            BENEATH | ResolveFlags::NO_XDEV,
        )
        .context("open a VM-disk directory")?;
        if created {
            rustix::fs::fchown(
                &backing,
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            )
            .context("give a VM-disk directory to the workspace owner")?;
            rustix::fs::fchmod(&backing, RustixMode::from_raw_mode(0o755))
                .context("set a VM-disk directory's mode")?;
            return Ok(backing);
        }
        let stat = rustix::fs::fstat(&backing).context("inspect a VM-disk directory")?;
        if !retire || stat.st_uid == uid {
            return Ok(backing);
        }
        drop(backing);
        let retired_name = format!(
            "{name}.{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        );
        let retired_root = rustix::fs::openat2(
            &root,
            RETIRED_NAME,
            RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
            BENEATH | ResolveFlags::NO_XDEV,
        )
        .context("open the retired VM-disk directories")?;
        rustix::fs::renameat(&root, name.as_str(), &retired_root, retired_name.as_str())
            .context("retire a VM-disk directory of an earlier workspace owner")?;
    }
    anyhow::bail!("a VM-disk directory kept changing owner")
}

fn remove_retired() {
    let retired = Path::new(VM_ONLY_ROOT_PATH).join(RETIRED_NAME);
    let Ok(entries) = fs::read_dir(&retired) else {
        return;
    };
    for entry in entries.flatten() {
        // remove_dir_all never follows a symlink out of the tree.
        if let Err(error) = fs::remove_dir_all(entry.path()) {
            eprintln!("vm_only: could not remove a retired VM-disk directory: {error}");
        }
    }
}

/// Bind `backing` over `path` beneath the share `root`, unless it already is.
fn bind(root: &OwnedFd, path: &str, backing: &OwnedFd) -> Result<Outcome> {
    let mut components = path.split('/').collect::<Vec<_>>();
    let Some(last) = components.pop() else {
        anyhow::bail!("kept path is empty");
    };
    let mut parent = rustix::io::dup(root).context("reopen the direct-share root")?;
    for component in components {
        parent = match open_on_share(&parent, component) {
            Ok(next) => next,
            Err(error) => return Ok(Outcome::Skipped(skip_reason(error, false))),
        };
    }
    let backing_stat = rustix::fs::fstat(backing).context("inspect a VM-disk directory")?;
    if is_backing(&parent, last, &backing_stat)? {
        return Ok(Outcome::Bound);
    }
    match rustix::fs::mkdirat(&parent, last, RustixMode::from_raw_mode(0o755)) {
        Ok(()) | Err(RustixErrno::EXIST) => {}
        Err(error) => return Ok(Outcome::Skipped(skip_reason(error, true))),
    }
    let target = match open_on_share(&parent, last) {
        Ok(target) => target,
        Err(error) => return Ok(Outcome::Skipped(skip_reason(error, true))),
    };
    super::mount_fs(
        &format!("/proc/self/fd/{}", backing.as_raw_fd()),
        &format!("/proc/self/fd/{}", target.as_raw_fd()),
        "none",
        libc::MS_BIND,
        "",
    )
    .context("bind a VM-disk directory over the share")?;
    // The bind inherits nosuid and nodev from the state disk's mount. A host
    // that moved the folder in between leaves it bound elsewhere on the same
    // share; the next tick binds the listed path again.
    let bound = rustix::fs::openat2(
        &parent,
        last,
        RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH,
    );
    let Ok(bound) = bound else {
        return Ok(Outcome::Skipped(
            "the host changed the folder during the bind",
        ));
    };
    let flags = rustix::fs::fstatvfs(&bound)
        .context("inspect a kept path's mount")?
        .f_flag;
    ensure!(
        flags.contains(StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV)
            && !flags.contains(StatVfsMountFlags::RDONLY),
        "a kept path's mount lacks nosuid or nodev"
    );
    let stat = rustix::fs::fstat(&bound).context("inspect a kept path's mount")?;
    if (stat.st_dev, stat.st_ino) != (backing_stat.st_dev, backing_stat.st_ino) {
        return Ok(Outcome::Skipped(
            "the host changed the folder during the bind",
        ));
    }
    Ok(Outcome::Bound)
}

/// One directory component beneath `parent` on the same share mount: no
/// symlink, no magic link, no mount crossing.
fn open_on_share(parent: &OwnedFd, component: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(
        parent,
        component,
        RustixOFlags::PATH
            | RustixOFlags::DIRECTORY
            | RustixOFlags::NOFOLLOW
            | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH | ResolveFlags::NO_XDEV,
    )
}

/// Whether `name` beneath `parent` already shows the backing directory.
fn is_backing(parent: &OwnedFd, name: &str, backing: &rustix::fs::Stat) -> Result<bool> {
    let opened = rustix::fs::openat2(
        parent,
        name,
        RustixOFlags::PATH | RustixOFlags::NOFOLLOW | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH,
    );
    let opened = match opened {
        Ok(opened) => opened,
        Err(RustixErrno::NOENT | RustixErrno::LOOP | RustixErrno::NOTDIR) => return Ok(false),
        Err(error) => return Err(error).context("inspect a kept path"),
    };
    let stat = rustix::fs::fstat(opened.as_fd()).context("inspect a kept path")?;
    Ok(
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::Directory
            && (stat.st_dev, stat.st_ino) == (backing.st_dev, backing.st_ino),
    )
}

fn skip_reason(error: RustixErrno, last: bool) -> &'static str {
    match error {
        RustixErrno::NOENT if !last => "a parent folder is missing",
        RustixErrno::NOENT => "the folder could not be created",
        RustixErrno::NOTDIR if last => "it is a file",
        RustixErrno::NOTDIR => "a parent is a file",
        RustixErrno::LOOP => "it or a parent is a symlink",
        RustixErrno::XDEV => "another mount is in the way",
        RustixErrno::ACCESS | RustixErrno::PERM | RustixErrno::ROFS => {
            "the folder could not be created"
        }
        _ => "the share refused the lookup",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backing_names_are_one_fixed_component_per_guest_path() {
        let name = backing_name("/workspace/app", "node_modules");
        assert_eq!(name.len(), 64);
        assert!(name.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(name, backing_name("/workspace/app", "target"));
        assert_ne!(name, backing_name("/workspace/other", "node_modules"));
        assert_eq!(name, backing_name("/workspace/app", "node_modules"));
        assert_ne!(name, RETIRED_NAME);
    }

    #[test]
    fn share_lookup_refusals_skip_with_a_reason() {
        assert_eq!(
            skip_reason(RustixErrno::LOOP, true),
            "it or a parent is a symlink"
        );
        assert_eq!(skip_reason(RustixErrno::NOTDIR, true), "it is a file");
        assert_eq!(
            skip_reason(RustixErrno::NOENT, false),
            "a parent folder is missing"
        );
        assert_eq!(
            skip_reason(RustixErrno::XDEV, true),
            "another mount is in the way"
        );
    }
}
