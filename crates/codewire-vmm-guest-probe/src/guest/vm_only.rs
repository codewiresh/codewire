//! Workspace folders kept on the VM's own disk (codewire.yaml `workspace.vm_only`).
//!
//! The seed-bound direct-share plan carries `.dockerignore`-style patterns.
//! At every boot, before any workload process exists, init expands them over
//! its own view of each read-write share ([`codewire_project::expand_vm_only`]):
//! it lists folders from the share's mount root down, opening each one by
//! itself without following symlinks or crossing a mount, never enters `.git`,
//! keeps a matching folder whole (outermost wins), leaves a match that holds
//! its own `.git` shared, and stops at the walk's caps and a deadline. A list
//! of plain names needs no walk. Each folder found is backed by a directory on
//! the state disk, `/state/vm-only/<sha256 of the guest path>`, bound over it
//! inside the share. Installs and builds there run at VM-disk speed, and the
//! host's folder is hidden from the VM and left alone. A folder created after
//! boot that matches is kept from the next boot.
//!
//! Confinement: every bind lookup starts again at the share's mount root and
//! opens one checked component at a time beneath it without following
//! symlinks or crossing a mount, so a bind lands only on a directory of that
//! share; the bind is made through the opened descriptors. Only the last
//! component of a plain name is ever created, as an empty directory on the
//! share. Whatever the share holds (a symlink, a file, a missing parent, a
//! folder it refuses to show) leaves that path shared and is reported on the
//! console; only a failure on the VM's own disk fails the boot. The backing
//! root is root-owned, mode 0700 and outside everything the workload sees, so
//! the workload can neither swap a backing directory nor reach its parent.
//!
//! Kept binds: replacing or deleting the folder on the host (`cargo clean`,
//! `rm -rf node_modules`) invalidates the guest's dentry and the kernel then
//! detaches every mount on it. Each share mount is shared with the workload's
//! slave copy, so `Keeper::tick` binds the folder again from init's namespace
//! and the bind propagates into the workload: at once when the mount table
//! changes, and otherwise a few paths a second in turn.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use codewire_project::{MAX_VM_ONLY_MATCHES, VmOnlyPatterns, VmOnlyTree, expand_vm_only};
use rustix::fs::{
    FileType as RustixFileType, Mode as RustixMode, OFlags as RustixOFlags, ResolveFlags,
    StatVfsMountFlags, Timespec, Timestamps, UTIME_NOW,
};
use rustix::io::Errno as RustixErrno;
use sha2::{Digest as _, Sha256};

use crate::DirectShareMount;

pub(super) const VM_ONLY_ROOT_PATH: &str = "/state/vm-only";
const RETIRED_NAME: &str = ".retired";
/// virtio-fs is FUSE in the guest, on Cloud Hypervisor and on VZ alike.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
const KEEPER_INTERVAL: Duration = Duration::from_secs(1);
/// Kept paths looked at per tick while the mount table is unchanged.
const KEEPER_PATHS_PER_TICK: usize = 16;
/// How long one boot spends finding kept folders, across every share.
const EXPANSION_DEADLINE: Duration = Duration::from_secs(10);
/// A backing directory no boot has bound for this long is retired.
const ORPHAN_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
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

/// One read-write share with folders kept in the VM.
pub(super) struct Share {
    /// The share's mount root in init's namespace, opened just after mounting.
    root: OwnedFd,
    destination: String,
    patterns: VmOnlyPatterns,
    /// The folders the patterns matched at boot.
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
    let patterns =
        VmOnlyPatterns::parse(share.vm_only()).context("parse the share's vm_only patterns")?;
    super::mount_fs("none", target_path, "none", libc::MS_SHARED, "")
        .context("share the direct-share mount with the workspace")?;
    // A share at /workspace itself covers the persistent workspace, which
    // `workspace` was opened on before the mount: open its root by path,
    // and the device check below still tells the share from the disk.
    let root = if relative.as_os_str().is_empty() {
        rustix::fs::open(
            target_path,
            RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
        )
    } else {
        rustix::fs::openat2(
            workspace,
            relative,
            RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
            BENEATH,
        )
    }
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
        patterns,
        paths: Vec::new(),
    })
}

/// A share's folders, listed and opened through descriptors beneath its
/// mount root: never through a symlink, never across a mount.
struct ShareTree {
    deadline: Instant,
}

impl VmOnlyTree for ShareTree {
    type Folder = OwnedFd;

    fn names(&mut self, folder: &OwnedFd) -> Vec<String> {
        let Ok(mut entries) = rustix::fs::Dir::read_from(folder) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for entry in &mut entries {
            let Ok(entry) = entry else {
                break;
            };
            if !matches!(
                entry.file_type(),
                RustixFileType::Directory | RustixFileType::Unknown
            ) {
                continue;
            }
            if let Ok(name) = entry.file_name().to_str() {
                names.push(name.to_owned());
            }
        }
        names
    }

    fn open(&mut self, folder: &OwnedFd, name: &str) -> Option<OwnedFd> {
        rustix::fs::openat2(
            folder,
            name,
            RustixOFlags::RDONLY
                | RustixOFlags::DIRECTORY
                | RustixOFlags::NOFOLLOW
                | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
            BENEATH | ResolveFlags::NO_XDEV,
        )
        .ok()
    }

    fn holds_repository(&mut self, folder: &OwnedFd) -> bool {
        holds_repository(folder)
    }

    fn exhausted(&mut self) -> bool {
        Instant::now() >= self.deadline
    }
}

/// Whether `folder` holds a `.git` entry of any kind. A lookup the share
/// refuses counts as one, so such a folder stays shared.
fn holds_repository(folder: &OwnedFd) -> bool {
    !matches!(
        rustix::fs::openat2(
            folder,
            ".git",
            RustixOFlags::PATH | RustixOFlags::NOFOLLOW | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
            BENEATH | ResolveFlags::NO_XDEV,
        ),
        Err(RustixErrno::NOENT)
    )
}

/// The share's folders its patterns match now, and whether a cap or the
/// deadline stopped the search.
fn expand(share: &Share, deadline: Instant) -> Result<(Vec<String>, bool)> {
    let root = rustix::fs::openat2(
        &share.root,
        ".",
        RustixOFlags::RDONLY | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH | ResolveFlags::NO_XDEV,
    )
    .context("open the direct-share root to find kept folders")?;
    let expansion = expand_vm_only(&share.patterns, &mut ShareTree { deadline }, &root);
    for repository in &expansion.repositories {
        eprintln!(
            "vm_only: {}/{repository} stays shared with the host: it holds a Git repository",
            share.destination
        );
    }
    if expansion.truncated {
        eprintln!(
            "vm_only: {}: a limit stopped the search for kept folders; {} kept",
            share.destination,
            expansion.matches.len()
        );
    }
    Ok((
        expansion
            .matches
            .into_iter()
            .map(|found| found.path)
            .collect(),
        expansion.truncated,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// Bound now or before; `hid` when this bind newly hid host files.
    Bound { hid: bool },
    /// Left as it is on the share: the reason, for the console.
    Skipped(&'static str),
}

/// Binds every kept folder at boot and keeps the binds in place afterwards.
pub(super) struct Keeper {
    shares: Vec<Share>,
    uid: u32,
    gid: u32,
    vm_root: OwnedFd,
    last: Vec<Vec<Option<String>>>,
    next: Instant,
    turn: usize,
    mountinfo: Option<File>,
}

impl Keeper {
    /// Find and bind every kept folder before the workload starts. A failure
    /// on the VM's disk, or a bind without nosuid and nodev, fails the boot;
    /// anything the share content causes is skipped and reported.
    pub(super) fn bind_at_boot(mut shares: Vec<Share>, uid: u32, gid: u32) -> Result<Self> {
        let vm_root = rustix::fs::open(
            VM_ONLY_ROOT_PATH,
            RustixOFlags::PATH
                | RustixOFlags::DIRECTORY
                | RustixOFlags::NOFOLLOW
                | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
        )
        .context("open the VM-disk root for kept folders")?;
        let deadline = Instant::now() + EXPANSION_DEADLINE;
        let mut remaining = MAX_VM_ONLY_MATCHES;
        let mut complete = true;
        let mut walked = false;
        for share in &mut shares {
            let (mut paths, truncated) = expand(share, deadline)?;
            walked |= share.patterns.needs_walk();
            if paths.len() > remaining {
                eprintln!(
                    "vm_only: {}: the VM keeps at most {MAX_VM_ONLY_MATCHES} folders; {} more stay shared",
                    share.destination,
                    paths.len() - remaining
                );
                paths.truncate(remaining);
                complete = false;
            }
            complete &= !truncated;
            remaining -= paths.len();
            share.paths = paths;
        }
        if walked {
            // The search looked up many share entries; let the guest forget
            // them so virtiofsd closes the host descriptors it held for each.
            let _ = fs::write("/proc/sys/vm/drop_caches", b"2");
        }
        let mut used = BTreeSet::new();
        let mut last = Vec::with_capacity(shares.len());
        for share in &shares {
            let mut states = Vec::with_capacity(share.paths.len());
            for path in &share.paths {
                let name = backing_name(&share.destination, path);
                let (backing, created) = open_backing(&vm_root, &name, uid, gid, true)?;
                let outcome = bind(&share.root, path, &backing, created).with_context(|| {
                    format!("keep {}/{path} on the VM's disk", share.destination)
                })?;
                if matches!(outcome, Outcome::Bound { .. }) {
                    used.insert(name);
                    let now = Timespec {
                        tv_sec: 0,
                        tv_nsec: UTIME_NOW,
                    };
                    // Marks it seen, for retiring folders no boot binds.
                    let _ = rustix::fs::futimens(
                        &backing,
                        &Timestamps {
                            last_access: now,
                            last_modification: now,
                        },
                    );
                }
                let line = report(&share.destination, path, &Ok(outcome));
                eprintln!("{line}");
                states.push(Some(line));
            }
            last.push(states);
        }
        if complete {
            retire_orphans(&vm_root, &used);
        }
        // Retired trees are rebuildable caches; remove them without delaying
        // the boot.
        thread::spawn(remove_retired);
        let mut mountinfo = File::open("/proc/self/mountinfo").ok();
        if let Some(file) = mountinfo.as_mut() {
            let _ = std::io::copy(file, &mut std::io::sink());
        }
        Ok(Self {
            shares,
            uid,
            gid,
            vm_root,
            last,
            next: Instant::now() + KEEPER_INTERVAL,
            turn: 0,
            mountinfo,
        })
    }

    /// At most once a second, bind again a kept folder whose bind the kernel
    /// detached because the host replaced or removed it: every folder when
    /// the mount table changed, otherwise the next few in turn. Never fails
    /// the running VM; a changed outcome is reported on the console.
    pub(super) fn tick(&mut self) {
        let now = Instant::now();
        if now < self.next {
            return;
        }
        self.next = now + KEEPER_INTERVAL;
        let all = (0..self.shares.len())
            .flat_map(|share| (0..self.shares[share].paths.len()).map(move |path| (share, path)))
            .collect::<Vec<_>>();
        if all.is_empty() {
            return;
        }
        let chosen = if self.mount_table_changed() {
            all.clone()
        } else {
            (0..KEEPER_PATHS_PER_TICK.min(all.len()))
                .map(|offset| all[(self.turn + offset) % all.len()])
                .collect()
        };
        self.turn = (self.turn + KEEPER_PATHS_PER_TICK) % all.len();
        for (share_index, path_index) in chosen {
            let share = &self.shares[share_index];
            let path = &share.paths[path_index];
            let name = backing_name(&share.destination, path);
            let outcome = open_backing(&self.vm_root, &name, self.uid, self.gid, false)
                .and_then(|(backing, _)| bind(&share.root, path, &backing, false));
            let line = report(&share.destination, path, &outcome);
            let state = &mut self.last[share_index][path_index];
            if state.as_deref() != Some(line.as_str()) {
                eprintln!("{line}");
                *state = Some(line);
            }
        }
    }

    /// Whether init's mount table changed since the last look; reading the
    /// file again rearms the notice.
    fn mount_table_changed(&mut self) -> bool {
        let Some(file) = self.mountinfo.as_mut() else {
            return true;
        };
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: one valid pollfd, zero timeout.
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready <= 0 || poll.revents & (libc::POLLPRI | libc::POLLERR) == 0 {
            return false;
        }
        let _ = file.seek(SeekFrom::Start(0));
        let mut sink = Vec::new();
        let _ = file.read_to_end(&mut sink);
        true
    }
}

fn report(destination: &str, path: &str, outcome: &Result<Outcome>) -> String {
    match outcome {
        Ok(Outcome::Bound { hid: false }) => {
            format!("vm_only: {destination}/{path} is on the VM's disk")
        }
        Ok(Outcome::Bound { hid: true }) => format!(
            "vm_only: {destination}/{path} is newly kept on the VM's disk; what the host has there is now hidden from the VM"
        ),
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

/// Open the backing directory `name`, creating it for the workspace owner;
/// true when created now. At boot (`retire`), one owned by another user (the
/// workspace image's user changed; the workload cannot chown) is retired and
/// replaced by an empty one. The workload's own permission changes never
/// retire anything.
fn open_backing(
    vm_root: &OwnedFd,
    name: &str,
    uid: u32,
    gid: u32,
    retire: bool,
) -> Result<(OwnedFd, bool)> {
    for _ in 0..2 {
        let created = match rustix::fs::mkdirat(vm_root, name, RustixMode::from_raw_mode(0o700)) {
            Ok(()) => true,
            Err(RustixErrno::EXIST) => false,
            Err(error) => return Err(error).context("create a VM-disk directory"),
        };
        let backing = rustix::fs::openat2(
            vm_root,
            name,
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
            return Ok((backing, true));
        }
        let stat = rustix::fs::fstat(&backing).context("inspect a VM-disk directory")?;
        if !retire || stat.st_uid == uid {
            return Ok((backing, false));
        }
        drop(backing);
        retire_backing(vm_root, name)
            .context("retire a VM-disk directory of an earlier workspace owner")?;
    }
    anyhow::bail!("a VM-disk directory kept changing owner")
}

fn retire_backing(vm_root: &OwnedFd, name: &str) -> Result<()> {
    let retired_name = format!(
        "{name}.{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    );
    let retired_root = rustix::fs::openat2(
        vm_root,
        RETIRED_NAME,
        RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH | ResolveFlags::NO_XDEV,
    )
    .context("open the retired VM-disk directories")?;
    rustix::fs::renameat(vm_root, name, &retired_root, retired_name.as_str())
        .context("move a VM-disk directory to the retired ones")?;
    Ok(())
}

/// Retire backing directories this boot did not bind and no boot has bound
/// for [`ORPHAN_AGE`]: their folders are gone from the share (a package
/// removed, a branch switched). Run only after a complete search.
fn retire_orphans(vm_root: &OwnedFd, used: &BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(VM_ONLY_ROOT_PATH) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.len() != 64
            || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
            || used.contains(&name)
        {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .filter(|metadata| metadata.is_dir())
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= ORPHAN_AGE);
        if stale && let Err(error) = retire_backing(vm_root, &name) {
            eprintln!("vm_only: could not retire an unused VM-disk directory: {error:#}");
        }
    }
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

/// Bind `backing` over `path` beneath the share `root`, unless it already
/// is. `fresh` (a backing directory created now) reports host files the bind
/// hides. Share content only ever skips the path; a VM-disk failure, or a
/// bind that lacks nosuid and nodev, is an error.
fn bind(root: &OwnedFd, path: &str, backing: &OwnedFd, fresh: bool) -> Result<Outcome> {
    let mut components = path.split('/').collect::<Vec<_>>();
    // The expansion yields only checked names; refuse anything else here too.
    if components.iter().any(|component| {
        component.is_empty()
            || matches!(*component, "." | "..")
            || component.contains('\0')
            || component.eq_ignore_ascii_case(".git")
    }) {
        return Ok(Outcome::Skipped("it is not a plain relative path"));
    }
    let Some(last) = components.pop() else {
        return Ok(Outcome::Skipped("it is not a plain relative path"));
    };
    let mut parent = rustix::io::dup(root).context("reopen the direct-share root")?;
    for component in components {
        parent = match open_on_share(&parent, component) {
            Ok(next) => next,
            Err(error) => return Ok(Outcome::Skipped(skip_reason(error, false))),
        };
    }
    let backing_stat = rustix::fs::fstat(backing).context("inspect a VM-disk directory")?;
    match is_backing(&parent, last, &backing_stat) {
        Ok(true) => return Ok(Outcome::Bound { hid: false }),
        Ok(false) => {}
        Err(error) => return Ok(Outcome::Skipped(skip_reason(error, true))),
    }
    match rustix::fs::mkdirat(&parent, last, RustixMode::from_raw_mode(0o755)) {
        Ok(()) | Err(RustixErrno::EXIST) => {}
        Err(error) => return Ok(Outcome::Skipped(skip_reason(error, true))),
    }
    let target = match open_on_share(&parent, last) {
        Ok(target) => target,
        Err(error) => return Ok(Outcome::Skipped(skip_reason(error, true))),
    };
    if holds_repository(&target) {
        return Ok(Outcome::Skipped("it holds a Git repository"));
    }
    let hid = fresh && holds_entries(&parent, last);
    if super::mount_fs(
        &format!("/proc/self/fd/{}", backing.as_raw_fd()),
        &format!("/proc/self/fd/{}", target.as_raw_fd()),
        "none",
        libc::MS_BIND,
        "",
    )
    .is_err()
    {
        return Ok(Outcome::Skipped("the bind failed"));
    }
    // The bind inherits nosuid and nodev from the state disk's mount. A host
    // that moved the folder in between leaves it bound elsewhere on the same
    // share; the keeper binds the listed path again.
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
        .context("inspect a kept folder's mount")?
        .f_flag;
    ensure!(
        flags.contains(StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV)
            && !flags.contains(StatVfsMountFlags::RDONLY),
        "a kept folder's mount lacks nosuid or nodev"
    );
    let stat = rustix::fs::fstat(&bound).context("inspect a kept folder's mount")?;
    if (stat.st_dev, stat.st_ino) != (backing_stat.st_dev, backing_stat.st_ino) {
        return Ok(Outcome::Skipped(
            "the host changed the folder during the bind",
        ));
    }
    Ok(Outcome::Bound { hid })
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

/// Whether the share folder `name` beneath `parent` holds anything.
fn holds_entries(parent: &OwnedFd, name: &str) -> bool {
    let Ok(folder) = rustix::fs::openat2(
        parent,
        name,
        RustixOFlags::RDONLY
            | RustixOFlags::DIRECTORY
            | RustixOFlags::NOFOLLOW
            | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH | ResolveFlags::NO_XDEV,
    ) else {
        return false;
    };
    let Ok(mut entries) = rustix::fs::Dir::read_from(&folder) else {
        return false;
    };
    entries
        .any(|entry| entry.is_ok_and(|entry| !matches!(entry.file_name().to_bytes(), b"." | b"..")))
}

/// Whether `name` beneath `parent` already shows the backing directory.
fn is_backing(
    parent: &OwnedFd,
    name: &str,
    backing: &rustix::fs::Stat,
) -> rustix::io::Result<bool> {
    let opened = match rustix::fs::openat2(
        parent,
        name,
        RustixOFlags::PATH | RustixOFlags::NOFOLLOW | RustixOFlags::CLOEXEC,
        RustixMode::empty(),
        BENEATH,
    ) {
        Ok(opened) => opened,
        Err(RustixErrno::NOENT | RustixErrno::LOOP | RustixErrno::NOTDIR) => return Ok(false),
        Err(error) => return Err(error),
    };
    let stat = rustix::fs::fstat(opened.as_fd())?;
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
        RustixErrno::ACCESS | RustixErrno::PERM | RustixErrno::ROFS => "the share refused access",
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
    fn share_tree_expands_patterns_without_following_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for folder in [
            "a/node_modules/inner/node_modules",
            "b/c/node_modules",
            "outside/node_modules",
            ".git/node_modules",
            "file-parent",
            "vendored/node_modules/.git",
        ] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }
        // A symlinked folder and a symlinked match are never entered or kept.
        std::os::unix::fs::symlink(root.join("outside"), root.join("linked")).unwrap();
        std::os::unix::fs::symlink(
            root.join("outside/node_modules"),
            root.join("b/node_modules"),
        )
        .unwrap();
        fs::write(root.join("file-parent/node_modules"), b"a file").unwrap();
        let folder = rustix::fs::open(
            root,
            RustixOFlags::RDONLY | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
            RustixMode::empty(),
        )
        .unwrap();
        let patterns =
            VmOnlyPatterns::parse(&["**/node_modules".to_owned(), "target".to_owned()]).unwrap();
        let expansion = expand_vm_only(
            &patterns,
            &mut ShareTree {
                deadline: Instant::now() + Duration::from_secs(60),
            },
            &folder,
        );
        let found = expansion
            .matches
            .iter()
            .map(|found| (found.path.as_str(), found.exists))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            [
                ("a/node_modules", true),
                ("b/c/node_modules", true),
                ("outside/node_modules", true),
                ("target", false),
            ]
        );
        // A match holding its own repository stays shared.
        assert_eq!(expansion.repositories, ["vendored/node_modules".to_owned()]);
        assert!(!expansion.truncated);
        // An expired deadline stops the search and says so.
        let expansion = expand_vm_only(
            &patterns,
            &mut ShareTree {
                deadline: Instant::now(),
            },
            &folder,
        );
        assert!(expansion.truncated);
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
        assert_eq!(
            skip_reason(RustixErrno::ACCESS, false),
            "the share refused access"
        );
    }

    #[test]
    fn bind_refuses_unchecked_paths_before_touching_the_share() {
        let temp = tempfile::tempdir().unwrap();
        let open = |path: &Path| {
            rustix::fs::open(
                path,
                RustixOFlags::PATH | RustixOFlags::DIRECTORY | RustixOFlags::CLOEXEC,
                RustixMode::empty(),
            )
            .unwrap()
        };
        let root = open(temp.path());
        let backing = open(temp.path());
        for path in ["", ".", "..", "a/../b", "a//b", ".git", "x/.GIT", "a\0b"] {
            assert_eq!(
                bind(&root, path, &backing, false).unwrap(),
                Outcome::Skipped("it is not a plain relative path"),
                "{path:?}"
            );
        }
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }
}
