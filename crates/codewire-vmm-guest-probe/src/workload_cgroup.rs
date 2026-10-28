//! The one freezable cgroup that holds the whole guest workload.
//!
//! Everything the workspace runs sits under `workload` in the guest's private
//! cgroup v1 hierarchy: the runc workspace container (and so every session the
//! daemon starts in it), dockerd with its containerd and shims, and every
//! Docker container. Codewire's own guest services (PID 1, the daemon, the
//! network agent and the progress server) stay outside it, so freezing
//! `workload` stops every workload task while those services keep running.
//! A VM checkpoint freezes it before the VM pauses and thaws it after the
//! resume hook has re-keyed the guest.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

/// The workload cgroup, relative to the private hierarchy's root.
pub(crate) const WORKLOAD_CGROUP: &str = "workload";
/// runc's `linux.cgroupsPath` for the workspace container.
pub(crate) const WORKSPACE_CGROUPS_PATH: &str = "/workload/workspace";
/// The cgroup dockerd (and the containerd and shims it starts) runs in.
pub(crate) const DOCKERD_CGROUP: &str = "workload/dockerd";
/// dockerd's `--cgroup-parent` for every Docker container.
pub(crate) const DOCKER_CGROUP_PARENT: &str = "/workload/docker";
/// How long a freeze may take before it is abandoned and thawed. A task in
/// uninterruptible I/O can hold a cgroup in `FREEZING`.
#[allow(dead_code)] // The checkpoint hook is its first caller.
pub(crate) const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a thaw may take to read back `THAWED`.
pub(crate) const THAW_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STATE_FILE: &str = "freezer.state";
const PROCS_FILE: &str = "cgroup.procs";

/// The cgroup v1 freezer's three states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FreezerState {
    Thawed,
    Freezing,
    Frozen,
}

impl FreezerState {
    fn parse(value: &str) -> Result<Self> {
        match value.trim_end_matches('\n') {
            "THAWED" => Ok(Self::Thawed),
            "FREEZING" => Ok(Self::Freezing),
            "FROZEN" => Ok(Self::Frozen),
            other => bail!("workload freezer reported an unknown state {other:?}"),
        }
    }
}

/// The workload cgroup inside one mounted cgroup v1 hierarchy.
#[derive(Clone, Debug)]
pub(crate) struct WorkloadCgroup {
    directory: PathBuf,
}

impl WorkloadCgroup {
    /// Creates `workload` and its `dockerd` child under `hierarchy` and checks
    /// that the freezer controls them.
    pub(crate) fn create(hierarchy: &Path) -> Result<Self> {
        let workload = Self {
            directory: hierarchy.join(WORKLOAD_CGROUP),
        };
        for directory in [workload.directory.clone(), hierarchy.join(DOCKERD_CGROUP)] {
            match fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create cgroup {}", directory.display()));
                }
            }
            let metadata = fs::symlink_metadata(&directory)
                .with_context(|| format!("inspect cgroup {}", directory.display()))?;
            ensure!(
                metadata.file_type().is_dir(),
                "workload cgroup path is not a directory"
            );
        }
        for required in [STATE_FILE, PROCS_FILE] {
            let path = workload.directory.join(required);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect workload cgroup file {}", path.display()))?;
            ensure!(
                metadata.file_type().is_file(),
                "workload cgroup control path is not a regular file"
            );
        }
        ensure!(
            workload.state()? == FreezerState::Thawed,
            "a new workload cgroup must start thawed"
        );
        Ok(workload)
    }

    /// The workload cgroup under `hierarchy`, without creating anything.
    #[allow(dead_code)] // The checkpoint hook is its first caller.
    pub(crate) fn at(hierarchy: &Path) -> Self {
        Self {
            directory: hierarchy.join(WORKLOAD_CGROUP),
        }
    }

    /// The `cgroup.procs` file a process writes `0` to so it joins dockerd's
    /// cgroup.
    pub(crate) fn dockerd_procs(hierarchy: &Path) -> PathBuf {
        hierarchy.join(DOCKERD_CGROUP).join(PROCS_FILE)
    }

    pub(crate) fn state(&self) -> Result<FreezerState> {
        let path = self.directory.join(STATE_FILE);
        let value = fs::read_to_string(&path)
            .with_context(|| format!("read workload freezer state {}", path.display()))?;
        FreezerState::parse(&value)
    }

    /// Freezes every workload task, waiting up to `timeout` for the kernel to
    /// report `FROZEN`. On a timeout or any error the workload is thawed
    /// again before the error returns, so a failed freeze never leaves it
    /// stopped.
    #[allow(dead_code)] // The checkpoint hook is its first caller.
    pub(crate) fn freeze(&self, timeout: Duration) -> Result<Duration> {
        let started = Instant::now();
        let result = self
            .write_state("FROZEN")
            .and_then(|()| settle(|| self.state(), FreezerState::Frozen, timeout));
        match result {
            Ok(()) => Ok(started.elapsed()),
            Err(error) => {
                if let Err(thaw) = self.thaw(THAW_TIMEOUT) {
                    return Err(error.context(format!("and the workload did not thaw: {thaw:#}")));
                }
                Err(error)
            }
        }
    }

    /// Thaws every workload task and waits up to `timeout` for `THAWED`.
    pub(crate) fn thaw(&self, timeout: Duration) -> Result<()> {
        self.write_state("THAWED")?;
        settle(|| self.state(), FreezerState::Thawed, timeout)
    }

    fn write_state(&self, value: &str) -> Result<()> {
        let path = self.directory.join(STATE_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("open workload freezer state {}", path.display()))?;
        file.write_all(value.as_bytes())
            .with_context(|| format!("set workload freezer state to {value}"))
    }
}

/// Polls `read` until it reports `want`, with a short backoff, for at most
/// `timeout`.
fn settle(
    mut read: impl FnMut() -> Result<FreezerState>,
    want: FreezerState,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut interval = POLL_INTERVAL;
    loop {
        let state = read()?;
        if state == want {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            bail!(
                "the workload freezer stayed {state:?} instead of {want:?} for {} ms",
                timeout.as_millis()
            );
        }
        thread::sleep(interval.min(deadline - now));
        interval = (interval * 2).min(MAX_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn hierarchy() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        // A real hierarchy gives every new cgroup its control files; a plain
        // directory needs them written first.
        for cgroup in [WORKLOAD_CGROUP, DOCKERD_CGROUP] {
            fs::create_dir_all(directory.path().join(cgroup)).unwrap();
            fs::write(directory.path().join(cgroup).join(STATE_FILE), "THAWED\n").unwrap();
            fs::write(directory.path().join(cgroup).join(PROCS_FILE), "").unwrap();
        }
        directory
    }

    #[test]
    fn paths_put_every_workload_part_under_one_parent() {
        for path in [WORKSPACE_CGROUPS_PATH, DOCKER_CGROUP_PARENT] {
            assert!(path.starts_with(&format!("/{WORKLOAD_CGROUP}/")), "{path}");
        }
        assert!(DOCKERD_CGROUP.starts_with(&format!("{WORKLOAD_CGROUP}/")));
        assert_eq!(
            WorkloadCgroup::dockerd_procs(Path::new("/sys/fs/cgroup/codewire")),
            Path::new("/sys/fs/cgroup/codewire/workload/dockerd/cgroup.procs")
        );
    }

    #[test]
    fn create_requires_the_freezer_and_a_thawed_start() {
        let directory = hierarchy();
        let workload = WorkloadCgroup::create(directory.path()).unwrap();
        assert_eq!(workload.state().unwrap(), FreezerState::Thawed);

        fs::write(
            directory.path().join(WORKLOAD_CGROUP).join(STATE_FILE),
            "FROZEN\n",
        )
        .unwrap();
        assert!(WorkloadCgroup::create(directory.path()).is_err());

        let bare = tempfile::tempdir().unwrap();
        let error = WorkloadCgroup::create(bare.path()).unwrap_err();
        assert!(format!("{error:#}").contains("freezer.state"), "{error:#}");
    }

    #[test]
    fn freeze_and_thaw_write_the_freezer_state() {
        let directory = hierarchy();
        let workload = WorkloadCgroup::create(directory.path()).unwrap();
        workload.freeze(FREEZE_TIMEOUT).unwrap();
        assert_eq!(workload.state().unwrap(), FreezerState::Frozen);
        workload.thaw(THAW_TIMEOUT).unwrap();
        assert_eq!(workload.state().unwrap(), FreezerState::Thawed);
    }

    #[test]
    fn settle_waits_through_freezing_and_gives_up_at_the_deadline() {
        let reads = Cell::new(0);
        settle(
            || {
                reads.set(reads.get() + 1);
                Ok(if reads.get() < 4 {
                    FreezerState::Freezing
                } else {
                    FreezerState::Frozen
                })
            },
            FreezerState::Frozen,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reads.get(), 4);

        let started = Instant::now();
        let error = settle(
            || Ok(FreezerState::Freezing),
            FreezerState::Frozen,
            Duration::from_millis(30),
        )
        .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(format!("{error}").contains("Freezing"), "{error}");
    }

    #[test]
    fn unknown_states_are_errors() {
        assert_eq!(
            FreezerState::parse("FROZEN\n").unwrap(),
            FreezerState::Frozen
        );
        assert!(FreezerState::parse("frozen").is_err());
        assert!(FreezerState::parse("").is_err());
    }
}
