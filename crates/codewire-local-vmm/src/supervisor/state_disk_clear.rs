//! Clearing a local VM's own state disk before a boot that intercepts (#6277;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Clearing a local VM's state disk").
//!
//! A boot that doesn't intercept may get the real sign-in, and each rewrite of
//! it leaves the earlier copy in a freed block, where a root process in a later
//! guest can read it from the raw disk. So the VM's marker is removed before
//! such a boot runs, and a boot that intercepts with no marker first clears the
//! stopped disk on the host, by the local snapshot's own steps. A restore or a
//! fork of a VM checkpoint can't be cleared first, so its checkpoint's record
//! decides instead.

use super::snapshots::scrub::{self, ScrubStep, ScrubTarget};
use super::*;

/// The marker in a VM's directory: its state disk holds no delivered sign-in,
/// in a file or in a free block.
const MARKER: &str = "state-disk-cleared";

/// The step a clearing of a VM's own state disk failed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearStep {
    /// Another process holds the VM, or its VMM could not be proven dead.
    InUse,
    /// The e2fsprogs the clearing runs are missing.
    Tools,
    /// A step of the scrub itself.
    Scrub(ScrubStep),
    /// The marker could not be written or removed.
    Marker,
}

impl ClearStep {
    pub(in crate::supervisor) fn name(self) -> &'static str {
        match self {
            Self::InUse => "in_use",
            Self::Tools => "tools",
            Self::Scrub(step) => step.name(),
            Self::Marker => "marker",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::InUse => "the VM is in use by another process",
            Self::Tools => "the e2fsprogs it runs are missing",
            Self::Scrub(ScrubStep::Check) => "e2fsck could not settle the disk without asking",
            Self::Scrub(ScrubStep::Logins) => "a sign-in could not be removed",
            Self::Scrub(ScrubStep::Recheck) => "e2fsck failed after the sign-ins were removed",
            Self::Scrub(ScrubStep::Punch) => "its free blocks could not be cleared",
            Self::Marker => "it could not be recorded as cleared",
        }
    }
}

/// Why a boot that intercepts is refused: its VM's disk may hold an earlier
/// sign-in. A VM on a platform profile has no override, since its credentials
/// are not the user's to accept that risk for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclearedDisk {
    /// Clearing the stopped VM's state disk failed.
    ClearFailed { step: ClearStep, platform: bool },
    /// The VM checkpoint being restored or forked doesn't record a cleared
    /// state disk.
    Checkpoint { platform: bool },
}

impl std::fmt::Display for UnclearedDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ClearFailed { step, platform } => {
                write!(
                    f,
                    "this VM's state disk may still hold a sign-in from a boot without agent interception, and clearing it failed: {}; ",
                    step.describe()
                )?;
                if platform {
                    f.write_str("start it again, or recreate it: a VM on a platform profile can't start with an uncleared disk")
                } else {
                    f.write_str("start it again; or sign the provider out, then start it once with --start-with-uncleared-disk; or recreate it")
                }
            }
            Self::Checkpoint { platform } => {
                f.write_str("this VM checkpoint may hold an earlier sign-in on its disk, which a restore can't clear; ")?;
                if platform {
                    f.write_str("remove it with `cw checkpoint rm`: a VM on a platform profile can't restore it")
                } else {
                    f.write_str("sign the provider out, then restore it once with --start-with-uncleared-disk, or remove it with `cw checkpoint rm`")
                }
            }
        }
    }
}

impl std::error::Error for UnclearedDisk {}

impl UnclearedDisk {
    /// The lifecycle failure cause, one per fix.
    pub(in crate::supervisor) fn code(self) -> &'static str {
        match self {
            Self::ClearFailed { .. } => "state_disk_not_cleared",
            Self::Checkpoint { .. } => "checkpoint_disk_uncleared",
        }
    }

    /// The code of a create that failed with this refusal.
    pub(in crate::supervisor) fn create_code(self) -> &'static str {
        match self {
            Self::ClearFailed { .. } => "create_state_disk_not_cleared",
            Self::Checkpoint { .. } => "create_checkpoint_disk_uncleared",
        }
    }
}

/// What one boot does with its VM's marker before the runner starts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plan {
    /// The boot doesn't intercept, so it may get real sign-ins: remove the
    /// marker first.
    Uncleared,
    /// The disk is recorded as cleared: nothing to do.
    Cleared,
    /// Clear the disk, then write the marker.
    Clear,
    /// A new disk, or a restore or fork whose checkpoint recorded a cleared
    /// disk: write the marker.
    Mark,
    /// A restore or fork whose checkpoint may hold an earlier sign-in.
    Refuse,
}

/// What a VM checkpoint being restored or forked recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::supervisor) struct CheckpointDisk {
    /// Its boot intercepted.
    pub(in crate::supervisor) intercepted: bool,
    /// Its VM's state disk was recorded as cleared when it was taken.
    pub(in crate::supervisor) cleared: bool,
}

impl CheckpointDisk {
    /// It may hold an earlier real sign-in: taken without interception, or
    /// from a disk not recorded as cleared.
    pub(in crate::supervisor) fn may_hold_sign_in(self) -> bool {
        !self.intercepted || !self.cleared
    }
}

/// What a boot's disk starts from, with its checkpoint's record read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Existing,
    New,
    Checkpoint(CheckpointDisk),
}

/// The plan for a boot. A checkpoint taken without interception and restored
/// with it on is refused by the runner (`RestoreSwitchedOn`), so here it only
/// loses the marker.
fn plan(intercept: bool, marker: bool, origin: Origin) -> Plan {
    match (intercept, origin) {
        (false, _) => Plan::Uncleared,
        (true, Origin::Checkpoint(checkpoint)) if !checkpoint.intercepted => Plan::Uncleared,
        (true, Origin::Checkpoint(checkpoint)) if checkpoint.cleared => Plan::Mark,
        (true, Origin::Checkpoint(_)) => Plan::Refuse,
        (true, Origin::New) => Plan::Mark,
        (true, Origin::Existing) if marker => Plan::Cleared,
        (true, Origin::Existing) => Plan::Clear,
    }
}

/// What the boot being settled is.
#[derive(Clone, Copy, Debug)]
struct BootDisk {
    environment_id: Uuid,
    intercept: bool,
    /// The VM's credentials come from the platform.
    platform: bool,
    /// This one start, restore or fork passed `--start-with-uncleared-disk`.
    override_uncleared: bool,
    origin: Origin,
}

impl Supervisor {
    /// Settle the state disk of `environment_id` for the boot that
    /// `operation_id` applies, before its runner starts it (#6277).
    pub(in crate::supervisor) async fn settle_state_disk_for_boot(
        &self,
        operation_id: Uuid,
        environment_id: Uuid,
        egress: &super::boot_egress::BootEgress,
    ) -> Result<(), SupervisorError> {
        let (origin, override_uncleared) = checkpoints::boot_source(self, operation_id)?;
        let origin = match origin {
            checkpoints::BootOrigin::Existing => Origin::Existing,
            checkpoints::BootOrigin::New => Origin::New,
            checkpoints::BootOrigin::Checkpoint(id) => {
                Origin::Checkpoint(checkpoints::checkpoint_disk(self, id)?)
            }
        };
        self.settle_state_disk(BootDisk {
            environment_id,
            intercept: egress.intercept,
            platform: egress.platform.is_some(),
            override_uncleared,
            origin,
        })
        .await
    }

    /// Settle the VM's state disk for this boot before the runner starts it:
    /// remove the marker before a boot that doesn't intercept, clear the disk
    /// before one that does when the marker is missing, and take a restore's
    /// or fork's marker from its checkpoint's record alone.
    async fn settle_state_disk(&self, boot: BootDisk) -> Result<(), SupervisorError> {
        let paths = VmPaths::create(
            &PrivateRoot::open(&self.config.engine_root())?,
            boot.environment_id,
        )?;
        let marker = marker_present(&paths);
        match plan(boot.intercept, marker, boot.origin) {
            Plan::Uncleared => remove_marker(&paths).map_err(|()| self.marker_failed(boot)),
            Plan::Cleared => Ok(()),
            Plan::Mark => write_marker(&paths).map_err(|()| self.marker_failed(boot)),
            Plan::Refuse => self.overridden(
                boot,
                UnclearedDisk::Checkpoint {
                    platform: boot.platform,
                },
                &paths,
            ),
            Plan::Clear => match self.clear(&paths, boot.environment_id).await {
                Ok(removed) => {
                    write_marker(&paths).map_err(|()| self.marker_failed(boot))?;
                    diagnostic_log::record(
                        self.log.as_deref(),
                        "state_disk_clear",
                        &[
                            ("outcome", LogField::Name("cleared")),
                            ("removed_logins", LogField::Count(u64::from(removed))),
                        ],
                    );
                    Ok(())
                }
                Err(step) => {
                    diagnostic_log::record(
                        self.log.as_deref(),
                        "state_disk_clear",
                        &[
                            ("outcome", LogField::Name("failed")),
                            ("step", LogField::Name(step.name())),
                        ],
                    );
                    self.overridden(
                        boot,
                        UnclearedDisk::ClearFailed {
                            step,
                            platform: boot.platform,
                        },
                        &paths,
                    )
                }
            },
        }
    }

    /// The refusal, unless this one start passed the override on a VM that
    /// isn't on a platform profile: then it is logged, the marker stays
    /// missing, and the boot goes on.
    fn overridden(
        &self,
        boot: BootDisk,
        refusal: UnclearedDisk,
        paths: &VmPaths,
    ) -> Result<(), SupervisorError> {
        if !boot.override_uncleared || boot.platform {
            return Err(SupervisorError::UnclearedDisk(refusal));
        }
        remove_marker(paths).map_err(|()| self.marker_failed(boot))?;
        diagnostic_log::record(
            self.log.as_deref(),
            "state_disk_clear",
            &[
                ("outcome", LogField::Name("overridden")),
                ("refusal", LogField::Name(refusal.code())),
            ],
        );
        Ok(())
    }

    /// The marker could not be written or removed. A boot that may get real
    /// sign-ins is refused too, since its disk would stay recorded as cleared.
    fn marker_failed(&self, boot: BootDisk) -> SupervisorError {
        SupervisorError::UnclearedDisk(UnclearedDisk::ClearFailed {
            step: ClearStep::Marker,
            platform: boot.platform,
        })
    }

    /// Clear the stopped VM's `state.raw` in place, holding its `vm.lock`,
    /// which every process that opens the disk holds, with its VMM proven
    /// dead.
    async fn clear(&self, paths: &VmPaths, environment_id: Uuid) -> Result<u32, ClearStep> {
        let _lock = paths.lock().map_err(|_| ClearStep::InUse)?;
        snapshots::require_vmm_dead(paths, environment_id).map_err(|_| ClearStep::InUse)?;
        scrub::require_scrub_tools(&self.config).map_err(|_| ClearStep::Tools)?;
        scrub::scrub(&paths.state_disk, ScrubTarget::OwnDisk)
            .await
            .map_err(|(step, _)| ClearStep::Scrub(step))
    }
}

/// Whether the state disk of `environment_id` is recorded as cleared, for a
/// VM checkpoint taken of it now.
pub(in crate::supervisor) fn state_disk_cleared(
    config: &NativeRuntimeConfig,
    environment_id: Uuid,
) -> bool {
    PrivateRoot::open(&config.engine_root())
        .ok()
        .and_then(|engine| VmPaths::create(&engine, environment_id).ok())
        .is_some_and(|paths| marker_present(&paths))
}

fn marker_present(paths: &VmPaths) -> bool {
    match fs::symlink_metadata(paths.vm_dir.join(MARKER)) {
        Ok(_) => paths
            .open_vm_root()
            .ok()
            .and_then(|root| {
                root.open_regular(Path::new(MARKER), false, Some(0), false, Some(0o600))
                    .ok()
            })
            .is_some(),
        Err(_) => false,
    }
}

/// Write the marker, then fsync it and the VM's directory, so a crash after
/// leaves it there and a crash before leaves none.
fn write_marker(paths: &VmPaths) -> Result<(), ()> {
    let root = paths.open_vm_root().map_err(|_| ())?;
    let opened = root
        .create_regular(Path::new(MARKER), 0o600, false)
        .map_err(|_| ())?;
    opened
        .file()
        .set_len(0)
        .and_then(|()| opened.file().sync_all())
        .map_err(|_| ())?;
    File::open(root.path())
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ())
}

/// Remove the marker, and fsync the VM's directory.
fn remove_marker(paths: &VmPaths) -> Result<(), ()> {
    let root = paths.open_vm_root().map_err(|_| ())?;
    root.remove_private_regular(Path::new(MARKER), 0o600)
        .map(|_| ())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests;
