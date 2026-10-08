//! Live progress for `cw env create --local` and `cw env start` on a local
//! environment.
//!
//! The local supervisor publishes every lifecycle stage, and inside VM start
//! every runner and guest-boot stage, on its operation stream. This maps them
//! onto the same stage lines as platform creates: one updating status line on
//! a terminal, one plain line per stage elsewhere. Bookkeeping stages (journal
//! writes) stay quiet; only work a person waits on is shown.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use codewire_local_vmm::control::v1;

use super::environment::progress::{StartProgress, live_progress_enabled};

/// The CLI-side stage before the supervisor has an operation: it inspects the
/// workspace source and fetches repositories inside the create request.
const SOURCES: (&str, &str) = ("cli:sources", "Preparing sources");

#[derive(Clone)]
pub(crate) struct NativeProgress {
    view: Arc<Mutex<StartProgress<std::io::Stderr>>>,
    current: Arc<Mutex<Option<(&'static str, &'static str)>>>,
}

impl NativeProgress {
    pub(crate) fn new(began: Instant) -> Self {
        Self {
            view: Arc::new(Mutex::new(StartProgress::new(
                std::io::stderr(),
                live_progress_enabled(),
                began,
                "Working",
            ))),
            current: Arc::new(Mutex::new(None)),
        }
    }

    /// Opens the CLI's own pre-operation stage.
    pub(crate) fn begin_sources(&self) {
        self.enter(SOURCES.0, SOURCES.1, None);
    }

    /// Feeds one operation update from the supervisor.
    pub(crate) fn observe(&self, operation: &v1::Operation) {
        match stage_of(operation) {
            Some((key, label)) => self.enter(key, label, guest_detail(operation)),
            None => {
                // The sources stage ends with the supervisor's first update.
                if self.current_key() == Some(SOURCES.0) {
                    self.close_current();
                }
            }
        }
    }

    /// Closes the last open stage once the operation has succeeded.
    pub(crate) fn complete(&self) {
        self.close_current();
        let _ = self.view.lock().map(|mut view| view.finish());
    }

    /// Removes the live line without claiming the open stage completed.
    pub(crate) fn abandon(&self) {
        let _ = self.view.lock().map(|mut view| view.finish());
    }

    /// Redraws the live line once a second until `work` finishes, so elapsed
    /// time keeps counting between supervisor updates.
    pub(crate) async fn tick_while<T>(&self, work: impl Future<Output = T>) -> T {
        tokio::pin!(work);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                result = &mut work => return result,
                _ = tick.tick() => {
                    let _ = self.view.lock().map(|mut view| view.redraw(Instant::now()));
                }
            }
        }
    }

    fn current_key(&self) -> Option<&'static str> {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.map(|(key, _)| key))
    }

    fn enter(&self, key: &'static str, label: &'static str, detail: Option<&'static str>) {
        let (Ok(mut current), Ok(mut view)) = (self.current.lock(), self.view.lock()) else {
            return;
        };
        let now = Instant::now();
        if current.map(|(open, _)| open) != Some(key) {
            if let Some((open, open_label)) = current.take() {
                let _ = view.complete_local_stage(open, open_label, now);
            }
            let _ = view.begin_local_stage(key, label, now);
            *current = Some((key, label));
        }
        let _ = view.set_local_detail(key, detail, now);
    }

    fn close_current(&self) {
        let (Ok(mut current), Ok(mut view)) = (self.current.lock(), self.view.lock()) else {
            return;
        };
        if let Some((open, label)) = current.take() {
            let _ = view.complete_local_stage(open, label, Instant::now());
        }
    }
}

/// The stage a person is waiting on, or `None` for bookkeeping.
fn stage_of(operation: &v1::Operation) -> Option<(&'static str, &'static str)> {
    use v1::OperationStage as Stage;
    use v1::RunnerStage as Runner;
    Some(match Stage::try_from(operation.stage).ok()? {
        // Recording a new environment admits the runtime artifacts and the
        // in-guest cw runtime first, which takes seconds on a first create.
        Stage::RecordEnvironment => ("runtime", "Checking the VM runtime"),
        Stage::BindEnvironmentAccess
        | Stage::RequireEnvironmentAccess
        | Stage::ApplySourceAccessBinding => ("access", "Checking credential access"),
        Stage::ProvisionWorkspace => ("disk", "Preparing the workspace disk"),
        Stage::StageWorkspaceGeneration => ("image", "Pulling the image"),
        Stage::EnsureRunner => ("runner", "Starting the VM runner"),
        Stage::StartVm | Stage::RestartVm => match Runner::try_from(operation.runner_stage) {
            Ok(Runner::WaitingGuest | Runner::GuestInit | Runner::DaemonReady) => {
                ("boot", "Booting the workspace")
            }
            Ok(Runner::PreparingVm) => ("vm-disks", "Preparing the VM disks"),
            _ => ("vm", "Starting the VM"),
        },
        Stage::GrowDisk => ("grow", "Growing the disk"),
        Stage::StopVm => ("stop", "Stopping the VM"),
        _ => return None,
    })
}

/// What the guest is doing while it boots, for the live line.
fn guest_detail(operation: &v1::Operation) -> Option<&'static str> {
    use v1::GuestBootStage as Guest;
    if v1::RunnerStage::try_from(operation.runner_stage) == Ok(v1::RunnerStage::DaemonReady) {
        return Some("daemon ready");
    }
    Some(match Guest::try_from(operation.guest_stage).ok()? {
        Guest::StateMounted | Guest::CgroupsReady | Guest::DisksAdmitted => "mounting disks",
        Guest::RootMounted | Guest::RootLayersReady | Guest::RootGenerationReady => {
            "unpacking the image"
        }
        Guest::SetupHeaderReady | Guest::SetupContentReady => "running setup",
        Guest::WorkspacePlanReady | Guest::OwnershipReady | Guest::PersistentLayoutReady => {
            "preparing the workspace"
        }
        Guest::ContainerControlReady | Guest::RuncLaunching | Guest::RuncRunning => {
            "starting the workspace"
        }
        Guest::WorkspaceRunning | Guest::DaemonStarted => "starting the daemon",
        Guest::Unspecified | Guest::SetupFailed | Guest::WorkspaceFailed => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(stage: v1::OperationStage, runner: v1::RunnerStage) -> v1::Operation {
        v1::Operation {
            stage: stage as i32,
            runner_stage: runner as i32,
            ..Default::default()
        }
    }

    #[test]
    fn create_stages_map_to_what_a_person_waits_on() {
        use v1::OperationStage as Stage;
        use v1::RunnerStage as Runner;
        for (stage, runner, expected) in [
            (
                Stage::RecordEnvironment,
                Runner::Unspecified,
                Some("runtime"),
            ),
            (Stage::ProvisionWorkspace, Runner::Unspecified, Some("disk")),
            (
                Stage::StageWorkspaceGeneration,
                Runner::Unspecified,
                Some("image"),
            ),
            (Stage::RecordStarting, Runner::Unspecified, None),
            (Stage::EnsureRunner, Runner::Unspecified, Some("runner")),
            (Stage::StartVm, Runner::PreparingVm, Some("vm-disks")),
            (Stage::StartVm, Runner::StartingVmm, Some("vm")),
            (Stage::StartVm, Runner::GuestInit, Some("boot")),
            (Stage::StartVm, Runner::DaemonReady, Some("boot")),
            (Stage::RecordRunning, Runner::DaemonReady, None),
        ] {
            assert_eq!(
                stage_of(&operation(stage, runner)).map(|(key, _)| key),
                expected,
                "{stage:?} {runner:?}"
            );
        }
    }

    #[test]
    fn guest_boot_detail_names_the_current_step() {
        let mut boot = operation(v1::OperationStage::StartVm, v1::RunnerStage::GuestInit);
        boot.guest_stage = v1::GuestBootStage::RootLayersReady as i32;
        assert_eq!(guest_detail(&boot), Some("unpacking the image"));
        boot.guest_stage = v1::GuestBootStage::SetupContentReady as i32;
        assert_eq!(guest_detail(&boot), Some("running setup"));
        boot.runner_stage = v1::RunnerStage::DaemonReady as i32;
        assert_eq!(guest_detail(&boot), Some("daemon ready"));
    }
}
