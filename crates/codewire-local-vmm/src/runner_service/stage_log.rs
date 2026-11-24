//! The start's timing lines in the runner log (#4242): `vm_started` splits
//! the network wait into the guest's boot and the host's network stack, and
//! `guest_stages` says when each guest boot stage reached the host.

use std::time::{Duration, Instant};

use codewire_vmm_guest_probe::GuestBootStage;
use uuid::Uuid;

use crate::RunningVm;
use crate::diagnostic_log::{self, DiagnosticLog, LogField};
use crate::runner::{GuestStageTimes, NETWORK_WORKER_RETRY_DELAY};

/// A start's phase times, in milliseconds.
pub(super) struct StartTimes {
    pub(super) launch_ms: u64,
    pub(super) guest_boot_ms: Option<u64>,
    pub(super) network_ms: u64,
    pub(super) guest_ms: u64,
}

/// The network wait so far, split at the guest's ready report.
pub(super) fn network_wait(network_started: Instant, running: &RunningVm) -> (Option<u64>, u64) {
    split_network_wait(
        network_started,
        running.stage_times().guest_ready(),
        Instant::now(),
    )
}

/// Records the `vm_started` and `guest_stages` lines.
pub(super) fn vm_started(
    log: Option<&DiagnosticLog>,
    (environment_id, generation): (Uuid, u64),
    started: Instant,
    times: StartTimes,
    running: Option<&RunningVm>,
) {
    let mut fields = vec![
        ("environment", LogField::Id(environment_id)),
        ("generation", LogField::Count(generation)),
        (
            "elapsed_ms",
            LogField::Count(duration_ms(started.elapsed())),
        ),
        ("launch_ms", LogField::Count(times.launch_ms)),
    ];
    if let Some(guest_boot_ms) = times.guest_boot_ms {
        fields.push(("guest_boot_ms", LogField::Count(guest_boot_ms)));
    }
    fields.push(("network_ms", LogField::Count(times.network_ms)));
    fields.push(("guest_ms", LogField::Count(times.guest_ms)));
    diagnostic_log::record(log, "vm_started", &fields);
    if let Some(running) = running {
        let stages = guest_stage_fields(environment_id, generation, started, running.stage_times());
        diagnostic_log::record(log, "guest_stages", &stages);
    }
}

/// The network wait as two phases (#4242): the guest's boot up to its root
/// generation, then the host's network stack. Without a ready time, the
/// whole wait is the network's, as before.
fn split_network_wait(
    network_started: Instant,
    guest_ready: Option<Instant>,
    network_done: Instant,
) -> (Option<u64>, u64) {
    let guest_boot_ms =
        guest_ready.map(|ready| duration_ms(ready.saturating_duration_since(network_started)));
    let network_ms =
        duration_ms(network_done.saturating_duration_since(guest_ready.unwrap_or(network_started)));
    (guest_boot_ms, network_ms)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The `guest_stages` line (#4242): when the host first received each guest
/// boot stage, in milliseconds since the start began, and the progress
/// port's retry interval, which bounds how late a stage can read.
fn guest_stage_fields(
    environment_id: Uuid,
    generation: u64,
    started: Instant,
    times: &GuestStageTimes,
) -> Vec<(&'static str, LogField<'static>)> {
    let mut fields = vec![
        ("environment", LogField::Id(environment_id)),
        ("generation", LogField::Count(generation)),
        (
            "retry_ms",
            LogField::Count(duration_ms(NETWORK_WORKER_RETRY_DELAY)),
        ),
    ];
    for (stage, at) in times.seen() {
        fields.push((
            guest_stage_ms_field(*stage),
            LogField::Count(duration_ms(at.saturating_duration_since(started))),
        ));
    }
    fields
}

/// A guest boot stage's field in the `guest_stages` line.
fn guest_stage_ms_field(stage: GuestBootStage) -> &'static str {
    match stage {
        GuestBootStage::StateMounted => "state_mounted_ms",
        GuestBootStage::CgroupsReady => "cgroups_ready_ms",
        GuestBootStage::DisksAdmitted => "disks_admitted_ms",
        GuestBootStage::RootMounted => "root_mounted_ms",
        GuestBootStage::SetupHeaderReady => "setup_header_ready_ms",
        GuestBootStage::SetupContentReady => "setup_content_ready_ms",
        GuestBootStage::RootLayersReady => "root_layers_ready_ms",
        GuestBootStage::WorkspacePlanReady => "workspace_plan_ready_ms",
        GuestBootStage::OwnershipReady => "ownership_ready_ms",
        GuestBootStage::ContainerControlReady => "container_control_ready_ms",
        GuestBootStage::RootGenerationReady => "root_generation_ready_ms",
        GuestBootStage::PersistentLayoutReady => "persistent_layout_ready_ms",
        GuestBootStage::RuncLaunching => "runc_launching_ms",
        GuestBootStage::RuncRunning => "runc_running_ms",
        GuestBootStage::WorkspaceRunning => "workspace_running_ms",
        GuestBootStage::DaemonStarted => "daemon_started_ms",
        GuestBootStage::SetupFailed => "setup_failed_ms",
        GuestBootStage::WorkspaceFailed => "workspace_failed_ms",
        GuestBootStage::DockerToolingMissing => "docker_tooling_missing_ms",
        GuestBootStage::WorkspaceLaunchRefused => "workspace_launch_refused_ms",
    }
}

/// The closed log name of a guest boot stage.
pub(super) fn guest_stage_name(stage: GuestBootStage) -> &'static str {
    match stage {
        GuestBootStage::StateMounted => "state_mounted",
        GuestBootStage::CgroupsReady => "cgroups_ready",
        GuestBootStage::DisksAdmitted => "disks_admitted",
        GuestBootStage::RootMounted => "root_mounted",
        GuestBootStage::SetupHeaderReady => "setup_header_ready",
        GuestBootStage::SetupContentReady => "setup_content_ready",
        GuestBootStage::RootLayersReady => "root_layers_ready",
        GuestBootStage::WorkspacePlanReady => "workspace_plan_ready",
        GuestBootStage::OwnershipReady => "ownership_ready",
        GuestBootStage::ContainerControlReady => "container_control_ready",
        GuestBootStage::RootGenerationReady => "root_generation_ready",
        GuestBootStage::PersistentLayoutReady => "persistent_layout_ready",
        GuestBootStage::RuncLaunching => "runc_launching",
        GuestBootStage::RuncRunning => "runc_running",
        GuestBootStage::WorkspaceRunning => "workspace_running",
        GuestBootStage::DaemonStarted => "daemon_started",
        GuestBootStage::SetupFailed => "setup_failed",
        GuestBootStage::WorkspaceFailed => "workspace_failed",
        GuestBootStage::DockerToolingMissing => "docker_tooling_missing",
        GuestBootStage::WorkspaceLaunchRefused => "workspace_launch_refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #4242: the network wait splits at the guest's ready report into the
    /// guest's boot and the host's network stack; without a report, all of
    /// it is the network's, as before.
    #[test]
    fn the_network_wait_splits_at_the_guests_ready_report() {
        let started = Instant::now();
        let ready = started + Duration::from_millis(1_200);
        let done = started + Duration::from_millis(1_500);
        assert_eq!(
            split_network_wait(started, Some(ready), done),
            (Some(1_200), 300)
        );
        assert_eq!(split_network_wait(started, None, done), (None, 1_500));
    }

    /// #4242: each stage is timed once, at its first report, and the line
    /// names every stage seen, in order, with the retry interval.
    #[test]
    fn the_guest_stages_line_times_each_stage_once_in_order() {
        let started = Instant::now();
        let mut times = GuestStageTimes::default();
        times.record(GuestBootStage::RootMounted);
        times.record(GuestBootStage::WorkspacePlanReady);
        times.record(GuestBootStage::RootMounted);
        times.record(GuestBootStage::DaemonStarted);
        assert_eq!(times.seen().len(), 3);
        let environment = Uuid::new_v4();
        let fields = guest_stage_fields(environment, 7, started, &times);
        let names: Vec<_> = fields.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "environment",
                "generation",
                "retry_ms",
                "root_mounted_ms",
                "workspace_plan_ready_ms",
                "daemon_started_ms",
            ]
        );
        assert!(matches!(fields[2].1, LogField::Count(50)));
        // Every stage has its own field, and none is a guest-supplied name.
        let mut all: Vec<_> = (1..=19)
            .filter_map(|value| GuestBootStage::try_from(value).ok())
            .map(guest_stage_ms_field)
            .collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 19);
        assert!(all.iter().all(|name| name.ends_with("_ms")));
    }
}
