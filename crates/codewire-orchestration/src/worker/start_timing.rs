//! Start-stage timing shared by the create and start activities: the
//! metadata carried by `environment_logs` stage rows and the bounded labels
//! of their Prometheus observations.

use std::time::Duration;

use k8s_openapi::jiff::Timestamp;

use super::create::{SandboxWorkerCfg, runtime_profile_for_isolation_tier};
use crate::sandbox::client::PodStartTimeline;
use crate::start_metrics::{self, CreateMilestone, StartPath, StartProfile, StartStage};

/// One workspace Pod start stage between two consecutive Kubernetes marks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PodStageTiming {
    pub stage: StartStage,
    pub duration: Duration,
    /// The Kubernetes mark that ended this stage.
    pub completed_at: Timestamp,
    pub since_pod_created: Duration,
}

impl PodStageTiming {
    /// `pod_uid` identifies the Pod incarnation, so its marks are recorded
    /// once however many times create reaches it.
    /// The row's metadata. `start_path` tells a reader whether this Pod
    /// booted for the create (cold, resume) or earlier as a warm pool member,
    /// whose start is not part of the create's time.
    pub fn metadata(&self, pod_uid: &str, path: StartPath) -> serde_json::Value {
        serde_json::json!({
            "duration_ms": duration_ms(self.duration),
            "at": self.completed_at.to_string(),
            "since_pod_created_ms": duration_ms(self.since_pod_created),
            "pod_uid": pod_uid,
            "start_path": path.as_str(),
        })
    }
}

/// The `environment_logs` phases that carry Pod start marks.
pub(super) const POD_STAGE_PHASES: [&str; 10] = [
    StartStage::PodScheduled.as_str(),
    StartStage::PodInitialized.as_str(),
    StartStage::PodRunning.as_str(),
    StartStage::PodContainersReady.as_str(),
    StartStage::PodCreated.as_str(),
    StartStage::PodVolumeProvisioned.as_str(),
    StartStage::PodVolumeBound.as_str(),
    StartStage::PodSandboxReady.as_str(),
    StartStage::PodWorkspaceStarted.as_str(),
    StartStage::PodDindStarted.as_str(),
];

/// Pod start stages, in the order their rows are written: each condition
/// stage before the finer stages that split it. A stage is
/// reported only when both of its bounding marks are known, so a missing
/// mark never folds two stages into one name. Marks have one-second
/// resolution; an inverted pair (for example a later readiness flap) clamps
/// to zero.
///
/// The four condition stages (`pod_scheduled` through
/// `pod_containers_ready`) partition the Pod's start. The finer stages split
/// them where the time goes (Program #2238, "Measure first"):
///
/// - `pod_created` precedes the Pod: Claim created to Pod created, on a cold
///   start only, since a warm member's or a resumed Pod's Claim predates it.
/// - `pod_volume_provisioned` + `pod_volume_bound` = `pod_scheduled`, split
///   at the workspace volume's creation, when that volume was provisioned for
///   this Pod.
/// - `pod_sandbox_ready`, then one stage per container in start order
///   (`pod_workspace_started`, `pod_dind_started`), run from scheduled to
///   every container running: `pod_initialized` + `pod_running` on a Pod
///   without init containers. The first container stage starts at the later
///   of the sandbox and init completion, and container stages need every
///   container on its first start.
pub(super) fn pod_stage_timings(
    timeline: &PodStartTimeline,
    path: StartPath,
) -> Vec<PodStageTiming> {
    let Some(created_at) = timeline.created_at else {
        return Vec::new();
    };
    let claim_created_at = timeline
        .claim_created_at
        .filter(|claimed| path == StartPath::Cold && *claimed <= created_at);
    let volume_created_at = timeline
        .volume_created_at
        .filter(|provisioned| *provisioned >= created_at);
    // Each condition stage is written before the finer stages that split
    // it, so a reader can show the parts under their whole.
    let mut stages = vec![
        (StartStage::PodCreated, claim_created_at, Some(created_at)),
        (
            StartStage::PodScheduled,
            timeline.created_at,
            timeline.scheduled_at,
        ),
        (
            StartStage::PodVolumeProvisioned,
            Some(created_at),
            volume_created_at,
        ),
        (
            StartStage::PodVolumeBound,
            volume_created_at,
            timeline.scheduled_at,
        ),
        (
            StartStage::PodInitialized,
            timeline.scheduled_at,
            timeline.initialized_at,
        ),
        (
            StartStage::PodRunning,
            timeline.initialized_at,
            timeline.running_at,
        ),
        (
            StartStage::PodSandboxReady,
            timeline.scheduled_at,
            timeline.ready_to_start_containers_at,
        ),
    ];
    stages.extend(container_stages(timeline));
    stages.push((
        StartStage::PodContainersReady,
        timeline.running_at,
        timeline.containers_ready_at,
    ));
    stages
        .into_iter()
        .filter_map(|(stage, from, to)| {
            let (from, to) = (from?, to?);
            Some(PodStageTiming {
                stage,
                duration: elapsed(from, to),
                completed_at: to,
                since_pod_created: elapsed(created_at, to),
            })
        })
        .collect()
}

type StageMarks = (StartStage, Option<Timestamp>, Option<Timestamp>);

/// The kubelet starts a Pod's containers one after another, so each
/// container's stage runs from the previous start (the first from the later
/// of sandbox ready and init completion) to its own first start.
fn container_stages(timeline: &PodStartTimeline) -> Vec<StageMarks> {
    let (Some(_), Some(sandbox), Some(initialized)) = (
        timeline.running_at,
        timeline.ready_to_start_containers_at,
        timeline.initialized_at,
    ) else {
        return Vec::new();
    };
    let mut started: Vec<_> = [
        (
            StartStage::PodWorkspaceStarted,
            timeline.workspace_started_at,
        ),
        (StartStage::PodDindStarted, timeline.dind_started_at),
    ]
    .into_iter()
    .filter_map(|(stage, at)| Some((stage, at?)))
    .collect();
    // Stable: a same-second tie keeps the rendered container order.
    started.sort_by_key(|(_, at)| *at);
    let mut previous = sandbox.max(initialized);
    started
        .into_iter()
        .map(|(stage, at)| {
            let from = previous;
            previous = at;
            (stage, Some(from), Some(at))
        })
        .collect()
}

/// The runtime profile label for an environment's isolation tier, resolved
/// exactly as `environment_template_opts` resolves the rendered profile.
pub(super) fn start_profile(cfg: &SandboxWorkerCfg, isolation_tier: &str) -> StartProfile {
    match runtime_profile_for_isolation_tier(isolation_tier) {
        Ok(Some(profile)) => StartProfile::from_runtime_profile(profile),
        Ok(None) => StartProfile::from_runtime_profile(&cfg.runtime_profile),
        Err(_) => StartProfile::Other,
    }
}

/// The path a newly recorded workspace binding is observed under, or `None`
/// when the binding is not part of a start: a running environment's replaced
/// Pod or a resize. A bind while `starting` is a resume, including a retried
/// start's, whose resumed Sandbox the binding check reports as cold because
/// an environment bound it before.
pub(super) fn bind_stage_path(state: &str, recorded: StartPath) -> Option<StartPath> {
    matches!(state, "creating" | "starting").then(|| StartPath::for_state(state, recorded))
}

/// How long ago the API accepted this environment's create, by the database
/// clock. `environments.created_at` is the `now()` of the API transaction
/// that inserted the row, so both instants come from one clock and no worker
/// clock skew enters. The column has no time zone: Postgres reads it back in
/// the session time zone it was written in, which no session here changes.
///
/// `None` on a failed read or a missing row. Timing is observational, so it
/// never fails the create.
pub(super) async fn since_accepted<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    environment_id: &str,
) -> Option<Duration> {
    let read = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT EXTRACT(EPOCH FROM (clock_timestamp() - created_at))::float8
           FROM environments WHERE id = $1",
    )
    .bind(environment_id)
    .fetch_optional(executor)
    .await;
    match read {
        Ok(seconds) => seconds
            .flatten()
            .and_then(|seconds| Duration::try_from_secs_f64(seconds.max(0.0)).ok()),
        Err(error) => {
            tracing::warn!(
                environment_id,
                error = %error,
                "create: skip a milestone time after a failed accepted-time read"
            );
            None
        }
    }
}

/// The path a create milestone is observed under, or `None` when the
/// environment is not being created: a resume (`starting`) or a running
/// environment's replaced Pod.
pub(super) fn create_milestone_path(state: &str, path: StartPath) -> Option<StartPath> {
    matches!(state, "pending" | "creating").then_some(path)
}

/// `metadata` with the milestone's `since_accepted_ms`, when it was read.
pub(super) fn with_since_accepted(
    metadata: Option<serde_json::Value>,
    since_accepted: Option<Duration>,
) -> Option<serde_json::Value> {
    let Some(since_accepted) = since_accepted else {
        return metadata;
    };
    let mut metadata = metadata.unwrap_or_else(|| serde_json::json!({}));
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "since_accepted_ms".to_owned(),
            duration_ms(since_accepted).into(),
        );
    }
    Some(metadata)
}

/// Observe a create milestone after its durable row committed, and emit it
/// as a tracing event, which the opt-in `otel` export carries with its span.
pub(super) fn record_create_milestone(
    environment_id: &str,
    milestone: CreateMilestone,
    path: StartPath,
    profile: StartProfile,
    since_accepted: Duration,
) {
    start_metrics::observe_create_milestone(milestone, path, profile, since_accepted);
    tracing::info!(
        environment_id,
        milestone = milestone.as_str(),
        path = path.as_str(),
        profile = profile.as_str(),
        since_accepted_ms = duration_ms(since_accepted),
        "environment create milestone"
    );
}

pub(super) fn duration_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn elapsed(from: Timestamp, to: Timestamp) -> Duration {
    let millis = to
        .as_millisecond()
        .saturating_sub(from.as_millisecond())
        .max(0);
    Duration::from_millis(millis.unsigned_abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Option<Timestamp> {
        Some(Timestamp::from_second(1_790_000_000 + seconds).unwrap())
    }

    #[test]
    fn pod_stages_are_consecutive_increments_from_kubernetes_marks() {
        let timeline = PodStartTimeline {
            created_at: at(0),
            scheduled_at: at(3),
            initialized_at: at(36),
            running_at: at(38),
            containers_ready_at: at(40),
            ..Default::default()
        };
        let stages = pod_stage_timings(&timeline, StartPath::Cold);
        let summary: Vec<_> = stages
            .iter()
            .map(|stage| {
                (
                    stage.stage.as_str(),
                    stage.duration.as_secs(),
                    stage.since_pod_created.as_secs(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("pod_scheduled", 3, 3),
                ("pod_initialized", 33, 36),
                ("pod_running", 2, 38),
                ("pod_containers_ready", 2, 40),
            ]
        );
        assert_eq!(
            stages[1].metadata("pod-uid-1", StartPath::Cold),
            serde_json::json!({
                "duration_ms": 33_000,
                "at": at(36).unwrap().to_string(),
                "since_pod_created_ms": 36_000,
                "pod_uid": "pod-uid-1",
                "start_path": "cold",
            })
        );
        // A warm member's rows say so, so a reader does not count its boot
        // in the create that claimed it.
        assert_eq!(
            stages[1].metadata("pod-uid-1", StartPath::Warm)["start_path"],
            "warm"
        );
    }

    #[test]
    fn a_missing_mark_drops_both_adjacent_stages_instead_of_merging_them() {
        let timeline = PodStartTimeline {
            created_at: at(0),
            scheduled_at: at(3),
            initialized_at: at(36),
            // A restarted container leaves the running mark unknown.
            running_at: None,
            containers_ready_at: at(40),
            ..Default::default()
        };
        let stages: Vec<_> = pod_stage_timings(&timeline, StartPath::Cold)
            .into_iter()
            .map(|stage| stage.stage)
            .collect();
        assert_eq!(
            stages,
            [StartStage::PodScheduled, StartStage::PodInitialized]
        );
        assert!(pod_stage_timings(&PodStartTimeline::default(), StartPath::Cold).is_empty());
    }

    #[test]
    fn inverted_marks_clamp_to_zero() {
        let timeline = PodStartTimeline {
            created_at: at(0),
            scheduled_at: at(1),
            initialized_at: at(5),
            running_at: at(9),
            // A readiness flap can leave ContainersReady's latest transition
            // earlier than a later mark only after clock skew; never negative.
            containers_ready_at: at(8),
            ..Default::default()
        };
        let ready = pod_stage_timings(&timeline, StartPath::Cold)
            .into_iter()
            .find(|stage| stage.stage == StartStage::PodContainersReady)
            .unwrap();
        assert_eq!(ready.duration, Duration::ZERO);
    }

    /// A cold commodity start as Dev reports it: no init containers, so
    /// `Initialized` follows kubelet admission and precedes the sandbox.
    fn cold_commodity_pod() -> PodStartTimeline {
        PodStartTimeline {
            claim_created_at: at(-1),
            created_at: at(0),
            volume_created_at: at(3),
            scheduled_at: at(4),
            initialized_at: at(4),
            ready_to_start_containers_at: at(7),
            workspace_started_at: at(8),
            dind_started_at: at(9),
            running_at: at(9),
            containers_ready_at: at(12),
        }
    }

    fn durations(stages: &[PodStageTiming]) -> Vec<(&'static str, u64)> {
        stages
            .iter()
            .map(|stage| (stage.stage.as_str(), stage.duration.as_secs()))
            .collect()
    }

    #[test]
    fn finer_stages_split_scheduling_and_container_start_where_the_time_goes() {
        let stages = pod_stage_timings(&cold_commodity_pod(), StartPath::Cold);
        assert_eq!(
            durations(&stages),
            [
                ("pod_created", 1),
                ("pod_scheduled", 4),
                ("pod_volume_provisioned", 3),
                ("pod_volume_bound", 1),
                ("pod_initialized", 0),
                ("pod_running", 5),
                ("pod_sandbox_ready", 3),
                ("pod_workspace_started", 1),
                ("pod_dind_started", 1),
                ("pod_containers_ready", 3),
            ]
        );
        let total = |names: &[&str]| -> u64 {
            durations(&stages)
                .iter()
                .filter(|(name, _)| names.contains(name))
                .map(|(_, seconds)| seconds)
                .sum()
        };
        assert_eq!(
            total(&["pod_volume_provisioned", "pod_volume_bound"]),
            total(&["pod_scheduled"])
        );
        assert_eq!(
            total(&[
                "pod_sandbox_ready",
                "pod_workspace_started",
                "pod_dind_started"
            ]),
            total(&["pod_initialized", "pod_running"])
        );
        // Every row is a Pod row: its phase starts with `pod_` and it carries
        // the Pod UID.
        for stage in &stages {
            assert!(POD_STAGE_PHASES.contains(&stage.stage.as_str()));
            assert!(stage.stage.as_str().starts_with("pod_"));
            assert_eq!(stage.metadata("uid", StartPath::Cold)["pod_uid"], "uid");
        }
        let created = &stages[0];
        assert_eq!(created.completed_at, at(0).unwrap());
        assert_eq!(created.since_pod_created, Duration::ZERO);
    }

    #[test]
    fn claim_and_volume_stages_need_marks_from_this_start() {
        // A warm member and a resumed Pod were created under an older Claim.
        for path in [StartPath::Warm, StartPath::Resume] {
            let stages = pod_stage_timings(&cold_commodity_pod(), path);
            assert!(
                stages
                    .iter()
                    .all(|stage| stage.stage != StartStage::PodCreated),
                "{path:?}"
            );
        }
        // A pool member created before the Claim is no controller latency.
        let early_member = PodStartTimeline {
            claim_created_at: at(2),
            ..cold_commodity_pod()
        };
        assert!(
            pod_stage_timings(&early_member, StartPath::Cold)
                .iter()
                .all(|stage| stage.stage != StartStage::PodCreated)
        );
        // A resumed Pod mounts a volume provisioned for an earlier Pod, and
        // an ephemeral or unread volume has no mark: neither volume stage.
        for volume_created_at in [at(-600), None] {
            let timeline = PodStartTimeline {
                volume_created_at,
                ..cold_commodity_pod()
            };
            let names: Vec<_> = pod_stage_timings(&timeline, StartPath::Resume)
                .into_iter()
                .map(|stage| stage.stage)
                .collect();
            assert!(!names.contains(&StartStage::PodVolumeProvisioned));
            assert!(!names.contains(&StartStage::PodVolumeBound));
            assert!(names.contains(&StartStage::PodScheduled));
        }
    }

    #[test]
    fn container_stages_follow_start_order_after_the_sandbox_and_init() {
        // Confidential: an init container runs inside the sandbox, so the
        // first container stage starts at init completion.
        let confidential = PodStartTimeline {
            ready_to_start_containers_at: at(6),
            initialized_at: at(20),
            workspace_started_at: at(22),
            dind_started_at: at(25),
            running_at: at(25),
            ..cold_commodity_pod()
        };
        let stages = durations(&pod_stage_timings(&confidential, StartPath::Cold));
        assert!(stages.contains(&("pod_sandbox_ready", 2)), "{stages:?}");
        assert!(stages.contains(&("pod_workspace_started", 2)), "{stages:?}");
        assert!(stages.contains(&("pod_dind_started", 3)), "{stages:?}");

        // A workspace-only Pod has one container stage.
        let workspace_only = PodStartTimeline {
            dind_started_at: None,
            running_at: at(8),
            ..cold_commodity_pod()
        };
        let stages = durations(&pod_stage_timings(&workspace_only, StartPath::Cold));
        assert!(stages.contains(&("pod_workspace_started", 1)), "{stages:?}");
        assert!(!stages.iter().any(|(name, _)| *name == "pod_dind_started"));

        // A restarted container leaves the Pod's running mark unknown: no
        // container stage, rather than one that absorbs another's time.
        let restarted = PodStartTimeline {
            workspace_started_at: None,
            running_at: None,
            ..cold_commodity_pod()
        };
        let stages = durations(&pod_stage_timings(&restarted, StartPath::Cold));
        assert!(
            !stages
                .iter()
                .any(|(name, _)| matches!(*name, "pod_workspace_started" | "pod_dind_started")),
            "{stages:?}"
        );
        assert!(stages.contains(&("pod_sandbox_ready", 3)), "{stages:?}");
    }

    #[test]
    fn a_bind_while_starting_is_a_resume_not_a_cold_create() {
        // A retried start's bind: the resumed Sandbox was bound before, so
        // the binding check reports it cold.
        assert_eq!(
            bind_stage_path("starting", StartPath::Cold),
            Some(StartPath::Resume)
        );
        assert_eq!(
            bind_stage_path("starting", StartPath::Warm),
            Some(StartPath::Resume)
        );
        assert_eq!(
            bind_stage_path("creating", StartPath::Cold),
            Some(StartPath::Cold)
        );
        assert_eq!(
            bind_stage_path("creating", StartPath::Warm),
            Some(StartPath::Warm)
        );
        for outside_a_start in ["running", "resizing", "pending", "stopped"] {
            assert_eq!(bind_stage_path(outside_a_start, StartPath::Cold), None);
        }
    }

    #[test]
    fn profile_follows_the_isolation_tier_before_the_process_default() {
        let cfg = SandboxWorkerCfg {
            runtime_profile: "commodity".into(),
            ..Default::default()
        };
        assert_eq!(start_profile(&cfg, "standard"), StartProfile::Commodity);
        assert_eq!(
            start_profile(&cfg, "confidential"),
            StartProfile::Confidential
        );
        assert_eq!(start_profile(&cfg, "unsupported"), StartProfile::Other);
    }

    #[test]
    fn only_a_create_records_milestones() {
        for path in [StartPath::Cold, StartPath::Warm] {
            assert_eq!(create_milestone_path("pending", path), Some(path));
            assert_eq!(create_milestone_path("creating", path), Some(path));
            assert_eq!(create_milestone_path("starting", path), None);
            assert_eq!(create_milestone_path("running", path), None);
        }
    }

    #[test]
    fn since_accepted_joins_the_row_metadata_only_when_read() {
        let metadata = Some(serde_json::json!({ "duration_ms": 7 }));
        assert_eq!(with_since_accepted(metadata.clone(), None), metadata);
        assert_eq!(
            with_since_accepted(metadata, Some(Duration::from_micros(41_600))),
            Some(serde_json::json!({ "duration_ms": 7, "since_accepted_ms": 41 }))
        );
        assert_eq!(
            with_since_accepted(None, Some(Duration::from_millis(9))),
            Some(serde_json::json!({ "since_accepted_ms": 9 }))
        );
    }
}
