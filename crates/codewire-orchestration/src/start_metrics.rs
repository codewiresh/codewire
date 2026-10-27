//! Bounded Prometheus telemetry for environment start stages.
//!
//! One histogram records how long each measured start stage took, for a
//! create and for the resume of a stopped environment, observed where the
//! matching `environment_logs` stage row is committed. Labels are
//! closed operational categories only: the stage name, the start path and
//! the runtime profile. Environment, organization, Pod and claim identifiers
//! never become labels; the per-environment record stays in
//! `environment_logs`, which the admin startup summary reads.
//!
//! Only completed stages are observed. A failed stage's elapsed time measures
//! how long the failure took to surface, not how long the stage takes, so it
//! is left to the durable `failed` log row.
//!
//! A second histogram (Program #2238, the < 50 ms warm create goal) records,
//! for a create only, how long after the API accepted the request each create
//! milestone landed. Its buckets start at 5 ms, where the stage histogram's
//! start at half a second, and it carries the same closed labels with the
//! milestone in place of the stage.

use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{HistogramOpts, HistogramVec, register_histogram_vec};

use crate::sandbox::template::{
    RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL, RUNTIME_PROFILE_NONE,
    RUNTIME_PROFILE_RUNC,
};

static STAGE_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static CREATE_MILESTONE_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

/// Sub-second API stages through multi-minute image pulls. The top bucket is
/// the commodity create readiness timeout; slower confidential starts fall in
/// `+Inf`.
const STAGE_BUCKETS: [f64; 16] = [
    0.5, 1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0, 300.0, 600.0,
];

/// Tens of milliseconds, the warm create goal, through a minute, past a cold
/// create's usual setup completion; slower creates fall in `+Inf`.
const CREATE_MILESTONE_BUCKETS: [f64; 16] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0, 20.0, 30.0, 60.0,
];

/// A create milestone, timed from the instant the API accepted the create.
/// The milestone's `completed` `environment_logs` row (named on each value)
/// carries the same time as `since_accepted_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMilestone {
    /// The workspace binding committed (`workspace_bind`): an identity-free
    /// daemon listens from here.
    Bound,
    /// The credential gateway served readiness (`access_ready`): SSH access
    /// is ready.
    AccessReady,
    /// Setup committed (`complete`).
    SetupComplete,
}

impl CreateMilestone {
    pub const ALL: [Self; 3] = [Self::Bound, Self::AccessReady, Self::SetupComplete];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::AccessReady => "access_ready",
            Self::SetupComplete => "setup_complete",
        }
    }
}

/// A measured start stage. Each value is also the `environment_logs` phase
/// that records the same stage for one environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStage {
    /// Environment-scoped template, shadow pool, claim and gateway objects
    /// created. Excludes the readiness wait.
    CreateClaim,
    /// Credential gateway readiness wait. The gateway serves `/readyz` only
    /// after it reaches the workspace daemon, so this covers the workspace
    /// cold start.
    AccessReady,
    /// Claim readiness wait, when the claim was not already ready.
    WaitForReady,
    /// Recording the claim-time workspace binding (Program #2238 B2): the
    /// live chain, image and PVC checks and the fenced write, between Claim
    /// readiness and the gateway readiness wait.
    WorkspaceBind,
    /// Workspace Pod created until scheduled (includes volume provisioning
    /// under `WaitForFirstConsumer`).
    PodScheduled,
    /// Scheduled until init containers completed (volume attach, sandbox
    /// boot, init image pulls and daemon-init).
    PodInitialized,
    /// Initialized until every container is running on its first start
    /// (workload image pulls and container creation).
    PodRunning,
    /// Every container running until every container is ready.
    PodContainersReady,
    // Finer Pod start stages (Program #2238, "Measure first"). They split the
    // Pod marks above where the time goes, so each lies inside one or two of
    // them rather than adding to them.
    /// SandboxClaim created until its workspace Pod is created: the
    /// agent-sandbox controller's Sandbox and Pod creation. Cold starts only.
    PodCreated,
    /// Pod created until its workspace PersistentVolume is created: node
    /// selection under `WaitForFirstConsumer` and the storage provisioner
    /// creating the volume (LINSTOR resource, DRBD, LUKS). Only when the
    /// volume was provisioned for this Pod. The first part of `PodScheduled`.
    PodVolumeProvisioned,
    /// PersistentVolume created until the Pod is scheduled: the PVC bind and
    /// the scheduler's Pod binding. The rest of `PodScheduled`.
    PodVolumeBound,
    /// Pod scheduled until `PodReadyToStartContainers`: kubelet admission,
    /// volume attach and mount, and the Pod sandbox (the Kata VM) with its
    /// network.
    PodSandboxReady,
    /// The sandbox ready (and init containers complete) until the `workspace`
    /// container's first start: its image pull, create and start.
    PodWorkspaceStarted,
    /// The previous container's start until the `dind` container's first
    /// start: its image pull, create and start.
    PodDindStarted,
}

impl StartStage {
    pub const ALL: [Self; 14] = [
        Self::CreateClaim,
        Self::AccessReady,
        Self::WaitForReady,
        Self::WorkspaceBind,
        Self::PodScheduled,
        Self::PodInitialized,
        Self::PodRunning,
        Self::PodContainersReady,
        Self::PodCreated,
        Self::PodVolumeProvisioned,
        Self::PodVolumeBound,
        Self::PodSandboxReady,
        Self::PodWorkspaceStarted,
        Self::PodDindStarted,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateClaim => "create_claim",
            Self::AccessReady => "access_ready",
            Self::WaitForReady => "wait_for_ready",
            Self::WorkspaceBind => "workspace_bind",
            Self::PodScheduled => "pod_scheduled",
            Self::PodInitialized => "pod_initialized",
            Self::PodRunning => "pod_running",
            Self::PodContainersReady => "pod_containers_ready",
            Self::PodCreated => "pod_created",
            Self::PodVolumeProvisioned => "pod_volume_provisioned",
            Self::PodVolumeBound => "pod_volume_bound",
            Self::PodSandboxReady => "pod_sandbox_ready",
            Self::PodWorkspaceStarted => "pod_workspace_started",
            Self::PodDindStarted => "pod_dind_started",
        }
    }
}

/// How the workspace was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartPath {
    /// A Sandbox created for this environment: its own template, or a pool
    /// claim that found no ready member.
    Cold,
    /// A ready warm-pool member a claim adopted (Program #2238 C3): the
    /// agent-sandbox `launch-type` is `warm`.
    Warm,
    /// A stopped environment's own suspended Sandbox scaled back to one
    /// replica with its retained volume (the `starting` state). Restoring
    /// from a snapshot and forking will get their own values when hosted
    /// environments gain them.
    Resume,
}

impl StartPath {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Resume => "resume",
        }
    }

    /// The path of a stage observed while the environment is in `state`,
    /// for a Sandbox whose own path is `sandbox`. Only an environment that
    /// ran before enters `starting` (from `stopped` or `error`), so whichever
    /// activity drives it, the start or a create recovering an interrupted
    /// start, it resumes that environment's Sandbox rather than creating one.
    pub fn for_state(state: &str, sandbox: Self) -> Self {
        if state == "starting" {
            Self::Resume
        } else {
            sandbox
        }
    }

    /// The path of a Sandbox, from the agent-sandbox launch type it carries.
    pub fn from_launch_type(launch_type: Option<&str>) -> Self {
        if launch_type == Some(crate::sandbox::warm_pool::LAUNCH_TYPE_WARM) {
            Self::Warm
        } else {
            Self::Cold
        }
    }
}

/// The resolved runtime profile, closed so a misconfigured profile string
/// cannot mint a new label value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartProfile {
    Commodity,
    Confidential,
    Runc,
    None,
    Other,
}

impl StartProfile {
    pub fn from_runtime_profile(profile: &str) -> Self {
        match profile.trim() {
            RUNTIME_PROFILE_COMMODITY => Self::Commodity,
            RUNTIME_PROFILE_CONFIDENTIAL => Self::Confidential,
            RUNTIME_PROFILE_RUNC => Self::Runc,
            RUNTIME_PROFILE_NONE => Self::None,
            _ => Self::Other,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commodity => "commodity",
            Self::Confidential => "confidential",
            Self::Runc => "runc",
            Self::None => "none",
            Self::Other => "other",
        }
    }
}

fn stage_seconds_metric() -> &'static HistogramVec {
    STAGE_SECONDS.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "codewire_environment_start_stage_seconds",
                "Duration of completed environment start stages."
            )
            .buckets(STAGE_BUCKETS.to_vec()),
            &["stage", "path", "profile"]
        )
        .expect("environment start stage metric registration must be unique")
    })
}

fn create_milestone_seconds_metric() -> &'static HistogramVec {
    CREATE_MILESTONE_SECONDS.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "codewire_environment_create_milestone_seconds",
                "Time from the API accepting an environment create until each create milestone."
            )
            .buckets(CREATE_MILESTONE_BUCKETS.to_vec()),
            &["milestone", "path", "profile"]
        )
        .expect("environment create milestone metric registration must be unique")
    })
}

/// Record one create milestone, `since_accepted` after the API accepted the
/// create. Call only after the milestone's durable log row committed, with
/// the time the row carries. `path` is `cold` or `warm`: a resume is not a
/// create.
pub fn observe_create_milestone(
    milestone: CreateMilestone,
    path: StartPath,
    profile: StartProfile,
    since_accepted: Duration,
) {
    debug_assert_ne!(path, StartPath::Resume, "a resume has no create milestones");
    create_milestone_seconds_metric()
        .with_label_values(&[milestone.as_str(), path.as_str(), profile.as_str()])
        .observe(since_accepted.as_secs_f64());
}

/// Record one completed stage. Call only after the stage's durable log row
/// committed, with the same duration the row carries.
pub fn observe_stage(
    stage: StartStage,
    path: StartPath,
    profile: StartProfile,
    duration: Duration,
) {
    stage_seconds_metric()
        .with_label_values(&[stage.as_str(), path.as_str(), profile.as_str()])
        .observe(duration.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use prometheus::{Encoder, TextEncoder};

    use super::*;

    fn sample_count(stage: StartStage, profile: StartProfile) -> u64 {
        stage_seconds_metric()
            .get_metric_with_label_values(&[stage.as_str(), "cold", profile.as_str()])
            .unwrap()
            .get_sample_count()
    }

    #[test]
    fn renders_the_stage_histogram_with_closed_labels_and_start_buckets() {
        observe_stage(
            StartStage::AccessReady,
            StartPath::Cold,
            StartProfile::Commodity,
            Duration::from_millis(21_600),
        );

        let mut rendered = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut rendered)
            .unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("# TYPE codewire_environment_start_stage_seconds histogram"));
        assert!(rendered.contains(
            "codewire_environment_start_stage_seconds_bucket{path=\"cold\",profile=\"commodity\",stage=\"access_ready\",le=\"0.5\"}"
        ));
        assert!(rendered.contains(
            "codewire_environment_start_stage_seconds_bucket{path=\"cold\",profile=\"commodity\",stage=\"access_ready\",le=\"600\"}"
        ));
        // Only the closed label names (plus the bucket bound) may appear.
        let series: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with("codewire_environment_start_stage_seconds"))
            .collect();
        assert!(!series.is_empty());
        for line in series {
            let labels = line
                .split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(labels, _)| labels)
                .unwrap_or_default();
            for pair in labels.split(',') {
                let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(pair);
                assert!(
                    matches!(name, "stage" | "path" | "profile" | "le"),
                    "unexpected label {name:?} in {line}"
                );
            }
        }
    }

    #[test]
    fn each_observation_lands_in_exactly_one_stage_series() {
        let before = sample_count(StartStage::PodScheduled, StartProfile::Confidential);
        observe_stage(
            StartStage::PodScheduled,
            StartPath::Cold,
            StartProfile::Confidential,
            Duration::from_secs(3),
        );
        assert_eq!(
            sample_count(StartStage::PodScheduled, StartProfile::Confidential),
            before + 1
        );
    }

    #[test]
    fn buckets_cover_half_a_second_to_ten_minutes_in_order() {
        assert_eq!(STAGE_BUCKETS.first(), Some(&0.5));
        assert_eq!(STAGE_BUCKETS.last(), Some(&600.0));
        assert!(STAGE_BUCKETS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn runtime_profiles_map_to_a_closed_label_set() {
        assert_eq!(
            StartProfile::from_runtime_profile("commodity"),
            StartProfile::Commodity
        );
        assert_eq!(
            StartProfile::from_runtime_profile(" confidential "),
            StartProfile::Confidential
        );
        assert_eq!(
            StartProfile::from_runtime_profile("runc"),
            StartProfile::Runc
        );
        assert_eq!(
            StartProfile::from_runtime_profile("none"),
            StartProfile::None
        );
        assert_eq!(StartProfile::from_runtime_profile(""), StartProfile::Other);
        assert_eq!(
            StartProfile::from_runtime_profile("kata-clh-unreviewed"),
            StartProfile::Other
        );
    }

    #[test]
    fn only_an_adopted_pool_member_is_a_warm_start() {
        assert_eq!(StartPath::from_launch_type(Some("warm")), StartPath::Warm);
        assert_eq!(StartPath::from_launch_type(Some("cold")), StartPath::Cold);
        assert_eq!(StartPath::from_launch_type(None), StartPath::Cold);
        assert_eq!(StartPath::Warm.as_str(), "warm");
        observe_stage(
            StartStage::WorkspaceBind,
            StartPath::Warm,
            StartProfile::Commodity,
            Duration::from_millis(900),
        );
        assert_eq!(
            stage_seconds_metric()
                .get_metric_with_label_values(&["workspace_bind", "warm", "commodity"])
                .unwrap()
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn starting_is_a_resume_whatever_the_sandbox_path() {
        assert_eq!(StartPath::Resume.as_str(), "resume");
        for sandbox in [StartPath::Cold, StartPath::Warm] {
            assert_eq!(StartPath::for_state("starting", sandbox), StartPath::Resume);
            assert_eq!(StartPath::for_state("creating", sandbox), sandbox);
            assert_eq!(StartPath::for_state("pending", sandbox), sandbox);
        }
    }

    #[test]
    fn resume_stages_render_their_own_series_apart_from_create() {
        let count = |path: &str| {
            stage_seconds_metric()
                .get_metric_with_label_values(&["wait_for_ready", path, "runc"])
                .unwrap()
                .get_sample_count()
        };
        let (cold, warm, resume) = (count("cold"), count("warm"), count("resume"));
        observe_stage(
            StartStage::WaitForReady,
            StartPath::Resume,
            StartProfile::Runc,
            Duration::from_millis(4_200),
        );
        assert_eq!(
            (count("cold"), count("warm"), count("resume")),
            (cold, warm, resume + 1)
        );

        let mut rendered = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut rendered)
            .unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains(
            "codewire_environment_start_stage_seconds_bucket{path=\"resume\",profile=\"runc\",stage=\"wait_for_ready\",le=\"5\"}"
        ));
    }

    fn rendered() -> String {
        let mut rendered = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut rendered)
            .unwrap();
        String::from_utf8(rendered).unwrap()
    }

    fn milestone_count(milestone: CreateMilestone, path: StartPath, profile: StartProfile) -> u64 {
        create_milestone_seconds_metric()
            .get_metric_with_label_values(&[milestone.as_str(), path.as_str(), profile.as_str()])
            .unwrap()
            .get_sample_count()
    }

    #[test]
    fn renders_the_create_milestone_histogram_with_closed_labels_and_millisecond_buckets() {
        observe_create_milestone(
            CreateMilestone::AccessReady,
            StartPath::Warm,
            StartProfile::Commodity,
            Duration::from_millis(42),
        );

        let rendered = rendered();
        assert!(
            rendered.contains("# TYPE codewire_environment_create_milestone_seconds histogram")
        );
        for bound in ["0.005", "0.05", "60"] {
            assert!(
                rendered.contains(&format!(
                    "codewire_environment_create_milestone_seconds_bucket{{milestone=\"access_ready\",path=\"warm\",profile=\"commodity\",le=\"{bound}\"}}"
                )),
                "missing bucket {bound}"
            );
        }
        let series: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with("codewire_environment_create_milestone_seconds"))
            .collect();
        assert!(!series.is_empty());
        for line in series {
            let labels = line
                .split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(labels, _)| labels)
                .unwrap_or_default();
            for pair in labels.split(',') {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                let value = value.trim_matches('"');
                match name {
                    "milestone" => assert!(
                        CreateMilestone::ALL.iter().any(|m| m.as_str() == value),
                        "unexpected milestone {value:?} in {line}"
                    ),
                    "path" => assert!(
                        matches!(value, "cold" | "warm"),
                        "unexpected path {value:?} in {line}"
                    ),
                    "profile" | "le" => {}
                    _ => panic!("unexpected label {name:?} in {line}"),
                }
            }
        }
    }

    #[test]
    fn a_milestone_lands_in_its_own_series_and_millisecond_bucket() {
        let before = milestone_count(CreateMilestone::Bound, StartPath::Cold, StartProfile::Runc);
        let others: Vec<u64> = [CreateMilestone::AccessReady, CreateMilestone::SetupComplete]
            .into_iter()
            .map(|m| milestone_count(m, StartPath::Cold, StartProfile::Runc))
            .collect();
        observe_create_milestone(
            CreateMilestone::Bound,
            StartPath::Cold,
            StartProfile::Runc,
            Duration::from_millis(30),
        );
        assert_eq!(
            milestone_count(CreateMilestone::Bound, StartPath::Cold, StartProfile::Runc),
            before + 1
        );
        let after: Vec<u64> = [CreateMilestone::AccessReady, CreateMilestone::SetupComplete]
            .into_iter()
            .map(|m| milestone_count(m, StartPath::Cold, StartProfile::Runc))
            .collect();
        assert_eq!(after, others);

        // 30 ms is above the 25 ms bucket and within the 50 ms one.
        let rendered = rendered();
        let cumulative = |bound: &str| -> u64 {
            let series = format!(
                "codewire_environment_create_milestone_seconds_bucket{{milestone=\"bound\",path=\"cold\",profile=\"runc\",le=\"{bound}\"}} "
            );
            rendered
                .lines()
                .find_map(|line| line.strip_prefix(series.as_str()))
                .and_then(|count| count.parse().ok())
                .unwrap_or_else(|| panic!("missing bucket {bound}"))
        };
        assert_eq!(cumulative("0.05") - cumulative("0.025"), 1);
    }

    #[test]
    fn milestone_buckets_cover_five_milliseconds_to_a_minute_in_order() {
        assert_eq!(CREATE_MILESTONE_BUCKETS.first(), Some(&0.005));
        assert_eq!(CREATE_MILESTONE_BUCKETS.last(), Some(&60.0));
        assert!(
            CREATE_MILESTONE_BUCKETS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(
            CREATE_MILESTONE_BUCKETS.contains(&0.05),
            "the warm create goal is a bound"
        );
    }

    #[test]
    fn milestone_names_are_unique() {
        let mut names: Vec<_> = CreateMilestone::ALL.iter().map(|m| m.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CreateMilestone::ALL.len());
    }

    #[test]
    fn stage_names_are_unique() {
        let mut names: Vec<_> = StartStage::ALL.iter().map(|stage| stage.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), StartStage::ALL.len());
    }
}
