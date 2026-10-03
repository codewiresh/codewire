//! Bounded Prometheus telemetry for environment start stages.
//!
//! One histogram records how long each measured create stage took, observed
//! where the matching `environment_logs` stage row is committed. Labels are
//! closed operational categories only: the stage name, the start path and
//! the runtime profile. Environment, organization, Pod and claim identifiers
//! never become labels; the per-environment record stays in
//! `environment_logs`, which the admin startup summary reads.
//!
//! Only completed stages are observed. A failed stage's elapsed time measures
//! how long the failure took to surface, not how long the stage takes, so it
//! is left to the durable `failed` log row.

use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{HistogramOpts, HistogramVec, register_histogram_vec};

use crate::sandbox::template::{
    RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL, RUNTIME_PROFILE_NONE,
    RUNTIME_PROFILE_RUNC,
};

static STAGE_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

/// Sub-second API stages through multi-minute image pulls. The top bucket is
/// the commodity create readiness timeout; slower confidential starts fall in
/// `+Inf`.
const STAGE_BUCKETS: [f64; 16] = [
    0.5, 1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0, 300.0, 600.0,
];

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
    GatewayReady,
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
}

impl StartStage {
    pub const ALL: [Self; 8] = [
        Self::CreateClaim,
        Self::GatewayReady,
        Self::WaitForReady,
        Self::WorkspaceBind,
        Self::PodScheduled,
        Self::PodInitialized,
        Self::PodRunning,
        Self::PodContainersReady,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateClaim => "create_claim",
            Self::GatewayReady => "gateway_ready",
            Self::WaitForReady => "wait_for_ready",
            Self::WorkspaceBind => "workspace_bind",
            Self::PodScheduled => "pod_scheduled",
            Self::PodInitialized => "pod_initialized",
            Self::PodRunning => "pod_running",
            Self::PodContainersReady => "pod_containers_ready",
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
}

impl StartPath {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
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
            StartStage::GatewayReady,
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
            "codewire_environment_start_stage_seconds_bucket{path=\"cold\",profile=\"commodity\",stage=\"gateway_ready\",le=\"0.5\"}"
        ));
        assert!(rendered.contains(
            "codewire_environment_start_stage_seconds_bucket{path=\"cold\",profile=\"commodity\",stage=\"gateway_ready\",le=\"600\"}"
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
    fn stage_names_are_unique() {
        let mut names: Vec<_> = StartStage::ALL.iter().map(|stage| stage.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), StartStage::ALL.len());
    }
}
