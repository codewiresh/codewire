//! Start-stage timing shared by the create activity: the metadata carried by
//! `environment_logs` stage rows and the bounded labels of their Prometheus
//! observations.

use std::time::Duration;

use k8s_openapi::jiff::Timestamp;

use super::create::{SandboxWorkerCfg, runtime_profile_for_isolation_tier};
use crate::sandbox::client::PodStartTimeline;
use crate::start_metrics::{StartProfile, StartStage};

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
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "duration_ms": duration_ms(self.duration),
            "at": self.completed_at.to_string(),
            "since_pod_created_ms": duration_ms(self.since_pod_created),
        })
    }
}

/// Consecutive Pod start stages. A stage is reported only when both of its
/// bounding marks are known, so a missing mark never folds two stages into
/// one name. Marks have one-second resolution; an inverted pair (for example
/// a later readiness flap) clamps to zero.
pub(super) fn pod_stage_timings(timeline: &PodStartTimeline) -> Vec<PodStageTiming> {
    let Some(created_at) = timeline.created_at else {
        return Vec::new();
    };
    [
        (
            StartStage::PodScheduled,
            timeline.created_at,
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
            StartStage::PodContainersReady,
            timeline.running_at,
            timeline.containers_ready_at,
        ),
    ]
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

/// The runtime profile label for an environment's isolation tier, resolved
/// exactly as `environment_template_opts` resolves the rendered profile.
pub(super) fn start_profile(cfg: &SandboxWorkerCfg, isolation_tier: &str) -> StartProfile {
    match runtime_profile_for_isolation_tier(isolation_tier) {
        Ok(Some(profile)) => StartProfile::from_runtime_profile(profile),
        Ok(None) => StartProfile::from_runtime_profile(&cfg.runtime_profile),
        Err(_) => StartProfile::Other,
    }
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
        };
        let stages = pod_stage_timings(&timeline);
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
            stages[1].metadata(),
            serde_json::json!({
                "duration_ms": 33_000,
                "at": at(36).unwrap().to_string(),
                "since_pod_created_ms": 36_000,
            })
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
        };
        let stages: Vec<_> = pod_stage_timings(&timeline)
            .into_iter()
            .map(|stage| stage.stage)
            .collect();
        assert_eq!(
            stages,
            [StartStage::PodScheduled, StartStage::PodInitialized]
        );
        assert!(pod_stage_timings(&PodStartTimeline::default()).is_empty());
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
        };
        let ready = pod_stage_timings(&timeline)
            .into_iter()
            .find(|stage| stage.stage == StartStage::PodContainersReady)
            .unwrap();
        assert_eq!(ready.duration, Duration::ZERO);
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
}
