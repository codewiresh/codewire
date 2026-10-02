//! Gateway Prometheus metrics, served as text on the readiness listener's
//! `/metrics`. A private registry holds only these counters, so the endpoint
//! exposes no process or build details.

use std::sync::OnceLock;

use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};

pub const DAEMON_CREDENTIAL_REFRESHES: &str = "codewire_gateway_daemon_credential_refreshes_total";

/// What one refusal-driven daemon credential refresh found (Program #2238 B2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A new credential or Pod UID was installed.
    Changed,
    /// The binding returned the credential already held for the same Pod.
    Unchanged,
    /// No credential was issued: not bound yet, refused or unreachable.
    Failed,
}

impl RefreshOutcome {
    pub const ALL: [Self; 3] = [Self::Changed, Self::Unchanged, Self::Failed];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
        }
    }
}

struct Metrics {
    registry: Registry,
    refreshes: IntCounterVec,
}

fn metrics() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let registry = Registry::new();
        let refreshes = IntCounterVec::new(
            Opts::new(
                DAEMON_CREDENTIAL_REFRESHES,
                "Refusal-driven workspace daemon credential refreshes by result",
            ),
            &["result"],
        )
        .expect("static daemon credential refresh metric is valid");
        registry
            .register(Box::new(refreshes.clone()))
            .expect("daemon credential refresh metric registers once");
        for outcome in RefreshOutcome::ALL {
            refreshes.with_label_values(&[outcome.as_str()]);
        }
        Metrics {
            registry,
            refreshes,
        }
    })
}

pub fn observe_daemon_credential_refresh(outcome: RefreshOutcome) {
    metrics()
        .refreshes
        .with_label_values(&[outcome.as_str()])
        .inc();
}

pub fn daemon_credential_refreshes(outcome: RefreshOutcome) -> u64 {
    metrics()
        .refreshes
        .with_label_values(&[outcome.as_str()])
        .get()
}

/// The Prometheus text exposition of every gateway metric.
pub fn render() -> String {
    let mut buffer = Vec::new();
    TextEncoder::new()
        .encode(&metrics().registry.gather(), &mut buffer)
        .expect("text encoding of gateway counters");
    String::from_utf8(buffer).expect("Prometheus text exposition is UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refresh_outcome_is_counted_and_rendered() {
        for outcome in RefreshOutcome::ALL {
            let before = daemon_credential_refreshes(outcome);
            observe_daemon_credential_refresh(outcome);
            assert!(daemon_credential_refreshes(outcome) > before);
        }
        let text = render();
        for outcome in RefreshOutcome::ALL {
            assert!(
                text.contains(&format!(
                    "{DAEMON_CREDENTIAL_REFRESHES}{{result=\"{}\"}}",
                    outcome.as_str()
                )),
                "{text}"
            );
        }
        assert!(!text.contains("process_"), "{text}");
    }
}
