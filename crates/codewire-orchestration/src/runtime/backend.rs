//! Which driver runs an environment: `environments.runtime_backend` (#3609).

/// The driver an environment runs on. Parsed from its row; a value this
/// orchestration doesn't know is refused rather than read as a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBackend {
    /// The deployment's own cluster.
    Kubernetes,
    /// An enrolled host. Its compute is its owner's: it draws no credit and
    /// counts against no CPU or memory limit, only the environment counts.
    Host,
}

impl RuntimeBackend {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "kubernetes" => Ok(Self::Kubernetes),
            "host" => Ok(Self::Host),
            other => anyhow::bail!("unknown environment runtime backend {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Host => "host",
        }
    }

    /// Whether the platform pays for this environment's compute, so credit
    /// and the plan's CPU and memory limits apply.
    pub fn platform_compute(self) -> bool {
        self == Self::Kubernetes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backend_round_trips_and_an_unknown_one_is_refused() {
        for backend in [RuntimeBackend::Kubernetes, RuntimeBackend::Host] {
            assert_eq!(RuntimeBackend::parse(backend.as_str()).unwrap(), backend);
        }
        assert!(RuntimeBackend::parse("docker").is_err());
        assert!(RuntimeBackend::parse("").is_err());
        assert!(RuntimeBackend::Kubernetes.platform_compute());
        assert!(!RuntimeBackend::Host.platform_compute());
    }
}
