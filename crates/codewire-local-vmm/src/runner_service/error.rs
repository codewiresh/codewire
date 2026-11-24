//! Why a runner could not be served, adopted or reached.

use super::*;

#[derive(Debug, thiserror::Error)]
pub enum RunnerServiceError {
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Uds(#[from] UdsError),
    #[error("runtime artifact store operation failed")]
    ArtifactStore,
    #[error("serve private environment runner failed")]
    Serve,
    #[error("adopt private environment runner failed")]
    Adoption,
    #[error("private environment runner configuration is invalid")]
    Configuration,
    #[error("the native environment runner does not implement the required compatibility protocol")]
    RunnerProtocolUnavailable,
    #[error(
        "native environment runner protocol version mismatch: expected {expected}, running runner reported {actual}"
    )]
    RunnerProtocolMismatch { expected: u32, actual: u32 },
    #[error("query native environment runner compatibility failed")]
    RunnerProtocolInfoUnavailable,
}

impl RunnerServiceError {
    pub(crate) fn incompatible_protocol(&self) -> bool {
        matches!(
            self,
            Self::RunnerProtocolUnavailable | Self::RunnerProtocolMismatch { .. }
        )
    }
}
