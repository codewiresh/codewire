use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub state_root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("the Cloud Hypervisor local VM engine is supported only on Linux")]
    UnsupportedPlatform,
}

#[derive(Debug)]
pub struct CloudHypervisorRunner;

impl CloudHypervisorRunner {
    pub async fn new(_config: RunnerConfig) -> Result<Self, RunnerError> {
        Err(RunnerError::UnsupportedPlatform)
    }
}
