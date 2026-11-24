//! The arguments of cw's hidden roles: the local supervisor, runner and the
//! confined processes each environment runs.

use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub(crate) struct NativeSupervisorArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_lock: PathBuf,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
    #[arg(long)]
    pub(crate) credential_authority_root: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct NativeRunnerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) socket: PathBuf,
    #[arg(long)]
    pub(crate) engine_state_root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_generation: String,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct NativeNetworkWorkerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
    /// A broker-mode standard guest's network (#5602): its `eth0` takes the
    /// /30 beside the one its `cwegress0` holds. Only the runner sets it.
    #[arg(long)]
    pub(crate) hosted_broker_network: bool,
}

#[derive(Debug, Args)]
pub(crate) struct NativeEgressBrokerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
    /// Hand intercepted dials to the front door over the inherited
    /// hand-off socket instead of refusing them (#3999).
    #[arg(long)]
    pub(crate) intercept_handoff: bool,
}

#[derive(Debug, Args)]
pub(crate) struct NativeMeshTransportArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[derive(Debug, Args)]
pub(crate) struct NativeMeshEnrollmentBrokerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
}
