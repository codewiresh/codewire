//! `cw __native-front-door`: one environment's TLS front door, Linux only
//! until its macOS confinement lands.

use anyhow::Context as _;
use clap::Args;

/// One environment's TLS front door (#3999).
#[derive(Debug, Args)]
pub(crate) struct NativeFrontDoorArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

pub(crate) async fn run_native_front_door(args: NativeFrontDoorArgs) -> anyhow::Result<()> {
    // The front door checks that the id is canonical itself.
    codewire_local_vmm::front_door::run_inherited_front_door(&args.environment_id, args.generation)
        .await
        .context("run native environment front door")
}
