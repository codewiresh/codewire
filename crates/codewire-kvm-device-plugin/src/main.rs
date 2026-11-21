//! cw-kvm-device-plugin: hands the node's `/dev/kvm` to Pods that request
//! `codewire.sh/kvm`. It runs as a DaemonSet on the nodes that may run
//! `standard` sandboxes.

use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use codewire_kvm_device_plugin::{CONTAINER_DEVICE, Config, KUBELET_PLUGIN_DIR, run};

#[derive(Parser)]
#[command(about = "Hands /dev/kvm to Pods that request codewire.sh/kvm")]
struct Args {
    /// How many Pods on this node may hold /dev/kvm at once.
    #[arg(long)]
    devices: NonZeroU16,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let config = Config {
        plugin_dir: PathBuf::from(KUBELET_PLUGIN_DIR),
        node_device: CONTAINER_DEVICE.to_owned(),
        devices: args.devices,
        poll: Duration::from_secs(5),
    };
    match run(config).await {
        Ok(never) => match never {},
        Err(error) => {
            tracing::error!(%error, "cw-kvm-device-plugin stopped");
            ExitCode::FAILURE
        }
    }
}
