//! Explicit-path native supervisor entrypoint; no ordinary local CLI routing.

use anyhow::Context as _;
use codewire_local_vmm::supervisor_config::NativeRuntimeConfig;

use super::NativeSupervisorArgs;

pub(crate) async fn run_native_supervisor(args: NativeSupervisorArgs) -> anyhow::Result<()> {
    let executable = std::env::current_exe().context("resolve current cw executable")?;
    let executable =
        std::fs::canonicalize(executable).context("canonicalize current cw executable")?;
    codewire_local_vmm::darwin::supervisor::serve_supervisor(NativeRuntimeConfig {
        root: args.root,
        artifact_root: args.artifact_root,
        artifact_lock: args.artifact_lock,
        mesh_data_dir: args.mesh_data_dir,
        platform_config_dir: args.platform_config_dir,
        credential_authority_root: args.credential_authority_root,
        executable,
    })
    .await
    .context("run native local supervisor")
}
