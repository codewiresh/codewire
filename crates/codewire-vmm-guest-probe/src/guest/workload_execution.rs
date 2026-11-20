//! How the guest daemon runs a process in the workspace container: through
//! runc, as the plan's identity, in the workload's network namespace.

use std::path::PathBuf;

use codewire_daemon::execution::{ProcessExecution, RuncExecution};

use super::{
    CONTAINER_INIT_PATH, INIT_PATH, NETWORK_NAMESPACE_PATH, ROOT_MERGED_PATH, RUNC_PROCESS_PATH,
    WORKSPACE_CONTAINER_ID, runtime_path_environment,
};
use crate::Seed;
use crate::workspace_plan::WorkspacePlan;

/// `live_runtime` says a published cw runtime is on this boot's path.
pub(super) fn workload_execution(
    seed: &Seed,
    plan: &WorkspacePlan,
    live_runtime: bool,
) -> ProcessExecution {
    ProcessExecution::Runc(Box::new(RuncExecution {
        helper_path: PathBuf::from(INIT_PATH),
        process_directory: PathBuf::from(RUNC_PROCESS_PATH),
        container_id: WORKSPACE_CONTAINER_ID.to_owned(),
        process_wrapper: vec![CONTAINER_INIT_PATH.to_owned(), "workspace-exec".to_owned()],
        default_shell: plan.identity.shell.clone(),
        base_environment: runtime_path_environment(&plan.environment, live_runtime),
        uid: plan.identity.uid,
        gid: plan.identity.gid,
        additional_gids: plan.identity.additional_gids.clone(),
        network_namespace: PathBuf::from(NETWORK_NAMESPACE_PATH),
        workload_may_become_root: seed.docker_data_disk(),
        workload_root: PathBuf::from(ROOT_MERGED_PATH),
    }))
}
