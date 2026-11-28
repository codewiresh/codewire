//! What a create on a host (#3609) shares with `cw --local create`: the
//! project fields a local VM cannot honour, and the empty workspace it starts
//! from. The host agent refuses exactly what `cw --local create` refuses.

use super::{NATIVE_EMPTY_WORKSPACE, OsEnv, ResolvePaths, empty_native_workspace};

/// The fields of `spec` a local VM does not support. `has_local_mounts` is
/// whether the project mounts a host folder, which makes a working
/// directory other than `/workspace` usable.
pub(crate) fn unsupported_project_fields(
    spec: &codewire_project::ProjectSpec,
    has_local_mounts: bool,
) -> Vec<&'static str> {
    let mut unsupported = Vec::new();
    if !spec.preset.is_empty() {
        unsupported.push("preset");
    }
    if spec.repositories.is_empty() && !has_local_mounts && spec.working_directory != "/workspace" {
        unsupported.push("working_directory");
    }
    unsupported
}

/// The implicit source of a create that names no repositories and no path:
/// the kept-empty directory, and the path mode that copies it.
pub(crate) fn native_empty_workspace_source() -> anyhow::Result<(String, String)> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let workspace = empty_native_workspace(
        Some(&paths.mesh_data_dir.join(NATIVE_EMPTY_WORKSPACE)),
        None,
    )?;
    Ok((workspace.source_path, workspace.path_mode))
}
