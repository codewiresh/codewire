//! Environment names for `ENV` and `--in` (journey `complete-environments`).

use std::ffi::OsStr;

use clap_complete::CompletionCandidate;

/// The local VMs' names, read from the supervisor's state database without
/// the supervisor (#4156): read-only, no wait, so a stopped VM is named, a
/// stopped or wedged supervisor costs nothing, and nothing starts or changes.
/// A development build refuses the user's own store (#4819), so it names none.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn local_names() -> Vec<String> {
    let Ok(paths) = crate::config::ResolvePaths::from_env(&crate::config::OsEnv) else {
        return Vec::new();
    };
    let Ok(root) = crate::commands::dev_store::state_root(&paths.mesh_data_dir) else {
        return Vec::new();
    };
    codewire_local_vmm::supervisor::read_environment_index(&root)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .map(|environment| environment.name)
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn local_names() -> Vec<String> {
    Vec::new()
}

pub(crate) fn environments(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(prefix) = current.to_str() else {
        return Vec::new();
    };
    // `--cloud`, before or after the command, selects the cloud's names alone.
    let cloud_only = super::words_before_cursor()
        .iter()
        .any(|word| word == "--cloud");
    if cloud_only {
        return Vec::new();
    }
    local_names()
        .into_iter()
        .filter(|name| name.starts_with(prefix))
        .map(|name| CompletionCandidate::new(name).help(Some("local".into())))
        .collect()
}
