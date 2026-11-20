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
    let words = super::words_before_cursor();
    let said = |flag: &str| words.iter().any(|word| word == flag);
    // `--local` and `--cloud`, before or after the command, narrow the names
    // to one placement; with neither, both are offered, a local one first.
    let mut candidates: Vec<CompletionCandidate> = Vec::new();
    let mut offer = |names: Vec<String>, placement: &'static str| {
        for name in names.into_iter().filter(|name| name.starts_with(prefix)) {
            if !candidates
                .iter()
                .any(|offered| offered.get_value() == OsStr::new(&name))
            {
                candidates.push(CompletionCandidate::new(name).help(Some(placement.into())));
            }
        }
    };
    if !said("--cloud") {
        offer(local_names(), "local");
    }
    if !said("--local") {
        offer(super::cloud::environment_names(), "cloud");
    }
    candidates
}
