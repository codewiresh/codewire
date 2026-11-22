//! Spotlight types a local VM's `.raw` disk images as camera RAW and its image
//! importer reads them in any folder it indexes, so on a Mac `cw` warns when
//! the state root sits where Spotlight looks (#5831, until #5830 renames the
//! disks). Spotlight skips a dot folder and a folder whose name ends in
//! `.noindex`; the default root, under `~/.codewire`, is one.

use std::path::{Component, Path};

/// The warning for a state root Spotlight may index, or `None` when a folder
/// in its path is one Spotlight skips. It goes by the path alone.
pub(super) fn indexed_state_root_warning(root: &Path) -> Option<String> {
    let skipped = root.components().any(|component| match component {
        Component::Normal(name) => {
            let name = name.to_string_lossy();
            name.starts_with('.') || name.ends_with(".noindex")
        }
        _ => false,
    });
    (!skipped).then(|| {
        format!(
            "Warning: Spotlight may index {}, where its image importer would read your local VMs' disks; keep the state root in a folder whose name ends in .noindex, or in the default ~/.codewire.",
            root.display()
        )
    })
}

/// This `cw`'s local VM state root's warning, printed once to stderr so that
/// `-o json` output stays only the JSON. A root that does not resolve gets no
/// warning here; the command that needs it reports why.
#[cfg_attr(test, allow(dead_code))]
pub(super) fn warn_when_indexed() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = crate::config::ResolvePaths::from_env(&crate::config::OsEnv)
            .ok()
            .and_then(|paths| super::super::dev_store::state_root(&paths.mesh_data_dir).ok());
        if let Some(warning) = root.and_then(|root| indexed_state_root_warning(&root)) {
            eprintln!("{warning}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dot_or_noindex_folder_anywhere_in_the_path_keeps_spotlight_out() {
        for skipped in [
            "/Users/a/.codewire/native-v1",
            "/Users/a/.cache/cw/native-v1",
            "/Users/a/vms.noindex/native-v1",
            "/Volumes/Work/vms.noindex/deep/native-v1",
            "/Users/a/vms/.state",
        ] {
            assert_eq!(
                indexed_state_root_warning(Path::new(skipped)),
                None,
                "{skipped}"
            );
        }
    }

    #[test]
    fn a_visible_root_is_warned_about_and_named() {
        for indexed in [
            "/Users/a/cw-visible/native-v1",
            "/Users/a/Library/Application Support/cw/native-v1",
            "/Volumes/Work/native-v1",
            "/Users/a/noindex/native-v1",
            "/Users/a/vms.noindex.old/native-v1",
        ] {
            let warning = indexed_state_root_warning(Path::new(indexed))
                .unwrap_or_else(|| panic!("{indexed} should be warned about"));
            assert!(warning.contains(indexed), "{warning}");
            assert!(warning.contains(".noindex"), "{warning}");
        }
    }
}
