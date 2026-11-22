//! The state root's `engine/` directory, which holds each local VM's tree
//! under `vms/`. On a Mac that tree carries Time Machine's backup exclusion,
//! as `tmutil addexclusion` writes it, so a VM's disks and the sign-ins
//! delivered onto its state disk never reach a backup (#5900). The supervisor
//! sets it at every start: a new root has it before its first VM, and a root
//! from before #5900 has it from its next start.

use std::path::Path;

use crate::host::path::PrivateRoot;
use crate::supervisor::SupervisorError;

/// Ensure `engine/` under the supervisor's root, and on a Mac its `vms/`
/// tree, kept out of Time Machine.
pub(crate) fn prepare(root: &PrivateRoot) -> Result<(), SupervisorError> {
    let engine = root.ensure_dir(Path::new("engine"), 0o700)?;
    #[cfg(target_os = "macos")]
    {
        let vms = PrivateRoot::open(&engine)?.ensure_dir(Path::new("vms"), 0o700)?;
        crate::darwin::memory_store::exclude_from_backup(&vms)
            .map_err(|source| SupervisorError::Io { path: vms, source })?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = engine;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::darwin::memory_store::excluded_from_backup;
    use std::os::unix::fs::PermissionsExt as _;

    fn private_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn a_new_root_and_an_older_one_keep_their_vms_out_of_time_machine() {
        let new = private_tempdir();
        let root = PrivateRoot::create(&new.path().join("native-v1")).unwrap();
        prepare(&root).unwrap();
        let vms = root.path().join("engine").join("vms");
        assert!(excluded_from_backup(&vms).unwrap());
        prepare(&root).unwrap();
        assert!(excluded_from_backup(&vms).unwrap());

        // A root from before #5900: its VM tree exists, without the attribute.
        let older = private_tempdir();
        let root = PrivateRoot::create(&older.path().join("native-v1")).unwrap();
        let engine =
            PrivateRoot::open(&root.ensure_dir(Path::new("engine"), 0o700).unwrap()).unwrap();
        let vms = engine.ensure_dir(Path::new("vms"), 0o700).unwrap();
        PrivateRoot::open(&vms)
            .unwrap()
            .ensure_dir(Path::new("0b7a9f3e-5c7d-4b6a-9e2f-1d3c5b7a9e2f"), 0o700)
            .unwrap();
        assert!(!excluded_from_backup(&vms).unwrap());
        prepare(&root).unwrap();
        assert!(excluded_from_backup(&vms).unwrap());
    }
}
