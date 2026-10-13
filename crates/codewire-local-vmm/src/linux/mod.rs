pub(crate) mod confinement;
pub mod path;
pub mod preflight;
pub mod process;
pub(crate) mod supervisor_peer;

pub use preflight::{PreflightError, PreflightReport, preflight};
pub use process::{LiveProcess, ProcessIdentity, RecoveryError};

/// The distribution's e2fsprogs program, such as `mkfs.ext4`: the first of
/// `/usr/sbin` and `/usr/bin` that holds it. Debian and Ubuntu install these
/// tools in `/usr/sbin`; Arch and Fedora link `/usr/sbin` to `/usr/bin`. Only
/// these root-owned system directories are searched, never `PATH`.
pub(crate) fn e2fsprogs(program: &str) -> Option<std::path::PathBuf> {
    e2fsprogs_in(&["/usr/sbin", "/usr/bin"], program)
}

fn e2fsprogs_in(directories: &[&str], program: &str) -> Option<std::path::PathBuf> {
    if !matches!(program, "mkfs.ext4" | "e2fsck" | "resize2fs" | "debugfs") {
        return None;
    }
    directories
        .iter()
        .map(|directory| std::path::Path::new(directory).join(program))
        .find(|path| path.is_file())
}

/// The system git; Linux hosts provide it.
pub(crate) fn git() -> Option<crate::host_git::HostGit> {
    Some(crate::host_git::HostGit {
        program: "/usr/bin/git".into(),
        environment: Vec::new(),
        exec_path: None,
    })
}

#[cfg(test)]
mod e2fsprogs_tests {
    use std::os::unix::fs::symlink;

    #[test]
    fn e2fsprogs_prefers_sbin_then_bin_and_only_names_its_tools() {
        let root = tempfile::tempdir().unwrap();
        let sbin = root.path().join("sbin");
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&sbin).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let (sbin_dir, bin_dir) = (sbin.to_str().unwrap(), bin.to_str().unwrap());
        // Debian and Ubuntu: e2fsck only in sbin; mkfs.ext4 a link to mke2fs.
        std::fs::write(sbin.join("e2fsck"), "").unwrap();
        std::fs::write(sbin.join("mke2fs"), "").unwrap();
        symlink("mke2fs", sbin.join("mkfs.ext4")).unwrap();
        // Arch and Fedora: everything in bin.
        std::fs::write(bin.join("resize2fs"), "").unwrap();
        std::fs::write(bin.join("e2fsck"), "").unwrap();
        let dirs = [sbin_dir, bin_dir];
        assert_eq!(
            super::e2fsprogs_in(&dirs, "e2fsck"),
            Some(sbin.join("e2fsck"))
        );
        assert_eq!(
            super::e2fsprogs_in(&dirs, "mkfs.ext4"),
            Some(sbin.join("mkfs.ext4"))
        );
        assert_eq!(
            super::e2fsprogs_in(&dirs, "resize2fs"),
            Some(bin.join("resize2fs"))
        );
        assert_eq!(super::e2fsprogs_in(&dirs, "debugfs"), None);
        std::fs::write(bin.join("sh"), "").unwrap();
        assert_eq!(super::e2fsprogs_in(&dirs, "sh"), None);
        // A directory of that name is not a program.
        std::fs::create_dir(bin.join("debugfs")).unwrap();
        assert_eq!(super::e2fsprogs_in(&dirs, "debugfs"), None);
    }
}
