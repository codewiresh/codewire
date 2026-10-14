pub(crate) mod confinement;
pub(crate) mod disk_tool;
pub mod path;
pub mod preflight;
pub mod process;
pub(crate) mod supervisor_peer;

pub use preflight::{
    HostProblem, PreflightError, PreflightReport, host_prerequisites, host_problem_report,
    preflight,
};
pub use process::{LiveProcess, ProcessIdentity, RecoveryError};

/// The distribution's e2fsprogs program, such as `mkfs.ext4`: the first of
/// `/usr/sbin` and `/usr/bin` that holds it, resolved to the real file that
/// cw then runs. Debian and Ubuntu install these tools in `/usr/sbin`; Arch
/// and Fedora link `/usr/sbin` to `/usr/bin`. Only these system directories
/// are searched, never `PATH`, and a tool is used only when only root can
/// change it.
pub(crate) fn e2fsprogs(program: &str) -> Option<std::path::PathBuf> {
    locate_e2fsprogs(program).ok()
}

/// Why [`e2fsprogs`] has no program for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum E2fsprogsProblem {
    Missing,
    /// The real file, or a directory above it, is not owned by root or is
    /// writable by its group or others.
    Untrusted(std::path::PathBuf),
}

pub(crate) fn locate_e2fsprogs(program: &str) -> Result<std::path::PathBuf, E2fsprogsProblem> {
    let found =
        e2fsprogs_in(&["/usr/sbin", "/usr/bin"], program).ok_or(E2fsprogsProblem::Missing)?;
    let real = std::fs::canonicalize(&found).map_err(|_| E2fsprogsProblem::Missing)?;
    if real.ancestors().all(|entry| {
        std::fs::symlink_metadata(entry).is_ok_and(|metadata| only_owner_writes(&metadata, 0))
    }) {
        Ok(real)
    } else {
        Err(E2fsprogsProblem::Untrusted(real))
    }
}

/// Whether `metadata` is owned by `owner` and not writable by its group or
/// others.
fn only_owner_writes(metadata: &std::fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.uid() == owner && metadata.mode() & 0o022 == 0
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

/// Every new ext4 disk's format, given to `mkfs.ext4` before any option of
/// its own, so the host's `/etc/mke2fs.conf` cannot change it: the filesystem
/// type (cw runs the real `mke2fs`, which otherwise takes it from its name),
/// exactly these features, and the block and inode geometry. It matches the
/// configuration the macOS runtime pins, so both hosts make the same disks.
pub(crate) const EXT4_FORMAT: [&str; 10] = [
    "-t",
    "ext4",
    "-O",
    "none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum",
    "-b",
    "4096",
    "-I",
    "256",
    "-i",
    "16384",
];

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

    #[test]
    fn a_tool_is_trusted_only_when_only_its_owner_can_change_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("e2fsck");
        std::fs::write(&tool, "").unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let trusted = |mode: u32, owner: u32| {
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(mode)).unwrap();
            super::only_owner_writes(&std::fs::symlink_metadata(&tool).unwrap(), owner)
        };
        assert!(trusted(0o755, owner));
        assert!(trusted(0o555, owner));
        assert!(!trusted(0o775, owner));
        assert!(!trusted(0o757, owner));
        assert!(!trusted(0o755, owner + 1));
    }

    #[test]
    fn the_host_e2fsprogs_resolve_to_root_owned_files() {
        for program in ["mkfs.ext4", "e2fsck", "resize2fs", "debugfs"] {
            let real = super::locate_e2fsprogs(program).unwrap();
            assert!(real.is_absolute(), "{program}: {}", real.display());
            assert_eq!(std::fs::canonicalize(&real).unwrap(), real);
        }
    }

    /// The explicit format wins over a host configuration that asks for other
    /// features and geometry.
    #[test]
    fn the_explicit_format_overrides_the_host_mke2fs_configuration() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("mke2fs.conf");
        std::fs::write(
            &config,
            "[defaults]\nbase_features = sparse_super,filetype,inline_data,orphan_file\nblocksize = 1024\ninode_size = 128\ninode_ratio = 4096\n[fs_types]\next4 = {\nfeatures = has_journal,encrypt,casefold,metadata_csum_seed,orphan_file\ninode_size = 128\n}\nsmall = {\nblocksize = 1024\ninode_ratio = 4096\n}\n",
        )
        .unwrap();
        let mkfs = super::locate_e2fsprogs("mkfs.ext4").unwrap();
        let format = |name: &str, extra: &[&str]| {
            let disk = root.path().join(name);
            std::fs::File::create(&disk)
                .unwrap()
                .set_len(64 << 20)
                .unwrap();
            let status = std::process::Command::new(&mkfs)
                .args(super::EXT4_FORMAT)
                .args(extra)
                .args(["-q", "-F"])
                .arg(&disk)
                .env_clear()
                .env("LC_ALL", "C")
                .env("MKE2FS_CONFIG", &config)
                .status()
                .unwrap();
            assert!(status.success());
            let image = std::fs::read(&disk).unwrap();
            let word = |offset: usize| {
                u32::from_le_bytes(image[1024 + offset..1024 + offset + 4].try_into().unwrap())
            };
            let inode_size =
                u16::from_le_bytes(image[1024 + 0x58..1024 + 0x5a].try_into().unwrap());
            // compat, incompat and ro_compat; log2(block size) - 10; inode
            // size; bytes per inode.
            (
                (word(0x5c), word(0x60), word(0x64)),
                word(0x18),
                inode_size,
                u64::from(word(0x04)) * (1024 << word(0x18)) / u64::from(word(0x00)),
            )
        };
        // The macOS runtime's pinned words (scripts/dev/macos-ext4-tool.py).
        assert_eq!(
            format("root.raw", &[]),
            ((0x3c, 0x2c2, 0x46b), 2, 256, 16384)
        );
        // A call site's own options still apply after the format.
        assert_eq!(
            format("catalog.raw", &["-O", "^has_journal"]).0,
            (0x38, 0x2c2, 0x46b)
        );
    }
}
