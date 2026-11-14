use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::PermissionsExt as _;

use super::*;

const MIB: u64 = 1024 * 1024;

fn sparse_source(path: &Path) -> File {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.set_len(64 * MIB).unwrap();
    for (offset, byte) in [(0, b'a'), (20 * MIB, b'b'), (63 * MIB, b'c')] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&vec![byte; MIB as usize]).unwrap();
    }
    file.sync_all().unwrap();
    file
}

fn new_file(path: &Path) -> File {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn contents(mut file: &File) -> Vec<u8> {
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn a_sparse_copy_keeps_the_bytes_and_the_holes() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let destination = new_file(&directory.path().join("destination"));

    sparse_copy(&source, &destination).unwrap();

    assert_eq!(destination.metadata().unwrap().len(), 64 * MIB);
    assert_eq!(contents(&source), contents(&destination));
    // Three mebibytes of data; the 61 MiB between them stay holes.
    assert!(allocated_bytes(&destination).unwrap() < 8 * MIB);
}

#[test]
fn a_copy_falls_back_when_the_filesystem_cannot_share_extents() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let mut reserved = None;

    let (destination, mode) =
        clone_or_copy(&source, &directory.path().join("destination"), |bytes| {
            reserved = Some(bytes);
            Ok(())
        })
        .unwrap();

    assert_eq!(contents(&source), contents(&destination));
    assert_eq!(
        destination.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    match mode {
        // A filesystem that shares extents reserves nothing.
        CloneMode::Reflink => assert_eq!(reserved, None),
        CloneMode::Copy => assert!(reserved.is_some_and(|bytes| bytes >= 3 * MIB)),
    }
}

#[test]
fn a_copy_between_filesystems_is_sparse_and_checks_space_first() {
    // tmpfs never shares extents with the test directory's filesystem.
    let Ok(shared_memory) = tempfile::tempdir_in("/dev/shm") else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let destination_path = shared_memory.path().join("destination");

    let refused = clone_or_copy(&source, &destination_path, |bytes| {
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!("{bytes} bytes needed"),
        ))
    })
    .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::StorageFull);
    assert!(!destination_path.exists(), "a refused copy leaves nothing");

    let (destination, mode) = clone_or_copy(&source, &destination_path, |_| Ok(())).unwrap();
    assert_eq!(mode, CloneMode::Copy);
    assert_eq!(contents(&source), contents(&destination));
}

#[test]
fn a_clone_shares_its_blocks_where_the_filesystem_allows_it() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let Ok(destination) = clone_new(&source, &directory.path().join("destination")) else {
        assert!(
            !directory.path().join("destination").exists(),
            "a failed clone leaves nothing"
        );
        return;
    };
    assert_eq!(contents(&source), contents(&destination));
    assert_eq!(
        destination.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    if let Some(shared) = shared_bytes(&destination) {
        assert!(shared >= 3 * MIB);
    }
    let destination_path = directory.path().join("destination");
    OpenOptions::new()
        .write(true)
        .open(&destination_path)
        .unwrap()
        .write_all_at(b"changed", 0)
        .unwrap();
    assert_eq!(contents(&source)[..7], [b'a'; 7]);
}

/// A Mac's temporary directory is on APFS, which always clones, so this
/// one may not skip.
#[cfg(target_os = "macos")]
#[test]
fn a_mac_clones_on_apfs_and_reserves_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let (destination, mode) = clone_or_copy(&source, &directory.path().join("destination"), |_| {
        panic!("an APFS clone reserves nothing")
    })
    .unwrap();
    assert_eq!(mode, CloneMode::Reflink);
    assert_eq!(contents(&source), contents(&destination));
    assert!(reflink_works(directory.path()).unwrap());
}

#[test]
fn the_reflink_probe_agrees_with_a_clone_and_leaves_nothing_behind() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let works = clone_new(&source, &directory.path().join("destination")).is_ok();
    let probe = tempfile::tempdir().unwrap();
    assert_eq!(reflink_works(probe.path()).unwrap(), works);
    assert_eq!(std::fs::read_dir(probe.path()).unwrap().count(), 0);
}

const REFUSED_WRITE_CHILD: &str = "CODEWIRE_FS_CLONE_REFUSED_WRITE_CHILD";

/// Run in a child whose file-size limit is 8 MiB: the kernel refuses the
/// copy's write past it (EFBIG), as a full disk refuses one (ENOSPC).
#[test]
fn refused_write_child() {
    let Some(directory) = std::env::var_os(REFUSED_WRITE_CHILD) else {
        return;
    };
    let directory = Path::new(&directory);
    let source = File::open(directory.join("source")).unwrap();
    let error = clone_or_copy(&source, &directory.join("destination"), |_| Ok(())).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EFBIG), "{error}");
}

#[test]
fn a_write_the_filesystem_refuses_mid_copy_fails_the_copy() {
    use std::os::unix::process::CommandExt as _;

    let Ok(shared_memory) = tempfile::tempdir_in("/dev/shm") else {
        return;
    };
    // The source lives on another filesystem, so the copy is sparse; its
    // second data range lies past the limit.
    let directory = tempfile::tempdir().unwrap();
    sparse_source(&directory.path().join("source"));
    std::os::unix::fs::symlink(
        directory.path().join("source"),
        shared_memory.path().join("source"),
    )
    .unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "fs_clone::tests::refused_write_child",
            "--nocapture",
        ])
        .env(REFUSED_WRITE_CHILD, shared_memory.path())
        .stdin(std::process::Stdio::null());
    // SAFETY: only async-signal-safe calls run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 8 * MIB,
                rlim_max: 8 * MIB,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
                || libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().unwrap();
    assert!(status.success(), "{status}");
}

#[test]
fn an_existing_destination_is_refused_and_kept() {
    let directory = tempfile::tempdir().unwrap();
    let source = sparse_source(&directory.path().join("source"));
    let mut existing = new_file(&directory.path().join("destination"));
    existing.write_all(b"existing").unwrap();
    let error =
        clone_or_copy(&source, &directory.path().join("destination"), |_| Ok(())).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(contents(&existing), b"existing");
    let error = clone_new(&source, &directory.path().join("destination")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
}
