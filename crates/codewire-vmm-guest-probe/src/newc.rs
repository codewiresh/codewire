use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

const HEADER_LEN: usize = 110;
const NEWC_MAGIC: &[u8; 6] = b"070701";
const INIT_NAME: &[u8] = b"init\0";
const TRAILER_NAME: &[u8] = b"TRAILER!!!\0";
const INIT_MODE: u32 = 0o100755;
const DIRECTORY_MODE: u32 = 0o040755;
const SYMLINK_MODE: u32 = 0o120777;
const ARCHIVE_BLOCK: usize = 512;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const BASIC_BUSYBOX_APPLETS: &[&str] = &[
    "[",
    "awk",
    "basename",
    "cat",
    "chmod",
    "cp",
    "cut",
    "date",
    "dd",
    "dirname",
    "echo",
    "env",
    "expr",
    "false",
    "find",
    "grep",
    "head",
    "hostname",
    "id",
    "kill",
    "ln",
    "ls",
    "mkdir",
    "mktemp",
    "mv",
    "nproc",
    "printf",
    "ps",
    "pwd",
    "readlink",
    "rm",
    "rmdir",
    "sed",
    "sha256sum",
    "sh",
    "sleep",
    "sort",
    "stat",
    "stty",
    "sync",
    "tail",
    "tee",
    "test",
    "touch",
    "tr",
    "true",
    "tty",
    "uname",
    "wc",
    "which",
    "xargs",
];

pub fn canonical_newc(probe: &[u8]) -> Result<Vec<u8>, NewcError> {
    let size = u32::try_from(probe.len()).map_err(|_| NewcError::ProbeTooLarge)?;
    if probe.is_empty() {
        return Err(NewcError::EmptyProbe);
    }

    let mut archive = Vec::with_capacity(
        HEADER_LEN + INIT_NAME.len() + probe.len() + HEADER_LEN + TRAILER_NAME.len() + 512,
    );
    append_entry(&mut archive, 1, INIT_MODE, INIT_NAME, probe, size);
    append_entry(&mut archive, 0, 0, TRAILER_NAME, &[], 0);
    pad_to(&mut archive, ARCHIVE_BLOCK);
    Ok(archive)
}

/// Build the first product-shaped guest root. `/init` remains the trusted
/// static Codewire PID 1/daemon binary. BusyBox supplies only the interactive
/// shell and bounded basic utilities; it is not part of the host trust
/// boundary and the VM still boots with no IP-capable device.
pub fn canonical_guest_root_newc(probe: &[u8], busybox: &[u8]) -> Result<Vec<u8>, NewcError> {
    let probe_size = u32::try_from(probe.len()).map_err(|_| NewcError::ProbeTooLarge)?;
    let busybox_size = u32::try_from(busybox.len()).map_err(|_| NewcError::BusyboxTooLarge)?;
    if probe.is_empty() {
        return Err(NewcError::EmptyProbe);
    }
    if busybox.is_empty() {
        return Err(NewcError::EmptyBusybox);
    }

    let mut archive = Vec::with_capacity(
        probe
            .len()
            .saturating_add(busybox.len())
            .saturating_add(BASIC_BUSYBOX_APPLETS.len() * 160)
            .saturating_add(2048),
    );
    let mut inode = 1_u32;
    append_named_entry(&mut archive, inode, DIRECTORY_MODE, "bin", &[], 0);
    inode += 1;
    append_named_entry(&mut archive, inode, INIT_MODE, "init", probe, probe_size);
    inode += 1;
    append_named_entry(
        &mut archive,
        inode,
        INIT_MODE,
        "bin/busybox",
        busybox,
        busybox_size,
    );
    inode += 1;
    for applet in BASIC_BUSYBOX_APPLETS {
        append_named_entry(
            &mut archive,
            inode,
            SYMLINK_MODE,
            &format!("bin/{applet}"),
            b"busybox",
            7,
        );
        inode += 1;
    }
    append_entry(&mut archive, 0, 0, TRAILER_NAME, &[], 0);
    pad_to(&mut archive, ARCHIVE_BLOCK);
    Ok(archive)
}

pub fn write_canonical_initramfs(
    probe_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<(), NewcError> {
    let probe_path = probe_path.as_ref();
    let output_path = output_path.as_ref();
    let metadata = fs::symlink_metadata(probe_path).map_err(|source| NewcError::ReadProbe {
        path: probe_path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(NewcError::ProbeNotRegular);
    }
    let probe = fs::read(probe_path).map_err(|source| NewcError::ReadProbe {
        path: probe_path.to_path_buf(),
        source,
    })?;
    let archive = canonical_newc(&probe)?;
    write_atomic(output_path, &archive)
}

pub fn write_canonical_guest_root_initramfs(
    probe_path: impl AsRef<Path>,
    busybox_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<(), NewcError> {
    let probe_path = probe_path.as_ref();
    let busybox_path = busybox_path.as_ref();
    let output_path = output_path.as_ref();
    let probe = read_regular_input(probe_path, false)?;
    let busybox = read_regular_input(busybox_path, true)?;
    let archive = canonical_guest_root_newc(&probe, &busybox)?;
    write_atomic(output_path, &archive)
}

fn read_regular_input(path: &Path, busybox: bool) -> Result<Vec<u8>, NewcError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if busybox {
            NewcError::ReadBusybox {
                path: path.to_path_buf(),
                source,
            }
        } else {
            NewcError::ReadProbe {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(if busybox {
            NewcError::BusyboxNotRegular
        } else {
            NewcError::ProbeNotRegular
        });
    }
    fs::read(path).map_err(|source| {
        if busybox {
            NewcError::ReadBusybox {
                path: path.to_path_buf(),
                source,
            }
        } else {
            NewcError::ReadProbe {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn append_named_entry(
    archive: &mut Vec<u8>,
    inode: u32,
    mode: u32,
    name: &str,
    contents: &[u8],
    contents_len: u32,
) {
    let mut nul_terminated = Vec::with_capacity(name.len() + 1);
    nul_terminated.extend_from_slice(name.as_bytes());
    nul_terminated.push(0);
    append_entry(
        archive,
        inode,
        mode,
        &nul_terminated,
        contents,
        contents_len,
    );
}

fn append_entry(
    archive: &mut Vec<u8>,
    inode: u32,
    mode: u32,
    name: &[u8],
    contents: &[u8],
    contents_len: u32,
) {
    let header_start = archive.len();
    archive.extend_from_slice(NEWC_MAGIC);
    for value in [
        inode,
        mode,
        0, // uid
        0, // gid
        1, // nlink
        0, // mtime
        contents_len,
        0, // dev major
        0, // dev minor
        0, // rdev major
        0, // rdev minor
        name.len() as u32,
        0, // checksum (newc, rather than crc)
    ] {
        write_hex_u32(archive, value);
    }
    debug_assert_eq!(archive.len() - header_start, HEADER_LEN);
    archive.extend_from_slice(name);
    pad_to(archive, 4);
    archive.extend_from_slice(contents);
    pad_to(archive, 4);
}

fn write_hex_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn pad_to(output: &mut Vec<u8>, alignment: usize) {
    let padding = (alignment - output.len() % alignment) % alignment;
    output.resize(output.len() + padding, 0);
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), NewcError> {
    if !path.is_absolute() {
        return Err(NewcError::OutputMustBeAbsolute);
    }
    let parent = path.parent().ok_or(NewcError::OutputMustHaveParent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(NewcError::InvalidOutputName)?;
    let mut last_collision = None;

    for _ in 0..16 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            sequence
        ));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            }
            Err(source) => {
                return Err(NewcError::WriteOutput {
                    path: temporary,
                    source,
                });
            }
        };

        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(parent)?.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&temporary);
            return Err(NewcError::WriteOutput {
                path: path.to_path_buf(),
                source,
            });
        }
        return Ok(());
    }

    Err(NewcError::WriteOutput {
        path: path.to_path_buf(),
        source: last_collision.unwrap_or_else(|| io::Error::other("temporary-name collision")),
    })
}

#[derive(Debug, Error)]
pub enum NewcError {
    #[error("initramfs probe is empty")]
    EmptyProbe,
    #[error("initramfs probe exceeds the newc size field")]
    ProbeTooLarge,
    #[error("initramfs BusyBox is empty")]
    EmptyBusybox,
    #[error("initramfs BusyBox exceeds the newc size field")]
    BusyboxTooLarge,
    #[error("initramfs probe is not a regular file")]
    ProbeNotRegular,
    #[error("initramfs BusyBox is not a regular file")]
    BusyboxNotRegular,
    #[error("read initramfs probe {path}: {source}")]
    ReadProbe { path: PathBuf, source: io::Error },
    #[error("read initramfs BusyBox {path}: {source}")]
    ReadBusybox { path: PathBuf, source: io::Error },
    #[error("initramfs output path must be absolute")]
    OutputMustBeAbsolute,
    #[error("initramfs output path must have a parent")]
    OutputMustHaveParent,
    #[error("initramfs output filename is invalid")]
    InvalidOutputName,
    #[error("write initramfs output {path}: {source}")]
    WriteOutput { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    #[test]
    fn canonical_archive_contains_only_executable_init_and_trailer() {
        let archive = canonical_newc(b"probe-bytes").unwrap();

        assert_eq!(&archive[..6], NEWC_MAGIC);
        assert_eq!(&archive[14..22], b"000081ed");
        assert_eq!(&archive[94..102], b"00000005");
        assert_eq!(
            &archive[HEADER_LEN..HEADER_LEN + INIT_NAME.len()],
            INIT_NAME
        );
        assert_eq!(archive.len() % ARCHIVE_BLOCK, 0);
        assert!(
            archive
                .windows(TRAILER_NAME.len())
                .any(|part| part == TRAILER_NAME)
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&archive)),
            "7d170ccd99684aa54b9deb05c5591e8418427b710d8c22a14af26bd3af0b9898"
        );
        assert_eq!(
            Sha256::digest(&archive),
            Sha256::digest(canonical_newc(b"probe-bytes").unwrap())
        );
    }

    #[test]
    fn product_archive_contains_real_shell_and_is_deterministic() {
        let archive = canonical_guest_root_newc(b"probe-bytes", b"busybox-bytes").unwrap();
        for entry in [
            b"bin\0".as_slice(),
            b"init\0",
            b"bin/busybox\0",
            b"bin/sh\0",
        ] {
            assert!(archive.windows(entry.len()).any(|window| window == entry));
        }
        assert!(
            archive
                .windows(b"busybox-bytes".len())
                .any(|window| window == b"busybox-bytes")
        );
        assert_eq!(archive.len() % ARCHIVE_BLOCK, 0);
        assert_eq!(
            Sha256::digest(&archive),
            Sha256::digest(canonical_guest_root_newc(b"probe-bytes", b"busybox-bytes").unwrap())
        );
    }

    #[test]
    fn atomic_writer_is_deterministic_and_sets_public_read_mode() {
        let temporary = TempDir::new().unwrap();
        let probe_path = temporary.path().join("probe");
        let output_path = temporary.path().join("initramfs.cpio");
        fs::write(&probe_path, b"same input").unwrap();

        write_canonical_initramfs(&probe_path, &output_path).unwrap();
        let first = fs::read(&output_path).unwrap();
        write_canonical_initramfs(&probe_path, &output_path).unwrap();
        let second = fs::read(&output_path).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!fs::read_dir(temporary.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")
        }));
    }

    #[test]
    fn writer_rejects_relative_output_and_non_regular_probe() {
        let temporary = TempDir::new().unwrap();
        assert!(matches!(
            write_canonical_initramfs(temporary.path(), temporary.path().join("out")),
            Err(NewcError::ProbeNotRegular)
        ));
        let probe = temporary.path().join("probe");
        fs::write(&probe, b"probe").unwrap();
        assert!(matches!(
            write_canonical_initramfs(&probe, Path::new("relative.cpio")),
            Err(NewcError::OutputMustBeAbsolute)
        ));
        assert!(matches!(
            write_canonical_guest_root_initramfs(
                &probe,
                temporary.path(),
                temporary.path().join("root.cpio")
            ),
            Err(NewcError::BusyboxNotRegular)
        ));
    }
}
