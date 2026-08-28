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
const ARCHIVE_BLOCK: usize = 512;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    #[error("initramfs probe is not a regular file")]
    ProbeNotRegular,
    #[error("read initramfs probe {path}: {source}")]
    ReadProbe { path: PathBuf, source: io::Error },
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
    }
}
