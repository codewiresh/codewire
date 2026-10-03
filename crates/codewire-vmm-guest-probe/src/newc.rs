use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cw_runtime::CwRuntimeProvenance;
#[cfg(target_os = "linux")]
use crate::cw_runtime::{CW_RUNTIME_MAX_BYTES, CW_RUNTIME_MAX_PROVENANCE};
use thiserror::Error;

const HEADER_LEN: usize = 110;
const NEWC_MAGIC: &[u8; 6] = b"070701";
const INIT_NAME: &[u8] = b"init\0";
const TRAILER_NAME: &[u8] = b"TRAILER!!!\0";
const INIT_MODE: u32 = 0o100755;
const DIRECTORY_MODE: u32 = 0o040755;
const SYMLINK_MODE: u32 = 0o120777;
const NULL_DEVICE_MODE: u32 = 0o020666;
const ARCHIVE_BLOCK: usize = 512;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) const BASIC_BUSYBOX_APPLETS: &[&str] = &[
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
    append_boot_devices(&mut archive);
    append_entry(&mut archive, 3, INIT_MODE, INIT_NAME, probe, size, (0, 0));
    append_entry(&mut archive, 0, 0, TRAILER_NAME, &[], 0, (0, 0));
    pad_to(&mut archive, ARCHIVE_BLOCK);
    Ok(archive)
}

/// Build the first product-shaped guest root. `/init` remains the trusted
/// static Codewire PID 1/daemon binary. The sealed static runc binary is a
/// trusted guest control component. BusyBox supplies only the interactive
/// shell and bounded basic utilities, and the VM still boots with no
/// IP-capable device.
pub fn canonical_guest_root_newc(
    probe: &[u8],
    busybox: &[u8],
    runc: &[u8],
) -> Result<Vec<u8>, NewcError> {
    canonical_guest_root_newc_with_cw(probe, busybox, runc, None)
}

/// Image payload and externally pinned image provenance are one atomic asset.
/// The canonical archive fixes root ownership and workload-readable modes.
pub fn canonical_guest_root_newc_with_cw(
    probe: &[u8],
    busybox: &[u8],
    runc: &[u8],
    cw: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, NewcError> {
    let runtime = cw
        .map(|(binary, provenance)| {
            let identity = CwRuntimeProvenance::decode(provenance).map_err(NewcError::InvalidCw)?;
            identity
                .validate_payload(binary)
                .map_err(NewcError::InvalidCw)?;
            Ok::<_, NewcError>((binary, provenance, identity))
        })
        .transpose()?;
    let probe_size = u32::try_from(probe.len()).map_err(|_| NewcError::ProbeTooLarge)?;
    let busybox_size = u32::try_from(busybox.len()).map_err(|_| NewcError::BusyboxTooLarge)?;
    let runc_size = u32::try_from(runc.len()).map_err(|_| NewcError::RuncTooLarge)?;
    if probe.is_empty() {
        return Err(NewcError::EmptyProbe);
    }
    if busybox.is_empty() {
        return Err(NewcError::EmptyBusybox);
    }
    if runc.is_empty() {
        return Err(NewcError::EmptyRunc);
    }

    let mut archive = Vec::with_capacity(
        probe
            .len()
            .saturating_add(busybox.len())
            .saturating_add(runc.len())
            .saturating_add(
                runtime
                    .as_ref()
                    .map_or(0, |(binary, provenance, _)| binary.len() + provenance.len()),
            )
            .saturating_add(BASIC_BUSYBOX_APPLETS.len() * 160)
            .saturating_add(2048),
    );
    append_boot_devices(&mut archive);
    let mut inode = 3_u32;
    append_named_entry(&mut archive, inode, DIRECTORY_MODE, "bin", &[], 0);
    inode += 1;
    append_named_entry(&mut archive, inode, DIRECTORY_MODE, "sbin", &[], 0);
    inode += 1;
    append_named_entry(&mut archive, inode, DIRECTORY_MODE, "run", &[], 0);
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
    append_named_entry(&mut archive, inode, INIT_MODE, "sbin/runc", runc, runc_size);
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
    if let Some((binary, provenance, identity)) = runtime {
        for directory in [
            "codewire-cw".to_owned(),
            format!("codewire-cw/{}", identity.payload.sha256),
        ] {
            append_named_entry(&mut archive, inode, 0o040555, &directory, &[], 0);
            inode += 1;
        }
        append_named_entry(
            &mut archive,
            inode,
            0o100555,
            &identity.archive_entry(),
            binary,
            binary.len() as u32,
        );
        inode += 1;
        append_named_entry(
            &mut archive,
            inode,
            0o100444,
            "codewire-cw/provenance.json",
            provenance,
            provenance.len() as u32,
        );
    }
    append_entry(&mut archive, 0, 0, TRAILER_NAME, &[], 0, (0, 0));
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
    runc_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<(), NewcError> {
    let probe_path = probe_path.as_ref();
    let busybox_path = busybox_path.as_ref();
    let runc_path = runc_path.as_ref();
    let output_path = output_path.as_ref();
    let probe = read_regular_input(probe_path, GuestRootInput::Probe)?;
    let busybox = read_regular_input(busybox_path, GuestRootInput::Busybox)?;
    let runc = read_regular_input(runc_path, GuestRootInput::Runc)?;
    let archive = canonical_guest_root_newc(&probe, &busybox, &runc)?;
    write_atomic(output_path, &archive)
}

#[cfg(target_os = "linux")]
pub fn write_canonical_guest_root_initramfs_with_cw(
    probe_path: impl AsRef<Path>,
    busybox_path: impl AsRef<Path>,
    runc_path: impl AsRef<Path>,
    cw_path: impl AsRef<Path>,
    provenance_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<(), NewcError> {
    let probe = read_regular_input(probe_path.as_ref(), GuestRootInput::Probe)?;
    let busybox = read_regular_input(busybox_path.as_ref(), GuestRootInput::Busybox)?;
    let runc = read_regular_input(runc_path.as_ref(), GuestRootInput::Runc)?;
    let cw = read_bounded_cw_input(cw_path.as_ref(), CW_RUNTIME_MAX_BYTES)?;
    let provenance = read_bounded_cw_input(provenance_path.as_ref(), CW_RUNTIME_MAX_PROVENANCE)?;
    let archive =
        canonical_guest_root_newc_with_cw(&probe, &busybox, &runc, Some((&cw, &provenance)))?;
    write_atomic(output_path.as_ref(), &archive)
}

#[cfg(target_os = "linux")]
fn read_bounded_cw_input(path: &Path, limit: usize) -> Result<Vec<u8>, NewcError> {
    let read = || -> io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
            return Err(io::Error::other("cw input is not a bounded regular file"));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(io::Error::other("cw input changed size"));
        }
        Ok(bytes)
    };
    read().map_err(|source| NewcError::ReadCw {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Clone, Copy)]
enum GuestRootInput {
    Probe,
    Busybox,
    Runc,
}

fn read_regular_input(path: &Path, input: GuestRootInput) -> Result<Vec<u8>, NewcError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| match input {
        GuestRootInput::Probe => NewcError::ReadProbe {
            path: path.to_path_buf(),
            source,
        },
        GuestRootInput::Busybox => NewcError::ReadBusybox {
            path: path.to_path_buf(),
            source,
        },
        GuestRootInput::Runc => NewcError::ReadRunc {
            path: path.to_path_buf(),
            source,
        },
    })?;
    if !metadata.file_type().is_file() {
        return Err(match input {
            GuestRootInput::Probe => NewcError::ProbeNotRegular,
            GuestRootInput::Busybox => NewcError::BusyboxNotRegular,
            GuestRootInput::Runc => NewcError::RuncNotRegular,
        });
    }
    fs::read(path).map_err(|source| match input {
        GuestRootInput::Probe => NewcError::ReadProbe {
            path: path.to_path_buf(),
            source,
        },
        GuestRootInput::Busybox => NewcError::ReadBusybox {
            path: path.to_path_buf(),
            source,
        },
        GuestRootInput::Runc => NewcError::ReadRunc {
            path: path.to_path_buf(),
            source,
        },
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
        (0, 0),
    );
}

fn append_boot_devices(archive: &mut Vec<u8>) {
    // A console-free kernel can invoke /init with closed standard descriptors.
    // Rust repairs them through /dev/null before main, so mounting devtmpfs in
    // guest init is too late. This is a guest null device, not a host console.
    append_named_entry(archive, 1, DIRECTORY_MODE, "dev", &[], 0);
    append_entry(archive, 2, NULL_DEVICE_MODE, b"dev/null\0", &[], 0, (1, 3));
}

fn append_entry(
    archive: &mut Vec<u8>,
    inode: u32,
    mode: u32,
    name: &[u8],
    contents: &[u8],
    contents_len: u32,
    rdev: (u32, u32),
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
        rdev.0,
        rdev.1,
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
    #[error("invalid cw boot asset: {0}")]
    InvalidCw(&'static str),
    #[error("read cw boot asset {path}: {source}")]
    ReadCw { path: PathBuf, source: io::Error },
    #[error("initramfs probe is empty")]
    EmptyProbe,
    #[error("initramfs probe exceeds the newc size field")]
    ProbeTooLarge,
    #[error("initramfs BusyBox is empty")]
    EmptyBusybox,
    #[error("initramfs BusyBox exceeds the newc size field")]
    BusyboxTooLarge,
    #[error("initramfs runc is empty")]
    EmptyRunc,
    #[error("initramfs runc exceeds the newc size field")]
    RuncTooLarge,
    #[error("initramfs probe is not a regular file")]
    ProbeNotRegular,
    #[error("initramfs BusyBox is not a regular file")]
    BusyboxNotRegular,
    #[error("initramfs runc is not a regular file")]
    RuncNotRegular,
    #[error("read initramfs probe {path}: {source}")]
    ReadProbe { path: PathBuf, source: io::Error },
    #[error("read initramfs BusyBox {path}: {source}")]
    ReadBusybox { path: PathBuf, source: io::Error },
    #[error("read initramfs runc {path}: {source}")]
    ReadRunc { path: PathBuf, source: io::Error },
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
    fn canonical_archive_contains_boot_devices_init_and_trailer() {
        let archive = canonical_newc(b"probe-bytes").unwrap();
        let entries = parse_entries(&archive);
        assert_eq!(
            entries.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            [b"dev".as_slice(), b"dev/null", b"init", b"TRAILER!!!"]
        );
        assert_eq!(entries[2].1[1], 0o100755);
        assert_eq!(entries[2].2, b"probe-bytes");
        assert_eq!(archive.len() % ARCHIVE_BLOCK, 0);
        assert!(
            archive
                .windows(TRAILER_NAME.len())
                .any(|part| part == TRAILER_NAME)
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&archive)),
            "2dbb6be76671e71ba57f1e5031be82d26f5e7310ccf22339f5807e3a597d5e65"
        );
        assert_eq!(
            Sha256::digest(&archive),
            Sha256::digest(canonical_newc(b"probe-bytes").unwrap())
        );
    }

    fn parse_entries(archive: &[u8]) -> Vec<(&[u8], [u32; 13], &[u8])> {
        let mut entries = Vec::new();
        let mut offset = 0;
        loop {
            assert_eq!(&archive[offset..offset + 6], b"070701");
            let fields = std::array::from_fn(|index| {
                let start = offset + 6 + index * 8;
                u32::from_str_radix(std::str::from_utf8(&archive[start..start + 8]).unwrap(), 16)
                    .unwrap()
            });
            let name_start = offset + 110;
            let name_end = name_start + fields[11] as usize;
            assert_eq!(archive[name_end - 1], 0);
            let name = &archive[name_start..name_end - 1];
            let data_start = name_end.next_multiple_of(4);
            let data_end = data_start + fields[6] as usize;
            entries.push((name, fields, &archive[data_start..data_end]));
            offset = data_end.next_multiple_of(4);
            if name == b"TRAILER!!!" {
                assert!(archive[offset..].iter().all(|byte| *byte == 0));
                return entries;
            }
        }
    }

    #[test]
    fn every_archive_provides_only_the_exact_null_device_before_rust_init() {
        for archive in [
            canonical_newc(b"probe-bytes").unwrap(),
            canonical_guest_root_newc(b"probe-bytes", b"busybox-bytes", b"runc-bytes").unwrap(),
        ] {
            let entries = parse_entries(&archive);
            assert_eq!(entries[0].0, b"dev");
            assert_eq!(entries[0].1[1], 0o040755);
            assert_eq!(entries[0].1[2..4], [0, 0]);
            assert!(entries[0].2.is_empty());
            assert_eq!(entries[1].0, b"dev/null");
            assert_eq!(entries[1].1, [2, 0o020666, 0, 0, 1, 0, 0, 0, 0, 1, 3, 9, 0]);
            assert!(entries[1].2.is_empty());
            assert!(entries.iter().position(|entry| entry.0 == b"init").unwrap() > 1);
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| entry.0 == b"dev/null")
                    .count(),
                1
            );
            let devices = entries
                .iter()
                .filter(|entry| matches!(entry.1[1] & 0o170000, 0o020000 | 0o060000))
                .map(|entry| entry.0)
                .collect::<Vec<_>>();
            assert_eq!(devices, [b"dev/null".as_slice()]);
        }
    }

    #[test]
    fn previous_product_layout_is_bound_to_accepted_prior_bytes() {
        let current =
            canonical_guest_root_newc(b"probe-bytes\n", b"busybox-bytes\n", b"runc-bytes\n")
                .unwrap();
        let mut prior = Vec::new();
        // Serialize the prior format independently, omitting the two new
        // entries. The digest below was produced by the previous packer.
        for (name, mut fields, payload) in parse_entries(&current).into_iter().skip(2) {
            if fields[0] != 0 {
                fields[0] -= 2;
            }
            prior.extend_from_slice(b"070701");
            for field in fields {
                prior.extend_from_slice(format!("{field:08x}").as_bytes());
            }
            prior.extend_from_slice(name);
            prior.push(0);
            prior.resize(prior.len().next_multiple_of(4), 0);
            prior.extend_from_slice(payload);
            prior.resize(prior.len().next_multiple_of(4), 0);
        }
        prior.resize(prior.len().next_multiple_of(512), 0);
        assert_eq!(
            format!("{:x}", Sha256::digest(&prior)),
            "17d8f3e38f1bcfbfedf9f555a5a64dbdb6ab2aeed34785cdd5edf64d43aeaf34"
        );
        assert_ne!(current, prior);
    }

    #[test]
    fn product_archive_contains_real_shell_and_is_deterministic() {
        let archive =
            canonical_guest_root_newc(b"probe-bytes", b"busybox-bytes", b"runc-bytes").unwrap();
        for entry in [
            b"bin\0".as_slice(),
            b"sbin\0",
            b"init\0",
            b"bin/busybox\0",
            b"bin/sh\0",
            b"sbin/runc\0",
        ] {
            assert!(archive.windows(entry.len()).any(|window| window == entry));
        }
        assert!(
            archive
                .windows(b"busybox-bytes".len())
                .any(|window| window == b"busybox-bytes")
        );
        assert!(
            archive
                .windows(b"runc-bytes".len())
                .any(|window| window == b"runc-bytes")
        );
        assert_eq!(archive.len() % ARCHIVE_BLOCK, 0);
        assert_eq!(
            Sha256::digest(&archive),
            Sha256::digest(
                canonical_guest_root_newc(b"probe-bytes", b"busybox-bytes", b"runc-bytes").unwrap()
            )
        );
    }

    #[test]
    fn cw_image_asset_has_root_ownership_readable_system_modes_and_atomic_identity() {
        let (cw, provenance) = crate::cw_runtime::fixture();
        let archive = canonical_guest_root_newc_with_cw(
            b"probe",
            b"busybox",
            b"runc",
            Some((&cw, &provenance)),
        )
        .unwrap();
        let entries = parse_entries(&archive);
        let runtime = entries
            .iter()
            .filter(|entry| entry.0.starts_with(b"codewire-cw"))
            .collect::<Vec<_>>();
        assert_eq!(runtime.len(), 4);
        for (name, fields, payload) in runtime {
            assert_eq!(fields[2..4], [0, 0]);
            if name.ends_with(b"/cw") {
                assert_eq!(fields[1], 0o100555);
                assert_eq!(payload, &cw);
            } else if name.ends_with(b".json") {
                assert_eq!(fields[1], 0o100444);
                assert_eq!(payload, &provenance);
            } else {
                assert_eq!(fields[1], 0o040555);
            }
        }
        let mut substituted = cw.clone();
        substituted[135] = 1;
        assert!(
            canonical_guest_root_newc_with_cw(
                b"probe",
                b"busybox",
                b"runc",
                Some((&substituted, &provenance))
            )
            .is_err()
        );
        assert_ne!(
            archive,
            canonical_guest_root_newc(b"probe", b"busybox", b"runc").unwrap()
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
                temporary.path(),
                temporary.path().join("root.cpio")
            ),
            Err(NewcError::BusyboxNotRegular)
        ));
    }
}
