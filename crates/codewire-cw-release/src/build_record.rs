//! Bounded build-record decoding and admission of an already-held executable.
//!
//! A caller supplies its trusted compile-time marker. This module never embeds
//! that marker, opens a diagnostic path, executes bytes, fetches a release or
//! changes a version store. Incoming releases require the complete signed
//! identity; development self-identification also admits matching GNU targets.

use std::fs::{File, Metadata};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use crate::sha256::Sha256;
use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::identity::{
    Arch, CwPayloadIdentity, EXECUTABLE_HEADER_BYTES, MAX_EXECUTABLE_BYTES, Os,
    PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION, Platform, RECORD_VERSION, canonical_json,
    is_sha256_hex, valid_package_version,
};

fn validate_marker(marker: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        (8..=128).contains(&marker.len()),
        "build record marker exceeds its bound"
    );
    Ok(())
}

const MAX_RECORD_JSON: usize = 1024;
const MAX_TARGET: usize = 64;
const MAX_RUSTC: usize = 128;
const SCAN_CHUNK: usize = 1024 * 1024;

/// A decoded build record. The source fields are absent only for a build
/// that was not given explicit provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecord {
    pub package_version: String,
    pub rustc: String,
    pub source_revision: Option<String>,
    pub source_tree_sha256: Option<String>,
    pub target: String,
}

impl BuildRecord {
    /// Decode a complete frame beginning with the trusted caller's marker,
    /// followed by a little-endian length and canonical JSON. Unknown, missing,
    /// duplicate and non-canonical fields are refused.
    pub fn decode(record: &[u8], marker: &[u8]) -> anyhow::Result<Self> {
        validate_marker(marker)?;
        let json_start = marker.len() + 4;
        anyhow::ensure!(
            record.len() <= json_start + MAX_RECORD_JSON && record.starts_with(marker),
            "the build record marker or frame bound is invalid"
        );
        let length = json_start
            .checked_sub(4)
            .and_then(|start| record.get(start..json_start))
            .context("the build record has no length")?;
        let length = u32::from_le_bytes(length.try_into().expect("four bytes")) as usize;
        let json = record
            .get(json_start..)
            .filter(|json| json.len() == length && length <= MAX_RECORD_JSON)
            .context("the build record length is inconsistent")?;
        let decoded: Self =
            serde_json::from_slice(json).context("the build record is malformed")?;
        decoded.validate()?;
        anyhow::ensure!(
            canonical_json(&decoded)? == json,
            "the build record is not canonical"
        );
        Ok(decoded)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            valid_package_version(&self.package_version),
            "the build record version is invalid"
        );
        anyhow::ensure!(
            !self.target.is_empty()
                && self.target.len() <= MAX_TARGET
                && self
                    .target
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
            "the build record target is invalid"
        );
        anyhow::ensure!(
            self.rustc.starts_with("rustc ")
                && self.rustc.len() <= MAX_RUSTC
                && self.rustc.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "the build record compiler is invalid"
        );
        match (&self.source_revision, &self.source_tree_sha256) {
            (Some(revision), Some(tree)) => anyhow::ensure!(
                revision.len() == 40
                    && revision
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                    && is_sha256_hex(tree),
                "the build record source provenance is invalid"
            ),
            (None, None) => {}
            _ => anyhow::bail!("the build record has partial source provenance"),
        }
        Ok(())
    }

    /// Canonical bounded frame using a trusted caller-owned marker.
    pub fn frame(&self, marker: &[u8]) -> anyhow::Result<Vec<u8>> {
        validate_marker(marker)?;
        self.validate()?;
        let json = canonical_json(self)?;
        anyhow::ensure!(
            json.len() <= MAX_RECORD_JSON,
            "incoming build record exceeds its bound"
        );
        let mut frame = Vec::with_capacity(marker.len() + 4 + json.len());
        frame.extend_from_slice(marker);
        frame.extend_from_slice(&(json.len() as u32).to_le_bytes());
        frame.extend_from_slice(&json);
        Ok(frame)
    }
}

/// Complete identity of the already-held executable. `path` is diagnostic
/// only; the framed record is decoded and bound to these exact bytes.
/// Refuses a build without source provenance, a target for another
/// platform, and bytes that do not hold `record` and its marker exactly once.
pub fn identify(
    file: &mut File,
    path: &Path,
    framed: &[u8],
    marker: &[u8],
    host: Platform,
) -> anyhow::Result<CwPayloadIdentity> {
    let record = BuildRecord::decode(framed, marker)?;
    let (Some(source_revision), Some(source_tree_sha256)) =
        (&record.source_revision, &record.source_tree_sha256)
    else {
        anyhow::bail!(
            "this cw was built without source provenance, so it has no complete identity; \
             build and install it with `make cli-install` from an authorized source checkout"
        );
    };
    anyhow::ensure!(
        target_platform(&record.target) == Some(host),
        "this cw was built for {}, which is not a supported {} target",
        record.target,
        host.as_str()
    );
    let scan = scan_file(file, path, framed, marker)?;
    host.validate_executable_header(&scan.header)?;
    anyhow::ensure!(
        scan.records == 1,
        "{} holds {} copies of this cw's build record, not exactly one",
        path.display(),
        scan.records
    );
    anyhow::ensure!(
        scan.markers == 1,
        "{} holds {} cw build record markers, not exactly one",
        path.display(),
        scan.markers
    );
    let identity = CwPayloadIdentity {
        schema_version: PAYLOAD_SCHEMA_VERSION,
        protocol_version: PROTOCOL_VERSION,
        record_version: RECORD_VERSION,
        package_version: record.package_version.clone(),
        target: record.target.clone(),
        source_revision: source_revision.clone(),
        source_tree_sha256: source_tree_sha256.clone(),
        rustc: record.rustc.clone(),
        sha256: scan.sha256,
        size: scan.size,
    };
    // The shared contract checks every field. A development host target
    // such as x86_64-unknown-linux-gnu is not a release target, so the
    // target alone is checked against this platform above instead.
    let mut contract = identity.clone();
    contract.target = host.release_target().as_str().to_owned();
    contract.validate()?;
    Ok(identity)
}

/// The platform a supported cw build target runs on.
pub fn target_platform(target: &str) -> Option<Platform> {
    let (os, arch) = match target {
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => (Os::Linux, Arch::X86_64),
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => (Os::Linux, Arch::Aarch64),
        "x86_64-apple-darwin" => (Os::Macos, Arch::X86_64),
        "aarch64-apple-darwin" => (Os::Macos, Arch::Aarch64),
        _ => return None,
    };
    Some(Platform::new(os, arch))
}

struct Scan {
    sha256: String,
    size: u64,
    header: Vec<u8>,
    records: usize,
    markers: usize,
}

/// Admit downloaded bytes without executing them. The expected record is
/// assembled from the signed identity and trusted caller-owned marker.
/// `path` is diagnostic only. The caller owns scratch ancestry and bindings.
pub fn admit_incoming(
    file: &mut File,
    path: &Path,
    expected: &CwPayloadIdentity,
    host: Platform,
    marker: &[u8],
) -> anyhow::Result<()> {
    validate_marker(marker)?;
    // IdentityError's unsupported-target diagnostic owns a copy of the target.
    // Bound this public input before asking the identity contract to validate it.
    anyhow::ensure!(
        expected.target.len() <= MAX_TARGET,
        "release target exceeds its bound"
    );
    let target = expected.validate()?;
    anyhow::ensure!(
        target.platform() == host,
        "release target differs from this host"
    );
    let record = BuildRecord {
        package_version: expected.package_version.clone(),
        rustc: expected.rustc.clone(),
        source_revision: Some(expected.source_revision.clone()),
        source_tree_sha256: Some(expected.source_tree_sha256.clone()),
        target: expected.target.clone(),
    };
    let framed = record.frame(marker)?;
    let before = file.metadata().context("inspect incoming executable")?;
    anyhow::ensure!(
        before.is_file() && before.len() <= MAX_EXECUTABLE_BYTES,
        "incoming executable is not a bounded regular file"
    );
    if target == crate::identity::ReleaseTarget::X86_64UnknownLinuxMusl {
        admit_static_elf(file, before.len())?;
    }
    file.seek(SeekFrom::Start(0))
        .context("rewind downloaded release executable")?;
    let scan = scan_file(file, path, &framed, marker)?;
    host.validate_executable_header(&scan.header)?;
    anyhow::ensure!(
        scan.records == 1 && scan.markers == 1,
        "incoming executable does not hold exactly one matching complete build record"
    );
    anyhow::ensure!(
        scan.sha256 == expected.sha256 && scan.size == expected.size,
        "incoming executable differs from its signed digest or size"
    );
    anyhow::ensure!(
        unchanged(&before, &file.metadata()?),
        "incoming executable changed during target admission"
    );
    Ok(())
}

/// The release producer's musl contract: no interpreter or needed library.
/// Read only bounded tables from the same held stream that is then hashed.
fn admit_static_elf(file: &File, size: u64) -> anyhow::Result<()> {
    let mut header = [0_u8; 64];
    file.read_exact_at(&mut header, 0)
        .context("read incoming ELF header")?;
    let offset = u64::from_le_bytes(header[32..40].try_into().expect("ELF offset"));
    let entry_size = u16::from_le_bytes(header[54..56].try_into().expect("ELF size"));
    let count = u16::from_le_bytes(header[56..58].try_into().expect("ELF count"));
    anyhow::ensure!(
        offset >= 64
            && entry_size == 56
            && (1..=128).contains(&count)
            && offset
                .checked_add(u64::from(entry_size) * u64::from(count))
                .is_some_and(|end| end <= size),
        "musl release has invalid ELF program headers"
    );
    let mut dynamic_bytes = 0_u64;
    for index in 0..u64::from(count) {
        let mut entry = [0_u8; 56];
        file.read_exact_at(&mut entry, offset + index * 56)?;
        let kind = u32::from_le_bytes(entry[..4].try_into().expect("ELF kind"));
        anyhow::ensure!(kind != 3, "musl release has a dynamic interpreter");
        if kind == 2 {
            let start = u64::from_le_bytes(entry[8..16].try_into().expect("dynamic offset"));
            let length = u64::from_le_bytes(entry[32..40].try_into().expect("dynamic length"));
            dynamic_bytes = dynamic_bytes
                .checked_add(length)
                .context("ELF table overflow")?;
            anyhow::ensure!(
                length % 16 == 0
                    && dynamic_bytes <= MAX_EXECUTABLE_BYTES
                    && start.checked_add(length).is_some_and(|end| end <= size),
                "musl release has an invalid or unbounded dynamic table"
            );
            let mut buffer = [0_u8; 4096];
            let mut position = 0;
            'table: while position < length {
                let n = (length - position).min(buffer.len() as u64) as usize;
                file.read_exact_at(&mut buffer[..n], start + position)?;
                for entry in buffer[..n].as_chunks::<16>().0 {
                    let tag = i64::from_le_bytes(entry[..8].try_into().expect("dynamic tag"));
                    if tag == 0 {
                        break 'table;
                    }
                    anyhow::ensure!(tag != 1, "musl release names a shared library");
                }
                position += n as u64;
            }
        }
    }
    Ok(())
}

fn scan_file(file: &mut File, path: &Path, record: &[u8], marker: &[u8]) -> anyhow::Result<Scan> {
    BuildRecord::decode(record, marker)?;
    file.seek(SeekFrom::Start(0))
        .context("rewind held executable")?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        before.is_file() && before.len() <= MAX_EXECUTABLE_BYTES,
        "{} is not a bounded regular file",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(EXECUTABLE_HEADER_BYTES);
    let mut buffer = vec![0_u8; SCAN_CHUNK];
    let mut window = Vec::with_capacity(SCAN_CHUNK + record.len());
    let mut marker_window = Vec::with_capacity(SCAN_CHUNK + marker.len());
    let mut size = 0_u64;
    let mut records = 0;
    let mut markers = 0;
    loop {
        let read = match read_some(file, &mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        };
        size += read as u64;
        anyhow::ensure!(
            size <= MAX_EXECUTABLE_BYTES,
            "{} exceeds its size bound",
            path.display()
        );
        let chunk = &buffer[..read];
        hasher.update(chunk);
        let wanted = EXECUTABLE_HEADER_BYTES
            .saturating_sub(header.len())
            .min(read);
        header.extend_from_slice(&chunk[..wanted]);
        // The retained tail is shorter than a record, so every match ends in
        // this chunk and is counted once.
        window.extend_from_slice(chunk);
        records += occurrences(&window, record);
        let keep = record.len().saturating_sub(1);
        window.drain(..window.len().saturating_sub(keep));
        // This shorter tail counts every marker once, including a different
        // or truncated record, without recounting markers in the record tail.
        marker_window.extend_from_slice(chunk);
        markers += occurrences(&marker_window, marker);
        let keep = marker.len().saturating_sub(1);
        marker_window.drain(..marker_window.len().saturating_sub(keep));
    }
    let after = file
        .metadata()
        .with_context(|| format!("recheck {}", path.display()))?;
    anyhow::ensure!(
        unchanged(&before, &after) && size == before.len(),
        "{} changed while it was read",
        path.display()
    );
    Ok(Scan {
        sha256: format!("{:x}", hasher.finalize()),
        size,
        header,
        records,
        markers,
    })
}

fn read_some(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) == (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    )
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    const PREFIX: usize = 8;
    let Some(last) = haystack.len().checked_sub(needle.len()) else {
        return 0;
    };
    if needle.len() < PREFIX {
        return 0;
    }
    let prefix = u64::from_ne_bytes(needle[..PREFIX].try_into().expect("prefix"));
    (0..=last)
        .filter(|&start| {
            u64::from_ne_bytes(haystack[start..start + PREFIX].try_into().expect("prefix"))
                == prefix
                && haystack[start..start + needle.len()] == *needle
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MARKER: &[u8] = b"synthetic-caller-record-v1\0";

    fn record(target: &str) -> BuildRecord {
        BuildRecord {
            package_version: "v1.2.3".to_owned(),
            rustc: "rustc 1.93.0 (synthetic 2026-01-01)".to_owned(),
            source_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            source_tree_sha256: Some(
                "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567".to_owned(),
            ),
            target: target.to_owned(),
        }
    }

    fn executable(host: Platform, frame: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; EXECUTABLE_HEADER_BYTES];
        match host.os {
            Os::Linux => {
                bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
                bytes[16] = 3;
                bytes[18] = if host.arch == Arch::X86_64 { 62 } else { 183 };
                if host.arch == Arch::X86_64 {
                    bytes.extend_from_slice(&[0; 56]);
                    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
                    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
                    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
                    bytes[64] = 1;
                }
            }
            Os::Macos => {
                bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
                let cpu: u32 = if host.arch == Arch::X86_64 {
                    0x0100_0007
                } else {
                    0x0100_000c
                };
                bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
                bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
            }
        }
        bytes.extend_from_slice(frame);
        bytes
    }

    fn expected(record: &BuildRecord, bytes: &[u8]) -> CwPayloadIdentity {
        CwPayloadIdentity {
            schema_version: PAYLOAD_SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION,
            record_version: RECORD_VERSION,
            package_version: record.package_version.clone(),
            target: record.target.clone(),
            source_revision: record.source_revision.clone().unwrap(),
            source_tree_sha256: record.source_tree_sha256.clone().unwrap(),
            rustc: record.rustc.clone(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        }
    }

    #[test]
    fn public_marker_frame_and_field_bounds_precede_stream_io() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate");
        let host = Platform::new(Os::Linux, Arch::X86_64);
        let record = record(host.release_target().as_str());
        let frame = record.frame(MARKER).unwrap();
        let bytes = executable(host, &frame);
        fs::write(&path, &bytes).unwrap();
        let expected = expected(&record, &bytes);
        let mut held = File::open(&path).unwrap();
        held.seek(SeekFrom::Start(13)).unwrap();
        for length in [0, 1, 7, 129, SCAN_CHUNK] {
            let marker = vec![b'x'; length];
            assert!(record.frame(&marker).is_err());
            assert!(BuildRecord::decode(&frame, &marker).is_err());
            assert!(identify(&mut held, &path, &frame, &marker, host).is_err());
            assert!(admit_incoming(&mut held, &path, &expected, host, &marker).is_err());
            assert_eq!(held.stream_position().unwrap(), 13);
        }
        let mut oversized = frame.clone();
        oversized.resize(MARKER.len() + 4 + MAX_RECORD_JSON + 1, b'x');
        assert!(BuildRecord::decode(&oversized, MARKER).is_err());
        assert!(BuildRecord::decode(&[], MARKER).is_err());
        let mut huge_length = MARKER.to_vec();
        huge_length.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(BuildRecord::decode(&huge_length, MARKER).is_err());
        for field in ["package_version", "target", "rustc", "revision", "tree"] {
            let mut invalid = record.clone();
            match field {
                "package_version" => invalid.package_version = "v".repeat(65),
                "target" => invalid.target = "x".repeat(MAX_TARGET + 1),
                "rustc" => invalid.rustc = format!("rustc {}", "x".repeat(MAX_RUSTC)),
                "revision" => invalid.source_revision = Some("a".repeat(41)),
                _ => invalid.source_tree_sha256 = Some("a".repeat(65)),
            }
            assert!(invalid.frame(MARKER).is_err(), "{field}");
        }
        let mut invalid_identity = expected.clone();
        invalid_identity.target = "x".repeat(SCAN_CHUNK);
        let error = admit_incoming(&mut held, &path, &invalid_identity, host, MARKER).unwrap_err();
        assert!(error.to_string().contains("target exceeds its bound"));
        assert_eq!(held.stream_position().unwrap(), 13);
    }

    #[test]
    fn admission_rewinds_the_held_inode_without_reopening_the_diagnostic_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate");
        let original = directory.path().join("original");
        let host = Platform::new(Os::Linux, Arch::X86_64);
        let record = record(host.release_target().as_str());
        let bytes = executable(host, &record.frame(MARKER).unwrap());
        let expected = expected(&record, &bytes);
        fs::write(&path, &bytes).unwrap();
        let mut held = File::open(&path).unwrap();
        held.seek(SeekFrom::End(0)).unwrap();
        admit_incoming(&mut held, &path, &expected, host, MARKER).unwrap();
        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"replacement must never be opened").unwrap();
        held.seek(SeekFrom::Start(17)).unwrap();
        admit_incoming(&mut held, &path, &expected, host, MARKER).unwrap();
        assert_eq!(held.stream_position().unwrap(), bytes.len() as u64);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"replacement must never be opened"
        );
        let before = held.metadata().unwrap();
        let mut writer = fs::OpenOptions::new().append(true).open(&original).unwrap();
        use std::io::Write as _;
        writer.write_all(b"changed in place").unwrap();
        assert!(!unchanged(&before, &held.metadata().unwrap()));
        assert!(admit_incoming(&mut held, &path, &expected, host, MARKER).is_err());
    }

    #[test]
    fn all_release_targets_share_the_same_full_record_and_marker_admission() {
        let directory = tempfile::tempdir().unwrap();
        for host in Platform::ALL {
            let record = record(host.release_target().as_str());
            let frame = record.frame(MARKER).unwrap();
            assert_eq!(BuildRecord::decode(&frame, MARKER).unwrap(), record);
            let bytes = executable(host, &frame);
            let path = directory.path().join(host.as_str());
            fs::write(&path, &bytes).unwrap();
            admit_incoming(
                &mut File::open(&path).unwrap(),
                &path,
                &expected(&record, &bytes),
                host,
                MARKER,
            )
            .unwrap();
            for extra in [&frame[..], MARKER, &frame[..MARKER.len() + 2]] {
                let mut duplicate = bytes.clone();
                duplicate.extend_from_slice(extra);
                fs::write(&path, &duplicate).unwrap();
                assert!(
                    admit_incoming(
                        &mut File::open(&path).unwrap(),
                        &path,
                        &expected(&record, &duplicate),
                        host,
                        MARKER
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn scanner_counts_split_records_and_truncated_extra_markers_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate");
        let host = Platform::new(Os::Linux, Arch::X86_64);
        let record = record(host.release_target().as_str());
        let frame = record.frame(MARKER).unwrap();
        let mut bytes = executable(host, &[]);
        bytes.resize(SCAN_CHUNK - 11, b'x');
        bytes.extend_from_slice(&frame);
        fs::write(&path, &bytes).unwrap();
        let mut held = File::open(&path).unwrap();
        let scan = scan_file(&mut held, &path, &frame, MARKER).unwrap();
        assert_eq!((scan.records, scan.markers), (1, 1));
        bytes.extend_from_slice(MARKER);
        fs::write(&path, &bytes).unwrap();
        let scan = scan_file(&mut held, &path, &frame, MARKER).unwrap();
        assert_eq!((scan.records, scan.markers), (1, 2));
    }
    #[test]
    fn occurrences_counts_every_exact_match() {
        let needle = b"0123456789";
        assert_eq!(occurrences(b"", needle), 0);
        assert_eq!(occurrences(b"012345678", needle), 0);
        assert_eq!(occurrences(b"x0123456789y0123456789", needle), 2);
        assert_eq!(occurrences(b"01234567890123456789", needle), 2);
        assert_eq!(occurrences(b"0123456788", needle), 0);
    }
}
