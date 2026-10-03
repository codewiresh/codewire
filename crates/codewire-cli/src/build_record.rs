//! This cw's closed compile-time build record.
//!
//! `build.rs` embeds exactly one record: a unique marker, a little-endian
//! length and canonical JSON naming the effective compiled version, the Cargo
//! target, the compiler and, when the build supplied both, the source revision
//! and source-tree digest. [`CLI_VERSION`] is borrowed from those bytes, so the
//! version `cw --version` reports is the version producers admit from the
//! executable. The record never holds a digest of its own executable; the
//! identity's `sha256` and `size` are always computed from the bytes.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use anyhow::Context as _;
use codewire_cw_release::identity::{
    Arch, CwPayloadIdentity, EXECUTABLE_HEADER_BYTES, MAX_EXECUTABLE_BYTES, Os,
    PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION, Platform, RECORD_VERSION, canonical_json,
    is_sha256_hex, valid_package_version,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

include!(concat!(env!("OUT_DIR"), "/build_record.rs"));

/// The effective compiled version, borrowed from [`BUILD_RECORD`] itself. A
/// static, not a const: its value is a reference into another static.
pub(crate) static CLI_VERSION: &str = record_text(PACKAGE_VERSION_TEXT.0, PACKAGE_VERSION_TEXT.1);

const fn record_text(start: usize, end: usize) -> &'static str {
    let (head, _) = BUILD_RECORD.split_at(end);
    let (_, text) = head.split_at(start);
    match std::str::from_utf8(text) {
        Ok(text) => text,
        Err(_) => panic!("build record version is not UTF-8"),
    }
}

const MAX_RECORD_JSON: usize = 1024;
const MAX_TARGET: usize = 64;
const MAX_RUSTC: usize = 128;
const SCAN_CHUNK: usize = 1024 * 1024;

/// A decoded build record. The source fields are absent only for a build
/// that was not given explicit provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildRecord {
    pub(crate) package_version: String,
    pub(crate) rustc: String,
    pub(crate) source_revision: Option<String>,
    pub(crate) source_tree_sha256: Option<String>,
    pub(crate) target: String,
}

impl BuildRecord {
    /// This executable's own record.
    pub(crate) fn embedded() -> anyhow::Result<Self> {
        let record = Self::decode(&BUILD_RECORD, BUILD_RECORD_JSON)?;
        anyhow::ensure!(
            record.package_version == CLI_VERSION,
            "the build record version differs from the reported version"
        );
        Ok(record)
    }

    /// Decode `record`, whose canonical JSON starts at `json_start` after its
    /// little-endian length. Unknown, missing, duplicate and non-canonical
    /// fields are refused.
    fn decode(record: &[u8], json_start: usize) -> anyhow::Result<Self> {
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
        anyhow::ensure!(
            canonical_json(&decoded)? == json,
            "the build record is not canonical"
        );
        decoded.validate()?;
        Ok(decoded)
    }

    fn validate(&self) -> anyhow::Result<()> {
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

    /// The complete schema-2 identity of the executable at `path`: this
    /// record's compile context plus the digest and size of those exact bytes.
    /// Refuses a build without source provenance, a target for another
    /// platform, and bytes that do not hold `record` and its marker exactly once.
    pub(crate) fn identity(
        &self,
        record: &[u8],
        path: &Path,
        host: Platform,
    ) -> anyhow::Result<CwPayloadIdentity> {
        let (Some(source_revision), Some(source_tree_sha256)) =
            (&self.source_revision, &self.source_tree_sha256)
        else {
            anyhow::bail!(
                "this cw was built without source provenance, so it has no complete identity; \
                 build and install it with `make cli-install` from an authorized source checkout"
            );
        };
        anyhow::ensure!(
            target_platform(&self.target) == Some(host),
            "this cw was built for {}, which is not a supported {} target",
            self.target,
            host.as_str()
        );
        let scan = scan(path, record)?;
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
            package_version: self.package_version.clone(),
            target: self.target.clone(),
            source_revision: source_revision.clone(),
            source_tree_sha256: source_tree_sha256.clone(),
            rustc: self.rustc.clone(),
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
}

/// The platform a supported cw build target runs on.
fn target_platform(target: &str) -> Option<Platform> {
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

/// Hash the bounded regular file at `path` and count `record` and its marker.
/// Only Linux `/proc/self/exe` may be followed; it names the running image.
fn scan(path: &Path, record: &[u8]) -> anyhow::Result<Scan> {
    let follow = cfg!(target_os = "linux") && path == Path::new("/proc/self/exe");
    let flags = libc::O_NONBLOCK | if follow { 0 } else { libc::O_NOFOLLOW };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .with_context(|| format!("open the running cw executable {}", path.display()))?;
    scan_file(&mut file, path, record)
}

/// Admit downloaded bytes without executing them. The expected record is
/// assembled from the signed shared identity, borrowing this executable's
/// marker instead of adding another compiled marker literal.
pub(crate) fn admit_incoming(
    file: &mut File,
    path: &Path,
    expected: &CwPayloadIdentity,
    host: Platform,
) -> anyhow::Result<()> {
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
    let json = canonical_json(&record)?;
    anyhow::ensure!(
        json.len() <= MAX_RECORD_JSON,
        "incoming build record exceeds its bound"
    );
    let mut framed = BUILD_RECORD[..BUILD_RECORD_JSON - 4].to_vec();
    framed.extend_from_slice(&(json.len() as u32).to_le_bytes());
    framed.extend_from_slice(&json);
    let before = file.metadata().context("inspect incoming executable")?;
    anyhow::ensure!(
        before.is_file() && before.len() <= MAX_EXECUTABLE_BYTES,
        "incoming executable is not a bounded regular file"
    );
    if target == codewire_cw_release::identity::ReleaseTarget::X86_64UnknownLinuxMusl {
        admit_static_elf(file, before.len())?;
    }
    file.seek(SeekFrom::Start(0))
        .context("rewind downloaded release executable")?;
    let scan = scan_file(file, path, &framed)?;
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
                for entry in buffer[..n].chunks_exact(16) {
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

fn scan_file(file: &mut File, path: &Path, record: &[u8]) -> anyhow::Result<Scan> {
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
    // Borrow the generated record's marker so the executable does not embed
    // a second literal marker solely for scanning itself.
    let marker = &BUILD_RECORD[..BUILD_RECORD_JSON - 4];
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
pub(crate) mod tests {
    use std::fs;

    use super::*;

    pub(crate) const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    pub(crate) const TREE: &str =
        "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";

    /// A record framed like the embedded one, reusing its marker.
    pub(crate) fn framed(json: &str) -> Vec<u8> {
        let mut record = BUILD_RECORD[..BUILD_RECORD_JSON - 4].to_vec();
        record.extend_from_slice(&(json.len() as u32).to_le_bytes());
        record.extend_from_slice(json.as_bytes());
        record
    }

    pub(crate) fn decoded(record: &[u8]) -> BuildRecord {
        BuildRecord::decode(record, BUILD_RECORD_JSON).unwrap()
    }

    pub(crate) fn json(version: &str, target: &str, source: bool) -> String {
        let (revision, tree) = if source {
            (format!("\"{REVISION}\""), format!("\"{TREE}\""))
        } else {
            ("null".to_owned(), "null".to_owned())
        };
        format!(
            "{{\"package_version\":\"{version}\",\"rustc\":\"rustc 1.93.0 (synthetic 2026-01-01)\",\
             \"source_revision\":{revision},\"source_tree_sha256\":{tree},\"target\":\"{target}\"}}\n"
        )
    }

    pub(crate) fn host() -> Platform {
        Platform::host().expect("supported test host")
    }

    pub(crate) fn host_target() -> &'static str {
        match (host().os, host().arch) {
            (Os::Linux, Arch::X86_64) => "x86_64-unknown-linux-gnu",
            (Os::Linux, Arch::Aarch64) => "aarch64-unknown-linux-gnu",
            (Os::Macos, Arch::X86_64) => "x86_64-apple-darwin",
            (Os::Macos, Arch::Aarch64) => "aarch64-apple-darwin",
        }
    }

    /// Synthetic executable bytes: a valid host header, then `body`.
    pub(crate) fn executable(body: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![0_u8; EXECUTABLE_HEADER_BYTES];
        match host().os {
            Os::Linux => {
                bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
                bytes[16] = 3;
                bytes[18] = if host().arch == Arch::X86_64 { 62 } else { 183 };
            }
            Os::Macos => {
                bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
                let cpu: u32 = if host().arch == Arch::X86_64 {
                    0x0100_0007
                } else {
                    0x0100_000c
                };
                bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
                bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
            }
        }
        for part in body {
            bytes.extend_from_slice(part);
            bytes.extend_from_slice(&[0x5a; 37]);
        }
        bytes
    }

    pub(crate) fn release_executable(body: &[&[u8]]) -> Vec<u8> {
        let mut bytes = executable(body);
        if host().release_target()
            == codewire_cw_release::identity::ReleaseTarget::X86_64UnknownLinuxMusl
        {
            bytes.splice(64..64, [0_u8; 56]);
            bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
            bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
            bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
            bytes[64] = 1;
        }
        bytes
    }

    pub(crate) fn write(directory: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn reported_version_is_borrowed_from_the_embedded_record() {
        use clap::CommandFactory as _;
        let record = BuildRecord::embedded().unwrap();
        assert_eq!(record.package_version, CLI_VERSION);
        assert!(
            BUILD_RECORD
                .as_ptr_range()
                .contains(&CLI_VERSION.as_bytes().as_ptr())
        );
        assert_eq!(target_platform(&record.target), Platform::host());
        assert_eq!(
            record.package_version,
            option_env!("CODEWIRE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        assert!(crate::Cli::command().render_version().contains(CLI_VERSION));
    }

    #[test]
    fn decode_refuses_unknown_missing_duplicate_partial_and_noncanonical_records() {
        let valid = json("v1.2.3", host_target(), true);
        let start = BUILD_RECORD_JSON;
        let decoded = BuildRecord::decode(&framed(&valid), start).unwrap();
        assert_eq!(decoded.package_version, "v1.2.3");
        assert_eq!(decoded.source_revision.as_deref(), Some(REVISION));
        assert!(
            BuildRecord::decode(&framed(&json("v1.2.3", host_target(), false)), start)
                .unwrap()
                .source_revision
                .is_none()
        );
        let refused = [
            valid.replacen('{', "{\"extra\":1,", 1),
            valid.replacen(
                ",\"source_revision\":",
                ",\"source_revision\":null,\"source_revision\":",
                1,
            ),
            valid.replace(&format!("\"source_revision\":\"{REVISION}\","), ""),
            valid.replace(&format!("\"{TREE}\""), "null"),
            valid.replace(
                &format!("\"{REVISION}\""),
                &format!("\"{}\"", REVISION.to_uppercase()),
            ),
            valid.replace("rustc 1.93.0", "cargo 1.93.0"),
            valid.replace("v1.2.3", "v1.2.3 beta"),
            valid.replace(':', ": "),
            valid.trim_end().to_owned(),
        ];
        for json in refused {
            assert!(
                BuildRecord::decode(&framed(&json), start).is_err(),
                "{json}"
            );
        }
        let mut truncated = framed(&valid);
        truncated.pop();
        assert!(BuildRecord::decode(&truncated, start).is_err());
        assert!(BuildRecord::decode(&framed(&valid), 2).is_err());
    }

    #[test]
    fn identity_binds_the_record_and_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.30", host_target(), true));
        let decoded = BuildRecord::decode(&record, BUILD_RECORD_JSON).unwrap();
        // Incidental text naming another version does not change the record's.
        let bytes = executable(&[b"cw v1.2.3 compatibility note", &record]);
        let path = write(directory.path(), "cw", &bytes);
        let identity = decoded.identity(&record, &path, host()).unwrap();
        assert_eq!(identity.package_version, "v1.2.30");
        assert_eq!(identity.target, host_target());
        assert_eq!(identity.source_revision, REVISION);
        assert_eq!(identity.source_tree_sha256, TREE);
        assert_eq!(identity.rustc, "rustc 1.93.0 (synthetic 2026-01-01)");
        assert_eq!(identity.sha256, format!("{:x}", Sha256::digest(&bytes)));
        assert_eq!(identity.size, bytes.len() as u64);
        assert_eq!(
            (
                identity.schema_version,
                identity.protocol_version,
                identity.record_version
            ),
            (2, 1, 1)
        );
        // A record spanning the scanner's chunk boundary is still found once.
        let mut large = executable(&[]);
        large.resize(SCAN_CHUNK - 11, 0x41);
        large.extend_from_slice(&record);
        large.extend_from_slice(&[0x42; 4096]);
        let path = write(directory.path(), "cw-large", &large);
        assert_eq!(
            decoded.identity(&record, &path, host()).unwrap().size,
            large.len() as u64
        );
    }

    #[test]
    fn incoming_admission_binds_signed_record_fields_and_exact_held_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let target = host().release_target().as_str();
        let record = framed(&json("v1.2.3", target, true));
        let bytes = release_executable(&[&record]);
        let expected = CwPayloadIdentity {
            schema_version: 2,
            protocol_version: 1,
            record_version: 1,
            package_version: "v1.2.3".into(),
            target: target.into(),
            source_revision: REVISION.into(),
            source_tree_sha256: TREE.into(),
            rustc: "rustc 1.93.0 (synthetic 2026-01-01)".into(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size: bytes.len() as u64,
        };
        let path = write(directory.path(), "candidate", &bytes);
        let mut held = File::open(&path).unwrap();
        admit_incoming(&mut held, &path, &expected, host()).unwrap();
        for field in [
            "version", "revision", "tree", "rustc", "target", "sha256", "size",
        ] {
            let mut wrong = expected.clone();
            match field {
                "version" => wrong.package_version = "v1.2.4".into(),
                "revision" => wrong.source_revision = "a".repeat(40),
                "tree" => wrong.source_tree_sha256 = "b".repeat(64),
                "rustc" => wrong.rustc = "rustc 1.94.0 (synthetic)".into(),
                "target" => {
                    wrong.target = if target == "aarch64-apple-darwin" {
                        "x86_64-unknown-linux-musl"
                    } else {
                        "aarch64-apple-darwin"
                    }
                    .into()
                }
                "sha256" => wrong.sha256 = "c".repeat(64),
                _ => wrong.size += 1,
            }
            assert!(
                admit_incoming(&mut held, &path, &wrong, host()).is_err(),
                "field {field}"
            );
        }
        // Replacement of the name cannot change the held stream being admitted.
        fs::rename(&path, directory.path().join("original")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        admit_incoming(&mut held, &path, &expected, host()).unwrap();
        fs::write(directory.path().join("original"), b"in-place mutation").unwrap();
        assert!(admit_incoming(&mut held, &path, &expected, host()).is_err());
    }

    #[test]
    fn incoming_admission_rejects_extra_or_truncated_markers_and_bad_headers() {
        let directory = tempfile::tempdir().unwrap();
        let target = host().release_target().as_str();
        let record = framed(&json("v1.2.3", target, true));
        let other = framed(&json("v9.9.9", target, true));
        let marker = &record[..BUILD_RECORD_JSON - 4];
        for (index, mut bytes) in [
            release_executable(&[&record, &record]),
            release_executable(&[&record, &other]),
            release_executable(&[&record, marker]),
            release_executable(&[b"v1.2.3"]),
            release_executable(&[&record]),
        ]
        .into_iter()
        .enumerate()
        {
            if index == 4 {
                bytes[0] = b'x';
            }
            let expected = CwPayloadIdentity {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: "v1.2.3".into(),
                target: target.into(),
                source_revision: REVISION.into(),
                source_tree_sha256: TREE.into(),
                rustc: "rustc 1.93.0 (synthetic 2026-01-01)".into(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            };
            let path = write(directory.path(), "candidate", &bytes);
            assert!(
                admit_incoming(&mut File::open(&path).unwrap(), &path, &expected, host()).is_err()
            );
        }
    }

    #[test]
    fn static_musl_admission_rejects_interpreters_libraries_and_unbounded_tables() {
        if host().release_target()
            != codewire_cw_release::identity::ReleaseTarget::X86_64UnknownLinuxMusl
        {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host().release_target().as_str(), true));
        let good = release_executable(&[&record]);
        let path = write(directory.path(), "candidate", &good);
        admit_static_elf(&File::open(&path).unwrap(), good.len() as u64).unwrap();
        for mode in [
            "interp",
            "needed",
            "offset",
            "size",
            "count",
            "dynamic-end",
            "dynamic-size",
        ] {
            let mut bytes = good.clone();
            match mode {
                "interp" => bytes[64..68].copy_from_slice(&3_u32.to_le_bytes()),
                "offset" => bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes()),
                "size" => bytes[54..56].copy_from_slice(&55_u16.to_le_bytes()),
                "count" => bytes[56..58].copy_from_slice(&129_u16.to_le_bytes()),
                _ => {
                    bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
                    bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
                    bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
                    if mode == "needed" {
                        bytes[120..128].copy_from_slice(&1_i64.to_le_bytes());
                    } else if mode == "dynamic-end" {
                        bytes[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
                    } else {
                        bytes[96..104].copy_from_slice(&15_u64.to_le_bytes());
                    }
                }
            }
            let path = write(directory.path(), "candidate", &bytes);
            assert!(
                admit_static_elf(&File::open(&path).unwrap(), bytes.len() as u64).is_err(),
                "{mode}"
            );
        }
    }

    #[test]
    fn identity_refuses_any_additional_build_record() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = BuildRecord::decode(&record, BUILD_RECORD_JSON).unwrap();
        let other = framed(&json("v9.9.9", host_target(), true));
        let path = write(
            directory.path(),
            "candidate",
            &executable(&[&record, &other]),
        );
        let error = decoded.identity(&record, &path, host()).unwrap_err();
        assert!(
            error.to_string().contains("2 cw build record markers"),
            "{error:#}"
        );
    }

    #[test]
    fn identity_refuses_trailing_build_record_marker() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = BuildRecord::decode(&record, BUILD_RECORD_JSON).unwrap();
        let marker = &record[..BUILD_RECORD_JSON - 4];
        let path = write(
            directory.path(),
            "candidate",
            &executable(&[&record, marker]),
        );
        let error = decoded.identity(&record, &path, host()).unwrap_err();
        assert!(
            error.to_string().contains("2 cw build record markers"),
            "{error:#}"
        );
    }

    #[test]
    fn identity_refuses_missing_corrupt_repeated_and_foreign_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = BuildRecord::decode(&record, BUILD_RECORD_JSON).unwrap();
        let refused = |bytes: Vec<u8>, decoded: &BuildRecord, expected: &str| {
            let path = write(directory.path(), "candidate", &bytes);
            let error = format!(
                "{:#}",
                decoded.identity(&record, &path, host()).unwrap_err()
            );
            assert!(error.contains(expected), "{error}");
            fs::remove_file(path).unwrap();
        };

        let unbound = BuildRecord {
            source_revision: None,
            source_tree_sha256: None,
            ..decoded.clone()
        };
        refused(
            executable(&[&record]),
            &unbound,
            "without source provenance",
        );
        refused(executable(&[b"v1.2.3"]), &decoded, "0 copies");
        refused(executable(&[&record, &record]), &decoded, "2 copies");
        let mut corrupt = record.clone();
        *corrupt.last_mut().unwrap() = b' ';
        refused(executable(&[&corrupt]), &decoded, "0 copies");
        let mut foreign = executable(&[&record]);
        foreign[..4].copy_from_slice(b"\0\0\0\0");
        let path = write(directory.path(), "foreign", &foreign);
        assert!(decoded.identity(&record, &path, host()).is_err());
        let other = BuildRecord {
            target: match host().os {
                Os::Linux => "aarch64-apple-darwin".into(),
                Os::Macos => "x86_64-unknown-linux-musl".into(),
            },
            ..decoded.clone()
        };
        refused(executable(&[&record]), &other, "not a supported");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(
            write(directory.path(), "real", &executable(&[&record])),
            &link,
        )
        .unwrap();
        assert!(decoded.identity(&record, &link, host()).is_err());
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
