//! This cw's closed compile-time build record.
//!
//! `build.rs` embeds exactly one record: a unique marker, a little-endian
//! length and canonical JSON naming the effective compiled version, the Cargo
//! target, the compiler and, when the build supplied both, the source revision
//! and source-tree digest. [`CLI_VERSION`] is borrowed from those bytes, so the
//! version `cw --version` reports is the version producers admit from the
//! executable. The record never holds a digest of its own executable; the
//! identity's `sha256` and `size` are always computed from the bytes.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::Context as _;
use codewire_cw_release::build_record::{self as shared, BuildRecord};
use codewire_cw_release::identity::{CwPayloadIdentity, Platform};

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

fn marker() -> &'static [u8] {
    &BUILD_RECORD[..BUILD_RECORD_JSON - 4]
}

/// This executable's own record and reported version share the same bytes.
pub(crate) fn embedded() -> anyhow::Result<BuildRecord> {
    let record = shared::BuildRecord::decode(&BUILD_RECORD, marker())?;
    anyhow::ensure!(
        record.package_version == CLI_VERSION,
        "the build record version differs from the reported version"
    );
    Ok(record)
}

/// Open only this executable's image; Linux /proc/self/exe names the running
/// inode. Incoming release admission always receives an already-held file.
pub(crate) fn executable_identity(
    decoded: &BuildRecord,
    record: &[u8],
    path: &Path,
    host: Platform,
) -> anyhow::Result<CwPayloadIdentity> {
    decoded.validate()?;
    anyhow::ensure!(
        decoded.source_revision.is_some(),
        "this cw was built without source provenance, so it has no complete identity; build and install it with `make cli-install` from an authorized source checkout"
    );
    anyhow::ensure!(
        shared::target_platform(&decoded.target) == Some(host),
        "this cw was built for {}, which is not a supported {} target",
        decoded.target,
        host.as_str()
    );
    anyhow::ensure!(
        shared::BuildRecord::decode(record, marker())? == *decoded,
        "the decoded build record differs from its framed bytes"
    );
    let follow = cfg!(target_os = "linux") && path == Path::new("/proc/self/exe");
    let flags = libc::O_NONBLOCK | if follow { 0 } else { libc::O_NOFOLLOW };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .with_context(|| format!("open the running cw executable {}", path.display()))?;
    shared::identify(&mut file, path, record, marker(), host)
}

pub(crate) fn admit_incoming(
    file: &mut File,
    path: &Path,
    expected: &CwPayloadIdentity,
    host: Platform,
) -> anyhow::Result<()> {
    shared::admit_incoming(file, path, expected, host, marker())
}

#[cfg(test)]
fn decode(record: &[u8], json_start: usize) -> anyhow::Result<BuildRecord> {
    anyhow::ensure!(
        json_start == BUILD_RECORD_JSON,
        "the build record has no length"
    );
    BuildRecord::decode(record, marker())
}

#[cfg(test)]
pub(crate) mod tests {
    use codewire_cw_release::build_record::target_platform;
    use codewire_cw_release::identity::{Arch, EXECUTABLE_HEADER_BYTES, Os};
    use sha2::{Digest as _, Sha256};
    use std::fs;
    const SCAN_CHUNK: usize = 1024 * 1024;

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
        decode(record, BUILD_RECORD_JSON).unwrap()
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
        let record = embedded().unwrap();
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
        let decoded = decode(&framed(&valid), start).unwrap();
        assert_eq!(decoded.package_version, "v1.2.3");
        assert_eq!(decoded.source_revision.as_deref(), Some(REVISION));
        assert!(
            decode(&framed(&json("v1.2.3", host_target(), false)), start)
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
            assert!(decode(&framed(&json), start).is_err(), "{json}");
        }
        let mut truncated = framed(&valid);
        truncated.pop();
        assert!(decode(&truncated, start).is_err());
        assert!(decode(&framed(&valid), 2).is_err());
    }

    #[test]
    fn identity_binds_the_record_and_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.30", host_target(), true));
        let decoded = decode(&record, BUILD_RECORD_JSON).unwrap();
        // Incidental text naming another version does not change the record's.
        let bytes = executable(&[b"cw v1.2.3 compatibility note", &record]);
        let path = write(directory.path(), "cw", &bytes);
        let identity = executable_identity(&decoded, &record, &path, host()).unwrap();
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
            executable_identity(&decoded, &record, &path, host())
                .unwrap()
                .size,
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
        let expected = executable_identity(
            &decode(&record, BUILD_RECORD_JSON).unwrap(),
            &record,
            &path,
            host(),
        )
        .unwrap();
        admit_incoming(&mut File::open(&path).unwrap(), &path, &expected, host()).unwrap();
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
                {
                    let mut expected = expected.clone();
                    expected.sha256 = format!("{:x}", Sha256::digest(&bytes));
                    expected.size = bytes.len() as u64;
                    admit_incoming(&mut File::open(&path).unwrap(), &path, &expected, host())
                        .is_err()
                },
                "{mode}"
            );
        }
    }

    #[test]
    fn identity_refuses_any_additional_build_record() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = decode(&record, BUILD_RECORD_JSON).unwrap();
        let other = framed(&json("v9.9.9", host_target(), true));
        let path = write(
            directory.path(),
            "candidate",
            &executable(&[&record, &other]),
        );
        let error = executable_identity(&decoded, &record, &path, host()).unwrap_err();
        assert!(
            error.to_string().contains("2 cw build record markers"),
            "{error:#}"
        );
    }

    #[test]
    fn identity_refuses_trailing_build_record_marker() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = decode(&record, BUILD_RECORD_JSON).unwrap();
        let marker = &record[..BUILD_RECORD_JSON - 4];
        let path = write(
            directory.path(),
            "candidate",
            &executable(&[&record, marker]),
        );
        let error = executable_identity(&decoded, &record, &path, host()).unwrap_err();
        assert!(
            error.to_string().contains("2 cw build record markers"),
            "{error:#}"
        );
    }

    #[test]
    fn identity_refuses_missing_corrupt_repeated_and_foreign_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let record = framed(&json("v1.2.3", host_target(), true));
        let decoded = decode(&record, BUILD_RECORD_JSON).unwrap();
        let refused = |bytes: Vec<u8>, decoded: &BuildRecord, expected: &str| {
            let path = write(directory.path(), "candidate", &bytes);
            let error = format!(
                "{:#}",
                executable_identity(decoded, &record, &path, host()).unwrap_err()
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
        assert!(executable_identity(&decoded, &record, &path, host()).is_err());
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
        assert!(executable_identity(&decoded, &record, &link, host()).is_err());
    }
}
