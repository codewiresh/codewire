use serde_json::{Value, json};

use super::*;
use crate::identity::canonical_json;
use crate::release::ReleaseManifest;

const PRODUCER: &[u8] = include_bytes!("../release/fixtures/producer-manifest.json");

fn manifest() -> ReleaseManifest {
    ReleaseManifest::decode(PRODUCER).unwrap()
}

fn digest(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn spec(path: &str, seed: u8) -> Value {
    json!({"path": path, "size": 1000 + u64::from(seed), "sha256": digest(seed), "architecture": "aarch64"})
}

fn macos_lock() -> Value {
    json!({
        "schema_version": 1,
        "vz_runner": spec("codewire-vz-runner", 1),
        "kernel": spec("kernel", 2),
        "initramfs": spec("initramfs", 3),
        "e2fsprogs": {
            "mkfs_ext4": spec("mkfs.ext4", 4),
            "e2fsck": spec("e2fsck", 5),
            "resize2fs": spec("resize2fs", 6),
            "debugfs": spec("debugfs", 7),
            "mke2fs_conf": spec("mke2fs.conf", 8),
        },
        "git": {"git": spec("git", 9), "git_remote_https": spec("git-remote-https", 10)},
    })
}

/// A document as a release's cw embeds it.
fn published() -> Value {
    let manifest = manifest();
    json!({
        "schema": LOCAL_RUNTIME_SCHEMA,
        "source_revision": manifest.source_revision,
        "targets": {"macos-aarch64": {
            "lock": macos_lock(),
            "components": [{
                "name": "e2fsprogs", "version": "1.47.4", "license": "GPL-2.0-only",
                "source": {"sha256": digest(20), "size": 9_000_000},
            }],
        }},
    })
}

fn encode(value: &Value) -> Vec<u8> {
    canonical_json(value).unwrap()
}

fn decode(value: &Value) -> Result<LocalRuntimeDocument> {
    LocalRuntimeDocument::decode(&encode(value))
}

#[test]
fn a_document_names_its_source_and_targets() {
    let document = decode(&published()).unwrap();
    assert_eq!(document.source_revision, manifest().source_revision);
    assert!(
        document
            .target(Platform::parse("macos-aarch64").unwrap())
            .is_some()
    );
    assert!(
        document
            .target(Platform::parse("linux-x86_64").unwrap())
            .is_none()
    );
    let mut revision = published();
    revision["source_revision"] = json!("main");
    assert!(decode(&revision).is_err());
}

#[test]
fn only_canonical_closed_documents_decode() {
    let value = published();
    assert!(LocalRuntimeDocument::decode(&serde_json::to_vec_pretty(&value).unwrap()).is_err());
    let mut unknown = value.clone();
    unknown["extra"] = json!(true);
    assert!(decode(&unknown).is_err());
    let mut unknown_in_lock = value.clone();
    unknown_in_lock["targets"]["macos-aarch64"]["lock"]["extra"] = json!(1);
    assert!(decode(&unknown_in_lock).is_err());
    let mut schema = value.clone();
    schema["schema"] = json!("codewire.cw.local-runtime/v2");
    assert!(decode(&schema).is_err());
    let mut oversized = value;
    oversized["targets"]["macos-aarch64"]["components"] = json!(
        (0..2000)
            .map(
                |index| json!({"name": format!("c{index}"), "version": "1", "license": "MIT",
                "source": {"sha256": digest(21), "size": 1}})
            )
            .collect::<Vec<_>>()
    );
    assert!(matches!(decode(&oversized), Err(ReleaseError::Bounds)));
}

#[test]
fn targets_and_lock_files_are_exact() {
    let mut unknown_target = published();
    let target = unknown_target["targets"]["macos-aarch64"].clone();
    unknown_target["targets"] = json!({"windows-x86_64": target});
    assert!(decode(&unknown_target).is_err());

    // A macOS lock is only for Apple silicon, and every file must match it.
    let mut intel = published();
    let target = intel["targets"]["macos-aarch64"].clone();
    intel["targets"] = json!({"macos-x86_64": target});
    assert!(decode(&intel).is_err());

    for (pointer, value) in [
        (
            "/targets/macos-aarch64/lock/kernel/architecture",
            json!("x86_64"),
        ),
        (
            "/targets/macos-aarch64/lock/kernel/path",
            json!("../kernel"),
        ),
        (
            "/targets/macos-aarch64/lock/kernel/path",
            json!("boot/kernel"),
        ),
        (
            "/targets/macos-aarch64/lock/kernel/path",
            json!("initramfs"),
        ),
        (
            "/targets/macos-aarch64/lock/kernel/sha256",
            json!("A".repeat(64)),
        ),
        ("/targets/macos-aarch64/lock/kernel/size", json!(0)),
        (
            "/targets/macos-aarch64/lock/kernel/size",
            json!(MAX_OBJECT_BYTES + 1),
        ),
        ("/targets/macos-aarch64/lock/schema_version", json!(2)),
        (
            "/targets/macos-aarch64/components/0/license",
            json!("GPL;rm"),
        ),
        ("/targets/macos-aarch64/components/0/source/size", json!(0)),
    ] {
        let mut changed = published();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(decode(&changed).is_err(), "{pointer}");
    }
    // The same digest with two sizes is refused.
    let mut conflicting = published();
    conflicting["targets"]["macos-aarch64"]["components"][0]["source"] =
        json!({"sha256": digest(2), "size": 1});
    assert!(decode(&conflicting).is_err());

    let mut missing_git = published();
    missing_git["targets"]["macos-aarch64"]["lock"]
        .as_object_mut()
        .unwrap()
        .remove("git");
    assert!(decode(&missing_git).is_err());
}

#[test]
fn a_linux_lock_is_checked_by_its_target_architecture() {
    let linux = |arch: &str| {
        json!({
            "schema_version": 1,
            "cloud_hypervisor": {"path": "cloud-hypervisor", "size": 1, "sha256": digest(11), "architecture": arch, "version": "v54.0"},
            "kernel": {"path": "kernel", "size": 2, "sha256": digest(12), "architecture": arch},
            "initramfs": {"path": "initramfs", "size": 3, "sha256": digest(13), "architecture": arch},
        })
    };
    let mut document = published();
    document["targets"] = json!({
        "linux-x86_64": {"lock": linux("x86_64")},
        "macos-aarch64": {"lock": macos_lock()},
    });
    let decoded = decode(&document).unwrap();
    assert_eq!(decoded.targets.len(), 2);
    document["targets"] = json!({"linux-x86_64": {"lock": linux("aarch64")}});
    assert!(decode(&document).is_err());
    document["targets"] = json!({"linux-aarch64": {"lock": linux("aarch64")}});
    decode(&document).unwrap();
}

#[test]
fn blobs_list_every_lock_file_cw_runtime_and_source_once() {
    let mut value = published();
    value["targets"]["macos-aarch64"]["cw_runtime"] = json!({
        "lock": {"sha256": digest(30), "size": 30},
        "pack": {"sha256": digest(31), "size": 31},
    });
    let document = decode(&value).unwrap();
    let blobs = document.blobs();
    assert_eq!(blobs.len(), 10 + 2 + 1);
    let mut digests: Vec<_> = blobs.iter().map(|blob| blob.sha256.clone()).collect();
    digests.dedup();
    assert_eq!(digests.len(), blobs.len());
    assert!(
        blobs
            .iter()
            .any(|blob| blob.sha256 == digest(20) && blob.size == 9_000_000)
    );
    // An install never fetches component sources.
    let target = document
        .target(Platform::parse("macos-aarch64").unwrap())
        .unwrap();
    let install = target.install_blobs();
    assert_eq!(install.len(), 10 + 2);
    assert!(install.iter().all(|blob| blob.sha256 != digest(20)));
}

/// The release scripts' Python validator (scripts/ci/release/cw_release.py)
/// must agree with this decoder: both decode these shared fixtures, and
/// scripts/ci/tests/test-cw-release-delivery.py checks the same files.
#[test]
fn shared_fixtures_agree_with_the_release_scripts() {
    let valid =
        LocalRuntimeDocument::decode(include_bytes!("fixtures/valid-macos-aarch64.json")).unwrap();
    assert_eq!(valid.blobs().len(), 14);
    let invalid: &[(&str, &[u8])] = &[
        (
            "invalid-blob-sizes-disagree.json",
            include_bytes!("fixtures/invalid-blob-sizes-disagree.json").as_slice(),
        ),
        (
            "invalid-component-license.json",
            include_bytes!("fixtures/invalid-component-license.json").as_slice(),
        ),
        (
            "invalid-component-unknown-field.json",
            include_bytes!("fixtures/invalid-component-unknown-field.json").as_slice(),
        ),
        (
            "invalid-empty-components.json",
            include_bytes!("fixtures/invalid-empty-components.json").as_slice(),
        ),
        (
            "invalid-lock-architecture.json",
            include_bytes!("fixtures/invalid-lock-architecture.json").as_slice(),
        ),
        (
            "invalid-lock-boolean-schema-version.json",
            include_bytes!("fixtures/invalid-lock-boolean-schema-version.json").as_slice(),
        ),
        (
            "invalid-lock-duplicate-path.json",
            include_bytes!("fixtures/invalid-lock-duplicate-path.json").as_slice(),
        ),
        (
            "invalid-lock-missing-git.json",
            include_bytes!("fixtures/invalid-lock-missing-git.json").as_slice(),
        ),
        (
            "invalid-lock-oversized.json",
            include_bytes!("fixtures/invalid-lock-oversized.json").as_slice(),
        ),
        (
            "invalid-lock-path-separator.json",
            include_bytes!("fixtures/invalid-lock-path-separator.json").as_slice(),
        ),
        (
            "invalid-lock-schema-version.json",
            include_bytes!("fixtures/invalid-lock-schema-version.json").as_slice(),
        ),
        (
            "invalid-lock-uppercase-digest.json",
            include_bytes!("fixtures/invalid-lock-uppercase-digest.json").as_slice(),
        ),
        (
            "invalid-lock-zero-size.json",
            include_bytes!("fixtures/invalid-lock-zero-size.json").as_slice(),
        ),
        (
            "invalid-macos-lock-on-linux.json",
            include_bytes!("fixtures/invalid-macos-lock-on-linux.json").as_slice(),
        ),
        (
            "invalid-no-targets.json",
            include_bytes!("fixtures/invalid-no-targets.json").as_slice(),
        ),
        (
            "invalid-not-canonical.json",
            include_bytes!("fixtures/invalid-not-canonical.json").as_slice(),
        ),
        (
            "invalid-null-cw-runtime.json",
            include_bytes!("fixtures/invalid-null-cw-runtime.json").as_slice(),
        ),
        (
            "invalid-schema.json",
            include_bytes!("fixtures/invalid-schema.json").as_slice(),
        ),
        (
            "invalid-short-revision.json",
            include_bytes!("fixtures/invalid-short-revision.json").as_slice(),
        ),
        (
            "invalid-unknown-field.json",
            include_bytes!("fixtures/invalid-unknown-field.json").as_slice(),
        ),
        (
            "invalid-unknown-platform.json",
            include_bytes!("fixtures/invalid-unknown-platform.json").as_slice(),
        ),
    ];
    assert_eq!(invalid.len(), 21);
    for (name, bytes) in invalid {
        assert!(
            LocalRuntimeDocument::decode(bytes).is_err(),
            "{name} decoded"
        );
    }
}
