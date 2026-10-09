use std::process::Command;

use serde_json::{Value, json};

use super::*;

const PRODUCER: &[u8] = include_bytes!("fixtures/producer-manifest.json");

fn manifest() -> ReleaseManifest {
    ReleaseManifest::decode(PRODUCER).unwrap()
}
fn value() -> Value {
    serde_json::from_slice(PRODUCER).unwrap()
}
fn encode(value: &Value) -> Vec<u8> {
    canonical_json(value).unwrap()
}
fn refuses(value: Value) {
    assert!(ReleaseManifest::decode(&encode(&value)).is_err());
}

#[test]
fn actual_python_producer_and_rust_canonical_contract_match() {
    let parsed = manifest();
    assert_eq!(canonical_json(&parsed).unwrap(), PRODUCER);
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin")
        .current_dir(repo).args(["-B", "-c", concat!(
            "import importlib.util,pathlib;",
            "s=importlib.util.spec_from_file_location('release','scripts/ci/release/cw_release.py');",
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);",
            "b=pathlib.Path('crates/codewire-cw-release/src/release/fixtures/producer-manifest.json').read_bytes();",
            "assert m.canonical(m.validate_manifest(m.parse_canonical(b)))==b"
        )]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compiled_trust_is_an_exact_producer_and_artifact_graph_input() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(repo).args(["-B", "-c", concat!(
            "import importlib.util,pathlib,json;",
            "s=importlib.util.spec_from_file_location('release','scripts/ci/release/cw_release.py');",
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);",
            "p='apps/cli/GPG_PUBLIC_KEY.asc';",
            "assert p in m.SOURCE_PATHSPEC and p.encode() in m.source_inputs(pathlib.Path.cwd());",
            "g=json.loads(pathlib.Path('scripts/ci/plan/artifact-graph.json').read_text());",
            "assert all(p in g['artifacts'][a]['package_inputs']['codewire-cli'] for a in ('cw_cli_release_assets','workspace_cw_binary'))"
        )]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn canonical_unknown_and_duplicate_fields_refuse() {
    let mut v = value();
    v["unknown"] = json!(true);
    refuses(v);
    let pretty = serde_json::to_vec_pretty(&value()).unwrap();
    assert!(ReleaseManifest::decode(&pretty).is_err());
    let text = std::str::from_utf8(PRODUCER).unwrap();
    let duplicate = text.replacen(
        "\"schema\":",
        "\"schema\":\"codewire.cw.release/v1\",\"schema\":",
        1,
    );
    assert!(ReleaseManifest::decode(duplicate.as_bytes()).is_err());
    let mut v = value();
    v["targets"][0]["identity"]["unknown"] = json!(0);
    refuses(v);
}

#[test]
fn integers_are_never_boolean_float_string_or_null() {
    for bad in [
        json!(true),
        json!(false),
        json!(2.0),
        json!("2"),
        Value::Null,
    ] {
        let mut v = value();
        v["targets"][0]["identity"]["schema_version"] = bad;
        refuses(v);
    }
    for bad in [json!(true), json!(128.0), json!("128"), Value::Null] {
        let mut v = value();
        v["targets"][0]["executable"]["size"] = bad;
        refuses(v);
    }
}

#[test]
fn exact_four_targets_and_order_are_required() {
    let mut v = value();
    v["targets"].as_array_mut().unwrap().swap(0, 1);
    refuses(v);
    let mut v = value();
    v["targets"].as_array_mut().unwrap().pop();
    refuses(v);
    let mut v = value();
    v["targets"][1] = v["targets"][0].clone();
    refuses(v);
    let mut v = value();
    v["targets"][0]["target"] = json!("x86_64-unknown-linux-gnu");
    refuses(v);
}

#[test]
fn every_target_binds_version_source_compiler_protocol_and_record() {
    for (field, bad) in [
        ("package_version", json!("v1.2.4")),
        ("source_revision", json!("d".repeat(40))),
        ("source_tree_sha256", json!("d".repeat(64))),
        ("rustc", json!("rustc 1.91.1")),
        ("protocol_version", json!(2)),
        ("record_version", json!(2)),
    ] {
        let mut v = value();
        v["targets"][2]["identity"][field] = bad;
        refuses(v);
    }
    let mut v = value();
    v["package_version"] = json!("v1.2.4");
    refuses(v);
    let mut v = value();
    v["targets"][0]["asset_name"] = json!("../../cw");
    refuses(v);
}

#[test]
fn exact_immutable_keys_and_content_addressed_transports_refuse_paths() {
    for bad in [
        "https://other.invalid/cw",
        "cw/v1/blobs/sha256/../secret",
        "cw/v1/releases/v1.2.3/cw?auth=x",
    ] {
        let mut v = value();
        v["targets"][0]["executable"]["key"] = json!(bad);
        refuses(v);
    }
    let mut v = value();
    v["checksums"]["file"]["key"] = json!("cw/v1/releases/v1.2.4/SHA256SUMS");
    refuses(v);
    let mut v = value();
    v["targets"][3]["runtime_lock"]["key"] = json!("cw/v1/lock");
    refuses(v);
    let mut v = value();
    v["targets"][3]["oci"]["archive"]["sha256"] = json!("e".repeat(64));
    refuses(v);
    let mut v = value();
    v["targets"][3]["runtime_pack"] = Value::Null;
    refuses(v);
    let mut v = value();
    v["targets"][0]["runtime_lock"] = v["targets"][3]["runtime_lock"].clone();
    refuses(v);
}

#[test]
fn all_signed_sizes_and_document_caps_are_enforced() {
    for size in [0, MAX_EXECUTABLE_BYTES + 1] {
        let mut v = value();
        v["targets"][0]["identity"]["size"] = json!(size);
        v["targets"][0]["executable"]["size"] = json!(size);
        refuses(v);
    }
    let mut v = value();
    v["checksums"]["signature"]["size"] = json!(MAX_SIGNATURE_BYTES + 1);
    refuses(v);
    assert_eq!(
        ReleaseManifest::decode(&vec![b' '; MAX_JSON_BYTES + 1]),
        Err(ReleaseError::Bounds)
    );
}

#[test]
fn signed_sums_must_be_exactly_the_four_raw_assets() {
    let mut m = manifest();
    let sums: String = m
        .targets
        .iter()
        .map(|e| format!("{}  {}\n", e.identity.sha256, e.asset_name))
        .collect();
    m.verify_checksums(sums.as_bytes()).unwrap();
    for bad in [
        format!("{sums}{}  other\n", "a".repeat(64)),
        sums.trim_end().to_owned(),
        sums.replace("  ", " "),
    ] {
        m.checksums.file.sha256 = format!("{:x}", Sha256::digest(bad.as_bytes()));
        m.checksums.file.size = bad.len() as u64;
        assert_eq!(
            m.verify_checksums(bad.as_bytes()),
            Err(ReleaseError::Invalid("four checksums"))
        );
    }
}

#[test]
fn stable_channel_is_closed_and_binds_both_exact_release_objects() {
    let reference = |name: &str, size| ObjectRef {
        key: release_key("v1.2.3", name),
        sha256: "a".repeat(64),
        size,
    };
    let envelope = ChannelEnvelope {
        schema: CHANNEL_SCHEMA.into(),
        pointer: ChannelPointer {
            channel: "stable".into(),
            release_tag: "v1.2.3".into(),
            release: reference("release.json", 100),
            release_signature: reference("release.json.asc", 100),
        },
        signature: "-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n".into(),
    };
    let bytes = canonical_json(&envelope).unwrap();
    assert_eq!(ChannelEnvelope::decode(&bytes).unwrap(), envelope);
    for (field, bad) in [
        ("channel", json!("latest")),
        ("release_tag", json!("../v1.2.3")),
    ] {
        let mut v: Value = serde_json::from_slice(&bytes).unwrap();
        v["pointer"][field] = bad;
        assert!(ChannelEnvelope::decode(&encode(&v)).is_err());
    }
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    v["pointer"]["release"]["key"] = json!("cw/v1/releases/v1.2.4/release.json");
    assert!(ChannelEnvelope::decode(&encode(&v)).is_err());
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    v["signature"] = json!(true);
    assert!(ChannelEnvelope::decode(&encode(&v)).is_err());
}

#[test]
fn armored_signature_bounds_and_single_block_are_required() {
    let valid = b"-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n";
    validate_signature(valid).unwrap();
    assert!(validate_signature(&[valid.as_slice(), valid.as_slice()].concat()).is_err());
    assert!(validate_signature(&vec![b'x'; MAX_SIGNATURE_BYTES + 1]).is_err());
    assert!(validate_signature(b"not armor").is_err());
}

#[test]
fn stable_semver_order_is_numeric_and_rejects_equivocation() {
    let mut identity = manifest().targets[3].identity.clone();
    for (current, offered, ordering) in [
        ("v1.2.3-rc.2", "v1.2.3-rc.10", Ordering::Greater),
        ("v1.2.3-alpha.1", "v1.2.3-alpha.beta", Ordering::Greater),
        ("v1.2.3-rc.1", "v1.2.3", Ordering::Greater),
        ("v2.0.0", "v1.99.99", Ordering::Less),
        ("1.2.3+local", "v1.2.3", Ordering::Equal),
    ] {
        assert_eq!(
            Semver::parse(offered)
                .unwrap()
                .compare(&Semver::parse(current).unwrap()),
            ordering
        );
        identity.package_version = offered.into();
        let result = guard_stable(Some((current, &identity.sha256)), &identity);
        assert_eq!(result.is_ok(), ordering != Ordering::Less);
    }
    identity.package_version = "v1.2.3".into();
    assert_eq!(
        guard_stable(Some(("v1.2.3", &"f".repeat(64))), &identity),
        Err(ReleaseError::Equivocation)
    );
    guard_stable(None, &identity).unwrap();
    for invalid in ["v01.2.3", "v1.2.3-01", "v1.2.3-", "development"] {
        assert_eq!(
            guard_stable(Some((invalid, &identity.sha256)), &identity),
            Err(ReleaseError::VersionOrder)
        );
    }
}
