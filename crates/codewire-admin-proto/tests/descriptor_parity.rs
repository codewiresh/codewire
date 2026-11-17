//! Holds the descriptor sets this build compiled from `proto/` to the pinned
//! buf's (#4950).
//!
//! The proto crates' build scripts compile their descriptor sets with a Rust
//! compiler, so nothing checked in can drift from the protos. What can still
//! go wrong is that compiler and the pinned toolchain, which generates the
//! other languages, disagreeing about a proto. Its first case: taken through
//! the compiler's typed form, `debug_redact` is dropped, and the generated
//! `Debug` prints the 39 fields it marks.
//!
//! CI's contracts job builds the reference set and runs these:
//! `CODEWIRE_BUF_DESCRIPTOR_SET=FILE cargo test -p codewire-admin-proto
//! --test descriptor_parity -- --ignored`. They live in this crate because
//! it is the one contract crate that may depend on the other.

use std::collections::BTreeMap;
use std::path::Path;

use prost_reflect::{DescriptorPool, DynamicMessage, Value};

/// A crate's name, the set its build compiled, and the files it generates
/// from.
const BUILT: [(&str, &[u8], &str); 2] = [
    (
        "codewire-proto",
        codewire_proto::FILE_DESCRIPTOR_SET,
        codewire_proto::PROTO_FILES,
    ),
    (
        "codewire-admin-proto",
        codewire_admin_proto::FILE_DESCRIPTOR_SET,
        codewire_admin_proto::PROTO_FILES,
    ),
];

const REFERENCE: &str = "CODEWIRE_BUF_DESCRIPTOR_SET";

fn reference() -> Vec<u8> {
    let path = std::env::var_os(REFERENCE).unwrap_or_else(|| {
        panic!("{REFERENCE} must name a descriptor set built by the pinned buf")
    });
    std::fs::read(&path).expect("read the reference descriptor set")
}

/// A set's files by name, without their source positions and comments.
fn files(set: &[u8]) -> BTreeMap<String, DynamicMessage> {
    let descriptor = DescriptorPool::global()
        .get_message_by_name("google.protobuf.FileDescriptorSet")
        .expect("the descriptor of a descriptor set");
    let set = DynamicMessage::decode(descriptor, set).expect("decode a descriptor set");
    let files = set.get_field_by_name("file").expect("a set has files");
    files
        .as_list()
        .expect("files are a list")
        .iter()
        .map(|file| {
            let mut file = file.as_message().expect("a file is a message").clone();
            file.clear_field_by_name("source_code_info");
            let name = match file
                .get_field_by_name("name")
                .expect("a file has a name")
                .as_ref()
            {
                Value::String(name) => name.clone(),
                other => panic!("a file's name is {other:?}"),
            };
            (name, file)
        })
        .collect()
}

/// The Rust `connectrpc-build` generates from `set` for `names`, with the
/// options the crates' build scripts give it, by generated file name.
fn generated(set: &[u8], names: &[&str]) -> BTreeMap<String, String> {
    let directory = tempfile::tempdir().expect("a scratch directory");
    let descriptor_set = directory.path().join("set.bin");
    std::fs::write(&descriptor_set, set).expect("write a descriptor set");
    let out = directory.path().join("out");
    std::fs::create_dir(&out).expect("an output directory");
    connectrpc_build::Config::new()
        .files(names)
        .descriptor_set(&descriptor_set)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .emit_rerun_directives(false)
        .out_dir(&out)
        .compile()
        .expect("generate from a descriptor set");
    read_all(&out)
}

fn read_all(directory: &Path) -> BTreeMap<String, String> {
    std::fs::read_dir(directory)
        .expect("list the generated files")
        .map(|entry| {
            let entry = entry.expect("a generated file");
            let name = entry.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(entry.path()).expect("read a generated file");
            (name, text)
        })
        .collect()
}

/// The first line on which two texts differ, for a failure a reader can act
/// on.
fn first_difference(built: &str, pinned: &str) -> String {
    let mut pinned_lines = pinned.lines();
    for (number, line) in built.lines().enumerate() {
        match pinned_lines.next() {
            Some(other) if other == line => {}
            other => {
                return format!(
                    "line {}: built `{line}`, pinned buf `{}`",
                    number + 1,
                    other.unwrap_or("<no such line>")
                );
            }
        }
    }
    "the pinned buf's has more lines".to_owned()
}

#[test]
#[ignore = "needs a descriptor set built by the pinned buf; CI's contracts job runs it"]
fn the_built_descriptor_sets_equal_the_pinned_bufs_once_source_positions_are_dropped() {
    let reference = files(&reference());
    for (crate_name, built, _) in BUILT {
        let built = files(built);
        assert!(!built.is_empty(), "{crate_name}: the built set is empty");
        for (name, file) in built {
            let pinned = reference
                .get(&name)
                .unwrap_or_else(|| panic!("{crate_name}: the pinned buf has no {name}"));
            assert!(
                &file == pinned,
                "{crate_name}: {name} differs from the pinned buf's descriptor"
            );
        }
    }
}

#[test]
#[ignore = "needs a descriptor set built by the pinned buf; CI's contracts job runs it"]
fn the_built_descriptor_sets_generate_the_same_rust_as_the_pinned_bufs() {
    let reference = reference();
    for (crate_name, built, names) in BUILT {
        let names: Vec<&str> = names.split(',').collect();
        let (from_built, from_pinned) = (generated(built, &names), generated(&reference, &names));
        assert!(
            from_built.len() > names.len(),
            "{crate_name}: {} files were generated for {} protos",
            from_built.len(),
            names.len()
        );
        assert_eq!(
            from_built.keys().collect::<Vec<_>>(),
            from_pinned.keys().collect::<Vec<_>>(),
            "{crate_name}: the two sets generate different files"
        );
        for (file, text) in &from_built {
            assert!(
                text == &from_pinned[file],
                "{crate_name}: {file} is generated differently from the pinned buf's descriptor: {}",
                first_difference(text, &from_pinned[file])
            );
        }
    }
}
