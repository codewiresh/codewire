#![forbid(unsafe_code)]

//! The build-time check behind every crate that generates protobuf types
//! with prost (#5034).
//!
//! prost ignores the `debug_redact` field option: its derived `Debug` prints
//! a marked field. Such a crate names each message that holds a marked field
//! in `skip_debug`, which leaves the message and its oneof enums without
//! `Debug`, and writes a redacting one by hand where one is needed.
//! [`require_covered`] fails the build when a marked message is missing from
//! that list, so the next secret field cannot be printed by an oversight.

use std::collections::BTreeSet;
use std::path::Path;

use prost::Message;

// prost-types' `FieldOptions` has no `debug_redact` field and would drop the
// option, so the descriptor is read through these. They carry only the
// fields the check needs; prost skips the rest.

#[derive(Clone, PartialEq, Message)]
struct FileDescriptorSet {
    #[prost(message, repeated, tag = "1")]
    file: Vec<FileDescriptorProto>,
}

#[derive(Clone, PartialEq, Message)]
struct FileDescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    package: Option<String>,
    #[prost(message, repeated, tag = "4")]
    message_type: Vec<DescriptorProto>,
}

#[derive(Clone, PartialEq, Message)]
struct DescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    /// Every field, a oneof's members included.
    #[prost(message, repeated, tag = "2")]
    field: Vec<FieldDescriptorProto>,
    #[prost(message, repeated, tag = "3")]
    nested_type: Vec<DescriptorProto>,
}

#[derive(Clone, PartialEq, Message)]
struct FieldDescriptorProto {
    #[prost(message, optional, tag = "8")]
    options: Option<FieldOptions>,
}

#[derive(Clone, PartialEq, Message)]
struct FieldOptions {
    #[prost(bool, optional, tag = "16")]
    debug_redact: Option<bool>,
}

/// The fully qualified names (`.package.Message`) of the messages defined in
/// one of `compiled` that hold a `debug_redact` field and that no path in
/// `skip_debug` covers.
///
/// `descriptor_set` is protoc's output as `file_descriptor_set_path` writes
/// it, imports included; `compiled` names the files the crate generates, as
/// the descriptor names them (relative to their include root). A path covers
/// a message when it names it or one of the messages it is nested in.
pub fn uncovered(
    descriptor_set: &[u8],
    compiled: &[&str],
    skip_debug: &[&str],
) -> Result<BTreeSet<String>, prost::DecodeError> {
    let set = FileDescriptorSet::decode(descriptor_set)?;
    let mut marked = BTreeSet::new();
    for file in &set.file {
        if !compiled.contains(&file.name.as_deref().unwrap_or_default()) {
            continue;
        }
        let package = match file.package.as_deref() {
            Some(package) if !package.is_empty() => format!(".{package}"),
            _ => String::new(),
        };
        for message in &file.message_type {
            collect_marked(&package, message, &mut marked);
        }
    }
    marked.retain(|message| !skip_debug.iter().any(|path| covers(path, message)));
    Ok(marked)
}

fn collect_marked(scope: &str, message: &DescriptorProto, marked: &mut BTreeSet<String>) {
    let name = format!("{scope}.{}", message.name.as_deref().unwrap_or_default());
    let redacts = message.field.iter().any(|field| {
        field
            .options
            .as_ref()
            .and_then(|options| options.debug_redact)
            == Some(true)
    });
    for nested in &message.nested_type {
        collect_marked(&name, nested, marked);
    }
    if redacts {
        marked.insert(name);
    }
}

fn covers(path: &str, message: &str) -> bool {
    message
        .strip_prefix(path)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Fails the build script unless every message with a `debug_redact` field
/// in `compiled` is covered by `skip_debug` (see [`uncovered`]).
///
/// # Panics
///
/// When the descriptor set cannot be read or decoded, or a marked message is
/// not covered.
pub fn require_covered(descriptor_set: &Path, compiled: &[&str], skip_debug: &[&str]) {
    let bytes = std::fs::read(descriptor_set)
        .unwrap_or_else(|error| panic!("read {}: {error}", descriptor_set.display()));
    let missing = uncovered(&bytes, compiled, skip_debug)
        .unwrap_or_else(|error| panic!("decode {}: {error}", descriptor_set.display()));
    assert!(
        missing.is_empty(),
        "these messages have a field marked debug_redact, which prost's derived Debug would \
         print: {}. Add each to this build script's skip_debug list; if it needs Debug, write one \
         for it, and for its oneof enums, that prints [REDACTED] in place of the field (#5034).",
        missing.into_iter().collect::<Vec<_>>().join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPILED: &[&str] = &["a/v1/a.proto"];

    fn field(debug_redact: Option<bool>) -> FieldDescriptorProto {
        FieldDescriptorProto {
            options: Some(FieldOptions { debug_redact }),
        }
    }

    fn message(
        name: &str,
        field: Vec<FieldDescriptorProto>,
        nested_type: Vec<DescriptorProto>,
    ) -> DescriptorProto {
        DescriptorProto {
            name: Some(name.to_owned()),
            field,
            nested_type,
        }
    }

    fn set(files: Vec<(&str, Vec<DescriptorProto>)>) -> Vec<u8> {
        FileDescriptorSet {
            file: files
                .into_iter()
                .map(|(name, message_type)| FileDescriptorProto {
                    name: Some(name.to_owned()),
                    package: Some("a.v1".to_owned()),
                    message_type,
                })
                .collect(),
        }
        .encode_to_vec()
    }

    fn names(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_marked_message_no_path_covers_is_reported() {
        let set = set(vec![(
            "a/v1/a.proto",
            vec![
                message("Login", vec![field(None), field(Some(true))], vec![]),
                message("Plain", vec![field(None), field(Some(false))], vec![]),
            ],
        )]);
        assert_eq!(
            uncovered(&set, COMPILED, &[".a.v1.Plain"]).unwrap(),
            names(&[".a.v1.Login"])
        );
        assert!(
            uncovered(&set, COMPILED, &[".a.v1.Login"])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_path_covers_the_messages_nested_in_the_one_it_names() {
        let set = set(vec![(
            "a/v1/a.proto",
            vec![message(
                "Outer",
                vec![field(None)],
                vec![message("Inner", vec![field(Some(true))], vec![])],
            )],
        )]);
        assert!(
            uncovered(&set, COMPILED, &[".a.v1.Outer"])
                .unwrap()
                .is_empty()
        );
        assert!(
            uncovered(&set, COMPILED, &[".a.v1.Outer.Inner"])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            uncovered(&set, COMPILED, &[".a.v1.Out"]).unwrap(),
            names(&[".a.v1.Outer.Inner"])
        );
    }

    #[test]
    fn an_imported_file_the_crate_does_not_generate_is_not_checked() {
        let set = set(vec![(
            "b/v1/b.proto",
            vec![message("Login", vec![field(Some(true))], vec![])],
        )]);
        assert!(uncovered(&set, COMPILED, &[]).unwrap().is_empty());
    }

    #[test]
    fn the_option_is_read_from_field_options_field_16() {
        // descriptor.proto: `optional bool debug_redact = 16;`, a varint
        // whose key is 16 << 3 = 128.
        let options = FieldOptions::decode([0x80, 0x01, 0x01].as_slice()).unwrap();
        assert_eq!(options.debug_redact, Some(true));
    }
}
