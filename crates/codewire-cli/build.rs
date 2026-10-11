//! Embed this cw's closed build record.
//!
//! The record names the effective compiled version, the Cargo target, the
//! compiler that built the crate and, only when the caller supplies both,
//! the source revision and source-tree digest. It never runs Git or reads the
//! working tree: a build without explicit provenance records `null` and
//! cannot self-install. The executable's own digest and size are computed
//! outside its bytes and are never part of the record.
//!
//! Layout: a unique marker, the JSON length as a little-endian `u32`, then
//! canonical JSON (sorted keys, compact, ASCII, one trailing newline).

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Marker that occurs exactly once in a cw executable. Only this script and
/// external admission tools spell it out; cw itself never repeats it.
const MAGIC: &[u8] = b"\0codewire-cw-build-record-v1\0";
const MAX_JSON: usize = 1024;
const MAX_VERSION: usize = 64;
const MAX_TARGET: usize = 64;
const MAX_RUSTC: usize = 128;

fn fail(message: &str) -> ! {
    panic!("cw build record: {message}");
}

fn input(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => fail(&format!("{name} is not UTF-8")),
    }
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Printable ASCII that canonical JSON encodes without escapes.
fn plain(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\')
}

fn quoted(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""))
}

fn main() {
    for name in [
        "CODEWIRE_VERSION",
        "CODEWIRE_SOURCE_REVISION",
        "CODEWIRE_SOURCE_TREE_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");

    // An explicit CODEWIRE_VERSION is the effective version; otherwise the
    // workspace package version, as `cw --version` has always reported.
    let version = input("CODEWIRE_VERSION")
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").expect("Cargo package version"));
    let valid_version = !version.is_empty()
        && version.len() <= MAX_VERSION
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'));
    if !valid_version {
        fail("CODEWIRE_VERSION must be 1-64 ASCII letters, digits, '.', '-' or '+'");
    }

    let source = match (
        input("CODEWIRE_SOURCE_REVISION"),
        input("CODEWIRE_SOURCE_TREE_SHA256"),
    ) {
        (Some(revision), Some(tree)) => {
            if !lower_hex(&revision, 40) || !lower_hex(&tree, 64) {
                fail(
                    "CODEWIRE_SOURCE_REVISION and CODEWIRE_SOURCE_TREE_SHA256 must be \
                     lowercase 40- and 64-digit hex",
                );
            }
            Some((revision, tree))
        }
        (None, None) => None,
        _ => {
            fail("supply both CODEWIRE_SOURCE_REVISION and CODEWIRE_SOURCE_TREE_SHA256, or neither")
        }
    };

    let target = env::var("TARGET").expect("Cargo target");
    if target.is_empty()
        || target.len() > MAX_TARGET
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        fail("Cargo target is not a plain target triple");
    }

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(&rustc)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| fail(&format!("run the compiler for its version: {error}")));
    let rustc = String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| {
            output.status.success()
                && text.starts_with("rustc ")
                && text.len() <= MAX_RUSTC
                && plain(text)
        })
        .unwrap_or_else(|| fail("the compiler did not report a plain `rustc` version"));

    let (revision, tree) = match &source {
        Some((revision, tree)) => (Some(revision.as_str()), Some(tree.as_str())),
        None => (None, None),
    };
    let json = format!(
        "{{\"package_version\":\"{version}\",\"rustc\":\"{rustc}\",\"source_revision\":{},\
         \"source_tree_sha256\":{},\"target\":\"{target}\"}}\n",
        quoted(revision),
        quoted(tree),
    );
    if json.len() > MAX_JSON {
        fail("record exceeds its bound");
    }
    let json_start = MAGIC.len() + 4;
    let mut record = MAGIC.to_vec();
    record.extend_from_slice(&u32::try_from(json.len()).expect("bounded").to_le_bytes());
    record.extend_from_slice(json.as_bytes());

    let version_start = json_start + "{\"package_version\":\"".len();
    let mut bytes = String::new();
    for byte in &record {
        let _ = write!(bytes, "{byte:#04x},");
    }
    let generated = format!(
        "// @generated by crates/codewire-cli/build.rs\n\
         #[used]\n\
         pub(crate) static BUILD_RECORD: [u8; {}] = [{bytes}];\n\
         const BUILD_RECORD_JSON: usize = {json_start};\n\
         const PACKAGE_VERSION_TEXT: (usize, usize) = ({version_start}, {});\n",
        record.len(),
        version_start + version.len(),
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    fs::write(out.join("build_record.rs"), generated)
        .unwrap_or_else(|error| fail(&format!("write the generated record: {error}")));

    embed_local_runtime(&out, revision);
}

/// Largest canonical runtime document; the same bound as release documents.
const MAX_LOCAL_RUNTIME: usize = 64 * 1024;

/// Embed the release's local VM runtime document when the release pipeline
/// supplies `CODEWIRE_LOCAL_RUNTIME` (#2539). Its digests pin the runtime
/// `cw setup --local` downloads, covered by the trust already placed in this
/// cw. A build without it embeds nothing and installs only `--from DIR`.
/// cw decodes the embedded bytes strictly before any use.
fn embed_local_runtime(out: &std::path::Path, revision: Option<&str>) {
    println!("cargo:rerun-if-env-changed=CODEWIRE_LOCAL_RUNTIME");
    let bytes = match input("CODEWIRE_LOCAL_RUNTIME") {
        None => Vec::new(),
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                fail("CODEWIRE_LOCAL_RUNTIME must be an absolute path");
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| fail(&format!("read CODEWIRE_LOCAL_RUNTIME: {error}")));
            if bytes.is_empty()
                || bytes.len() > MAX_LOCAL_RUNTIME
                || !bytes.is_ascii()
                || !bytes.ends_with(b"}\n")
            {
                fail("CODEWIRE_LOCAL_RUNTIME is not a bounded canonical document");
            }
            // A canonical document spells its revision exactly once, and the
            // runtime's guest root must come from this cw's own source.
            let Some(revision) = revision else {
                fail("a pinned local runtime needs CODEWIRE_SOURCE_REVISION");
            };
            let needle = format!("\"source_revision\":\"{revision}\"");
            let text = String::from_utf8(bytes.clone()).expect("ASCII");
            if text.matches(&needle).count() != 1 {
                fail("CODEWIRE_LOCAL_RUNTIME was built from another source revision");
            }
            bytes
        }
    };
    let document = out.join("local_runtime.json");
    fs::write(&document, &bytes)
        .unwrap_or_else(|error| fail(&format!("write the local runtime document: {error}")));
    let generated = format!(
        "// @generated by crates/codewire-cli/build.rs\n\
         pub(crate) static LOCAL_RUNTIME: &[u8] = include_bytes!({:?});\n",
        document.display().to_string()
    );
    fs::write(out.join("local_runtime.rs"), generated)
        .unwrap_or_else(|error| fail(&format!("write the generated runtime pin: {error}")));
}
