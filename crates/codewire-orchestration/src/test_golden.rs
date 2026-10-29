//! The sandbox rendering goldens in `tests/fixtures/sandbox`, and a bless
//! mode to regenerate them.
//!
//! A test compares a render with its golden by value. When a render changes
//! on purpose, rerun the tests with `CODEWIRE_BLESS_GOLDENS=1` to rewrite
//! every golden whose value differs, then review the diff:
//!
//! ```sh
//! CODEWIRE_BLESS_GOLDENS=1 cargo test -p codewire-orchestration --lib golden
//! ```
//!
//! Blessing rewrites only goldens whose value changed, as pretty JSON with a
//! final newline, and refuses to run in CI, where a golden must be compared,
//! never written.

use std::path::PathBuf;

use serde_json::Value;

const BLESS: &str = "CODEWIRE_BLESS_GOLDENS";

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sandbox")
        .join(name)
}

fn blessing() -> bool {
    match std::env::var(BLESS).as_deref() {
        Ok("1") => {
            assert!(
                std::env::var_os("CI").is_none() && std::env::var_os("GITHUB_ACTIONS").is_none(),
                "{BLESS} rewrites goldens; CI compares them and never writes"
            );
            true
        }
        Ok("") | Err(_) => false,
        Ok(other) => panic!("{BLESS} is 1 or unset, not {other:?}"),
    }
}

/// Fails unless `actual` equals the golden `name`; with
/// `CODEWIRE_BLESS_GOLDENS=1`, rewrites the golden to `actual` instead.
#[track_caller]
pub(crate) fn assert_golden(name: &str, actual: &Value) {
    compare_or_bless(&path(name), actual, blessing());
}

#[track_caller]
fn compare_or_bless(path: &std::path::Path, actual: &Value, bless: bool) {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let expected = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    if expected.as_ref() == Some(actual) {
        return;
    }
    if bless {
        let mut text = serde_json::to_string_pretty(actual).expect("a rendered value is JSON");
        text.push('\n');
        std::fs::write(path, text).unwrap_or_else(|error| panic!("bless golden {name}: {error}"));
        eprintln!("blessed golden {name}");
        return;
    }
    assert_eq!(
        Some(actual),
        expected.as_ref(),
        "the render drifted from golden {name}; if that is intended, rerun with {BLESS}=1 and review the diff"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_golden_compares_by_value_and_blesses_only_a_drift() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("self-test.golden.json");
        std::fs::write(&file, "{\"a\":   1}").unwrap();
        // An equal value passes whatever its formatting, and blessing leaves
        // an equal golden's bytes alone.
        compare_or_bless(&file, &serde_json::json!({ "a": 1 }), false);
        compare_or_bless(&file, &serde_json::json!({ "a": 1 }), true);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"a\":   1}");
        // A drift fails and names the bless mode.
        let drift = std::panic::catch_unwind(|| {
            compare_or_bless(&file, &serde_json::json!({ "a": 2 }), false);
        })
        .expect_err("a drifted render passed its golden");
        let message = drift.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.contains("CODEWIRE_BLESS_GOLDENS=1"), "{message}");
        // Blessing rewrites it as pretty JSON, after which it compares equal.
        compare_or_bless(&file, &serde_json::json!({ "a": 2 }), true);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "{\n  \"a\": 2\n}\n"
        );
        compare_or_bless(&file, &serde_json::json!({ "a": 2 }), false);
    }
}
