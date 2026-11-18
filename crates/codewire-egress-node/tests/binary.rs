//! The built `cw-egress` treats anything that looks like a child command
//! word as a child, and a child never becomes the supervisor.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Stdio};

const POD: &str = "0b0f7d1e-6c1c-4a55-9a5e-0d6d8c2f1a11";

fn cw_egress(arguments: &[&str]) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_cw-egress"))
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
}

#[test]
fn a_mistyped_child_word_is_a_usage_error() {
    assert_eq!(cw_egress(&["__egress-brokr", "--pod-uid", POD]), Some(64));
    assert_eq!(cw_egress(&["__egress-worker"]), Some(64));
}

#[test]
fn a_child_started_without_its_sockets_fails_as_that_child() {
    // No supervisor gave these their inherited sockets, so each fails at
    // its own first step with its own code, not the usage error and not 0.
    for word in ["__egress-broker", "__egress-worker"] {
        let code = cw_egress(&[word, "--pod-uid", POD]);
        assert!(
            matches!(code, Some(code) if code != 0 && code != 64),
            "{word}: {code:?}"
        );
    }
}
