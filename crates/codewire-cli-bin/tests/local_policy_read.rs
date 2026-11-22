#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

//! A local `cw policy ls` is a read and starts nothing (docs/dev/CLI-PARITY.md,
//! P3): on a computer with no local VM state it lists the built-ins and
//! leaves no supervisor or store behind.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn cw(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cw"))
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Every file under `root`, as paths relative to it.
fn files(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    found
}

#[test]
fn a_local_policy_list_lists_the_built_ins_and_starts_nothing() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        &["--local", "policy", "ls"][..],
        &["policy", "ls"][..],
        &["--local", "policy", "ls", "--output", "json"][..],
    ] {
        let output = cw(home.path(), args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if args.contains(&"json") {
            assert_eq!(stdout.trim(), "[]", "{args:?}");
        } else {
            assert!(stdout.starts_with("open    built-in"), "{args:?}: {stdout}");
            assert!(stdout.contains("\nlocked  built-in"), "{args:?}: {stdout}");
        }
        let started: Vec<_> = files(home.path())
            .into_iter()
            .filter(|file| {
                [
                    "supervisor.db",
                    "supervisor.lock",
                    "supervisor.sock",
                    "network-policies.db",
                ]
                .iter()
                .any(|name| file.ends_with(name))
            })
            .collect();
        assert!(started.is_empty(), "{args:?} left {started:?}");
    }
}
