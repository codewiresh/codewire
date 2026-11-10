use std::path::Path;
use std::process::Command;

use super::{NESTED_CHECKOUT_GUARD, NESTED_CHECKOUT_TRACKED_EXIT};

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn guard(parent: &Path, relative: &str) -> Option<i32> {
    Command::new("sh")
        .args(["-c", NESTED_CHECKOUT_GUARD, "sh"])
        .arg(parent)
        .arg(relative)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap()
        .code()
}

#[test]
fn the_guard_refuses_tracked_paths_and_excludes_a_nested_checkout() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("root");
    std::fs::create_dir_all(parent.join("docs")).unwrap();
    std::fs::write(parent.join("docs/README.md"), "tracked\n").unwrap();
    std::fs::write(parent.join("tools"), "a file\n").unwrap();
    git(&parent, &["init", "-q", "--template="]);
    git(&parent, &["add", "docs", "tools"]);
    git(
        &parent,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "parent",
        ],
    );

    for tracked in ["docs", "docs/README.md", "tools/inner"] {
        assert_eq!(
            guard(&parent, tracked),
            Some(NESTED_CHECKOUT_TRACKED_EXIT),
            "{tracked}"
        );
    }
    assert_eq!(guard(&parent, "child"), Some(0));
    std::fs::create_dir_all(parent.join("child/.git")).unwrap();
    std::fs::write(parent.join("child/file"), "child\n").unwrap();
    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(&parent)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        status.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&status.stdout)
    );

    // Without a checked-out parent the guard fails, but not as "tracked".
    let empty = temp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let code = guard(&empty, "child");
    assert!(
        code.is_some_and(|code| code != 0 && code != NESTED_CHECKOUT_TRACKED_EXIT),
        "{code:?}"
    );
}
