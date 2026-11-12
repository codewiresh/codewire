use std::path::Path;
use std::process::Command;

use super::{
    CHECKOUT_PREPARATION, NESTED_CHECKOUT_GUARD, NESTED_CHECKOUT_TRACKED_EXIT,
    WORKSPACE_ROOT_NOT_EMPTY_EXIT,
};

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

fn prepare(dir: &Path, root: &Path) -> Option<i32> {
    Command::new("sh")
        .args(["-c", CHECKOUT_PREPARATION, "sh"])
        .arg(dir)
        .arg(root)
        .status()
        .unwrap()
        .code()
}

/// #4027: the workspace root is never removed or emptied before a clone. A
/// repository there needs it empty already; with anything in it the
/// preparation refuses and leaves every file where it was.
#[test]
fn the_workspace_root_is_refused_with_content_and_never_cleaned() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    std::fs::create_dir(&root).unwrap();

    assert_eq!(prepare(&root, &root), Some(0), "an empty root is ready");
    assert!(root.is_dir(), "an empty root is kept, not removed");

    std::fs::create_dir(root.join(".codewire")).unwrap();
    std::fs::write(root.join(".codewire/keep"), "the user's\n").unwrap();
    std::fs::write(root.join(".gitconfig"), "[user]\n").unwrap();
    assert_eq!(
        prepare(&root, &root),
        Some(WORKSPACE_ROOT_NOT_EMPTY_EXIT),
        "a root with content is refused"
    );
    assert_eq!(
        std::fs::read_to_string(root.join(".codewire/keep")).unwrap(),
        "the user's\n"
    );
    assert!(root.join(".gitconfig").is_file());

    // Any other destination is an earlier attempt's checkout: removed.
    let checkout = root.join("app");
    std::fs::create_dir_all(checkout.join("partial")).unwrap();
    std::fs::write(checkout.join("partial/file"), "x\n").unwrap();
    assert_eq!(prepare(&checkout, &root), Some(0));
    assert!(!checkout.exists());
    assert_eq!(prepare(&checkout, &root), Some(0), "an absent one is fine");
    assert!(
        root.join(".codewire/keep").is_file(),
        "the root is untouched"
    );
}
