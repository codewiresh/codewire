use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::*;

fn config(home_root: PathBuf) -> Config {
    Config {
        interception: None,
        listen_addr: "127.0.0.1:0".into(),
        workspace_root: home_root.clone(),
        home_root,
        mount_roots: Vec::new(),
        auth_token: crate::DaemonAuthToken::new("shared-repositories-test-token").unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
        session_working_dir: None,
        sandbox_server_url: None,
    }
}

/// A synthetic daemon environment whose `HOME` is the test's own directory,
/// never the home the test runs in.
fn environment(home: &Path) -> Vec<(String, String)> {
    vec![
        ("HOME".to_owned(), home.display().to_string()),
        (
            "PATH".to_owned(),
            std::env::var("PATH").expect("the test has a PATH"),
        ),
    ]
}

async fn trust(home: &Path) -> Result<(), &'static str> {
    trust_within(
        &config(home.to_path_buf()),
        Duration::ZERO,
        environment(home),
    )
    .await
}

/// `git config --global` as the test home's own Git reads it.
fn global(home: &Path, arguments: &[&str]) -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["config", "--global"])
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var("PATH").unwrap())
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn the_product_file_trusts_every_repository_through_one_include() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    trust(home).await.unwrap();
    let file = home.join(".codewire/gitconfig");
    let contents = fs::read_to_string(&file).unwrap();
    assert!(
        contents.starts_with("# Codewire rewrites this file"),
        "{contents}"
    );
    assert!(contents.contains("[safe]\n\tdirectory = *\n"), "{contents}");
    assert_eq!(
        global(home, &["--get-all", "include.path"]),
        [file.display().to_string()]
    );
    assert_eq!(
        global(home, &["--includes", "--get-all", "safe.directory"]),
        ["*"]
    );
    // The global file itself holds no `safe.directory` of the product's.
    assert!(global(home, &["--no-includes", "--get-all", "safe.directory"]).is_empty());
}

#[tokio::test]
async fn a_second_boot_adds_nothing_and_a_users_own_lines_stay_as_written() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let own = "# mine\n[safe]\n\tdirectory = /mine\n[user]\n\tname = Synthetic Dev\n";
    fs::write(home.join(".gitconfig"), own).unwrap();
    trust(home).await.unwrap();
    trust(home).await.unwrap();
    let written = fs::read_to_string(home.join(".gitconfig")).unwrap();
    assert!(written.starts_with(own), "{written}");
    assert_eq!(global(home, &["--get-all", "include.path"]).len(), 1);
    assert_eq!(
        global(home, &["--no-includes", "--get-all", "safe.directory"]),
        ["/mine"]
    );
}

/// The write is the workload user's own, so a `~/.gitconfig` symlinked to a
/// file that user may not write leaves that file as it was (cw-security,
/// #5478). Meaningless as root, which may write anywhere.
#[tokio::test]
async fn a_symlinked_gitconfig_whose_target_the_user_may_not_write_stays_unchanged() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root may write the target");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let locked = temp.path().join("locked");
    fs::create_dir(&locked).unwrap();
    let target = locked.join("gitconfig");
    fs::write(&target, "[user]\n\tname = Someone Else\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    std::os::unix::fs::symlink(&target, home.join(".gitconfig")).unwrap();

    assert_eq!(trust(&home).await, Err("git refused"));
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "[user]\n\tname = Someone Else\n"
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
}

/// An image that gets Git only after boot: the include is appended without
/// `git`, once, and the Git installed later trusts the shares.
#[tokio::test]
async fn without_git_at_boot_the_include_is_appended_once_for_the_git_installed_later() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    for tool in ["mkdir", "mv", "grep"] {
        let path = which(tool);
        std::os::unix::fs::symlink(path, bin.join(tool)).unwrap();
    }
    let own = "[user]\n\tname = Synthetic Dev\n";
    fs::write(home.join(".gitconfig"), own).unwrap();
    let environment = vec![
        ("HOME".to_owned(), home.display().to_string()),
        ("PATH".to_owned(), bin.display().to_string()),
    ];
    for _ in 0..2 {
        trust_within(&config(home.clone()), Duration::ZERO, environment.clone())
            .await
            .unwrap();
    }
    let written = fs::read_to_string(home.join(".gitconfig")).unwrap();
    assert!(written.starts_with(own), "{written}");
    assert_eq!(global(&home, &["--get-all", "include.path"]).len(), 1);
    assert_eq!(
        global(&home, &["--includes", "--get-all", "safe.directory"]),
        ["*"]
    );
}

fn which(tool: &str) -> PathBuf {
    std::env::var("PATH")
        .unwrap()
        .split(':')
        .map(|directory| Path::new(directory).join(tool))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("the test host has no {tool}"))
}

#[tokio::test]
async fn without_the_basic_tools_the_attempt_fails_by_its_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let environment = vec![
        ("HOME".to_owned(), home.display().to_string()),
        ("PATH".to_owned(), "/nonexistent".to_owned()),
    ];
    let outcome = trust_within(&config(home.to_path_buf()), Duration::ZERO, environment).await;
    assert!(outcome.is_err(), "{outcome:?}");
}
