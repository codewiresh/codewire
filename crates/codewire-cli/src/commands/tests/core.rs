fn private_mesh_data_fixture() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[cfg(not(unix))]
    tempfile::tempdir().unwrap()
}

#[test]
fn member_mutation_flags_require_member_on_shared_session_commands() {
    for command in ["stop", "restart", "interrupt"] {
        let ordinary = Cli::try_parse_from(["cw", command, "session"]).unwrap();
        crate::validate_member_mutation_flags(&ordinary).unwrap();
        for (flag, value) in [
            ("--request-id", "00000000-0000-4000-8000-000000000001"),
            ("--expected-launch-generation", "1"),
        ] {
            let cli = Cli::try_parse_from(["cw", command, "session", flag, value]).unwrap();
            assert!(
                crate::validate_member_mutation_flags(&cli)
                    .unwrap_err()
                    .to_string()
                    .contains("member mutation flags require --member")
            );
        }
    }
    let member = Cli::try_parse_from([
        "cw",
        "stop",
        "--member",
        "build-linux",
        "session",
        "--request-id",
        "00000000-0000-4000-8000-000000000001",
        "--expected-launch-generation",
        "1",
    ])
    .unwrap();
    crate::validate_member_mutation_flags(&member).unwrap();

    // A member inbox is read-only: only the launch generation applies.
    let ordinary = Cli::try_parse_from(["cw", "inbox", "--session", "session"]).unwrap();
    crate::validate_member_mutation_flags(&ordinary).unwrap();
    let cli = Cli::try_parse_from([
        "cw",
        "inbox",
        "--session",
        "session",
        "--expected-launch-generation",
        "1",
    ])
    .unwrap();
    assert!(
        crate::validate_member_mutation_flags(&cli)
            .unwrap_err()
            .to_string()
            .contains("member mutation flags require --member")
    );
    assert!(
        Cli::try_parse_from([
            "cw",
            "inbox",
            "--session",
            "session",
            "--request-id",
            "00000000-0000-4000-8000-000000000001",
        ])
        .is_err()
    );
    for (flag, value) in [
        ("--request-id", "00000000-0000-4000-8000-000000000001"),
        ("--expected-launch-generation", "1"),
    ] {
        let cli = Cli::try_parse_from(["cw", "msg", "--session", "session", "text", flag, value])
            .unwrap();
        assert!(
            crate::validate_member_mutation_flags(&cli)
                .unwrap_err()
                .to_string()
                .contains("member mutation flags require --member")
        );
    }
}

#[test]
fn accepted_organization_deletion_is_not_reported_as_deleted() {
    let started = organization_deletion_started_message("op_test");
    let stopped = organization_deletion_polling_stopped_message("op_test");

    assert_eq!(
        started,
        "Organization deletion started (operation op_test)."
    );
    assert!(!started.to_ascii_lowercase().contains("deleted"));
    assert!(stopped.contains("server work continues"));
    assert!(!stopped.to_ascii_lowercase().contains("deleted"));
}

const TEST_CW: &str = "/opt/codewire/bin/cw";

fn ssh_test_options(ssh_options: &[&str]) -> SshConfigOptions {
    SshConfigOptions {
        cw_command: TEST_CW.to_string(),
        ssh_options: ssh_options
            .iter()
            .map(|option| option.to_string())
            .collect(),
    }
}

const CURRENT_MANAGED_SSH_BLOCK: &str = "# ---- START CODEWIRE ----
# This section is managed by Codewire. Re-run `cw setup ssh` to update it.
# It stays first in this file: OpenSSH uses the first value it finds for an option.
Host cw-local-*
    ProxyCommand /opt/codewire/bin/cw --local shell --stdio %n
    User codewire
    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /dev/null
    KnownHostsCommand /opt/codewire/bin/cw --local ssh known-hosts %H
    HostKeyAlgorithms ssh-ed25519
    UpdateHostKeys no
    ForwardAgent no
    ForwardX11 no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication no
    GSSAPIAuthentication no
    GSSAPIDelegateCredentials no
Host cw-cloud-*
    ProxyCommand /opt/codewire/bin/cw --cloud shell --stdio %n
    User codewire
    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /dev/null
    KnownHostsCommand /opt/codewire/bin/cw --cloud ssh known-hosts %H
    HostKeyAlgorithms ssh-ed25519
    UpdateHostKeys no
    ForwardAgent no
    ForwardX11 no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication no
    GSSAPIAuthentication no
    GSSAPIDelegateCredentials no
Host *
# ---- END CODEWIRE ----";

#[test]
fn managed_ssh_block_is_fail_closed_and_hardened() {
    assert_eq!(
        ssh_config_block(&ssh_test_options(&[])).unwrap(),
        CURRENT_MANAGED_SSH_BLOCK
    );
    assert_eq!(
        place_managed_ssh_section("", CURRENT_MANAGED_SSH_BLOCK).unwrap(),
        format!("{CURRENT_MANAGED_SSH_BLOCK}\n")
    );
}

#[test]
fn managed_ssh_block_replaces_an_old_first_use_block_and_goes_first() {
    let existing = [
        "Host *",
        "    ForwardAgent yes",
        "",
        "Host github.com",
        "    User git",
        "",
        SSH_CONFIG_MARKER_START,
        "Host cw-*",
        "    ProxyCommand cw shell --stdio %n",
        "    StrictHostKeyChecking accept-new",
        "    UserKnownHostsFile ~/.ssh/codewire_known_hosts",
        "    User codewire",
        SSH_CONFIG_MARKER_END,
        "",
        "Host other",
        "    User someone",
        "",
    ]
    .join("\n");

    let rendered = place_managed_ssh_section(
        &existing,
        &ssh_config_block(&ssh_test_options(&[])).unwrap(),
    )
    .unwrap();

    assert!(rendered.starts_with(&format!("{CURRENT_MANAGED_SSH_BLOCK}\n\nHost *\n")));
    assert!(!rendered.contains("accept-new"));
    assert!(!rendered.contains("codewire_known_hosts"));
    assert_eq!(rendered.matches(SSH_CONFIG_MARKER_START).count(), 1);
    // The user's own entries are kept, unchanged and in order.
    let user = rendered
        .strip_prefix(&format!("{CURRENT_MANAGED_SSH_BLOCK}\n\n"))
        .unwrap();
    assert_eq!(
        user,
        "Host *\n    ForwardAgent yes\n\nHost github.com\n    User git\n\n\nHost other\n    User someone\n"
    );
}

#[test]
fn managed_ssh_block_placement_is_idempotent() {
    let options = ssh_test_options(&["ServerAliveInterval 30"]);
    let block = ssh_config_block(&options).unwrap();
    let once = place_managed_ssh_section("Host other\n    User someone", &block).unwrap();
    let twice = place_managed_ssh_section(&once, &block).unwrap();
    assert_eq!(once, twice);
    assert!(once.contains("    ServerAliveInterval 30\nHost *\n"));
    // A user option applies to both managed host blocks.
    assert_eq!(once.matches("    ServerAliveInterval 30\n").count(), 2);
    assert!(once.contains("    ServerAliveInterval 30\nHost cw-cloud-*\n"));
}

#[test]
fn managed_ssh_block_refuses_options_that_would_weaken_it() {
    for option in [
        "ForwardAgent yes",
        "forwardagent=yes",
        "StrictHostKeyChecking=accept-new",
        "UserKnownHostsFile ~/.ssh/known_hosts",
        "KnownHostsCommand /bin/true",
        "PasswordAuthentication yes",
        "PubkeyAuthentication yes",
        "GSSAPIDelegateCredentials yes",
        "HostKeyAlias other",
        "ProxyJump bastion",
        "Host *",
        "Match all",
        "Include ~/.ssh/other",
    ] {
        let err = ssh_config_block(&ssh_test_options(&[option])).unwrap_err();
        assert!(
            err.to_string().contains("cannot be overridden"),
            "{option}: {err}"
        );
    }
    let err = ssh_config_block(&ssh_test_options(&[
        "ServerAliveInterval 30\nForwardAgent yes",
    ]))
    .unwrap_err();
    assert!(err.to_string().contains("single line"));
}

#[test]
fn remove_managed_ssh_section_rejects_incomplete_markers() {
    let err = place_managed_ssh_section(SSH_CONFIG_MARKER_START, "managed").unwrap_err();

    assert!(
        err.to_string()
            .contains("malformed ssh config: Codewire markers are incomplete")
    );
}

/// OpenSSH itself accepts every managed directive and resolves the
/// hardening for Codewire hosts even when the user's own config says
/// otherwise, while other hosts keep the user's settings. Needs OpenSSH
/// 8.5 or later (KnownHostsCommand); skipped where `ssh` is absent.
#[test]
fn openssh_resolves_the_managed_block_first() {
    if std::process::Command::new("ssh")
        .arg("-V")
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("ssh not installed; skipping OpenSSH resolution check");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    fs::write(
            &config_path,
            "Host *\n    ForwardAgent yes\n    PasswordAuthentication yes\n    StrictHostKeyChecking no\n",
        )
        .unwrap();
    let outcome = install_managed_ssh_config(
        SshConfigFile::resolve(Some(config_path.clone())).unwrap(),
        &ssh_test_options(&[]),
        false,
    )
    .unwrap();
    assert_eq!(outcome.change, SshConfigChange::Written);

    let resolve = |host: &str| {
        let output = std::process::Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(&config_path)
            .arg(host)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh -G {host}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    // A qualified alias takes its own block's commands, which pass its
    // placement. The bare `cw-<ref>` is retired: no managed block applies.
    let local = resolve("cw-local-demo");
    for (keyword, value) in [
        ("proxycommand", "/opt/codewire/bin/cw --local shell --stdio %n"),
        (
            "knownhostscommand",
            "/opt/codewire/bin/cw --local ssh known-hosts %H",
        ),
        ("forwardagent", "no"),
    ] {
        assert!(
            local.lines().any(|line| line == format!("{keyword} {value}")),
            "cw-local-demo {keyword}:\n{local}"
        );
    }
    let cloud = resolve("cw-cloud-demo");
    for (keyword, value) in [
        ("proxycommand", "/opt/codewire/bin/cw --cloud shell --stdio %n"),
        (
            "knownhostscommand",
            "/opt/codewire/bin/cw --cloud ssh known-hosts %H",
        ),
        ("forwardagent", "no"),
    ] {
        assert!(
            cloud.lines().any(|line| line == format!("{keyword} {value}")),
            "cw-cloud-demo {keyword}:\n{cloud}"
        );
    }
    let bare = resolve("cw-demo");
    assert!(
        !bare.lines().any(|line| line.starts_with("proxycommand ")
            && line.contains("/opt/codewire/bin/cw")),
        "cw-demo must not reach a managed block:\n{bare}"
    );
    let codewire = cloud;
    // OpenSSH versions spell some booleans differently (`no` or `false`).
    for (keyword, accepted) in [
        (
            "proxycommand",
            &["/opt/codewire/bin/cw --cloud shell --stdio %n"][..],
        ),
        ("user", &["codewire"]),
        ("stricthostkeychecking", &["true", "yes"]),
        ("userknownhostsfile", &["/dev/null"]),
        ("globalknownhostsfile", &["/dev/null"]),
        (
            "knownhostscommand",
            &["/opt/codewire/bin/cw --cloud ssh known-hosts %H"],
        ),
        ("updatehostkeys", &["false", "no"]),
        ("forwardagent", &["no", "false"]),
        ("forwardx11", &["no", "false"]),
        ("passwordauthentication", &["no", "false"]),
        ("kbdinteractiveauthentication", &["no", "false"]),
        ("pubkeyauthentication", &["no", "false"]),
        ("gssapiauthentication", &["no", "false"]),
        ("gssapidelegatecredentials", &["no", "false"]),
    ] {
        let value = codewire
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{keyword} ")))
            .unwrap_or_else(|| panic!("ssh -G printed no {keyword}:\n{codewire}"));
        assert!(
            accepted.contains(&value),
            "{keyword} resolved to {value:?}, expected one of {accepted:?}"
        );
    }
    let other = resolve("other.example");
    assert!(other.lines().any(|line| line == "forwardagent yes"));
    assert!(
        other
            .lines()
            .any(|line| line == "passwordauthentication yes")
    );
    assert!(
        !other
            .lines()
            .any(|line| line.starts_with("knownhostscommand"))
    );
}

/// OpenSSH runs `KnownHostsCommand` only from an absolute path, and an
/// editor's Remote-SSH may start `ssh` without the user's `PATH`, so both
/// commands name `cw` absolutely.
#[test]
fn managed_ssh_block_runs_cw_from_an_absolute_path() {
    let block = ssh_config_block(&ssh_test_options(&[])).unwrap();
    for keyword in ["ProxyCommand", "KnownHostsCommand"] {
        let value = block
            .lines()
            .find_map(|line| line.trim_start().strip_prefix(&format!("{keyword} ")))
            .unwrap_or_else(|| panic!("no {keyword} in\n{block}"));
        assert!(
            value.starts_with(&format!("{TEST_CW} ")),
            "{keyword} {value}"
        );
    }
    assert!(current_cw_executable().unwrap().is_absolute());
    let rendered = ssh_cw_command(&current_cw_executable().unwrap()).unwrap();
    assert!(rendered.trim_start_matches('"').starts_with('/'));
}

#[test]
fn ssh_cw_command_escapes_tokens_and_quotes_whitespace() {
    assert_eq!(
        ssh_cw_command(std::path::Path::new("/usr/local/bin/cw")).unwrap(),
        "/usr/local/bin/cw"
    );
    assert_eq!(
        ssh_cw_command(std::path::Path::new("/Users/a b/bin/cw")).unwrap(),
        "\"/Users/a b/bin/cw\""
    );
    assert_eq!(
        ssh_cw_command(std::path::Path::new("/opt/100%/cw")).unwrap(),
        "/opt/100%%/cw"
    );
    let err = ssh_cw_command(std::path::Path::new("cw")).unwrap_err();
    assert!(err.to_string().contains("not absolute"), "{err}");
    for path in [
        "/opt/$HOME/cw",
        "/opt/a\"b/cw",
        "/opt/a'b/cw",
        "/opt/a`b`/cw",
        "/opt/a\\b/cw",
        "/opt/a\nb/cw",
    ] {
        let err = ssh_cw_command(std::path::Path::new(path)).unwrap_err();
        assert!(
            err.to_string().contains("cannot be written"),
            "{path}: {err}"
        );
    }
}

#[test]
fn managed_ssh_section_is_current_only_for_the_same_cw() {
    let content = format!("{CURRENT_MANAGED_SSH_BLOCK}\n");
    assert!(managed_ssh_section_is_current(&content, TEST_CW));
    assert!(!managed_ssh_section_is_current(&content, "/usr/bin/cw"));
    let bare = CURRENT_MANAGED_SSH_BLOCK.replace(TEST_CW, "cw");
    assert!(!managed_ssh_section_is_current(&bare, TEST_CW));
    // Sections an older cw wrote are outdated: one with only `Host cw-*`,
    // one without the local block, and one that still ends with the retired
    // catch-all `Host cw-*`.
    let (head, qualified_and_rest) = CURRENT_MANAGED_SSH_BLOCK
        .split_once("Host cw-local-*\n")
        .unwrap();
    let (_, cloud_and_rest) = qualified_and_rest.split_once("Host cw-cloud-*\n").unwrap();
    let single = format!("{head}Host cw-*\n{cloud_and_rest}\n");
    assert!(!managed_ssh_section_is_current(&single, TEST_CW));
    let without_local = format!("{head}Host cw-cloud-*\n{cloud_and_rest}\n");
    assert!(!managed_ssh_section_is_current(&without_local, TEST_CW));
    let with_catch_all = content.replacen(
        "Host *\n",
        "Host cw-*\n    ProxyCommand /opt/codewire/bin/cw shell --stdio %n\nHost *\n",
        1,
    );
    assert!(!managed_ssh_section_is_current(&with_catch_all, TEST_CW));
    // So is one whose blocks are swapped.
    let swapped = content
        .replace("Host cw-local-*\n", "Host SWAP\n")
        .replace("Host cw-cloud-*\n", "Host cw-local-*\n")
        .replace("Host SWAP\n", "Host cw-cloud-*\n");
    assert!(!managed_ssh_section_is_current(&swapped, TEST_CW));
}

fn ssh_test_file(path: &std::path::Path) -> SshConfigFile {
    SshConfigFile::resolve(Some(path.to_path_buf())).unwrap()
}

fn install_test_ssh_config(
    path: &std::path::Path,
    dry_run: bool,
) -> anyhow::Result<SshConfigOutcome> {
    install_managed_ssh_config(ssh_test_file(path), &ssh_test_options(&[]), dry_run)
}

#[cfg(unix)]
fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn ssh_setup_reruns_unchanged_and_remove_restores_the_user_entries() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    let user = "Host github.com\n    User git\n\nHost *\n    ServerAliveInterval 30\n";
    fs::write(&config_path, user).unwrap();

    let preview = install_test_ssh_config(&config_path, true).unwrap();
    assert_eq!(preview.change, SshConfigChange::Written);
    assert!(preview.dry_run && preview.before.is_empty());
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        user,
        "a dry run writes nothing"
    );

    let written = install_test_ssh_config(&config_path, false).unwrap();
    assert_eq!(written.change, SshConfigChange::Written);
    let configured = fs::read_to_string(&config_path).unwrap();
    assert_eq!(configured, format!("{CURRENT_MANAGED_SSH_BLOCK}\n\n{user}"));

    let again = install_test_ssh_config(&config_path, false).unwrap();
    assert_eq!(again.change, SshConfigChange::Unchanged);
    assert_eq!(fs::read_to_string(&config_path).unwrap(), configured);

    let preview = remove_managed_ssh_config(ssh_test_file(&config_path), true).unwrap();
    assert_eq!(preview.change, SshConfigChange::Removed);
    assert_eq!(preview.before, CURRENT_MANAGED_SSH_BLOCK);
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        configured,
        "a dry run writes nothing"
    );

    let removed = remove_managed_ssh_config(ssh_test_file(&config_path), false).unwrap();
    assert_eq!(removed.change, SshConfigChange::Removed);
    assert_eq!(fs::read_to_string(&config_path).unwrap(), user);

    let second = remove_managed_ssh_config(ssh_test_file(&config_path), false).unwrap();
    assert_eq!(second.change, SshConfigChange::NothingToRemove);
    assert!(second.existed);
    assert_eq!(fs::read_to_string(&config_path).unwrap(), user);
}

#[test]
fn ssh_setup_creates_a_private_file_and_remove_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join("home/.ssh");
    let config_path = ssh_dir.join("config");

    let removed = remove_managed_ssh_config(ssh_test_file(&config_path), false).unwrap();
    assert_eq!(removed.change, SshConfigChange::NothingToRemove);
    assert!(!removed.existed);
    assert!(!dir.path().join("home").exists(), "remove creates nothing");

    let preview = install_test_ssh_config(&config_path, true).unwrap();
    assert_eq!(preview.change, SshConfigChange::Written);
    assert!(
        !dir.path().join("home").exists(),
        "a dry run creates nothing"
    );

    install_test_ssh_config(&config_path, false).unwrap();
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        format!("{CURRENT_MANAGED_SSH_BLOCK}\n")
    );
    #[cfg(unix)]
    {
        assert_eq!(file_mode(&config_path), 0o600);
        assert_eq!(file_mode(&ssh_dir), 0o700);
    }
    // Only the config is left beside it: the replacement file was renamed.
    let names: Vec<_> = fs::read_dir(&ssh_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["config"]);

    remove_managed_ssh_config(ssh_test_file(&config_path), false).unwrap();
    assert_eq!(fs::read_to_string(&config_path).unwrap(), "");
}

#[cfg(unix)]
#[test]
fn ssh_setup_keeps_an_existing_files_mode() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    fs::write(&config_path, "Host a\n    User b\n").unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();

    install_test_ssh_config(&config_path, false).unwrap();
    assert_eq!(file_mode(&config_path), 0o644);
    remove_managed_ssh_config(ssh_test_file(&config_path), false).unwrap();
    assert_eq!(file_mode(&config_path), 0o644);
}

#[test]
fn ssh_setup_refuses_incomplete_markers_and_leaves_the_file_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    for broken in [
        format!("Host a\n{SSH_CONFIG_MARKER_START}\nHost cw-*\n    User codewire\n"),
        format!("Host a\n{SSH_CONFIG_MARKER_END}\n"),
        format!("{SSH_CONFIG_MARKER_END}\nHost a\n{SSH_CONFIG_MARKER_START}\n"),
        format!(
            "{SSH_CONFIG_MARKER_START}\nHost a\n{SSH_CONFIG_MARKER_START}\nHost b\n{SSH_CONFIG_MARKER_END}\n"
        ),
    ] {
        fs::write(&config_path, &broken).unwrap();
        let error = install_test_ssh_config(&config_path, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("incomplete Codewire section"), "{error}");
        assert!(error.contains("it was not changed"), "{error}");
        assert!(
            error.contains("then run `cw setup ssh --ssh-config-file "),
            "{error}"
        );
        let error = remove_managed_ssh_config(ssh_test_file(&config_path), false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("then run `cw setup ssh remove --ssh-config-file "),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&config_path).unwrap(), broken);
    }
}

#[test]
fn ssh_setup_refuses_a_config_that_is_not_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    let latin1 = b"# caf\xe9\nHost a\n    User b\n";
    fs::write(&config_path, latin1).unwrap();

    let error = install_test_ssh_config(&config_path, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not UTF-8 text"), "{error}");
    let error = remove_managed_ssh_config(ssh_test_file(&config_path), false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not UTF-8 text"), "{error}");
    assert_eq!(fs::read(&config_path).unwrap(), latin1);
}

#[cfg(unix)]
#[test]
fn ssh_setup_refuses_a_read_only_config_and_leaves_it_unchanged() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    let stale = CURRENT_MANAGED_SSH_BLOCK.replace(TEST_CW, "/old/cw") + "\n\nHost a\n";
    fs::write(&config_path, &stale).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o400)).unwrap();
    if fs::OpenOptions::new()
        .write(true)
        .open(&config_path)
        .is_ok()
    {
        eprintln!("running with permission to write any file; skipping the read-only check");
        return;
    }

    let error = install_test_ssh_config(&config_path, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not writable"), "{error}");
    assert!(error.contains("chmod u+w"), "{error}");
    assert!(
        error.contains("then run `cw setup ssh --ssh-config-file "),
        "{error}"
    );
    let error = remove_managed_ssh_config(ssh_test_file(&config_path), false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not writable"), "{error}");
    assert_eq!(fs::read_to_string(&config_path).unwrap(), stale);
    assert_eq!(file_mode(&config_path), 0o400);
    // A config that needs no change is not written, so it is not refused.
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&config_path, format!("{CURRENT_MANAGED_SSH_BLOCK}\n")).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        install_test_ssh_config(&config_path, false).unwrap().change,
        SshConfigChange::Unchanged
    );
}

#[cfg(unix)]
#[test]
fn ssh_setup_writes_through_a_symlinked_config() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("dotfiles")).unwrap();
    fs::create_dir_all(dir.path().join(".ssh")).unwrap();
    let real = dir.path().join("dotfiles/ssh_config");
    let link = dir.path().join(".ssh/config");
    let user = "Host a\n    User b\n";
    fs::write(&real, user).unwrap();
    std::os::unix::fs::symlink("../dotfiles/ssh_config", &link).unwrap();

    let file = ssh_test_file(&link);
    assert_eq!(
        file.target,
        fs::canonicalize(dir.path().join("dotfiles"))
            .unwrap()
            .join("ssh_config")
    );
    install_test_ssh_config(&link, false).unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(&real).unwrap(),
        format!("{CURRENT_MANAGED_SSH_BLOCK}\n\n{user}")
    );
    remove_managed_ssh_config(ssh_test_file(&link), false).unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&real).unwrap(), user);

    // A link to a file that does not exist yet: remove leaves it alone, and
    // setup creates the file it names.
    let dangling = dir.path().join(".ssh/dangling");
    std::os::unix::fs::symlink("../dotfiles/new_config", &dangling).unwrap();
    let removed = remove_managed_ssh_config(ssh_test_file(&dangling), false).unwrap();
    assert_eq!(removed.change, SshConfigChange::NothingToRemove);
    assert!(!dir.path().join("dotfiles/new_config").exists());
    install_test_ssh_config(&dangling, false).unwrap();
    assert!(
        fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("dotfiles/new_config")).unwrap(),
        format!("{CURRENT_MANAGED_SSH_BLOCK}\n")
    );
}

#[cfg(unix)]
#[test]
fn ssh_setup_refuses_a_hard_linked_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    fs::write(&config_path, "Host a\n").unwrap();
    fs::hard_link(&config_path, dir.path().join("other")).unwrap();

    let error = install_test_ssh_config(&config_path, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("has 2 hard links"), "{error}");
    assert_eq!(fs::read_to_string(&config_path).unwrap(), "Host a\n");
}

#[test]
fn split_managed_ssh_sections_takes_every_section_and_keeps_the_rest() {
    let section = format!(
        "{SSH_CONFIG_MARKER_START}\nHost cw-*\n    User codewire\nHost *\n{SSH_CONFIG_MARKER_END}"
    );
    // Two sections, one in the middle of the user's entries; CRLF line ends.
    let existing = format!("{section}\r\n\r\nHost a\r\n\r\n{section}\r\nHost b\r\n");
    let split = split_managed_ssh_sections(&existing).unwrap();
    assert_eq!(split.sections, [section.clone(), section.clone()]);
    assert_eq!(split.rest, "Host a\r\n\r\nHost b\r\n");
    // A section that is not first keeps the blank lines around it.
    let existing = format!("Host a\n\n{section}\n\nHost b\n");
    assert_eq!(
        split_managed_ssh_sections(&existing).unwrap().rest,
        "Host a\n\n\nHost b\n"
    );
    let split = split_managed_ssh_sections("Host a\n").unwrap();
    assert!(split.sections.is_empty());
    assert_eq!(split.rest, "Host a\n");
}

#[test]
fn ssh_section_diff_marks_kept_removed_and_added_lines() {
    assert_eq!(
        ssh_section_diff("a\nb\nc", "a\nB\nc\nd"),
        [(' ', "a"), ('-', "b"), ('+', "B"), (' ', "c"), ('+', "d")]
    );
    assert_eq!(ssh_section_diff("", "a"), [('+', "a")]);
    assert_eq!(ssh_section_diff("a", ""), [('-', "a")]);
}

#[test]
fn ssh_setup_output_names_the_outcome_the_file_and_the_next_step() {
    let style = crate::output::Style::new(false, crate::output::Charset::Unicode);
    let default = SshConfigFile {
        path: "/home/u/.ssh/config".into(),
        target: "/home/u/.ssh/config".into(),
        named: false,
    };
    let outcome = |change, file: &SshConfigFile, existed, dry_run, before: &str, after: &str| {
        SshConfigOutcome {
            change,
            file: file.clone(),
            existed,
            dry_run,
            before: before.to_string(),
            after: after.to_string(),
        }
        .render(style)
    };
    assert_eq!(
        outcome(SshConfigChange::Written, &default, true, false, "", "x"),
        "✓ Codewire SSH section written\n  /home/u/.ssh/config\n\n→ ssh cw-local-NAME\n  A local VM, by name or ID.\n→ ssh cw-cloud-NAME\n  A cloud environment, by name or ID.\n"
    );
    assert_eq!(
        outcome(SshConfigChange::Unchanged, &default, true, false, "x", "x"),
        "✓ Codewire SSH section unchanged\n  /home/u/.ssh/config\n\n→ ssh cw-local-NAME\n  A local VM, by name or ID.\n→ ssh cw-cloud-NAME\n  A cloud environment, by name or ID.\n"
    );
    assert_eq!(
        outcome(SshConfigChange::Removed, &default, true, false, "x", ""),
        "✓ Codewire SSH section removed\n  /home/u/.ssh/config · your own entries kept\n\n→ Add it back: cw setup ssh\n"
    );
    assert_eq!(
        outcome(
            SshConfigChange::NothingToRemove,
            &default,
            true,
            false,
            "",
            ""
        ),
        "✓ Nothing to remove\n  /home/u/.ssh/config has no Codewire SSH section\n"
    );
    assert_eq!(
        outcome(
            SshConfigChange::NothingToRemove,
            &default,
            false,
            true,
            "",
            ""
        ),
        "✓ Nothing to remove\n  /home/u/.ssh/config does not exist\n"
    );
    // A named file needs `-F`, and every command names it again.
    let named = SshConfigFile {
        path: "/tmp/my ssh/config".into(),
        target: "/tmp/dotfiles/config".into(),
        named: true,
    };
    assert_eq!(
        outcome(SshConfigChange::Written, &named, true, false, "", "x"),
        "✓ Codewire SSH section written\n  /tmp/my ssh/config -> /tmp/dotfiles/config\n\n→ ssh -F '/tmp/my ssh/config' cw-local-NAME\n  A local VM, by name or ID.\n→ ssh -F '/tmp/my ssh/config' cw-cloud-NAME\n  A cloud environment, by name or ID.\n"
    );
    assert_eq!(
        outcome(SshConfigChange::Removed, &named, true, false, "x", ""),
        "✓ Codewire SSH section removed\n  /tmp/my ssh/config -> /tmp/dotfiles/config · your own entries kept\n\n→ Add it back: cw setup ssh --ssh-config-file '/tmp/my ssh/config'\n"
    );
    // A dry run shows the managed section's change, and only that.
    assert_eq!(
        outcome(
            SshConfigChange::Written,
            &default,
            true,
            true,
            "# start\n    ProxyCommand /old/cw\n# end",
            "# start\n    ProxyCommand /new/cw\n# end",
        ),
        "Dry run: would write the Codewire SSH section\n  /home/u/.ssh/config · nothing written\n\n    # start\n  -     ProxyCommand /old/cw\n  +     ProxyCommand /new/cw\n    # end\n"
    );
    assert_eq!(
        outcome(
            SshConfigChange::Removed,
            &default,
            true,
            true,
            "# start\n\x1b[2J\n# end",
            ""
        ),
        "Dry run: would remove the Codewire SSH section\n  /home/u/.ssh/config · nothing written\n\n  - # start\n  - ?[2J\n  - # end\n"
    );
    assert!(
        outcome(SshConfigChange::Written, &default, true, true, "x", "x")
            .contains("Its text is unchanged; it moves to the top of the file")
    );
    assert_eq!(
        render_ssh_setup_failure(
            &anyhow::anyhow!("/home/u/.ssh/config is not writable"),
            style
        ),
        "! SSH config not updated\n  /home/u/.ssh/config is not writable\n\n→ Retry: cw setup ssh\n"
    );
}

#[test]
fn format_doctor_text_reports_paths_and_checks() {
    let report = DoctorReport {
        platform_config_dir: "/tmp/cw-config".to_string(),
        mesh_data_dir: "/tmp/cw-data".to_string(),
        checks: vec![
            doctor_check("platform", DoctorStatus::Ok, "Noel on https://codewire.sh"),
            doctor_check("local node", DoctorStatus::Warn, "not running"),
        ],
    };

    assert_eq!(
        format_doctor_text(&report),
        concat!(
            "Config:      /tmp/cw-config\n",
            "Mesh data:   /tmp/cw-data\n",
            "\n",
            "platform     ok     Noel on https://codewire.sh\n",
            "local node   warn   not running\n",
        )
    );
}

fn test_tailnet_diagnostic(transport: &str) -> tailnet_ssh::EnvironmentTailnetDiagnostic {
    tailnet_ssh::EnvironmentTailnetDiagnostic {
        environment_id: "env_123".to_string(),
        server_url: "https://codewire.test/".to_string(),
        forced_derp: false,
        direct_wait: "15s".to_string(),
        stages: vec![tailnet_ssh::TailnetDiagnosticStage {
            name: "path".to_string(),
            status: "ok",
            detail: format!("transport={transport} expected=any"),
            duration_ms: Some(12),
        }],
        derp_map: Some(tailnet_ssh::TailnetDerpMapDiagnostic {
            regions: 1,
            derp_nodes: 1,
            stun_nodes: 1,
        }),
        peer: Some(tailnet_ssh::TailnetPeerDiagnostic {
            id: "env_123".to_string(),
            preferred_derp: 1,
            endpoints: vec!["203.0.113.10:41641".to_string()],
            addresses: vec!["fd7a:115c:a1e0::1/128".to_string()],
        }),
        direct_path: None,
        final_path: Some(tailnet_ssh::TailnetPathDiagnostic {
            ready: true,
            transport: transport.to_string(),
            endpoint: "203.0.113.10:41641".to_string(),
            derp_region_id: None,
            error: String::new(),
        }),
        peer_relay: None,
    }
}

#[test]
fn format_tailnet_doctor_text_uses_current_transport_terms() {
    let report = TailnetDoctorReport {
        environment_id: "env_123".to_string(),
        server_url: "https://codewire.test/".to_string(),
        expect: "udp_relay".to_string(),
        direct: test_tailnet_diagnostic("udp_relay"),
        forced_derp: Some(test_tailnet_diagnostic("derp")),
    };

    let text = format_tailnet_doctor_text(&report);
    assert!(text.contains("Expect:      udp_relay"));
    assert!(text.contains("transport=udp_relay"));
    assert!(text.contains("transport=derp"));
    assert!(text.contains("Probe:       forced derp"));
    assert!(!text.contains("peer_relay"));
    assert!(!text.contains("derp_relay"));
}

#[test]
fn validate_tailnet_doctor_report_checks_transport_expectations() {
    let report = TailnetDoctorReport {
        environment_id: "env_123".to_string(),
        server_url: "https://codewire.test/".to_string(),
        expect: "udp_relay".to_string(),
        direct: test_tailnet_diagnostic("udp_relay"),
        forced_derp: None,
    };
    validate_tailnet_doctor_report(&report).unwrap();

    let missing = TailnetDoctorReport {
        expect: "direct_udp".to_string(),
        ..report
    };
    assert!(
        validate_tailnet_doctor_report(&missing)
            .unwrap_err()
            .to_string()
            .contains("expected direct_udp")
    );
}

#[test]
fn parse_tailnet_doctor_duration_accepts_ms_seconds_and_minutes() {
    assert_eq!(
        parse_tailnet_doctor_duration("direct-wait", "250ms", true).unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        parse_tailnet_doctor_duration("direct-wait", "15s", true).unwrap(),
        Duration::from_secs(15)
    );
    assert_eq!(
        parse_tailnet_doctor_duration("peer-timeout", "1m", false).unwrap(),
        Duration::from_secs(60)
    );
    assert!(parse_tailnet_doctor_duration("peer-timeout", "0s", false).is_err());
}

#[test]
fn doctor_ssh_config_check_at_reports_missing_and_managed_section() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");

    let missing = doctor_ssh_config_check_at(&config_path, TEST_CW);
    assert_eq!(missing.status, DoctorStatus::Warn);
    assert!(missing.detail.contains("missing"));

    fs::write(&config_path, "Host github.com\n  User git\n").unwrap();
    let unmanaged = doctor_ssh_config_check_at(&config_path, TEST_CW);
    assert_eq!(unmanaged.status, DoctorStatus::Warn);
    assert!(unmanaged.detail.contains("Codewire section missing"));

    fs::write(
        &config_path,
        format!(
            "{}\nHost cw-*\n    StrictHostKeyChecking accept-new\n{}\n",
            SSH_CONFIG_MARKER_START, SSH_CONFIG_MARKER_END
        ),
    )
    .unwrap();
    let outdated = doctor_ssh_config_check_at(&config_path, TEST_CW);
    assert_eq!(outdated.status, DoctorStatus::Warn);
    assert!(outdated.detail.contains("outdated or not first"));

    fs::write(
        &config_path,
        format!("Host github.com\n  User git\n\n{CURRENT_MANAGED_SSH_BLOCK}\n"),
    )
    .unwrap();
    let not_first = doctor_ssh_config_check_at(&config_path, TEST_CW);
    assert_eq!(not_first.status, DoctorStatus::Warn);
    assert!(not_first.detail.contains("outdated or not first"));

    fs::write(
        &config_path,
        format!("{CURRENT_MANAGED_SSH_BLOCK}\n\nHost github.com\n  User git\n"),
    )
    .unwrap();
    let managed = doctor_ssh_config_check_at(&config_path, TEST_CW);
    assert_eq!(managed.status, DoctorStatus::Ok);
    assert_eq!(managed.detail, config_path.display().to_string());
}

#[test]
fn network_invite_parser_rejects_removed_browser_qr_flag() {
    let cli = Cli::try_parse_from([
        "cw",
        "network",
        "invite",
        "--org",
        "org-alpha",
        "--network",
        "project-alpha",
        "--ttl",
        "2h",
        "--qr",
    ])
    .unwrap_err();

    assert_eq!(cli.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn global_token_flag_is_rejected_without_echoing_its_value() {
    const MARKER: &str = "synthetic-retired-global-token-canary";

    for argument in ["--token".to_owned(), format!("--token={MARKER}")] {
        let argv = if argument == "--token" {
            vec![
                "cw".to_owned(),
                argument,
                MARKER.to_owned(),
                "whoami".to_owned(),
            ]
        } else {
            vec!["cw".to_owned(), argument, "whoami".to_owned()]
        };
        let error = Cli::try_parse_from(argv).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        assert!(!error.to_string().contains(MARKER));
    }
}

#[test]
fn one_use_mesh_arguments_are_redacted_through_nested_cli_debug() {
    const MARKER: &str = "synthetic-one-use-mesh-argument-canary";
    for argv in [
        vec!["cw", "network", "join", MARKER],
        vec!["cw", "network", "enroll", "redeem", MARKER],
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        let debug = format!("{cli:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(MARKER));
    }
}

#[test]
fn normalize_login_server_url_trims_trailing_slash() {
    assert_eq!(
        normalize_login_server_url(Some(" https://codewire.sh/ ")).as_deref(),
        Some("https://codewire.sh")
    );
    assert_eq!(normalize_login_server_url(Some("   ")), None);
    assert_eq!(normalize_login_server_url(None), None);
}

#[test]
fn save_login_platform_config_persists_only_reconciled_default_org() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    config::save_platform_config(
        &paths.platform_config_dir,
        &config::PlatformConfig {
            server_url: "https://old.codewire.sh".to_string(),
            default_org: "org_123".to_string(),
        },
    )
    .unwrap();

    let credentials = codewire_client::OAuthCredentials::new(
        "https://new.codewire.sh",
        codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
        "access-token",
        "refresh-token",
        u64::MAX,
        codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
    )
    .unwrap();
    assert_eq!(
        saved_login_default_org(&paths, "https://old.codewire.sh").as_deref(),
        Some("org_123")
    );
    assert_eq!(
        saved_login_default_org(&paths, "https://new.codewire.sh"),
        None
    );
    save_login_platform_config(
        &paths,
        "https://new.codewire.sh",
        &credentials,
        Some("org_new"),
    )
    .unwrap();

    let saved = config::load_platform_config(&paths.platform_config_dir).unwrap();
    assert_eq!(saved.server_url, "https://new.codewire.sh");
    assert_eq!(saved.default_org, "org_new");
    assert!(config::oauth_credentials_path(&paths.platform_config_dir).is_file());
    let resolved =
        config::resolve_platform(config::PlatformResolveOptions::default(), &paths, &env).unwrap();
    let orgs = vec![OrgWithRole {
        id: "org_new".to_string(),
        name: "New Org".to_string(),
        slug: "new-org".to_string(),
        role: "owner".to_string(),
        ..OrgWithRole::default()
    }];
    assert_eq!(current_org_id(&resolved, &orgs).unwrap(), "org_new");
    assert_eq!(
        doctor_org_selection_check(&resolved, &orgs),
        doctor_check("org", DoctorStatus::Ok, "New Org")
    );

    save_login_platform_config(&paths, "https://new.codewire.sh", &credentials, None).unwrap();
    let saved = config::load_platform_config(&paths.platform_config_dir).unwrap();
    assert!(saved.default_org.is_empty());
}

#[test]
fn a_login_replaces_the_account_record_and_a_failed_one_leaves_none() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    let server = "https://offline.invalid";
    let credentials = codewire_client::OAuthCredentials::new(
        server,
        codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
        "synthetic-access-canary",
        "synthetic-refresh-canary",
        u64::MAX,
        codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
    )
    .unwrap();
    let user = |sub: &str| OAuthUserInfo {
        sub: sub.to_owned(),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    let recorded_user = || config::local_account(None, &paths, &env).map(|account| account.user_id);

    save_login(&paths, server, &credentials, Some("org-a"), &user("user-a")).unwrap();
    assert_eq!(recorded_user().as_deref(), Some("user-a"));
    save_login(&paths, server, &credentials, Some("org-a"), &user("user-b")).unwrap();
    assert_eq!(recorded_user().as_deref(), Some("user-b"));
    // Only the record is left in the directory: no temporary file.
    let mut names = std::fs::read_dir(&paths.platform_config_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["account.json", "config.json", "credentials.json"]);

    // A login that fails after the old record is gone records no account,
    // never the previous user's.
    let config_file = paths.platform_config_dir.join("config.json");
    std::fs::remove_file(&config_file).unwrap();
    std::fs::create_dir(&config_file).unwrap();
    assert!(save_login(&paths, server, &credentials, Some("org-a"), &user("user-c")).is_err());
    assert!(!paths.platform_config_dir.join("account.json").exists());
    assert_eq!(recorded_user(), None);
}

#[test]
fn platform_login_saves_the_owner_organization_and_no_mesh_projection() {
    let home = tempfile::tempdir().unwrap();
    let paths =
        ResolvePaths::from_home_and_env(home.path().to_path_buf(), &config::MapEnv::default())
            .unwrap();
    let credentials = codewire_client::OAuthCredentials::new(
        "https://api.codewire-dev.sh",
        codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
        "synthetic-access-canary",
        "synthetic-refresh-canary",
        u64::MAX,
        codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
    )
    .unwrap();

    save_login_platform_config(
        &paths,
        "https://api.codewire-dev.sh",
        &credentials,
        Some("org-alpha"),
    )
    .unwrap();

    // The hosted Mesh owner is the saved platform and default organization;
    // login writes no Mesh state of its own.
    assert_eq!(
        load_local_mesh_owner_context(&paths.mesh_data_dir).unwrap(),
        None
    );
    assert!(!paths.mesh_data_dir.exists());
    let saved = config::load_platform_config(&paths.platform_config_dir).unwrap();
    assert_eq!(saved.default_org, "org-alpha");
    assert_eq!(
        config::derive_hosted_mesh_url_for_server(&saved.server_url).as_deref(),
        Some("https://mesh.codewire-dev.sh")
    );
}

#[test]
fn local_mesh_children_receive_only_explicit_startup_and_logging_environment() {
    const CHILD_SENTINEL: &str = "CODEWIRE_TEST_LOCAL_MESH_ENV_CHILD";
    const AMBIENT_CANARY: &str = "synthetic-ambient-secret-canary";
    if std::env::var_os(CHILD_SENTINEL).is_none() {
        let test_name = std::thread::current().name().unwrap().to_owned();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD_SENTINEL, "1")
            .env("UNRELATED_SECRET", AMBIENT_CANARY)
            .env("DATABASE_URL", AMBIENT_CANARY)
            .env("CODEWIRE_MESH_AUTHORIZATION_URL", "https://ambient.invalid")
            .env("CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET", AMBIENT_CANARY)
            .env("RUST_LOG", "codewire_mesh=trace")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    use crate::commands::mesh_commands::owner::{derp_environment, owner_environment};
    let raw_api_key = "cw_synthetic-local-mesh-api-key";
    let identity = config::LocalMeshIdentity {
        organization_id: "local-org-synthetic".to_owned(),
        api_key: raw_api_key.to_owned(),
    };
    let spec = LocalMeshStartSpec {
        binary: PathBuf::from("/synthetic/cw"),
        base_url: "http://127.0.0.1:18090".to_owned(),
        listen_addr: "127.0.0.1:18090".to_owned(),
        local_identity: identity.clone(),
        log_path: PathBuf::from("/synthetic/mesh.log"),
        derp: Some(LocalDerpStartSpec {
            binary: PathBuf::from("/synthetic/cw"),
            url: "http://127.0.0.1:18091".to_owned(),
            listen_addr: "127.0.0.1:18091".to_owned(),
            log_path: PathBuf::from("/synthetic/derp.log"),
        }),
    };
    let mesh = owner_environment(
        &spec,
        std::path::Path::new("/synthetic/mesh.sock"),
        std::path::Path::new("/synthetic/mesh"),
        "00000000-0000-4000-8000-000000000001",
    );
    let derp = derp_environment("127.0.0.1:18091");
    for (environment, is_mesh) in [(&mesh, true), (&derp, false)] {
        let mut command = std::process::Command::new("/usr/bin/env");
        command.env_clear().envs(environment.iter().cloned());
        let output = command.output().unwrap();
        assert!(output.status.success());
        let dump = String::from_utf8(output.stdout).unwrap();
        assert_eq!(dump.contains("CW_LOCAL_HELPER_NONCE="), is_mesh);
        assert!(dump.contains("RUST_LOG=codewire_mesh=trace"));
        if is_mesh {
            assert!(dump.contains("CODEWIRE_MESH_LOCAL_ORGANIZATION_ID=local-org-synthetic"));
            assert!(dump.contains(&identity.api_key_hash()));
        } else {
            assert!(dump.contains("PORT=-1"));
            assert!(dump.contains("STUN_LISTEN_ADDR=-1"));
            assert!(dump.contains("TLS_LISTEN_ADDR=127.0.0.1:18091"));
            assert!(!dump.contains("CODEWIRE_MESH_LOCAL_API_KEY_HASH="));
        }
        for forbidden in [
            raw_api_key,
            CHILD_SENTINEL,
            "UNRELATED_SECRET",
            "DATABASE_URL",
            "CODEWIRE_MESH_AUTHORIZATION_URL",
            "CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET",
            AMBIENT_CANARY,
        ] {
            assert!(!dump.contains(forbidden), "helper inherited {forbidden}");
        }
    }
}

#[test]
fn login_parser_accepts_default_org() {
    let cli = Cli::try_parse_from(["cw", "login", "--org", "codewire"]).unwrap();
    let Command::Login(args) = cli.command else {
        panic!("expected login command");
    };
    assert_eq!(args.org.as_deref(), Some("codewire"));
}

#[test]
fn setup_parser_accepts_noninteractive_flags() {
    let cli = Cli::try_parse_from(["cw", "setup", "--org", "codewire", "--skip-ssh"]).unwrap();

    let Command::Setup(args) = cli.command else {
        panic!("expected setup command");
    };
    assert_eq!(args.org.as_deref(), Some("codewire"));
    assert!(args.skip_ssh);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn setup_local_installs_the_runtime_without_signing_in() {
    // The global flag reaches setup from either side of the command.
    for argv in [
        vec!["cw", "setup", "--local", "--from", "/abs/release", "--replace"],
        vec!["cw", "--local", "setup", "--from", "/abs/release", "--replace"],
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.placement().unwrap(), Some(EnvironmentPlacement::Local));
        let Command::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert!(args.replace);
        assert_eq!(args.from.as_deref(), Some(std::path::Path::new("/abs/release")));
        validate_setup_placement(&args, Some(EnvironmentPlacement::Local)).unwrap();
    }
    for command in [
        vec!["cw", "setup", "--from", "/abs/release"],
        vec!["cw", "setup", "--replace"],
        vec!["cw", "setup", "--local", "--org", "codewire"],
        vec!["cw", "setup", "--local", "--skip-ssh"],
        vec!["cw", "--cloud", "setup", "--replace"],
    ] {
        let cli = Cli::try_parse_from(command.clone()).unwrap();
        let placement = cli.placement().unwrap();
        let Command::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert!(validate_setup_placement(&args, placement).is_err(), "{command:?}");
    }
}

#[test]
fn setup_ssh_replaces_config_ssh_and_takes_no_placement() {
    let cli = Cli::try_parse_from(["cw", "setup", "ssh", "-n", "-o", "ForwardX11 no"]).unwrap();
    let Command::Setup(SetupArgs {
        command: Some(SetupCommand::Ssh(args)),
        ..
    }) = cli.command
    else {
        panic!("expected setup ssh");
    };
    assert!(args.dry_run);
    assert_eq!(args.ssh_options, ["ForwardX11 no"]);
    assert!(args.command.is_none());
    assert!(Cli::try_parse_from(["cw", "setup", "ssh", "--org", "codewire"]).is_err());
    assert!(Cli::try_parse_from(["cw", "config-ssh"]).is_err());
    let cli = Cli::try_parse_from([
        "cw",
        "setup",
        "ssh",
        "remove",
        "-n",
        "--ssh-config-file",
        "/tmp/ssh_config",
    ])
    .unwrap();
    let Command::Setup(SetupArgs {
        command:
            Some(SetupCommand::Ssh(SshSetupArgs {
                command: Some(SshSetupCommand::Remove(remove)),
                ..
            })),
        ..
    }) = cli.command
    else {
        panic!("expected setup ssh remove");
    };
    assert!(remove.dry_run);
    assert_eq!(
        remove.ssh_config_file.as_deref(),
        Some(std::path::Path::new("/tmp/ssh_config"))
    );
    // Remove takes no SSH options, and setup's own flags do not reach it.
    assert!(Cli::try_parse_from(["cw", "setup", "ssh", "remove", "-o", "ForwardX11 no"]).is_err());
    assert!(Cli::try_parse_from(["cw", "setup", "ssh", "-n", "remove"]).is_err());
    let cli = Cli::try_parse_from(["cw", "--cloud", "setup", "ssh", "remove"]).unwrap();
    let error =
        crate::validate_placement_scope(&cli.command, "setup", cli.placement().unwrap(), false)
            .unwrap_err();
    assert_eq!(
        error.to_string(),
        "--cloud does not apply to `cw setup ssh`"
    );
    // `%n` in ProxyCommand needs an OpenSSH with the CVE-2023-51385 fix.
    let help = Cli::try_parse_from(["cw", "setup", "ssh", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("OpenSSH 9.6 or later"), "{help}");
    assert!(help.contains("CVE-2023-51385"), "{help}");
    assert!(help.contains("remove"), "{help}");
    let cli = Cli::try_parse_from(["cw", "--local", "setup", "ssh"]).unwrap();
    let error = crate::validate_placement_scope(
        &cli.command,
        "setup",
        cli.placement().unwrap(),
        false,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "--local does not apply to `cw setup ssh`");
}

#[test]
fn removed_platform_github_commands_and_setup_flags_are_rejected() {
    for command in [
        vec!["cw", "github", "status"],
        vec!["cw", "setup", "--github"],
        vec!["cw", "setup", "--skip-github"],
    ] {
        assert!(Cli::try_parse_from(command).is_err());
    }
}

#[test]
fn native_login_commands_do_not_accept_password_flags() {
    for command in [
        vec!["cw", "login", "--password"],
        vec!["cw", "setup", "--password"],
    ] {
        let error = Cli::try_parse_from(command).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected argument '--password'")
        );
    }
}

#[test]
fn setup_parser_requires_create_org_for_org_slug() {
    let err = Cli::try_parse_from(["cw", "setup", "--org-slug", "codewire"]).unwrap_err();

    assert!(err.to_string().contains("--create-org"));
}

#[test]
fn attach_command_parser_accepts_environment_and_session() {
    let cli = Cli::try_parse_from(["cw", "attach", "builder", "--session", "worker"]).unwrap();

    let Command::Attach(args) = cli.command else {
        panic!("expected attach command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.session.as_deref(), Some("worker"));
    assert!(args.retired_session.is_empty());
}

#[test]
fn attach_command_parser_accepts_selected_environment_session_flag() {
    let cli = Cli::try_parse_from(["cw", "attach", "--session", "worker"]).unwrap();

    let Command::Attach(args) = cli.command else {
        panic!("expected attach command");
    };
    assert_eq!(args.environment, None);
    assert_eq!(args.in_environment, None);
    assert_eq!(args.session.as_deref(), Some("worker"));
}

#[test]
fn resolve_login_server_url_in_a_fresh_config_is_the_hosted_default() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    let globals = Globals {
        server: None,
        member: None,
        placement: None,
        org: None,
    };

    // `cw login` before `cw setup` (#3888).
    assert_eq!(
        resolve_login_server_url(&globals, &paths, &env),
        "https://codewire.sh"
    );
}

#[test]
fn resolve_login_server_url_prefers_global_server() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::new([("CODEWIRE_SERVER_URL", "https://env.codewire.sh")]);
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    let globals = Globals {
        server: Some(" https://flag.codewire.sh/ ".to_string()),
        member: None,
        placement: None,
        org: None,
    };

    assert_eq!(
        resolve_login_server_url(&globals, &paths, &env),
        "https://flag.codewire.sh"
    );
}

#[test]
fn oauth_user_display_name_prefers_name_then_email() {
    let named = OAuthUserInfo {
        name: Some("Noel".to_string()),
        email: Some("n@example.com".to_string()),
        ..OAuthUserInfo::default()
    };
    let email_only = OAuthUserInfo {
        email: Some("n@example.com".to_string()),
        ..OAuthUserInfo::default()
    };

    assert_eq!(oauth_user_display_name(&named), "Noel");
    assert_eq!(oauth_user_display_name(&email_only), "n@example.com");
    assert_eq!(
        oauth_user_display_name(&OAuthUserInfo::default()),
        "(unknown)"
    );
}

#[test]
fn nodes_have_multiple_networks_ignores_blank_networks() {
    let nodes = vec![
        Node {
            network_id: String::new(),
            name: "legacy".to_string(),
            peer_url: String::new(),
            connected: false,
            last_seen_at: String::new(),
        },
        Node {
            network_id: "project-alpha".to_string(),
            name: "builder".to_string(),
            peer_url: String::new(),
            connected: true,
            last_seen_at: String::new(),
        },
    ];

    assert!(!nodes_have_multiple_networks(&nodes));
}

#[test]
fn nodes_have_multiple_networks_detects_distinct_networks() {
    let nodes = vec![
        Node {
            network_id: "project-alpha".to_string(),
            name: "builder".to_string(),
            peer_url: String::new(),
            connected: true,
            last_seen_at: String::new(),
        },
        Node {
            network_id: "project-beta".to_string(),
            name: "planner".to_string(),
            peer_url: String::new(),
            connected: false,
            last_seen_at: String::new(),
        },
    ];

    assert!(nodes_have_multiple_networks(&nodes));
}

#[test]
fn format_whoami_text_matches_go_layout() {
    let user = PlatformUser {
        name: "Example Owner".to_string(),
        email: "n@example.com".to_string(),
        ..PlatformUser::default()
    };

    assert_eq!(
        format_whoami_text(&user, "https://codewire.sh", Some("noel")),
        concat!(
            "User:      Example Owner (n@example.com)\n",
            "Server:    https://codewire.sh\n",
            "Org:       noel\n",
        )
    );
}

#[test]
fn format_whoami_text_omits_empty_default_org() {
    let user = PlatformUser {
        email: "n@example.com".to_string(),
        ..PlatformUser::default()
    };

    assert_eq!(
        format_whoami_text(&user, "https://codewire.sh", Some("  ")),
        concat!(
            "User:       (n@example.com)\n",
            "Server:    https://codewire.sh\n",
        )
    );
}

fn test_environment(id: &str, name: Option<&str>, state: &str) -> Environment {
    Environment {
        id: id.to_string(),
        name: name.map(str::to_string),
        state: state.to_string(),
        ..Environment::default()
    }
}

#[test]
fn env_report_command_parser_accepts_json_and_rejects_retired_names() {
    let cli = Cli::try_parse_from(["cw", "report", "builder", "--output", "json"]).unwrap();
    let (_, _, EnvCommand::Report(args)) = env_operation(cli)
    else {
        panic!("expected env report command");
    };
    assert_eq!(args.environment, "builder");
    assert_eq!(args.output, OutputFormat::Json);

    assert!(Cli::try_parse_from(["cw", "trust-report", "builder"]).is_err());
    assert!(Cli::try_parse_from(["cw", "attest", "builder"]).is_err());
}

#[test]
fn format_env_report_text_marks_confidential_dev_proof() {
    let report: EnvironmentTrustReport = serde_json::from_value(serde_json::json!({
            "environment": {
                "id": "env_123",
                "org_id": "org_123",
                "type": "sandbox",
                "state": "running",
                "isolation_tier": "confidential"
            },
            "runtime": {
                "profile": "confidential",
                "runtime_class": "confidential",
                "handler": "kata-qemu-snp",
                "confidential": true
            },
            "placement": {
                "namespace": "dev-sandboxes",
                "workspace_pod": "workspace-env-123",
                "pod_ip": "10.42.0.12",
                "node": "node-a",
                "zone": "hel1",
                "region": "eu-central"
            },
            "images": {
                "workspace_image": "ghcr.io/codewiresh/workspace@sha256:abc",
                "workspace_image_id": "docker-pullable://ghcr.io/codewiresh/workspace@sha256:abc",
                "dind_image": "docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
                "dind_image_id": "docker-pullable://docker.io/library/docker@sha256:123",
                "daemon_init_image": "ghcr.io/codewiresh/codewire-daemon@sha256:456",
                "daemon_init_image_id": "docker-pullable://ghcr.io/codewiresh/codewire-daemon@sha256:456"
            },
            "provenance": {
                "status": "not_available",
                "notes": [
                    "Guest kernel, initrd/image, and firmware provenance are not persisted by the runtime API yet."
                ]
            },
            "attestation": {
                "status": "dev_evidence_available",
                "tee": "sev-snp",
                "report_available": false,
                "report_source": "Gitea #618 dev smoke",
                "metadata": {
                    "report_version": "5",
                    "vmpl": "1"
                }
            },
            "trustee": {
                "status": "dev_policy_matched",
                "resource_uri": "kbs:///default/codewire/runtime-test-resource",
                "reference_values": "dev_reference_values_registered",
                "policy": "claim_bound_dev_policy",
                "evidence_issues": ["#619", "#620"]
            },
            "summary": {
                "trust_level": "dev_proof",
                "production_verified": false,
                "warnings": [
                    "Current confidential evidence is dev-only.",
                    "Raw SEV-SNP reports are intentionally not exposed."
                ]
            }
        }))
        .unwrap();

    let text = format_env_report_text(&report);

    assert!(text.contains("Environment report: env_123\n"));
    assert!(text.contains("Trust level: dev_proof\n"));
    assert!(text.contains("Isolation: confidential\n"));
    assert!(
        text.contains(
            "Runtime: confidential / RuntimeClass confidential / handler kata-qemu-snp\n"
        )
    );
    assert!(text.contains("Node: node-a\n"));
    assert!(text.contains(
        "Daemon init image ID: docker-pullable://ghcr.io/codewiresh/codewire-daemon@sha256:456\n"
    ));
    assert!(!text.contains("Gateway"));
    assert!(text.contains("Provenance: not_available\n"));
    assert!(text.contains("Attestation: dev_evidence_available (sev-snp)\n"));
    assert!(text.contains("Resource: kbs:///default/codewire/runtime-test-resource\n"));
    assert!(text.contains("Evidence issues: #619, #620\n"));
    assert!(text.contains("Raw SEV-SNP reports are intentionally not exposed."));
}

#[test]
fn format_env_report_text_describes_standard_isolation_without_attestation_claims() {
    let report: EnvironmentTrustReport = serde_json::from_value(serde_json::json!({
            "environment": {
                "id": "env_standard",
                "org_id": "org_123",
                "type": "sandbox",
                "state": "running",
                "isolation_tier": "standard"
            },
            "runtime": {
                "profile": "commodity",
                "runtime_class": "commodity",
                "handler": "kata-clh",
                "confidential": false
            },
            "attestation": {
                "status": "not_applicable",
                "tee": "none",
                "report_available": false
            },
            "trustee": {
                "status": "not_applicable"
            },
            "summary": {
                "trust_level": "not_confidential",
                "production_verified": false,
                "warnings": [
                    "Commodity runtime has a Kata VM boundary but does not make a TEE attestation claim."
                ]
            }
        }))
        .unwrap();

    let text = format_env_report_text(&report);

    assert!(text.contains("Environment report: env_standard\n"));
    assert!(text.contains("Isolation: standard\n"));
    assert!(text.contains("Runtime: commodity / RuntimeClass commodity / handler kata-clh\n"));
    assert!(text.contains("Confidential: no\n"));
    assert!(text.contains("Attestation: not_applicable (none)\n"));
    assert!(text.contains("Trustee: not_applicable\n"));
    assert!(text.contains("Trust level: not_confidential\n"));
    assert!(text.contains("does not make a TEE attestation claim"));
}

#[test]
fn resolve_environment_id_matches_name_exactly_then_id_prefix() {
    let environments = vec![
        test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        ),
        test_environment(
            "87654321-abcd-4000-9000-000000000002",
            Some("tester"),
            "stopped",
        ),
    ];

    assert_eq!(
        resolve_environment_id_from_list(&environments, "builder").unwrap(),
        "12345678-abcd-4000-9000-000000000001"
    );
    assert_eq!(
        resolve_environment_id_from_list(&environments, "87654321").unwrap(),
        "87654321-abcd-4000-9000-000000000002"
    );
}

#[test]
fn resolve_environment_id_rejects_ambiguous_targets() {
    let environments = vec![
        test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        ),
        test_environment(
            "12345679-abcd-4000-9000-000000000002",
            Some("builder"),
            "stopped",
        ),
    ];

    let name_err = resolve_environment_id_from_list(&environments, "builder").unwrap_err();
    assert!(
        name_err
            .to_string()
            .contains("multiple environments named \"builder\"")
    );

    let prefix_err = resolve_environment_id_from_list(&environments, "1234567").unwrap_err();
    assert!(
        prefix_err
            .to_string()
            .contains("matched multiple IDs, use a longer prefix")
    );
}

/// Rows of a rendered top-level help, as (section heading, command name).
fn help_rows(help: &str) -> Vec<(String, String)> {
    let mut heading = String::new();
    let mut rows = Vec::new();
    for line in help.lines() {
        if line.ends_with(':') && !line.starts_with(' ') {
            heading = line.trim_end_matches(':').to_owned();
        } else if let Some(row) = line.strip_prefix("  ")
            && heading != "Options"
            && !row.starts_with(' ')
            && !row.is_empty()
        {
            let name = row.split([' ', ',']).next().unwrap_or_default();
            rows.push((heading.clone(), name.to_owned()));
        }
    }
    rows
}

#[test]
fn top_level_help_groups_every_visible_command_once() {
    use clap::CommandFactory as _;
    let visible: Vec<String> = crate::Cli::command()
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(|command| command.get_name().to_owned())
        .collect();
    for name in &visible {
        let sections = crate::HELP_SECTIONS
            .iter()
            .filter(|section| section.commands.contains(&name.as_str()))
            .count();
        assert_eq!(sections, 1, "{name} belongs to exactly one help section");
    }
    // Every listed name is a real visible command: nothing removed lingers.
    for section in crate::HELP_SECTIONS {
        for name in section.commands {
            assert!(
                visible.iter().any(|candidate| candidate == name),
                "{name} in {} is a visible command",
                section.heading
            );
        }
    }
    for all in [false, true] {
        let help = crate::cli_command_with(all).render_help().to_string();
        let rows = help_rows(&help);
        assert!(!help.contains("\nOther:\n"));
        assert!(!help.contains("__"));
        let expected: Vec<&str> = crate::HELP_SECTIONS
            .iter()
            .filter(|section| all || section.everyday)
            .map(|section| section.heading)
            .collect();
        let mut headings: Vec<&str> = Vec::new();
        for (heading, _) in &rows {
            if headings.last() != Some(&heading.as_str()) {
                headings.push(heading);
            }
        }
        assert_eq!(headings, expected, "help --all={all}");
        for section in crate::HELP_SECTIONS {
            for name in section.commands {
                let listed = rows
                    .iter()
                    .filter(|(heading, row)| heading == section.heading && row == name)
                    .count();
                let shown = all || section.everyday;
                assert_eq!(listed, usize::from(shown), "{name} with --all={all}");
            }
        }
        // Hidden internals and removed routes never appear.
        for hidden in ["env", "ssh", "config-ssh", "list", "_agent-driver"] {
            assert!(
                !rows.iter().any(|(_, name)| name == hidden),
                "{hidden} is hidden from help --all={all}"
            );
        }
    }
    // `cw help --all` lists every visible command.
    let full = help_rows(&crate::cli_command_with(true).render_help().to_string());
    for name in &visible {
        assert!(full.iter().any(|(_, row)| row == name), "{name} in help --all");
    }
    let everyday = crate::cli_command().render_help().to_string();
    assert!(everyday.contains("`cw help --all` lists every command"));
}

#[test]
fn help_names_availability_limits_and_the_help_command_renders_from_the_parser() {
    let full = crate::cli_command_with(true).render_help().to_string();
    assert!(full.contains("(Linux only)"), "{full}");
    let restart = full
        .lines()
        .find(|line| line.trim_start().starts_with("restart "))
        .unwrap();
    assert!(restart.contains("local environment"), "{restart}");
    let cli = Cli::try_parse_from(["cw", "help", "--all"]).unwrap();
    let Command::Help(args) = cli.command else {
        panic!("expected help");
    };
    assert!(args.all && args.command.is_empty());
    let cli = Cli::try_parse_from(["cw", "help", "runtime", "update"]).unwrap();
    let Command::Help(args) = cli.command else {
        panic!("expected help");
    };
    assert_eq!(args.command, ["runtime", "update"]);
    assert!(Cli::try_parse_from(["cw", "help", "--all", "stop"]).is_err());
    assert!(crate::commands::flat::handle_help(crate::commands::HelpArgs {
        all: false,
        command: vec!["env".into()],
    })
    .is_err());
}

#[test]
fn every_list_subcommand_answers_to_ls_and_ls_is_the_one_inventory_route() {
    use clap::CommandFactory as _;
    fn walk(command: &clap::Command, path: &str, lists: &mut Vec<String>) {
        for subcommand in command.get_subcommands() {
            let path = format!("{path} {}", subcommand.get_name());
            if subcommand.get_name() == "list" {
                assert!(
                    subcommand.get_visible_aliases().any(|alias| alias == "ls"),
                    "{path} shows the ls alias"
                );
                lists.push(path.clone());
            }
            walk(subcommand, &path, lists);
        }
    }
    let mut lists = Vec::new();
    walk(&crate::Cli::command(), "cw", &mut lists);
    for path in ["cw credentials list", "cw network list"] {
        assert!(lists.iter().any(|list| list == path), "{path} exists");
    }
    // `cw ls` is the one inventory route; `list` is its visible alias.
    let ls = crate::Cli::command();
    let ls = ls.find_subcommand("ls").unwrap();
    assert!(ls.get_visible_aliases().any(|alias| alias == "list"));
    let help = crate::cli_command().render_help().to_string();
    assert!(help.lines().any(|line| line.trim_start().starts_with("ls, list ")));
    for (alias, canonical) in [
        (vec!["cw", "list"], vec!["cw", "ls"]),
        (
            vec!["cw", "list", "--type", "sandbox", "--state", "running", "-a", "--output", "json"],
            vec!["cw", "ls", "--type", "sandbox", "--state", "running", "-a", "--output", "json"],
        ),
        (vec!["cw", "--cloud", "list", "app"], vec!["cw", "--cloud", "ls", "app"]),
    ] {
        let alias = Cli::try_parse_from(alias).unwrap();
        let canonical = Cli::try_parse_from(canonical).unwrap();
        assert_eq!(
            (alias.local, alias.cloud, format!("{:?}", alias.command)),
            (canonical.local, canonical.cloud, format!("{:?}", canonical.command))
        );
    }
}

/// A saved sign-in for `issuer` in a fresh config folder, with the saved
/// configuration and account `cw logout` also removes (#4016).
fn saved_sign_in(issuer: &str) -> tempfile::TempDir {
    let config = private_mesh_data_fixture();
    let credentials = codewire_client::OAuthCredentials::new(
        issuer,
        "codewire-cli",
        "access-token-4016",
        "refresh-token-4016",
        1_800_000_000,
        "openid codewire.api",
    )
    .unwrap();
    codewire_client::CredentialStore::save(
        &codewire_client::FileCredentialStore::at(crate::config::oauth_credentials_path(
            config.path(),
        )),
        &credentials,
    )
    .unwrap();
    std::fs::write(config.path().join("config.json"), b"{}").unwrap();
    std::fs::write(config.path().join("account.json"), b"{}").unwrap();
    config
}

fn assert_signed_out_locally(config: &std::path::Path) {
    for leftover in [
        crate::config::oauth_credentials_path(config),
        config.join("config.json"),
        config.join("account.json"),
    ] {
        assert!(!leftover.exists(), "cw logout left {}", leftover.display());
    }
}

/// The revocation endpoint answering one token type with `status`.
async fn revocation(server: &wiremock::MockServer, hint: &str, status: u16, calls: u64) {
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/api/oauth/revoke"))
        .and(wiremock::matchers::body_string_contains(format!(
            "token_type_hint={hint}"
        )))
        .respond_with(wiremock::ResponseTemplate::new(status).set_body_string("revocation refused"))
        .expect(calls)
        .mount(server)
        .await;
}

#[tokio::test]
async fn logout_reports_logged_out_only_when_the_server_revoked_both_tokens() {
    let server = wiremock::MockServer::start().await;
    revocation(&server, "refresh_token", 200, 1).await;
    revocation(&server, "access_token", 200, 1).await;
    let config = saved_sign_in(&server.uri());
    let outcome = log_out(config.path(), Some(&server.uri())).await.unwrap();
    assert_eq!(outcome, LogoutOutcome::Revoked);
    assert_signed_out_locally(config.path());
    logout_result(outcome).unwrap();
}

#[tokio::test]
async fn logout_that_the_server_did_not_confirm_removes_the_sign_in_and_fails() {
    // An error response for the refresh token, then for the access token
    // after the refresh token was revoked: either leaves the sign-in alive.
    for (refresh, access, access_calls) in [(500, 200, 0), (200, 400, 1)] {
        let server = wiremock::MockServer::start().await;
        revocation(&server, "refresh_token", refresh, 1).await;
        revocation(&server, "access_token", access, access_calls).await;
        let config = saved_sign_in(&server.uri());
        let outcome = log_out(config.path(), Some(&server.uri())).await.unwrap();
        let LogoutOutcome::NotConfirmed { reason, access_token_expires_at_unix } = &outcome else {
            panic!("an error response was reported as {outcome:?}");
        };
        assert!(reason.contains("revocation refused"), "{reason}");
        assert_eq!(*access_token_expires_at_unix, Some(1_800_000_000));
        assert_signed_out_locally(config.path());
        let message = logout_result(outcome).unwrap_err().to_string();
        assert!(message.contains("the server did not confirm it ended"), "{message}");
        assert!(message.contains("until 2027-01-15 08:00 UTC"), "{message}");
    }
}

#[tokio::test]
async fn logout_with_an_unreachable_server_removes_the_sign_in_and_says_so() {
    // Nothing listens on loopback port 1 and no process is ever given it,
    // so the connection is refused.
    let server_url = "http://127.0.0.1:1".to_owned();
    let config = saved_sign_in(&server_url);
    let outcome = log_out(config.path(), Some(&server_url)).await.unwrap();
    assert_eq!(
        outcome,
        LogoutOutcome::NotConfirmed {
            reason: "the server could not be reached".to_owned(),
            access_token_expires_at_unix: Some(1_800_000_000),
        }
    );
    assert_signed_out_locally(config.path());
    assert!(logout_result(outcome).is_err());
}

#[tokio::test]
async fn logout_never_sends_a_sign_in_to_another_server() {
    let server = wiremock::MockServer::start().await;
    revocation(&server, "refresh_token", 200, 0).await;
    revocation(&server, "access_token", 200, 0).await;
    let config = saved_sign_in("https://other.example.test");
    let outcome = log_out(config.path(), Some(&server.uri())).await.unwrap();
    let LogoutOutcome::NotConfirmed { reason, .. } = &outcome else {
        panic!("an issuer mismatch was reported as {outcome:?}");
    };
    assert!(reason.contains("not for this Codewire server"), "{reason}");
    assert_signed_out_locally(config.path());
}

#[tokio::test]
async fn logout_without_a_saved_sign_in_only_removes_the_configuration() {
    let config = private_mesh_data_fixture();
    std::fs::write(config.path().join("config.json"), b"{}").unwrap();
    let outcome = log_out(config.path(), None).await.unwrap();
    assert_eq!(outcome, LogoutOutcome::NoSignIn);
    assert_signed_out_locally(config.path());
    logout_result(outcome).unwrap();
}
