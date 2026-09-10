use super::*;

const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";

fn selected() -> Option<ManagedCredentialClients> {
    Some(ManagedCredentialClients::from_profile_slots(["ssh"]).unwrap())
}

fn repository(source: &str) -> Repo {
    let host = parse_repository_ssh_host(source).unwrap().unwrap();
    Repo {
        url: source.into(),
        mount_path: "/workspace/app".into(),
        known_hosts: vec![format!("{} ssh-ed25519 {KEY}", host.known_hosts_name())],
        ..Default::default()
    }
}

#[test]
fn exact_alias_and_port_are_separate_arguments() {
    for (source, host, port, alias) in [
        (
            "git@Example.COM:org/app.git",
            "example.com",
            "22",
            "example.com",
        ),
        (
            "ssh://git@example.com:2222/org/app.git",
            "example.com",
            "2222",
            "[example.com]:2222",
        ),
        (
            "ssh://git@[2001:db8::1]:2222/org/app.git",
            "2001:db8::1",
            "2222",
            "[2001:db8::1]:2222",
        ),
    ] {
        let repo = repository(source);
        let command = commands(std::slice::from_ref(&repo), selected())
            .unwrap()
            .remove(0)
            .unwrap();
        assert_eq!(
            &command[4..9],
            &[source, "/workspace/app", host, port, alias]
        );
        assert_eq!(command[9..], repo.known_hosts);
        assert_eq!(command[2], SCRIPT);
    }
}

#[test]
fn missing_or_unselected_ssh_never_returns_launch_commands() {
    let repo = repository("git@example.com:org/app.git");
    for clients in [
        None,
        Some(Default::default()),
        Some(ManagedCredentialClients::from_profile_slots(["github"]).unwrap()),
    ] {
        assert!(commands(std::slice::from_ref(&repo), clients).is_err());
    }
}

#[test]
fn all_trust_is_checked_before_any_commands_are_returned() {
    let valid = repository("git@example.com:org/app.git");
    for pins in [
        Vec::new(),
        vec![format!("wrong.example ssh-ed25519 {KEY}")],
        vec![format!(" example.com  ssh-ed25519 {KEY}")],
        vec![format!(
            "example.com ssh-ed25519 {KEY}\nother ssh-ed25519 {KEY}"
        )],
    ] {
        let mut invalid = valid.clone();
        invalid.known_hosts = pins;
        assert!(commands(&[valid.clone(), invalid], selected()).is_err());
    }
}

#[test]
fn https_has_no_ssh_wrapper_and_rejects_ignored_trust() {
    let mut repo = Repo {
        url: "https://github.com/org/app.git".into(),
        mount_path: "/workspace/app".into(),
        ..Default::default()
    };
    assert_eq!(
        commands(std::slice::from_ref(&repo), None).unwrap(),
        vec![None]
    );
    repo.known_hosts = vec![format!("github.com ssh-ed25519 {KEY}")];
    assert!(commands(&[repo], selected()).is_err());
}

#[test]
fn maximum_public_trust_stays_in_separate_bounded_arguments() {
    let mut repo = repository("git@example.com:org/app.git");
    let prefix = format!("example.com ssh-ed25519 {KEY} ");
    repo.known_hosts = (0..8)
        .map(|index| {
            let prefix = format!("{prefix}{index} ");
            format!("{prefix}{}", "'".repeat(8191 - prefix.len()))
        })
        .collect();
    assert_eq!(
        repo.known_hosts
            .iter()
            .map(|line| line.len() + 1)
            .sum::<usize>(),
        codewire_project::MAX_REPOSITORY_KNOWN_HOSTS_BYTES
    );
    let command = commands(&[repo], selected()).unwrap().remove(0).unwrap();
    assert_eq!(command[2], SCRIPT);
    assert!(command.iter().all(|argument| argument.len() < 128 * 1024));
    assert!(command.iter().map(String::len).sum::<usize>() < 1024 * 1024);
    assert!(command.len() < 1024);
}

#[test]
fn selected_socket_and_stock_ssh_fences_are_fixed() {
    assert!(SCRIPT.contains(&format!(
        "test \"${{SSH_AUTH_SOCK-}}\" = {}",
        codewire_access::SSH_PLATFORM_AUTH_SOCK
    )));
    for option in [
        "-F /dev/null",
        "-p '$cw_port'",
        "HostKeyAlias=$cw_alias",
        "GlobalKnownHostsFile=/dev/null",
        "StrictHostKeyChecking=yes",
        "IdentityFile=none",
        "IdentitiesOnly=no",
        "BatchMode=yes",
        "IdentityAgent=/codewire/run/ssh-agent.sock",
        "PreferredAuthentications=publickey",
        "ForwardAgent=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ControlMaster=no",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "core.hooksPath=/dev/null",
    ] {
        assert!(SCRIPT.contains(option), "missing {option}");
    }
    assert!(!SCRIPT.contains("IdentitiesOnly=yes"));
    assert!(!SCRIPT.contains("exec /usr/bin/git"));
}

#[cfg(target_os = "linux")]
mod shell {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::process::Command;

    use super::*;

    fn executable(path: &std::path::Path, content: &str) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run(exit_code: i32, replace_trust: bool, terminate_parent: bool) {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_str().unwrap();
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        let socket = run.join("ssh-agent.sock");
        let _socket = UnixListener::bind(&socket).unwrap();
        let fake_git = root.path().join("git");
        let fake_ssh = root.path().join("ssh");
        fs::write(root.path().join("unrelated"), b"preserve public fixture").unwrap();
        executable(
            &fake_git,
            &format!(
                r#"#!/bin/sh
set -eu
test -z "${{GIT_CONFIG_COUNT-}}"
test -z "${{GIT_DIR-}}"
test -z "${{GIT_EXEC_PATH-}}"
test -z "${{GIT_SSH-}}"
test "$GIT_CONFIG_GLOBAL" = /dev/null
test "$GIT_CONFIG_SYSTEM" = /dev/null
test "$GIT_SSH_VARIANT" = ssh
printf '%s\n' "$@" >'{root_path}/git-argv'
status=0
/bin/sh -c "$GIT_SSH_COMMAND" || status=$?
if test '{terminate_parent}' = true; then
    # This fixture's direct parent is its owned checkout-wrapper process.
    kill -TERM "$PPID"
fi
exit "$status"
"#
            ),
        );
        executable(
            &fake_ssh,
            &format!(
                r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >'{root_path}/ssh-argv'
for argument do
    case "$argument" in UserKnownHostsFile=*) trust=${{argument#*=}} ;; esac
done
test "$(/usr/bin/stat -c %a -- "$trust")" = 600
/bin/cat -- "$trust" >'{root_path}/pins'
if test '{replace_trust}' = true; then
    /bin/rm -- "$trust"
    /bin/ln -s '{root_path}/unrelated' "$trust"
fi
exit {exit_code}
"#
            ),
        );
        let mut repo = repository("ssh://git@example.com:2222/org/app.git");
        repo.known_hosts[0].push_str(" literal ' $() `not-executed` %s");
        let mut command = commands(std::slice::from_ref(&repo), selected())
            .unwrap()
            .remove(0)
            .unwrap();
        // Substitute only fixed executable/runtime paths inside this synthetic
        // no-network fixture. Production accepts none of these as input knobs.
        command[2] = command[2]
            .replace("/codewire/run", run.to_str().unwrap())
            .replace("/usr/bin/git", fake_git.to_str().unwrap())
            .replace("/usr/bin/ssh", fake_ssh.to_str().unwrap());
        let output = Command::new(&command[0])
            .args(&command[1..])
            .env_clear()
            .env("SSH_AUTH_SOCK", &socket)
            .env("GIT_CONFIG_COUNT", "999")
            .env("GIT_DIR", "/ambient/forbidden")
            .env("GIT_EXEC_PATH", "/ambient/forbidden")
            .env("GIT_SSH", "/ambient/forbidden")
            .env("GIT_SSH_COMMAND", "/ambient/forbidden")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if replace_trust {
                125
            } else if terminate_parent {
                143
            } else {
                exit_code
            }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(root.path().join("pins")).unwrap(),
            format!("{}\n", repo.known_hosts.join("\n"))
        );
        let ssh = fs::read_to_string(root.path().join("ssh-argv")).unwrap();
        assert!(ssh.contains("HostKeyAlias=[example.com]:2222\n"));
        assert!(ssh.contains("-p\n2222\n"));
        assert!(ssh.contains("IdentityFile=none\n"));
        assert!(ssh.contains("IdentitiesOnly=no\n"));
        let git = fs::read_to_string(root.path().join("git-argv")).unwrap();
        assert!(
            git.ends_with("clone\n--\nssh://git@example.com:2222/org/app.git\n/workspace/app\n")
        );
        let files = fs::read_dir(&run)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(files.len(), if replace_trust { 2 } else { 1 });
        assert_eq!(
            fs::read(root.path().join("unrelated")).unwrap(),
            b"preserve public fixture"
        );
    }

    #[test]
    fn success_uses_literal_pins_and_cleans_its_owned_file() {
        run(0, false, false);
    }

    #[test]
    fn clone_failure_preserves_exit_and_cleans_its_owned_file() {
        run(23, false, false);
    }

    #[test]
    fn replaced_trust_is_preserved_and_requires_recovery() {
        run(0, true, false);
    }

    #[test]
    fn termination_preserves_signal_exit_and_cleans_its_owned_file() {
        run(0, false, true);
    }
}
