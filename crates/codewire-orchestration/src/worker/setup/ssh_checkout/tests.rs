use super::*;

const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";
const GITHUB_HTTPS: &str = "https://github.com/org/app.git";

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

fn https(source: &str) -> Repo {
    Repo {
        url: source.into(),
        mount_path: "/workspace/app".into(),
        ..Default::default()
    }
}

fn only(repo: &Repo, clients: Option<ManagedCredentialClients>) -> Option<Command> {
    commands(std::slice::from_ref(repo), clients)
        .unwrap()
        .remove(0)
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
        let command = only(&repo, selected()).unwrap();
        assert!(!command.https_fallback, "an SSH source has no HTTPS URL");
        let argv = command.argv;
        assert_eq!(&argv[4..9], &[source, "/workspace/app", host, port, alias]);
        assert_eq!(argv[9..], repo.known_hosts);
        assert_eq!(argv[2], SCRIPT);
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
        let error = commands(std::slice::from_ref(&repo), clients).unwrap_err();
        assert!(error.to_string().contains("needs an SSH key"), "{error}");
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
fn a_selected_ssh_key_clones_a_github_https_source_over_ssh_with_github_pins() {
    let both = Some(ManagedCredentialClients::from_profile_slots(["github", "ssh"]).unwrap());
    for clients in [selected(), both] {
        for (source, ssh) in [
            (GITHUB_HTTPS, "git@github.com:org/app.git"),
            ("https://github.com/org/app", "git@github.com:org/app"),
        ] {
            let command = only(&https(source), clients).unwrap();
            assert!(command.https_fallback);
            assert_eq!(
                &command.argv[4..9],
                &[ssh, "/workspace/app", "github.com", "22", "github.com"]
            );
            assert_eq!(
                command.argv[9..],
                codewire_project::GITHUB_SSH_KNOWN_HOSTS.map(str::to_owned)
            );
        }
    }
}

#[test]
fn https_without_a_selected_ssh_key_has_no_ssh_wrapper() {
    for clients in [
        None,
        Some(Default::default()),
        Some(ManagedCredentialClients::from_profile_slots(["github"]).unwrap()),
    ] {
        assert_eq!(only(&https(GITHUB_HTTPS), clients), None);
    }
    // Other hosts and non-canonical GitHub URLs keep their own transport.
    for source in [
        "https://gitlab.com/org/app.git",
        "https://github.com/org/app/tree/main",
    ] {
        assert_eq!(only(&https(source), selected()), None);
    }
}

#[test]
fn https_rejects_ignored_trust() {
    let mut repo = https(GITHUB_HTTPS);
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
    let command = only(&repo, selected()).unwrap().argv;
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
    assert!(SCRIPT.contains(&format!("        return {SSH_REFUSED_EXIT}\n")));
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
    use std::path::{Path, PathBuf};
    use std::process::{Command as Process, Output};

    use super::*;

    const PERMISSION_DENIED: &str = "git@github.com: Permission denied (publickey).";
    const NOT_FOUND: &str = "ERROR: Repository not found.";
    const HOST_KEY: &str = "Host key verification failed.";
    const NETWORK: &str = "ssh: connect to host github.com port 22: Connection timed out";

    fn executable(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A synthetic no-network checkout root: the agent socket, a home and
    /// stand-ins for any fixed executables a test replaces.
    struct Fixture {
        root: tempfile::TempDir,
        run: PathBuf,
        socket: PathBuf,
        _listener: UnixListener,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let run = root.path().join("run");
            fs::create_dir(&run).unwrap();
            fs::create_dir(root.path().join("home")).unwrap();
            let socket = run.join("ssh-agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::write(root.path().join("unrelated"), b"preserve public fixture").unwrap();
            Self {
                root,
                run,
                socket,
                _listener: listener,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.path().join(name)
        }

        fn known_hosts(&self) -> PathBuf {
            self.path("home/.ssh/known_hosts")
        }

        /// Run the production script with only its fixed runtime paths and the
        /// named executables substituted. Production accepts none as input.
        fn run(&self, mut argv: Vec<String>, executables: &[(&str, &Path)]) -> Output {
            let mut script = argv[2]
                .replace("/codewire/run", self.run.to_str().unwrap())
                .replace("/home/codewire", self.path("home").to_str().unwrap());
            for (fixed, replacement) in executables {
                script = script.replace(fixed, replacement.to_str().unwrap());
            }
            argv[2] = script;
            Process::new(&argv[0])
                .args(&argv[1..])
                .env_clear()
                .env("SSH_AUTH_SOCK", &self.socket)
                .env("GIT_CONFIG_COUNT", "999")
                .env("GIT_DIR", "/ambient/forbidden")
                .env("GIT_EXEC_PATH", "/ambient/forbidden")
                .env("GIT_SSH", "/ambient/forbidden")
                .env("GIT_SSH_COMMAND", "/ambient/forbidden")
                .output()
                .unwrap()
        }

        /// The script's owned temporary files are gone; `extra` counts any
        /// fixture object left in the runtime directory besides the socket.
        fn assert_runtime_clean(&self, extra: usize) {
            let files = fs::read_dir(&self.run)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(files.len(), 1 + extra, "{files:?}");
            assert_eq!(
                fs::read(self.path("unrelated")).unwrap(),
                b"preserve public fixture"
            );
        }
    }

    /// Stand-in Git that checks the script's isolated environment, records
    /// its arguments and runs the SSH command the script built.
    fn fake_git(fixture: &Fixture, terminate_parent: bool) -> PathBuf {
        let path = fixture.path("git");
        let root = fixture.root.path().to_str().unwrap();
        executable(
            &path,
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
printf '%s\n' "$@" >'{root}/git-argv'
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
        path
    }

    /// Stand-in SSH that records its arguments and pins, says `message` on
    /// stderr and exits `status`.
    fn fake_ssh(fixture: &Fixture, message: &str, status: i32, replace_trust: bool) -> PathBuf {
        let path = fixture.path("ssh");
        let root = fixture.root.path().to_str().unwrap();
        executable(
            &path,
            &format!(
                r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >'{root}/ssh-argv'
for argument do
    case "$argument" in UserKnownHostsFile=*) trust=${{argument#*=}} ;; esac
done
test "$(/usr/bin/stat -c %a -- "$trust")" = 600
/bin/cat -- "$trust" >'{root}/pins'
if test '{replace_trust}' = true; then
    /bin/rm -- "$trust"
    /bin/ln -s '{root}/unrelated' "$trust"
fi
printf '%s\n' '{message}' >&2
exit {status}
"#
            ),
        );
        path
    }

    fn port_repository() -> Repo {
        let mut repo = repository("ssh://git@example.com:2222/org/app.git");
        repo.known_hosts[0].push_str(" literal ' $() `not-executed` %s");
        repo
    }

    fn run_fake(
        repo: &Repo,
        message: &str,
        ssh_status: i32,
        replace_trust: bool,
        terminate_parent: bool,
    ) -> (Fixture, Output) {
        let fixture = Fixture::new();
        let git = fake_git(&fixture, terminate_parent);
        let ssh = fake_ssh(&fixture, message, ssh_status, replace_trust);
        let argv = only(repo, selected()).unwrap().argv;
        let output = fixture.run(argv, &[("/usr/bin/git", &git), ("/usr/bin/ssh", &ssh)]);
        (fixture, output)
    }

    fn assert_exit(output: &Output, expected: i32) {
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_fixed_ssh_call(fixture: &Fixture, repo: &Repo) {
        assert_eq!(
            fs::read_to_string(fixture.path("pins")).unwrap(),
            format!("{}\n", repo.known_hosts.join("\n"))
        );
        let ssh = fs::read_to_string(fixture.path("ssh-argv")).unwrap();
        assert!(ssh.contains("HostKeyAlias=[example.com]:2222\n"));
        assert!(ssh.contains("-p\n2222\n"));
        assert!(ssh.contains("IdentityFile=none\n"));
        assert!(ssh.contains("IdentitiesOnly=no\n"));
        let git = fs::read_to_string(fixture.path("git-argv")).unwrap();
        assert!(git.ends_with(
            "clone\n--progress\n--\nssh://git@example.com:2222/org/app.git\n/workspace/app\n"
        ));
    }

    #[test]
    fn success_uses_literal_pins_records_them_and_cleans_its_owned_files() {
        let repo = port_repository();
        let (fixture, output) = run_fake(&repo, "", 0, false, false);
        assert_exit(&output, 0);
        assert_fixed_ssh_call(&fixture, &repo);
        fixture.assert_runtime_clean(0);
        assert_eq!(
            fs::read_to_string(fixture.known_hosts()).unwrap(),
            format!("{}\n", repo.known_hosts.join("\n"))
        );
        assert_eq!(mode(&fixture.path("home/.ssh")), 0o700);
        assert_eq!(mode(&fixture.known_hosts()), 0o600);
    }

    #[test]
    fn clone_failure_preserves_exit_records_nothing_and_cleans_its_owned_files() {
        let repo = port_repository();
        let (fixture, output) = run_fake(&repo, "", 23, false, false);
        assert_exit(&output, 23);
        assert_fixed_ssh_call(&fixture, &repo);
        fixture.assert_runtime_clean(0);
        assert!(!fixture.path("home/.ssh").exists());
    }

    #[test]
    fn replaced_trust_is_preserved_and_requires_recovery() {
        let repo = port_repository();
        let (fixture, output) = run_fake(&repo, "", 0, true, false);
        assert_exit(&output, 125);
        fixture.assert_runtime_clean(1);
    }

    #[test]
    fn termination_preserves_signal_exit_and_cleans_its_owned_files() {
        let repo = port_repository();
        let (fixture, output) = run_fake(&repo, "", 0, false, true);
        assert_exit(&output, 143);
        fixture.assert_runtime_clean(0);
        assert!(!fixture.path("home/.ssh").exists());
    }

    #[test]
    fn only_a_refused_key_or_repository_reports_the_refusal_status() {
        for (message, expected) in [
            (PERMISSION_DENIED, SSH_REFUSED_EXIT),
            (NOT_FOUND, SSH_REFUSED_EXIT),
            (
                "ERROR: Permission to org/app.git denied to someone.",
                SSH_REFUSED_EXIT,
            ),
            (HOST_KEY, 255),
            (NETWORK, 255),
            (
                "ssh: Could not resolve hostname github.com: Name or service not known",
                255,
            ),
        ] {
            let repo = port_repository();
            let (fixture, output) = run_fake(&repo, message, 255, false, false);
            assert_exit(&output, expected);
            // What OpenSSH and the server said still reaches the exec's stderr.
            assert!(String::from_utf8_lossy(&output.stderr).contains(message));
            fixture.assert_runtime_clean(0);
            assert!(!fixture.path("home/.ssh").exists());
        }
    }

    #[test]
    fn a_host_key_failure_never_reports_a_refusal() {
        let repo = port_repository();
        let message = format!("{HOST_KEY}\n{PERMISSION_DENIED}");
        let (_fixture, output) = run_fake(&repo, &message, 255, false, false);
        assert_exit(&output, 255);
    }

    #[test]
    fn recorded_trust_is_appended_once_and_never_rewrites_existing_lines() {
        let repo = port_repository();
        let fixture = Fixture::new();
        let git = fake_git(&fixture, false);
        let ssh = fake_ssh(&fixture, "", 0, false);
        fs::create_dir(fixture.path("home/.ssh")).unwrap();
        // An existing user line without a trailing newline stays intact.
        fs::write(fixture.known_hosts(), "own.example ssh-ed25519 AAAA").unwrap();
        for _ in 0..2 {
            let argv = only(&repo, selected()).unwrap().argv;
            let output = fixture.run(argv, &[("/usr/bin/git", &git), ("/usr/bin/ssh", &ssh)]);
            assert_exit(&output, 0);
        }
        assert_eq!(
            fs::read_to_string(fixture.known_hosts()).unwrap(),
            format!(
                "own.example ssh-ed25519 AAAA\n{}\n",
                repo.known_hosts.join("\n")
            )
        );
    }

    /// Real Git clones the rewritten GitHub source through a stand-in SSH
    /// transport that serves a local repository, so the recorded origin and
    /// checkout are Git's own.
    mod real_git {
        use super::*;

        const CONTENT: &str = "ssh-first-checkout-synthetic\n";

        fn git(directory: &Path, arguments: &[&str]) -> String {
            let output = Process::new("/usr/bin/git")
                .arg("-C")
                .arg(directory)
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
                .env("GIT_COMMITTER_NAME", "fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        }

        /// A bare repository with one commit, and an SSH stand-in that serves
        /// it for exactly the rewritten path, or refuses the key.
        fn serve(fixture: &Fixture, refuse: bool) -> PathBuf {
            let work = fixture.path("work");
            fs::create_dir(&work).unwrap();
            git(&work, &["init", "--quiet", "--initial-branch=main"]);
            fs::write(work.join("proof.txt"), CONTENT).unwrap();
            git(&work, &["add", "proof.txt"]);
            git(&work, &["commit", "--quiet", "-m", "proof"]);
            let bare = fixture.path("served.git");
            git(
                fixture.root.path(),
                &[
                    "clone",
                    "--quiet",
                    "--bare",
                    work.to_str().unwrap(),
                    bare.to_str().unwrap(),
                ],
            );
            let ssh = fixture.path("ssh");
            let root = fixture.root.path().to_str().unwrap();
            executable(
                &ssh,
                &format!(
                    r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >'{root}/ssh-argv'
for last do :; done
if test '{refuse}' = true; then
    printf '%s\n' '{PERMISSION_DENIED}' >&2
    exit 255
fi
test "$last" = "git-upload-pack 'org/app.git'"
exec /usr/bin/git upload-pack '{bare}'
"#,
                    bare = bare.display(),
                ),
            );
            ssh
        }

        #[test]
        fn the_checkout_records_the_ssh_origin_and_the_github_pins() {
            let fixture = Fixture::new();
            let ssh = serve(&fixture, false);
            for destination in ["first", "second"] {
                let destination = fixture.path(destination);
                let mut repo = https(GITHUB_HTTPS);
                repo.mount_path = destination.to_str().unwrap().into();
                let argv = only(&repo, selected()).unwrap().argv;
                let output = fixture.run(argv, &[("/usr/bin/ssh", &ssh)]);
                assert_exit(&output, 0);
                assert_eq!(
                    git(&destination, &["config", "--get", "remote.origin.url"]),
                    "git@github.com:org/app.git\n"
                );
                assert_eq!(
                    fs::read_to_string(destination.join("proof.txt")).unwrap(),
                    CONTENT
                );
                // No Codewire SSH command or trust is left in the checkout.
                assert!(
                    !fs::read_to_string(destination.join(".git/config"))
                        .unwrap()
                        .contains("sshCommand")
                );
            }
            let ssh_argv = fs::read_to_string(fixture.path("ssh-argv")).unwrap();
            assert!(ssh_argv.contains("HostKeyAlias=github.com\n"));
            assert!(ssh_argv.contains("git@github.com\n"));
            assert_eq!(
                fs::read_to_string(fixture.known_hosts()).unwrap(),
                format!("{}\n", codewire_project::GITHUB_SSH_KNOWN_HOSTS.join("\n"))
            );
            assert_eq!(mode(&fixture.known_hosts()), 0o600);
            fixture.assert_runtime_clean(0);
        }

        #[test]
        fn a_refused_key_reports_the_refusal_and_leaves_nothing_behind() {
            let fixture = Fixture::new();
            let ssh = serve(&fixture, true);
            let destination = fixture.path("refused");
            let mut repo = https(GITHUB_HTTPS);
            repo.mount_path = destination.to_str().unwrap().into();
            let argv = only(&repo, selected()).unwrap().argv;
            let output = fixture.run(argv, &[("/usr/bin/ssh", &ssh)]);
            assert_exit(&output, SSH_REFUSED_EXIT);
            assert!(!destination.exists());
            assert!(!fixture.path("home/.ssh").exists());
            fixture.assert_runtime_clean(0);
        }
    }
}
