//! Rust-owned workspace setup script builders, pinned byte-for-byte by the
//! checked-in fixtures under `tests/fixtures/setup_scripts`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::sandbox::template::DIND_SOCKET_PATH;

/// Mirrors `shellQuoteLiteral` / sandbox.`shellQuote` (same impl).
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn unused_heredoc_delimiter(prefix: &str, content: &str) -> String {
    let lines = content.lines().collect::<BTreeSet<_>>();
    for index in 0..=lines.len() {
        let candidate = format!("{prefix}_{index}");
        if !lines.contains(candidate.as_str()) {
            return candidate;
        }
    }
    unreachable!("one more delimiter candidate exists than occupied lines")
}

/// Set the global Git author in one workspace exec: the email, then the name
/// only if the email succeeded. Both values travel as positional arguments,
/// never as shell source.
pub fn build_git_identity_command(email: &str, name: &str) -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        r#"git config --global user.email "$1" && git config --global user.name "$2""#.to_string(),
        "codewire-git-identity".to_string(),
        email.to_string(),
        name.to_string(),
    ]
}

/// The configure-environment exec's status when the ordinary defaults were
/// published and only the Git author could not be set: setup keeps that a
/// warning. A failed publication keeps its own status, and is never this one.
pub const GIT_IDENTITY_FAILED_EXIT: i32 = 78;

/// `configure_environment` in one workspace exec: publish the ordinary
/// defaults ([`build_workspace_env_script`]), then, only once they are
/// published, set the Git author exactly as [`build_git_identity_command`]
/// does. Without an author it is the defaults script alone.
///
/// The defaults run in a subshell, so their `set -eu` and traps are their own
/// and the author never runs after a failed publication. That failure keeps
/// its status, except that [`GIT_IDENTITY_FAILED_EXIT`] reads as 1. The Git
/// values travel as positional arguments, never as shell source.
pub fn build_configure_environment_command(
    env_vars: &BTreeMap<String, String>,
    git_identity: Option<(&str, &str)>,
) -> Vec<String> {
    configure_environment_command_at(env_vars, "/home/codewire/.codewire", git_identity)
}

fn configure_environment_command_at(
    env_vars: &BTreeMap<String, String>,
    directory: &str,
    git_identity: Option<(&str, &str)>,
) -> Vec<String> {
    let defaults = workspace_env_script_at(env_vars, directory);
    let Some((email, name)) = git_identity else {
        return vec!["/bin/sh".to_string(), "-c".to_string(), defaults];
    };
    let script = format!(
        concat!(
            "(\n{defaults})\n",
            "cw_status=$?\n",
            "if [ \"$cw_status\" -ne 0 ]; then\n",
            "  [ \"$cw_status\" -ne {git_failed} ] || cw_status=1\n",
            "  exit \"$cw_status\"\n",
            "fi\n",
            "git config --global user.email \"$1\" && git config --global user.name \"$2\" ",
            "|| exit {git_failed}\n",
        ),
        defaults = defaults,
        git_failed = GIT_IDENTITY_FAILED_EXIT,
    );
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        script,
        "codewire-configure-environment".to_string(),
        email.to_string(),
        name.to_string(),
    ]
}

/// How long a setup command waits for the pod-local Docker socket.
pub const DOCKER_SOCKET_WAIT: Duration = Duration::from_secs(60);

/// Run a user's setup command (install command or startup script) as
/// `sh -c <script>`, after a bounded wait for the pod-local Docker socket.
/// Docker no longer gates workspace readiness, so setup can reach a user
/// command while dockerd is still starting (owner, 2026-10-27: "a docker
/// command run before then waits for it"; Program #2238). The wait applies
/// only while the workspace's `DOCKER_HOST` names that socket and it does not
/// exist yet; it never fails, so after [`DOCKER_SOCKET_WAIT`] the command runs
/// and Docker reports its own error. The script then replaces the waiting
/// shell, with the same argv, `$0`, process and exit status as before.
pub fn build_user_setup_command(script: &str) -> Vec<String> {
    user_setup_command_at(script, DIND_SOCKET_PATH, DOCKER_SOCKET_WAIT)
}

fn user_setup_command_at(script: &str, socket: &str, wait: Duration) -> Vec<String> {
    // Fifth-of-a-second steps; a `sleep` without fractions counts five.
    let steps = wait.as_secs() * 5;
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            concat!(
                "socket={socket}\n",
                "if [ \"${{DOCKER_HOST:-}}\" = \"unix://$socket\" ]; then\n",
                "  steps=0\n",
                "  while [ ! -S \"$socket\" ] && [ \"$steps\" -lt {steps} ]; do\n",
                "    if sleep 0.2 2>/dev/null; then steps=$((steps + 1)); else sleep 1; steps=$((steps + 5)); fi\n",
                "  done\n",
                "fi\n",
                "exec sh -c \"$1\"\n",
            ),
            socket = shell_quote(socket),
            steps = steps,
        ),
        "sh".to_string(),
        script.to_string(),
    ]
}

/// Publish ordinary defaults for the daemon, never resolved application values.
/// The daemon home is fixed, independent of a projected or overridden HOME.
/// Shell startup files must not reapply defaults above a launch projection.
pub fn build_workspace_env_script(env_vars: &BTreeMap<String, String>) -> String {
    workspace_env_script_at(env_vars, "/home/codewire/.codewire")
}

fn workspace_env_script_at(env_vars: &BTreeMap<String, String>, directory: &str) -> String {
    let environment_json = serde_json::to_string_pretty(env_vars).expect("string map serializes");
    let json_delimiter = unused_heredoc_delimiter("CW_ENVIRONMENT_JSON", &environment_json);

    format!(
        concat!(
            "set -eu\n",
            "umask 077\n",
            "cw_env_dir={directory}\n",
            "/bin/mkdir -p -- \"$cw_env_dir\"\n",
            "cw_env_file=$(/usr/bin/mktemp \"$cw_env_dir/.environment.XXXXXXXX\")\n",
            "trap '/bin/rm -f -- \"$cw_env_file\"' EXIT HUP INT TERM\n",
            "/bin/cat > \"$cw_env_file\" <<'{json_delimiter}'\n",
            "{environment_json}\n{json_delimiter}\n",
            "/bin/chmod 0600 -- \"$cw_env_file\"\n",
            "/bin/mv -fT -- \"$cw_env_file\" \"$cw_env_dir/environment.json\"\n",
            "trap - EXIT HUP INT TERM\n",
        ),
        directory = shell_quote(directory),
        json_delimiter = json_delimiter,
        environment_json = environment_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn golden(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/setup_scripts/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read golden {path}: {e}"))
    }

    #[test]
    fn workspace_env_script_matches_golden() {
        let mut vars = BTreeMap::new();
        vars.insert("ZETA_TOKEN".to_string(), "it's quoted".to_string());
        vars.insert("ALPHA_KEY".to_string(), "plain-value".to_string());
        vars.insert(
            "CONNECT_URL".to_string(),
            "postgres://u:p@h:5432/db?sslmode=disable".to_string(),
        );
        assert_eq!(
            build_workspace_env_script(&vars),
            golden("workspace_env.golden.txt")
        );
    }

    #[test]
    fn workspace_env_script_round_trips_delimiters_and_shell_syntax() {
        let home = tempfile::tempdir().expect("temporary home");
        let payload = concat!(
            "before\n",
            "CW_ENVIRONMENT_SH_0\n",
            "touch \"$HOME/injected\"\n",
            "CW_ENVIRONMENT_JSON_0\n",
            "$(touch \"$HOME/expanded\")\n",
            "`touch \"$HOME/backtick\"`\n",
            "after"
        );
        let vars = BTreeMap::from([("PAYLOAD".to_owned(), payload.to_owned())]);
        let script = workspace_env_script_at(&vars, home.path().to_str().unwrap());
        assert!(script.contains("<<'CW_ENVIRONMENT_JSON_0'"));

        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin")
            .status()
            .expect("execute generated setup script");
        assert!(status.success());
        for marker in ["injected", "expanded", "backtick"] {
            assert!(!home.path().join(marker).exists(), "created {marker}");
        }

        let json: BTreeMap<String, String> = serde_json::from_slice(
            &fs::read(home.path().join("environment.json")).expect("read generated JSON"),
        )
        .expect("parse generated JSON");
        assert_eq!(json, vars);
        assert!(!script.contains("environment.sh"));
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);
    }

    #[test]
    fn ordinary_defaults_replace_with_empty_and_do_not_follow_workload_home() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("daemon's defaults");
        let decoy = root.path().join("workload-home");
        for values in [
            BTreeMap::from([("OLD".into(), "synthetic".into())]),
            BTreeMap::new(),
        ] {
            let status = Command::new("/bin/sh")
                .args([
                    "-c",
                    &workspace_env_script_at(&values, directory.to_str().unwrap()),
                ])
                .env_clear()
                .env("HOME", &decoy)
                .env("PATH", "/nonexistent")
                .status()
                .unwrap();
            assert!(status.success());
            let path = directory.join("environment.json");
            let actual: BTreeMap<String, String> =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(actual, values);
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
            assert!(!decoy.exists());
        }
        assert!(!build_workspace_env_script(&BTreeMap::new()).contains("$HOME"));
    }

    /// Run the Git identity command against a recording `git` that fails
    /// only for `fail_key`. Returns its exit status, the recorded calls, and
    /// whether any shell syntax in a value ran.
    fn run_git_identity(
        email: &str,
        name: &str,
        fail_key: &str,
    ) -> (std::process::ExitStatus, Vec<String>, bool) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let git = root.path().join("git");
        fs::write(
            &git,
            concat!(
                "#!/bin/sh\n",
                "printf '[%s]' \"$@\" >> \"$GIT_LOG\"\n",
                "printf '\\n' >> \"$GIT_LOG\"\n",
                "[ \"$3\" != \"$FAIL_KEY\" ]\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        let log = root.path().join("calls");
        let command = build_git_identity_command(email, name);
        let status = Command::new(&command[0])
            .args(&command[1..])
            .current_dir(root.path())
            .env_clear()
            // The recording `git` shadows any real one; `touch` stays
            // reachable so injected shell syntax would leave a marker.
            .env("PATH", format!("{}:/usr/bin:/bin", root.path().display()))
            .env("HOME", root.path())
            .env("GIT_LOG", &log)
            .env("FAIL_KEY", fail_key)
            .status()
            .unwrap();
        let calls = fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        (status, calls, root.path().join("injected").exists())
    }

    #[test]
    fn git_identity_sets_email_then_name_from_literal_arguments() {
        let email = "o'brien+$(touch injected)@example.test";
        let name = "Ann `touch injected` \"Q\" O'Brien";
        let (status, calls, injected) = run_git_identity(email, name, "");
        assert!(status.success());
        assert!(!injected);
        assert_eq!(
            calls,
            [
                format!("[config][--global][user.email][{email}]"),
                format!("[config][--global][user.name][{name}]"),
            ]
        );
    }

    #[test]
    fn git_identity_failure_is_not_success_and_stops_after_email() {
        let (status, calls, _) = run_git_identity("a@example.test", "A", "user.email");
        assert!(!status.success());
        assert_eq!(
            calls,
            ["[config][--global][user.email][a@example.test]".to_string()]
        );
        let (status, calls, _) = run_git_identity("a@example.test", "A", "user.name");
        assert!(!status.success());
        assert_eq!(calls.len(), 2);
    }

    /// Run the configure-environment command against a recording `git` that
    /// fails only for `fail_key`, publishing into `directory` unless
    /// `block_defaults` makes that path a file. Returns the exit code, the
    /// recorded Git calls, and the published defaults, if any.
    fn run_configure_environment(
        vars: &BTreeMap<String, String>,
        identity: (&str, &str),
        fail_key: &str,
        block_defaults: bool,
    ) -> (i32, Vec<String>, Option<BTreeMap<String, String>>, bool) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let git = root.path().join("git");
        fs::write(
            &git,
            concat!(
                "#!/bin/sh\n",
                "printf '[%s]' \"$@\" >> \"$GIT_LOG\"\n",
                "printf '\\n' >> \"$GIT_LOG\"\n",
                "[ \"$3\" != \"$FAIL_KEY\" ]\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        let directory = root.path().join("defaults");
        if block_defaults {
            fs::write(&directory, b"synthetic existing object").unwrap();
        }
        let log = root.path().join("calls");
        let command =
            configure_environment_command_at(vars, directory.to_str().unwrap(), Some(identity));
        let status = Command::new(&command[0])
            .args(&command[1..])
            .current_dir(root.path())
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", root.path().display()))
            .env("HOME", root.path())
            .env("GIT_LOG", &log)
            .env("FAIL_KEY", fail_key)
            .status()
            .unwrap();
        let calls = fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        let published = (!block_defaults)
            .then(|| fs::read(directory.join("environment.json")).ok())
            .flatten()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap());
        (
            status.code().expect("exit status"),
            calls,
            published,
            root.path().join("injected").exists(),
        )
    }

    #[test]
    fn configure_environment_without_identity_is_the_defaults_script() {
        let vars = BTreeMap::from([("ALPHA_KEY".to_owned(), "plain-value".to_owned())]);
        assert_eq!(
            build_configure_environment_command(&vars, None),
            [
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                build_workspace_env_script(&vars)
            ]
        );
    }

    #[test]
    fn configure_environment_publishes_defaults_then_sets_the_author() {
        let vars = BTreeMap::from([(
            "PAYLOAD".to_owned(),
            "CW_ENVIRONMENT_JSON_0\n$(touch injected)\n'quoted'".to_owned(),
        )]);
        let email = "o'brien+$(touch injected)@example.test";
        let name = "Ann `touch injected` \"Q\" O'Brien";
        let (code, calls, published, injected) =
            run_configure_environment(&vars, (email, name), "", false);
        assert_eq!(code, 0);
        assert!(!injected);
        assert_eq!(published, Some(vars));
        assert_eq!(
            calls,
            [
                format!("[config][--global][user.email][{email}]"),
                format!("[config][--global][user.name][{name}]"),
            ]
        );
    }

    #[test]
    fn configure_environment_author_failure_is_its_own_status() {
        let vars = BTreeMap::from([("ALPHA_KEY".to_owned(), "plain-value".to_owned())]);
        for (fail_key, expected_calls) in [("user.email", 1), ("user.name", 2)] {
            let (code, calls, published, _) =
                run_configure_environment(&vars, ("a@example.test", "A"), fail_key, false);
            assert_eq!(code, GIT_IDENTITY_FAILED_EXIT);
            assert_eq!(calls.len(), expected_calls);
            assert_eq!(published.as_ref(), Some(&vars));
        }
    }

    #[test]
    fn configure_environment_defaults_failure_skips_the_author() {
        let (code, calls, _, _) =
            run_configure_environment(&BTreeMap::new(), ("a@example.test", "A"), "", true);
        assert_ne!(code, 0);
        assert_ne!(code, GIT_IDENTITY_FAILED_EXIT);
        assert!(calls.is_empty());
    }

    #[test]
    fn ordinary_defaults_write_failure_is_not_success() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("not-a-directory");
        fs::write(&directory, b"synthetic existing object").unwrap();
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                &workspace_env_script_at(&BTreeMap::new(), directory.to_str().unwrap()),
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(fs::read(directory).unwrap(), b"synthetic existing object");
    }

    #[test]
    fn user_setup_command_matches_golden() {
        let command = build_user_setup_command("npm ci && docker compose up -d");
        assert_eq!(command[..2], ["sh", "-c"]);
        assert_eq!(command[2], golden("user_setup_command.golden.txt"));
        assert_eq!(command[3..], ["sh", "npm ci && docker compose up -d"]);
    }

    /// Run a user setup command that waits up to `wait` for `socket`, with
    /// `docker_host` as the workspace's `DOCKER_HOST`. Returns its output and
    /// how long it took.
    fn run_user_setup_command(
        script: &str,
        socket: &std::path::Path,
        docker_host: Option<String>,
        wait: Duration,
    ) -> (std::process::Output, Duration) {
        let command = user_setup_command_at(script, socket.to_str().unwrap(), wait);
        let mut process = Command::new(&command[0]);
        process
            .args(&command[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        if let Some(docker_host) = docker_host {
            process.env("DOCKER_HOST", docker_host);
        }
        let started = std::time::Instant::now();
        let output = process.output().unwrap();
        (output, started.elapsed())
    }

    #[test]
    fn user_setup_command_runs_the_script_unchanged_without_pod_docker() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("docker.sock");
        let script = "printf '%s|%s|%s' \"$0\" \"$#\" \"$socket\"; exit 7";
        for docker_host in [None, Some("unix:///elsewhere/docker.sock".to_string())] {
            let (output, elapsed) =
                run_user_setup_command(script, &socket, docker_host.clone(), DOCKER_SOCKET_WAIT);
            assert_eq!(output.status.code(), Some(7), "{docker_host:?}");
            // `$0` is `sh` and no wait variable reaches the script.
            assert_eq!(output.stdout, b"sh|0|", "{docker_host:?}");
            assert!(elapsed < Duration::from_secs(5), "{docker_host:?} waited");
        }
    }

    #[test]
    fn user_setup_command_waits_for_the_pod_docker_socket() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("docker.sock");
        let late = socket.clone();
        let listener = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            std::os::unix::net::UnixListener::bind(late).unwrap()
        });
        let (output, elapsed) = run_user_setup_command(
            "printf ok",
            &socket,
            Some(format!("unix://{}", socket.display())),
            DOCKER_SOCKET_WAIT,
        );
        let _listener = listener.join().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ok");
        assert!(socket.exists());
        assert!(
            elapsed >= Duration::from_millis(500),
            "ran before the socket"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "kept waiting after the socket"
        );
    }

    #[test]
    fn user_setup_command_stops_waiting_after_its_bound() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("docker.sock");
        let (output, elapsed) = run_user_setup_command(
            "printf ran; exit 3",
            &socket,
            Some(format!("unix://{}", socket.display())),
            Duration::from_secs(1),
        );
        // The wait never fails the command: it runs and keeps its status.
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"ran");
        assert!(elapsed >= Duration::from_secs(1), "gave up early");
        assert!(elapsed < Duration::from_secs(10), "did not stop waiting");
    }
}
