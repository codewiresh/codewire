//! Rust-owned workspace setup script builders, pinned byte-for-byte by the
//! checked-in fixtures under `tests/fixtures/setup_scripts`.

use std::collections::{BTreeMap, BTreeSet};

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
}
