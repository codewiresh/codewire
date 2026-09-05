//! Rust-owned workspace setup script builders, pinned byte-for-byte by the
//! checked-in fixtures under `tests/fixtures/setup_scripts`.

use std::collections::{BTreeMap, BTreeSet};

/// Mirrors `shellQuoteLiteral` / sandbox.`shellQuote` (same impl).
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Pretty-prints JSON the way Go's `json.MarshalIndent(v, "", "  ")`
/// does for a string map: sorted keys (BTreeMap), two-space indent,
/// and HTML-escaped `&`, `<`, `>` inside strings.
fn go_marshal_indent(map: &BTreeMap<String, String>) -> String {
    let v: serde_json::Value = map
        .iter()
        .map(|(k, val)| (k.clone(), serde_json::Value::String(val.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    serde_json::to_string_pretty(&v)
        .expect("string map serializes")
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
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

/// Mirrors `buildWorkspaceEnvScript`.
pub fn build_workspace_env_script(env_vars: &BTreeMap<String, String>) -> String {
    let mut environment_sh = String::new();
    for (key, value) in env_vars {
        environment_sh.push_str("export ");
        environment_sh.push_str(key);
        environment_sh.push('=');
        environment_sh.push_str(&shell_quote(value));
        environment_sh.push('\n');
    }
    let environment_json = go_marshal_indent(env_vars);
    let shell_delimiter = unused_heredoc_delimiter("CW_ENVIRONMENT_SH", &environment_sh);
    let json_delimiter = unused_heredoc_delimiter("CW_ENVIRONMENT_JSON", &environment_json);

    format!(
        concat!(
            "set -eu\n",
            "umask 077\n",
            "mkdir -p \"$HOME/.codewire\"\n",
            "cat > \"$HOME/.codewire/environment.sh\" <<'{shell_delimiter}'\n",
            "{environment_sh}{shell_delimiter}\n",
            "cat > \"$HOME/.codewire/environment.json\" <<'{json_delimiter}'\n",
            "{environment_json}\n{json_delimiter}\n",
            "chmod 600 \"$HOME/.codewire/environment.sh\" \"$HOME/.codewire/environment.json\"\n",
            "for rc in \"$HOME/.profile\" \"$HOME/.bash_profile\" \"$HOME/.bashrc\" \"$HOME/.zshrc\"; do\n",
            "  touch \"$rc\"\n",
            "  line='[ -f \"$HOME/.codewire/environment.sh\" ] && . \"$HOME/.codewire/environment.sh\"'\n",
            "  if ! grep -Fqx \"$line\" \"$rc\"; then\n",
            "    printf '\\n%s\\n' \"$line\" >> \"$rc\"\n",
            "  fi\n",
            "done\n",
        ),
        shell_delimiter = shell_delimiter,
        environment_sh = environment_sh,
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
        let script = build_workspace_env_script(&vars);
        assert!(script.contains("<<'CW_ENVIRONMENT_SH_1'"));
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

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(". \"$HOME/.codewire/environment.sh\"; printf '%s' \"$PAYLOAD\"")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("source generated environment");
        assert!(output.status.success());
        assert_eq!(output.stdout, payload.as_bytes());

        let json: BTreeMap<String, String> = serde_json::from_slice(
            &fs::read(home.path().join(".codewire/environment.json")).expect("read generated JSON"),
        )
        .expect("parse generated JSON");
        assert_eq!(json, vars);
    }
}
