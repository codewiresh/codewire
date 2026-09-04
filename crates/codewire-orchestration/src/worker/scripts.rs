//! Rust-owned workspace setup script builders, pinned byte-for-byte by the
//! checked-in fixtures under `tests/fixtures/setup_scripts`.

use std::collections::BTreeMap;

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

/// Mirrors `buildWorkspaceEnvScript`.
pub fn build_workspace_env_script(env_vars: &BTreeMap<String, String>) -> String {
    let mut b = String::new();
    b.push_str(
        "set -eu\nmkdir -p \"$HOME/.codewire\"\ncat > \"$HOME/.codewire/environment.sh\" <<'CWEOF'\n",
    );
    for (key, value) in env_vars {
        b.push_str("export ");
        b.push_str(key);
        b.push('=');
        b.push_str(&shell_quote(value));
        b.push('\n');
    }
    b.push_str("CWEOF\ncat > \"$HOME/.codewire/environment.json\" <<'CWJSON'\n");
    b.push_str(&go_marshal_indent(env_vars));
    b.push_str(
        "\nCWJSON\nchmod 600 \"$HOME/.codewire/environment.sh\" \"$HOME/.codewire/environment.json\"\nfor rc in \"$HOME/.profile\" \"$HOME/.bash_profile\" \"$HOME/.bashrc\" \"$HOME/.zshrc\"; do\n  touch \"$rc\"\n  line='[ -f \"$HOME/.codewire/environment.sh\" ] && . \"$HOME/.codewire/environment.sh\"'\n  if ! grep -Fqx \"$line\" \"$rc\"; then\n    printf '\\n%s\\n' \"$line\" >> \"$rc\"\n  fi\ndone\n",
    );
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
}
