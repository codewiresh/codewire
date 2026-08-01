//! Rust-owned workspace setup script builders, pinned byte-for-byte by the
//! checked-in fixtures under `tests/fixtures/setup_scripts`.

use std::collections::BTreeMap;

/// Well-known SSH host keys for major git providers (ssh_injection.go).
pub const KNOWN_HOSTS: &str = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBM9kHCqFEVAlZECEbqTqEoxUFBzn/JPC2HC7R7bBcpPGKZ5FZSB6wB5LBGKO0xQEh1dsMySnvIPXlfc=
";

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

/// Mirrors `buildSSHSetupScript`.
pub fn build_ssh_setup_script(private_key: &str, public_key: &str) -> String {
    format!(
        "set -eu\numask 077\nmkdir -p \"$HOME/.ssh\"\ncat > \"$HOME/.ssh/id_ed25519\" << 'CWEOF'\n{}\nCWEOF\ncat > \"$HOME/.ssh/id_ed25519.pub\" << 'CWEOF'\n{}\nCWEOF\ncat > \"$HOME/.ssh/known_hosts\" << 'CWEOF'\n{}\nCWEOF\ncat > \"$HOME/.ssh/config\" << 'CWEOF'\nHost *\n    IdentityFile ~/.ssh/id_ed25519\n    StrictHostKeyChecking accept-new\nCWEOF",
        private_key.trim(),
        public_key.trim(),
        KNOWN_HOSTS.trim(),
    )
}

/// Mirrors `buildClaudeBootstrapScript`.
pub fn build_claude_bootstrap_script(work_dir: &str) -> String {
    let work_dir = if work_dir.is_empty() {
        "/workspace"
    } else {
        work_dir
    };
    format!(
        r#"set -eu
mkdir -p "$HOME/.claude"
cfg="$HOME/.claude.json"
_cw_workdir={}
_cw_home="$HOME"
_cw_trust='{{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true}}'
if command -v jq >/dev/null 2>&1 && [ -f "$cfg" ]; then
  jq --arg workdir "$_cw_workdir" --arg home "$_cw_home" --argjson trust "$_cw_trust" \
    '.autoUpdaterStatus = "disabled" |
     .bypassPermissionsModeAccepted = true |
     .hasAcknowledgedCostThreshold = true |
     .hasCompletedOnboarding = true |
     .projects[$workdir] = $trust |
     .projects[$home] = $trust |
     .projects["/workspace"] = $trust' \
    "$cfg" > "${{cfg}}.tmp" && mv "${{cfg}}.tmp" "$cfg"
else
  cat > "$cfg" <<CWEOF
{{
  "autoUpdaterStatus": "disabled",
  "bypassPermissionsModeAccepted": true,
  "hasAcknowledgedCostThreshold": true,
  "hasCompletedOnboarding": true,
  "projects": {{
    "$_cw_workdir": {{
      "hasCompletedProjectOnboarding": true,
      "hasTrustDialogAccepted": true
    }},
    "$_cw_home": {{
      "hasCompletedProjectOnboarding": true,
      "hasTrustDialogAccepted": true
    }},
    "/workspace": {{
      "hasCompletedProjectOnboarding": true,
      "hasTrustDialogAccepted": true
    }}
  }}
}}
CWEOF
  chmod 600 "$cfg"
fi
"#,
        shell_quote(work_dir)
    )
}

/// Mirrors `buildCodexBootstrapScript`. Empty string for unknown modes.
pub fn build_codex_bootstrap_script(mode: &str, value: &str) -> String {
    match mode {
        "apikey" => format!(
            "set -eu\nmkdir -p \"$HOME/.codex\"\necho {} | codex login --with-api-key\n",
            shell_quote(value)
        ),
        "oauth" => format!(
            "set -eu\nmkdir -p \"$HOME/.codex\"\ncat > \"$HOME/.codex/auth.json\" <<'CWEOF'\n{}\nCWEOF\nchmod 600 \"$HOME/.codex/auth.json\"\n",
            value
        ),
        _ => String::new(),
    }
}

/// Mirrors `buildGhCliAuthScript`.
pub fn build_gh_cli_auth_script(token: &str, username: &str) -> String {
    format!(
        "set -eu\nmkdir -p \"$HOME/.config/gh\"\ncat > \"$HOME/.config/gh/hosts.yml\" << 'CWEOF'\ngithub.com:\n    oauth_token: \"{}\"\n    user: \"{}\"\n    git_protocol: ssh\nCWEOF",
        token, username
    )
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

    #[test]
    fn ssh_setup_script_matches_golden() {
        let got = build_ssh_setup_script(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ngolden-private-key-bytes\n-----END OPENSSH PRIVATE KEY-----\n",
            "ssh-ed25519 AAAAGoldenPublicKey user@codewire\n",
        );
        assert_eq!(got, golden("ssh_setup.golden.txt"));
    }

    #[test]
    fn claude_bootstrap_script_matches_golden() {
        assert_eq!(
            build_claude_bootstrap_script("/workspace/my-repo"),
            golden("claude_bootstrap.golden.txt")
        );
    }

    #[test]
    fn codex_bootstrap_scripts_match_golden() {
        assert_eq!(
            build_codex_bootstrap_script("apikey", "sk-golden-key"),
            golden("codex_apikey.golden.txt")
        );
        assert_eq!(
            build_codex_bootstrap_script("oauth", r#"{"tokens":{"access_token":"golden"}}"#),
            golden("codex_oauth.golden.txt")
        );
        assert_eq!(build_codex_bootstrap_script("nope", "x"), "");
    }

    #[test]
    fn gh_cli_auth_script_matches_golden() {
        assert_eq!(
            build_gh_cli_auth_script("gho_goldentoken", "octocat"),
            golden("gh_cli_auth.golden.txt")
        );
    }
}
