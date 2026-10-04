use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::PathBuf;

use codewire_access::ManagedCredentialClientPlacement;

use crate::config::{
    Config, CredentialBridgeTransport, DAEMON_AUTH_TOKEN_ENV, MANAGED_CREDENTIAL_CLIENTS_ENV,
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Only explicit per-command/terminal inputs outrank an application projection.
/// Keep their names separate from the flattened image/project environment.
#[derive(Debug)]
pub struct ProcessEnvironment {
    pub entries: Vec<String>,
    pub override_names: BTreeSet<String>,
}

pub fn build_process_env(
    config: &Config,
    extra: &[String],
    term: &str,
) -> io::Result<ProcessEnvironment> {
    let persisted = load_persisted_environment(config);
    let inherited = config.process_execution.base_environment(std::env::vars());
    let fallback_shell = default_shell_for(config);
    build_managed_process_env_from(config, persisted, extra, term, inherited, &fallback_shell)
}

fn build_managed_process_env_from(
    config: &Config,
    persisted: Vec<String>,
    extra: &[String],
    term: &str,
    inherited: impl IntoIterator<Item = (String, String)>,
    fallback_shell: &str,
) -> io::Result<ProcessEnvironment> {
    if protects_native_codex_home(config)
        && environment_names(&persisted)
            .chain(environment_names(extra))
            .any(|name| name == "CODEX_HOME")
    {
        return Err(managed_environment_collision());
    }
    config
        .managed_credential_clients
        .check_collisions(environment_names(&persisted))
        .map_err(|_| managed_environment_collision())?;
    config
        .managed_credential_clients
        .check_collisions(environment_names(extra))
        .map_err(|_| managed_environment_collision())?;
    if config.managed_credential_clients != Default::default()
        && (config.credential_bridge.is_none() || config.launch_projection.is_none())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed credential client selection has no launch authority",
        ));
    }
    let placement = match config
        .credential_bridge
        .as_ref()
        .map(|identity| identity.transport)
    {
        Some(CredentialBridgeTransport::Hosted) => ManagedCredentialClientPlacement::Platform,
        Some(CredentialBridgeTransport::Local) | None => ManagedCredentialClientPlacement::Native,
    };
    let managed = config.managed_credential_clients.for_placement(placement);
    let managed_names = managed.environment.keys().cloned().collect::<BTreeSet<_>>();
    let mut inherited = inherited.into_iter().collect::<Vec<_>>();
    inherited.retain(|(name, _)| !managed_names.contains(name));
    inherited.extend(managed.environment);
    Ok(ProcessEnvironment {
        entries: build_process_env_from(config, persisted, extra, term, inherited, fallback_shell),
        override_names: command_override_names(extra, term),
    })
}

fn environment_names(entries: &[String]) -> impl Iterator<Item = &str> {
    entries
        .iter()
        .filter_map(|entry| entry.split_once('=').map(|(name, _)| name))
}

fn managed_environment_collision() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "environment conflicts with managed credential client routing",
    )
}

fn protects_native_codex_home(config: &Config) -> bool {
    matches!(
        &config.process_execution,
        crate::execution::ProcessExecution::Runc(_)
    )
}

fn command_override_names(extra: &[String], term: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<_> = extra
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .filter(|(name, _)| !is_internal_environment_name(name))
        .map(|(name, _)| name.to_owned())
        .collect();
    if !term.is_empty() {
        names.insert("TERM".into());
    }
    names
}

fn build_process_env_from(
    config: &Config,
    persisted: Vec<String>,
    extra: &[String],
    term: &str,
    inherited: impl IntoIterator<Item = (String, String)>,
    fallback_shell: &str,
) -> Vec<String> {
    let mut override_keys = HashMap::<String, bool>::new();
    let mut session_override = HashMap::<String, bool>::new();
    for entry in &persisted {
        if let Some((key, _)) = entry.split_once('=') {
            if is_internal_environment_name(key) {
                continue;
            }
            override_keys.insert(key.into(), true);
        }
    }
    if !term.is_empty() {
        override_keys.insert("TERM".into(), true);
        session_override.insert("TERM".into(), true);
    }
    for entry in extra {
        if let Some((key, _)) = entry.split_once('=') {
            if is_internal_environment_name(key) {
                continue;
            }
            override_keys.insert(key.into(), true);
            session_override.insert(key.into(), true);
        }
    }

    let mut env = Vec::new();
    for (key, value) in inherited {
        if is_internal_environment_name(&key) {
            continue;
        }
        if override_keys.contains_key(&key) {
            continue;
        }
        if value.is_empty() && matches!(key.as_str(), "HOME" | "USER" | "SHELL" | "PATH") {
            continue;
        }
        env.push(format!("{key}={value}"));
    }

    if !has_non_empty_env_value(&env, "HOME") && !override_keys.contains_key("HOME") {
        env.push(format!("HOME={}", config.home_root.display()));
    }
    if !has_non_empty_env_value(&env, "USER") && !override_keys.contains_key("USER") {
        env.push("USER=codewire".into());
    }
    if !has_non_empty_env_value(&env, "SHELL") && !override_keys.contains_key("SHELL") {
        env.push(format!("SHELL={fallback_shell}"));
    }
    if !has_non_empty_env_value(&env, "PATH") && !override_keys.contains_key("PATH") {
        env.push(format!("PATH={DEFAULT_PATH}"));
    }
    if !term.is_empty() {
        env.push(format!("TERM={term}"));
    }
    for entry in persisted {
        if let Some((key, _)) = entry.split_once('=')
            && (is_internal_environment_name(key) || session_override.contains_key(key))
        {
            continue;
        }
        env.push(entry);
    }
    env.extend(
        extra
            .iter()
            .filter(|entry| {
                entry
                    .split_once('=')
                    .is_none_or(|(key, _)| !is_internal_environment_name(key))
            })
            .cloned(),
    );
    env
}

pub fn load_persisted_environment(config: &Config) -> Vec<String> {
    let path: PathBuf = config.home_root.join(".codewire/environment.json");
    let Ok(data) = fs::read(&path) else {
        return Vec::new();
    };
    if data.is_empty() {
        return Vec::new();
    }

    let Ok(values) = serde_json::from_slice::<BTreeMap<String, String>>(&data) else {
        tracing::warn!(path = %path.display(), "workspace daemon: ignoring invalid persisted environment");
        return Vec::new();
    };

    values
        .into_iter()
        .filter(|(key, _)| !is_internal_environment_name(key))
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

pub(crate) fn is_internal_environment_name(name: &str) -> bool {
    matches!(name, DAEMON_AUTH_TOKEN_ENV | MANAGED_CREDENTIAL_CLIENTS_ENV)
}

pub fn default_shell() -> String {
    if let Ok(shell) = std::env::var("SHELL")
        && !shell.is_empty()
    {
        return shell;
    }
    if is_executable("/bin/bash") {
        return "/bin/bash".into();
    }
    "/bin/sh".into()
}

pub fn default_shell_for(config: &Config) -> String {
    config.process_execution.default_shell(default_shell)
}

fn is_executable(path: &str) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }
}

fn has_non_empty_env_value(env: &[String], key: &str) -> bool {
    let prefix = format!("{key}=");
    env.iter()
        .any(|entry| entry.starts_with(&prefix) && entry.len() > prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialBridgeConfig, LaunchProjectionConfig};

    fn test_config(home_root: PathBuf) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".into(),
            workspace_root: PathBuf::from("/workspace"),
            home_root,
            auth_token: crate::DaemonAuthToken::new("daemon-env-test-token").unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
        }
    }

    fn selected_config(
        home_root: PathBuf,
        slots: &[&str],
        transport: CredentialBridgeTransport,
    ) -> Config {
        let mut config = test_config(home_root);
        config.managed_credential_clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
                .unwrap();
        config.credential_bridge = Some(CredentialBridgeConfig {
            transport,
            environment_id: uuid::Uuid::from_u128(29),
            environment_generation: 7,
            ingress_socket: "/run/codewire/credentials.sock".into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        });
        config.launch_projection = Some(LaunchProjectionConfig {
            selection_sha256: [7; 32],
            native: None,
        });
        config
    }

    #[test]
    fn selected_managed_routing_replaces_only_selected_inherited_provider_values() {
        for (transport, expected_codex_home) in [
            (
                CredentialBridgeTransport::Local,
                codewire_access::CODEX_NATIVE_HOME,
            ),
            (
                CredentialBridgeTransport::Hosted,
                codewire_access::CODEX_PLATFORM_HOME,
            ),
        ] {
            let config = selected_config(
                PathBuf::from("/home/codewire"),
                &["codex", "openai", "anthropic", "ssh"],
                transport,
            );
            let environment = build_managed_process_env_from(
                &config,
                vec!["APPLICATION=declared".into()],
                &["REQUEST=explicit".into()],
                "",
                [
                    ("CODEX_HOME".into(), "/image/codex".into()),
                    ("OPENAI_API_KEY".into(), "image-openai".into()),
                    ("OPENAI_BASE_URL".into(), "https://image.openai".into()),
                    ("ANTHROPIC_API_KEY".into(), "image-anthropic".into()),
                    ("ANTHROPIC_AUTH_TOKEN".into(), "image-token".into()),
                    (
                        "ANTHROPIC_BASE_URL".into(),
                        "https://image.anthropic".into(),
                    ),
                    ("CLAUDE_CODE_OAUTH_TOKEN".into(), "image-oauth".into()),
                    ("GITHUB_TOKEN".into(), "unselected-image-value".into()),
                    ("SSH_AUTH_SOCK".into(), "/image/ssh-agent.sock".into()),
                    (MANAGED_CREDENTIAL_CLIENTS_ENV.into(), "v1:codex".into()),
                ],
                "/bin/sh",
            )
            .unwrap();
            let values = env_map(&environment.entries);
            assert_eq!(values["CODEX_HOME"], expected_codex_home);
            assert_eq!(values["OPENAI_API_KEY"], "codewire-managed");
            assert_eq!(
                values["OPENAI_BASE_URL"],
                "http://127.0.0.1:38081/_codewire/openai/v1"
            );
            assert_eq!(values["ANTHROPIC_API_KEY"], "");
            assert_eq!(values["ANTHROPIC_AUTH_TOKEN"], "codewire-managed");
            assert_eq!(values["ANTHROPIC_BASE_URL"], "http://127.0.0.1:38081");
            assert_eq!(values["CLAUDE_CODE_OAUTH_TOKEN"], "");
            assert_eq!(values["GITHUB_TOKEN"], "unselected-image-value");
            assert_eq!(
                values["SSH_AUTH_SOCK"],
                match transport {
                    CredentialBridgeTransport::Local => codewire_access::SSH_NATIVE_AUTH_SOCK,
                    CredentialBridgeTransport::Hosted => codewire_access::SSH_PLATFORM_AUTH_SOCK,
                }
            );
            assert_eq!(values["APPLICATION"], "declared");
            assert_eq!(values["REQUEST"], "explicit");
            assert!(!values.contains_key(MANAGED_CREDENTIAL_CLIENTS_ENV));
        }
    }

    #[test]
    fn a_selected_claude_subscription_token_projects_the_claude_code_oauth_placeholder() {
        for transport in [
            CredentialBridgeTransport::Local,
            CredentialBridgeTransport::Hosted,
        ] {
            let mut config =
                selected_config(PathBuf::from("/home/codewire"), &["anthropic"], transport);
            config.managed_credential_clients = config
                .managed_credential_clients
                .with_anthropic_subscription_token()
                .unwrap();
            let environment = build_managed_process_env_from(
                &config,
                Vec::new(),
                &[],
                "",
                [
                    ("ANTHROPIC_API_KEY".into(), "image-anthropic".into()),
                    ("ANTHROPIC_AUTH_TOKEN".into(), "image-token".into()),
                    (
                        "ANTHROPIC_BASE_URL".into(),
                        "https://image.anthropic".into(),
                    ),
                    ("CLAUDE_CODE_OAUTH_TOKEN".into(), "image-oauth".into()),
                    (MANAGED_CREDENTIAL_CLIENTS_ENV.into(), "v2:24".into()),
                ],
                "/bin/sh",
            )
            .unwrap();
            let values = env_map(&environment.entries);
            // Claude Code's subscription mode reaches the managed route with
            // only the placeholder; the empty higher-precedence names unset.
            assert_eq!(values["CLAUDE_CODE_OAUTH_TOKEN"], "codewire-managed");
            assert_eq!(values["ANTHROPIC_AUTH_TOKEN"], "");
            assert_eq!(values["ANTHROPIC_API_KEY"], "");
            assert_eq!(values["ANTHROPIC_BASE_URL"], "http://127.0.0.1:38081");
            assert!(!values.contains_key(MANAGED_CREDENTIAL_CLIENTS_ENV));
            assert!(!values.values().any(|value| value.starts_with("image-")));
        }
    }

    #[test]
    fn managed_routing_rejects_declared_and_explicit_collisions_before_merge() {
        let config = selected_config(
            PathBuf::from("/home/codewire"),
            &["codex", "openai"],
            CredentialBridgeTransport::Local,
        );
        for (persisted, extra) in [
            (vec!["CODEX_HOME=".into()], Vec::new()),
            (Vec::new(), vec!["OPENAI_API_KEY=".into()]),
            (
                vec!["APPLICATION=ordinary".into()],
                vec!["OPENAI_BASE_URL=https://explicit.invalid".into()],
            ),
        ] {
            let error = build_managed_process_env_from(
                &config,
                persisted,
                &extra,
                "",
                [("PATH".into(), "/usr/bin:/bin".into())],
                "/bin/sh",
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        let allowed = build_managed_process_env_from(
            &config,
            vec!["ANTHROPIC_API_KEY=unselected-declared".into()],
            &["ANTHROPIC_BASE_URL=https://unselected.invalid".into()],
            "",
            [("PATH".into(), "/usr/bin:/bin".into())],
            "/bin/sh",
        )
        .unwrap();
        let allowed = env_map(&allowed.entries);
        assert_eq!(allowed["ANTHROPIC_API_KEY"], "unselected-declared");
        assert_eq!(allowed["ANTHROPIC_BASE_URL"], "https://unselected.invalid");

        let ssh = selected_config(
            PathBuf::from("/home/codewire"),
            &["ssh"],
            CredentialBridgeTransport::Local,
        );
        for (persisted, extra) in [
            (vec!["SSH_AUTH_SOCK=/declared.sock".into()], Vec::new()),
            (Vec::new(), vec!["SSH_AUTH_SOCK=/explicit.sock".into()]),
        ] {
            assert_eq!(
                build_managed_process_env_from(&ssh, persisted, &extra, "", Vec::new(), "/bin/sh")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        fs::create_dir_all(home.join(".codewire")).unwrap();
        fs::write(
            home.join(".codewire/environment.json"),
            br#"{"CODEX_HOME":"persisted-user-value"}"#,
        )
        .unwrap();
        let config = selected_config(home, &["codex"], CredentialBridgeTransport::Local);
        assert_eq!(
            build_process_env(&config, &[], "").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        fs::write(config.home_root.join(".codewire/environment.json"), b"{}").unwrap();
        assert_eq!(
            build_process_env(&config, &["CODEX_HOME=".into()], "")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn no_managed_selection_preserves_provider_environment_and_needs_no_authority() {
        let config = test_config(PathBuf::from("/home/codewire"));
        let environment = build_managed_process_env_from(
            &config,
            Vec::new(),
            &[],
            "",
            [
                ("CODEX_HOME".into(), "/image/codex".into()),
                ("OPENAI_API_KEY".into(), "image-openai".into()),
                ("ANTHROPIC_AUTH_TOKEN".into(), "image-anthropic".into()),
                ("SSH_AUTH_SOCK".into(), "/image/ssh-agent.sock".into()),
            ],
            "/bin/sh",
        )
        .unwrap();
        let values = env_map(&environment.entries);
        assert_eq!(values["CODEX_HOME"], "/image/codex");
        assert_eq!(values["OPENAI_API_KEY"], "image-openai");
        assert_eq!(values["ANTHROPIC_AUTH_TOKEN"], "image-anthropic");
        assert_eq!(values["SSH_AUTH_SOCK"], "/image/ssh-agent.sock");

        let mut invalid = config;
        invalid.managed_credential_clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
        let error =
            build_managed_process_env_from(&invalid, Vec::new(), &[], "", Vec::new(), "/bin/sh")
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn native_runc_protects_fixed_codex_home_without_a_profile_selection() {
        let mut native = test_config(PathBuf::from("/home/codewire"));
        native.process_execution =
            crate::execution::ProcessExecution::Runc(crate::execution::RuncExecution {
                helper_path: "/init".into(),
                process_directory: "/run/codewire/processes".into(),
                container_id: "workspace".into(),
                process_wrapper: vec!["/init".into(), "workspace-exec".into()],
                default_shell: "/bin/sh".into(),
                base_environment: vec![format!(
                    "CODEX_HOME={}",
                    codewire_access::CODEX_NATIVE_HOME
                )],
                uid: 1000,
                gid: 1000,
                additional_gids: Vec::new(),
            });
        native.credential_bridge = Some(CredentialBridgeConfig {
            transport: CredentialBridgeTransport::Local,
            environment_id: uuid::Uuid::from_u128(30),
            environment_generation: 8,
            ingress_socket: "/run/codewire/credentials.sock".into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        });

        let inherited = build_managed_process_env_from(
            &native,
            Vec::new(),
            &[],
            "",
            [(
                "CODEX_HOME".into(),
                codewire_access::CODEX_NATIVE_HOME.into(),
            )],
            "/bin/sh",
        )
        .unwrap();
        assert_eq!(
            env_map(&inherited.entries)["CODEX_HOME"],
            codewire_access::CODEX_NATIVE_HOME
        );
        for (persisted, explicit) in [
            (vec!["CODEX_HOME=/declared".into()], Vec::new()),
            (Vec::new(), vec!["CODEX_HOME=".into()]),
        ] {
            assert_eq!(
                build_managed_process_env_from(
                    &native,
                    persisted,
                    &explicit,
                    "",
                    [(
                        "CODEX_HOME".into(),
                        codewire_access::CODEX_NATIVE_HOME.into()
                    )],
                    "/bin/sh",
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        let mut platform = native;
        platform.process_execution = crate::execution::ProcessExecution::Native;
        platform.credential_bridge.as_mut().unwrap().transport = CredentialBridgeTransport::Hosted;
        let declared = build_managed_process_env_from(
            &platform,
            vec!["CODEX_HOME=/ordinary-platform-value".into()],
            &[],
            "",
            Vec::new(),
            "/bin/sh",
        )
        .unwrap();
        assert_eq!(
            env_map(&declared.entries)["CODEX_HOME"],
            "/ordinary-platform-value"
        );
    }

    #[test]
    fn command_provenance_excludes_image_and_project_defaults_but_preserves_empty_and_term() {
        // Persisted session.env remains the explicit inputs, not resolved app
        // values; rebuilding this pair on relaunch retains the same precedence.
        let extra = vec![
            "DATABASE_URL=first-explicit".into(),
            "DATABASE_URL=".into(),
            "TERM=explicit-terminal".into(),
            format!("{DAEMON_AUTH_TOKEN_ENV}=never-inherit"),
        ];
        for _launch in 0..2 {
            let entries = build_process_env_from(
                &test_config(PathBuf::from("/home/codewire")),
                vec![
                    "PROJECT_ONLY=declared".into(),
                    "DATABASE_URL=declared".into(),
                ],
                &extra,
                "requested-terminal",
                [
                    ("IMAGE_ONLY".into(), "default".into()),
                    ("DATABASE_URL".into(), "image".into()),
                ],
                "/bin/sh",
            );
            let names = command_override_names(&extra, "requested-terminal");
            assert_eq!(
                names,
                BTreeSet::from(["DATABASE_URL".into(), "TERM".into()])
            );
            let values = env_map(&entries);
            assert_eq!(values["DATABASE_URL"], "");
            assert_eq!(values["TERM"], "explicit-terminal");
            assert_eq!(values["PROJECT_ONLY"], "declared");
            assert_eq!(values["IMAGE_ONLY"], "default");
            assert!(!values.contains_key(DAEMON_AUTH_TOKEN_ENV));
        }
        assert_eq!(
            command_override_names(&[], "xterm"),
            BTreeSet::from(["TERM".into()])
        );
        assert!(command_override_names(&[], "").is_empty());
    }

    #[test]
    fn build_process_env_session_overrides_inherited_values() {
        let env = build_process_env_from(
            &test_config(PathBuf::from("/home/codewire")),
            Vec::new(),
            &[
                "HOME=/session-home".into(),
                "USER=session-user".into(),
                "EXTRA=value".into(),
            ],
            "xterm-256color",
            [
                ("HOME".into(), "/container-home".into()),
                ("USER".into(), "container-user".into()),
                ("SHELL".into(), String::new()),
                ("TERM".into(), "linux".into()),
                ("PATH".into(), "/usr/local/bin:/usr/bin".into()),
            ],
            "/bin/sh",
        );
        let values = env_map(&env);

        assert_eq!(
            values.get("HOME").map(String::as_str),
            Some("/session-home")
        );
        assert_eq!(values.get("USER").map(String::as_str), Some("session-user"));
        assert_eq!(values.get("SHELL").map(String::as_str), Some("/bin/sh"));
        assert_eq!(
            values.get("TERM").map(String::as_str),
            Some("xterm-256color")
        );
        assert_eq!(
            values.get("PATH").map(String::as_str),
            Some("/usr/local/bin:/usr/bin")
        );
        assert_eq!(values.get("EXTRA").map(String::as_str), Some("value"));
    }

    #[test]
    fn build_process_env_includes_persisted_workspace_environment() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().to_path_buf();
        fs::create_dir_all(home.join(".codewire")).expect("env dir");
        fs::write(
            home.join(".codewire/environment.json"),
            br#"{"FOO":"from-file","BAR":"from-file","USER":"persisted-user"}"#,
        )
        .expect("environment file");

        let config = test_config(home);
        let persisted = load_persisted_environment(&config);
        let env = build_process_env_from(
            &config,
            persisted,
            &["BAR=from-session".into(), "BAZ=from-session".into()],
            "xterm-256color",
            [
                ("HOME".into(), "/container-home".into()),
                ("USER".into(), "container-user".into()),
                ("SHELL".into(), String::new()),
                ("PATH".into(), "/usr/local/bin:/usr/bin".into()),
            ],
            "/bin/sh",
        );
        let values = env_map(&env);

        assert_eq!(values.get("FOO").map(String::as_str), Some("from-file"));
        assert_eq!(values.get("BAR").map(String::as_str), Some("from-session"));
        assert_eq!(values.get("BAZ").map(String::as_str), Some("from-session"));
        assert_eq!(
            values.get("USER").map(String::as_str),
            Some("persisted-user")
        );
    }

    #[test]
    fn build_process_env_never_projects_daemon_auth_token() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().to_path_buf();
        fs::create_dir_all(home.join(".codewire")).expect("env dir");
        fs::write(
            home.join(".codewire/environment.json"),
            br#"{"CODEWIRE_DAEMON_AUTH_TOKEN":"persisted-marker","CODEWIRE_MANAGED_CREDENTIAL_CLIENTS":"persisted-managed-marker","PERSISTED":"visible"}"#,
        )
        .expect("environment file");

        let config = test_config(home);
        let persisted = load_persisted_environment(&config);
        let env = build_process_env_from(
            &config,
            persisted,
            &[
                "CODEWIRE_DAEMON_AUTH_TOKEN=request-marker".into(),
                "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS=request-managed-marker".into(),
                "REQUEST=visible".into(),
            ],
            "xterm-256color",
            [
                (DAEMON_AUTH_TOKEN_ENV.into(), "inherited-marker".into()),
                (
                    MANAGED_CREDENTIAL_CLIENTS_ENV.into(),
                    "inherited-managed-marker".into(),
                ),
                ("INHERITED".into(), "visible".into()),
            ],
            "/bin/sh",
        );
        let values = env_map(&env);

        assert!(!values.contains_key(DAEMON_AUTH_TOKEN_ENV));
        assert!(!values.contains_key(MANAGED_CREDENTIAL_CLIENTS_ENV));
        assert_eq!(values.get("PERSISTED").map(String::as_str), Some("visible"));
        assert_eq!(values.get("REQUEST").map(String::as_str), Some("visible"));
        assert_eq!(values.get("INHERITED").map(String::as_str), Some("visible"));
        let rendered = format!("{env:?}");
        for marker in [
            "persisted-marker",
            "persisted-managed-marker",
            "request-marker",
            "request-managed-marker",
            "inherited-marker",
            "inherited-managed-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }

    #[test]
    fn build_process_env_supplies_path_for_environment_free_guest_daemon() {
        let env = build_process_env_from(
            &test_config(PathBuf::from("/home/codewire")),
            Vec::new(),
            &[],
            "xterm-256color",
            [
                ("HOME".into(), String::new()),
                ("USER".into(), String::new()),
                ("SHELL".into(), String::new()),
                ("PATH".into(), String::new()),
            ],
            "/bin/sh",
        );
        let values = env_map(&env);
        assert_eq!(values.get("PATH").map(String::as_str), Some(DEFAULT_PATH));
        assert_eq!(
            values.get("HOME").map(String::as_str),
            Some("/home/codewire")
        );
    }

    fn env_map(env: &[String]) -> BTreeMap<String, String> {
        env.iter()
            .filter_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                Some((key.into(), value.into()))
            })
            .collect()
    }
}
