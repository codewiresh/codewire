use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use crate::config::Config;

pub fn build_process_env(config: &Config, extra: &[String], term: &str) -> Vec<String> {
    let persisted = load_persisted_environment(config);

    let mut override_keys = HashMap::<String, bool>::new();
    let mut session_override = HashMap::<String, bool>::new();
    for entry in &persisted {
        if let Some((key, _)) = entry.split_once('=') {
            override_keys.insert(key.into(), true);
        }
    }
    if !term.is_empty() {
        override_keys.insert("TERM".into(), true);
        session_override.insert("TERM".into(), true);
    }
    for entry in extra {
        if let Some((key, _)) = entry.split_once('=') {
            override_keys.insert(key.into(), true);
            session_override.insert(key.into(), true);
        }
    }

    let mut env = Vec::new();
    for (key, value) in std::env::vars() {
        if override_keys.contains_key(&key) {
            continue;
        }
        if value.is_empty() && matches!(key.as_str(), "HOME" | "USER" | "SHELL") {
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
        env.push(format!("SHELL={}", default_shell()));
    }
    if !term.is_empty() {
        env.push(format!("TERM={term}"));
    }
    for entry in persisted {
        if let Some((key, _)) = entry.split_once('=')
            && session_override.contains_key(key)
        {
            continue;
        }
        env.push(entry);
    }
    env.extend(extra.iter().cloned());
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
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
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
    use crate::config::Config;

    fn test_config(home_root: PathBuf) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".into(),
            workspace_root: PathBuf::from("/workspace"),
            home_root,
            auth_token: None,
        }
    }

    #[test]
    fn build_process_env_session_overrides_inherited_values() {
        unsafe {
            std::env::set_var("HOME", "/container-home");
            std::env::set_var("USER", "container-user");
            std::env::set_var("SHELL", "");
            std::env::set_var("TERM", "linux");
            std::env::set_var("PATH", "/usr/local/bin:/usr/bin");
        }

        let env = build_process_env(
            &test_config(PathBuf::from("/home/codewire")),
            &[
                "HOME=/session-home".into(),
                "USER=session-user".into(),
                "EXTRA=value".into(),
            ],
            "xterm-256color",
        );
        let values = env_map(&env);

        assert_eq!(
            values.get("HOME").map(String::as_str),
            Some("/session-home")
        );
        assert_eq!(values.get("USER").map(String::as_str), Some("session-user"));
        assert_eq!(
            values.get("SHELL").map(String::as_str),
            Some(default_shell().as_str())
        );
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

        unsafe {
            std::env::set_var("HOME", home.display().to_string());
            std::env::set_var("USER", "container-user");
            std::env::set_var("SHELL", "");
            std::env::set_var("PATH", "/usr/local/bin:/usr/bin");
        }

        let env = build_process_env(
            &test_config(home),
            &["BAR=from-session".into(), "BAZ=from-session".into()],
            "xterm-256color",
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

    fn env_map(env: &[String]) -> BTreeMap<String, String> {
        env.iter()
            .filter_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                Some((key.into(), value.into()))
            })
            .collect()
    }
}
