//! The refusal a `config.toml` the private state reader won't open becomes:
//! it names the file and, for a mode, the command that fixes it.

use std::path::Path;

use super::ConfigError;
use crate::commands::mesh_commands::retained::PrivateFileRefusal;

pub(super) fn read_error(path: &Path, error: anyhow::Error) -> ConfigError {
    let reason = match error.downcast_ref::<PrivateFileRefusal>() {
        Some(PrivateFileRefusal::Mode(mode)) => format!(
            "it is mode {mode:o}, and only you may read or write it: run `chmod 600 {}`",
            path.display()
        ),
        Some(PrivateFileRefusal::Other) => {
            "it must be a regular file you own, with no other links, of at most 64 KiB".to_owned()
        }
        None => {
            return ConfigError::ReadConfig {
                path: path.to_owned(),
                reason: std::io::Error::other(error),
            };
        }
    };
    ConfigError::ReadConfig {
        path: path.to_owned(),
        reason: std::io::Error::other(reason),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use crate::config::load_mesh_config;

    #[test]
    fn a_config_others_can_read_is_refused_with_the_chmod_that_fixes_it() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = directory.path().join("config.toml");
        fs::write(&config, "local_credential_store = \"file\"\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();

        let refusal = load_mesh_config(directory.path()).unwrap_err().to_string();
        assert!(refusal.contains("mode 644"), "{refusal}");
        assert!(
            refusal.contains(&format!("chmod 600 {}", config.display())),
            "{refusal}"
        );
        assert!(!refusal.contains("Mesh state"), "{refusal}");

        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        load_mesh_config(directory.path()).unwrap();
    }

    #[test]
    fn a_config_that_is_not_a_private_regular_file_says_what_it_must_be() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = directory.path().join("config.toml");
        fs::write(&config, "").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&config, directory.path().join("second-link")).unwrap();

        let refusal = load_mesh_config(directory.path()).unwrap_err().to_string();
        assert!(refusal.contains("no other links"), "{refusal}");
        assert!(!refusal.contains("Mesh state"), "{refusal}");
    }
}
