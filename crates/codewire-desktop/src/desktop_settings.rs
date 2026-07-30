//! Desktop-only local settings.
//!
//! Local project history is deliberately independent of the retired native
//! foundation storage abstraction. It contains no Codewire credential or
//! control-plane state; OAuth credentials stay in the system keyring through
//! the shared client.

use std::path::PathBuf;

const LOCAL_PROJECTS_FILE: &str = "desktop-local-projects.json";

fn settings_path() -> Result<PathBuf, String> {
    let root = dirs::config_dir()
        .ok_or_else(|| "could not determine the desktop configuration directory".to_string())?
        .join("codewire");
    Ok(root.join(LOCAL_PROJECTS_FILE))
}

pub fn load_local_projects() -> Result<Vec<String>, String> {
    let path = settings_path()?;
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map_err(|_| "desktop local-project history is invalid".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err("could not read desktop local-project history".to_string()),
    }
}

pub fn save_local_projects(projects: &[String]) -> Result<(), String> {
    let path = settings_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "desktop configuration path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "could not create desktop configuration directory".to_string())?;
    let serialized = serde_json::to_vec(projects)
        .map_err(|_| "could not serialize desktop local-project history".to_string())?;
    std::fs::write(path, serialized)
        .map_err(|_| "could not save desktop local-project history".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_projects_filename_is_not_legacy_core_storage() {
        assert_eq!(super::LOCAL_PROJECTS_FILE, "desktop-local-projects.json");
    }
}
