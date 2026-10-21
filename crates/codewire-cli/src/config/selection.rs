//! The current environment: what `cw use` selected.
//!
//! It is kept in `current-environment.toml` beside `config.toml`, with the
//! environment's canonical identity, location, display name and, for a
//! cloud environment, its organization:
//!
//! ```toml
//! version = 1
//!
//! [environment]
//! location = "local"
//! id = "8f0c2b3e-…"
//! name = "app"
//! ```
//!
//! `config.toml`'s `[current_target]` is still written, exactly as earlier
//! releases wrote it (a local VM by name), so an older `cw` keeps reading
//! and changing the selection. That entry is written last and is the commit
//! point: the file is authoritative only while `[current_target]` still
//! names the same environment. When it names another one, an older `cw`
//! selected since (or a write stopped between the two files), and
//! `[current_target]` is read as that older selection. A file this release
//! cannot read (a later version, or damaged) falls back the same way.

use super::*;

/// The selection file's name in the Mesh data directory.
pub const SELECTION_FILE: &str = "current-environment.toml";
const SELECTION_VERSION: u32 = 1;

/// Where the selected environment runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionLocation {
    /// A local VM.
    Local,
    /// A cloud environment.
    Cloud,
    /// A trusted host environment (never offered by the picker).
    Host,
}

/// The selected environment.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct EnvironmentSelection {
    pub location: SelectionLocation,
    /// The canonical ID. A selection an older `cw` made of a local VM
    /// carries that VM's name here instead, and matches by name.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct SelectionFile {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment: Option<EnvironmentSelection>,
}

impl EnvironmentSelection {
    /// True when `id` is a canonical ID rather than a name an older `cw`
    /// saved; a local VM is then matched by ID only.
    pub fn has_canonical_id(&self) -> bool {
        uuid::Uuid::parse_str(&self.id).is_ok()
    }

    /// Whether this selects the local VM with this ID and name: by ID, or
    /// by name for a selection an older `cw` saved.
    pub fn is_local_vm(&self, id: &str, name: &str) -> bool {
        self.location == SelectionLocation::Local
            && if self.has_canonical_id() {
                self.id == id
            } else {
                self.id == name
            }
    }

    /// The target the session, port and daemon commands resolve. A local
    /// VM's reference is its ID, which never matches a recreated VM.
    pub fn target(&self) -> CurrentTargetConfig {
        let kind = match self.location {
            SelectionLocation::Local => "local",
            SelectionLocation::Cloud => "env",
            SelectionLocation::Host => "host",
        };
        CurrentTargetConfig {
            kind: kind.to_owned(),
            target_ref: self.id.clone(),
            name: self.name.clone(),
        }
    }

    /// `config.toml`'s `[current_target]` as earlier releases write it.
    fn legacy_target(&self) -> CurrentTargetConfig {
        let mut target = self.target();
        if self.location == SelectionLocation::Local {
            target.target_ref = self.name.clone();
        }
        target
    }

    /// A selection read from `[current_target]` alone.
    fn from_legacy(target: &CurrentTargetConfig) -> Option<Self> {
        let (kind, target_ref) = (target.kind.trim(), target.target_ref.trim());
        let location = match kind {
            // `local` / `local` is the unset default, not a selection.
            "local" if target_ref == "local" => return None,
            "local" => SelectionLocation::Local,
            "env" => SelectionLocation::Cloud,
            "host" => SelectionLocation::Host,
            _ => return None,
        };
        if target_ref.is_empty() {
            return None;
        }
        let name = match target.name.trim() {
            "" => target_ref,
            name => name,
        };
        Some(Self {
            location,
            id: target_ref.to_owned(),
            name: name.to_owned(),
            organization_id: None,
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let id = self.id.trim();
        let name = self.name.trim();
        if id.is_empty()
            || name.is_empty()
            || id != self.id
            || name != self.name
            || (self.location == SelectionLocation::Local && !self.has_canonical_id())
        {
            return Err(ConfigError::InvalidCurrentTarget);
        }
        Ok(())
    }
}

/// The current selection, or `None` when nothing is selected.
pub fn load(data_dir: &Path) -> Result<Option<EnvironmentSelection>, ConfigError> {
    let legacy = load_mesh_config(data_dir)?.current_target;
    let stored = read_file(data_dir)?;
    Ok(resolve(stored.as_deref(), legacy.as_ref()))
}

/// The selection the two files describe; see the module documentation.
fn resolve(
    stored: Option<&str>,
    legacy: Option<&CurrentTargetConfig>,
) -> Option<EnvironmentSelection> {
    let legacy_selection = legacy.and_then(EnvironmentSelection::from_legacy);
    let stored = stored
        .and_then(|data| toml::from_str::<SelectionFile>(data).ok())
        .filter(|file| file.version == SELECTION_VERSION)
        .and_then(|file| file.environment)
        .filter(|selection| selection.validate().is_ok());
    match (stored, legacy) {
        (Some(stored), Some(legacy)) if same_target(&stored.legacy_target(), legacy) => {
            Some(stored)
        }
        _ => legacy_selection,
    }
}

fn same_target(left: &CurrentTargetConfig, right: &CurrentTargetConfig) -> bool {
    left.kind.trim() == right.kind.trim() && left.target_ref.trim() == right.target_ref.trim()
}

/// Selects `selection`: the file first, then `[current_target]`, which
/// makes it current.
pub fn save(data_dir: &Path, selection: &EnvironmentSelection) -> Result<(), ConfigError> {
    selection.validate()?;
    let path = data_dir.join(SELECTION_FILE);
    let data = toml::to_string_pretty(&SelectionFile {
        version: SELECTION_VERSION,
        environment: Some(selection.clone()),
    })
    .map_err(|source| ConfigError::SerializeMesh { path, source })?;
    write_file(data_dir, data.as_bytes())?;
    let legacy = selection.legacy_target();
    update_mesh_config(data_dir, |config| config.current_target = Some(legacy))
}

/// Clears the selection: `[current_target]` first, then the file.
pub fn clear(data_dir: &Path) -> Result<(), ConfigError> {
    if load_mesh_config(data_dir)?.current_target.is_some() {
        update_mesh_config(data_dir, |config| config.current_target = None)?;
    }
    remove_file(data_dir)
}

/// Clears the selection when it is the environment `selected` describes,
/// for example one that was just removed. Returns whether it cleared.
pub fn clear_if(
    data_dir: &Path,
    selected: impl FnOnce(&EnvironmentSelection) -> bool,
) -> Result<bool, ConfigError> {
    match load(data_dir)? {
        Some(selection) if selected(&selection) => clear(data_dir).map(|()| true),
        _ => Ok(false),
    }
}

#[cfg(target_os = "linux")]
fn state_error(path: &Path, write: bool, error: anyhow::Error) -> ConfigError {
    let path = path.to_path_buf();
    let source = std::io::Error::other(error);
    if write {
        ConfigError::WriteConfig { path, source }
    } else {
        ConfigError::ReadConfig { path, source }
    }
}

#[cfg(target_os = "linux")]
fn read_file(data_dir: &Path) -> Result<Option<String>, ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    let Some(directory) = crate::commands::MeshStateDir::open(data_dir, false)
        .map_err(|error| state_error(&path, false, error))?
    else {
        return Ok(None);
    };
    let bytes = directory
        .read(SELECTION_FILE)
        .map_err(|error| state_error(&path, false, error))?;
    // Bytes that are not text are a damaged file, read like a missing one.
    Ok(bytes.and_then(|bytes| String::from_utf8(bytes).ok()))
}

#[cfg(target_os = "linux")]
fn write_file(data_dir: &Path, data: &[u8]) -> Result<(), ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    let directory = crate::commands::MeshStateDir::open(data_dir, true)
        .map_err(|error| state_error(&path, true, error))?
        .ok_or_else(|| ConfigError::WriteConfig {
            path: path.clone(),
            source: std::io::Error::other("local Mesh directory is absent"),
        })?;
    directory
        .write(SELECTION_FILE, data)
        .map_err(|error| state_error(&path, true, error))
}

#[cfg(target_os = "linux")]
fn remove_file(data_dir: &Path) -> Result<(), ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    let Some(directory) = crate::commands::MeshStateDir::open(data_dir, false)
        .map_err(|error| state_error(&path, true, error))?
    else {
        return Ok(());
    };
    directory
        .remove(SELECTION_FILE, None)
        .map_err(|error| state_error(&path, true, error))
}

#[cfg(not(target_os = "linux"))]
fn read_file(data_dir: &Path) -> Result<Option<String>, ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    match fs::read(&path) {
        Ok(bytes) => Ok(String::from_utf8(bytes).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::ReadConfig { path, source }),
    }
}

#[cfg(not(target_os = "linux"))]
fn write_file(data_dir: &Path, data: &[u8]) -> Result<(), ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    fs::create_dir_all(data_dir).map_err(|source| ConfigError::CreateConfigDir {
        path: data_dir.to_path_buf(),
        source,
    })?;
    harden_dir(data_dir)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|source| ConfigError::WriteConfig {
            path: path.clone(),
            source,
        })?;
    harden_file(&path)?;
    file.write_all(data)
        .map_err(|source| ConfigError::WriteConfig { path, source })
}

#[cfg(not(target_os = "linux"))]
fn remove_file(data_dir: &Path) -> Result<(), ConfigError> {
    let path = data_dir.join(SELECTION_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::WriteConfig { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VM_ID: &str = "8f0c2b3e-4d5a-4b6c-9d7e-0f1a2b3c4d5e";
    const CLOUD_ID: &str = "12345678-abcd-4000-9000-000000000001";

    fn data_dir() -> tempfile::TempDir {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap()
        }
        #[cfg(not(unix))]
        tempfile::tempdir().unwrap()
    }

    fn local(id: &str, name: &str) -> EnvironmentSelection {
        EnvironmentSelection {
            location: SelectionLocation::Local,
            id: id.to_owned(),
            name: name.to_owned(),
            organization_id: None,
        }
    }

    fn cloud() -> EnvironmentSelection {
        EnvironmentSelection {
            location: SelectionLocation::Cloud,
            id: CLOUD_ID.to_owned(),
            name: "review".to_owned(),
            organization_id: Some("org-1".to_owned()),
        }
    }

    fn legacy(kind: &str, target_ref: &str, name: &str) -> CurrentTargetConfig {
        CurrentTargetConfig {
            kind: kind.to_owned(),
            target_ref: target_ref.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The `[current_target]` an older `cw` (3321309b7) wrote and reads.
    fn older_cw_target(dir: &Path) -> Option<CurrentTargetConfig> {
        load_mesh_config(dir).unwrap().current_target
    }

    #[test]
    fn nothing_selected_reads_as_none_and_the_unset_default() {
        let dir = data_dir();
        assert_eq!(load(dir.path()).unwrap(), None);
        assert_eq!(
            current_target(dir.path()).unwrap(),
            default_current_target()
        );
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(legacy("local", "local", "local"));
        })
        .unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(legacy(" ", "env_123", "builder"));
        })
        .unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);
    }

    #[test]
    fn save_writes_the_file_and_the_older_cw_entry() {
        let dir = data_dir();
        update_mesh_config(dir.path(), |config| {
            config.mesh_url = Some("https://mesh.codewire.sh".to_owned());
            config.mesh_node_network = Some("project-alpha".to_owned());
        })
        .unwrap();
        save(dir.path(), &local(VM_ID, "app")).unwrap();

        let file = fs::read_to_string(dir.path().join(SELECTION_FILE)).unwrap();
        assert_eq!(
            file,
            format!(
                "version = 1\n\n[environment]\nlocation = \"local\"\nid = \"{VM_ID}\"\nname = \"app\"\n"
            )
        );
        // Exactly what an older cw writes for `cw use app`.
        assert_eq!(
            older_cw_target(dir.path()),
            Some(legacy("local", "app", "app"))
        );
        let config = load_mesh_config(dir.path()).unwrap();
        assert_eq!(config.mesh_url.as_deref(), Some("https://mesh.codewire.sh"));
        assert_eq!(config.mesh_node_network.as_deref(), Some("project-alpha"));
        assert_eq!(load(dir.path()).unwrap(), Some(local(VM_ID, "app")));
        assert_eq!(
            current_target(dir.path()).unwrap(),
            legacy("local", VM_ID, "app")
        );

        save(dir.path(), &cloud()).unwrap();
        assert_eq!(
            older_cw_target(dir.path()),
            Some(legacy("env", CLOUD_ID, "review"))
        );
        assert_eq!(load(dir.path()).unwrap(), Some(cloud()));
        assert!(
            fs::read_to_string(dir.path().join(SELECTION_FILE))
                .unwrap()
                .contains("organization_id = \"org-1\"")
        );
    }

    #[test]
    fn save_refuses_incomplete_or_name_only_identities() {
        let dir = data_dir();
        for selection in [local("", "app"), local(VM_ID, " "), local("app", "app")] {
            assert!(matches!(
                save(dir.path(), &selection),
                Err(ConfigError::InvalidCurrentTarget)
            ));
        }
        assert!(!dir.path().join(SELECTION_FILE).exists());
        assert_eq!(older_cw_target(dir.path()), None);
    }

    #[test]
    fn an_older_cw_change_wins_over_the_file() {
        let dir = data_dir();
        save(dir.path(), &local(VM_ID, "app")).unwrap();
        // An older cw runs `cw use review` (a cloud environment).
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(legacy("env", CLOUD_ID, "review"));
        })
        .unwrap();
        let selected = load(dir.path()).unwrap().unwrap();
        assert_eq!(selected.location, SelectionLocation::Cloud);
        assert_eq!(selected.id, CLOUD_ID);
        assert_eq!(selected.organization_id, None);

        // An older cw selects another local VM by name.
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(legacy("local", "scratch", "scratch"));
        })
        .unwrap();
        let selected = load(dir.path()).unwrap().unwrap();
        assert_eq!(selected, local("scratch", "scratch"));
        assert!(!selected.has_canonical_id());
        assert!(selected.is_local_vm("any-id", "scratch"));
        assert_eq!(
            current_target(dir.path()).unwrap(),
            legacy("local", "scratch", "scratch")
        );

        // An older cw removed the selected VM and reset the target.
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(default_current_target());
        })
        .unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);
    }

    #[test]
    fn the_same_selection_by_an_older_cw_keeps_the_identity() {
        let dir = data_dir();
        save(dir.path(), &local(VM_ID, "app")).unwrap();
        // An older cw runs `cw use app` again: same entry, different name text.
        update_mesh_config(dir.path(), |config| {
            config.current_target = Some(legacy(" local ", "app", ""));
        })
        .unwrap();
        let selected = load(dir.path()).unwrap().unwrap();
        assert_eq!(selected, local(VM_ID, "app"));
        assert!(selected.is_local_vm(VM_ID, "app"));
        assert!(
            !selected.is_local_vm("0b6a1d5e-0000-4000-8000-000000000000", "app"),
            "a recreated VM with the same name is not the selection"
        );
    }

    #[test]
    fn an_interrupted_save_keeps_the_previous_selection() {
        // The file was written but `[current_target]` was not.
        let stored = toml::to_string_pretty(&SelectionFile {
            version: SELECTION_VERSION,
            environment: Some(local(VM_ID, "app")),
        })
        .unwrap();
        let previous = legacy("env", CLOUD_ID, "review");
        let selected = resolve(Some(&stored), Some(&previous)).unwrap();
        assert_eq!(selected.location, SelectionLocation::Cloud);
        assert_eq!(resolve(Some(&stored), None), None);
    }

    #[test]
    fn unreadable_or_later_files_fall_back_to_the_older_cw_entry() {
        let older = legacy("local", "app", "app");
        let later = format!(
            "version = 2\n[environment]\nlocation = \"local\"\nid = \"{VM_ID}\"\nname = \"app\"\n"
        );
        let extra = format!(
            "version = 1\nadded = true\n[environment]\nlocation = \"local\"\nid = \"{VM_ID}\"\nname = \"app\"\nnote = \"x\"\n"
        );
        for (stored, expected) in [
            (later.as_str(), local("app", "app")),
            ("not toml [", local("app", "app")),
            ("version = 1\n", local("app", "app")),
            (
                "version = 1\n[environment]\nlocation = \"vm\"\nid = \"x\"\nname = \"app\"\n",
                local("app", "app"),
            ),
            // Fields a later v1 adds are ignored, not an error.
            (extra.as_str(), local(VM_ID, "app")),
        ] {
            assert_eq!(resolve(Some(stored), Some(&older)), Some(expected));
        }
    }

    #[test]
    fn clear_and_clear_if_remove_both_entries() {
        let dir = data_dir();
        save(dir.path(), &local(VM_ID, "app")).unwrap();
        assert!(
            !clear_if(dir.path(), |selection| selection.location
                == SelectionLocation::Cloud)
            .unwrap()
        );
        assert!(dir.path().join(SELECTION_FILE).exists());
        assert!(clear_if(dir.path(), |selection| selection.is_local_vm(VM_ID, "app")).unwrap());
        assert!(!dir.path().join(SELECTION_FILE).exists());
        assert_eq!(older_cw_target(dir.path()), None);
        assert_eq!(load(dir.path()).unwrap(), None);
        // Clearing nothing is not an error and creates no config.
        let empty = data_dir();
        clear(empty.path()).unwrap();
        assert!(!empty.path().join("config.toml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = data_dir();
        save(dir.path(), &cloud()).unwrap();
        let mode = fs::metadata(dir.path().join(SELECTION_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
