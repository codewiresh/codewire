//! Several codewire.yaml files read as one: a base file and the override
//! files merged onto it in order, such as `codewire.local.yaml` or the
//! variants a create names with repeated `--file`.
//!
//! Each file is checked on its own (its size, YAML, the schema's keys and
//! value types, its version) but need not be complete. Mappings merge by key,
//! recursively; a scalar or a list in a later file replaces the earlier value
//! whole; `key: null` in a later file removes the key. Only the merged
//! document must be a valid project.

use std::path::Path;

use serde_json::{Map, Value};

use crate::{
    MAX_PROJECT_DOCUMENT_BYTES, PROJECT_SCHEMA_VERSION, ProjectDocument, ProjectError, RawProject,
    YamlError, normalize, read_yaml,
};

/// One file of a merged configuration, checked on its own.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectYamlFile(Value);

impl ProjectYamlFile {
    pub fn parse(content: &str) -> Result<Self, ProjectError> {
        if content.len() > MAX_PROJECT_DOCUMENT_BYTES {
            return Err(ProjectError::DocumentTooLarge {
                actual: content.len(),
                maximum: MAX_PROJECT_DOCUMENT_BYTES,
            });
        }
        let value: Value = read_yaml(content).map_err(ProjectError::Yaml)?;
        // Checked without its nulls, which only remove keys, so `FOO: null`
        // under `environment` is not a wrong value type. A real error is
        // reported from the text, with its line and column in this file.
        let mut checked = Value::Object(Map::new());
        merge_value(&mut checked, value.clone());
        let raw: RawProject = serde_path_to_error::deserialize(checked).map_err(|error| {
            ProjectError::Yaml(
                read_yaml::<RawProject>(content)
                    .err()
                    .unwrap_or_else(|| YamlError::from(error)),
            )
        })?;
        if let Some(version) = raw.version
            && version != PROJECT_SCHEMA_VERSION
        {
            return Err(ProjectError::UnsupportedSchema(version));
        }
        Ok(Self(value))
    }

    /// Joins each relative `mounts[].source` to `directory`, the folder of
    /// the file that declares it, so a mount means the same folder whichever
    /// file it came from.
    pub fn resolve_mount_sources(&mut self, directory: &Path) -> Result<(), ProjectError> {
        let Some(Value::Array(mounts)) = self.0.get_mut("mounts") else {
            return Ok(());
        };
        for source in mounts
            .iter_mut()
            .filter_map(|mount| mount.get_mut("source"))
        {
            let Value::String(path) = source else {
                continue;
            };
            if path.is_empty() || Path::new(path.as_str()).is_absolute() {
                continue;
            }
            let joined = directory.join(path.as_str());
            *path = joined
                .to_str()
                .ok_or_else(|| ProjectError::InvalidField {
                    field: "mounts.source",
                    detail: format!("{} is not valid UTF-8", joined.display()),
                })?
                .to_owned();
        }
        Ok(())
    }
}

/// `files` merged in order into one project document.
pub fn merge_project_files(
    files: impl IntoIterator<Item = ProjectYamlFile>,
) -> Result<ProjectDocument, ProjectError> {
    let mut merged = Value::Object(Map::new());
    for ProjectYamlFile(value) in files {
        merge_value(&mut merged, value);
    }
    let size = serde_saphyr::to_string(&merged)
        .map_err(|error| {
            ProjectError::Yaml(YamlError {
                message: error.to_string(),
                position: None,
            })
        })?
        .len();
    if size > MAX_PROJECT_DOCUMENT_BYTES {
        return Err(ProjectError::DocumentTooLarge {
            actual: size,
            maximum: MAX_PROJECT_DOCUMENT_BYTES,
        });
    }
    let raw: RawProject = serde_path_to_error::deserialize(merged)
        .map_err(|error| ProjectError::Yaml(YamlError::from(error)))?;
    normalize::normalize_raw_project(raw)
}

fn merge_value(base: &mut Value, later: Value) {
    match (base, later) {
        (Value::Object(base), Value::Object(later)) => {
            for (key, value) in later {
                if value.is_null() {
                    base.remove(&key);
                } else if let Some(existing) = base.get_mut(&key) {
                    merge_value(existing, value);
                } else {
                    // A new mapping is merged into an empty one, so the nulls
                    // inside it remove keys rather than becoming values.
                    let mut fresh = match value {
                        Value::Object(_) => Value::Object(Map::new()),
                        _ => Value::Null,
                    };
                    merge_value(&mut fresh, value);
                    base.insert(key, fresh);
                }
            }
        }
        // An empty file adds nothing.
        (_, Value::Null) => {}
        (base, later) => *base = later,
    }
}
