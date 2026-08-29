//! Local-instance persistence lookup and serialized entry models.

use super::*;

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalInstanceEntry {
    pub(crate) name: String,
    pub(crate) backend: String,
    pub(crate) status: String,
    pub(crate) runtime_name: String,
    pub(crate) repo_path: String,
    pub(crate) workdir: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) image: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) preset: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) install: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) startup: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) secrets: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) agent: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<LocalPortEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) mounts: Vec<LocalMountEntry>,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) cpu: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) memory: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) disk: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) last_used_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lima: Option<LocalLimaEntry>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalPortEntry {
    pub(crate) host_port: i32,
    pub(crate) guest_port: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalMountEntry {
    pub(crate) source: String,
    pub(crate) target: String,
    #[serde(skip_serializing_if = "is_false")]
    pub(crate) readonly: bool,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalLimaEntry {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) instance_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mount_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) vm_type: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalFileEntry {
    pub(crate) name: String,
    pub(crate) size: i64,
    pub(crate) is_dir: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mtime: String,
}

pub(crate) fn sorted_local_instance_entries(
    config: &config::LocalInstancesConfig,
) -> Vec<LocalInstanceEntry> {
    let mut entries = config
        .instances
        .iter()
        .map(|(key, instance)| local_instance_entry(key, instance, "unknown"))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

pub(crate) fn resolve_local_instance_entry(
    data_dir: &Path,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<LocalInstanceEntry> {
    let (key, instance) = resolve_local_instance_config(data_dir, name, current_dir)?;
    Ok(local_instance_entry(&key, &instance, "unknown"))
}

pub(crate) fn resolve_local_instance_config(
    data_dir: &Path,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<(String, config::LocalInstanceConfig)> {
    let config = config::load_local_instances_config(data_dir)?;
    resolve_local_instance_config_from_state(&config, name, current_dir)
}

pub(crate) fn resolve_local_instance_config_from_state(
    config: &config::LocalInstancesConfig,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<(String, config::LocalInstanceConfig)> {
    if config.instances.is_empty() {
        anyhow::bail!("no local instances found");
    }

    if let Some(name) = name.and_then(trimmed_str) {
        if let Some(instance) = config.instances.get(name) {
            return Ok((name.to_string(), instance.clone()));
        }
        for (key, instance) in &config.instances {
            if trimmed_str(&instance.runtime_name) == Some(name) {
                return Ok((key.clone(), instance.clone()));
            }
        }
        anyhow::bail!("local instance not found: {name}");
    }

    let current_dir = normalized_path(current_dir);
    let mut matches = config
        .instances
        .iter()
        .filter(|(_, instance)| {
            trimmed_str(&instance.repo_path)
                .map(|repo_path| {
                    path_contains(&normalized_path(Path::new(repo_path)), &current_dir)
                })
                .unwrap_or(false)
        })
        .map(|(key, instance)| (key.as_str(), instance))
        .collect::<Vec<_>>();
    matches.sort_by_key(|(key, _)| *key);

    match matches.as_slice() {
        [(key, instance)] => Ok(((*key).to_string(), (*instance).clone())),
        [] => anyhow::bail!(
            "no local environment associated with this directory; pass a name explicitly or run 'cw env create --local'"
        ),
        _ => {
            let names = matches
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("multiple local instances match this repo: {names}");
        }
    }
}

pub(crate) fn local_instance_entry(
    key: &str,
    instance: &config::LocalInstanceConfig,
    status: &str,
) -> LocalInstanceEntry {
    let ports = instance
        .ports
        .iter()
        .filter_map(local_port_entry)
        .collect::<Vec<_>>();
    let mounts = instance
        .mounts
        .iter()
        .filter_map(local_mount_entry)
        .collect::<Vec<_>>();
    let lima = if instance.backend == "lima" {
        let lima = LocalLimaEntry {
            instance_name: instance.lima_instance_name.clone(),
            mount_type: instance.lima_mount_type.clone(),
            vm_type: instance.lima_vm_type.clone(),
        };
        if lima.instance_name.is_empty() && lima.mount_type.is_empty() && lima.vm_type.is_empty() {
            None
        } else {
            Some(lima)
        }
    } else {
        None
    };

    LocalInstanceEntry {
        name: local_instance_display_name(key, instance).to_string(),
        backend: instance.backend.clone(),
        status: status.to_string(),
        runtime_name: instance.runtime_name.clone(),
        repo_path: instance.repo_path.clone(),
        workdir: instance.workdir.clone(),
        image: instance.image.clone(),
        preset: instance.preset.clone(),
        install: instance.install.clone(),
        startup: instance.startup.clone(),
        secrets: instance.secrets.clone(),
        agent: instance.agent.clone(),
        env: instance.env.clone(),
        ports,
        mounts,
        cpu: instance.cpu,
        memory: instance.memory,
        disk: instance.disk,
        created_at: instance.created_at.clone(),
        last_used_at: instance.last_used_at.clone(),
        lima,
    }
}

pub(crate) fn local_port_entry(port: &config::LocalPortConfig) -> Option<LocalPortEntry> {
    let host_port = port.effective_host_port();
    let guest_port = port.effective_guest_port();
    if host_port <= 0 || guest_port <= 0 {
        return None;
    }
    Some(LocalPortEntry {
        host_port,
        guest_port,
        label: port.label.clone(),
    })
}
