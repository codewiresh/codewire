//! Backend-neutral runtime command specifications and identities.

use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LocalRuntimeCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

impl std::fmt::Debug for LocalRuntimeCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRuntimeCommand")
            .field("program", &self.program)
            .field("arg_count", &self.args.len())
            .field("args", &"<redacted>")
            .finish()
    }
}

pub(crate) fn local_runtime_command_spec(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
    command: &[String],
    env_overrides: &BTreeMap<String, String>,
) -> anyhow::Result<LocalRuntimeCommand> {
    local_runtime_command_spec_with_tty(instance, workdir, command, env_overrides, false)
}

pub(crate) fn local_runtime_command_spec_with_tty(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
    command: &[String],
    env_overrides: &BTreeMap<String, String>,
    allocate_tty: bool,
) -> anyhow::Result<LocalRuntimeCommand> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }
    let backend = trimmed_required(&instance.backend, "local backend")?;
    let workdir = local_runtime_workdir(instance, workdir);
    let mut env_args = Vec::new();
    for (key, value) in env_overrides {
        env_args.push("-e".to_string());
        env_args.push(format!("{key}={value}"));
    }

    match backend {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let mut args = vec!["exec".to_string(), "-i".to_string()];
            if allocate_tty {
                args.push("-t".to_string());
            }
            if !workdir.is_empty() {
                args.push("-w".to_string());
                args.push(workdir);
            }
            args.extend(env_args);
            args.push(runtime.to_string());
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let mut docker_args = vec![
                "sudo".to_string(),
                "docker".to_string(),
                "exec".to_string(),
                "-i".to_string(),
            ];
            if allocate_tty {
                docker_args.push("-t".to_string());
            }
            if !workdir.is_empty() {
                docker_args.push("-w".to_string());
                docker_args.push(workdir);
            }
            docker_args.extend(env_args);
            docker_args.push(LIMA_CONTAINER_NAME.to_string());
            docker_args.extend(command.iter().cloned());

            let mut args = vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
            ];
            args.extend(docker_args);
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_runtime_workdir(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
) -> String {
    workdir
        .and_then(trimmed_str)
        .or_else(|| trimmed_str(&instance.workdir))
        .unwrap_or(LOCAL_WORKSPACE_PATH)
        .to_string()
}

pub(crate) fn local_runtime_name(instance: &config::LocalInstanceConfig) -> anyhow::Result<&str> {
    trimmed_str(&instance.runtime_name)
        .or_else(|| trimmed_str(&instance.name))
        .ok_or_else(|| anyhow::anyhow!("local runtime name is empty"))
}

pub(crate) fn local_lima_instance_name(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<&str> {
    trimmed_str(&instance.lima_instance_name)
        .or_else(|| trimmed_str(&instance.runtime_name))
        .or_else(|| trimmed_str(&instance.name))
        .ok_or_else(|| anyhow::anyhow!("Lima instance name is empty"))
}
