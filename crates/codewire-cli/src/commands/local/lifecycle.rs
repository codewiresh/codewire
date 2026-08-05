//! Local Docker and Lima lifecycle, daemon repair, and resize behavior.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalLifecycleAction {
    Start,
    Stop,
    Remove,
}

impl LocalLifecycleAction {
    pub(crate) fn docker_subcommand(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "rm",
        }
    }

    pub(crate) fn lima_subcommand(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "delete",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "remove",
        }
    }
}

pub(crate) fn local_lifecycle_command_spec(
    instance: &config::LocalInstanceConfig,
    action: LocalLifecycleAction,
) -> anyhow::Result<LocalRuntimeCommand> {
    let backend = trimmed_required(&instance.backend, "local backend")?;
    match backend {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let args = match action {
                LocalLifecycleAction::Start | LocalLifecycleAction::Stop => {
                    vec![action.docker_subcommand().to_string(), runtime.to_string()]
                }
                LocalLifecycleAction::Remove => vec![
                    action.docker_subcommand().to_string(),
                    "-f".to_string(),
                    runtime.to_string(),
                ],
            };
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let args = match action {
                LocalLifecycleAction::Start | LocalLifecycleAction::Stop => {
                    vec![action.lima_subcommand().to_string(), lima_name.to_string()]
                }
                LocalLifecycleAction::Remove => vec![
                    action.lima_subcommand().to_string(),
                    "--force".to_string(),
                    lima_name.to_string(),
                ],
            };
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn run_local_lifecycle_command(
    instance: &config::LocalInstanceConfig,
    action: LocalLifecycleAction,
) -> anyhow::Result<()> {
    let backend = trimmed_required(&instance.backend, "local backend")?;
    let spec = local_lifecycle_command_spec(instance, action)?;
    let status = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .status()
        .with_context(|| format!("{} local runtime command", action.label()))?;
    if !status.success() {
        anyhow::bail!(
            "local runtime {} failed with exit code {}",
            action.label(),
            status.code().unwrap_or(1)
        );
    }
    if backend == "lima" && action == LocalLifecycleAction::Start {
        run_local_command_combined(&local_lima_docker_service_start_command_spec(instance)?)
            .context("start Docker inside Lima environment")?;
        run_local_command_combined(&local_lima_workspace_start_command_spec(instance)?)
            .context("start managed workspace inside Lima environment")?;
    }
    Ok(())
}

pub(crate) fn local_lima_docker_service_start_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            local_lima_instance_name(instance)?.to_string(),
            "sudo".to_string(),
            "systemctl".to_string(),
            "start".to_string(),
            "docker".to_string(),
        ],
    })
}

pub(crate) fn local_lima_workspace_start_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            local_lima_instance_name(instance)?.to_string(),
            "sudo".to_string(),
            "docker".to_string(),
            "start".to_string(),
            LIMA_CONTAINER_NAME.to_string(),
        ],
    })
}

pub(crate) fn local_daemon_logs_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => Ok(LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "logs".to_string(),
                "--tail".to_string(),
                "200".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        }),
        "lima" => Ok(LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                local_lima_instance_name(instance)?.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "logs".to_string(),
                "--tail".to_string(),
                "200".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ],
        }),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_daemon_repair_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => Ok(LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "restart".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        }),
        "lima" => Ok(LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                local_lima_instance_name(instance)?.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "restart".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ],
        }),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn read_local_daemon_logs(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    run_local_command_combined(&local_daemon_logs_command_spec(instance)?)
        .context("read local environment daemon logs")
}

pub(crate) fn repair_local_daemon(instance: &config::LocalInstanceConfig) -> anyhow::Result<()> {
    run_local_command_combined(&local_daemon_repair_command_spec(instance)?)
        .context("restart local environment daemon")?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalLimaWorkspaceRecovery {
    AlreadyRunning,
    StartVmAndWorkspace,
    StartWorkspace,
}

pub(crate) fn classify_local_lima_workspace_recovery(
    vm_status: &str,
    workspace_status: Option<&str>,
) -> anyhow::Result<LocalLimaWorkspaceRecovery> {
    match vm_status.trim().to_ascii_lowercase().as_str() {
        "missing" => anyhow::bail!(
            "saved local Lima environment is missing; recreate it instead of starting a new runtime implicitly"
        ),
        "running" => match workspace_status
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("running") => Ok(LocalLimaWorkspaceRecovery::AlreadyRunning),
            Some("missing") => anyhow::bail!(
                "saved local Lima environment has no managed cw-workspace container; recreate it instead of creating one implicitly"
            ),
            Some(_) => Ok(LocalLimaWorkspaceRecovery::StartWorkspace),
            None => anyhow::bail!(
                "Lima VM is running but its managed workspace container status was unavailable"
            ),
        },
        _ => Ok(LocalLimaWorkspaceRecovery::StartVmAndWorkspace),
    }
}

pub(crate) fn local_lima_workspace_recovery_command_specs(
    instance: &config::LocalInstanceConfig,
    recovery: LocalLimaWorkspaceRecovery,
) -> anyhow::Result<Vec<LocalRuntimeCommand>> {
    match recovery {
        LocalLimaWorkspaceRecovery::AlreadyRunning => Ok(Vec::new()),
        LocalLimaWorkspaceRecovery::StartVmAndWorkspace => Ok(vec![
            local_lima_vm_start_command_spec(instance)?,
            local_lima_docker_service_start_command_spec(instance)?,
            local_lima_workspace_start_command_spec(instance)?,
        ]),
        LocalLimaWorkspaceRecovery::StartWorkspace => {
            Ok(vec![local_lima_workspace_start_command_spec(instance)?])
        }
    }
}

pub(crate) fn local_lima_vm_start_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "start".to_string(),
            "--tty=false".to_string(),
            local_lima_instance_name(instance)?.to_string(),
        ],
    })
}

pub(crate) fn ensure_local_environment_runtime_ready(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<()> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => {
            match docker_workspace_container_status(local_runtime_name(instance)?)?.as_str() {
                "running" => Ok(()),
                "missing" => anyhow::bail!(
                    "saved local Docker environment is missing; recreate it instead of starting a new runtime implicitly"
                ),
                _ => {
                    run_local_command_combined(&local_lifecycle_command_spec(
                        instance,
                        LocalLifecycleAction::Start,
                    )?)
                    .context("start saved local Docker environment before session launch")?;
                    Ok(())
                }
            }
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let vm_status = local_lima_instance_status(lima_name)?;
            let workspace_status = vm_status
                .eq_ignore_ascii_case("running")
                .then(|| lima_workspace_container_status(lima_name))
                .transpose()?;
            let recovery =
                classify_local_lima_workspace_recovery(&vm_status, workspace_status.as_deref())?;
            for command in local_lima_workspace_recovery_command_specs(instance, recovery)? {
                run_local_command_combined(&command)
                    .context("recover saved Lima environment before session launch")?;
            }
            Ok(())
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_environment_lifecycle_status(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => docker_workspace_container_status(local_runtime_name(instance)?),
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let vm_status = local_lima_instance_status(lima_name)?;
            if vm_status == "running" {
                lima_workspace_container_status(lima_name)
            } else {
                Ok(vm_status)
            }
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn docker_workspace_container_status(runtime_name: &str) -> anyhow::Result<String> {
    let output = ProcessCommand::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", runtime_name])
        .output()
        .context("inspect local workspace container")?;
    parse_docker_workspace_container_status(
        output.status.success(),
        output.status.code().unwrap_or(1),
        &output.stdout,
        &output.stderr,
    )
    .with_context(|| format!("docker inspect {runtime_name}"))
}

pub(crate) fn parse_docker_workspace_container_status(
    success: bool,
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Result<String> {
    let combined = combined_output(stdout, stderr);
    if !success {
        let lower = combined.to_ascii_lowercase();
        if lower.contains("no such object")
            || lower.contains("no such container")
            || lower.contains("not found")
        {
            return Ok("missing".to_string());
        }
        anyhow::bail!("exit code {exit_code}\\n{}", combined.trim());
    }
    Ok(combined.trim().to_ascii_lowercase())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalResizeResult {
    pub(crate) restart_after_resize: bool,
    pub(crate) status_after_resize: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalLimaResources {
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
    pub(crate) disk_gb: i32,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct LimaListEntry {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) cpus: i32,
    #[serde(default)]
    pub(crate) memory: i64,
    #[serde(default)]
    pub(crate) disk: i64,
}

pub(crate) fn validate_local_resize_args(args: &LocalResizeArgs) -> anyhow::Result<()> {
    if args.cpu == 0 && args.memory == 0 && args.disk == 0 {
        anyhow::bail!("at least one of --cpu, --memory, or --disk is required");
    }
    if args.cpu < 0 {
        anyhow::bail!("--cpu must be positive");
    }
    if args.memory < 0 {
        anyhow::bail!("--memory must be positive");
    }
    if args.disk < 0 {
        anyhow::bail!("--disk must be positive");
    }
    Ok(())
}

pub(crate) fn resize_local_runtime(
    instance: &mut config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalResizeResult> {
    match trimmed_required(&instance.backend, "local backend")? {
        "lima" => resize_local_lima_instance(instance, args),
        _ => anyhow::bail!("local resize is currently only supported for Lima-backed instances"),
    }
}

pub(crate) fn resize_local_lima_instance(
    instance: &mut config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalResizeResult> {
    let name = local_lima_instance_name(instance)?;
    let status = local_lima_instance_status(name)?;
    if status == "missing" {
        anyhow::bail!(
            "Lima instance {:?} is missing; recreate it with 'cw env --local create --backend lima'",
            instance.name
        );
    }
    let current = local_lima_instance_resources(name)?;
    if args.disk > 0 && args.disk < current.disk_gb {
        anyhow::bail!(
            "Lima disk shrink is not supported (current: {} Gi, requested: {} Gi)",
            current.disk_gb,
            args.disk
        );
    }

    let mut restart_after_resize = false;
    if status == "running" {
        if !args.restart {
            anyhow::bail!(
                "Lima instance {:?} is running; pass --restart to stop, resize, and start it again",
                instance.name
            );
        }
        run_local_lifecycle_command(instance, LocalLifecycleAction::Stop)?;
        restart_after_resize = true;
    }

    let spec = local_resize_command_spec(instance, args)?;
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .context("resize local runtime command")?;
    if !output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let trimmed = combined.trim();
        let message = if trimmed.is_empty() {
            format!(
                "limactl edit {name}: exit code {}",
                output.status.code().unwrap_or(1)
            )
        } else {
            format!(
                "limactl edit {name}: exit code {}\n{trimmed}",
                output.status.code().unwrap_or(1)
            )
        };
        if restart_after_resize {
            run_local_lifecycle_command(instance, LocalLifecycleAction::Start).with_context(
                || format!("restore running Lima environment after failed resize ({message})"),
            )?;
        }
        anyhow::bail!(message);
    }

    if args.cpu > 0 {
        instance.cpu = args.cpu;
    }
    if args.memory > 0 {
        instance.memory = args.memory;
    }
    if args.disk > 0 {
        instance.disk = args.disk;
    }

    Ok(LocalResizeResult {
        restart_after_resize,
        status_after_resize: if restart_after_resize {
            "running".to_string()
        } else {
            status
        },
    })
}

pub(crate) fn local_resize_command_spec(
    instance: &config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalRuntimeCommand> {
    if trimmed_required(&instance.backend, "local backend")? != "lima" {
        anyhow::bail!("local resize is currently only supported for Lima-backed instances");
    }
    let name = local_lima_instance_name(instance)?;
    let mut command_args = vec![
        "edit".to_string(),
        "--tty=false".to_string(),
        name.to_string(),
    ];
    if args.cpu > 0 {
        command_args.push("--cpus".to_string());
        command_args.push(lima_cpus_from_millicores(args.cpu).to_string());
    }
    if args.memory > 0 {
        command_args.push("--memory".to_string());
        command_args.push(lima_memory_gib_from_mb(args.memory).to_string());
    }
    if args.disk > 0 {
        command_args.push("--disk".to_string());
        command_args.push(args.disk.to_string());
    }
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: command_args,
    })
}

pub(crate) fn local_lima_instance_status(name: &str) -> anyhow::Result<String> {
    let output = ProcessCommand::new("limactl")
        .args(["list", "--format", "json"])
        .output()
        .context("limactl list --format json")?;
    if !output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lower = combined.to_lowercase();
        if lower.contains("not found")
            || lower.contains("no such")
            || lower.contains("no instance matching")
            || lower.contains("unmatched instances")
        {
            return Ok("missing".to_string());
        }
        anyhow::bail!(
            "limactl list --format json: exit code {}\n{}",
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    parse_lima_instance_status(name, &output.stdout)
}

pub(crate) fn local_lima_instance_resources(name: &str) -> anyhow::Result<LocalLimaResources> {
    let output = ProcessCommand::new("limactl")
        .args(["list", "--format", "json"])
        .output()
        .context("limactl list --format json")?;
    if !output.status.success() {
        anyhow::bail!(
            "limactl list --format json: exit code {}",
            output.status.code().unwrap_or(1)
        );
    }
    parse_lima_instance_resources(name, &output.stdout)
}

pub(crate) fn parse_lima_instance_status(name: &str, data: &[u8]) -> anyhow::Result<String> {
    let entries = parse_lima_list_entries(data)?;

    for entry in entries {
        if entry.name.trim() == name {
            let status = entry.status.trim().to_lowercase();
            return Ok(if status.is_empty() {
                "unknown".to_string()
            } else {
                status
            });
        }
    }
    Ok("missing".to_string())
}

pub(crate) fn parse_lima_instance_resources(
    name: &str,
    data: &[u8],
) -> anyhow::Result<LocalLimaResources> {
    let entry = parse_lima_list_entries(data)?
        .into_iter()
        .find(|entry| entry.name.trim() == name)
        .ok_or_else(|| anyhow::anyhow!("Lima instance {name:?} is missing"))?;
    let memory_mb = entry.memory / (1024 * 1024);
    let disk_gb = entry.disk / (1024 * 1024 * 1024);
    if entry.cpus <= 0 || memory_mb <= 0 || disk_gb <= 0 {
        anyhow::bail!("Lima instance {name:?} did not report valid resources");
    }
    Ok(LocalLimaResources {
        cpu_millicores: entry.cpus.saturating_mul(1000),
        memory_mb: memory_mb.try_into().context("Lima memory exceeds i32")?,
        disk_gb: disk_gb.try_into().context("Lima disk exceeds i32")?,
    })
}

fn parse_lima_list_entries(data: &[u8]) -> anyhow::Result<Vec<LimaListEntry>> {
    let data = trim_ascii_bytes(data);
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] == b'[' {
        return serde_json::from_slice::<Vec<LimaListEntry>>(data)
            .context("parse limactl list output");
    }
    let mut entries = Vec::new();
    for line in data.split(|byte| *byte == b'\n') {
        let line = trim_ascii_bytes(line);
        if line.first() != Some(&b'{') {
            continue;
        }
        entries.push(
            serde_json::from_slice::<LimaListEntry>(line).context("parse limactl list output")?,
        );
    }
    Ok(entries)
}

pub(crate) fn trim_ascii_bytes(mut data: &[u8]) -> &[u8] {
    while data.first().is_some_and(u8::is_ascii_whitespace) {
        data = &data[1..];
    }
    while data.last().is_some_and(u8::is_ascii_whitespace) {
        data = &data[..data.len() - 1];
    }
    data
}

pub(crate) fn lima_cpus_from_millicores(millicores: i32) -> i32 {
    ((millicores + 999) / 1000).max(1)
}

pub(crate) fn lima_memory_gib_from_mb(memory_mb: i32) -> f32 {
    (memory_mb.max(1) as f32) / 1024.0
}
