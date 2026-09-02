use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use codewire_local_vmm::control::v1;
use codewire_local_vmm::runner_service::{RunnerEntrypointConfig, serve_runner};
use codewire_local_vmm::supervisor::{
    NativeRuntimeConfig, NativeSupervisorClient, inspect_orphans, serve_supervisor,
};
use codewire_local_vmm::workspace::{
    WorkspaceSelection, WorkspaceSourceMode, resolve_workspace_mode,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::*;

const NATIVE_STATE_ROOT_ENV: &str = "CODEWIRE_NATIVE_STATE_ROOT";
const NATIVE_ARTIFACT_ROOT_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_ROOT";
const NATIVE_ARTIFACT_LOCK_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_LOCK";
const DEFAULT_NATIVE_VCPUS: u32 = 2;
const DEFAULT_NATIVE_MEMORY_MIB: u32 = 4 * 1024;
const DEFAULT_NATIVE_DISK_BYTES: u64 = 20 * 1024 * 1024 * 1024;

pub(crate) async fn run_native_supervisor(args: NativeSupervisorArgs) -> anyhow::Result<()> {
    let executable = canonical_current_executable()?;
    serve_supervisor(NativeRuntimeConfig {
        root: args.root,
        artifact_root: args.artifact_root,
        artifact_lock: args.artifact_lock,
        executable,
    })
    .await
    .context("run native local supervisor")
}

pub(crate) async fn run_native_runner(args: NativeRunnerArgs) -> anyhow::Result<()> {
    let environment_id =
        Uuid::parse_str(&args.environment_id).context("native runner environment ID is invalid")?;
    serve_runner(RunnerEntrypointConfig {
        environment_id,
        socket: args.socket,
        engine_state_root: args.engine_state_root,
        artifact_generation: args.artifact_generation,
    })
    .await
    .context("run native environment runner")
}

pub(crate) async fn run_native_network_worker(args: NativeNetworkWorkerArgs) -> anyhow::Result<()> {
    let environment_id = Uuid::parse_str(&args.environment_id)
        .context("native network worker environment ID is invalid")?;
    codewire_local_vmm::network_worker::run_inherited_worker(environment_id, args.generation)
        .await
        .context("run native environment network worker")
}

pub(crate) async fn run_native_egress_broker(args: NativeEgressBrokerArgs) -> anyhow::Result<()> {
    let environment_id = Uuid::parse_str(&args.environment_id)
        .context("native egress broker environment ID is invalid")?;
    codewire_local_vmm::egress_broker::run_inherited_egress_broker(environment_id, args.generation)
        .await
        .context("run native environment egress broker")
}

pub(crate) async fn run_native_mesh_transport(args: NativeMeshTransportArgs) -> anyhow::Result<()> {
    let environment_id = Uuid::parse_str(&args.environment_id)
        .context("native Mesh transport environment ID is invalid")?;
    codewire_local_vmm::mesh_process::run_inherited_mesh_transport(environment_id, args.generation)
        .await
        .context("run native environment Mesh transport")
}

pub(crate) fn native_create_selected(args: &EnvCreateArgs) -> anyhow::Result<bool> {
    match args.backend.as_deref().map(str::trim) {
        None | Some("") | Some("native") | Some("cloud-hypervisor") => Ok(true),
        Some("docker" | "lima") => Ok(false),
        Some(other) => anyhow::bail!(
            "unsupported local backend {other:?}; use native, cloud-hypervisor, docker, or lima"
        ),
    }
}

pub(crate) async fn create_native_environment(
    args: EnvCreateArgs,
) -> anyhow::Result<v1::Environment> {
    reject_unsupported_native_create_options(&args)?;
    let name = args
        .name
        .as_deref()
        .and_then(trimmed_str)
        .ok_or_else(|| anyhow::anyhow!("native local creation requires --name"))?
        .to_owned();
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    if resolve_local_instance_target(&paths.mesh_data_dir, &name).is_some() {
        anyhow::bail!(
            "local environment {name:?} already exists in the legacy Docker/Lima state; choose a different name or remove it explicitly"
        );
    }
    let requested_path = args.path.as_deref().unwrap_or_else(|| Path::new("."));
    let source_path = std::fs::canonicalize(requested_path)
        .with_context(|| format!("resolve native workspace {}", requested_path.display()))?;
    let project = native_codewire_yaml(&source_path, args.file.as_deref())?;
    let (request_source_path, implicit_path_mode) =
        native_workspace_request(&source_path, &project.spec, args.path_mode)?;
    let vcpus = match args.cpu.as_deref() {
        Some(value) => parse_native_cpu(value)?,
        None => project.vcpus.unwrap_or(DEFAULT_NATIVE_VCPUS),
    };
    let memory_mib = match args.memory.as_deref() {
        Some(value) => parse_native_memory(value)?,
        None => project.memory_mib.unwrap_or(DEFAULT_NATIVE_MEMORY_MIB),
    };
    let disk_bytes = match args.disk.as_deref() {
        Some(value) => parse_native_disk(value)?,
        None => project.disk_bytes.unwrap_or(DEFAULT_NATIVE_DISK_BYTES),
    };
    let host_ports = project
        .host_ports
        .iter()
        .map(|binding| v1::HostPortBinding {
            host_port: u32::from(binding.host_port),
            guest_port: u32::from(binding.guest_port),
        })
        .collect();
    let (project_spec_json, project_spec_sha256) =
        canonical_native_project_intent(project.spec, vcpus, memory_mib, disk_bytes)?;
    let mut client = native_client().await?;
    client
        .create(v1::CreateEnvironmentRequest {
            name,
            source_path: request_source_path,
            vcpus,
            memory_mib,
            disk_bytes,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json,
            project_spec_sha256,
            implicit_path_mode,
            host_ports,
            mesh: None,
        })
        .await
        .map_err(native_status)
}

pub(crate) async fn native_environments() -> anyhow::Result<Vec<v1::Environment>> {
    if !native_state_exists()? {
        return Ok(Vec::new());
    }
    native_client().await?.list().await.map_err(native_status)
}

pub(crate) fn native_orphan_report() -> anyhow::Result<NativeOrphanReport> {
    if !native_state_exists()? {
        return Ok(NativeOrphanReport {
            orphans: Vec::new(),
            reclaimable_bytes: 0,
        });
    }
    let response = inspect_orphans(&native_runtime_config()?.root)
        .context("inspect native local orphan inventory")?;
    Ok(NativeOrphanReport {
        orphans: response
            .orphans
            .into_iter()
            .map(|orphan| NativeOrphanView {
                kind: orphan.kind,
                path: orphan.path,
                reason: orphan.reason,
                reclaimable_bytes: orphan.reclaimable_bytes,
            })
            .collect(),
        reclaimable_bytes: response.reclaimable_bytes,
    })
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeOrphanReport {
    pub(crate) orphans: Vec<NativeOrphanView>,
    pub(crate) reclaimable_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeOrphanView {
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) reason: String,
    pub(crate) reclaimable_bytes: u64,
}

pub(crate) fn print_native_orphan_report(
    report: &NativeOrphanReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text if report.orphans.is_empty() => {
            println!("Native local VM orphans: none");
        }
        OutputFormat::Text => {
            println!("Native local VM orphans:");
            for orphan in &report.orphans {
                println!(
                    "  {}  {}  {}  {}",
                    orphan.kind,
                    orphan.reason,
                    format_binary_bytes(orphan.reclaimable_bytes),
                    orphan.path
                );
            }
            println!("Reclaimable allocated bytes: {}", report.reclaimable_bytes);
        }
    }
    Ok(())
}

pub(crate) async fn native_environment(name: &str) -> anyhow::Result<Option<v1::Environment>> {
    let name = match trimmed_str(name) {
        Some(name) => name,
        None => return Ok(None),
    };
    Ok(native_environments()
        .await?
        .into_iter()
        .find(|environment| environment.name == name || environment.id == name))
}

pub(crate) async fn native_selected_environment() -> anyhow::Result<Option<v1::Environment>> {
    Ok(native_environments()
        .await?
        .into_iter()
        .find(|environment| environment.selected))
}

pub(crate) async fn get_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    native_client()
        .await?
        .get(name)
        .await
        .map_err(native_status)
}

pub(crate) async fn start_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    native_client()
        .await?
        .start(name)
        .await
        .map_err(native_status)
}

pub(crate) async fn stop_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    native_client()
        .await?
        .stop(name)
        .await
        .map_err(native_status)
}

pub(crate) async fn resize_native_environment(
    name: &str,
    vcpus: u32,
    memory_mib: u32,
    disk_bytes: u64,
) -> anyhow::Result<v1::Environment> {
    native_client()
        .await?
        .resize(name, vcpus, memory_mib, disk_bytes)
        .await
        .map_err(native_status)
}

pub(crate) async fn delete_native_environment(
    name: &str,
) -> anyhow::Result<v1::DeleteEnvironmentResponse> {
    native_client()
        .await?
        .delete(name)
        .await
        .map_err(native_status)
}

pub(crate) async fn native_environment_session_client(
    name: &str,
) -> anyhow::Result<codewire_local_vmm::public_client::NativePublicSessionClient> {
    codewire_local_vmm::public_client::NativePublicSessionClient::connect_or_start(
        &native_runtime_config()?,
        name,
    )
    .await
    .map_err(anyhow::Error::from)
}

pub(crate) async fn native_environment_diagnostic_client(
    name: &str,
) -> anyhow::Result<codewire_local_vmm::public_client::NativePublicEnvironmentClient> {
    codewire_local_vmm::public_client::NativePublicEnvironmentClient::connect_or_start(
        &native_runtime_config()?,
        name,
    )
    .await
    .map_err(anyhow::Error::from)
}

pub(crate) fn print_native_environment(
    environment: &v1::Environment,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let view = NativeEnvironmentView::from(environment);
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&view)?),
        OutputFormat::Text => print!("{}", format_native_environment(&view)),
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeEnvironmentView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) backend: String,
    pub(crate) state: String,
    pub(crate) selected: bool,
    pub(crate) cpu: u32,
    pub(crate) memory: String,
    pub(crate) disk: String,
    pub(crate) workspace_plan: String,
    pub(crate) workspace_inputs: u32,
    pub(crate) working_directory: String,
    pub(crate) ports: Vec<NativeHostPortView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeHostPortView {
    pub(crate) listen: String,
    pub(crate) guest_port: u32,
}

impl From<&v1::Environment> for NativeEnvironmentView {
    fn from(environment: &v1::Environment) -> Self {
        Self {
            id: environment.id.clone(),
            name: environment.name.clone(),
            backend: "cloud-hypervisor".to_owned(),
            state: native_state_label(environment.state).to_owned(),
            selected: environment.selected,
            cpu: environment.vcpus,
            memory: format_binary_mib(environment.memory_mib),
            disk: format_binary_bytes(environment.disk_bytes),
            workspace_plan: environment.workspace_plan_sha256.clone(),
            workspace_inputs: environment.workspace_input_count,
            working_directory: environment.working_directory.clone(),
            ports: environment
                .host_ports
                .iter()
                .map(|binding| NativeHostPortView {
                    listen: format!("127.0.0.1:{}", binding.host_port),
                    guest_port: binding.guest_port,
                })
                .collect(),
        }
    }
}

fn format_native_environment(view: &NativeEnvironmentView) -> String {
    let mut output = format!(
        "Environment: {}\nBackend:     {}\nState:       {}\nCPU:         {}\nMemory:      {}\nDisk:        {}\nWorkspace:   {} input(s), plan {}\nWorking dir: {}\n",
        view.name,
        view.backend,
        view.state,
        view.cpu,
        view.memory,
        view.disk,
        view.workspace_inputs,
        view.workspace_plan,
        view.working_directory,
    );
    for port in &view.ports {
        output.push_str(&format!(
            "Port:        {} -> {}\n",
            port.listen, port.guest_port
        ));
    }
    output
}

pub(crate) fn native_state_label(state: i32) -> &'static str {
    match v1::EnvironmentState::try_from(state) {
        Ok(v1::EnvironmentState::Stopped) => "stopped",
        Ok(v1::EnvironmentState::Starting) => "starting",
        Ok(v1::EnvironmentState::Running) => "running",
        Ok(v1::EnvironmentState::Error) => "error",
        Ok(v1::EnvironmentState::Orphaned) => "orphaned",
        _ => "unavailable",
    }
}

fn format_binary_mib(memory_mib: u32) -> String {
    if memory_mib.is_multiple_of(1024) {
        format!("{}Gi", memory_mib / 1024)
    } else {
        format!("{memory_mib}Mi")
    }
}

fn format_binary_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes.is_multiple_of(GIB) {
        format!("{}Gi", bytes / GIB)
    } else {
        bytes.to_string()
    }
}

async fn native_client() -> anyhow::Result<NativeSupervisorClient> {
    let config = native_runtime_config()?;
    NativeSupervisorClient::connect_or_start(&config)
        .await
        .context("connect to native local supervisor")
}

fn native_runtime_config() -> anyhow::Result<NativeRuntimeConfig> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let root = absolute_override(NATIVE_STATE_ROOT_ENV)?
        .unwrap_or_else(|| paths.mesh_data_dir.join("native-v1"));
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/.codewire-home"));
    let artifact_parent = home.join(".cache").join("codewire").join("local-vmm-v1");
    let artifact_root = absolute_override(NATIVE_ARTIFACT_ROOT_ENV)?
        .unwrap_or_else(|| artifact_parent.join("artifacts"));
    let artifact_lock = absolute_override(NATIVE_ARTIFACT_LOCK_ENV)?
        .unwrap_or_else(|| artifact_parent.join("artifacts.lock.json"));
    Ok(NativeRuntimeConfig {
        root,
        artifact_root,
        artifact_lock,
        executable: canonical_current_executable()?,
    })
}

fn absolute_override(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        anyhow::bail!("{name} must be an absolute path");
    }
    Ok(Some(path))
}

fn native_state_exists() -> anyhow::Result<bool> {
    let config = native_runtime_config()?;
    for name in ["supervisor.db", "state.json"] {
        match std::fs::symlink_metadata(config.root.join(name)) {
            Ok(metadata) if metadata.is_file() => return Ok(true),
            Ok(_) => anyhow::bail!("native local state {name} is not a regular file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect native local state"),
        }
    }
    Ok(false)
}

fn canonical_current_executable() -> anyhow::Result<PathBuf> {
    let executable = env::current_exe().context("resolve current cw executable")?;
    std::fs::canonicalize(&executable).with_context(|| {
        format!(
            "canonicalize current cw executable {}",
            executable.display()
        )
    })
}

#[derive(Debug, Default)]
struct NativeProjectPlan {
    spec: codewire_project::ProjectSpec,
    host_ports: Vec<codewire_project::HostPortBinding>,
    vcpus: Option<u32>,
    memory_mib: Option<u32>,
    disk_bytes: Option<u64>,
}

fn native_codewire_yaml(
    source_path: &Path,
    requested_file: Option<&Path>,
) -> anyhow::Result<NativeProjectPlan> {
    let file = requested_file.unwrap_or_else(|| Path::new("codewire.yaml"));
    if file.is_absolute()
        || file.as_os_str().is_empty()
        || file
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!("native --file must be a relative path beneath --path");
    }
    let path = source_path.join(file);
    let data = match std::fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && requested_file.is_none() => {
            return Ok(NativeProjectPlan::default());
        }
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let document = codewire_project::parse_project_yaml(&data)
        .with_context(|| format!("parse {}", path.display()))?;
    let unsupported = native_unsupported_project_fields(&document);
    if !unsupported.is_empty() {
        anyhow::bail!(
            "native local preview does not yet support codewire.yaml fields: {}",
            unsupported.join(", ")
        );
    }
    let resources = &document.spec.resources;
    let vcpus = resources
        .cpu_millicores
        .map(native_vcpus_from_millicores)
        .transpose()?;
    let memory_mib = resources
        .memory_mib
        .map(native_memory_from_mib)
        .transpose()?;
    let disk_bytes = resources.disk_gib.map(native_disk_from_gib).transpose()?;
    Ok(NativeProjectPlan {
        spec: document.spec,
        host_ports: document.local.host_ports,
        vcpus,
        memory_mib,
        disk_bytes,
    })
}

fn native_unsupported_project_fields(
    document: &codewire_project::ProjectDocument,
) -> Vec<&'static str> {
    let spec = &document.spec;
    let mut unsupported = Vec::new();
    if !spec.preset.is_empty() {
        unsupported.push("preset");
    }
    if !spec.image.is_empty() {
        unsupported.push("image");
    }
    if spec.repositories.is_empty() && spec.working_directory != "/workspace" {
        unsupported.push("working_directory");
    }
    if !spec.install_command.is_empty() {
        unsupported.push("install");
    }
    if !spec.startup_script.is_empty() {
        unsupported.push("startup");
    }
    if !spec.environment.is_empty() {
        unsupported.push("env");
    }
    if !spec.agents.is_empty() || !spec.agent_environment.is_empty() {
        unsupported.push("agents");
    }
    if !spec.skills.is_empty() {
        unsupported.push("skills");
    }
    if !spec.secrets.is_empty() {
        unsupported.push("secrets");
    }
    if !spec.credentials.is_empty() {
        unsupported.push("credentials");
    }
    if !document.local.mounts.is_empty() {
        unsupported.push("mounts");
    }
    unsupported
}

fn native_vcpus_from_millicores(millicores: u32) -> anyhow::Result<u32> {
    if !millicores.is_multiple_of(1000) {
        anyhow::bail!("native CPU must resolve to a whole core count");
    }
    parse_native_cpu(&(millicores / 1000).to_string())
}

fn native_memory_from_mib(memory_mib: u64) -> anyhow::Result<u32> {
    parse_native_memory(&format!("{memory_mib}Mi"))
}

fn native_disk_from_gib(disk_gib: u64) -> anyhow::Result<u64> {
    parse_native_disk(&format!("{disk_gib}Gi"))
}

fn canonical_native_project_intent(
    mut spec: codewire_project::ProjectSpec,
    vcpus: u32,
    memory_mib: u32,
    disk_bytes: u64,
) -> anyhow::Result<(Vec<u8>, String)> {
    spec.image = CANONICAL_WORKSPACE_IMAGE.to_owned();
    spec.resources = codewire_project::ResourceSpec {
        cpu_millicores: Some(
            vcpus
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("native CPU quantity is too large"))?,
        ),
        memory_mib: Some(u64::from(memory_mib)),
        disk_gib: Some(disk_bytes / (1024 * 1024 * 1024)),
    };
    let bytes = spec
        .canonical_json()
        .context("encode canonical native project intent")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn workspace_selection_from_arg(value: PathModeArg) -> WorkspaceSelection {
    match value {
        PathModeArg::Auto => WorkspaceSelection::Auto,
        PathModeArg::Clone => WorkspaceSelection::Clone,
        PathModeArg::Copy => WorkspaceSelection::Copy,
    }
}

fn workspace_source_mode_name(value: WorkspaceSourceMode) -> &'static str {
    match value {
        WorkspaceSourceMode::Clone => "clone",
        WorkspaceSourceMode::Copy => "copy",
    }
}

fn native_workspace_request(
    source_path: &Path,
    spec: &codewire_project::ProjectSpec,
    requested_mode: Option<PathModeArg>,
) -> anyhow::Result<(String, String)> {
    if !spec.repositories.is_empty() {
        if requested_mode.is_some() {
            anyhow::bail!("--path-mode applies only when codewire.yaml has no repositories");
        }
        return Ok((String::new(), String::new()));
    }
    let requested_workspace = requested_mode
        .map(workspace_selection_from_arg)
        .unwrap_or(WorkspaceSelection::Auto);
    let mode = resolve_workspace_mode(source_path, requested_workspace)
        .context("resolve native workspace preparation mode")?;
    Ok((
        source_path.to_string_lossy().into_owned(),
        workspace_source_mode_name(mode).to_owned(),
    ))
}

fn reject_unsupported_native_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    let mut unsupported = Vec::new();
    if !args.repo_urls.is_empty() || !args.repo_flags.is_empty() {
        unsupported.push("repositories");
    }
    if args.preset_slug.is_some() || args.preset_id.is_some() {
        unsupported.push("presets");
    }
    if args.spec.is_some() {
        unsupported.push("--spec");
    }
    if args.ttl.is_some() {
        unsupported.push("--ttl");
    }
    if args.isolation.is_some() {
        unsupported.push("--isolation");
    }
    if args.branch.is_some() {
        unsupported.push("--branch");
    }
    if args.image.is_some() {
        unsupported.push("--image");
    }
    if args.install.is_some() {
        unsupported.push("--install");
    }
    if args.startup.is_some() {
        unsupported.push("--startup");
    }
    if args.coding_agent.is_some() {
        unsupported.push("--coding-agent");
    }
    if !args.env.is_empty() {
        unsupported.push("--env");
    }
    if args.secret_project.is_some() || args.no_org_secrets || args.no_user_secrets {
        unsupported.push("secrets");
    }
    if args.network.is_some() || args.no_network {
        unsupported.push("networking");
    }
    if !args.follow || args.no_wait {
        unsupported.push("asynchronous creation");
    }
    if args.write_preset || args.save_preset.is_some() {
        unsupported.push("preset publication");
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "native local preview does not yet support: {}",
            unsupported.join(", ")
        );
    }
    Ok(())
}

fn parse_native_cpu(value: &str) -> anyhow::Result<u32> {
    let value = value.trim();
    let vcpus = value.parse::<u32>().with_context(|| {
        format!("invalid native CPU quantity {value:?}; use a core count such as 2")
    })?;
    if !(1..=32).contains(&vcpus) {
        anyhow::bail!("native CPU must be from 1 through 32 cores");
    }
    Ok(vcpus)
}

fn parse_native_memory(value: &str) -> anyhow::Result<u32> {
    let value = value.trim();
    let memory_mib = if let Some(amount) = value.strip_suffix("Gi") {
        amount
            .parse::<u32>()
            .context("invalid native memory quantity")?
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("native memory quantity is too large"))?
    } else if let Some(amount) = value.strip_suffix("Mi") {
        amount
            .parse::<u32>()
            .context("invalid native memory quantity")?
    } else {
        value.parse::<u32>().with_context(|| {
            format!("invalid native memory quantity {value:?}; use 512Mi or 16Gi")
        })?
    };
    if !(128..=65_536).contains(&memory_mib) {
        anyhow::bail!("native memory must be from 128Mi through 64Gi");
    }
    Ok(memory_mib)
}

fn parse_native_disk(value: &str) -> anyhow::Result<u64> {
    const GIB: u64 = 1024 * 1024 * 1024;
    let value = value.trim();
    let gib = value
        .strip_suffix("Gi")
        .unwrap_or(value)
        .parse::<u64>()
        .with_context(|| {
            format!("invalid native disk quantity {value:?}; use a value such as 20Gi")
        })?;
    let bytes = gib
        .checked_mul(GIB)
        .ok_or_else(|| anyhow::anyhow!("native disk quantity is too large"))?;
    if !(1..=1024).contains(&gib) {
        anyhow::bail!("native disk must be from 1Gi through 1024Gi");
    }
    Ok(bytes)
}

fn native_status(status: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!(status.message().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_resource_quantities_match_the_canonical_command() {
        assert_eq!(parse_native_cpu("2").unwrap(), 2);
        assert_eq!(parse_native_memory("16Gi").unwrap(), 16 * 1024);
        assert_eq!(parse_native_disk("20Gi").unwrap(), 20 * 1024 * 1024 * 1024);
    }

    #[test]
    fn native_yaml_rejects_unsupported_product_fields() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("codewire.yaml"), "image: workspace\n").unwrap();
        let error = native_codewire_yaml(temp.path(), None).unwrap_err();
        assert!(error.to_string().contains("fields: image"));
    }

    #[test]
    fn native_yaml_uses_shared_resource_normalization() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "version: 1\ncpu: 2000m\nmemory: 16Gi\ndisk: 40Gi\n",
        )
        .unwrap();
        let resources = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(resources.vcpus, Some(2));
        assert_eq!(resources.memory_mib, Some(16 * 1024));
        assert_eq!(resources.disk_bytes, Some(40 * 1024 * 1024 * 1024));
    }

    #[test]
    fn native_yaml_recognizes_mode_bearing_mounts_before_runtime_assembly() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "mounts: [{source: ./fixtures, destination: /workspace/fixtures, mode: copy}]\n",
        )
        .unwrap();
        let error = native_codewire_yaml(temp.path(), None).unwrap_err();
        assert!(error.to_string().contains("fields: mounts"), "{error}");
    }

    #[test]
    fn native_yaml_repositories_replace_the_implicit_local_workspace() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            r#"version: 1
repositories:
  - source: https://github.com/noeljackson/method.git
    revision: 93f68ba4abc9f6e222481265b9b759e71d332575
    destination: /workspace/github
  - source: https://git.example.invalid/supplychain.git
    revision: bcbae548ab2f4f0e407068aa8717cec341084d7a
    destination: /workspace/gitea
working_directory: /workspace/github
"#,
        )
        .unwrap();

        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.spec.repositories.len(), 2);
        assert_eq!(project.spec.working_directory, "/workspace/github");
        assert_eq!(
            native_workspace_request(temp.path(), &project.spec, None).unwrap(),
            (String::new(), String::new())
        );
        let error = native_workspace_request(temp.path(), &project.spec, Some(PathModeArg::Copy))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--path-mode applies only when codewire.yaml has no repositories"),
            "{error}"
        );
    }

    #[test]
    fn native_yaml_keeps_port_intent_and_exact_loopback_publications() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "ports:\n  - 3000\n  - 18080:8080\n",
        )
        .unwrap();

        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(
            project
                .spec
                .application_ports
                .iter()
                .map(|port| port.port)
                .collect::<Vec<_>>(),
            vec![3_000, 8_080]
        );
        assert_eq!(project.host_ports.len(), 1);
        assert_eq!(project.host_ports[0].host_port, 18_080);
        assert_eq!(project.host_ports[0].guest_port, 8_080);
    }

    #[test]
    fn path_mode_arguments_map_only_the_implicit_local_source() {
        assert_eq!(
            workspace_selection_from_arg(PathModeArg::Auto),
            WorkspaceSelection::Auto
        );
        assert_eq!(
            workspace_selection_from_arg(PathModeArg::Clone),
            WorkspaceSelection::Clone
        );
        assert_eq!(
            workspace_selection_from_arg(PathModeArg::Copy),
            WorkspaceSelection::Copy
        );
    }

    #[test]
    fn native_project_intent_records_effective_resources_and_default_image() {
        let spec = codewire_project::ProjectSpec::default();
        let (bytes, digest) =
            canonical_native_project_intent(spec, 2, 16 * 1024, 40 * 1024 * 1024 * 1024).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
        let spec: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(spec.image, CANONICAL_WORKSPACE_IMAGE);
        assert_eq!(spec.resources.cpu_millicores, Some(2_000));
        assert_eq!(spec.resources.memory_mib, Some(16 * 1024));
        assert_eq!(spec.resources.disk_gib, Some(40));
        assert_eq!(spec.canonical_json().unwrap(), bytes);
    }

    #[test]
    fn native_state_labels_are_stable() {
        assert_eq!(
            native_state_label(v1::EnvironmentState::Running as i32),
            "running"
        );
        assert_eq!(native_state_label(i32::MAX), "unavailable");
    }

    #[test]
    fn native_environment_text_reports_exact_loopback_mapping() {
        let view = NativeEnvironmentView {
            id: Uuid::new_v4().to_string(),
            name: "dev".to_owned(),
            backend: "cloud-hypervisor".to_owned(),
            state: "running".to_owned(),
            selected: true,
            cpu: 2,
            memory: "16Gi".to_owned(),
            disk: "20Gi".to_owned(),
            workspace_plan: "c".repeat(64),
            workspace_inputs: 1,
            working_directory: "/workspace".to_owned(),
            ports: vec![NativeHostPortView {
                listen: "127.0.0.1:18080".to_owned(),
                guest_port: 8_080,
            }],
        };

        assert!(
            format_native_environment(&view).contains("Port:        127.0.0.1:18080 -> 8080\n")
        );
    }
}
