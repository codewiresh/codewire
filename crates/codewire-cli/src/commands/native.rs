use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use codewire_local_vmm::control::v1;
use codewire_local_vmm::runner_service::{RunnerEntrypointConfig, serve_runner};
use codewire_local_vmm::supervisor::{
    NativeRuntimeConfig, NativeSupervisorClient, inspect_orphans, serve_supervisor,
};
use serde::Serialize;
use serde_yaml::Value as YamlValue;
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
        artifact_root: args.artifact_root,
        artifact_lock: args.artifact_lock,
    })
    .await
    .context("run native environment runner")
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
    let requested_path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let source_path = std::fs::canonicalize(&requested_path)
        .with_context(|| format!("resolve native workspace {}", requested_path.display()))?;
    let yaml = native_codewire_yaml(&source_path, args.file.as_deref())?;
    let vcpus = match args.cpu.as_deref().or(yaml.cpu.as_deref()) {
        Some(value) => parse_native_cpu(value)?,
        None => DEFAULT_NATIVE_VCPUS,
    };
    let memory_mib = match args.memory.as_deref().or(yaml.memory.as_deref()) {
        Some(value) => parse_native_memory(value)?,
        None => DEFAULT_NATIVE_MEMORY_MIB,
    };
    let disk_bytes = match args.disk.as_deref().or(yaml.disk.as_deref()) {
        Some(value) => parse_native_disk(value)?,
        None => DEFAULT_NATIVE_DISK_BYTES,
    };
    let mut client = native_client().await?;
    client
        .create(v1::CreateEnvironmentRequest {
            name,
            source_path: source_path.to_string_lossy().into_owned(),
            vcpus,
            memory_mib,
            disk_bytes,
            request_id: Uuid::new_v4().to_string(),
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
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    let access = native_client()
        .await?
        .daemon_access(name)
        .await
        .map_err(native_status)?;
    if access.generation_capability.is_empty() || access.guest_port == 0 {
        anyhow::bail!("native environment returned invalid daemon access");
    }
    let socket = PathBuf::from(access.hybrid_socket);
    if !socket.is_absolute() {
        anyhow::bail!("native environment returned invalid daemon access");
    }
    codewire_local_vmm::hybrid_vsock::connect_daemon(
        &socket,
        access.guest_port,
        access.generation_capability,
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
    pub(crate) workspace_commit: String,
    pub(crate) source_path: String,
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
            workspace_commit: environment.workspace_commit.clone(),
            source_path: environment.source_path.clone(),
        }
    }
}

fn format_native_environment(view: &NativeEnvironmentView) -> String {
    format!(
        "Environment: {}\nBackend:     {}\nState:       {}\nCPU:         {}\nMemory:      {}\nDisk:        {}\nCommit:      {}\nSource:      {}\n",
        view.name,
        view.backend,
        view.state,
        view.cpu,
        view.memory,
        view.disk,
        view.workspace_commit,
        view.source_path,
    )
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
struct NativeYamlResources {
    cpu: Option<String>,
    memory: Option<String>,
    disk: Option<String>,
}

fn native_codewire_yaml(
    source_path: &Path,
    requested_file: Option<&Path>,
) -> anyhow::Result<NativeYamlResources> {
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
            return Ok(NativeYamlResources::default());
        }
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let value: YamlValue =
        serde_yaml::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    let mapping = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a mapping", path.display()))?;
    let mut resources = NativeYamlResources::default();
    for (key, value) in mapping {
        let key = key
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{} contains a non-string key", path.display()))?;
        let quantity = yaml_quantity(value, key, &path)?;
        match key {
            "cpu" => resources.cpu = Some(quantity),
            "memory" => resources.memory = Some(quantity),
            "disk" => resources.disk = Some(quantity),
            unsupported => anyhow::bail!(
                "native local preview does not yet support codewire.yaml field {unsupported:?}"
            ),
        }
    }
    Ok(resources)
}

fn yaml_quantity(value: &YamlValue, key: &str, path: &Path) -> anyhow::Result<String> {
    match value {
        YamlValue::String(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        YamlValue::Number(value) => Ok(value.to_string()),
        _ => anyhow::bail!(
            "{} field {key:?} must be a number or resource quantity",
            path.display()
        ),
    }
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
        assert!(error.to_string().contains("field \"image\""));
    }

    #[test]
    fn native_state_labels_are_stable() {
        assert_eq!(
            native_state_label(v1::EnvironmentState::Running as i32),
            "running"
        );
        assert_eq!(native_state_label(i32::MAX), "unavailable");
    }
}
