use std::future::Future;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use anyhow::Context as _;
use codewire_access::{AccessProfileReference, EnvironmentId};
use codewire_client::TokenProvider as _;
use codewire_local_credentials::LocalCredentialClient;
use codewire_local_vmm::control::v1;
use codewire_local_vmm::oci::RegistryReference;
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

mod sources;

const NATIVE_STATE_ROOT_ENV: &str = "CODEWIRE_NATIVE_STATE_ROOT";
const NATIVE_ARTIFACT_ROOT_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_ROOT";
const NATIVE_ARTIFACT_LOCK_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_LOCK";
const DEFAULT_NATIVE_VCPUS: u32 = 2;
const DEFAULT_NATIVE_MEMORY_MIB: u32 = 4 * 1024;
const DEFAULT_NATIVE_DISK_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const DEFAULT_NATIVE_DOCKER_DISK_BYTES: u64 =
    codewire_local_vmm::linux::state::DEFAULT_DOCKER_DISK_BYTES;
const NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE: &str = "local credential authority is unavailable";

pub(crate) async fn run_native_supervisor(args: NativeSupervisorArgs) -> anyhow::Result<()> {
    let executable = canonical_current_executable()?;
    serve_supervisor(NativeRuntimeConfig {
        root: args.root,
        artifact_root: args.artifact_root,
        artifact_lock: args.artifact_lock,
        mesh_data_dir: args.mesh_data_dir,
        platform_config_dir: args.platform_config_dir,
        credential_authority_root: args.credential_authority_root,
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
        mesh_data_dir: args.mesh_data_dir,
        platform_config_dir: args.platform_config_dir,
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

struct NativeMeshEnrollmentCredentials {
    paths: ResolvePaths,
}

impl codewire_local_vmm::mesh_enrollment::MeshEnrollmentCredentialResolver
    for NativeMeshEnrollmentCredentials
{
    fn resolve<'a>(
        &'a self,
        attachment: &'a codewire_local_vmm::mesh_ingress::MeshAttachment,
    ) -> Pin<Box<dyn Future<Output = Result<codewire_client::BearerToken, ()>> + Send + 'a>> {
        Box::pin(async move {
            match attachment.auth_source {
                codewire_local_vmm::mesh_enrollment::MeshEnrollmentAuthSource::StandaloneLocal => {
                    let mesh_data_dir =
                        canonical_private_auth_root(self.paths.mesh_data_dir.clone())?;
                    let path = mesh_data_dir.join("config.toml");
                    validate_private_auth_file(&path)?;
                    let mut mesh = config::load_mesh_config(&mesh_data_dir).map_err(|_| ())?;
                    let identity = mesh.local_identity.take().ok_or(())?;
                    let token = mesh.mesh_auth_token.take().ok_or(())?;
                    let saved_url = mesh.mesh_url.take().ok_or(())?;
                    if !config::same_mesh_url(&saved_url, &attachment.mesh_url)
                        || identity.organization_id != attachment.organization_id
                        || identity.api_key != token
                        || !identity.api_key.starts_with("cw_")
                    {
                        return Err(());
                    }
                    codewire_client::BearerToken::new(token).map_err(|_| ())
                }
                codewire_local_vmm::mesh_enrollment::MeshEnrollmentAuthSource::HostedCurrent => {
                    let platform_config_dir =
                        canonical_private_auth_root(self.paths.platform_config_dir.clone())?;
                    let config_path = platform_config_dir.join("config.json");
                    let credentials_path = config::oauth_credentials_path(&platform_config_dir);
                    validate_private_auth_file(&config_path)?;
                    validate_private_auth_file(&credentials_path)?;
                    let platform =
                        config::load_platform_config(&platform_config_dir).map_err(|_| ())?;
                    let hosted =
                        config::derive_hosted_mesh_url_for_server(&platform.server_url).ok_or(())?;
                    if !config::same_mesh_url(&hosted, &attachment.mesh_url)
                        || platform.default_org.trim() != attachment.organization_id
                    {
                        return Err(());
                    }
                    let http = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .no_proxy()
                        .build()
                        .map_err(|_| ())?;
                    let oauth = codewire_client::OAuthClient::for_server_url_with_http(
                        &platform.server_url,
                        http,
                    )
                    .map_err(|_| ())?;
                    let provider = codewire_client::RefreshingTokenProvider::from_store(
                        oauth,
                        codewire_client::FileCredentialStore::at(credentials_path),
                    )
                    .map_err(|_| ())?;
                    provider.token().await.map_err(|_| ())
                }
            }
        })
    }
}

pub(crate) async fn run_native_mesh_enrollment_broker(
    args: NativeMeshEnrollmentBrokerArgs,
) -> anyhow::Result<()> {
    let environment_id = Uuid::parse_str(&args.environment_id)
        .context("native Mesh enrollment environment ID is invalid")?;
    let paths = ResolvePaths {
        mesh_data_dir: absolute_auth_root_argument(args.mesh_data_dir)?,
        platform_config_dir: absolute_auth_root_argument(args.platform_config_dir)?,
    };
    let credentials = NativeMeshEnrollmentCredentials { paths };
    codewire_local_vmm::mesh_enrollment::run_inherited_mesh_enrollment_broker(
        environment_id,
        args.generation,
        &credentials,
    )
    .await
    .context("run native Mesh enrollment issuer")
}

fn absolute_auth_root_argument(path: PathBuf) -> anyhow::Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!("native Mesh enrollment auth root must be absolute");
    }
    Ok(path)
}

fn canonical_private_auth_root(path: PathBuf) -> Result<PathBuf, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let canonical = std::fs::canonicalize(&path).map_err(|_| ())?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| ())?;
    if canonical != path
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(());
    }
    Ok(canonical)
}

fn validate_private_auth_file(path: &Path) -> Result<(), ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || std::fs::canonicalize(path).map_err(|_| ())? != path
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn native_create_selected(args: &EnvCreateArgs) -> anyhow::Result<bool> {
    match args.backend.as_deref().map(str::trim) {
        None | Some("") | Some("native") | Some("cloud-hypervisor") => Ok(true),
        Some(other) => anyhow::bail!("unsupported local backend {other:?}; use native"),
    }
}

fn resolve_native_mesh_attachment(
    paths: &ResolvePaths,
    env: &impl config::Env,
    name: &str,
    project: &NativeProjectPlan,
    requested_network: Option<&str>,
    disable_network: bool,
    assume_yes: bool,
) -> anyhow::Result<Option<v1::MeshAttachment>> {
    let requested_network = requested_network.and_then(trimmed_str);
    if disable_network && requested_network.is_some() {
        anyhow::bail!("--network and --no-network cannot be used together");
    }
    if disable_network {
        return Ok(None);
    }

    // This descriptor is deliberately separate from both credential stores.
    // It contains only status-visible metadata written by Mesh/platform setup;
    // ordinary environment creation must never deserialize a bearer.
    let owner = load_local_mesh_owner_context(&paths.mesh_data_dir)?;
    let environment_network = env
        .var(config::CODEWIRE_MESH_NETWORK_ENV)
        .and_then(|network| trimmed_str(&network).map(str::to_owned));
    let network_id = requested_network
        .map(str::to_owned)
        .or(environment_network)
        .or_else(|| {
            owner
                .as_ref()
                .and_then(|owner| owner.selected_network.as_deref())
                .and_then(trimmed_str)
                .map(str::to_owned)
        });
    let Some(network_id) = network_id else {
        return Ok(None);
    };

    let auto_connect = owner.as_ref().is_some_and(|owner| {
        owner.auto_connect && owner.selected_network.as_deref() == Some(network_id.as_str())
    });
    if requested_network.is_none() && !assume_yes && !auto_connect {
        if !stdin_is_interactive() {
            return Ok(None);
        }
        let mesh_url = owner
            .as_ref()
            .map(|owner| owner.mesh_url.as_str())
            .unwrap_or("the local Mesh service");
        if !prompt_confirm_default_no(&format!(
            "Join Codewire Mesh network {network_id:?} at {mesh_url} for remote access. Continue"
        ))? {
            return Ok(None);
        }
    }

    let owner = owner.ok_or_else(|| {
        anyhow::anyhow!(
            "no Mesh owner is configured; run 'cw login --org <org>' for hosted Mesh or run 'cw mesh up' for standalone Mesh before attaching network {network_id:?}"
        )
    })?;
    let (auth_source, proto_auth_source) = match owner.auth_source {
        LocalMeshOwnerAuthSource::StandaloneLocal => {
            let runtime = load_local_mesh_runtime(&paths.mesh_data_dir)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "local Mesh is not running; run 'cw mesh up' before attaching network {network_id:?}"
                )
            })?;
            if !local_process_is_running(runtime.pid) {
                anyhow::bail!(
                    "local Mesh runtime is stale; run 'cw mesh up' before attaching network {network_id:?}"
                );
            }
            if !config::same_mesh_url(&owner.mesh_url, &runtime.base_url) {
                anyhow::bail!(
                    "local Mesh owner projection does not match the active standalone runtime"
                );
            }
            (
                codewire_local_vmm::mesh_ingress::MeshEnrollmentAuthSource::StandaloneLocal,
                v1::MeshEnrollmentAuthSource::StandaloneLocal,
            )
        }
        LocalMeshOwnerAuthSource::HostedCurrent => (
            codewire_local_vmm::mesh_ingress::MeshEnrollmentAuthSource::HostedCurrent,
            v1::MeshEnrollmentAuthSource::HostedCurrent,
        ),
    };

    let attachment = codewire_local_vmm::mesh_ingress::MeshAttachment::new_with_auth_source(
        auth_source,
        &owner.mesh_url,
        &owner.organization_id,
        &network_id,
        name,
        project.spec.application_ports.iter().map(|port| port.port),
    )
    .context("validate native local Mesh attachment")?;
    Ok(Some(v1::MeshAttachment {
        mesh_url: attachment.mesh_url,
        organization_id: attachment.organization_id,
        network_id: attachment.network_id,
        node_name: attachment.node_name,
        guest_ports: attachment.guest_ports.into_iter().map(u32::from).collect(),
        auth_source: proto_auth_source as i32,
    }))
}

pub(crate) async fn create_native_environment(
    globals: &Globals,
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
    let requested_path = args.path.as_deref().unwrap_or_else(|| Path::new("."));
    let source_path = std::fs::canonicalize(requested_path)
        .with_context(|| format!("resolve native workspace {}", requested_path.display()))?;
    let mut project = native_codewire_yaml(&source_path, args.file.as_deref())?;
    apply_native_setup_overrides(
        &mut project.spec,
        args.install.as_deref(),
        args.startup.as_deref(),
    )?;
    if let Some(image) = args.image.as_deref().and_then(trimmed_str) {
        project.spec.image = image.to_owned();
    }
    sources::apply_create_source_flags(&mut project.spec, &args)?;
    let (request_source_path, implicit_path_mode) = native_workspace_request(
        &source_path,
        &project.spec,
        &project.local_mounts,
        args.path_mode,
    )?;
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
    let docker_disk_bytes = if args.no_docker {
        0
    } else {
        match args.docker_disk.as_deref() {
            Some(value) => parse_native_disk(value)?,
            None => DEFAULT_NATIVE_DOCKER_DISK_BYTES,
        }
    };
    let host_ports = project
        .host_ports
        .iter()
        .map(|binding| v1::HostPortBinding {
            host_port: u32::from(binding.host_port),
            guest_port: u32::from(binding.guest_port),
        })
        .collect();
    let mesh = resolve_native_mesh_attachment(
        &paths,
        &env,
        &name,
        &project,
        args.network.as_deref(),
        args.no_network,
        args.yes,
    )?;
    let mut credentials = connect_native_credential_authority_if_required(
        native_project_requires_credential_authority(&project.spec),
        connect_local_credential_authority,
    )
    .await?;
    let selected = sources::resolve_requested_sources(
        globals,
        &paths,
        &env,
        credentials.as_mut(),
        &mut project.spec,
        sources::SourceChanges::all(),
    )
    .await?;
    if native_project_requires_credential_authority(&project.spec) {
        sources::confirm_create_sources(&name, &project.spec, &selected, args.yes, args.output)?;
    }
    if project
        .local_mounts
        .iter()
        .any(|mount| mount.mode == v1::LocalMountMode::Copy as i32)
    {
        eprintln!(
            "Warning: copy mounts expose every selected file to the guest, including credentials deliberately stored beneath a selected source."
        );
    }
    let direct_mounts = project
        .local_mounts
        .iter()
        .filter(|mount| mount.mode == v1::LocalMountMode::Direct as i32)
        .collect::<Vec<_>>();
    if !direct_mounts.is_empty() {
        let write_warning = if direct_mounts
            .iter()
            .any(|mount| mount.read_only == Some(false))
        {
            " Read-write grants let guest root modify or delete that host content."
        } else {
            ""
        };
        eprintln!(
            "Warning: direct mounts let guest root inspect every file beneath each selected host directory.{write_warning} The explicit mode: direct and read_only choice acknowledges this grant."
        );
    }
    let NativeProjectPlan {
        spec, local_mounts, ..
    } = project;
    let (project_spec_json, project_spec_sha256) =
        canonical_native_project_intent(spec, vcpus, memory_mib, disk_bytes)?;
    let mut client = native_client().await?;
    let request = v1::CreateEnvironmentRequest {
        name,
        source_path: request_source_path,
        vcpus,
        memory_mib,
        disk_bytes,
        docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json,
        project_spec_sha256,
        implicit_path_mode,
        host_ports,
        mesh,
        access_profile_id: selected
            .profile
            .as_ref()
            .map(|profile| profile.id.clone())
            .unwrap_or_default(),
        access_profile_revision: selected
            .profile
            .as_ref()
            .map(|profile| profile.revision)
            .unwrap_or_default(),
        access_profile_reference: selected
            .profile
            .as_ref()
            .map(|profile| profile.reference.clone())
            .unwrap_or_default(),
        platform_source_authority: selected.platform,
        local_mounts,
    };
    let environment = client
        .create(request.clone())
        .await
        .map_err(native_status)?;
    sources::validate_created_environment(&environment, &request)?;
    Ok(environment)
}

pub(crate) async fn native_environments() -> anyhow::Result<Vec<v1::Environment>> {
    if !native_state_exists()? {
        return Ok(Vec::new());
    }
    let mut client = native_client().await?;
    let first = client.list().await;
    retry_native_rpc_after_authority_unavailable(
        first,
        || client.list(),
        connect_native_credential_authority,
    )
    .await
}

pub(crate) async fn handle_native_environment_update(
    globals: &Globals,
    args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    sources::validate_update_args(&args)?;
    let mut supervisor = native_client().await?;
    let environment = supervisor
        .get(&args.environment)
        .await
        .map_err(native_status)?;
    let current = sources::project_from_environment(&environment)?;
    let mut target = sources::patch_sources(&current, &args);
    let mut credentials = connect_native_credential_authority_if_required(
        native_project_requires_credential_authority(&current)
            || native_project_requires_credential_authority(&target),
        connect_local_credential_authority,
    )
    .await?;
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let resolved = sources::resolve_requested_sources(
        globals,
        &paths,
        &env,
        credentials.as_mut(),
        &mut target,
        sources::SourceChanges::update(&args),
    )
    .await?;
    let profile = if args.clear_profile {
        None
    } else if args.profile.is_some() {
        resolved.profile
    } else {
        sources::profile_from_environment(&environment)
    };
    let platform = sources::select_platform_authority(
        environment.platform_source_authority.as_ref(),
        resolved.platform,
        sources::retained_platform_source(&current, &args),
        &target,
        profile.as_ref(),
    )?;
    let request =
        sources::update_request(&environment, &target, profile.as_ref(), platform.as_ref())?;
    sources::confirm_update_sources(
        &environment,
        &current,
        &target,
        profile.as_ref(),
        platform.as_ref(),
        request.allow_restart,
        &args,
    )?;
    let request_id = request.request_id.clone();
    // The supervisor client follows its existing durable operation. A failed
    // exact CAS is returned once, never refetched or submitted with new inputs.
    let operation = supervisor
        .update_environment_sources(request)
        .await
        .map_err(native_status)
        .context("update native sources; conflicts require a fresh exact preview")?;
    anyhow::ensure!(
        operation.request_id == request_id
            && operation.environment_id == environment.id
            && operation.phase == v1::OperationPhase::Completed as i32,
        "native source update returned an unexpected or incomplete operation"
    );
    let updated = supervisor
        .get(&environment.name)
        .await
        .map_err(native_status)?;
    anyhow::ensure!(
        updated.id == environment.id,
        "native environment identity changed after the source operation"
    );
    print_native_environment(&updated, args.output)
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
        .find(|environment| match uuid::Uuid::parse_str(name) {
            Ok(id) => environment.id == id.to_string(),
            Err(_) => environment.name == name,
        }))
}

pub(crate) async fn native_selected_environment() -> anyhow::Result<Option<v1::Environment>> {
    Ok(native_environments()
        .await?
        .into_iter()
        .find(|environment| environment.selected))
}

pub(crate) async fn get_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    get_native_environment_with_authority_recovery(&mut client, name).await
}

pub(crate) async fn select_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    client
        .select(&environment.name, &environment.id)
        .await
        .map_err(native_status)
}

pub(crate) async fn start_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    get_native_environment_with_required_authority(&mut client, name).await?;
    client.start(name).await.map_err(native_status)
}

pub(crate) async fn stop_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    client.stop(&environment.name).await.map_err(native_status)
}

pub(crate) async fn restart_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    let environment = get_native_environment_with_required_authority(&mut client, name).await?;
    client
        .restart(name, &environment.id)
        .await
        .map_err(native_status)
}

pub(crate) async fn refresh_native_environment_skills(
    name: &str,
) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    get_native_environment_with_required_authority(&mut client, name).await?;
    client.refresh_skills(name).await.map_err(native_status)
}

pub(crate) async fn resize_native_environment(
    name: &str,
    vcpus: u32,
    memory_mib: u32,
    disk_bytes: u64,
) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    get_native_environment_with_required_authority(&mut client, name).await?;
    client
        .resize(name, vcpus, memory_mib, disk_bytes)
        .await
        .map_err(native_status)
}

async fn get_native_environment_with_authority_recovery(
    client: &mut NativeSupervisorClient,
    name: &str,
) -> anyhow::Result<v1::Environment> {
    let first = client.get(name).await;
    retry_native_rpc_after_authority_unavailable(
        first,
        || client.get(name),
        connect_native_credential_authority,
    )
    .await
}

fn native_rpc_requires_credential_authority_retry(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::Unavailable
        && status.message() == NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE
}

async fn retry_native_rpc_after_authority_unavailable<T, R, RF, A, AF>(
    first: Result<T, tonic::Status>,
    retry: R,
    connect_authority: A,
) -> anyhow::Result<T>
where
    R: FnOnce() -> RF,
    RF: Future<Output = Result<T, tonic::Status>>,
    A: FnOnce() -> AF,
    AF: Future<Output = anyhow::Result<()>>,
{
    match first {
        Ok(value) => Ok(value),
        Err(status) if native_rpc_requires_credential_authority_retry(&status) => {
            connect_authority().await?;
            retry().await.map_err(native_status)
        }
        Err(status) => Err(native_status(status)),
    }
}

async fn connect_native_credential_authority() -> anyhow::Result<()> {
    drop(connect_local_credential_authority().await?);
    Ok(())
}

async fn get_native_environment_with_required_authority(
    client: &mut NativeSupervisorClient,
    name: &str,
) -> anyhow::Result<v1::Environment> {
    let expected_id = uuid::Uuid::parse_str(name).ok().map(|id| id.to_string());
    let lookup_name = if let Some(expected_id) = &expected_id {
        let listed = client.list().await.map_err(native_status)?;
        native_environment_name_for_id(&listed, expected_id)?.to_owned()
    } else {
        name.to_owned()
    };
    let environment = get_native_environment_with_authority_recovery(client, &lookup_name).await?;
    if expected_id.as_ref().is_some_and(|id| environment.id != *id) {
        anyhow::bail!("native environment identity changed before the operation");
    }
    ensure_native_credential_authority(&environment).await?;
    Ok(environment)
}

fn native_environment_name_for_id<'a>(
    environments: &'a [v1::Environment],
    expected_id: &str,
) -> anyhow::Result<&'a str> {
    environments
        .iter()
        .find(|environment| environment.id == expected_id)
        .map(|environment| environment.name.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "native environment {expected_id} no longer exists; a reused name cannot replace it"
            )
        })
}

/// Managed guests use a selected typed proxy, never the host agent's login.
pub(crate) async fn require_native_agent_profile(
    environment_id: &str,
    provider: &str,
) -> anyhow::Result<()> {
    let environment_id = uuid::Uuid::parse_str(environment_id)?.to_string();
    let environment = native_environments()
        .await?
        .into_iter()
        .find(|environment| environment.id == environment_id)
        .context("the managed native environment no longer exists")?;
    let spec = sources::project_from_environment(&environment)?;
    let selected = spec
        .credentials
        .context("managed VM agents require a selected local credential profile")?;
    if selected.profile.starts_with("platform:") {
        anyhow::bail!("managed native agents currently require a local credential profile");
    }
    let profile_id = codewire_access::AccessProfileId::parse(environment.access_profile_id)?;
    let mut credentials = connect_local_credential_authority().await?;
    let bound = credentials
        .get_profile_revision(&profile_id, environment.access_profile_revision)
        .await?;
    if !bound
        .profile
        .entries
        .keys()
        .any(|slot| slot.as_str() == provider)
    {
        anyhow::bail!(
            "the native environment's selected credential profile has no {provider} provider"
        );
    }
    Ok(())
}

pub(crate) async fn delete_native_environment(
    name: &str,
) -> anyhow::Result<v1::DeleteEnvironmentResponse> {
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    if !environment.access_profile.is_empty() {
        connect_native_credential_authority().await?;
    }
    client
        .delete(&environment.name)
        .await
        .map_err(native_status)
}

pub(crate) async fn handle_native_environment_access(args: EnvAccessArgs) -> anyhow::Result<()> {
    let name = args
        .environment
        .as_deref()
        .and_then(trimmed_str)
        .ok_or_else(|| anyhow::anyhow!("environment name is required"))?;
    let mut credentials = connect_local_credential_authority().await?;
    let environment = native_client()
        .await?
        .get(name)
        .await
        .map_err(native_status)?;
    let view = inspect_native_environment_access(&environment, &mut credentials).await?;
    print_native_environment_access(&view, args.output)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct NativeEnvironmentAccessView {
    pub(crate) environment: String,
    pub(crate) environment_id: String,
    pub(crate) placement: String,
    pub(crate) profile: Option<String>,
    pub(crate) bound_revision: Option<u64>,
    pub(crate) current_revision: Option<u64>,
    pub(crate) update_available: bool,
}

async fn inspect_native_environment_access(
    environment: &v1::Environment,
    credentials: &mut LocalCredentialClient,
) -> anyhow::Result<NativeEnvironmentAccessView> {
    let spec = sources::project_from_environment(environment)?;
    let environment_id = EnvironmentId::parse(environment.id.clone())
        .map_err(|_| anyhow::anyhow!("native environment returned an invalid ID"))?;
    if spec.credentials.is_none() {
        if environment.access_profile_revision != 0 {
            anyhow::bail!("native environment access metadata is inconsistent");
        }
        match credentials
            .get_environment_access_binding(&environment_id)
            .await
        {
            Err(status) if status.code() == tonic::Code::NotFound => {}
            Ok(_) => anyhow::bail!("native environment access metadata is inconsistent"),
            Err(status) => {
                return Err(native_status(status)).context("read local environment access binding");
            }
        }
        return Ok(NativeEnvironmentAccessView {
            environment: environment.name.clone(),
            environment_id: environment.id.clone(),
            placement: "local".to_owned(),
            profile: None,
            bound_revision: None,
            current_revision: None,
            update_available: false,
        });
    }
    if environment.access_profile_revision == 0 {
        anyhow::bail!("native environment access metadata is inconsistent");
    }
    let reference = environment
        .access_profile
        .parse::<AccessProfileReference>()
        .map_err(|_| anyhow::anyhow!("native environment access metadata is inconsistent"))?;
    let id = codewire_access::AccessProfileId::parse(environment.access_profile_id.clone())
        .context("native profile ID metadata is invalid")?;
    if spec
        .credentials
        .as_ref()
        .is_some_and(|binding| binding.profile.starts_with("platform:"))
    {
        // The exact pin is inspectable without refreshing current platform
        // credentials or substituting a profile from another current account.
        return Ok(NativeEnvironmentAccessView {
            environment: environment.name.clone(),
            environment_id: environment.id.clone(),
            placement: "local".to_owned(),
            profile: spec.credentials.map(|binding| binding.profile),
            bound_revision: Some(environment.access_profile_revision),
            current_revision: None,
            update_available: false,
        });
    }
    let current = credentials
        .get_profile(&id)
        .await
        .context("resolve bound local access profile")?;
    let binding = credentials
        .get_environment_access_binding(&environment_id)
        .await
        .context("read local environment access binding")?;
    if binding.binding.profile_id != id
        || current.profile.id != id
        || binding.binding.profile_revision != environment.access_profile_revision
    {
        anyhow::bail!("native environment access binding does not match supervisor state");
    }
    let bound = credentials
        .get_profile_revision(&current.profile.id, environment.access_profile_revision)
        .await
        .context("read bound local access profile revision")?;
    if bound.profile.name != *reference.name()
        || current.profile.revision < environment.access_profile_revision
    {
        anyhow::bail!("native environment access profile history is inconsistent");
    }
    Ok(NativeEnvironmentAccessView {
        environment: environment.name.clone(),
        environment_id: environment.id.clone(),
        placement: "local".to_owned(),
        profile: spec.credentials.map(|binding| binding.profile),
        bound_revision: Some(environment.access_profile_revision),
        current_revision: Some(current.profile.revision),
        update_available: current.profile.revision > environment.access_profile_revision,
    })
}

pub(crate) fn print_native_environment_access(
    view: &NativeEnvironmentAccessView,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(view)?),
        OutputFormat::Text => print!("{}", format_native_environment_access(view)),
    }
    Ok(())
}

pub(crate) fn format_native_environment_access(view: &NativeEnvironmentAccessView) -> String {
    match (
        view.profile.as_deref(),
        view.bound_revision,
        view.current_revision,
    ) {
        (Some(profile), Some(bound), Some(current)) => format!(
            "Environment:      {}\nPlacement:        local\nAccess profile:   {profile}\nBound revision:   {bound}\nCurrent revision: {current}\nUpdate available: {}\n",
            view.environment,
            if view.update_available { "yes" } else { "no" }
        ),
        (Some(profile), Some(bound), None) => format!(
            "Environment:      {}\nPlacement:        local\nCredential profile: {profile}\nBound revision:   {bound}\nCurrent revision: not queried\n",
            view.environment
        ),
        _ => format!(
            "Environment:    {}\nPlacement:      local\nAccess profile: none\n",
            view.environment
        ),
    }
}

fn native_project_requires_credential_authority(spec: &codewire_project::ProjectSpec) -> bool {
    spec.credentials.is_some() || !spec.secrets.is_empty()
}

async fn connect_native_credential_authority_if_required<T, C, CF>(
    required: bool,
    connect: C,
) -> anyhow::Result<Option<T>>
where
    C: FnOnce() -> CF,
    CF: Future<Output = anyhow::Result<T>>,
{
    if required {
        return connect().await.map(Some);
    }
    Ok(None)
}

async fn ensure_native_credential_authority(environment: &v1::Environment) -> anyhow::Result<()> {
    drop(
        connect_native_credential_authority_if_required(
            environment.requires_credential_authority,
            connect_local_credential_authority,
        )
        .await?,
    );
    Ok(())
}

pub(crate) async fn native_environment_session_client(
    name: &str,
) -> anyhow::Result<codewire_local_vmm::public_client::NativePublicSessionClient> {
    let mut supervisor = native_client().await?;
    get_native_environment_with_required_authority(&mut supervisor, name).await?;
    drop(supervisor);
    codewire_local_vmm::public_client::NativePublicSessionClient::connect_or_start(
        &native_runtime_config()?,
        name,
    )
    .await
    .map_err(anyhow::Error::from)
}

pub(crate) async fn native_environment_data_client(
    name: &str,
) -> anyhow::Result<codewire_local_vmm::public_client::NativePublicDataClient> {
    let mut supervisor = native_client().await?;
    get_native_environment_with_required_authority(&mut supervisor, name).await?;
    drop(supervisor);
    codewire_local_vmm::public_client::NativePublicDataClient::connect_or_start(
        &native_runtime_config()?,
        name,
    )
    .await
    .map_err(anyhow::Error::from)
}

pub(crate) async fn native_environment_managed_runtime(
    environment_id: &str,
) -> anyhow::Result<codewire_local_vmm::artifact::CwRuntimeProvenance> {
    let mut supervisor = native_client().await?;
    let environment =
        get_native_environment_with_required_authority(&mut supervisor, environment_id).await?;
    let runtime = supervisor
        .managed_runtime(&environment.name, &environment.id)
        .await
        .map_err(native_status)?;
    if runtime.environment_id != environment_id || runtime.artifact_generation.len() != 64 {
        anyhow::bail!("managed runtime does not match the selected environment");
    }
    codewire_local_vmm::artifact::CwRuntimeProvenance::decode(&runtime.provenance_json)
        .map_err(anyhow::Error::msg)
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
    let view = NativeEnvironmentView::try_from(environment)?;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) docker_disk: Option<String>,
    pub(crate) workspace_plan: String,
    pub(crate) workspace_inputs: u32,
    pub(crate) working_directory: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) skill_snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skill_snapshot_generation: Option<u64>,
    pub(crate) skill_count: u32,
    pub(crate) ports: Vec<NativeHostPortView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) access_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) access_profile_revision: Option<u64>,
    pub(crate) generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_selection: Option<sources::SourceView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeHostPortView {
    pub(crate) listen: String,
    pub(crate) guest_port: u32,
}

impl TryFrom<&v1::Environment> for NativeEnvironmentView {
    type Error = anyhow::Error;

    fn try_from(environment: &v1::Environment) -> anyhow::Result<Self> {
        Ok(Self {
            id: environment.id.clone(),
            name: environment.name.clone(),
            backend: "cloud-hypervisor".to_owned(),
            state: native_state_label(environment.state).to_owned(),
            selected: environment.selected,
            cpu: environment.vcpus,
            memory: format_binary_mib(environment.memory_mib),
            disk: format_binary_bytes(environment.disk_bytes),
            docker_disk: (environment.docker_disk_bytes != 0)
                .then(|| format_binary_bytes(environment.docker_disk_bytes)),
            workspace_plan: environment.workspace_plan_sha256.clone(),
            workspace_inputs: environment.workspace_input_count,
            working_directory: environment.working_directory.clone(),
            skill_snapshot: environment.skill_snapshot_sha256.clone(),
            skill_snapshot_generation: (environment.skill_snapshot_generation > 0)
                .then_some(environment.skill_snapshot_generation),
            skill_count: environment.skill_snapshot_count,
            ports: environment
                .host_ports
                .iter()
                .map(|binding| NativeHostPortView {
                    listen: format!("127.0.0.1:{}", binding.host_port),
                    guest_port: binding.guest_port,
                })
                .collect(),
            network: environment
                .mesh
                .as_ref()
                .and_then(|mesh| trimmed_str(&mesh.network_id))
                .map(str::to_owned),
            error_code: trimmed_str(&environment.error_code).map(str::to_owned),
            access_profile: environment.access_profile.clone(),
            access_profile_revision: (!environment.access_profile.is_empty()
                && environment.access_profile_revision > 0)
                .then_some(environment.access_profile_revision),
            generation: environment.generation,
            source_selection: sources::source_view(environment)?,
        })
    }
}

fn format_native_environment(view: &NativeEnvironmentView) -> String {
    let access = match (&view.access_profile, view.access_profile_revision) {
        (profile, Some(revision)) if !profile.is_empty() => {
            format!("{profile} (revision {revision})")
        }
        _ => "none".to_owned(),
    };
    let mut output = format!(
        "Environment: {}\nBackend:     {}\nState:       {}\nCPU:         {}\nMemory:      {}\nDisk:        {}\nWorkspace:   {} input(s), plan {}\nWorking dir: {}\nAccess:      {}\n",
        view.name,
        view.backend,
        view.state,
        view.cpu,
        view.memory,
        view.disk,
        view.workspace_inputs,
        view.workspace_plan,
        view.working_directory,
        access,
    );
    output.push_str(&format!(
        "Docker:      {}\n",
        view.docker_disk.as_deref().unwrap_or("disabled")
    ));
    if let Some(generation) = view.skill_snapshot_generation {
        output.push_str(&format!(
            "Skills:      {} snapshot(s), generation {}, plan {}\n",
            view.skill_count, generation, view.skill_snapshot
        ));
    }
    for port in &view.ports {
        output.push_str(&format!(
            "Port:        {} -> {}\n",
            port.listen, port.guest_port
        ));
    }
    if let Some(network) = &view.network {
        output.push_str(&format!("Network:     {network}\n"));
    }
    if let Some(error_code) = &view.error_code {
        output.push_str(&format!("Error:       {error_code}\n"));
    }
    output.push_str(&format!("Generation:  {}\n", view.generation));
    output.push_str(&sources::format_source_view(view.source_selection.as_ref()));
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
    connect_native_after_authority_admission(
        || async {
            // Admit an authority visible at the current credential root before
            // an existing supervisor can be reused. A live v6 authority is
            // replaced with v7, an unconnectable existing endpoint fails
            // closed, and only an absent endpoint avoids starting an authority
            // for credential-free native operations.
            admit_existing_local_credential_authority().await
        },
        || async {
            NativeSupervisorClient::connect_or_start(&config)
                .await
                .context("connect to native local supervisor")
        },
    )
    .await
}

async fn connect_native_after_authority_admission<T, A, AF, C, CF>(
    admit_authority: A,
    connect_supervisor: C,
) -> anyhow::Result<T>
where
    A: FnOnce() -> AF,
    AF: std::future::Future<Output = anyhow::Result<()>>,
    C: FnOnce() -> CF,
    CF: std::future::Future<Output = anyhow::Result<T>>,
{
    admit_authority().await?;
    connect_supervisor().await
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
        mesh_data_dir: paths.mesh_data_dir,
        platform_config_dir: paths.platform_config_dir,
        credential_authority_root: local_credential_root(&env)?,
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
    local_mounts: Vec<v1::LocalMountInput>,
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
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && requested_file.is_none() => {
            return Ok(NativeProjectPlan::default());
        }
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    use std::io::Read as _;
    let mut data = String::new();
    file.take((codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1) as u64)
        .read_to_string(&mut data)
        .with_context(|| format!("read {}", path.display()))?;
    let document = codewire_project::parse_project_yaml(&data)
        .with_context(|| format!("parse {}", path.display()))?;
    let unsupported = native_unsupported_project_fields(&document);
    if !unsupported.is_empty() {
        anyhow::bail!(
            "native local preview does not yet support codewire.yaml fields: {}",
            unsupported.join(", ")
        );
    }
    let config_directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native codewire.yaml has no parent directory"))?;
    let local_mounts = resolve_native_local_mounts(config_directory, &document.local.mounts)?;
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
        local_mounts,
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
    if spec.repositories.is_empty()
        && document.local.mounts.is_empty()
        && spec.working_directory != "/workspace"
    {
        unsupported.push("working_directory");
    }
    if spec.agents.install == Some(true) {
        unsupported.push("agents");
    }
    unsupported
}

fn apply_native_setup_overrides(
    spec: &mut codewire_project::ProjectSpec,
    install: Option<&str>,
    startup: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(install) = install {
        spec.install_command = install.trim().to_owned();
    }
    if let Some(startup) = startup {
        spec.startup_script = startup.trim().to_owned();
    }
    spec.validate().context("validate native project setup")
}

fn resolve_native_local_mounts(
    config_directory: &Path,
    mounts: &[codewire_project::LocalMountIntent],
) -> anyhow::Result<Vec<v1::LocalMountInput>> {
    mounts
        .iter()
        .map(|mount| {
            match mount.mode {
                codewire_project::LocalMountMode::Copy if mount.read_only.is_none() => {}
                codewire_project::LocalMountMode::Direct if mount.read_only.is_some() => {}
                codewire_project::LocalMountMode::Copy => {
                    anyhow::bail!("copy mounts cannot carry read_only");
                }
                codewire_project::LocalMountMode::Direct => {
                    anyhow::bail!("direct mounts require read_only: true or false");
                }
            }
            let requested = Path::new(&mount.source);
            let requested = if requested.is_absolute() {
                requested.to_owned()
            } else {
                config_directory.join(requested)
            };
            let source = std::fs::canonicalize(&requested)
                .with_context(|| format!("resolve copy mount source {}", requested.display()))?;
            let metadata = std::fs::metadata(&source)
                .with_context(|| format!("inspect copy mount source {}", source.display()))?;
            if source == Path::new("/") || !metadata.is_dir() {
                anyhow::bail!(
                    "copy mount source must be a directory other than the host root: {}",
                    source.display()
                );
            }
            Ok(v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: mount.destination.clone(),
                mode: match mount.mode {
                    codewire_project::LocalMountMode::Copy => v1::LocalMountMode::Copy as i32,
                    codewire_project::LocalMountMode::Direct => v1::LocalMountMode::Direct as i32,
                },
                read_only: mount.read_only,
            })
        })
        .collect()
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
    spec.image = canonical_native_workspace_image(&spec.image)?;
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

fn canonical_native_workspace_image(image: &str) -> anyhow::Result<String> {
    let image = trimmed_str(image)
        .map(expand_image_ref)
        .unwrap_or_else(|| CANONICAL_WORKSPACE_IMAGE.to_owned());
    RegistryReference::parse(&image).context("parse native OCI workspace image")?;
    Ok(image)
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
    local_mounts: &[v1::LocalMountInput],
    requested_mode: Option<PathModeArg>,
) -> anyhow::Result<(String, String)> {
    if !spec.repositories.is_empty() || !local_mounts.is_empty() {
        if requested_mode.is_some() {
            anyhow::bail!(
                "--path-mode applies only when codewire.yaml has no repositories or mounts"
            );
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
    if args.coding_agent.is_some() {
        unsupported.push("--coding-agent");
    }
    if !args.env.is_empty() {
        unsupported.push("--env");
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
    let memory_mib = if let Some(amount) = strip_ascii_case_suffix(value, &["gib", "gi", "gb"]) {
        amount
            .parse::<u32>()
            .context("invalid native memory quantity")?
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("native memory quantity is too large"))?
    } else if let Some(amount) = strip_ascii_case_suffix(value, &["mib", "mi", "mb"]) {
        amount
            .parse::<u32>()
            .context("invalid native memory quantity")?
    } else {
        value.parse::<u32>().with_context(|| {
            format!("invalid native memory quantity {value:?}; use 512MB or 8GB")
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
    let gib = if let Some(amount) = strip_ascii_case_suffix(value, &["mib", "mi", "mb"]) {
        let mib = amount.parse::<u64>().with_context(|| {
            format!("invalid native disk quantity {value:?}; use a value such as 40GB")
        })?;
        if !mib.is_multiple_of(1024) {
            anyhow::bail!("native disk quantity must resolve to a whole GB");
        }
        mib / 1024
    } else {
        strip_ascii_case_suffix(value, &["gib", "gi", "gb"])
            .unwrap_or(value)
            .parse::<u64>()
            .with_context(|| {
                format!("invalid native disk quantity {value:?}; use a value such as 40GB")
            })?
    };
    let bytes = gib
        .checked_mul(GIB)
        .ok_or_else(|| anyhow::anyhow!("native disk quantity is too large"))?;
    if !(1..=1024).contains(&gib) {
        anyhow::bail!("native disk must be from 1Gi through 1024Gi");
    }
    Ok(bytes)
}

fn strip_ascii_case_suffix<'a>(value: &'a str, suffixes: &[&str]) -> Option<&'a str> {
    let lowercase = value.to_ascii_lowercase();
    suffixes
        .iter()
        .find(|suffix| lowercase.ends_with(**suffix))
        .map(|suffix| &value[..value.len() - suffix.len()])
}

fn native_status(status: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!(status.message().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_id_lookup_resolves_the_private_name_without_following_a_uuid_shaped_name() {
        let expected_id = "8fc6e44a-047a-4e65-8e56-26df709fee44";
        let environments = [
            v1::Environment {
                id: "d52a6f57-0f19-4b8c-b89b-b941abfc90b3".to_owned(),
                name: expected_id.to_owned(),
                ..Default::default()
            },
            v1::Environment {
                id: expected_id.to_owned(),
                name: "native-team".to_owned(),
                ..Default::default()
            },
        ];
        assert_eq!(
            native_environment_name_for_id(&environments, expected_id).unwrap(),
            "native-team"
        );
        let error = native_environment_name_for_id(&environments[..1], expected_id).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a reused name cannot replace it")
        );
    }

    #[tokio::test]
    async fn native_rpc_authority_recovery_is_exact_and_bounded() {
        let authority_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let retry_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let success_retry_calls = std::sync::Arc::clone(&retry_calls);
        let success_authority_calls = std::sync::Arc::clone(&authority_calls);
        let value = retry_native_rpc_after_authority_unavailable(
            Ok(7_u8),
            move || async move {
                success_retry_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(8)
            },
            move || async move {
                success_authority_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(authority_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(retry_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let exact_retry_calls = std::sync::Arc::clone(&retry_calls);
        let exact_authority_calls = std::sync::Arc::clone(&authority_calls);
        let value = retry_native_rpc_after_authority_unavailable(
            Err(tonic::Status::unavailable(
                NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE,
            )),
            move || async move {
                exact_retry_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(9_u8)
            },
            move || async move {
                exact_authority_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 9);
        assert_eq!(authority_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(retry_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let unrelated_retry_calls = std::sync::Arc::clone(&retry_calls);
        let unrelated_authority_calls = std::sync::Arc::clone(&authority_calls);
        let error = retry_native_rpc_after_authority_unavailable(
            Err::<u8, _>(tonic::Status::unavailable("supervisor transport failed")),
            move || async move {
                unrelated_retry_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(10)
            },
            move || async move {
                unrelated_authority_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "supervisor transport failed");
        assert_eq!(authority_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(retry_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let bounded_retry_calls = std::sync::Arc::clone(&retry_calls);
        let bounded_authority_calls = std::sync::Arc::clone(&authority_calls);
        let error = retry_native_rpc_after_authority_unavailable(
            Err::<u8, _>(tonic::Status::unavailable(
                NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE,
            )),
            move || async move {
                bounded_retry_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(tonic::Status::unavailable(
                    NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE,
                ))
            },
            move || async move {
                bounded_authority_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE);
        assert_eq!(authority_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(retry_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn native_project_authority_requirement_covers_selected_secrets_and_credentials_only() {
        let mut spec = codewire_project::ProjectSpec::default();
        spec.environment
            .insert("PUBLIC_VALUE".to_owned(), "ordinary-value".to_owned());
        assert!(!native_project_requires_credential_authority(&spec));

        spec.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:user/work".to_owned(),
        });
        assert!(native_project_requires_credential_authority(&spec));

        for secrets in [
            codewire_project::SecretBindings {
                organization: true,
                ..Default::default()
            },
            codewire_project::SecretBindings {
                project: "project-alpha".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
        ] {
            let spec = codewire_project::ProjectSpec {
                secrets,
                ..Default::default()
            };
            assert!(native_project_requires_credential_authority(&spec));
        }
    }

    #[tokio::test]
    async fn required_native_authority_connection_is_conditional_and_fail_closed() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let skipped_calls = std::sync::Arc::clone(&calls);
        let skipped = connect_native_credential_authority_if_required(false, || async move {
            skipped_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, anyhow::Error>(7_u8)
        })
        .await
        .unwrap();
        assert_eq!(skipped, None);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let required_calls = std::sync::Arc::clone(&calls);
        let connected = connect_native_credential_authority_if_required(true, || async move {
            required_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, anyhow::Error>(7_u8)
        })
        .await
        .unwrap();
        assert_eq!(connected, Some(7));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let error = connect_native_credential_authority_if_required(true, || async {
            Err::<u8, _>(anyhow::anyhow!("authority unavailable"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "authority unavailable");
    }

    #[tokio::test]
    async fn authority_admission_precedes_native_supervisor_reuse() {
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let authority_order = std::sync::Arc::clone(&order);
        let supervisor_order = std::sync::Arc::clone(&order);
        let result = connect_native_after_authority_admission(
            || async move {
                authority_order.lock().unwrap().push("authority");
                Ok(())
            },
            || async move {
                supervisor_order.lock().unwrap().push("supervisor");
                Ok(7_u8)
            },
        )
        .await
        .unwrap();
        assert_eq!(result, 7);
        assert_eq!(*order.lock().unwrap(), ["authority", "supervisor"]);

        let supervisor_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = std::sync::Arc::clone(&supervisor_called);
        let error = connect_native_after_authority_admission(
            || async { anyhow::bail!("authority protocol rejected") },
            || async move {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "authority protocol rejected");
        assert!(!supervisor_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn native_resource_quantities_match_the_canonical_command() {
        assert_eq!(parse_native_cpu("2").unwrap(), 2);
        assert_eq!(parse_native_memory("16gi").unwrap(), 16 * 1024);
        assert_eq!(parse_native_memory("16gb").unwrap(), 16 * 1024);
        assert_eq!(parse_native_memory("1024mb").unwrap(), 1024);
        assert_eq!(parse_native_memory("2048mb").unwrap(), 2048);
        assert_eq!(parse_native_memory("8GB").unwrap(), 8 * 1024);
        assert_eq!(parse_native_memory("8GiB").unwrap(), 8 * 1024);
        assert_eq!(parse_native_disk("40gb").unwrap(), 40 * 1024 * 1024 * 1024);
        assert_eq!(parse_native_disk("2048mb").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_native_disk("40GB").unwrap(), 40 * 1024 * 1024 * 1024);
        assert_eq!(parse_native_disk("40GiB").unwrap(), 40 * 1024 * 1024 * 1024);
    }

    #[test]
    fn native_mesh_attachment_uses_only_the_public_owner_projection() {
        let root = tempfile::tempdir().unwrap();
        let mesh_data_dir = root.path().join("mesh");
        let paths = ResolvePaths {
            mesh_data_dir: mesh_data_dir.clone(),
            platform_config_dir: root.path().join("unused-platform"),
        };
        let runtime = LocalMeshRuntime {
            pid: std::process::id(),
            base_url: "http://127.0.0.1:18090".to_owned(),
            listen_addr: "127.0.0.1:18090".to_owned(),
            binary: "codewire-mesh".to_owned(),
            log_path: root.path().join("mesh.log").display().to_string(),
            started_at: "2026-09-02T00:00:00Z".to_owned(),
            derp: None,
        };
        save_local_mesh_runtime(&mesh_data_dir, &runtime).unwrap();
        save_local_mesh_owner_context(
            &mesh_data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                mesh_url: "http://127.0.0.1:18090".to_owned(),
                organization_id: "local-org-alpha".to_owned(),
                selected_network: Some("selected-network".to_owned()),
                auto_connect: false,
            },
        )
        .unwrap();
        // Native creation must not deserialize this credential-bearing file.
        std::fs::write(mesh_data_dir.join("config.toml"), "not valid toml = [").unwrap();
        let project = NativeProjectPlan {
            spec: codewire_project::parse_project_yaml("ports: [{port: 3001}, {port: 8080}]\n")
                .unwrap()
                .spec,
            ..NativeProjectPlan::default()
        };

        let explicit = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &project,
            Some("explicit-network"),
            false,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(explicit.mesh_url, "http://127.0.0.1:18090");
        assert_eq!(explicit.organization_id, "local-org-alpha");
        assert_eq!(explicit.network_id, "explicit-network");
        assert_eq!(explicit.node_name, "native-dev");
        assert_eq!(explicit.guest_ports, vec![3_001, 8_080]);
        assert_eq!(
            explicit.auth_source,
            v1::MeshEnrollmentAuthSource::StandaloneLocal as i32
        );

        let selected = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &project,
            None,
            false,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.network_id, "selected-network");

        let mut owner = load_local_mesh_owner_context(&mesh_data_dir)
            .unwrap()
            .unwrap();
        owner.auto_connect = true;
        save_local_mesh_owner_context(&mesh_data_dir, &owner).unwrap();
        let automatic = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &project,
            None,
            false,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(automatic.network_id, "selected-network");
    }

    #[test]
    fn native_mesh_attachment_honors_disable_and_requires_a_live_local_owner() {
        let root = tempfile::tempdir().unwrap();
        let paths = ResolvePaths {
            mesh_data_dir: root.path().join("missing-mesh"),
            platform_config_dir: root.path().join("unused-platform"),
        };
        let project = NativeProjectPlan::default();
        assert!(
            resolve_native_mesh_attachment(
                &paths,
                &config::MapEnv::default(),
                "native-dev",
                &project,
                None,
                true,
                true,
            )
            .unwrap()
            .is_none()
        );
        let error = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &project,
            Some("project-alpha"),
            false,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("run 'cw mesh up'"), "{error}");
        let conflict = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &project,
            Some("project-alpha"),
            true,
            true,
        )
        .unwrap_err();
        assert_eq!(
            conflict.to_string(),
            "--network and --no-network cannot be used together"
        );
    }

    #[test]
    fn native_hosted_mesh_attachment_uses_only_the_credential_free_projection() {
        let root = tempfile::tempdir().unwrap();
        let paths = ResolvePaths {
            mesh_data_dir: root.path().join("mesh"),
            platform_config_dir: root.path().join("missing-protected-platform-store"),
        };
        save_local_mesh_owner_context(
            &paths.mesh_data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::HostedCurrent,
                mesh_url: "https://mesh.codewire-dev.sh".to_owned(),
                organization_id: "org-hosted".to_owned(),
                selected_network: Some("project-alpha".to_owned()),
                auto_connect: true,
            },
        )
        .unwrap();

        let attachment = resolve_native_mesh_attachment(
            &paths,
            &config::MapEnv::default(),
            "native-dev",
            &NativeProjectPlan::default(),
            None,
            false,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(attachment.mesh_url, "https://mesh.codewire-dev.sh");
        assert_eq!(attachment.organization_id, "org-hosted");
        assert_eq!(attachment.network_id, "project-alpha");
        assert_eq!(attachment.node_name, "native-dev");
        assert_eq!(
            attachment.auth_source,
            v1::MeshEnrollmentAuthSource::HostedCurrent as i32
        );
    }

    #[tokio::test]
    async fn hosted_mesh_enrollment_uses_only_matching_fresh_saved_oauth() {
        use codewire_client::{CredentialStore as _, OAuthCredentials};
        use codewire_local_vmm::mesh_enrollment::{
            MeshEnrollmentAuthSource, MeshEnrollmentCredentialResolver as _,
        };
        use codewire_local_vmm::mesh_ingress::MeshAttachment;

        let root = tempfile::tempdir().unwrap();
        let mesh_data_dir = root.path().join("unused-missing-mesh-root");
        let platform_config_dir = root.path().join("platform");
        config::save_platform_config(
            &platform_config_dir,
            &config::PlatformConfig {
                server_url: "https://api.codewire-dev.sh".to_owned(),
                default_org: "org-hosted".to_owned(),
            },
        )
        .unwrap();
        let credentials = OAuthCredentials::new(
            "https://api.codewire-dev.sh",
            codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "synthetic-hosted-access",
            "synthetic-hosted-refresh",
            u64::MAX,
            codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .unwrap();
        codewire_client::FileCredentialStore::at(config::oauth_credentials_path(
            &platform_config_dir,
        ))
        .save(&credentials)
        .unwrap();
        let resolver = NativeMeshEnrollmentCredentials {
            paths: ResolvePaths {
                mesh_data_dir,
                platform_config_dir,
            },
        };
        let attachment = MeshAttachment::new_with_auth_source(
            MeshEnrollmentAuthSource::HostedCurrent,
            "https://mesh.codewire-dev.sh",
            "org-hosted",
            "network-hosted",
            "node-hosted",
            [3_000],
        )
        .unwrap();
        let token = resolver.resolve(&attachment).await.unwrap();
        assert_eq!(token.expose_secret(), "synthetic-hosted-access");

        let wrong_origin = MeshAttachment::new_with_auth_source(
            MeshEnrollmentAuthSource::HostedCurrent,
            "https://mesh.codewire.sh",
            "org-hosted",
            "network-hosted",
            "node-hosted",
            [3_000],
        )
        .unwrap();
        assert!(resolver.resolve(&wrong_origin).await.is_err());

        let wrong_organization = MeshAttachment::new_with_auth_source(
            MeshEnrollmentAuthSource::HostedCurrent,
            "https://mesh.codewire-dev.sh",
            "org-other",
            "network-hosted",
            "node-hosted",
            [3_000],
        )
        .unwrap();
        assert!(resolver.resolve(&wrong_organization).await.is_err());
    }

    #[test]
    fn native_yaml_accepts_the_shared_workspace_image_field() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("codewire.yaml"), "image: workspace\n").unwrap();
        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.spec.image, "workspace");
    }

    #[test]
    fn native_yaml_and_overrides_preserve_canonical_setup_commands() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "install_command: '  printf install  '\nstartup_script: '  printf startup  '\n",
        )
        .unwrap();
        let mut project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.spec.install_command, "printf install");
        assert_eq!(project.spec.startup_script, "printf startup");
        apply_native_setup_overrides(&mut project.spec, None, Some("  printf override  ")).unwrap();
        assert_eq!(project.spec.install_command, "printf install");
        assert_eq!(project.spec.startup_script, "printf override");
        let (bytes, digest) =
            canonical_native_project_intent(project.spec.clone(), 2, 4096, 20 * 1024 * 1024 * 1024)
                .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
        let persisted: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(persisted.install_command, "printf install");
        assert_eq!(persisted.startup_script, "printf override");
        apply_native_setup_overrides(&mut project.spec, Some("  "), Some("")).unwrap();
        assert!(project.spec.install_command.is_empty());
        assert!(project.spec.startup_script.is_empty());
    }

    #[test]
    fn native_setup_overrides_retain_shared_command_validation() {
        for (install, startup) in [
            (Some("command-canary\0".to_owned()), None),
            (None, Some("command-canary\0".to_owned())),
            (Some("x".repeat(64 * 1024 + 1)), None),
            (None, Some("x".repeat(64 * 1024 + 1))),
        ] {
            let error = apply_native_setup_overrides(
                &mut codewire_project::ProjectSpec::default(),
                install.as_deref(),
                startup.as_deref(),
            )
            .unwrap_err();
            assert!(!format!("{error:#}").contains("command-canary"));
        }
    }

    #[test]
    fn native_cli_admits_setup_flags_without_admitting_unrelated_options() {
        use clap::Parser as _;
        let cli = crate::Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "--local",
            "--install",
            "printf install",
            "--startup",
            "printf startup",
        ])
        .unwrap();
        let crate::Command::Env(EnvArgs {
            command: EnvCommand::Create(mut args),
            ..
        }) = cli.command
        else {
            panic!("expected environment creation");
        };
        reject_unsupported_native_create_options(&args).unwrap();
        args.ttl = Some("1h".to_owned());
        assert!(
            reject_unsupported_native_create_options(&args)
                .unwrap_err()
                .to_string()
                .contains("--ttl")
        );
    }

    #[test]
    fn native_yaml_uses_shared_resource_normalization() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "version: 1\ncpu: \"2000m\"\nmemory: \"8GB\"\ndisk: \"40GB\"\n",
        )
        .unwrap();
        let resources = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(resources.vcpus, Some(2));
        assert_eq!(resources.memory_mib, Some(8 * 1024));
        assert_eq!(resources.disk_bytes, Some(40 * 1024 * 1024 * 1024));
    }

    #[test]
    fn native_yaml_preserves_the_requested_credential_profile_until_metadata_resolution() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "version: 1\ncredentials: {profile: local:user/work}\n",
        )
        .unwrap();

        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(
            project.spec.credentials.as_ref().unwrap().profile,
            "local:user/work"
        );
    }

    #[test]
    fn native_yaml_preserves_workload_secret_selection_for_authority_resolution() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "version: 1\nenvironment: {EXPLICIT: wins}\nsecrets: {user: local, project: local:development}\n",
        )
        .unwrap();

        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.spec.secrets.project, "local:development");
        assert_eq!(
            project.spec.secrets.user,
            Some(codewire_project::StoragePlacement::Local)
        );
        assert_eq!(project.spec.environment["EXPLICIT"], "wins");
    }

    #[test]
    fn native_yaml_rejects_all_reserved_runtime_environment_keys() {
        let temp = tempfile::tempdir().unwrap();
        for key in codewire_project::RESERVED_RUNTIME_ENVIRONMENT_KEYS {
            std::fs::write(
                temp.path().join("codewire.yaml"),
                format!("environment: {{{key}: synthetic}}\n"),
            )
            .unwrap();
            let error = native_codewire_yaml(temp.path(), None).unwrap_err();
            assert!(
                format!("{error:#}")
                    .contains(&format!("{key} is reserved for Codewire runtime control")),
                "{error:#}"
            );
        }
    }

    #[test]
    fn native_yaml_resolves_copy_mounts_relative_to_the_config_file() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("config")).unwrap();
        let fixtures = temp.path().join("fixtures");
        std::fs::create_dir(&fixtures).unwrap();
        std::fs::write(
            temp.path().join("config/dev.yaml"),
            "mounts: [{source: ../fixtures, destination: /workspace/fixtures, mode: copy}]\n",
        )
        .unwrap();
        let project =
            native_codewire_yaml(temp.path(), Some(Path::new("config/dev.yaml"))).unwrap();
        assert_eq!(project.spec.working_directory, "/workspace/fixtures");
        assert_eq!(project.local_mounts.len(), 1);
        assert_eq!(
            project.local_mounts[0].source_path,
            fixtures.as_os_str().as_bytes()
        );
        assert_eq!(
            project.local_mounts[0].mode,
            v1::LocalMountMode::Copy as i32
        );
        assert_eq!(project.local_mounts[0].read_only, None);
        assert_eq!(
            native_workspace_request(temp.path(), &project.spec, &project.local_mounts, None,)
                .unwrap(),
            (String::new(), String::new())
        );
    }

    #[test]
    fn native_yaml_resolves_explicit_direct_mounts_without_an_implicit_workspace() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("fixtures")).unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "mounts: [{source: ./fixtures, destination: /workspace/fixtures, mode: direct, read_only: true}]\n",
        )
        .unwrap();
        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.local_mounts.len(), 1);
        assert_eq!(
            project.local_mounts[0].mode,
            v1::LocalMountMode::Direct as i32
        );
        assert_eq!(project.local_mounts[0].read_only, Some(true));
        assert_eq!(
            native_workspace_request(temp.path(), &project.spec, &project.local_mounts, None,)
                .unwrap(),
            (String::new(), String::new())
        );
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
            native_workspace_request(temp.path(), &project.spec, &project.local_mounts, None)
                .unwrap(),
            (String::new(), String::new())
        );
        let error = native_workspace_request(
            temp.path(),
            &project.spec,
            &project.local_mounts,
            Some(PathModeArg::Copy),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("codewire.yaml has no repositories or mounts"),
            "{error}"
        );
    }

    #[test]
    fn native_yaml_accepts_skill_projection_metadata_without_agent_installation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".agents/skills/rust")).unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "agents: {tools: [codex]}\nskills: [{source: repository, path: .agents/skills/rust}]\n",
        )
        .unwrap();
        let project = native_codewire_yaml(temp.path(), None).unwrap();
        assert_eq!(project.spec.agents.tools, vec!["codex"]);
        assert_eq!(project.spec.agents.install, None);
        assert_eq!(project.spec.skills.len(), 1);

        std::fs::write(
            temp.path().join("codewire.yaml"),
            "agents: {install: true, tools: [codex]}\nskills: [{source: repository, path: .agents/skills/rust}]\n",
        )
        .unwrap();
        let error = native_codewire_yaml(temp.path(), None).unwrap_err();
        assert!(error.to_string().contains("fields: agents"), "{error}");
    }

    #[test]
    fn native_yaml_keeps_port_intent_and_exact_loopback_publications() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "ports:\n  - port: 3000\n  - host_port: 18080\n    guest_port: 8080\n",
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
    fn native_project_intent_expands_and_validates_the_configured_image() {
        let spec = codewire_project::ProjectSpec {
            image: "ubuntu:24.04".to_owned(),
            ..codewire_project::ProjectSpec::default()
        };
        let (bytes, _) =
            canonical_native_project_intent(spec, 2, 4096, 20 * 1024 * 1024 * 1024).unwrap();
        let spec: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(spec.image, "docker.io/library/ubuntu:24.04");

        let invalid = codewire_project::ProjectSpec {
            image: "https://registry.example/workspace:latest".to_owned(),
            ..codewire_project::ProjectSpec::default()
        };
        let error =
            canonical_native_project_intent(invalid, 2, 4096, 20 * 1024 * 1024 * 1024).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("parse native OCI workspace image"),
            "{error}"
        );
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
    fn native_environment_view_reports_mesh_and_typed_runtime_failure() {
        let environment = v1::Environment {
            docker_disk_bytes: 8 * 1024 * 1024 * 1024,
            mesh: Some(v1::MeshAttachment {
                network_id: "mesh-dev".to_owned(),
                ..Default::default()
            }),
            state: v1::EnvironmentState::Error as i32,
            error_code: "mesh_transport_exit".to_owned(),
            ..Default::default()
        };

        let view = NativeEnvironmentView::try_from(&environment).unwrap();
        assert_eq!(view.network.as_deref(), Some("mesh-dev"));
        assert_eq!(view.error_code.as_deref(), Some("mesh_transport_exit"));
        assert_eq!(view.docker_disk.as_deref(), Some("8Gi"));
    }

    #[test]
    fn native_environment_view_omits_disabled_docker_disk_from_json() {
        let view = NativeEnvironmentView::try_from(&v1::Environment::default()).unwrap();

        let json = serde_json::to_value(view).expect("serialize native environment view");
        assert!(json.get("docker_disk").is_none());
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
            docker_disk: Some("8Gi".to_owned()),
            workspace_plan: "c".repeat(64),
            workspace_inputs: 1,
            working_directory: "/workspace".to_owned(),
            skill_snapshot: String::new(),
            skill_snapshot_generation: None,
            skill_count: 0,
            ports: vec![NativeHostPortView {
                listen: "127.0.0.1:18080".to_owned(),
                guest_port: 8_080,
            }],
            network: Some("mesh-dev".to_owned()),
            error_code: None,
            access_profile: "user/work".to_owned(),
            access_profile_revision: Some(2),
            generation: 7,
            source_selection: None,
        };

        let output = format_native_environment(&view);
        assert!(output.contains("Port:        127.0.0.1:18080 -> 8080\n"));
        assert!(output.contains("Network:     mesh-dev\n"));
        assert!(output.contains("Access:      user/work (revision 2)\n"));
        assert!(output.contains("Docker:      8Gi\n"));
    }

    #[test]
    fn native_access_view_locks_redacted_human_and_json_fields() {
        let view = NativeEnvironmentAccessView {
            environment: "dev".to_owned(),
            environment_id: "env-dev".to_owned(),
            placement: "local".to_owned(),
            profile: Some("user/work".to_owned()),
            bound_revision: Some(2),
            current_revision: Some(3),
            update_available: true,
        };
        assert_eq!(
            format_native_environment_access(&view),
            "Environment:      dev\nPlacement:        local\nAccess profile:   user/work\nBound revision:   2\nCurrent revision: 3\nUpdate available: yes\n"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["profile"], "user/work");
        assert_eq!(json["bound_revision"], 2);
        assert_eq!(json["current_revision"], 3);
        assert!(json.get("profile_id").is_none());

        let none = NativeEnvironmentAccessView {
            profile: None,
            bound_revision: None,
            current_revision: None,
            update_available: false,
            ..view
        };
        assert_eq!(
            format_native_environment_access(&none),
            "Environment:    dev\nPlacement:      local\nAccess profile: none\n"
        );
    }
}
