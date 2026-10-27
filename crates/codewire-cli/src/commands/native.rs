use std::future::Future;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

use codewire_access::{AccessProfileReference, EnvironmentId};
use codewire_client::TokenProvider as _;
use codewire_local_credentials::LocalCredentialClient;
use codewire_local_vmm::control::v1;

use super::native_progress::NativeProgress;
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
use crate::commands::progress::terminal_text;

mod host_support;
mod lifecycle;
mod ports;
mod sources;

pub(crate) use lifecycle::{
    NativeCreated, local_vm_credentials, network_ref, print_native_created,
    remove_native_environment, restart_native_environment, start_native_environment,
    stop_native_environment,
};
pub(crate) use ports::handle_native_environment_port;

const NATIVE_STATE_ROOT_ENV: &str = "CODEWIRE_NATIVE_STATE_ROOT";
const NATIVE_ARTIFACT_ROOT_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_ROOT";
const NATIVE_ARTIFACT_LOCK_ENV: &str = "CODEWIRE_NATIVE_ARTIFACT_LOCK";
const DEFAULT_NATIVE_VCPUS: u32 = 2;
const DEFAULT_NATIVE_MEMORY_MIB: u32 = 4 * 1024;
const DEFAULT_NATIVE_DISK_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const DEFAULT_NATIVE_DOCKER_DISK_BYTES: u64 = codewire_local_vmm::state::DEFAULT_DOCKER_DISK_BYTES;
const NATIVE_CREDENTIAL_AUTHORITY_UNAVAILABLE: &str = "local credential authority is unavailable";
pub(crate) const LOCAL_CREDENTIAL_ROOT_ENV: &str = "CODEWIRE_LOCAL_CREDENTIAL_ROOT";
/// The VMM a native environment reports as its backend.
#[cfg(target_os = "linux")]
const NATIVE_BACKEND: &str = "cloud-hypervisor";
#[cfg(target_os = "macos")]
const NATIVE_BACKEND: &str = "virtualization-framework";

/// The private root of the local credential authority's state.
pub(crate) fn local_credential_root(env: &impl config::Env) -> anyhow::Result<PathBuf> {
    if let Some(value) = env.var(LOCAL_CREDENTIAL_ROOT_ENV) {
        let root = PathBuf::from(value);
        if !root.is_absolute() {
            anyhow::bail!("{LOCAL_CREDENTIAL_ROOT_ENV} must be an absolute path");
        }
        return Ok(root);
    }
    Ok(ResolvePaths::from_env(env)?
        .mesh_data_dir
        .join("credentials-v1"))
}

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

/// The Mesh owner a local VM's attachment enrolls through: the local Mesh
/// service, or the signed-in platform's hosted Mesh. Read only from
/// credential-free records; never from a file that holds a bearer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeMeshOwner {
    pub(crate) kind: MeshKind,
    pub(crate) mesh_url: String,
    pub(crate) organization_id: String,
}

/// The local Mesh service's owner, when its runtime is this user's own.
fn native_local_mesh_owner(paths: &ResolvePaths, network: &str) -> anyhow::Result<NativeMeshOwner> {
    let not_running = || {
        anyhow::anyhow!(
            "the local Mesh service is not running; run `cw mesh up` before attaching local:{network}"
        )
    };
    let owner = load_local_mesh_owner_context(&paths.mesh_data_dir)?
        .filter(|owner| owner.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal)
        .ok_or_else(not_running)?;
    let runtime = load_local_mesh_runtime(&paths.mesh_data_dir)?.ok_or_else(not_running)?;
    #[cfg(target_os = "linux")]
    mesh_commands::retained::validate_owner(&runtime, &owner)
        .context("standalone local Mesh runtime custody is unknown; no attachment was admitted")?;
    #[cfg(not(target_os = "linux"))]
    if !local_process_is_running(runtime.pid) {
        anyhow::bail!(
            "the local Mesh service is stale; run `cw mesh up` before attaching local:{network}"
        );
    }
    anyhow::ensure!(
        config::same_mesh_url(&owner.mesh_url, &runtime.base_url),
        "local Mesh owner projection does not match the active standalone runtime"
    );
    Ok(NativeMeshOwner {
        kind: MeshKind::Local,
        mesh_url: owner.mesh_url,
        organization_id: owner.organization_id,
    })
}

/// The signed-in platform's hosted Mesh and the default organization that
/// owns new environments there, exactly as the hosted enrollment issuer
/// checks them. The saved OAuth credential is only required to exist.
fn native_cloud_mesh_owner(paths: &ResolvePaths, network: &str) -> anyhow::Result<NativeMeshOwner> {
    let platform = config::load_platform_config(&paths.platform_config_dir).map_err(|_| {
        anyhow::anyhow!(
            "Codewire Cloud Mesh needs a sign-in; run `cw login --org ORG` before attaching cloud:{network}"
        )
    })?;
    anyhow::ensure!(
        config::oauth_credentials_path(&paths.platform_config_dir).is_file(),
        "Codewire Cloud Mesh needs a sign-in; run `cw login --org ORG` before attaching cloud:{network}"
    );
    let organization_id = trimmed_str(&platform.default_org)
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "no default organization is saved; run `cw org set ORG` before attaching cloud:{network}"
            )
        })?;
    let mesh_url = config::derive_hosted_mesh_url_for_server(&platform.server_url)
        .context("the saved platform server has no hosted Mesh endpoint")?;
    Ok(NativeMeshOwner {
        kind: MeshKind::Cloud,
        mesh_url,
        organization_id,
    })
}

fn native_mesh_owner(
    paths: &ResolvePaths,
    kind: MeshKind,
    network: &str,
) -> anyhow::Result<NativeMeshOwner> {
    match kind {
        MeshKind::Local => native_local_mesh_owner(paths, network),
        MeshKind::Cloud => native_cloud_mesh_owner(paths, network),
    }
}

/// The Mesh a bare network name on a local VM means: the selected network's
/// Mesh, else the one Mesh available. Never both.
fn native_default_mesh(
    paths: &ResolvePaths,
    selection: Option<&NetworkSelection>,
    network: &str,
) -> anyhow::Result<MeshKind> {
    if let Some(selection) = selection {
        return Ok(selection.mesh);
    }
    let local = native_local_mesh_owner(paths, network).is_ok();
    let cloud = native_cloud_mesh_owner(paths, network).is_ok();
    match (local, cloud) {
        (true, true) => anyhow::bail!(
            "network {network:?} could be on the local Mesh service or Codewire Cloud Mesh; pass --network local:{network} or --network cloud:{network}"
        ),
        (true, false) => Ok(MeshKind::Local),
        (false, true) => Ok(MeshKind::Cloud),
        (false, false) => anyhow::bail!(
            "no Mesh is available for network {network:?}: run `cw mesh up` for a local Mesh service, or `cw login --org ORG` for Codewire Cloud Mesh"
        ),
    }
}

pub(crate) fn native_create_selected(args: &EnvCreateArgs) -> anyhow::Result<bool> {
    match args.backend.as_deref().map(str::trim) {
        None | Some("") | Some("native") | Some("cloud-hypervisor") => Ok(true),
        Some(other) => anyhow::bail!("unsupported local backend {other:?}; use native"),
    }
}

/// The Mesh attachment of a new local VM. VM location and Mesh location are
/// independent: `--network cloud:NAME` joins the hosted Mesh even while a
/// local Mesh service runs, and `local:NAME` the local service. A bare name
/// and `CODEWIRE_MESH_NETWORK` resolve against the selected Mesh; with
/// neither, the saved selection applies, asking first unless it connects
/// automatically.
fn resolve_native_mesh_attachment(
    paths: &ResolvePaths,
    env: &impl config::Env,
    name: &str,
    project: &NativeProjectPlan,
    requested_network: Option<&str>,
    disable_network: bool,
    assume_yes: bool,
) -> anyhow::Result<Option<v1::MeshAttachment>> {
    let requested = requested_network
        .and_then(trimmed_str)
        .map(NetworkReference::parse)
        .transpose()?;
    if disable_network && requested.is_some() {
        anyhow::bail!("--network and --no-network cannot be used together");
    }
    if disable_network {
        return Ok(None);
    }

    // Credential-free records only: the selection and owner projection.
    let selection = load_network_selection(&paths.mesh_data_dir)?;
    let environment_network = env
        .var(config::CODEWIRE_MESH_NETWORK_ENV)
        .and_then(|network| trimmed_str(&network).map(str::to_owned));
    let (kind, network_id, explicit, from_selection) = match requested {
        Some(NetworkReference {
            mesh: Some(kind),
            network,
        }) => (kind, network, true, false),
        Some(NetworkReference {
            mesh: None,
            network,
        }) => (
            native_default_mesh(paths, selection.as_ref(), &network)?,
            network,
            true,
            false,
        ),
        None => match (environment_network, selection.as_ref()) {
            (Some(network), _) => (
                native_default_mesh(paths, selection.as_ref(), &network)?,
                network,
                false,
                false,
            ),
            (None, Some(selection)) => (selection.mesh, selection.network_id.clone(), false, true),
            (None, None) => {
                if let Some(legacy) = load_local_mesh_owner_context(&paths.mesh_data_dir)
                    .ok()
                    .flatten()
                    .and_then(|owner| owner.selected_network)
                {
                    eprintln!(
                        "{}",
                        mesh_commands::selection::legacy_selection_notice(&terminal_text(&legacy))
                    );
                }
                return Ok(None);
            }
        },
    };

    let auto_connect = from_selection && selection.as_ref().is_some_and(|s| s.auto_connect);
    if !explicit && !assume_yes && !auto_connect && !stdin_is_interactive() {
        return Ok(None);
    }
    let owner = native_mesh_owner(paths, kind, &network_id)?;
    if from_selection
        && let Some(selection) = selection.as_ref()
        && !selection.is_for(&owner.mesh_url, &owner.organization_id)
    {
        anyhow::bail!(
            "the selected network {} is for {} in organization {}, but {} is now {} in organization {}; select it again with `cw {} network use {}`",
            selection.reference(),
            terminal_text(&selection.mesh_url),
            terminal_text(&selection.organization_id),
            kind.label(),
            terminal_text(&owner.mesh_url),
            terminal_text(&owner.organization_id),
            kind.flag(),
            terminal_text(&network_id),
        );
    }
    if !explicit
        && !assume_yes
        && !auto_connect
        && !prompt_confirm_default_no(&format!(
            "Join {} network {}:{} at {} (organization {}) for remote access. Continue",
            kind.label(),
            kind.prefix(),
            terminal_text(&network_id),
            terminal_text(&owner.mesh_url),
            terminal_text(&owner.organization_id),
        ))?
    {
        return Ok(None);
    }

    let (auth_source, proto_auth_source) = match owner.kind {
        MeshKind::Local => (
            codewire_local_vmm::mesh_ingress::MeshEnrollmentAuthSource::StandaloneLocal,
            v1::MeshEnrollmentAuthSource::StandaloneLocal,
        ),
        MeshKind::Cloud => (
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

/// `Ok(None)` when the person declined the reviewed settings.
pub(crate) async fn create_native_environment(
    globals: &Globals,
    mut args: EnvCreateArgs,
    caps: &crate::output::Capabilities,
) -> anyhow::Result<Option<NativeCreated>> {
    host_support::require_local_vm_host()?;
    reject_unsupported_native_create_options(&args)?;
    // Before the review: a VM of the cw this one updated from that still runs
    // refuses the create.
    let mut client = native_boot_client().await?;
    if args.name.as_deref().and_then(trimmed_str).is_none() {
        args.name = Some(default_native_name(
            Some(&native_source(&args)?.project_directory),
            &native_names().await,
        ));
    }
    let reviewed = native_create_is_interactive(&args);
    if reviewed && !review_native_create(&mut args).await? {
        return Ok(None);
    }
    if reviewed && let Some(profile) = args.profile.as_deref().and_then(local_profile_selector) {
        super::credentials::offer_local_profile_ssh_key(profile).await?;
    }
    let name = args
        .name
        .as_deref()
        .and_then(trimmed_str)
        .unwrap_or_default()
        .to_owned();
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let (source, mut project, provenance) = native_plan(&args)?;
    let source_path = source.project_directory.clone();
    apply_native_setup_overrides(
        &mut project.spec,
        args.install.as_deref(),
        args.startup.as_deref(),
    )?;
    if let Some(image) = args.image.as_deref().and_then(trimmed_str) {
        project.spec.image = image.to_owned();
    }
    sources::apply_create_source_flags(&mut project.spec, &args)?;
    let declared_direct_mounts = native_direct_mount_warning(&project.local_mounts);
    let implicit = project.spec.repositories.is_empty() && project.local_mounts.is_empty();
    let mut workspace = resolve_native_workspace(
        &source_path,
        &mut project,
        args.path_mode,
        Some(&paths.mesh_data_dir.join("native-empty-workspace")),
        native_runtime_supports_mounts(),
    )?;
    anchor_workspace(&mut workspace, &source, implicit);
    if !reviewed && matches!(args.output, OutputFormat::Text) {
        eprintln!("Configuration: {}", provenance.text());
        if let Some(notice) = &workspace.notice {
            eprintln!("{notice}");
        }
        eprintln!("Workspace: {}", workspace.description);
        if let Some(kept_in_vm) = &workspace.kept_in_vm {
            eprintln!("{kept_in_vm}");
        }
        for note in &workspace.vm_only_notes {
            eprintln!("{note}");
        }
    }
    let NativeWorkspace {
        source_path: request_source_path,
        path_mode: implicit_path_mode,
        vm_only: implicit_vm_only,
        ..
    } = workspace;
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
    if let Some(warning) = declared_direct_mounts {
        eprintln!("{warning}");
    }
    let NativeProjectPlan {
        spec, local_mounts, ..
    } = project;
    let context = lifecycle::CreateContext {
        credentials: crate::commands::lifecycle_output::credential_ref(
            spec.credentials
                .as_ref()
                .map(|binding| binding.profile.as_str()),
            selected
                .profile
                .as_ref()
                .map(|profile| profile.reference.as_str()),
        ),
        secrets: crate::commands::lifecycle_output::secret_refs(
            &spec.secrets,
            selected.project_name.as_deref(),
        ),
        network: lifecycle::network_ref(mesh.as_ref()),
    };
    let (project_spec_json, project_spec_sha256) =
        canonical_native_project_intent(spec, vcpus, memory_mib, disk_bytes)?;
    ensure_pinned_runtime().await?;
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
        implicit_vm_only,
        network_policy: args.policy.clone().unwrap_or_default(),
        snapshot: None,
    };
    if !request.network_policy.is_empty() {
        client
            .require_network_policy_selection()
            .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
    }
    crate::commands::lifecycle_output::print_context(
        &context.summary(&request.name, vcpus, memory_mib, disk_bytes),
        caps,
    );
    let progress = NativeProgress::new(caps).interruptible(
        caps,
        crate::commands::lifecycle_output::InterruptNotice::new(
            crate::output::VmLocation::Local,
            "creation",
            &request.name,
        ),
    );
    progress.begin_sources();
    let mut observe = |operation: &v1::Operation| progress.observe(operation);
    let created = progress
        .tick_while(client.create_observed(request.clone(), &mut observe))
        .await?;
    let environment = match created {
        Ok(environment) => {
            progress.complete();
            environment
        }
        Err(status) => {
            let stage = progress.fail_with_code(
                codewire_local_vmm::supervisor_client::operation_error_code(&status),
            );
            // The supervisor's reason already says whether the failed
            // environment was kept.
            return Err(lifecycle::lifecycle_failure(
                "create",
                &request.name,
                stage,
                native_status(status),
                false,
            )
            .await);
        }
    };
    sources::validate_created_environment(&environment, &request)?;
    Ok(Some(NativeCreated {
        environment,
        secrets: context.secrets,
        configuration: provenance,
    }))
}

/// The most environments one `cw create --snapshot --count` makes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const MAXIMUM_SNAPSHOT_COUNT: u32 = 16;
/// How many of them are created at once.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const SNAPSHOT_RESTORE_PARALLELISM: usize = 2;

/// One environment made from a snapshot, as `--output json` reports it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Serialize)]
struct SnapshotRestoreResult {
    name: String,
    id: String,
    snapshot: String,
    state: String,
    seconds: f64,
}

/// `cw create --local --snapshot S [--count N]`: environments started from a
/// local disk snapshot, each with fresh identity. Each request is built as
/// `cw create` builds one: its sources, credential profile and platform
/// account are resolved again here, its Mesh network from this host's
/// selection and flags, and it publishes no host port. Only the image,
/// workspace and disks come from the snapshot.
pub(crate) async fn create_native_environments_from_snapshot(
    globals: &Globals,
    args: EnvCreateArgs,
) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (globals, args);
        anyhow::bail!("local disk snapshots need a Linux host for now")
    }
    #[cfg(target_os = "linux")]
    {
        create_from_snapshot_on_linux(globals, args).await
    }
}

#[cfg(target_os = "linux")]
async fn create_from_snapshot_on_linux(
    globals: &Globals,
    args: EnvCreateArgs,
) -> anyhow::Result<()> {
    host_support::require_local_vm_host()?;
    reject_snapshot_create_options(&args)?;
    let selector = args
        .snapshot
        .as_deref()
        .and_then(trimmed_str)
        .context("name the snapshot to create from: --snapshot NAME")?
        .to_owned();
    let client = native_boot_client().await?;
    client
        .require_local_snapshots()
        .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
    let snapshot = client
        .get_snapshot(&selector)
        .await
        .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
    let existing = native_names().await;
    let names = snapshot_restore_names(
        &snapshot.name,
        args.name.as_deref(),
        args.name_prefix.as_deref(),
        args.count,
        &existing,
    )?;
    if snapshot.direct_mounts {
        if !args.share_mounts {
            anyhow::bail!(
                "snapshot {} was taken from a VM that mounts host folders directly; an environment made from it mounts the same folders live, shared with every other one that does. Pass --share-mounts to accept that",
                terminal_text(&snapshot.name)
            );
        }
        eprintln!(
            "Warning: these environments mount the snapshot source's host folders directly and share them live."
        );
    }
    if snapshot.consistency == "crash" {
        eprintln!(
            "Note: snapshot {} holds what a power loss would have left (its VM was not shut down cleanly).",
            terminal_text(&snapshot.name)
        );
    }
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let mut spec: codewire_project::ProjectSpec =
        serde_json::from_slice(&snapshot.project_spec_json)
            .context("read the snapshot's project")?;
    let spec_resources = (
        spec.resources
            .cpu_millicores
            .map(|millicores| millicores / 1_000)
            .context("the snapshot's project names no CPU count")?,
        spec.resources
            .memory_mib
            .and_then(|memory| u32::try_from(memory).ok())
            .context("the snapshot's project names no memory size")?,
        spec.resources
            .disk_gib
            .and_then(|disk| disk.checked_mul(1024 * 1024 * 1024))
            .context("the snapshot's project names no disk size")?,
    );
    // The same source resolution as `cw create`: the snapshot's selectors are
    // only names, resolved here under this host's current sign-ins.
    let mut credentials = connect_native_credential_authority_if_required(
        native_project_requires_credential_authority(&spec),
        connect_local_credential_authority,
    )
    .await?;
    let selected = sources::resolve_requested_sources(
        globals,
        &paths,
        &env,
        credentials.as_mut(),
        &mut spec,
        sources::SourceChanges::all(),
    )
    .await?;
    if native_project_requires_credential_authority(&spec) {
        sources::confirm_create_sources(&names[0], &spec, &selected, args.yes, args.output)?;
    }
    let account = sources::signed_in_account(globals, &paths, &env);
    let vcpus = match args.cpu.as_deref() {
        Some(value) => parse_native_cpu(value)?,
        None => snapshot.vcpus,
    };
    let memory_mib = match args.memory.as_deref() {
        Some(value) => parse_native_memory(value)?,
        None => snapshot.memory_mib,
    };
    let (project_spec_json, project_spec_sha256) = canonical_native_project_intent(
        spec.clone(),
        spec_resources.0,
        spec_resources.1,
        spec_resources.2,
    )?;
    let network_policy = match args.policy.as_deref() {
        Some(policy) => policy.to_owned(),
        None if matches!(snapshot.network_policy.as_str(), "" | "open") => String::new(),
        None => snapshot.network_policy.clone(),
    };
    if !network_policy.is_empty() {
        client
            .require_network_policy_selection()
            .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
    }
    let mesh_project = NativeProjectPlan {
        spec: spec.clone(),
        host_ports: Vec::new(),
        local_mounts: Vec::new(),
        vm_only: Vec::new(),
        vm_only_notes: Vec::new(),
        vcpus: None,
        memory_mib: None,
        disk_bytes: None,
        working_directory_explicit: false,
    };
    let mut requests = Vec::new();
    for name in &names {
        let mesh = resolve_native_mesh_attachment(
            &paths,
            &env,
            name,
            &mesh_project,
            args.network.as_deref(),
            args.no_network,
            args.yes,
        )?;
        requests.push(v1::CreateEnvironmentRequest {
            name: name.clone(),
            source_path: snapshot.source_path.clone(),
            vcpus: spec_resources.0,
            memory_mib: spec_resources.1,
            disk_bytes: spec_resources.2,
            docker_disk_bytes: snapshot.docker_disk_bytes,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json: project_spec_json.clone(),
            project_spec_sha256: project_spec_sha256.clone(),
            implicit_path_mode: snapshot.implicit_path_mode.clone(),
            local_mounts: snapshot.local_mounts.clone(),
            host_ports: Vec::new(),
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
            platform_source_authority: selected.platform.clone(),
            implicit_vm_only: snapshot.implicit_vm_only.clone(),
            network_policy: network_policy.clone(),
            snapshot: Some(v1::SnapshotRestore {
                snapshot_id: snapshot.id.clone(),
                vcpus,
                memory_mib,
                share_mounts: args.share_mounts,
                account: account.clone(),
            }),
        });
    }
    if matches!(args.output, OutputFormat::Text) {
        eprintln!(
            "Creating {} from snapshot {} ({}, {} vCPU, {} MiB)...",
            names
                .iter()
                .map(|name| terminal_text(name))
                .collect::<Vec<_>>()
                .join(", "),
            terminal_text(&snapshot.name),
            snapshot.mode,
            vcpus,
            memory_mib
        );
    }
    let started = std::time::Instant::now();
    let mut clients = Vec::new();
    for _ in &requests {
        clients.push(native_boot_client().await?);
    }
    use futures::StreamExt as _;
    let snapshot_name = snapshot.name.clone();
    let outcomes = futures::stream::iter(clients.into_iter().zip(requests))
        .map(|(mut client, request)| async move {
            let begun = std::time::Instant::now();
            let result = client.create_observed(request.clone(), &mut |_| {}).await;
            (request, result, begun.elapsed())
        })
        .buffer_unordered(SNAPSHOT_RESTORE_PARALLELISM)
        .collect::<Vec<_>>()
        .await;
    let mut created = Vec::new();
    let mut failures = Vec::new();
    for (request, result, elapsed) in outcomes {
        match result {
            Ok(environment) => {
                sources::validate_created_environment(&environment, &request)?;
                if matches!(args.output, OutputFormat::Text) {
                    println!(
                        "Created {} from snapshot {} in {:.1} s",
                        terminal_text(&environment.name),
                        terminal_text(&snapshot_name),
                        elapsed.as_secs_f64()
                    );
                }
                created.push(SnapshotRestoreResult {
                    name: environment.name,
                    id: environment.id,
                    snapshot: snapshot_name.clone(),
                    state: "running".to_owned(),
                    seconds: elapsed.as_secs_f64(),
                });
            }
            Err(status) => failures.push(
                lifecycle::lifecycle_failure(
                    "create",
                    &request.name,
                    None,
                    native_status(status),
                    false,
                )
                .await,
            ),
        }
    }
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&created)?),
        OutputFormat::Text if created.len() > 1 => println!(
            "{} environments from snapshot {} in {:.1} s",
            created.len(),
            terminal_text(&snapshot_name),
            started.elapsed().as_secs_f64()
        ),
        OutputFormat::Text => {}
    }
    if let Some(first) = failures.into_iter().next() {
        return Err(first);
    }
    Ok(())
}

/// The platform account this cw is signed in to, or `None`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn native_signed_in_account(globals: &Globals) -> Option<v1::PlatformAccount> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env).ok()?;
    sources::signed_in_account(globals, &paths, &env)
}

/// The new environments' names: `--name` for one, else `PREFIX-k` (the
/// snapshot's name by default) for the first free `k` from 1.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn snapshot_restore_names(
    snapshot: &str,
    name: Option<&str>,
    prefix: Option<&str>,
    count: u32,
    existing: &[String],
) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        (1..=MAXIMUM_SNAPSHOT_COUNT).contains(&count),
        "--count is 1 to {MAXIMUM_SNAPSHOT_COUNT}"
    );
    if let Some(name) = name.and_then(trimmed_str) {
        anyhow::ensure!(
            count == 1,
            "--name names one environment; use --name-prefix with --count"
        );
        anyhow::ensure!(
            codewire_local_vmm::valid_environment_name(name),
            "invalid environment name {name:?}"
        );
        return Ok(vec![name.to_owned()]);
    }
    let prefix = prefix.and_then(trimmed_str).unwrap_or(snapshot);
    let mut names = Vec::new();
    let mut index = 1_u32;
    while names.len() < count as usize {
        let candidate = format!("{prefix}-{index}");
        anyhow::ensure!(
            codewire_local_vmm::valid_environment_name(&candidate),
            "{candidate:?} is not a valid environment name; choose another --name-prefix"
        );
        if !existing.iter().any(|existing| existing == &candidate) {
            names.push(candidate);
        }
        index += 1;
    }
    Ok(names)
}

/// What a create from a snapshot cannot change: its image, workspace and
/// disks are the snapshot's.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reject_snapshot_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    let mut fixed = Vec::new();
    for (set, flag) in [
        (
            !args.repo_urls.is_empty() || !args.repo_flags.is_empty(),
            "repositories",
        ),
        (args.branch.is_some(), "--branch"),
        (args.path.is_some(), "--path"),
        (args.path_mode.is_some(), "--path-mode"),
        (args.file.is_some(), "--file"),
        (args.no_file, "--no-file"),
        (args.image.is_some(), "--image"),
        (args.install.is_some(), "--install"),
        (args.startup.is_some(), "--startup"),
        (args.disk.is_some(), "--disk"),
        (args.docker_disk.is_some(), "--docker-disk"),
        (args.no_docker, "--no-docker"),
        (args.profile.is_some(), "--profile"),
        (args.no_profile, "--no-profile"),
        (args.secrets.is_some(), "--secrets"),
        (args.user_secrets.is_some(), "--user-secrets"),
        (args.org_secrets, "--org-secrets"),
        (args.backend.is_some(), "--backend"),
    ] {
        if set {
            fixed.push(flag);
        }
    }
    if !fixed.is_empty() {
        anyhow::bail!(
            "a create from a snapshot keeps the snapshot's image, workspace, disks and source selection, so it does not take: {}",
            fixed.join(", ")
        );
    }
    reject_unsupported_native_create_options(args)
}

/// The acknowledgement codewire.yaml direct mounts carry. The default project
/// mount is announced by the workspace line instead.
fn native_direct_mount_warning(mounts: &[v1::LocalMountInput]) -> Option<String> {
    let direct = mounts
        .iter()
        .filter(|mount| mount.mode == v1::LocalMountMode::Direct as i32)
        .collect::<Vec<_>>();
    if direct.is_empty() {
        return None;
    }
    let write_warning = if direct.iter().any(|mount| mount.read_only == Some(false)) {
        " Read-write grants let guest root modify or delete that host content."
    } else {
        ""
    };
    Some(format!(
        "Warning: direct mounts let guest root inspect every file beneath each selected host directory.{write_warning} The explicit mode: direct and read_only choice acknowledges this grant."
    ))
}

/// The selector of an explicitly local credential profile reference.
fn local_profile_selector(reference: &str) -> Option<&str> {
    codewire_project::StorageReference::profile(reference)
        .ok()
        .filter(|reference| reference.placement == Some(codewire_project::StoragePlacement::Local))
        .map(|reference| reference.selector)
}

/// A create in a terminal shows the settings it will use and lets the person
/// change them first. Flags still apply; `--yes`, JSON output and scripts
/// never see a prompt.
fn native_create_is_interactive(args: &EnvCreateArgs) -> bool {
    use std::io::IsTerminal as _;
    !args.yes
        && matches!(args.output, OutputFormat::Text)
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
}

/// Shows the settings and asks Yes, edit or no. Returns `false` on no.
async fn review_native_create(args: &mut EnvCreateArgs) -> anyhow::Result<bool> {
    loop {
        eprintln!("{}", native_create_summary(args)?);
        let answer = prompt_text("Create with these settings? [Y]es / [e]dit / [n]o: ")?;
        match answer.to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => {
                eprintln!("Canceled; nothing was created.");
                return Ok(false);
            }
            "e" | "edit" => edit_native_create(args)?,
            _ => eprintln!("Answer y, e or n."),
        }
    }
}

/// Existing local environment names; empty before the first environment, when
/// no supervisor runs yet. Create itself reports a name that is taken.
async fn native_names() -> Vec<String> {
    if !native_state_exists().unwrap_or(false) {
        return Vec::new();
    }
    native_environments()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|environment| environment.name)
        .collect()
}

/// The directory's name as an environment name, made unique among `taken`.
fn default_native_name(path: Option<&Path>, taken: &[String]) -> String {
    let directory = std::fs::canonicalize(path.unwrap_or_else(|| Path::new(".")))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let mut base = directory
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(56)
        .collect::<String>();
    if base.is_empty() || !base.starts_with(|character: char| character.is_ascii_alphanumeric()) {
        base = "sandbox".to_owned();
    }
    let mut name = base.clone();
    let mut suffix = 2;
    while taken.iter().any(|existing| existing == &name) {
        name = format!("{base}-{suffix}");
        suffix += 1;
    }
    name
}

fn native_create_summary(args: &EnvCreateArgs) -> anyhow::Result<String> {
    let (source, mut project, provenance) = native_plan(args)?;
    let implicit = project.spec.repositories.is_empty() && project.local_mounts.is_empty();
    let mut workspace = resolve_native_workspace(
        &source.project_directory,
        &mut project,
        args.path_mode,
        None,
        native_runtime_supports_mounts(),
    )?;
    anchor_workspace(&mut workspace, &source, implicit);
    let image = args
        .image
        .as_deref()
        .and_then(trimmed_str)
        .map(str::to_owned)
        .or_else(|| (!project.spec.image.is_empty()).then(|| project.spec.image.clone()))
        .unwrap_or_else(|| "Codewire workspace (default)".to_owned());
    let cpus = match args.cpu.as_deref() {
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
    let docker = if args.no_docker {
        "off".to_owned()
    } else {
        let disk = match args.docker_disk.as_deref() {
            Some(value) => parse_native_disk(value)?,
            None => DEFAULT_NATIVE_DOCKER_DISK_BYTES,
        };
        format!("on ({} data disk)", gib_label(disk))
    };
    let profile = args
        .profile
        .clone()
        .or_else(|| {
            project
                .spec
                .credentials
                .as_ref()
                .map(|binding| binding.profile.clone())
        })
        .unwrap_or_else(|| "none".to_owned());
    let ports = if project.host_ports.is_empty() {
        "none".to_owned()
    } else {
        project
            .host_ports
            .iter()
            .map(|binding| format!("127.0.0.1:{} → {}", binding.host_port, binding.guest_port))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = vec![
        "Create a local sandbox".to_owned(),
        format!(
            "  Name         {}",
            args.name.as_deref().unwrap_or_default()
        ),
        format!("  Config       {}", provenance.text()),
        format!("  Workspace    {}", workspace.description),
    ];
    if let Some(kept_in_vm) = &workspace.kept_in_vm {
        lines.push(format!("               {kept_in_vm}"));
    }
    for note in &workspace.vm_only_notes {
        lines.push(format!("               {note}"));
    }
    lines.extend([
        format!("  Image        {image}"),
        format!(
            "  Resources    {cpus} vCPU · {} RAM · {} disk",
            gib_label(u64::from(memory_mib) * 1024 * 1024),
            gib_label(disk_bytes)
        ),
        format!("  Docker       {docker}"),
        format!("  Credentials  {profile}"),
        format!("  Ports        {ports}"),
    ]);
    if let Some(notice) = workspace.notice {
        lines.push(format!("  {notice}"));
    } else if workspace.description.starts_with("mount ") {
        lines.push(
            "  Guest root can read, change and delete files in the mounted directory.".to_owned(),
        );
    }
    Ok(lines.join("\n"))
}

/// Asks each setting in turn, with the current value as the default. An
/// answer that does not parse is asked again.
fn edit_native_create(args: &mut EnvCreateArgs) -> anyhow::Result<()> {
    loop {
        let name = prompt_default("Name", args.name.as_deref().unwrap_or_default())?;
        if codewire_local_vmm::valid_environment_name(&name) {
            args.name = Some(name);
            break;
        }
        eprintln!("Use 1 to 63 letters, digits, '-', '_' or '.', starting with a letter or digit.");
    }
    let current_path = args
        .path
        .as_deref()
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string();
    loop {
        let path = PathBuf::from(prompt_default("Project directory", &current_path)?);
        if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
            args.path = Some(path);
            break;
        }
        eprintln!("{} is not a directory.", path.display());
    }
    let current_mode = match args.path_mode.unwrap_or(PathModeArg::Mount) {
        PathModeArg::Mount => "mount",
        PathModeArg::Clone => "clone",
        PathModeArg::Copy => "copy",
        PathModeArg::Empty => "empty",
    };
    loop {
        let mode = prompt_default("Workspace (mount, copy, clone, empty)", current_mode)?;
        match <PathModeArg as clap::ValueEnum>::from_str(&mode, true) {
            Ok(mode) => {
                args.path_mode = Some(mode);
                break;
            }
            Err(_) => eprintln!("Choose mount, copy, clone or empty."),
        }
    }
    let image = prompt_default(
        "Image (default = Codewire workspace)",
        args.image.as_deref().unwrap_or("default"),
    )?;
    args.image = (image != "default").then_some(image);
    edit_quantity("vCPUs", &mut args.cpu, "2", |value| {
        parse_native_cpu(value).map(|_| ())
    })?;
    edit_quantity("Memory", &mut args.memory, "4GB", |value| {
        parse_native_memory(value).map(|_| ())
    })?;
    edit_quantity("Disk", &mut args.disk, "20GB", |value| {
        parse_native_disk(value).map(|_| ())
    })?;
    let docker = prompt_default(
        "Docker (on, off)",
        if args.no_docker { "off" } else { "on" },
    )?;
    args.no_docker = docker.eq_ignore_ascii_case("off") || docker.eq_ignore_ascii_case("no");
    if args.no_docker {
        args.docker_disk = None;
    }
    let profile = prompt_default(
        "Credential profile (local:NAME, platform:NAME or none)",
        args.profile.as_deref().unwrap_or("none"),
    )?;
    args.profile = (!profile.eq_ignore_ascii_case("none")).then_some(profile);
    Ok(())
}

fn edit_quantity(
    label: &str,
    value: &mut Option<String>,
    default: &str,
    parse: impl Fn(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    loop {
        let answer = prompt_default(label, value.as_deref().unwrap_or(default))?;
        match parse(&answer) {
            Ok(()) => {
                *value = Some(answer);
                return Ok(());
            }
            Err(error) => eprintln!("{error}"),
        }
    }
}

/// A binary size in GiB, the unit the VM is given: `20 GiB`, `1.5 GiB`.
fn gib_label(bytes: u64) -> String {
    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    if (gib - gib.round()).abs() < 0.05 {
        format!("{} GiB", gib.round() as u64)
    } else {
        format!("{gib:.1} GiB")
    }
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
    let mut supervisor = native_boot_client().await?;
    if let Some(policy) = args.policy.as_deref() {
        let updated = supervisor
            .update_environment_network_policy(&args.environment, policy)
            .await
            .map_err(native_status)?;
        print_network_policy_update(&updated, args.output)?;
        if !sources::selects_sources(&args) {
            return Ok(());
        }
    }
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
    let paths = ResolvePaths::from_env(&env)?;
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

pub(crate) async fn get_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    get_native_environment_with_authority_recovery(&mut client, name).await
}

/// `cw --local shell --stdio [ENV]`, the OpenSSH ProxyCommand for a local VM
/// (#3025): this process's stdin and stdout carry the SSH connection, which
/// the supervisor serves with the environment's own host key.
pub(crate) async fn native_shell_stdio(name: Option<&str>) -> anyhow::Result<()> {
    native_pipe_ssh(&native_ssh_target(name).await?).await
}

/// The local VM an SSH command names, or with no name the one `cw --local
/// use` selected.
pub(crate) async fn native_ssh_target(name: Option<&str>) -> anyhow::Result<v1::Environment> {
    match name {
        Some(name) => native_environment(name).await?,
        // Only an explicit `cw use` selects; the supervisor's own flag does not.
        None => {
            let paths = ResolvePaths::from_env(&OsEnv)?;
            let target = config::current_target(&paths.mesh_data_dir)?;
            if target.kind == "local" && target.target_ref != "local" {
                native_environment(&target.target_ref).await?
            } else {
                None
            }
        }
    }
    .ok_or_else(|| match name {
        Some(name) => anyhow::anyhow!("local environment {name} was not found"),
        None => anyhow::anyhow!(
            "no local environment is selected; name one, or select one with `cw --local use ENV`"
        ),
    })
}

const NATIVE_SSH_UNSUPPORTED: &str = "your local VMs run on an older cw's supervisor, which has no SSH; `cw upgrade --vms` moves them to this cw once they are idle";

/// Fails with the start pointer, as its SSH does, when `environment` is not
/// running.
pub(crate) fn ensure_native_running(environment: &v1::Environment) -> anyhow::Result<()> {
    let name = &environment.name;
    anyhow::ensure!(
        environment.state == v1::EnvironmentState::Running as i32,
        "local environment {name} is not running; start it with `cw start {name}`"
    );
    Ok(())
}

/// Fails with the upgrade pointer when the local VMs' supervisor has no SSH.
pub(crate) async fn ensure_native_ssh() -> anyhow::Result<()> {
    anyhow::ensure!(
        native_client()
            .await?
            .supports(codewire_local_vmm::supervisor_config::SupervisorFeature::Ssh),
        NATIVE_SSH_UNSUPPORTED
    );
    Ok(())
}

/// `environment`'s SSH host key as its supervisor holds it: one
/// `ssh-ed25519 <base64>` line, stable for the environment's life.
pub(crate) async fn native_ssh_host_key(environment: &v1::Environment) -> anyhow::Result<String> {
    ensure_native_ssh().await?;
    native_environment_diagnostic_client(&environment.id)
        .await?
        .host_key()
        .await
        .with_context(|| {
            format!(
                "read the SSH host key of local environment {}",
                environment.name
            )
        })
}

/// Carries an SSH connection between this process's stdin and stdout and
/// `environment`'s supervisor-served SSH.
pub(crate) async fn native_pipe_ssh(environment: &v1::Environment) -> anyhow::Result<()> {
    let environment_id = Uuid::parse_str(&environment.id).context("local environment UUID")?;
    let mut client = native_client().await?;
    anyhow::ensure!(
        client.supports(codewire_local_vmm::supervisor_config::SupervisorFeature::Ssh),
        NATIVE_SSH_UNSUPPORTED
    );
    client
        .pipe_ssh(environment_id, tokio::io::stdin(), tokio::io::stdout())
        .await
        .map_err(|status| {
            let name = &environment.name;
            match status.code() {
                tonic::Code::NotFound => anyhow::anyhow!("local environment {name} was not found"),
                tonic::Code::FailedPrecondition => anyhow::anyhow!(
                    "local environment {name} is not running; start it with `cw start {name}`"
                ),
                tonic::Code::Unavailable => anyhow::anyhow!(
                    "local environment {name} is not reachable yet; try again shortly"
                ),
                _ => anyhow::anyhow!("SSH to local environment {name}: {}", status.message()),
            }
        })
}

pub(crate) async fn select_native_environment(name: &str) -> anyhow::Result<v1::Environment> {
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    client
        .select(&environment.name, &environment.id)
        .await
        .map_err(native_status)
}

/// What a start needs before it begins: the pinned runtime and the
/// environment with its credential authority admitted.
async fn prepare_native_start(
    client: &mut NativeSupervisorClient,
    name: &str,
) -> anyhow::Result<v1::Environment> {
    ensure_pinned_runtime().await?;
    get_native_environment_with_required_authority(client, name).await
}

/// The start of a local VM: its environment, or the stage it stopped at
/// and why.
type NativeStart = Result<v1::Environment, (Option<&'static str>, anyhow::Error)>;

/// Starts `name` with its stages on `progress`. The outer error is an
/// interrupted wait; the inner one a failed start with its stage.
async fn run_native_start(
    mut client: NativeSupervisorClient,
    name: &str,
    progress: &NativeProgress,
) -> anyhow::Result<NativeStart> {
    let mut observe = |operation: &v1::Operation| progress.observe(operation);
    Ok(
        match progress
            .tick_while(client.start_observed(name, &mut observe))
            .await?
        {
            Ok(environment) => {
                progress.complete();
                Ok(environment)
            }
            Err(status) => Err((
                progress.fail_with_code(
                    codewire_local_vmm::supervisor_client::operation_error_code(&status),
                ),
                native_status(status),
            )),
        },
    )
}

/// Starts a local VM again after `cw upgrade` moved it to this cw.
async fn start_native_environment_with(
    mut client: NativeSupervisorClient,
    name: &str,
) -> anyhow::Result<v1::Environment> {
    prepare_native_start(&mut client, name).await?;
    let progress = NativeProgress::new(&super::environment::progress::text_progress_capabilities());
    run_native_start(client, name, &progress)
        .await?
        .map_err(|(stage, error)| match stage {
            Some(stage) => error.context(format!("start {name} failed at {stage:?}")),
            None => error,
        })
}

pub(crate) async fn refresh_native_environment_skills(
    name: &str,
) -> anyhow::Result<v1::Environment> {
    let mut client = native_boot_client().await?;
    get_native_environment_with_required_authority(&mut client, name).await?;
    client.refresh_skills(name).await.map_err(native_status)
}

pub(crate) async fn resize_native_environment(
    name: &str,
    vcpus: u32,
    memory_mib: u32,
    disk_bytes: u64,
) -> anyhow::Result<v1::Environment> {
    let mut client = native_boot_client().await?;
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
/// A local VM qualifies a managed agent by the rule hosted Sandboxes use
/// ([`codewire_access::ManagedCredentialClients::managed_agent_client`]), over
/// the slots its selected profile pinned: a platform profile's slots as the
/// environment captured them, a local profile's from its exact revision. The
/// VM's native Codex home is configured for the client the rule picks, so a
/// profile with only the OpenAI API-key slot runs Codex through that route, as
/// a hosted managed Codex agent does.
pub(crate) async fn require_native_agent_profile(
    environment_id: &str,
    agent: codewire_access::ManagedAgent,
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
        .context("managed VM agents require a selected credential profile")?;
    let clients = if selected.profile.starts_with("platform:") {
        pinned_platform_clients(&environment)?
    } else {
        let profile_id = codewire_access::AccessProfileId::parse(environment.access_profile_id)?;
        let mut credentials = connect_local_credential_authority().await?;
        let bound = credentials
            .get_profile_revision(&profile_id, environment.access_profile_revision)
            .await?;
        codewire_access::ManagedCredentialClients::from_profile_slots(
            bound.profile.entries.keys().map(|slot| slot.as_str()),
        )?
    };
    require_managed_agent_client(clients, agent)
}

/// The client slots a platform-profile environment pinned when its sources
/// were selected. They name provider identities only, never credentials.
fn pinned_platform_clients(
    environment: &v1::Environment,
) -> anyhow::Result<codewire_access::ManagedCredentialClients> {
    let authority = environment
        .platform_source_authority
        .as_ref()
        .context("the native environment's platform profile has no pinned selection")?;
    Ok(
        codewire_access::ManagedCredentialClients::from_profile_slots(
            authority.profile_slots.iter().map(String::as_str),
        )?,
    )
}

fn require_managed_agent_client(
    clients: codewire_access::ManagedCredentialClients,
    agent: codewire_access::ManagedAgent,
) -> anyhow::Result<()> {
    if clients.managed_agent_client(agent).is_none() {
        let provider = match agent {
            codewire_access::ManagedAgent::Codex => "Codex or OpenAI",
            codewire_access::ManagedAgent::Claude => "Anthropic",
        };
        anyhow::bail!(
            "the native environment's selected credential profile has no {provider} provider"
        );
    }
    Ok(())
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
    native_environment_managed_runtime_catalog(environment_id)
        .await?
        .active()
        .cloned()
        .map_err(anyhow::Error::msg)
}

pub(crate) async fn native_environment_managed_runtime_catalog(
    environment_id: &str,
) -> anyhow::Result<codewire_local_vmm::artifact::CwRuntimeCatalog> {
    let mut supervisor = native_client().await?;
    let environment =
        get_native_environment_with_required_authority(&mut supervisor, environment_id).await?;
    let runtime = supervisor
        .managed_runtime(&environment.name, &environment.id)
        .await
        .map_err(native_status)?;
    if runtime.environment_id != environment_id
        || !native_runtime_digest_valid(&runtime.artifact_generation)
        || !native_runtime_digest_valid(&runtime.cw_runtime_catalog_generation)
    {
        anyhow::bail!("managed runtime does not match the selected environment");
    }
    use sha2::{Digest as _, Sha256};
    if format!("{:x}", Sha256::digest(&runtime.catalog_json))
        != runtime.cw_runtime_catalog_generation
    {
        anyhow::bail!("managed runtime catalog digest does not match the running VM");
    }
    let catalog = codewire_local_vmm::artifact::CwRuntimeCatalog::decode(&runtime.catalog_json)
        .map_err(anyhow::Error::msg)?;
    if catalog.encode().map_err(anyhow::Error::msg)? != runtime.catalog_json
        || catalog.active().map_err(anyhow::Error::msg)?
            != &codewire_local_vmm::artifact::CwRuntimeProvenance::decode(&runtime.provenance_json)
                .map_err(anyhow::Error::msg)?
    {
        anyhow::bail!("managed runtime catalog and active provenance disagree");
    }
    // Bootstrap remains fixed. The separate service admits the live default
    // and retained helpers against the host's append-only asset custody.
    let selected = supervisor
        .runtime_info(environment_id)
        .await
        .map_err(native_status)?;
    let selection: codewire_local_vmm::cw_runtime::RuntimeSelection =
        serde_json::from_slice(&selected.selection_json)?;
    selection.validate().map_err(anyhow::Error::msg)?;
    if selected.environment_id != environment_id
        || selected.generation != environment.generation
        || selection.environment_id.to_string() != environment_id
        || selection.bootstrap_catalog_sha256 != runtime.cw_runtime_catalog_generation
        || catalog
            .runtimes
            .iter()
            .any(|member| selection.catalog.runtime(&member.payload.sha256) != Some(member))
    {
        anyhow::bail!("live cw selection does not match the running VM bootstrap");
    }
    Ok(selection.catalog)
}

fn native_runtime_digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    print_native_environment_info(environment, output, None)
}

/// `cw info` for a local VM: the environment and, while it runs, the managed
/// conversations that need attention (#2982). The JSON gains
/// `agents_attention` only when one does.
pub(crate) fn print_native_environment_info(
    environment: &v1::Environment,
    output: OutputFormat,
    attention: Option<&super::sessions::agents::ManagedAttentionReport>,
) -> anyhow::Result<()> {
    let view = NativeEnvironmentView::try_from(environment)?;
    match output {
        OutputFormat::Json => {
            let mut value = serde_json::to_value(&view)?;
            if let Some(entries) =
                attention.and_then(super::sessions::agents::managed_attention_json)
            {
                value["agents_attention"] = entries;
            }
            println!("{}", serde_json::to_string_pretty(&value)?)
        }
        OutputFormat::Text => {
            let configuration = (!environment.project_spec_json.is_empty())
                .then(|| sources::project_from_environment(environment).ok())
                .flatten();
            let rows = attention
                .map(super::sessions::agents::managed_attention_rows)
                .unwrap_or_default();
            print!(
                "{}",
                format_native_environment(&view, configuration.as_ref(), &rows)
            )
        }
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
    /// The `Network policy:` line (#2537); unrelated to the Mesh network.
    pub(crate) network_policy: Option<String>,
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
            backend: NATIVE_BACKEND.to_owned(),
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
            network_policy: environment.network_policy.as_ref().map(network_policy_text),
        })
    }
}

/// `work · rev 3`, then what a running VM enforces when it could not take
/// the selection (#2537): `work · rev 4 · enforces rev 3 until restarted`.
pub(crate) fn network_policy_text(policy: &v1::EnvironmentNetworkPolicy) -> String {
    let selected = if policy.revision > 0 {
        format!("{} · rev {}", policy.name, policy.revision)
    } else {
        policy.name.clone()
    };
    if !policy.restart_required {
        return selected;
    }
    let enforced = if policy.enforced_revision > 0 {
        format!("rev {}", policy.enforced_revision)
    } else {
        "an earlier selection".to_owned()
    };
    format!("{selected} · enforces {enforced} until restarted")
}

/// What `cw update ENV --policy` changed.
pub(crate) fn print_network_policy_update(
    environment: &v1::Environment,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let policy = environment
        .network_policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the supervisor did not report the network policy"))?;
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment": environment.name,
                "network_policy": {
                    "reference": policy.reference,
                    "name": policy.name,
                    "revision": policy.revision,
                    "digest": policy.digest,
                    "enforced_revision": policy.enforced_revision,
                    "enforced_digest": policy.enforced_digest,
                    "restart_required": policy.restart_required,
                },
            }))?
        ),
        OutputFormat::Text => {
            println!(
                "Network policy for {}: {}",
                environment.name,
                network_policy_text(policy)
            );
            if policy.restart_required {
                println!(
                    "Its running VM could not take it, so it applies at the next start: `cw restart {}`",
                    environment.name
                );
            }
        }
    }
    Ok(())
}

fn format_native_environment(
    view: &NativeEnvironmentView,
    configuration: Option<&codewire_project::ProjectSpec>,
    attention: &[String],
) -> String {
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
    if let Some(configuration) = configuration {
        output.push_str(&format_native_configuration(configuration));
    }
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
    if let Some(network_policy) = &view.network_policy {
        output.push_str(&format!("Network policy: {network_policy}\n"));
    }
    if let Some(error_code) = &view.error_code {
        output.push_str(&format!("Error:       {error_code}\n"));
    }
    for row in attention {
        output.push_str(&format!("Attention:   {row}\n"));
    }
    output.push_str(&format!("Generation:  {}\n", view.generation));
    output.push_str(&sources::format_source_view(view.source_selection.as_ref()));
    output
}

/// The saved configuration a person set in codewire.yaml or on create: the
/// install command, environment variable names (never their values) and
/// agents.
fn format_native_configuration(spec: &codewire_project::ProjectSpec) -> String {
    use crate::commands::progress::terminal_text;
    let install = Some(terminal_text(&spec.install_command))
        .filter(|command| !command.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let names = spec
        .environment
        .keys()
        .map(|name| terminal_text(name))
        .collect::<Vec<_>>();
    let variables = if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    };
    let mut agents = spec
        .agents
        .tools
        .iter()
        .map(|tool| terminal_text(tool))
        .collect::<Vec<_>>()
        .join(", ");
    if agents.is_empty() {
        agents = "none".to_owned();
    }
    if spec.agents.install == Some(false) {
        agents.push_str(" (agent install off)");
    }
    format!("Install:     {install}\nEnv vars:    {variables}\nAgents:      {agents}\n")
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

pub(crate) async fn native_runtime_control_client() -> anyhow::Result<NativeSupervisorClient> {
    NativeSupervisorClient::connect_runtime(&native_runtime_config()?)
        .await
        .context("connect to existing native runtime publisher")
}

pub(crate) async fn native_client() -> anyhow::Result<NativeSupervisorClient> {
    let config = native_runtime_config()?;
    connect_native_after_authority_admission(
        || async {
            // Admit an authority visible at the current credential root before
            // an existing supervisor can be reused. An incompatible or
            // unconnectable endpoint fails without replacing its authority.
            // Only an absent endpoint permits credential-free native
            // operations to continue without starting an authority.
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

/// The client for a command that boots or reconfigures a VM. After a cw
/// update the previous cw's supervisor may still serve its VMs: this cw takes
/// the state root over once it runs none, and refuses the command with one
/// line while it may (supervisor_upgrade). A command that boots installs
/// this cw's runtime only after this, so an older supervisor never starts a
/// VM from it.
async fn native_boot_client() -> anyhow::Result<NativeSupervisorClient> {
    match native_boot_client_here().await {
        Err(error) => Err(offer_restart_when_refused(error).await),
        client => client,
    }
}

/// [`native_boot_client`] without the restart offer, for the restart itself.
async fn native_boot_client_here() -> anyhow::Result<NativeSupervisorClient> {
    let config = native_runtime_config()?;
    let mut client = connect_native_after_authority_admission(
        || async { admit_existing_local_credential_authority().await },
        || async {
            codewire_local_vmm::supervisor_upgrade::connect_for_boot(&config)
                .await
                .map_err(anyhow::Error::from)
        },
    )
    .await?;
    replace_older_local_credential_authority(async {
        codewire_local_vmm::supervisor_upgrade::may_replace_older_authority(&mut client)
            .await
            .map_err(anyhow::Error::from)
    })
    .await?;
    Ok(client)
}

/// `cw upgrade` selected an older cw, one without the updater hand-off. It
/// refuses this cw's local VM supervisor ("a newer cw runs your local VMs")
/// and cannot retire it, so hand the state root back while no VM runs on it.
/// Anything but a confirmed idle supervisor changes nothing, and says how to
/// hand the VMs over: this cw stops them, and a rollback while none runs
/// hands the root over. Never fails the update.
pub(crate) async fn release_local_vms_for_older_cw(version: &str) {
    report_older_cw_handover(version, &hand_root_to_older_cw().await);
}

/// What handing the local VM state root to an older cw found.
pub(crate) enum OlderCwHandover {
    /// This cw's supervisor ran no VM and retired, or none served the root.
    Done,
    /// These VMs may run on this cw's supervisor, which keeps serving them.
    Busy(Vec<String>),
    /// This cw's supervisor could not be asked; it keeps running.
    Failed(String),
}

/// Retire this cw's local VM supervisor while it runs no VM, so an older cw
/// can serve the root. Prints nothing.
pub(crate) async fn hand_root_to_older_cw() -> OlderCwHandover {
    use codewire_local_vmm::supervisor_upgrade::{OlderCwRelease, release_for_older_cw};
    let Ok(config) = native_runtime_config() else {
        return OlderCwHandover::Done;
    };
    match release_for_older_cw(&config).await {
        Ok(OlderCwRelease::Nothing | OlderCwRelease::Released) => OlderCwHandover::Done,
        Ok(OlderCwRelease::Busy(names)) => OlderCwHandover::Busy(names),
        Err(error) => OlderCwHandover::Failed(error.to_string()),
    }
}

/// Say what keeps the root from cw `version`, and how to hand it over.
pub(crate) fn report_older_cw_handover(version: &str, handover: &OlderCwHandover) {
    // The first step runs in cw `version`, in its own grammar.
    let reselect = crate::update::rollback_command(version);
    let hand_over = format!(
        "to hand them over, select this cw again (`{reselect}`), stop them (`cw --local stop NAME`), then roll back"
    );
    match handover {
        OlderCwHandover::Done => {}
        OlderCwHandover::Busy(names) => eprintln!(
            "cw: local VMs {} run on the local VM supervisor of the cw you rolled back from, which cw {version} cannot use; {hand_over}",
            names.join(", ")
        ),
        OlderCwHandover::Failed(error) => eprintln!(
            "cw: the local VM supervisor of the cw you rolled back from keeps running ({error}); cw {version} cannot use it; {hand_over}"
        ),
    }
}

/// `cw upgrade --vms`: move the local VMs a previous cw's supervisor
/// still runs to this cw. Each stops through that supervisor, the ordinary
/// stop; the supervisor then hands the state root over, and each starts again
/// here. With `after_update`, the hand-off `cw upgrade` runs, nothing is
/// printed when nothing moves, and nothing moves unless this cw is still the
/// store's selection.
pub(crate) async fn upgrade_native_environments(
    yes: bool,
    after_update: bool,
) -> anyhow::Result<()> {
    if after_update && !crate::update::this_cw_is_selected() {
        return Ok(());
    }
    let config = native_runtime_config()?;
    let previous = match codewire_local_vmm::supervisor_upgrade::previous_cw(&config).await {
        Ok(previous) => previous,
        // The hand-off after an update never fails it: a supervisor this cw
        // cannot verify is named with its recovery, and nothing moves.
        Err(error)
            if after_update
                && codewire_local_vmm::supervisor_client::supervisor_refusal(&error)
                    .is_some_and(|refusal| refusal.recovery().is_some()) =>
        {
            eprintln!("cw: local VMs were not checked: {error}");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let Some(previous) = previous else {
        if !after_update {
            println!("No local VMs run on a previous cw.");
        }
        return Ok(());
    };
    refuse_orphaned(&previous)?;
    match restart_consent(&previous, yes) {
        Consent::Yes => move_previous_environments(&config, &previous, !after_update)
            .await
            .map(drop),
        Consent::Declined | Consent::NoTerminal => {
            for name in previous.stopping() {
                eprintln!("cw: local VM {name} still runs on the cw you updated from");
            }
            eprintln!("cw: restart them with `cw upgrade --vms`");
            Ok(())
        }
    }
}

/// The local VMs that would run on an older cw than the one `cw upgrade`
/// leaves selected: those on a previous cw's supervisor, and, when the CLI
/// selection changes, those on this cw's own. Starts nothing; a VM no stop
/// reaches refuses the question as it would the restart.
pub(crate) async fn local_vms_on_an_older_cw(cli_changes: bool) -> anyhow::Result<Vec<String>> {
    let config = native_runtime_config()?;
    if let Some(previous) = codewire_local_vmm::supervisor_upgrade::previous_cw(&config).await? {
        refuse_orphaned(&previous)?;
        return Ok(previous.stopping().map(str::to_owned).collect());
    }
    if !cli_changes || std::os::unix::net::UnixStream::connect(config.supervisor_socket()).is_err()
    {
        return Ok(Vec::new());
    }
    Ok(native_environments()
        .await?
        .into_iter()
        .filter(|environment| {
            matches!(
                v1::EnvironmentState::try_from(environment.state),
                Ok(v1::EnvironmentState::Running | v1::EnvironmentState::Starting)
            )
        })
        .map(|environment| environment.name)
        .collect())
}

enum Consent {
    Yes,
    Declined,
    NoTerminal,
}

/// Restarting ends the work running in a VM, so only `--yes` or an answer at
/// a terminal moves them; never a script without one. Nothing to restart
/// needs no consent: an idle previous supervisor just hands the root over.
fn restart_consent(
    previous: &codewire_local_vmm::supervisor_upgrade::PreviousCw,
    yes: bool,
) -> Consent {
    use std::io::{IsTerminal as _, Write as _};
    let names: Vec<&str> = previous.stopping().collect();
    if yes || names.is_empty() {
        return Consent::Yes;
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Consent::NoTerminal;
    }
    let noun = if names.len() == 1 { "VM" } else { "VMs" };
    eprint!(
        "Restart {} local {noun} ({}) now to use cw {}? [y/N] ",
        names.len(),
        names.join(", "),
        crate::update::release_name(crate::CLI_VERSION)
    );
    let mut response = String::new();
    if std::io::stderr().flush().is_err() || std::io::stdin().read_line(&mut response).is_err() {
        return Consent::Declined;
    }
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Consent::Yes
    } else {
        Consent::Declined
    }
}

/// Stop, hand over and start again; true once some VM moved. A VM in an
/// error state is stopped and stays stopped. `report` says when nothing
/// needed to move.
async fn move_previous_environments(
    config: &NativeRuntimeConfig,
    previous: &codewire_local_vmm::supervisor_upgrade::PreviousCw,
    report: bool,
) -> anyhow::Result<bool> {
    refuse_orphaned(previous)?;
    let names: Vec<&str> = previous.stopping().collect();
    if names.is_empty() {
        // An idle previous supervisor hands the root over; nothing restarts.
        codewire_local_vmm::supervisor_upgrade::stop_and_retire(config, previous, |_| {}).await?;
        if report {
            println!("No local VMs run on a previous cw.");
        }
        return Ok(false);
    }
    host_support::require_local_vm_host()?;
    eprintln!(
        "Stopping {} to restart on cw {}.",
        names.join(", "),
        crate::update::release_name(crate::CLI_VERSION)
    );
    codewire_local_vmm::supervisor_upgrade::stop_and_retire(config, previous, |name| {
        eprintln!("Stopped {name}.");
    })
    .await?;
    let mut failed = Vec::new();
    for name in &previous.restart {
        let started = match native_boot_client_here().await {
            Ok(client) => start_native_environment_with(client, name).await,
            Err(error) => Err(error),
        };
        match started {
            Ok(_) => eprintln!("Started {name}."),
            Err(error) => {
                eprintln!("cw: local VM {name} did not start: {error:#}");
                failed.push(name.as_str());
            }
        }
    }
    for name in &previous.stop_only {
        eprintln!(
            "cw: local VM {name} was in an error state and stays stopped; start it with `cw --local start {name}`"
        );
    }
    anyhow::ensure!(
        failed.is_empty(),
        "local VMs {} stopped but did not start on this cw; start them with `cw --local start NAME`",
        failed.join(", ")
    );
    Ok(true)
}

/// A VM no stop reaches keeps the previous supervisor serving; refuse before
/// stopping anything.
fn refuse_orphaned(
    previous: &codewire_local_vmm::supervisor_upgrade::PreviousCw,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        previous.blocked.is_empty(),
        "local VMs {} have orphaned ownership, so nothing moved to this cw; inspect them with `cw doctor local`",
        previous.blocked.join(", ")
    );
    Ok(())
}

/// A boot command or `cw setup --local` refused while a previous cw's
/// supervisor may run a VM (#2826): at a terminal, offer to move them here.
/// The refused command itself does not continue; it runs again by hand.
async fn offer_restart_when_refused(error: anyhow::Error) -> anyhow::Error {
    use codewire_local_vmm::supervisor_upgrade::{TakeoverError, previous_cw};
    if !matches!(
        error.downcast_ref::<TakeoverError>(),
        Some(TakeoverError::Busy(_))
    ) {
        return error;
    }
    let hint = || anyhow::anyhow!("{error}\ncw: restart them with `cw upgrade --vms`");
    let config = match native_runtime_config() {
        Ok(config) => config,
        Err(_) => return hint(),
    };
    let previous = match previous_cw(&config).await {
        Ok(Some(previous)) => previous,
        _ => return hint(),
    };
    if let Err(orphaned) = refuse_orphaned(&previous) {
        return orphaned;
    }
    if !matches!(restart_consent(&previous, false), Consent::Yes) {
        return hint();
    }
    match move_previous_environments(&config, &previous, false).await {
        Ok(_) if previous.restart.is_empty() => {
            anyhow::anyhow!("The previous cw's local VMs are stopped. Run the command again.")
        }
        Ok(_) => anyhow::anyhow!(
            "Local VMs {} now run on this cw. Run the command again.",
            previous.restart.join(", ")
        ),
        Err(failure) => failure,
    }
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

/// The installed local VM runtime: its artifact root and lock.
pub(crate) fn runtime_artifact_paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/.codewire-home"));
    let artifact_parent = home.join(".cache").join("codewire").join("local-vmm-v1");
    let artifact_root = absolute_override(NATIVE_ARTIFACT_ROOT_ENV)?
        .unwrap_or_else(|| artifact_parent.join("artifacts"));
    let artifact_lock = absolute_override(NATIVE_ARTIFACT_LOCK_ENV)?
        .unwrap_or_else(|| artifact_parent.join("artifacts.lock.json"));
    Ok((artifact_root, artifact_lock))
}

fn native_runtime_config() -> anyhow::Result<NativeRuntimeConfig> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let root = absolute_override(NATIVE_STATE_ROOT_ENV)?
        .unwrap_or_else(|| paths.mesh_data_dir.join("native-v1"));
    let (artifact_root, artifact_lock) = runtime_artifact_paths()?;
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

/// `cw setup --local`: install and verify the local VM runtime that belongs
/// to this cw (#2492, #2539). A release's cw downloads exactly the runtime it
/// pins; `--from DIR` installs a runtime directory built from the same source.
/// The guest root renders session environments, so a runtime built from other
/// source is refused.
pub(crate) async fn setup_local_runtime(
    from: Option<PathBuf>,
    replace: bool,
) -> anyhow::Result<()> {
    use codewire_local_vmm::runtime_install::{self, DirectoryBlobSource, RuntimePaths};
    host_support::require_local_vm_host()?;
    let config = native_runtime_config()?;
    // An older cw's supervisor would start its next VM from the new files.
    if let Err(error) =
        codewire_local_vmm::supervisor_upgrade::refuse_while_older_serves(&config).await
    {
        return Err(offer_restart_when_refused(error.into()).await);
    }
    let paths = RuntimePaths {
        artifact_root: config.artifact_root,
        artifact_lock: config.artifact_lock,
    };
    let Some(from) = from else {
        // A release pins one runtime document; a host it has no target for
        // (such as Linux arm64) gets the same answer as a cw with none.
        let Some(document) = crate::local_runtime_pin::embedded()?
            .filter(|document| runtime_install::host_runtime(document).is_ok())
        else {
            anyhow::bail!(no_pinned_runtime(
                &crate::build_record::embedded()?,
                &runtime_install::host_target()
            ));
        };
        report_runtime_install(install_embedded_runtime(&paths, &document).await?);
        return Ok(());
    };
    let source = DirectoryBlobSource::new(&from);
    let document = source
        .document()
        .map_err(|error| runtime_document_error(&from, error))?;
    match crate::build_record::embedded()?.source_revision {
        Some(revision) if revision != document.source_revision => anyhow::bail!(
            "this local VM runtime was built from {}, but this cw from {revision}; install the runtime from the same release",
            document.source_revision
        ),
        Some(_) => {}
        None => eprintln!(
            "Warning: this cw has no source provenance, so the runtime's source {} is not checked against it.",
            document.source_revision
        ),
    }
    report_runtime_install(runtime_install::install(&paths, &document, &source, replace).await?);
    Ok(())
}

/// Why `cw setup --local` has nothing to install (#2733). A published release
/// with no runtime for this host is not a development build, and no release
/// for this host may exist yet, so it points to hosted Sandboxes rather than
/// to `cw upgrade` or `--from`.
fn no_pinned_runtime(
    record: &codewire_cw_release::build_record::BuildRecord,
    host: &str,
) -> String {
    if record.source_revision.is_some()
        && codewire_cw_release::release::valid_release_tag(&record.package_version)
    {
        format!(
            "Local VMs aren't available on {} yet; hosted Sandboxes work (`cw --cloud create`).",
            host_name(host)
        )
    } else {
        "this cw is a development build with no pinned local VM runtime; pass --from DIR with a runtime directory built from the same source".to_owned()
    }
}

/// A runtime target as people name the host: `linux-aarch64` is Linux arm64.
fn host_name(host: &str) -> String {
    let (system, machine) = host.split_once('-').unwrap_or((host, ""));
    let system = match system {
        "linux" => "Linux",
        "macos" => "macOS",
        other => other,
    };
    let machine = match machine {
        "aarch64" => "arm64",
        other => other,
    };
    format!("{system} {machine}").trim_end().to_owned()
}

/// Installs this cw's pinned runtime (#2539), for `cw setup --local` and
/// before a local VM starts (#2582). Files this host already holds (the
/// current or previous runtime) are reused; only the rest is downloaded, so
/// rolling back to the previous runtime or re-running setup downloads
/// nothing. A damaged local file fails its digest check, and the whole
/// runtime is downloaded once.
async fn install_embedded_runtime(
    paths: &codewire_local_vmm::runtime_install::RuntimePaths,
    document: &codewire_local_vmm::runtime_install::LocalRuntimeDocument,
) -> anyhow::Result<codewire_local_vmm::runtime_install::InstallOutcome> {
    use codewire_local_vmm::runtime_install;
    let wanted = runtime_install::host_runtime(document)?.install_blobs();
    let local = runtime_install::LocalBlobs::open(paths)?;
    let missing: Vec<_> = wanted
        .iter()
        .filter(|blob| !local.has(&blob.sha256))
        .cloned()
        .collect();
    match install_pinned_runtime(paths, document, &local, &missing).await {
        Err(error) if local_file_damaged(&error) => {
            let empty = runtime_install::LocalBlobs::empty();
            install_pinned_runtime(paths, document, &empty, &wanted).await
        }
        result => result,
    }
}

/// Installs `document`'s runtime from `local` files plus a download of
/// `download`, replacing whatever another cw installed (kept as the previous
/// runtime). Running VMs keep the generation they started with.
async fn install_pinned_runtime(
    paths: &codewire_local_vmm::runtime_install::RuntimePaths,
    document: &codewire_local_vmm::runtime_install::LocalRuntimeDocument,
    local: &codewire_local_vmm::runtime_install::LocalBlobs,
    download: &[codewire_cw_release::local_runtime::BlobRef],
) -> anyhow::Result<codewire_local_vmm::runtime_install::InstallOutcome> {
    use codewire_local_vmm::runtime_install::{self, WithLocal};
    if download.is_empty() {
        return Ok(runtime_install::install(paths, document, local, true).await?);
    }
    let megabytes = download.iter().map(|blob| blob.size).sum::<u64>() / (1024 * 1024);
    eprintln!(
        "Downloading the local VM runtime ({} files, {megabytes} MiB)...",
        download.len()
    );
    let fetched = crate::public_fetch::fetch_runtime(download).await?;
    let source = WithLocal {
        local,
        fallback: &fetched,
    };
    let installed = runtime_install::install(paths, document, &source, true).await;
    let cleanup = fetched.cleanup();
    let outcome = installed?;
    cleanup.context("the runtime is installed, but its download scratch was retained")?;
    Ok(outcome)
}

/// Why `--from` could not read its runtime document. Only a document that
/// does not decode, as one packed before cw pinned its runtime, is worth
/// packing again; a missing or unreadable one is not.
fn runtime_document_error(
    from: &Path,
    error: codewire_local_vmm::runtime_install::InstallError,
) -> anyhow::Error {
    use codewire_local_vmm::runtime_install::InstallError;
    let hint = if matches!(error, InstallError::Document(_)) {
        " (a runtime directory packed before cw pinned its runtime must be packed again, e.g. with `make macos-local-runtime`)"
    } else {
        ""
    };
    anyhow::Error::from(error).context(format!(
        "read the local VM runtime in {}{hint}",
        from.display()
    ))
}

fn local_file_damaged(error: &anyhow::Error) -> bool {
    use codewire_local_vmm::runtime_install::InstallError;
    matches!(
        error.downcast_ref::<InstallError>(),
        Some(InstallError::BlobMismatch { .. } | InstallError::MissingBlob { .. })
    )
}

fn report_runtime_install(outcome: codewire_local_vmm::runtime_install::InstallOutcome) {
    use codewire_local_vmm::runtime_install::InstallOutcome;
    match outcome {
        InstallOutcome::Installed { generation } => {
            println!("Local VM runtime installed ({}).", &generation[..12]);
        }
        InstallOutcome::AlreadyInstalled { generation } => {
            println!(
                "Local VM runtime is installed and intact ({}).",
                &generation[..12]
            );
        }
    }
}

/// Before a local VM starts, install the runtime this cw pins when it is
/// missing, incomplete or another cw's (#2539, #2582). Running VMs keep the
/// generation they started with.
async fn ensure_pinned_runtime() -> anyhow::Result<()> {
    let config = native_runtime_config()?;
    let paths = codewire_local_vmm::runtime_install::RuntimePaths {
        artifact_root: config.artifact_root,
        artifact_lock: config.artifact_lock,
    };
    let paths = &paths;
    crate::local_runtime_pin::ensure_installed(paths, |document| async move {
        install_embedded_runtime(paths, &document).await
    })
    .await
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

pub(crate) fn native_state_exists() -> anyhow::Result<bool> {
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
    /// The project folder's kept (`vm_only`) paths.
    vm_only: Vec<String>,
    /// Why a default kept path was dropped, for the review.
    vm_only_notes: Vec<String>,
    vcpus: Option<u32>,
    memory_mib: Option<u32>,
    disk_bytes: Option<u64>,
    working_directory_explicit: bool,
}

/// Where a local create's configuration comes from and its project
/// directory: the implicit workspace, the base of `workspace.vm_only` and the
/// default name.
#[derive(Debug, PartialEq, Eq)]
struct NativeSource {
    project_directory: PathBuf,
    config: project_file::ConfigSource,
    /// The invoking directory, when a file found above it, without
    /// `--path`, made the file's folder the project directory.
    invoked_from: Option<PathBuf>,
}

/// The search starts at `--path` or the invoking directory. `--file` is a
/// relative path beneath that directory. Without `--path`, a file found
/// above the invoking directory makes its own folder the project directory,
/// so creating from a subdirectory matches creating beside the file; an
/// explicit `--path` stays the project directory.
fn native_source(args: &EnvCreateArgs) -> anyhow::Result<NativeSource> {
    let requested = args.path.as_deref().unwrap_or_else(|| Path::new("."));
    let start = std::fs::canonicalize(requested)
        .with_context(|| format!("resolve native workspace {}", requested.display()))?;
    if args.no_file {
        return Ok(NativeSource {
            project_directory: start,
            config: project_file::ConfigSource::NoFile,
            invoked_from: None,
        });
    }
    native_source_at(start, args.path.is_some(), args.file.as_deref())
}

/// [`native_source`] from the canonical start directory.
fn native_source_at(
    start: PathBuf,
    explicit_path: bool,
    file: Option<&Path>,
) -> anyhow::Result<NativeSource> {
    if let Some(file) = file {
        if file.is_absolute()
            || file.as_os_str().is_empty()
            || file
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            anyhow::bail!("native --file must be a relative path beneath --path");
        }
        return Ok(NativeSource {
            config: project_file::ConfigSource::File(start.join(file)),
            project_directory: start,
            invoked_from: None,
        });
    }
    let Some(found) = project_file::discover(&start)? else {
        return Ok(NativeSource {
            project_directory: start,
            config: project_file::ConfigSource::Flags,
            invoked_from: None,
        });
    };
    let folder = found
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native codewire.yaml has no parent directory"))?
        .to_owned();
    let (project_directory, invoked_from) = if explicit_path || folder == start {
        (start, None)
    } else {
        (folder, Some(start))
    };
    Ok(NativeSource {
        project_directory,
        config: project_file::ConfigSource::Discovered(found),
        invoked_from,
    })
}

/// The selected file with the repository flags applied, and where the
/// configuration came from. Explicit repositories replace the file's list.
fn native_plan(
    args: &EnvCreateArgs,
) -> anyhow::Result<(NativeSource, NativeProjectPlan, project_file::Provenance)> {
    let source = native_source(args)?;
    let mut project = native_codewire_yaml(&source.project_directory, &source.config)?;
    let mut provenance = project_file::Provenance::new(source.config.clone());
    provenance.repositories_from_flags = project_file::apply_repository_flags(
        &mut project.spec,
        &args.repo_urls,
        &args.repo_flags,
        args.branch.as_deref().and_then(trimmed_str),
        true,
    )?;
    provenance.default_image =
        project.spec.image.is_empty() && args.image.as_deref().and_then(trimmed_str).is_none();
    Ok((source, project, provenance))
}

/// The workspace line names the project directory a file above the invoking
/// directory chose, and where the person is.
fn anchor_workspace(workspace: &mut NativeWorkspace, source: &NativeSource, implicit: bool) {
    if let Some(from) = &source.invoked_from
        && implicit
        && workspace.description != "empty"
    {
        workspace.description = format!(
            "{} (from codewire.yaml; you are in {})",
            workspace.description,
            project_file::shown_path(from)
        );
    }
}

fn native_codewire_yaml(
    source_path: &Path,
    config: &project_file::ConfigSource,
) -> anyhow::Result<NativeProjectPlan> {
    let Some(path) = config.path() else {
        let (vm_only, vm_only_notes) = native_vm_only(source_path, None);
        return Ok(NativeProjectPlan {
            vm_only,
            vm_only_notes,
            ..NativeProjectPlan::default()
        });
    };
    let file = std::fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
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
            "native local preview does not yet support {} fields: {}",
            path.display(),
            unsupported.join(", ")
        );
    }
    let config_directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native codewire.yaml has no parent directory"))?;
    let (vm_only, vm_only_notes) = native_vm_only(source_path, document.local.vm_only.as_deref());
    let local_mounts = resolve_native_local_mounts(
        config_directory,
        source_path,
        &document.local.mounts,
        &vm_only,
    )?;
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
    let working_directory_explicit = document.working_directory_is_explicit();
    Ok(NativeProjectPlan {
        spec: document.spec,
        host_ports: document.local.host_ports,
        local_mounts,
        vm_only,
        vm_only_notes,
        vcpus,
        memory_mib,
        disk_bytes,
        working_directory_explicit,
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

/// The project folder's kept (`vm_only`) paths, from `workspace.vm_only` as
/// written or the default list, and why a default path was dropped: one Git
/// tracks there stays, since hiding it would show its files as deleted.
fn native_vm_only(source_path: &Path, declared: Option<&[String]>) -> (Vec<String>, Vec<String>) {
    let paths = codewire_project::effective_vm_only(declared);
    if declared.is_some() || paths.is_empty() {
        return (paths, Vec::new());
    }
    let tracked = codewire_local_vmm::workspace::tracked_paths(source_path, &paths);
    let notes = tracked
        .iter()
        .map(|path| format!("{path} is tracked by Git, so it is not kept in the VM"))
        .collect();
    (
        paths
            .into_iter()
            .filter(|path| !tracked.contains(path))
            .collect(),
        notes,
    )
}

/// The project folder's folders, for the review: listed and inspected
/// without following symlinks or leaving its filesystem, as the guest does.
struct HostVmOnlyTree {
    device: u64,
}

impl codewire_project::VmOnlyTree for HostVmOnlyTree {
    type Folder = PathBuf;

    fn names(&mut self, folder: &PathBuf) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(folder) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect()
    }

    fn open(&mut self, folder: &PathBuf, name: &str) -> Option<PathBuf> {
        let child = folder.join(name);
        std::fs::symlink_metadata(&child)
            .ok()
            .filter(|metadata| metadata.is_dir() && metadata.dev() == self.device)
            .map(|_| child)
    }

    fn holds_repository(&mut self, folder: &PathBuf) -> bool {
        std::fs::symlink_metadata(folder.join(".git")).is_ok()
    }
}

/// A path as the review shows it: bidirectional and other invisible format
/// characters escaped, so a name cannot disguise itself.
fn shown_vm_only_path(path: &str) -> String {
    path.chars()
        .map(|character| match character {
            '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}' => format!("\\u{{{:04x}}}", u32::from(character)),
            character => character.to_string(),
        })
        .collect()
}

/// The review lines for the project folder's kept patterns: each pattern
/// with the folders it matches now, folders left shared and why, and folders
/// holding files Git tracks. `live` is the mount, which the guest expands
/// again at every start; otherwise the one-time copy.
fn vm_only_review(source_path: &Path, patterns: &[String], live: bool) -> Vec<String> {
    let Ok(parsed) = codewire_project::VmOnlyPatterns::parse(patterns) else {
        return Vec::new();
    };
    let Ok(root) = std::fs::symlink_metadata(source_path) else {
        return Vec::new();
    };
    let expansion = codewire_project::expand_vm_only(
        &parsed,
        &mut HostVmOnlyTree { device: root.dev() },
        &source_path.to_path_buf(),
    );
    let mut kept_paths = Vec::new();
    let mut lines = Vec::new();
    for (index, pattern) in patterns.iter().enumerate() {
        let mut found = Vec::new();
        let mut notes = Vec::new();
        for kept in expansion
            .matches
            .iter()
            .filter(|kept| kept.pattern == index)
        {
            if kept.exists {
                found.push(kept.path.clone());
                continue;
            }
            let folder = source_path.join(&kept.path);
            let is_folder =
                std::fs::symlink_metadata(&folder).is_ok_and(|metadata| metadata.is_dir());
            if is_folder && std::fs::symlink_metadata(folder.join(".git")).is_ok() {
                notes.push(format!(
                    "{} holds a Git repository, so it {}",
                    shown_vm_only_path(&kept.path),
                    if live {
                        "stays shared with the host"
                    } else {
                        "is copied"
                    }
                ));
            } else if is_folder {
                found.push(kept.path.clone());
            } else {
                notes.push(match vm_only_blocked(source_path, &kept.path) {
                    Some(reason) if live => format!("{reason}, so it stays shared with the host"),
                    Some(reason) => format!("{reason}, so it is copied"),
                    None if live => format!("{} is created empty", shown_vm_only_path(&kept.path)),
                    None => format!("no {} to leave out", shown_vm_only_path(&kept.path)),
                });
            }
        }
        kept_paths.extend(found.iter().cloned());
        let mut parts = Vec::new();
        if !found.is_empty() {
            let shown = found
                .iter()
                .take(5)
                .map(|path| shown_vm_only_path(path))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(if found.len() > 5 {
                format!("{shown} and {} more", found.len() - 5)
            } else {
                shown
            });
        }
        parts.extend(notes);
        if parts.is_empty() {
            parts.push("no folder matches yet".to_owned());
        }
        lines.push(format!("  {pattern}: {}", parts.join("; ")));
    }
    for repository in &expansion.repositories {
        lines.push(format!(
            "  {} holds a Git repository, so it {}",
            shown_vm_only_path(repository),
            if live {
                "stays shared with the host"
            } else {
                "is copied"
            }
        ));
    }
    for tracked in codewire_local_vmm::workspace::tracked_paths(source_path, &kept_paths) {
        lines.push(format!(
            "  {} holds files Git tracks: in the VM they look deleted, so do not commit there",
            shown_vm_only_path(&tracked)
        ));
    }
    if expansion.truncated {
        lines.push(format!(
            "A limit stopped the search: at most {} folders are kept, from at most {} folders and {} names searched {} deep.",
            codewire_project::MAX_VM_ONLY_MATCHES,
            codewire_project::MAX_VM_ONLY_WALK_DIRECTORIES,
            codewire_project::MAX_VM_ONLY_WALK_ENTRIES,
            codewire_project::MAX_VM_ONLY_DEPTH
        ));
    }
    if live {
        lines.push(
            "Folders that match later are kept from the next start; what is written into them before then stays on the host, hidden from the VM, so install again."
                .to_owned(),
        );
    }
    lines
}

/// A declared workspace: each repository's isolated clone and destination,
/// then the file's mounts.
fn declared_workspace(
    repositories: &[codewire_project::RepositorySpec],
    mounts: &[v1::LocalMountInput],
) -> String {
    let mut parts = repositories
        .iter()
        .map(|repository| {
            format!(
                "clone {} at {}",
                terminal_text(&repository.source),
                terminal_text(&repository.destination)
            )
        })
        .collect::<Vec<_>>();
    if !mounts.is_empty() {
        parts.push(if repositories.is_empty() {
            "as declared in codewire.yaml".to_owned()
        } else {
            "mounts as declared in codewire.yaml".to_owned()
        });
    }
    parts.join(", ")
}

/// Why the guest leaves a pattern's folder shared: a symlink or file at the
/// path, or a parent that is not a plain folder. None when it can be created.
fn vm_only_blocked(source_path: &Path, path: &str) -> Option<String> {
    let mut current = source_path.to_path_buf();
    let components = path.split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let last = index + 1 == components.len();
        let reason = match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => "is a symlink",
            Ok(metadata) if !metadata.is_dir() => "is a file",
            Ok(_) => continue,
            Err(_) if last => return None,
            Err(_) => "is missing",
        };
        return Some(format!(
            "{} {reason}",
            shown_vm_only_path(&components[..=index].join("/"))
        ));
    }
    None
}

/// codewire.yaml mounts for the request. The project folder's kept paths
/// apply to a copy or read-write direct mount of the project folder itself;
/// any other mount, and a read-only one, keeps nothing in the VM.
fn resolve_native_local_mounts(
    config_directory: &Path,
    project_directory: &Path,
    mounts: &[codewire_project::LocalMountIntent],
    vm_only: &[String],
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
                vm_only: if mount.read_only != Some(true)
                    && std::fs::canonicalize(project_directory).ok().as_deref()
                        == Some(source.as_path())
                {
                    vm_only.to_vec()
                } else {
                    Vec::new()
                },
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
        PathModeArg::Clone => WorkspaceSelection::Clone,
        PathModeArg::Copy => WorkspaceSelection::Copy,
        PathModeArg::Mount | PathModeArg::Empty => {
            unreachable!("mount and empty workspaces are not one-time copies")
        }
    }
}

fn workspace_source_mode_name(value: WorkspaceSourceMode) -> &'static str {
    match value {
        WorkspaceSourceMode::Clone => "clone",
        WorkspaceSourceMode::Copy => "copy",
    }
}

/// How the implicit `--path` directory became the workspace, for the create
/// summary and the request.
#[derive(Debug, Default, PartialEq, Eq)]
struct NativeWorkspace {
    /// The implicit one-time copy or clone source and its mode; empty for mounts and for
    /// workspaces that codewire.yaml declares.
    source_path: String,
    path_mode: String,
    /// One line for the create summary.
    description: String,
    /// Why the default mount was not used, when it was not.
    notice: Option<String>,
    /// The implicit copy's skipped `vm_only` paths; empty for a clone, a
    /// mount (whose mount input carries them) and an empty workspace.
    vm_only: Vec<String>,
    /// The review's `vm_only` line, when the list applies to host content.
    kept_in_vm: Option<String>,
    /// Kept paths that are dropped or stay shared, and why.
    vm_only_notes: Vec<String>,
}

/// Mount the project directory live by default. A one-time copy or clone, or
/// an empty workspace is an explicit choice. No mode ever mounts or copies a
/// directory the host share policy refuses, such as the home directory itself
/// or a credential store; the default then falls back to an empty workspace.
fn resolve_native_workspace(
    source_path: &Path,
    project: &mut NativeProjectPlan,
    requested_mode: Option<PathModeArg>,
    empty_workspace: Option<&Path>,
    mounts_supported: bool,
) -> anyhow::Result<NativeWorkspace> {
    let vm_only = project.vm_only.clone();
    if !project.spec.repositories.is_empty() || !project.local_mounts.is_empty() {
        if requested_mode.is_some() {
            anyhow::bail!(
                "--path-mode applies only when codewire.yaml has no repositories or mounts and no --repo is given"
            );
        }
        let kept = project
            .local_mounts
            .iter()
            .filter(|mount| !mount.vm_only.is_empty())
            .collect::<Vec<_>>();
        let applies = !kept.is_empty();
        let live = kept
            .iter()
            .any(|mount| mount.mode == v1::LocalMountMode::Direct as i32);
        let vm_only_notes = if applies {
            vm_only_review(source_path, &vm_only, live)
        } else {
            Vec::new()
        };
        return Ok(NativeWorkspace {
            description: declared_workspace(&project.spec.repositories, &project.local_mounts),
            kept_in_vm: applies.then(|| codewire_project::vm_only_summary(&vm_only)),
            vm_only_notes: if applies {
                project
                    .vm_only_notes
                    .iter()
                    .cloned()
                    .chain(vm_only_notes)
                    .collect()
            } else {
                Vec::new()
            },
            ..NativeWorkspace::default()
        });
    }
    let shown = display_host_path(source_path);
    let refusal = codewire_local_vmm::workspace_source_refusal(source_path);
    match requested_mode.unwrap_or(PathModeArg::Mount) {
        PathModeArg::Empty => empty_native_workspace(empty_workspace, None),
        PathModeArg::Mount => {
            if let Some(reason) = refusal {
                if requested_mode.is_some() {
                    anyhow::bail!("refusing to mount {shown}: {reason}");
                }
                return empty_native_workspace(
                    empty_workspace,
                    Some(format!(
                        "Not mounting {shown}: {reason}. /workspace starts empty; run from a project directory or pass --path to mount one."
                    )),
                );
            }
            if !mounts_supported {
                if requested_mode.is_some() {
                    anyhow::bail!(
                        "this local runtime has no virtiofsd, so it cannot mount {shown}; reinstall the runtime or use --path-mode copy"
                    );
                }
                let mut workspace = resolve_native_workspace(
                    source_path,
                    project,
                    Some(PathModeArg::Copy),
                    empty_workspace,
                    mounts_supported,
                )?;
                workspace.notice = Some(format!(
                    "This local runtime has no virtiofsd, so {shown} is copied once instead of mounted; reinstall the runtime to mount it live."
                ));
                return Ok(workspace);
            }
            let destination = format!("/workspace/{}", workspace_directory_name(source_path));
            let kept_in_vm = Some(codewire_project::vm_only_summary(&vm_only));
            let vm_only_notes = project
                .vm_only_notes
                .iter()
                .cloned()
                .chain(vm_only_review(source_path, &vm_only, true))
                .collect();
            project.local_mounts.push(v1::LocalMountInput {
                source_path: source_path.as_os_str().as_bytes().to_vec(),
                destination: destination.clone(),
                mode: v1::LocalMountMode::Direct as i32,
                read_only: Some(false),
                vm_only,
            });
            if !project.working_directory_explicit {
                project.spec.working_directory = destination.clone();
            }
            Ok(NativeWorkspace {
                description: format!("mount {shown} at {destination} (live, read-write)"),
                kept_in_vm,
                vm_only_notes,
                ..NativeWorkspace::default()
            })
        }
        mode @ (PathModeArg::Clone | PathModeArg::Copy) => {
            if let Some(reason) = refusal {
                anyhow::bail!("refusing to copy {shown} into the workspace: {reason}");
            }
            let mode = resolve_workspace_mode(source_path, workspace_selection_from_arg(mode))
                .context("resolve native workspace preparation mode")?;
            let path_mode = workspace_source_mode_name(mode).to_owned();
            // A clone takes only committed files, so it skips nothing.
            let kept_in_vm = Some(codewire_project::vm_only_summary(&vm_only));
            let vm_only = if mode == WorkspaceSourceMode::Copy {
                vm_only
            } else {
                Vec::new()
            };
            let vm_only_notes = project
                .vm_only_notes
                .iter()
                .cloned()
                .chain(vm_only_review(source_path, &vm_only, false))
                .collect();
            Ok(NativeWorkspace {
                source_path: source_path.to_string_lossy().into_owned(),
                description: format!("one-time {path_mode} of {shown}"),
                path_mode,
                notice: None,
                vm_only,
                kept_in_vm,
                vm_only_notes,
            })
        }
    }
}

/// Direct mounts need virtio-fs: Virtualization.framework's own device on
/// macOS, and the runtime's virtiofsd on Linux. An unreadable lock is left to
/// the supervisor's own admission error.
fn native_runtime_supports_mounts() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(config) = native_runtime_config() else {
            return true;
        };
        !codewire_local_vmm::artifact::ArtifactLock::read(&config.artifact_lock)
            .is_ok_and(|lock| lock.virtiofsd.is_none())
    }
    #[cfg(not(target_os = "linux"))]
    true
}

/// An empty workspace is a one-time copy of one empty directory that cw keeps.
/// Without a directory this only describes the choice, for the create review.
fn empty_native_workspace(
    directory: Option<&Path>,
    notice: Option<String>,
) -> anyhow::Result<NativeWorkspace> {
    let Some(directory) = directory else {
        return Ok(NativeWorkspace {
            description: "empty".to_owned(),
            notice,
            ..NativeWorkspace::default()
        });
    };
    // Its parents, such as the Codewire data directory, may not exist yet in
    // a fresh HOME (#2734). Every directory created here is private.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("create {}", directory.display()))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict {}", directory.display()))?;
    let directory = std::fs::canonicalize(directory)
        .with_context(|| format!("resolve {}", directory.display()))?;
    anyhow::ensure!(
        std::fs::read_dir(&directory)
            .with_context(|| format!("read {}", directory.display()))?
            .next()
            .is_none(),
        "{} must stay empty; remove its contents",
        directory.display()
    );
    Ok(NativeWorkspace {
        source_path: directory.to_string_lossy().into_owned(),
        path_mode: workspace_source_mode_name(WorkspaceSourceMode::Copy).to_owned(),
        description: "empty".to_owned(),
        notice,
        ..NativeWorkspace::default()
    })
}

/// The mount directory beneath /workspace: the project directory's name,
/// reduced to characters every guest path accepts.
fn workspace_directory_name(source_path: &Path) -> String {
    let name = source_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let name = name
        .trim_matches(|character| matches!(character, '.' | '-'))
        .to_owned();
    if name.is_empty() {
        "project".to_owned()
    } else {
        name.chars().take(64).collect()
    }
}

/// A host path with the home directory shortened to `~`.
fn display_host_path(path: &Path) -> String {
    let home = env::var_os("HOME").map(PathBuf::from);
    match home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn reject_unsupported_native_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    let mut unsupported = Vec::new();
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
    let mut message = status.message().to_owned();
    // The supervisor names only which store directory; the directories are
    // this user's own, so read them here to name the path and modes (#3271).
    if codewire_local_vmm::supervisor_client::operation_error_code(&status)
        == Some(codewire_local_vmm::supervisor_client::UNSAFE_RUNTIME_ARTIFACT_STORE_ERROR_CODE)
        && let Ok(config) = native_runtime_config()
    {
        for directory in config.unsafe_runtime_artifact_store_directories() {
            message.push_str("\n  ");
            message.push_str(&directory);
        }
    }
    anyhow::anyhow!(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan from `dir`'s own codewire.yaml, or from no file.
    fn yaml_in(dir: &Path) -> anyhow::Result<NativeProjectPlan> {
        let path = dir.join("codewire.yaml");
        let config = if path.exists() {
            project_file::ConfigSource::Discovered(path)
        } else {
            project_file::ConfigSource::Flags
        };
        native_codewire_yaml(dir, &config)
    }

    /// A platform profile qualifies a managed agent in a local VM by its
    /// pinned slots and the rule hosted Sandboxes use; before, any platform
    /// profile was refused.
    #[test]
    fn create_offers_an_ssh_key_only_for_explicitly_local_profiles() {
        assert_eq!(local_profile_selector("local:work"), Some("work"));
        assert_eq!(local_profile_selector("local:user/work"), Some("user/work"));
        assert_eq!(local_profile_selector("platform:work"), None);
        assert_eq!(local_profile_selector("work"), None);
        assert_eq!(local_profile_selector("local:"), None);
    }

    #[test]
    fn a_platform_profile_qualifies_managed_agents_by_its_pinned_slots() {
        use codewire_access::ManagedAgent::{Claude, Codex};
        let environment = |slots: &[&str]| v1::Environment {
            platform_source_authority: Some(v1::PlatformSourceAuthority {
                anthropic_form: String::new(),
                server_url: "https://codewire.example".into(),
                organization_id: "org-synthetic".into(),
                user_id: "user-synthetic".into(),
                profile_slots: slots.iter().map(|slot| (*slot).to_owned()).collect(),
            }),
            ..Default::default()
        };
        for (slots, codex, claude) in [
            (&["codex", "anthropic", "github"][..], true, true),
            (&["openai", "github"], true, false),
            (&["codex", "openai"], true, false),
            (&["anthropic"], false, true),
            (&["ssh", "github"], false, false),
            (&[], false, false),
        ] {
            let clients = pinned_platform_clients(&environment(slots)).unwrap();
            assert_eq!(
                require_managed_agent_client(clients, Codex).is_ok(),
                codex,
                "{slots:?}"
            );
            assert_eq!(
                require_managed_agent_client(clients, Claude).is_ok(),
                claude,
                "{slots:?}"
            );
        }
        let refused = require_managed_agent_client(
            pinned_platform_clients(&environment(&["ssh"])).unwrap(),
            Claude,
        )
        .unwrap_err();
        assert_eq!(
            refused.to_string(),
            "the native environment's selected credential profile has no Anthropic provider"
        );
        // No pinned selection, or an unknown slot, is never a qualification.
        assert!(pinned_platform_clients(&v1::Environment::default()).is_err());
        assert!(pinned_platform_clients(&environment(&["telnet"])).is_err());
    }

    #[test]
    fn only_an_undecodable_runtime_document_suggests_packing_again() {
        use codewire_local_vmm::runtime_install::InstallError;
        let from = Path::new("/runtime");
        let undecodable = runtime_document_error(from, InstallError::Document("schema".into()));
        assert!(format!("{undecodable:#}").contains("must be packed again"));
        let unreadable = runtime_document_error(
            from,
            InstallError::Io {
                context: "read /runtime/local-runtime.json".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
        );
        let message = format!("{unreadable:#}");
        assert!(message.starts_with("read the local VM runtime in /runtime: "));
        assert!(!message.contains("packed again"));
    }

    #[test]
    fn only_a_damaged_or_missing_local_file_downloads_the_whole_runtime() {
        use codewire_local_vmm::runtime_install::InstallError;
        let sha256 = "a".repeat(64);
        for error in [
            InstallError::MissingBlob {
                sha256: sha256.clone(),
            },
            InstallError::BlobMismatch { sha256 },
        ] {
            assert!(local_file_damaged(&anyhow::Error::from(error)));
        }
        assert!(!local_file_damaged(&anyhow::Error::from(
            InstallError::Busy
        )));
        assert!(!local_file_damaged(&anyhow::anyhow!(
            "the release download was canceled; nothing was installed"
        )));
    }

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

    /// A signed-in platform as the hosted owner reads it: its saved server
    /// and default organization, and an OAuth file that is never parsed.
    fn signed_in_platform(platform_config_dir: &Path) {
        config::save_platform_config(
            platform_config_dir,
            &config::PlatformConfig {
                server_url: "https://api.codewire-dev.sh".to_owned(),
                default_org: "org-hosted".to_owned(),
            },
        )
        .unwrap();
        std::fs::write(
            config::oauth_credentials_path(platform_config_dir),
            "not parsed by environment creation",
        )
        .unwrap();
    }

    fn private_dir(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_mesh_attachment_uses_only_credential_free_records() {
        let root = tempfile::tempdir().unwrap();
        let mesh_data_dir = root.path().join("mesh");
        let paths = ResolvePaths {
            mesh_data_dir: mesh_data_dir.clone(),
            platform_config_dir: root.path().join("platform"),
        };
        let runtime = LocalMeshRuntime {
            pid: std::process::id(),
            base_url: "http://127.0.0.1:18090".to_owned(),
            listen_addr: "127.0.0.1:18090".to_owned(),
            binary: "codewire-mesh".to_owned(),
            log_path: root.path().join("mesh.log").display().to_string(),
            started_at: "2026-09-02T00:00:00Z".to_owned(),
            #[cfg(target_os = "linux")]
            custody: None,
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
                selected_network: None,
                auto_connect: false,
            },
        )
        .unwrap();
        signed_in_platform(&paths.platform_config_dir);
        // Native creation must not deserialize this credential-bearing file.
        std::fs::write(mesh_data_dir.join("config.toml"), "not valid toml = [").unwrap();
        let project = NativeProjectPlan {
            spec: codewire_project::parse_project_yaml("ports: [{port: 3001}, {port: 8080}]\n")
                .unwrap()
                .spec,
            ..NativeProjectPlan::default()
        };
        let attach = |requested: Option<&str>, yes: bool| {
            resolve_native_mesh_attachment(
                &paths,
                &config::MapEnv::default(),
                "native-dev",
                &project,
                requested,
                false,
                yes,
            )
        };

        // local: needs the owned running service; its custody is unknown here.
        let error = attach(Some("local:explicit-network"), false).unwrap_err();
        assert!(error.to_string().contains("custody is unknown"), "{error}");
        assert_eq!(
            load_local_mesh_runtime(&mesh_data_dir).unwrap().unwrap(),
            runtime
        );

        // cloud: joins the hosted Mesh even while a local Mesh record exists.
        let explicit = attach(Some("cloud:explicit-network"), false)
            .unwrap()
            .unwrap();
        assert_eq!(explicit.mesh_url, "https://mesh.codewire-dev.sh");
        assert_eq!(explicit.organization_id, "org-hosted");
        assert_eq!(explicit.network_id, "explicit-network");
        assert_eq!(explicit.node_name, "native-dev");
        assert_eq!(explicit.guest_ports, vec![3_001, 8_080]);
        assert_eq!(
            explicit.auth_source,
            v1::MeshEnrollmentAuthSource::HostedCurrent as i32
        );
        // A bare name resolves against the one Mesh available: the cloud.
        let bare = attach(Some("explicit-network"), false).unwrap().unwrap();
        assert_eq!(bare.mesh_url, "https://mesh.codewire-dev.sh");

        // The saved selection: asked for unless --yes or auto-connect.
        let mut selection = NetworkSelection::new(
            MeshKind::Cloud,
            "https://mesh.codewire-dev.sh",
            "org-hosted",
            "selected-network",
            false,
        );
        save_network_selection(&mesh_data_dir, &selection).unwrap();
        assert!(
            attach(None, false).unwrap().is_none(),
            "noninteractive asks first"
        );
        assert_eq!(
            attach(None, true).unwrap().unwrap().network_id,
            "selected-network"
        );
        selection.auto_connect = true;
        save_network_selection(&mesh_data_dir, &selection).unwrap();
        assert_eq!(
            attach(None, false).unwrap().unwrap().network_id,
            "selected-network"
        );

        // A selection for another organization is never applied silently.
        selection.organization_id = "org-other".to_owned();
        save_network_selection(&mesh_data_dir, &selection).unwrap();
        let stale = attach(None, false).unwrap_err().to_string();
        assert!(stale.contains("select it again"), "{stale}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_mesh_attachment_honors_disable_and_requires_a_live_owner() {
        let root = tempfile::tempdir().unwrap();
        let paths = ResolvePaths {
            mesh_data_dir: root.path().join("missing-mesh"),
            platform_config_dir: root.path().join("unused-platform"),
        };
        let project = NativeProjectPlan::default();
        let attach = |requested: Option<&str>, disable: bool| {
            resolve_native_mesh_attachment(
                &paths,
                &config::MapEnv::default(),
                "native-dev",
                &project,
                requested,
                disable,
                true,
            )
        };
        assert!(attach(None, true).unwrap().is_none());
        assert!(attach(None, false).unwrap().is_none(), "nothing selected");
        let local = attach(Some("local:project-alpha"), false).unwrap_err();
        assert!(local.to_string().contains("run `cw mesh up`"), "{local}");
        let cloud = attach(Some("cloud:project-alpha"), false).unwrap_err();
        assert!(cloud.to_string().contains("cw login"), "{cloud}");
        let bare = attach(Some("project-alpha"), false).unwrap_err();
        assert!(bare.to_string().contains("no Mesh is available"), "{bare}");
        let unknown = attach(Some("platform:project-alpha"), false).unwrap_err();
        assert!(unknown.to_string().contains("unknown Mesh"), "{unknown}");
        let conflict = attach(Some("project-alpha"), true).unwrap_err();
        assert_eq!(
            conflict.to_string(),
            "--network and --no-network cannot be used together"
        );
    }

    #[test]
    fn native_hosted_mesh_attachment_follows_the_hosted_selection() {
        let root = tempfile::tempdir().unwrap();
        let paths = ResolvePaths {
            mesh_data_dir: root.path().join("mesh"),
            platform_config_dir: root.path().join("platform"),
        };
        private_dir(&paths.mesh_data_dir);
        signed_in_platform(&paths.platform_config_dir);
        save_network_selection(
            &paths.mesh_data_dir,
            &NetworkSelection::new(
                MeshKind::Cloud,
                "https://mesh.codewire-dev.sh",
                "org-hosted",
                "project-alpha",
                true,
            ),
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
        // The issuer admits only a canonical auth root; macOS temporary
        // directories may sit behind the /var symlink.
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let mesh_data_dir = root_path.join("unused-missing-mesh-root");
        let platform_config_dir = root_path.join("platform");
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
        let project = yaml_in(temp.path()).unwrap();
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
        let mut project = yaml_in(temp.path()).unwrap();
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
            "create",
            "--local",
            "--install",
            "printf install",
            "--startup",
            "printf startup",
        ])
        .unwrap();
        let (_, _, EnvCommand::Create(mut args)) = crate::commands::env_operation(cli) else {
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
        let resources = yaml_in(temp.path()).unwrap();
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

        let project = yaml_in(temp.path()).unwrap();
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

        let project = yaml_in(temp.path()).unwrap();
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
            let error = yaml_in(temp.path()).unwrap_err();
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
        let mut project = native_codewire_yaml(
            temp.path(),
            &project_file::ConfigSource::File(temp.path().join("config/dev.yaml")),
        )
        .unwrap();
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
        // A mount of another folder keeps nothing in the VM.
        assert!(project.local_mounts[0].vm_only.is_empty());
        assert_eq!(
            resolve_native_workspace(temp.path(), &mut project, None, None, true).unwrap(),
            NativeWorkspace {
                description: "as declared in codewire.yaml".to_owned(),
                ..NativeWorkspace::default()
            }
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
        let mut project = yaml_in(temp.path()).unwrap();
        assert_eq!(project.local_mounts.len(), 1);
        assert_eq!(
            project.local_mounts[0].mode,
            v1::LocalMountMode::Direct as i32
        );
        assert_eq!(project.local_mounts[0].read_only, Some(true));
        // A read-only direct mount keeps nothing in the VM.
        assert!(project.local_mounts[0].vm_only.is_empty());
        assert_eq!(
            resolve_native_workspace(temp.path(), &mut project, None, None, true).unwrap(),
            NativeWorkspace {
                description: "as declared in codewire.yaml".to_owned(),
                ..NativeWorkspace::default()
            }
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
  - source: https://git.example.invalid/example/supplychain.git
    revision: bcbae548ab2f4f0e407068aa8717cec341084d7a
    destination: /workspace/gitea
working_directory: /workspace/github
"#,
        )
        .unwrap();

        let mut project = yaml_in(temp.path()).unwrap();
        assert_eq!(project.spec.repositories.len(), 2);
        assert_eq!(project.spec.working_directory, "/workspace/github");
        assert_eq!(
            resolve_native_workspace(temp.path(), &mut project, None, None, true).unwrap(),
            NativeWorkspace {
                description: "clone https://github.com/noeljackson/method.git at /workspace/github, clone https://git.example.invalid/example/supplychain.git at /workspace/gitea".to_owned(),
                ..NativeWorkspace::default()
            }
        );
        let error = resolve_native_workspace(
            temp.path(),
            &mut project,
            Some(PathModeArg::Copy),
            None,
            true,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("codewire.yaml has no repositories or mounts"),
            "{error}"
        );
    }

    fn local_create_args(argv: &[&str]) -> Box<EnvCreateArgs> {
        use clap::Parser as _;
        let mut full = vec!["cw", "--local", "create"];
        full.extend_from_slice(argv);
        let (_, _, EnvCommand::Create(args)) =
            crate::commands::env_operation(crate::Cli::try_parse_from(full).unwrap())
        else {
            panic!("expected environment creation");
        };
        args
    }

    /// A Git checkout `app` with a root codewire.yaml and `app/crates`.
    fn checkout(yaml: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap().join("app");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("crates")).unwrap();
        std::fs::write(root.join("codewire.yaml"), yaml).unwrap();
        (temp, root)
    }

    #[test]
    fn native_discovery_from_a_subdirectory_anchors_the_project_at_the_file() {
        let (_temp, root) = checkout("version: 1\ninstall_command: make setup\n");
        let found = project_file::ConfigSource::Discovered(root.join("codewire.yaml"));
        // Without --path: the file's folder is the project directory.
        assert_eq!(
            native_source_at(root.join("crates"), false, None).unwrap(),
            NativeSource {
                project_directory: root.clone(),
                config: found.clone(),
                invoked_from: Some(root.join("crates")),
            }
        );
        // Beside the file nothing changes.
        assert_eq!(
            native_source_at(root.clone(), false, None).unwrap(),
            NativeSource {
                project_directory: root.clone(),
                config: found.clone(),
                invoked_from: None,
            }
        );
        // An explicit --path stays the project directory; the file applies.
        assert_eq!(
            native_source_at(root.join("crates"), true, None).unwrap(),
            NativeSource {
                project_directory: root.join("crates"),
                config: found.clone(),
                invoked_from: None,
            }
        );
        // --file overrides the search and is read beneath the start.
        std::fs::write(root.join("crates/ci.yaml"), "version: 1\n").unwrap();
        assert_eq!(
            native_source_at(root.join("crates"), false, Some(Path::new("ci.yaml")))
                .unwrap()
                .config,
            project_file::ConfigSource::File(root.join("crates/ci.yaml"))
        );
        assert!(
            native_source_at(root.clone(), false, Some(Path::new("/etc/codewire.yaml"))).is_err()
        );
        let missing =
            native_source_at(root.clone(), false, Some(Path::new("missing.yaml"))).unwrap();
        assert!(native_codewire_yaml(&root, &missing.config).is_err());

        let source = native_source_at(root.join("crates"), false, None).unwrap();
        let mut workspace = NativeWorkspace {
            description: format!(
                "mount {} at /workspace/app (live, read-write)",
                root.display()
            ),
            ..NativeWorkspace::default()
        };
        anchor_workspace(&mut workspace, &source, true);
        assert_eq!(
            workspace.description,
            format!(
                "mount {} at /workspace/app (live, read-write) (from codewire.yaml; you are in {})",
                root.display(),
                project_file::shown_path(&root.join("crates"))
            )
        );
        // Declared repositories or an empty workspace use no project folder.
        for (description, implicit) in [("empty", true), ("clone x at /workspace/x", false)] {
            let mut workspace = NativeWorkspace {
                description: description.to_owned(),
                ..NativeWorkspace::default()
            };
            anchor_workspace(&mut workspace, &source, implicit);
            assert_eq!(workspace.description, description);
        }
    }

    #[test]
    fn native_no_file_skips_the_search() {
        let (_temp, root) = checkout("version: 1\ninstall_command: make setup\n");
        let args =
            local_create_args(&["--path", root.join("crates").to_str().unwrap(), "--no-file"]);
        let (source, project, provenance) = native_plan(&args).unwrap();
        assert_eq!(source.config, project_file::ConfigSource::NoFile);
        assert_eq!(source.project_directory, root.join("crates"));
        assert!(project.spec.install_command.is_empty());
        assert_eq!(
            provenance.text(),
            "flags only (--no-file); default workspace image"
        );
    }

    #[test]
    fn native_discovery_never_merges_a_nested_repository_file() {
        let (_temp, root) = checkout("version: 1\ninstall_command: make root\n");
        let nested = root.join("vendor/lib");
        std::fs::create_dir_all(nested.join(".git")).unwrap();
        std::fs::write(
            nested.join("codewire.yaml"),
            "version: 1\ninstall_command: make nested\nstartup_script: nested-only\n",
        )
        .unwrap();
        let source = native_source_at(root.clone(), false, None).unwrap();
        let plan = native_codewire_yaml(&source.project_directory, &source.config).unwrap();
        assert_eq!(plan.spec.install_command, "make root");
        assert!(plan.spec.startup_script.is_empty());
        let source = native_source_at(nested.clone(), false, None).unwrap();
        let plan = native_codewire_yaml(&source.project_directory, &source.config).unwrap();
        assert_eq!(plan.spec.install_command, "make nested");
    }

    #[test]
    fn native_repo_flags_select_isolated_clones_that_replace_the_file_list() {
        let (_temp, root) = checkout(
            "version: 1\nrepositories:\n  - source: https://example.test/org/file.git\n    destination: /workspace/file\ninstall_command: make setup\n",
        );
        let path = root.to_str().unwrap();
        let args = local_create_args(&[
            "--path",
            path,
            "--repo",
            "https://example.test/org/web.git::/workspace/web",
            "--repo",
            "https://example.test/org/api.git@dev::/workspace/api",
        ]);
        reject_unsupported_native_create_options(&args).unwrap();
        let (source, mut project, provenance) = native_plan(&args).unwrap();
        assert!(provenance.repositories_from_flags);
        assert_eq!(project.spec.install_command, "make setup");
        assert_eq!(project.spec.working_directory, "/workspace");
        assert_eq!(
            project
                .spec
                .repositories
                .iter()
                .map(|r| (r.source.as_str(), r.branch.as_str(), r.destination.as_str()))
                .collect::<Vec<_>>(),
            [
                ("https://example.test/org/web.git", "", "/workspace/web"),
                ("https://example.test/org/api.git", "dev", "/workspace/api"),
            ]
        );
        let workspace =
            resolve_native_workspace(&source.project_directory, &mut project, None, None, true)
                .unwrap();
        // Isolated clones: no host mount and no implicit one-time copy.
        assert!(project.local_mounts.is_empty());
        assert!(workspace.source_path.is_empty());
        assert_eq!(
            workspace.description,
            "clone https://example.test/org/web.git at /workspace/web, clone https://example.test/org/api.git at /workspace/api"
        );
        let error = resolve_native_workspace(
            &source.project_directory,
            &mut project,
            Some(PathModeArg::Copy),
            None,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--repo"), "{error}");

        // One positional repository with --branch, and no file.
        let empty = tempfile::tempdir().unwrap();
        let args = local_create_args(&[
            "--path",
            empty.path().to_str().unwrap(),
            "https://example.test/org/app.git",
            "--branch",
            "release",
        ]);
        let (_, project, provenance) = native_plan(&args).unwrap();
        assert_eq!(project.spec.repositories[0].branch, "release");
        assert_eq!(project.spec.working_directory, "/workspace/app");
        assert!(provenance.default_image);
        // --branch without a repository, and duplicate destinations, refuse.
        let args = local_create_args(&["--path", empty.path().to_str().unwrap(), "--branch", "x"]);
        assert!(native_plan(&args).is_err());
        let args = local_create_args(&[
            "--path",
            empty.path().to_str().unwrap(),
            "--repo",
            "https://example.test/org/a.git::/workspace/app",
            "--repo",
            "https://example.test/org/b.git::/workspace/app",
        ]);
        assert!(native_plan(&args).is_err());
    }

    #[test]
    fn native_review_names_the_configuration_source() {
        let (_temp, root) = checkout("version: 1\nimage: workspace\n");
        let mut args = local_create_args(&["--path", root.join("crates").to_str().unwrap()]);
        args.name = Some("app".to_owned());
        let summary = native_create_summary(&args).unwrap();
        assert!(
            summary.contains(&format!(
                "  Config       {}\n",
                project_file::shown_path(&root.join("codewire.yaml"))
            )),
            "{summary}"
        );
        std::fs::remove_file(root.join("codewire.yaml")).unwrap();
        let summary = native_create_summary(&args).unwrap();
        assert!(
            summary.contains(
                "  Config       flags only, no codewire.yaml found; default workspace image\n"
            ),
            "{summary}"
        );
    }

    #[test]
    fn start_restart_and_attach_take_no_project_file() {
        use clap::Parser as _;
        for argv in [
            ["cw", "start", "app", "--file", "codewire.yaml"],
            ["cw", "restart", "app", "--file", "codewire.yaml"],
            ["cw", "attach", "app", "--file", "codewire.yaml"],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_err(), "{argv:?}");
        }
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
        let project = yaml_in(temp.path()).unwrap();
        assert_eq!(project.spec.agents.tools, vec!["codex"]);
        assert_eq!(project.spec.agents.install, None);
        assert_eq!(project.spec.skills.len(), 1);

        std::fs::write(
            temp.path().join("codewire.yaml"),
            "agents: {install: true, tools: [codex]}\nskills: [{source: repository, path: .agents/skills/rust}]\n",
        )
        .unwrap();
        let error = yaml_in(temp.path()).unwrap_err();
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

        let project = yaml_in(temp.path()).unwrap();
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
    fn path_mode_offers_mount_copy_clone_and_empty_only() {
        use clap::Parser as _;
        for mode in ["mount", "copy", "clone", "empty"] {
            assert!(
                crate::Cli::try_parse_from(["cw", "--local", "create", "--path-mode", mode])
                    .is_ok(),
                "{mode}"
            );
        }
        let error =
            crate::Cli::try_parse_from(["cw", "--local", "create", "--path-mode", "snapshot"])
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("invalid value 'snapshot'")
                && error.contains("[possible values: mount, copy, clone, empty]"),
            "{error}"
        );
    }

    #[test]
    fn path_mode_arguments_map_only_the_implicit_local_source() {
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
    fn the_project_directory_is_mounted_live_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join("My App");
        std::fs::create_dir(&project_dir).unwrap();
        let source = std::fs::canonicalize(&project_dir).unwrap();
        let mut project = yaml_in(&source).unwrap();
        let workspace = resolve_native_workspace(&source, &mut project, None, None, true).unwrap();
        assert_eq!(workspace.source_path, "");
        assert_eq!(workspace.path_mode, "");
        assert_eq!(workspace.notice, None);
        assert!(
            workspace
                .description
                .ends_with("at /workspace/My-App (live, read-write)"),
            "{}",
            workspace.description
        );
        assert_eq!(
            project.local_mounts,
            vec![v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: "/workspace/My-App".to_owned(),
                mode: v1::LocalMountMode::Direct as i32,
                read_only: Some(false),
                vm_only: vec![
                    "node_modules".to_owned(),
                    "target".to_owned(),
                    ".venv".to_owned()
                ],
            }]
        );
        assert_eq!(
            workspace.kept_in_vm.as_deref(),
            Some("Kept in the VM: node_modules, target, .venv")
        );
        assert!(workspace.vm_only.is_empty());
        assert_eq!(project.spec.working_directory, "/workspace/My-App");
        assert_eq!(native_direct_mount_warning(&[]), None);
    }

    #[test]
    fn an_explicit_working_directory_survives_the_default_mount() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("codewire.yaml"),
            "working_directory: /workspace\n",
        )
        .unwrap();
        let source = std::fs::canonicalize(temp.path()).unwrap();
        let mut project = yaml_in(&source).unwrap();
        resolve_native_workspace(&source, &mut project, None, None, true).unwrap();
        assert_eq!(project.local_mounts.len(), 1);
        assert_eq!(project.spec.working_directory, "/workspace");
    }

    #[test]
    fn without_virtiofs_the_default_falls_back_to_a_one_time_copy() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("file"), "content").unwrap();
        let source = std::fs::canonicalize(temp.path()).unwrap();
        let mut project = yaml_in(&source).unwrap();
        let workspace = resolve_native_workspace(&source, &mut project, None, None, false).unwrap();
        assert!(project.local_mounts.is_empty());
        assert_eq!(workspace.source_path, source.to_string_lossy());
        assert_eq!(workspace.path_mode, "copy");
        assert_eq!(workspace.vm_only, ["node_modules", "target", ".venv"]);
        assert!(workspace.notice.unwrap().contains("no virtiofsd"));
        let error =
            resolve_native_workspace(&source, &mut project, Some(PathModeArg::Mount), None, false)
                .unwrap_err();
        assert!(error.to_string().contains("--path-mode copy"), "{error}");
    }

    #[test]
    fn vm_only_reaches_each_workspace_input_it_applies_to() {
        let temp = tempfile::tempdir().unwrap();
        let source = std::fs::canonicalize(temp.path()).unwrap();
        let mount = |yaml: &str| {
            std::fs::write(source.join("codewire.yaml"), yaml).unwrap();
            let mut project = yaml_in(&source).unwrap();
            let workspace =
                resolve_native_workspace(&source, &mut project, None, None, true).unwrap();
            (project, workspace)
        };

        let (project, workspace) = mount("workspace: {vm_only: []}\n");
        assert!(project.local_mounts[0].vm_only.is_empty());
        assert_eq!(
            workspace.kept_in_vm.as_deref(),
            Some("Kept in the VM: none")
        );

        let (project, workspace) = mount("workspace: {vm_only: [dist, web/node_modules]}\n");
        assert_eq!(
            project.local_mounts[0].vm_only,
            ["dist", "web/node_modules"]
        );
        assert_eq!(
            workspace.kept_in_vm.as_deref(),
            Some("Kept in the VM: dist, web/node_modules")
        );

        // A one-time copy skips the list; a clone takes only committed files.
        std::fs::write(source.join("codewire.yaml"), "version: 1\n").unwrap();
        let mut project = yaml_in(&source).unwrap();
        let copy =
            resolve_native_workspace(&source, &mut project, Some(PathModeArg::Copy), None, true)
                .unwrap();
        assert_eq!(copy.path_mode, "copy");
        assert_eq!(copy.vm_only, ["node_modules", "target", ".venv"]);
        assert!(project.local_mounts.is_empty());
        let clone =
            resolve_native_workspace(&source, &mut project, Some(PathModeArg::Clone), None, true)
                .unwrap();
        assert_eq!(clone.path_mode, "clone");
        assert!(clone.vm_only.is_empty());

        // An empty workspace has no host content to keep apart.
        let empty =
            resolve_native_workspace(&source, &mut project, Some(PathModeArg::Empty), None, true)
                .unwrap();
        assert!(empty.vm_only.is_empty());
        assert_eq!(empty.kept_in_vm, None);

        // codewire.yaml mounts: the list applies to a read-write direct or a
        // copy mount of the project folder itself; any other folder and any
        // read-only mount keep nothing in the VM.
        for directory in ["other", "ro"] {
            std::fs::create_dir(source.join(directory)).unwrap();
        }
        let (project, workspace) = mount(
            "workspace: {vm_only: [target]}\nmounts:\n  - {source: ., destination: /workspace/rw, mode: direct, read_only: false}\n  - {source: ., destination: /workspace/ro, mode: direct, read_only: true}\n  - {source: ., destination: /workspace/copied, mode: copy}\n  - {source: ./other, destination: /workspace/other, mode: direct, read_only: false}\n",
        );
        let lists = project
            .local_mounts
            .iter()
            .map(|mount| mount.vm_only.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            lists,
            [
                vec!["target".to_owned()],
                Vec::new(),
                vec!["target".to_owned()],
                Vec::new()
            ]
        );
        assert_eq!(
            workspace.kept_in_vm.as_deref(),
            Some("Kept in the VM: target")
        );
        let (project, workspace) = mount(
            "mounts: [{source: ./other, destination: /workspace/other, mode: direct, read_only: false}]\n",
        );
        assert!(project.local_mounts[0].vm_only.is_empty());
        assert_eq!(workspace.kept_in_vm, None);
    }

    #[test]
    fn vm_only_review_lists_each_pattern_with_the_folders_it_matches() {
        let temp = tempfile::tempdir().unwrap();
        let source = std::fs::canonicalize(temp.path()).unwrap();
        for folder in [
            "real",
            "packages/web/node_modules",
            "packages/api/node_modules/x/node_modules",
            "apps/a/node_modules",
            "apps/b/node_modules",
            "apps/c/node_modules",
            "apps/d/node_modules",
            "apps/e/node_modules",
            "apps/f/node_modules",
            ".git/node_modules",
        ] {
            std::fs::create_dir_all(source.join(folder)).unwrap();
        }
        std::os::unix::fs::symlink("real", source.join("node_modules")).unwrap();
        std::fs::write(source.join("target"), b"a file").unwrap();
        let patterns = [
            "node_modules",
            "target",
            ".venv",
            "**/node_modules",
            "lib/x/node_modules",
            "dist-*",
        ]
        .map(str::to_owned);
        assert_eq!(
            vm_only_review(&source, &patterns, true),
            [
                "  node_modules: node_modules is a symlink, so it stays shared with the host",
                "  target: target is a file, so it stays shared with the host",
                "  .venv: .venv is created empty",
                "  **/node_modules: apps/a/node_modules, apps/b/node_modules, apps/c/node_modules, apps/d/node_modules, apps/e/node_modules and 3 more",
                "  lib/x/node_modules: lib is missing, so it stays shared with the host",
                "  dist-*: no folder matches yet",
                "Folders that match later are kept from the next start; what is written into them before then stays on the host, hidden from the VM, so install again.",
            ]
        );
        assert_eq!(
            vm_only_review(&source, &["packages/*/node_modules".to_owned()], false),
            ["  packages/*/node_modules: packages/api/node_modules, packages/web/node_modules"]
        );

        // The default list drops a path Git tracks; a declared list is kept.
        // On macOS cw asks the runtime's own git, which only
        // codewire-local-vmm's tests admit; its `tracked_paths` test covers
        // that side.
        let git = Path::new("/usr/bin/git");
        if cfg!(target_os = "linux") && git.exists() {
            let run = |arguments: &[&str]| {
                let status = std::process::Command::new(git)
                    .args(arguments)
                    .current_dir(&source)
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success(), "{arguments:?}");
            };
            std::fs::remove_file(source.join("target")).unwrap();
            std::fs::create_dir(source.join("target")).unwrap();
            std::fs::write(source.join("target/committed"), b"x").unwrap();
            run(&["init", "-q"]);
            run(&["add", "target/committed"]);
            let (paths, notes) = native_vm_only(&source, None);
            assert_eq!(paths, ["node_modules", ".venv"]);
            assert_eq!(
                notes,
                ["target is tracked by Git, so it is not kept in the VM"]
            );
            let declared = ["target".to_owned()];
            assert_eq!(
                native_vm_only(&source, Some(&declared)),
                (vec!["target".to_owned()], Vec::new())
            );
            // A declared pattern over tracked files is kept, with a warning;
            // a match holding its own repository stays shared.
            std::fs::create_dir_all(source.join("apps/nested/.git")).unwrap();
            let review = vm_only_review(&source, &["target".to_owned(), "apps/*".to_owned()], true);
            assert!(
                review.contains(
                    &"  target holds files Git tracks: in the VM they look deleted, so do not commit there"
                        .to_owned()
                ),
                "{review:#?}"
            );
            assert!(
                review.contains(
                    &"  apps/nested holds a Git repository, so it stays shared with the host"
                        .to_owned()
                ),
                "{review:#?}"
            );
        }
        assert_eq!(shown_vm_only_path("a\u{202e}b"), "a\\u{202e}b");
    }

    #[test]
    fn a_refused_directory_is_never_mounted_or_copied() {
        let root = Path::new("/");
        let mut project = NativeProjectPlan::default();
        let workspace = resolve_native_workspace(root, &mut project, None, None, true).unwrap();
        assert!(project.local_mounts.is_empty());
        assert_eq!(workspace.description, "empty");
        assert!(
            workspace
                .notice
                .as_deref()
                .is_some_and(|notice| notice.starts_with("Not mounting /: it is a system")),
            "{workspace:?}"
        );
        for mode in [PathModeArg::Mount, PathModeArg::Clone, PathModeArg::Copy] {
            let error =
                resolve_native_workspace(root, &mut project, Some(mode), None, true).unwrap_err();
            assert!(error.to_string().starts_with("refusing to"), "{error}");
        }
        assert!(project.local_mounts.is_empty());
    }

    #[test]
    fn an_empty_workspace_is_one_kept_empty_directory() {
        let temp = tempfile::tempdir().unwrap();
        let empty = temp.path().join("native-empty-workspace");
        let mut project = NativeProjectPlan::default();
        let workspace = resolve_native_workspace(
            temp.path(),
            &mut project,
            Some(PathModeArg::Empty),
            Some(&empty),
            true,
        )
        .unwrap();
        assert_eq!(workspace.description, "empty");
        assert_eq!(workspace.path_mode, "copy");
        assert_eq!(
            workspace.source_path,
            std::fs::canonicalize(&empty).unwrap().to_string_lossy()
        );
        assert_eq!(
            std::fs::metadata(&empty).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::write(empty.join("stray"), "").unwrap();
        let error = resolve_native_workspace(
            temp.path(),
            &mut project,
            Some(PathModeArg::Empty),
            Some(&empty),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must stay empty"), "{error}");
    }

    #[test]
    fn a_release_without_a_runtime_is_not_called_a_development_build() {
        let record = |version: &str, revision: Option<&str>| {
            codewire_cw_release::build_record::BuildRecord {
                package_version: version.to_owned(),
                rustc: "rustc 1.93.0 (254b59607 2026-01-19)".to_owned(),
                source_revision: revision.map(str::to_owned),
                source_tree_sha256: revision.map(|_| "b".repeat(64)),
                target: "x86_64-unknown-linux-musl".to_owned(),
            }
        };
        let revision = "a".repeat(40);
        let release = no_pinned_runtime(&record("v0.3.389", Some(&revision)), "linux-aarch64");
        assert_eq!(
            release,
            "Local VMs aren't available on Linux arm64 yet; hosted Sandboxes work (`cw --cloud create`)."
        );
        let release = no_pinned_runtime(&record("v0.3.389", Some(&revision)), "linux-x86_64");
        assert!(
            release.starts_with("Local VMs aren't available on Linux x86_64 yet;"),
            "{release}"
        );
        for misleading in ["development build", "cw upgrade", "--from"] {
            assert!(!release.contains(misleading), "{release}");
        }
        assert_eq!(host_name("macos-aarch64"), "macOS arm64");
        for (version, revision) in [
            ("0.0.0-rca", Some(revision.as_str())),
            ("0.3.389", Some(revision.as_str())),
            ("v0.3.389", None),
        ] {
            let message = no_pinned_runtime(&record(version, revision), "linux-x86_64");
            assert!(
                message.starts_with("this cw is a development build"),
                "{version}: {message}"
            );
        }
    }

    #[test]
    fn an_empty_workspace_creates_a_missing_data_directory() {
        let home = tempfile::tempdir().unwrap();
        // Two missing levels: a data directory under a not-yet-created parent.
        let parent = home.path().join("missing");
        let data = parent.join(".codewire");
        let empty = data.join("native-empty-workspace");
        let mut project = NativeProjectPlan::default();
        let workspace = resolve_native_workspace(
            home.path(),
            &mut project,
            Some(PathModeArg::Empty),
            Some(&empty),
            true,
        )
        .unwrap();
        assert_eq!(workspace.description, "empty");
        for path in [&parent, &data, &empty] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700,
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn default_names_follow_the_directory_and_stay_unique() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join("My App!");
        std::fs::create_dir(&project_dir).unwrap();
        assert_eq!(default_native_name(Some(&project_dir), &[]), "my-app");
        assert_eq!(
            default_native_name(
                Some(&project_dir),
                &["my-app".to_owned(), "my-app-2".to_owned()]
            ),
            "my-app-3"
        );
        let odd = temp.path().join("___");
        std::fs::create_dir(&odd).unwrap();
        assert_eq!(default_native_name(Some(&odd), &[]), "sandbox");
    }

    #[test]
    fn gib_labels_round_whole_sizes() {
        assert_eq!(gib_label(20 * 1024 * 1024 * 1024), "20 GiB");
        assert_eq!(gib_label(1536 * 1024 * 1024), "1.5 GiB");
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
    fn only_a_running_local_vm_opens_in_an_editor() {
        let environment = |state: v1::EnvironmentState| v1::Environment {
            name: "vs1".to_owned(),
            state: state as i32,
            ..Default::default()
        };
        assert!(ensure_native_running(&environment(v1::EnvironmentState::Running)).is_ok());
        for state in [
            v1::EnvironmentState::Stopped,
            v1::EnvironmentState::Starting,
        ] {
            assert_eq!(
                ensure_native_running(&environment(state))
                    .unwrap_err()
                    .to_string(),
                "local environment vs1 is not running; start it with `cw start vs1`"
            );
        }
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
            network_policy: Some("work · rev 3".to_owned()),
            error_code: None,
            access_profile: "user/work".to_owned(),
            access_profile_revision: Some(2),
            generation: 7,
            source_selection: None,
        };

        let output = format_native_environment(&view, None, &[]);
        assert!(output.contains("Port:        127.0.0.1:18080 -> 8080\n"));
        assert!(output.contains("Network:     mesh-dev\n"));
        assert!(output.contains("Network policy: work · rev 3\n"));
        assert!(output.contains("Access:      user/work (revision 2)\n"));
        assert!(output.contains("Docker:      8Gi\n"));
        assert!(!output.contains("Install:"));

        let mut spec = codewire_project::ProjectSpec {
            install_command: "npm ci\nnpm run build".to_owned(),
            ..Default::default()
        };
        spec.environment.insert(
            "NODE_ENV".to_owned(),
            "synthetic-value-never-shown".to_owned(),
        );
        spec.environment
            .insert("API_URL".to_owned(), "https://synthetic.invalid".to_owned());
        spec.agents.tools = vec!["claude".to_owned(), "codex".to_owned()];
        let output = format_native_environment(&view, Some(&spec), &[]);
        assert!(output.contains(
            "Working dir: /workspace\nAccess:      user/work (revision 2)\nInstall:     npm ci npm run build\nEnv vars:    API_URL, NODE_ENV\nAgents:      claude, codex\nDocker:      8Gi\n"
        ), "{output}");
        assert!(!output.contains("synthetic-value-never-shown"));
        assert!(!output.contains("synthetic.invalid"));
        let empty =
            format_native_environment(&view, Some(&codewire_project::ProjectSpec::default()), &[]);
        assert!(empty.contains("Install:     none\nEnv vars:    none\nAgents:      none\n"));
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

    #[test]
    fn the_network_policy_line_names_what_a_running_vm_still_enforces() {
        let policy = |name: &str, revision, enforced_revision, restart_required| {
            v1::EnvironmentNetworkPolicy {
                reference: String::new(),
                name: name.to_owned(),
                revision,
                digest: String::new(),
                enforced_revision,
                enforced_digest: String::new(),
                restart_required,
            }
        };
        assert_eq!(network_policy_text(&policy("open", 0, 0, false)), "open");
        assert_eq!(
            network_policy_text(&policy("work", 3, 3, false)),
            "work · rev 3"
        );
        assert_eq!(
            network_policy_text(&policy("work", 4, 3, true)),
            "work · rev 4 · enforces rev 3 until restarted"
        );
        assert_eq!(
            network_policy_text(&policy("locked", 0, 0, true)),
            "locked · enforces an earlier selection until restarted"
        );
    }
}

#[cfg(test)]
mod snapshot_create_tests {
    use super::*;

    fn parsed_create(arguments: &[&str]) -> Result<EnvCreateArgs, clap::Error> {
        let parsed = crate::Cli::try_parse_from(
            ["cw", "--local", "create"].iter().chain(arguments).copied(),
        )?;
        match parsed.command {
            crate::Command::Create(args) => Ok(*args),
            _ => panic!("not a create"),
        }
    }

    #[test]
    fn create_from_a_snapshot_takes_its_own_flags() {
        let args = parsed_create(&["--snapshot", "s1", "--count", "3", "--share-mounts"]).unwrap();
        assert_eq!(args.snapshot.as_deref(), Some("s1"));
        assert_eq!(args.count, 3);
        assert!(args.share_mounts);
        let args = parsed_create(&["--snapshot", "s1", "--name-prefix", "forks"]).unwrap();
        assert_eq!(args.name_prefix.as_deref(), Some("forks"));
        assert_eq!(parsed_create(&["--snapshot", "s1"]).unwrap().count, 1);

        // Each needs --snapshot; --count is bounded; one name or a prefix.
        for invalid in [
            &["--count", "2"][..],
            &["--share-mounts"],
            &["--name-prefix", "forks"],
            &["--snapshot", "s1", "--count", "0"],
            &["--snapshot", "s1", "--count", "17"],
            &["--snapshot", "s1", "--name", "a", "--name-prefix", "b"],
        ] {
            assert!(parsed_create(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn a_create_from_a_snapshot_refuses_what_the_snapshot_fixes() {
        for fixed in [
            &["--image", "workspace"][..],
            &["--path", "/tmp"],
            &["--disk", "40GB"],
            &["--no-docker"],
            &["--profile", "local:work"],
            &["https://example.invalid/repo.git"],
        ] {
            let args = parsed_create(&[&["--snapshot", "s1"][..], fixed].concat()).unwrap();
            let error = reject_snapshot_create_options(&args).unwrap_err();
            assert!(
                error.to_string().contains("keeps the snapshot's image"),
                "{fixed:?}: {error}"
            );
        }
        let args = parsed_create(&["--snapshot", "s1", "--cpu", "4", "--memory", "8GB"]).unwrap();
        reject_snapshot_create_options(&args).unwrap();
    }

    #[test]
    fn forks_are_named_after_the_snapshot_skipping_taken_names() {
        assert_eq!(
            snapshot_restore_names("s1", None, None, 3, &[]).unwrap(),
            ["s1-1", "s1-2", "s1-3"]
        );
        assert_eq!(
            snapshot_restore_names("s1", None, None, 2, &["s1-1".to_owned()]).unwrap(),
            ["s1-2", "s1-3"]
        );
        assert_eq!(
            snapshot_restore_names("s1", None, Some("work"), 2, &[]).unwrap(),
            ["work-1", "work-2"]
        );
        assert_eq!(
            snapshot_restore_names("s1", Some("app2"), None, 1, &[]).unwrap(),
            ["app2"]
        );
        assert!(snapshot_restore_names("s1", Some("app2"), None, 2, &[]).is_err());
        assert!(snapshot_restore_names("s1", Some("-bad"), None, 1, &[]).is_err());
        assert!(snapshot_restore_names("s1", None, None, 17, &[]).is_err());
    }

    #[test]
    fn the_snapshot_command_parses_under_the_local_placement() {
        let parsed = crate::Cli::try_parse_from([
            "cw", "--local", "snapshot", "create", "app", "--name", "s1",
        ])
        .unwrap();
        assert!(matches!(parsed.command, crate::Command::Snapshot(_)));
        assert!(crate::Cli::try_parse_from(["cw", "snapshot", "ls"]).is_ok());
        assert!(crate::Cli::try_parse_from(["cw", "snapshot"]).is_err());
    }
}
