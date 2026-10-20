use std::path::Path;

use super::*;

pub(crate) mod network_output;
#[cfg(target_os = "linux")]
pub(crate) mod retained;
pub(crate) mod selection;

use crate::commands::progress::terminal_text;
use network_output::{
    CreateSelection, MeshContext, SelectionCleanup, format_delete_prompt, format_invite,
    format_network_created, format_network_current, format_network_deleted, format_network_joined,
    format_network_list, format_network_selected, format_node_enrolled, format_node_enrollment,
    format_node_revoked, format_nodes, stdout_style,
};
pub(crate) use selection::{
    MeshKind, NetworkMesh, NetworkReference, NetworkSelection, load_network_selection, network_for,
    print_legacy_selection_notice, remove_network_selection, resolve_network_mesh,
    running_local_mesh, save_network_selection,
};

/// Runs one Mesh request with a live progress row on an interactive stderr.
/// Redirected and JSON runs draw nothing: the result itself is the output.
async fn with_progress<T>(
    output: OutputFormat,
    label: &str,
    work: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let caps = crate::output::Capabilities::from_process(match output {
        OutputFormat::Json => crate::output::OutputMode::Machine,
        OutputFormat::Text => crate::output::OutputMode::Text,
    });
    if !caps.live {
        return work.await;
    }
    let mut progress = crate::output::StatusLine::new(std::io::stderr(), &caps);
    let _ = progress.begin(label);
    tokio::pin!(work);
    let result = loop {
        let tick = progress
            .tick_interval()
            .unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            result = &mut work => break result,
            () = tokio::time::sleep(tick) => {
                let _ = progress.tick();
            }
        }
    };
    let _ = progress.clear();
    result
}

fn print_json(value: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Why `network use` cannot name an owner organization on this Mesh.
fn missing_owner(mesh: &NetworkMesh) -> anyhow::Error {
    match mesh.kind {
        Some(MeshKind::Cloud) => anyhow::anyhow!(
            "no default organization is saved for this platform, so new environments have no owner on {}; run `cw org set ORG`",
            mesh.label()
        ),
        _ => anyhow::anyhow!(
            "only a network on Codewire Cloud Mesh or the local Mesh service can be selected; {} is neither",
            terminal_text(mesh.url())
        ),
    }
}

pub(crate) async fn handle_network_command(
    globals: &Globals,
    command: NetworkCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let style = stdout_style();

    match command {
        NetworkCommand::List(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let networks = with_progress(
                args.output,
                "Listing networks",
                MeshClient::new(&mesh.resolved)?.list_networks(org_id),
            )
            .await
            .with_context(|| {
                format!(
                    "could not list networks of organization {} on {} ({})",
                    terminal_text(org_id),
                    mesh.label(),
                    terminal_text(mesh.url())
                )
            })?;
            match args.output {
                OutputFormat::Json => print_json(&networks)?,
                OutputFormat::Text => {
                    let selected = load_network_selection(&paths.mesh_data_dir)?
                        .filter(|selection| selection.is_for(mesh.url(), org_id))
                        .map(|selection| selection.network_id);
                    print!(
                        "{}",
                        format_network_list(
                            style,
                            &mesh,
                            &MeshContext::new(&mesh, Some(org_id)),
                            &networks,
                            selected.as_deref(),
                        )
                    );
                }
            }
        }
        NetworkCommand::Create(args) => {
            let network_id = trimmed_required(&args.name, "network name")?;
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let context = MeshContext::new(&mesh, Some(org_id));
            with_progress(
                OutputFormat::Text,
                "Creating Mesh network",
                MeshClient::new(&mesh.resolved)?.create_network(org_id, network_id),
            )
            .await
            .with_context(|| {
                format!(
                    "network creation on {} ({}) could not be confirmed; inspect with `{}` before retrying",
                    mesh.label(),
                    terminal_text(mesh.url()),
                    mesh.command(&format!("list --org {}", terminal_text(org_id)))
                )
            })?;
            let (selection, save_error) = if args.no_use {
                (CreateSelection::Skipped, None)
            } else {
                match (mesh.kind, mesh.owner_organization.as_deref()) {
                    (Some(kind), Some(owner)) if owner == org_id => {
                        let selection =
                            NetworkSelection::new(kind, mesh.url(), org_id, network_id, false);
                        match save_network_selection(&paths.mesh_data_dir, &selection) {
                            Ok(()) => (CreateSelection::Selected, None),
                            Err(error) => (
                                CreateSelection::NotSelected(format!(
                                    "The selection could not be saved: {error:#}"
                                )),
                                Some(error),
                            ),
                        }
                    }
                    (Some(_), Some(owner)) => (
                        CreateSelection::NotSelected(format!(
                            "New environments on this Mesh are owned by organization {}.",
                            terminal_text(owner)
                        )),
                        None,
                    ),
                    _ => (
                        CreateSelection::NotSelected(missing_owner(&mesh).to_string()),
                        None,
                    ),
                }
            };
            print!(
                "{}",
                format_network_created(style, &context, network_id, &selection)
            );
            if let Some(error) = save_error {
                return Err(error.context(format!(
                    "network {} was created, but selecting it failed",
                    terminal_text(network_id)
                )));
            }
        }
        NetworkCommand::Delete(args) => {
            let network_id = trimmed_required(&args.name, "network name")?;
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let context = MeshContext::new(&mesh, Some(org_id));
            confirm_network_delete(&context, network_id, args.yes)?;
            with_progress(
                OutputFormat::Text,
                "Deleting Mesh network",
                MeshClient::new(&mesh.resolved)?.delete_network(org_id, network_id),
            )
            .await?;
            let cleanup = clear_deleted_network_selection(
                &paths.mesh_data_dir,
                mesh.url(),
                org_id,
                network_id,
            );
            print!(
                "{}",
                format_network_deleted(style, &mesh, &context, network_id, &cleanup)
            );
            if let SelectionCleanup::Failed(error) = cleanup {
                anyhow::bail!(
                    "network {} was deleted, but clearing its saved selection failed: {error}",
                    terminal_text(network_id)
                );
            }
        }
        NetworkCommand::Current(args) => {
            let selection = load_network_selection(&paths.mesh_data_dir)?;
            if selection.is_none() {
                print_legacy_selection_notice(&paths.mesh_data_dir);
            }
            match args.output {
                OutputFormat::Json => print_json(&selection)?,
                OutputFormat::Text => print!("{}", format_network_current(selection.as_ref())),
            }
        }
        NetworkCommand::Use(args) => {
            let network_id = trimmed_required(&args.name, "network name")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let (Some(kind), Some(org_id)) = (mesh.kind, mesh.owner_organization.as_deref()) else {
                return Err(missing_owner(&mesh));
            };
            let networks = with_progress(
                OutputFormat::Text,
                "Checking network",
                MeshClient::new(&mesh.resolved)?.list_networks(org_id),
            )
            .await?;
            anyhow::ensure!(
                networks.iter().any(|network| network.id == network_id),
                "network {} was not found in organization {} on {} ({}); nothing was selected",
                terminal_text(network_id),
                terminal_text(org_id),
                mesh.label(),
                terminal_text(mesh.url())
            );
            let selection =
                NetworkSelection::new(kind, mesh.url(), org_id, network_id, args.auto_connect);
            save_network_selection(&paths.mesh_data_dir, &selection).context(
                "the network selection could not be saved; the previous one is unchanged",
            )?;
            print!("{}", format_network_selected(style, &selection));
        }
        NetworkCommand::Clear => {
            if remove_network_selection(&paths.mesh_data_dir)? {
                println!(
                    "{} Cleared the network selection",
                    style.status(crate::output::Status::Done)
                );
            } else {
                println!("No network was selected.");
            }
        }
        NetworkCommand::Nodes(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            if args.all
                && args
                    .network
                    .as_ref()
                    .is_some_and(|network| !network.trim().is_empty())
            {
                anyhow::bail!("--all and --network cannot be used together");
            }
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let network_id = if args.all {
                None
            } else {
                Some(network_for(&mesh, &paths, &env, org_id, args.network)?)
            };
            let nodes = with_progress(
                args.output,
                "Listing nodes",
                MeshClient::new(&mesh.resolved)?.list_nodes(org_id, network_id.as_deref()),
            )
            .await?;
            match args.output {
                OutputFormat::Json => print_json(&nodes)?,
                OutputFormat::Text => print!(
                    "{}",
                    format_nodes(
                        style,
                        &mesh,
                        &MeshContext::new(&mesh, Some(org_id)),
                        network_id.as_deref(),
                        &nodes
                    )
                ),
            }
        }
        NetworkCommand::Invite(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let network_id = network_for(&mesh, &paths, &env, org_id, args.network)?;
            let ttl = trimmed_required(&args.ttl, "ttl")?;
            let invite = with_progress(
                args.output,
                "Creating invitation",
                MeshClient::new(&mesh.resolved)?.create_invite(org_id, &network_id, ttl),
            )
            .await?;
            match args.output {
                OutputFormat::Json => print_json(&invite)?,
                OutputFormat::Text => print!(
                    "{}",
                    format_invite(
                        style,
                        &mesh,
                        &MeshContext::new(&mesh, Some(org_id)),
                        &invite
                    )
                ),
            }
        }
        NetworkCommand::Join(args) => {
            let invite_code = trimmed_required(&args.invite_code, "invitation code")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let joined = with_progress(
                OutputFormat::Text,
                "Joining network",
                MeshClient::new(&mesh.resolved)?.join_network(invite_code),
            )
            .await?;
            let select_with = (mesh.kind.is_some()
                && mesh.owner_organization.as_deref() == Some(joined.org_id.as_str()))
            .then(|| mesh.command(&format!("use {}", terminal_text(&joined.network_id))));
            print!(
                "{}",
                format_network_joined(
                    style,
                    &MeshContext::new(&mesh, trimmed_str(&joined.org_id)),
                    &joined.network_id,
                    select_with.as_deref(),
                )
            );
        }
        NetworkCommand::Revoke(args) => {
            let node_name = trimmed_required(&args.node_name, "node name")?;
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
            let network_id = network_for(&mesh, &paths, &env, org_id, args.network)?;
            with_progress(
                OutputFormat::Text,
                "Revoking node",
                MeshClient::new(&mesh.resolved)?.revoke_node(org_id, &network_id, node_name),
            )
            .await?;
            print!(
                "{}",
                format_node_revoked(
                    style,
                    &MeshContext::new(&mesh, Some(org_id)),
                    node_name,
                    &network_id
                )
            );
        }
        NetworkCommand::Enroll { command } => match command {
            NetworkEnrollCommand::Create(args) => {
                let org_id = trimmed_required(&args.org, "organization ID")?;
                let mesh = resolve_network_mesh(globals, &paths, &env, args.mesh_url)?;
                let network_id = network_for(&mesh, &paths, &env, org_id, args.network)?;
                let node_name = args.node_name.as_deref().map(str::trim).unwrap_or("");
                let ttl = trimmed_required(&args.ttl, "ttl")?;
                let enrollment = with_progress(
                    args.output,
                    "Creating node enrollment",
                    MeshClient::new(&mesh.resolved)?.create_node_enrollment(
                        org_id,
                        &network_id,
                        node_name,
                        ttl,
                    ),
                )
                .await?;
                match args.output {
                    OutputFormat::Json => print_json(&enrollment)?,
                    OutputFormat::Text => print!(
                        "{}",
                        format_node_enrollment(
                            style,
                            &mesh,
                            &MeshContext::new(&mesh, Some(org_id)),
                            &enrollment
                        )
                    ),
                }
            }
            NetworkEnrollCommand::Redeem(args) => {
                let code = trimmed_required(&args.enrollment_code, "enrollment code")?;
                let node_name = args.node_name.as_deref().map(str::trim).unwrap_or("");
                let (kind, mesh_url) = redeem_endpoint(globals, &paths, &env, args.mesh_url)?;
                let redeemed = with_progress(
                    OutputFormat::Text,
                    "Enrolling node",
                    MeshClient::unauthenticated(&mesh_url)?.redeem_node_enrollment(code, node_name),
                )
                .await?;
                save_redeemed_node_enrollment(&paths.mesh_data_dir, &redeemed)?;
                let context = MeshContext {
                    label: kind
                        .map(MeshKind::label)
                        .unwrap_or("Mesh service")
                        .to_owned(),
                    endpoint: mesh_url,
                    organization: trimmed_str(&redeemed.org_id).map(str::to_owned),
                };
                print!(
                    "{}",
                    format_node_enrolled(
                        style,
                        &context,
                        &redeemed.node_name,
                        &redeemed.network_id
                    )
                );
            }
        },
    }

    Ok(())
}

/// Where an enrollment code is redeemed. Redemption needs no credential, so
/// a hosted Mesh is reachable without a sign-in.
fn redeem_endpoint(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    mesh_url: Option<String>,
) -> anyhow::Result<(Option<MeshKind>, String)> {
    let mesh_url = trimmed_optional(mesh_url);
    match globals.placement {
        Some(placement) => {
            anyhow::ensure!(
                mesh_url.is_none(),
                "--mesh-url names the Mesh endpoint itself; pass it without {}",
                MeshKind::from_placement(placement).flag()
            );
            match MeshKind::from_placement(placement) {
                MeshKind::Local => Ok((
                    Some(MeshKind::Local),
                    running_local_mesh(&paths.mesh_data_dir)?
                        .context("the local Mesh service is not running; run `cw mesh up`")?
                        .base_url,
                )),
                MeshKind::Cloud => {
                    let server =
                        config::resolve_platform_server_url(globals.server.clone(), paths, env)
                            .context(
                                "no platform server is selected; pass --server or run `cw login`",
                            )?;
                    let hosted =
                        config::derive_hosted_mesh_url_for_server(&server).with_context(|| {
                            format!(
                                "platform server {} has no hosted Mesh endpoint",
                                terminal_text(&server)
                            )
                        })?;
                    Ok((Some(MeshKind::Cloud), hosted))
                }
            }
        }
        None => {
            let url = mesh_url
                .or_else(|| trimmed_optional(env.var(config::CODEWIRE_MESH_URL_ENV)))
                .context("pass --mesh-url URL, the endpoint the enrollment command printed")?;
            let (kind, _) = selection::classify_endpoint(globals, paths, env, &url);
            Ok((kind, url))
        }
    }
}

fn confirm_network_delete(
    context: &MeshContext,
    network_id: &str,
    yes: bool,
) -> anyhow::Result<()> {
    if !yes {
        anyhow::ensure!(
            std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            "network deletion requires --yes when noninteractive"
        );
        eprint!("{}", format_delete_prompt(context, network_id));
        confirm_delete("network", network_id)?;
    }
    Ok(())
}

/// After a confirmed deletion, clear the saved selection only when it is
/// exactly this network on this Mesh endpoint and organization.
pub(crate) fn clear_deleted_network_selection(
    data_dir: &Path,
    deleted_mesh_url: &str,
    org_id: &str,
    network_id: &str,
) -> SelectionCleanup {
    let outcome = (|| -> anyhow::Result<bool> {
        let Some(selection) = load_network_selection(data_dir)? else {
            return Ok(false);
        };
        if !selection.is_for(deleted_mesh_url, org_id) || selection.network_id != network_id {
            return Ok(false);
        }
        remove_network_selection(data_dir)
    })();
    match outcome {
        Ok(true) => SelectionCleanup::Cleared,
        Ok(false) => SelectionCleanup::Untouched,
        Err(error) => SelectionCleanup::Failed(format!("{error:#}")),
    }
}

pub(crate) async fn handle_mesh_command(
    globals: &Globals,
    command: MeshCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    match command {
        MeshCommand::Up(args) => {
            let output = args.output;
            let report = handle_mesh_up(&paths, args).await?;
            print_mesh_up_report(&report, output)
        }
        MeshCommand::Status(args) => {
            let report = mesh_status_report(globals, &paths, &env);
            print_mesh_status_report(&report, args.output, &paths.mesh_data_dir)
        }
        MeshCommand::Down(args) => {
            let report = handle_mesh_down(&paths).await?;
            print_mesh_down_report(&report, args.output)
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshStatusReport {
    pub(crate) mesh_data_dir: String,
    pub(crate) configured: bool,
    pub(crate) mesh_url: Option<String>,
    pub(crate) selected_network: Option<String>,
    pub(crate) auto_connect: bool,
    pub(crate) auth_configured: bool,
    pub(crate) auth_source: Option<config::MeshAuthSource>,
    pub(crate) local: LocalMeshStatus,
    /// The Mesh a network command uses without `--cloud`, `--local` or
    /// `--mesh-url`, and the organization that owns new environments there.
    pub(crate) mesh: Option<MeshKind>,
    pub(crate) organization_id: Option<String>,
    /// Why no default Mesh resolves, when none does.
    pub(crate) default_mesh_error: Option<String>,
    /// The saved network selection, with its Mesh and organization.
    pub(crate) selection: Option<NetworkSelection>,
    /// Status reports configuration and process state only; no route to any
    /// node was probed.
    pub(crate) connectivity: &'static str,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalMeshStatus {
    pub(crate) state: String,
    pub(crate) pid: Option<u32>,
    /// The local service's own organization.
    pub(crate) organization_id: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) listen_addr: Option<String>,
    pub(crate) binary: Option<String>,
    pub(crate) log_path: Option<String>,
    pub(crate) derp: Option<LocalDerpStatus>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalDerpStatus {
    pub(crate) state: String,
    pub(crate) pid: Option<u32>,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[cfg_attr(target_os = "linux", serde(deny_unknown_fields))]
pub(crate) struct LocalMeshRuntime {
    pub(crate) pid: u32,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
    pub(crate) started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) derp: Option<LocalDerpRuntime>,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) custody: Option<retained::ProcessCustody>,
}

/// Credential-free projection consumed by native environment creation. It is
/// intentionally separate from both process state and the protected Mesh
/// config so the ordinary `cw` environment process never deserializes a bearer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalMeshOwnerContext {
    pub(crate) schema_version: u32,
    pub(crate) auth_source: LocalMeshOwnerAuthSource,
    pub(crate) mesh_url: String,
    pub(crate) organization_id: String,
    /// Parse-only: an older cw kept the network selection here. It now
    /// lives in `network_selection.json`; the next write drops it.
    #[serde(default, skip_serializing)]
    pub(crate) selected_network: Option<String>,
    /// Parse-only, with [`LocalMeshOwnerContext::selected_network`].
    #[serde(default, skip_serializing)]
    pub(crate) auto_connect: bool,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalMeshOwnerAuthSource {
    StandaloneLocal,
    HostedCurrent,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[cfg_attr(target_os = "linux", serde(deny_unknown_fields))]
pub(crate) struct LocalDerpRuntime {
    pub(crate) pid: u32,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) custody: Option<retained::ProcessCustody>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LocalMeshStartSpec {
    pub(crate) binary: PathBuf,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) local_identity: config::LocalMeshIdentity,
    pub(crate) log_path: PathBuf,
    pub(crate) derp: Option<LocalDerpStartSpec>,
}

impl std::fmt::Debug for LocalMeshStartSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalMeshStartSpec")
            .field("binary", &self.binary)
            .field("base_url", &self.base_url)
            .field("listen_addr", &self.listen_addr)
            .field("local_identity", &self.local_identity)
            .field("log_path", &self.log_path)
            .field("derp", &self.derp)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalDerpStartSpec {
    pub(crate) binary: PathBuf,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) log_path: PathBuf,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshUpReport {
    pub(crate) started: bool,
    pub(crate) pid: u32,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) derp: Option<LocalDerpRuntime>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshDownReport {
    pub(crate) stopped: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) state: String,
}

pub(crate) fn mesh_status_report(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> MeshStatusReport {
    let selection = load_network_selection(&paths.mesh_data_dir).ok().flatten();
    let default = resolve_network_mesh(globals, paths, env, None);
    let selected_network =
        trimmed_optional(env.var(config::CODEWIRE_MESH_NETWORK_ENV)).or_else(|| {
            selection
                .as_ref()
                .map(|selection| selection.network_id.clone())
        });
    let auto_connect = selection
        .as_ref()
        .is_some_and(|selection| selection.auto_connect);
    let mut local = local_mesh_status(&paths.mesh_data_dir);
    local.organization_id = load_local_mesh_owner_context(&paths.mesh_data_dir)
        .ok()
        .flatten()
        .filter(|owner| {
            owner.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal
                && local
                    .base_url
                    .as_deref()
                    .is_some_and(|url| config::same_mesh_url(url, &owner.mesh_url))
        })
        .map(|owner| owner.organization_id);
    let (mesh, error) = match default {
        Ok(mesh) => (Some(mesh), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    MeshStatusReport {
        mesh_data_dir: paths.mesh_data_dir.display().to_string(),
        configured: mesh.is_some(),
        mesh_url: mesh.as_ref().map(|mesh| mesh.url().to_owned()),
        selected_network,
        auto_connect,
        auth_configured: mesh
            .as_ref()
            .is_some_and(|mesh| mesh.resolved.auth_configured()),
        auth_source: mesh.as_ref().map(|mesh| mesh.resolved.auth_source),
        local,
        mesh: mesh.as_ref().and_then(|mesh| mesh.kind),
        organization_id: mesh.and_then(|mesh| mesh.owner_organization),
        default_mesh_error: error,
        selection,
        connectivity: "not_checked",
    }
}

pub(crate) fn print_mesh_status_report(
    report: &MeshStatusReport,
    output: OutputFormat,
    data_dir: &Path,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        OutputFormat::Text => {
            if report.selection.is_none() {
                print_legacy_selection_notice(data_dir);
            }
            print!("{}", format_mesh_status_report(report));
        }
    }
    Ok(())
}

/// Service state, selection and the default Mesh, kept apart from
/// connectivity, which status never checks.
pub(crate) fn format_mesh_status_report(report: &MeshStatusReport) -> String {
    let mut out = String::new();
    let local = &report.local;
    out.push_str(&format!(
        "Local Mesh service  {}{}\n",
        local.state.replace('_', " "),
        local
            .pid
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default()
    ));
    if let Some(base_url) = local.base_url.as_deref() {
        out.push_str(&format!("  Endpoint      {}\n", terminal_text(base_url)));
    }
    if let Some(organization) = local.organization_id.as_deref() {
        out.push_str(&format!(
            "  Organization  {}\n",
            terminal_text(organization)
        ));
    }
    if let Some(listen_addr) = local.listen_addr.as_deref() {
        out.push_str(&format!("  Listen        {}\n", terminal_text(listen_addr)));
    }
    if let Some(derp) = local.derp.as_ref() {
        out.push_str(&format!(
            "  DERP          {}{} at {}, listening on {}\n",
            derp.state.replace('_', " "),
            derp.pid
                .map(|pid| format!(" (pid {pid})"))
                .unwrap_or_default(),
            terminal_text(&derp.url),
            terminal_text(&derp.listen_addr)
        ));
        out.push_str(&format!(
            "  DERP log      {}\n",
            terminal_text(&derp.log_path)
        ));
    }
    if let Some(log_path) = local.log_path.as_deref() {
        out.push_str(&format!("  Log           {}\n", terminal_text(log_path)));
    }
    match report.selection.as_ref() {
        Some(selection) => {
            out.push_str(&format!(
                "Selected network    {}\n",
                terminal_text(&selection.network_id)
            ));
            out.push_str(&MeshContext::of_selection(selection).render());
            out.push_str(&format!(
                "  New VMs       {}\n",
                if selection.auto_connect {
                    "connect automatically"
                } else {
                    "ask before connecting"
                }
            ));
        }
        None => out.push_str("Selected network    none\n"),
    }
    match (report.mesh, report.mesh_url.as_deref()) {
        (kind, Some(url)) => {
            out.push_str(&format!(
                "Default Mesh        {}\n",
                kind.map(MeshKind::label).unwrap_or("Mesh service")
            ));
            out.push_str(&format!("  Endpoint      {}\n", terminal_text(url)));
            if let Some(organization) = report.organization_id.as_deref() {
                out.push_str(&format!(
                    "  Organization  {}\n",
                    terminal_text(organization)
                ));
            }
            out.push_str(&format!(
                "  Auth          {}\n",
                report
                    .auth_source
                    .map(mesh_auth_source_label)
                    .unwrap_or("not configured")
            ));
        }
        (_, None) => out.push_str(&format!(
            "Default Mesh        none: {}\n",
            terminal_text(report.default_mesh_error.as_deref().unwrap_or("unknown"))
        )),
    }
    out.push_str("Connectivity        not checked\n");
    out.push_str(&format!(
        "Data dir            {}\n",
        terminal_text(&report.mesh_data_dir)
    ));
    out
}

pub(crate) fn mesh_auth_source_label(source: config::MeshAuthSource) -> &'static str {
    match source {
        config::MeshAuthSource::Explicit => "explicit",
        config::MeshAuthSource::MeshEnv => "mesh_env",
        config::MeshAuthSource::MeshConfig => "mesh_config",
        config::MeshAuthSource::ApiKeyEnv => "api_key_env",
        config::MeshAuthSource::PlatformConfig => "platform_config",
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn handle_mesh_up(
    paths: &ResolvePaths,
    args: MeshUpArgs,
) -> anyhow::Result<MeshUpReport> {
    retained::up(paths, args).await
}

#[cfg(target_os = "linux")]
pub(crate) async fn handle_mesh_down(paths: &ResolvePaths) -> anyhow::Result<MeshDownReport> {
    retained::down(paths).await
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_local_mesh_runtime(runtime: &LocalMeshRuntime) -> anyhow::Result<()> {
    retained::validate_runtime(runtime).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn handle_mesh_up(
    paths: &ResolvePaths,
    args: MeshUpArgs,
) -> anyhow::Result<MeshUpReport> {
    let local_identity = config::ensure_local_mesh_identity(&paths.mesh_data_dir)
        .context("initialize standalone Mesh identity")?;
    let selected_network = selection::local_selection_for(
        &paths.mesh_data_dir,
        &args.base_url,
        &local_identity.organization_id,
    );
    if let Some(runtime) = load_local_mesh_runtime(&paths.mesh_data_dir)?
        && local_process_is_running(runtime.pid)
    {
        if local_mesh_runtime_matches_args(&runtime, &args) {
            save_local_mesh_owner_context(
                &paths.mesh_data_dir,
                &LocalMeshOwnerContext {
                    schema_version: 1,
                    auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                    mesh_url: runtime.base_url.clone(),
                    organization_id: local_identity.organization_id,
                    selected_network: None,
                    auto_connect: false,
                },
            )?;
            return Ok(mesh_up_report(false, &runtime));
        }
        stop_local_process(runtime.pid, "local Codewire Mesh").await?;
        if let Some(derp) = runtime.derp.as_ref()
            && local_process_is_running(derp.pid)
        {
            stop_local_process(derp.pid, "local Codewire DERP").await?;
        }
        remove_local_mesh_runtime(&paths.mesh_data_dir)?;
    }
    remove_local_mesh_owner_context(&paths.mesh_data_dir)?;

    let organization_id = local_identity.organization_id.clone();
    let spec = local_mesh_start_spec(paths, &args, local_identity)?;
    let derp = match spec.derp.as_ref() {
        Some(derp_spec) => Some(start_local_derp_process(derp_spec)?),
        None => None,
    };
    let pid = match start_local_mesh_process(&spec) {
        Ok(pid) => pid,
        Err(err) => {
            if let Some(derp) = derp.as_ref() {
                let _ = stop_local_process(derp.pid, "local Codewire DERP").await;
            }
            return Err(err);
        }
    };
    if let Err(error) = wait_for_standalone_mesh_catalog(
        paths,
        &spec,
        &organization_id,
        selected_network.as_deref(),
    )
    .await
    {
        let _ = stop_local_process(pid, "local Codewire Mesh").await;
        if let Some(derp) = derp.as_ref() {
            let _ = stop_local_process(derp.pid, "local Codewire DERP").await;
        }
        return Err(error);
    }
    let runtime = LocalMeshRuntime {
        pid,
        base_url: spec.base_url.clone(),
        listen_addr: spec.listen_addr.clone(),
        binary: spec.binary.display().to_string(),
        log_path: spec.log_path.display().to_string(),
        started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        derp,
    };
    let persist = (|| -> anyhow::Result<()> {
        config::save_mesh_connection(
            &paths.mesh_data_dir,
            &spec.base_url,
            &spec.local_identity.api_key,
        )
        .context("save local mesh config")?;
        save_local_mesh_runtime(&paths.mesh_data_dir, &runtime)?;
        save_local_mesh_owner_context(
            &paths.mesh_data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                mesh_url: runtime.base_url.clone(),
                organization_id,
                selected_network: None,
                auto_connect: false,
            },
        )
    })();
    if let Err(error) = persist {
        let mesh_stop = stop_local_process(runtime.pid, "local Codewire Mesh").await;
        let derp_stop = match runtime.derp.as_ref() {
            Some(derp) => stop_local_process(derp.pid, "local Codewire DERP").await,
            None => Ok(()),
        };
        if let Err(cleanup) = mesh_stop.and(derp_stop) {
            return Err(error.context(format!(
                "started local Mesh state could not be persisted and process cleanup failed: {cleanup}"
            )));
        }
        let _ = remove_local_mesh_runtime(&paths.mesh_data_dir);
        let _ = remove_mesh_owner_context_for_auth_source(
            &paths.mesh_data_dir,
            LocalMeshOwnerAuthSource::StandaloneLocal,
        );
        return Err(error);
    }
    Ok(mesh_up_report(true, &runtime))
}

async fn wait_for_standalone_mesh_catalog(
    paths: &ResolvePaths,
    spec: &LocalMeshStartSpec,
    organization_id: &str,
    selected_network: Option<&str>,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let resolved = config::ResolvedMeshConfig::static_token(
        spec.base_url.clone(),
        &spec.local_identity.api_key,
    )?;
    #[cfg(target_os = "linux")]
    let _ = paths;
    #[cfg(not(target_os = "linux"))]
    let env = OsEnv;
    #[cfg(not(target_os = "linux"))]
    let resolved = config::resolve_mesh(
        config::MeshResolveOptions {
            mesh_url: Some(spec.base_url.clone()),
            auth_token: Some(spec.local_identity.api_key.clone()),
            ..config::MeshResolveOptions::default()
        },
        paths,
        &env,
    )?;
    let client = MeshClient::new(&resolved)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let result = match selected_network {
            Some(network_id) => client.create_network(organization_id, network_id).await,
            None => client.list_networks(organization_id).await.map(|_| ()),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(error);
            }
            Err(error) => {
                return Err(error).context("initialize standalone Mesh catalog");
            }
        }
    }
}

pub(crate) fn local_mesh_runtime_matches_args(
    runtime: &LocalMeshRuntime,
    args: &MeshUpArgs,
) -> bool {
    runtime.base_url == args.base_url
        && runtime.listen_addr == args.listen
        && match (runtime.derp.as_ref(), args.no_derp) {
            (None, true) => true,
            (Some(derp), false) => {
                derp.url == args.derp_url && derp.listen_addr == args.derp_listen
            }
            _ => false,
        }
}

pub(crate) fn print_mesh_up_report(
    report: &MeshUpReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => {
            println!(
                "{} local Codewire Mesh at {} (pid {}).",
                if report.started {
                    "Started"
                } else {
                    "Using existing"
                },
                report.base_url,
                report.pid
            );
            println!("HTTP listen: {}", report.listen_addr);
            if let Some(derp) = report.derp.as_ref() {
                println!("DERP:        {} (pid {})", derp.url, derp.pid);
                println!("DERP listen: {}", derp.listen_addr);
                println!("DERP log:    {}", derp.log_path);
            }
            println!("Log:         {}", report.log_path);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn handle_mesh_down(paths: &ResolvePaths) -> anyhow::Result<MeshDownReport> {
    let Some(runtime) = load_local_mesh_runtime(&paths.mesh_data_dir)? else {
        remove_mesh_owner_context_for_auth_source(
            &paths.mesh_data_dir,
            LocalMeshOwnerAuthSource::StandaloneLocal,
        )?;
        return Ok(MeshDownReport {
            stopped: false,
            pid: None,
            state: "not_running".to_string(),
        });
    };

    let mut stopped = false;
    let mesh_running = local_process_is_running(runtime.pid);
    if mesh_running {
        stop_local_process(runtime.pid, "local Codewire Mesh").await?;
        stopped = true;
    }
    if let Some(derp) = runtime.derp.as_ref()
        && local_process_is_running(derp.pid)
    {
        stop_local_process(derp.pid, "local Codewire DERP").await?;
        stopped = true;
    }
    remove_local_mesh_runtime(&paths.mesh_data_dir)?;
    remove_mesh_owner_context_for_auth_source(
        &paths.mesh_data_dir,
        LocalMeshOwnerAuthSource::StandaloneLocal,
    )?;
    config::clear_local_mesh_connection(&paths.mesh_data_dir, &runtime.base_url)?;
    Ok(MeshDownReport {
        stopped,
        pid: Some(runtime.pid),
        state: if stopped { "stopped" } else { "stale" }.to_string(),
    })
}

pub(crate) fn print_mesh_down_report(
    report: &MeshDownReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => {
            if let Some(pid) = report.pid {
                match report.state.as_str() {
                    "stopped" => println!("Stopped local Codewire Mesh (pid {pid})."),
                    "stale" => println!("Removed stale local Codewire Mesh state (pid {pid})."),
                    _ => println!("Local Codewire Mesh state: {}", report.state),
                }
            } else {
                println!("Local Codewire Mesh is not running.");
            }
        }
    }
    Ok(())
}

pub(crate) fn local_mesh_start_spec(
    paths: &ResolvePaths,
    args: &MeshUpArgs,
    local_identity: config::LocalMeshIdentity,
) -> anyhow::Result<LocalMeshStartSpec> {
    let base_url = trimmed_required(&args.base_url, "base URL")?.to_string();
    let listen_addr = trimmed_required(&args.listen, "listen address")?.to_string();
    let binary = locate_codewire_mesh_binary(args.binary.as_ref())?;
    let derp = if args.no_derp {
        None
    } else {
        Some(LocalDerpStartSpec {
            binary: locate_codewire_derp_binary(args.derp_binary.as_ref())?,
            url: trimmed_required(&args.derp_url, "DERP URL")?.to_string(),
            listen_addr: trimmed_required(&args.derp_listen, "DERP listen address")?.to_string(),
            log_path: paths.mesh_data_dir.join(LOCAL_DERP_LOG_FILE),
        })
    };
    Ok(LocalMeshStartSpec {
        binary,
        base_url,
        listen_addr,
        local_identity,
        log_path: paths.mesh_data_dir.join(LOCAL_MESH_LOG_FILE),
        derp,
    })
}

pub(crate) fn locate_codewire_mesh_binary(
    override_path: Option<&PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path.clone());
    }
    #[cfg(target_os = "linux")]
    {
        fs::canonicalize(env::current_exe().context("locate retained cw helper executable")?)
            .context("resolve retained cw helper executable")
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Ok(current) = env::current_exe()
            && let Some(dir) = current.parent()
        {
            let sibling = dir.join("codewire-mesh");
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
        Ok(PathBuf::from("codewire-mesh"))
    }
}

pub(crate) fn locate_codewire_derp_binary(
    override_path: Option<&PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path.clone());
    }
    #[cfg(target_os = "linux")]
    {
        fs::canonicalize(env::current_exe().context("locate retained cw helper executable")?)
            .context("resolve retained cw helper executable")
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Ok(current) = env::current_exe()
            && let Some(dir) = current.parent()
        {
            let sibling = dir.join("codewire-derp");
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
        Ok(PathBuf::from("codewire-derp"))
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn start_local_mesh_process(spec: &LocalMeshStartSpec) -> anyhow::Result<u32> {
    let executable = resolve_local_service_executable(&spec.binary, "codewire-mesh")?;
    if let Some(parent) = spec.log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .with_context(|| format!("open {}", spec.log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("clone {}", spec.log_path.display()))?;
    let mut command = ProcessCommand::new(&executable);
    command
        .arg("--base-url")
        .arg(&spec.base_url)
        .arg("--listen")
        .arg(&spec.listen_addr)
        // The local API key remains a standard cw_ credential. Keep it out
        // of argv; only hash-only verification material reaches the Mesh
        // process. The client retains the credential; Mesh itself no longer
        // accepts a separate server auth-token mode.
        .env_clear()
        .envs(local_service_logging_environment())
        .env(
            "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID",
            &spec.local_identity.organization_id,
        )
        .env(
            "CODEWIRE_MESH_LOCAL_API_KEY_HASH",
            spec.local_identity.api_key_hash(),
        )
        .stdin(Stdio::null());
    if let Some(derp) = spec.derp.as_ref() {
        command.arg("--derp-url").arg(&derp.url);
    }
    let mut child = command
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| {
            format!(
                "start codewire-mesh via {} (install codewire-mesh or pass --binary)",
                spec.binary.display()
            )
        })?;

    std::thread::sleep(Duration::from_millis(150));
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("check codewire-mesh pid {}", child.id()))?
    {
        anyhow::bail!(
            "codewire-mesh exited immediately with {status}; see {}",
            spec.log_path.display()
        );
    }
    Ok(child.id())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn start_local_derp_process(
    spec: &LocalDerpStartSpec,
) -> anyhow::Result<LocalDerpRuntime> {
    let executable = resolve_local_service_executable(&spec.binary, "codewire-derp")?;
    if let Some(parent) = spec.log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .with_context(|| format!("open {}", spec.log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("clone {}", spec.log_path.display()))?;
    let mut child = ProcessCommand::new(&executable);
    child
        // Standalone Mesh advertises its loopback DERP URL with the
        // InsecureForTests marker so the transport can admit this one
        // self-signed endpoint. The relay itself still runs encrypted TLS;
        // never turn the managed local process into a plaintext DERP server.
        .env_clear()
        .envs(local_service_logging_environment())
        .env("PORT", "-1")
        .env("TLS_LISTEN_ADDR", &spec.listen_addr)
        .env("STUN_LISTEN_ADDR", "-1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));

    let mut child = child.spawn().with_context(|| {
        format!(
            "start codewire-derp via {} (install codewire-derp, pass --derp-binary, or use --no-derp)",
            spec.binary.display()
        )
    })?;

    std::thread::sleep(Duration::from_millis(150));
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("check codewire-derp pid {}", child.id()))?
    {
        anyhow::bail!(
            "codewire-derp exited immediately with {status}; see {}",
            spec.log_path.display()
        );
    }

    Ok(LocalDerpRuntime {
        pid: child.id(),
        url: spec.url.clone(),
        listen_addr: spec.listen_addr.clone(),
        binary: spec.binary.display().to_string(),
        log_path: spec.log_path.display().to_string(),
    })
}

fn local_service_logging_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    ["RUST_LOG", "RUST_BACKTRACE"]
        .into_iter()
        .filter_map(|name| env::var_os(name).map(|value| (std::ffi::OsString::from(name), value)))
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn resolve_local_service_executable(binary: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let direct = binary.is_absolute() || binary.components().count() > 1;
    let candidates = if direct {
        vec![binary.to_path_buf()]
    } else {
        let path = env::var_os("PATH").ok_or_else(|| {
            anyhow::anyhow!("PATH is unavailable; install {label} or pass its path")
        })?;
        env::split_paths(&path)
            .flat_map(|directory| local_executable_candidates(&directory, binary))
            .collect()
    };
    for candidate in candidates {
        if !local_executable_file(&candidate) {
            continue;
        }
        return fs::canonicalize(&candidate)
            .with_context(|| format!("resolve {label} executable {}", candidate.display()));
    }
    anyhow::bail!(
        "{label} executable {} was not found or executable",
        binary.display()
    )
}

#[cfg(not(target_os = "linux"))]
fn local_executable_candidates(directory: &Path, binary: &Path) -> Vec<PathBuf> {
    let candidate = directory.join(binary);
    #[cfg(windows)]
    {
        if candidate.extension().is_none() {
            return vec![candidate.clone(), candidate.with_extension("exe")];
        }
    }
    vec![candidate]
}

#[cfg(not(target_os = "linux"))]
fn local_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn stop_local_process(pid: u32, label: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let status = ProcessCommand::new("kill")
            .arg(pid.to_string())
            .status()
            .with_context(|| format!("stop {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to stop {label} pid {pid}: {status}");
        }
        if wait_for_local_process_exit(pid, Duration::from_secs(2)).await {
            return Ok(());
        }
        let status = ProcessCommand::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status()
            .with_context(|| format!("kill unresponsive {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to kill unresponsive {label} pid {pid}: {status}");
        }
        if !wait_for_local_process_exit(pid, Duration::from_secs(2)).await {
            anyhow::bail!("{label} pid {pid} did not exit after SIGKILL");
        }
    }
    #[cfg(windows)]
    {
        let status = ProcessCommand::new("taskkill")
            .arg("/PID")
            .arg(pid.to_string())
            .arg("/T")
            .status()
            .with_context(|| format!("stop {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to stop {label} pid {pid}: {status}");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_local_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if !local_process_is_running(pid) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn local_mesh_status(data_dir: &Path) -> LocalMeshStatus {
    let unresolved = retained::unresolved_start(data_dir).unwrap_or(true);
    let runtime = match load_local_mesh_runtime(data_dir) {
        Ok(Some(runtime)) => runtime,
        outcome => {
            return LocalMeshStatus {
                state: if outcome.is_err() || unresolved {
                    "unknown"
                } else {
                    "not_running"
                }
                .to_owned(),
                pid: None,
                organization_id: None,
                base_url: None,
                listen_addr: None,
                binary: None,
                log_path: None,
                derp: None,
            };
        }
    };
    let known = !unresolved && validate_local_mesh_runtime(&runtime).is_ok();
    LocalMeshStatus {
        state: if known { "running" } else { "unknown" }.to_owned(),
        pid: Some(runtime.pid),
        organization_id: None,
        base_url: Some(runtime.base_url),
        listen_addr: Some(runtime.listen_addr),
        binary: Some(runtime.binary),
        log_path: Some(runtime.log_path),
        derp: runtime.derp.map(|derp| LocalDerpStatus {
            state: if known { "running" } else { "unknown" }.to_owned(),
            pid: Some(derp.pid),
            url: derp.url,
            listen_addr: derp.listen_addr,
            binary: derp.binary,
            log_path: derp.log_path,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn local_mesh_status(data_dir: &Path) -> LocalMeshStatus {
    let runtime = load_local_mesh_runtime(data_dir).ok().flatten();
    let Some(runtime) = runtime else {
        return LocalMeshStatus {
            state: "not_running".to_string(),
            pid: None,
            organization_id: None,
            base_url: None,
            listen_addr: None,
            binary: None,
            log_path: None,
            derp: None,
        };
    };
    let running = local_process_is_running(runtime.pid);
    let derp = runtime.derp.map(|derp| LocalDerpStatus {
        state: if local_process_is_running(derp.pid) {
            "running".to_string()
        } else {
            "stale".to_string()
        },
        pid: Some(derp.pid),
        url: derp.url,
        listen_addr: derp.listen_addr,
        binary: derp.binary,
        log_path: derp.log_path,
    });
    LocalMeshStatus {
        state: if running { "running" } else { "stale" }.to_string(),
        pid: Some(runtime.pid),
        organization_id: None,
        base_url: Some(runtime.base_url),
        listen_addr: Some(runtime.listen_addr),
        binary: Some(runtime.binary),
        log_path: Some(runtime.log_path),
        derp,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn load_local_mesh_runtime(data_dir: &Path) -> anyhow::Result<Option<LocalMeshRuntime>> {
    let Some(directory) = retained::StateDir::open(data_dir, false)? else {
        return Ok(None);
    };
    directory
        .read(LOCAL_MESH_RUNTIME_FILE)?
        .map(|bytes| serde_json::from_slice(&bytes).context("parse private local Mesh runtime"))
        .transpose()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn load_local_mesh_runtime(data_dir: &Path) -> anyhow::Result<Option<LocalMeshRuntime>> {
    let path = local_mesh_runtime_path(data_dir);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    serde_json::from_str(&data)
        .map(Some)
        .with_context(|| format!("parse {}", path.display()))
}

pub(crate) fn save_local_mesh_runtime(
    data_dir: &Path,
    runtime: &LocalMeshRuntime,
) -> anyhow::Result<()> {
    let path = local_mesh_runtime_path(data_dir);
    let data = serde_json::to_vec_pretty(runtime)?;
    write_owner_only_mesh_file(data_dir, &path, &data)
}

fn remove_mesh_owner_context_for_auth_source(
    data_dir: &Path,
    auth_source: LocalMeshOwnerAuthSource,
) -> anyhow::Result<()> {
    if load_local_mesh_owner_context(data_dir)?
        .is_some_and(|context| context.auth_source == auth_source)
    {
        remove_local_mesh_owner_context(data_dir)?;
    }
    Ok(())
}

pub(crate) fn load_local_mesh_owner_context(
    data_dir: &Path,
) -> anyhow::Result<Option<LocalMeshOwnerContext>> {
    #[cfg(target_os = "linux")]
    let context: LocalMeshOwnerContext = {
        let Some(directory) = retained::StateDir::open(data_dir, false)? else {
            return Ok(None);
        };
        let Some(data) = directory.read(LOCAL_MESH_OWNER_CONTEXT_FILE)? else {
            return Ok(None);
        };
        serde_json::from_slice(&data).context("parse private local Mesh owner projection")?
    };
    #[cfg(not(target_os = "linux"))]
    let context: LocalMeshOwnerContext = {
        let path = local_mesh_owner_context_path(data_dir);
        let data = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?
    };
    if context.schema_version != 1 {
        anyhow::bail!(
            "unsupported local Mesh owner context schema {}",
            context.schema_version
        );
    }
    Ok(Some(context))
}

pub(crate) fn save_local_mesh_owner_context(
    data_dir: &Path,
    context: &LocalMeshOwnerContext,
) -> anyhow::Result<()> {
    if context.schema_version != 1 {
        anyhow::bail!("local Mesh owner context schema must be 1");
    }
    let path = local_mesh_owner_context_path(data_dir);
    let data = serde_json::to_vec_pretty(context)?;
    write_owner_only_mesh_file(data_dir, &path, &data)
}

#[cfg(target_os = "linux")]
fn write_owner_only_mesh_file(data_dir: &Path, path: &Path, data: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.parent() == Some(data_dir),
        "local Mesh state path is outside its private directory"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid local Mesh state name")?;
    let directory =
        retained::StateDir::open(data_dir, true)?.context("local Mesh directory is absent")?;
    directory.write(name, data)
}

#[cfg(not(target_os = "linux"))]
fn write_owner_only_mesh_file(data_dir: &Path, path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    fs::create_dir_all(data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", data_dir.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protect {}", path.display()))?;
    }
    file.write_all(data)
        .with_context(|| format!("write {}", path.display()))
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_local_mesh_owner_context(data_dir: &Path) -> anyhow::Result<()> {
    let Some(directory) = retained::StateDir::open(data_dir, false)? else {
        return Ok(());
    };
    directory.remove(LOCAL_MESH_OWNER_CONTEXT_FILE, None)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn remove_local_mesh_owner_context(data_dir: &Path) -> anyhow::Result<()> {
    let path = local_mesh_owner_context_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub(crate) fn local_mesh_owner_context_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCAL_MESH_OWNER_CONTEXT_FILE)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn remove_local_mesh_runtime(data_dir: &Path) -> anyhow::Result<()> {
    let path = local_mesh_runtime_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub(crate) fn local_mesh_runtime_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCAL_MESH_RUNTIME_FILE)
}

pub(crate) fn mesh_up_report(started: bool, runtime: &LocalMeshRuntime) -> MeshUpReport {
    MeshUpReport {
        started,
        pid: runtime.pid,
        base_url: runtime.base_url.clone(),
        listen_addr: runtime.listen_addr.clone(),
        binary: runtime.binary.clone(),
        log_path: runtime.log_path.clone(),
        derp: runtime.derp.clone(),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn local_process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat
                .rsplit_once(") ")
                .and_then(|(_, suffix)| suffix.as_bytes().first())
                .copied();
            !matches!(state, Some(b'Z' | b'X') | None)
        } else {
            false
        }
        #[cfg(not(target_os = "linux"))]
        ProcessCommand::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        ProcessCommand::new("tasklist")
            .arg("/FI")
            .arg(format!("PID eq {pid}"))
            .output()
            .map(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
