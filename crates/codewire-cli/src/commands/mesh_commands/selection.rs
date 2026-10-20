//! Which Mesh a network command talks to, and the saved network selection.
//!
//! `--cloud` is the selected platform's hosted Mesh, `--local` the local
//! Mesh service `cw mesh up` runs, `--mesh-url` one exact endpoint. Without
//! any of them a command uses the Mesh of the saved selection, else the one
//! Mesh that is available. A running local Mesh never redirects a cloud
//! operation, and a cloud sign-in never replaces the local service.

use std::path::Path;

use super::*;
use crate::commands::progress::terminal_text;

/// The saved network selection: Mesh, endpoint, organization and network
/// together. Credential-free; mode 0600 beside the other Mesh state.
pub(crate) const NETWORK_SELECTION_FILE: &str = "network_selection.json";
const NETWORK_SELECTION_SCHEMA: u32 = 1;

/// Which Mesh service owns a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MeshKind {
    /// The selected platform's hosted Mesh.
    Cloud,
    /// The local Mesh service `cw mesh up` runs.
    Local,
}

impl MeshKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            MeshKind::Cloud => "Codewire Cloud Mesh",
            MeshKind::Local => "Local Mesh service",
        }
    }

    pub(crate) fn flag(self) -> &'static str {
        match self {
            MeshKind::Cloud => "--cloud",
            MeshKind::Local => "--local",
        }
    }

    /// The `cloud:` / `local:` network reference prefix.
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            MeshKind::Cloud => "cloud",
            MeshKind::Local => "local",
        }
    }

    pub(crate) fn from_placement(placement: EnvironmentPlacement) -> Self {
        match placement {
            EnvironmentPlacement::Platform => MeshKind::Cloud,
            EnvironmentPlacement::Local => MeshKind::Local,
        }
    }
}

/// The network new environments join, scoped to one Mesh endpoint and
/// organization. Selecting never attaches an existing environment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkSelection {
    pub(crate) schema_version: u32,
    pub(crate) mesh: MeshKind,
    pub(crate) mesh_url: String,
    pub(crate) organization_id: String,
    pub(crate) network_id: String,
    pub(crate) auto_connect: bool,
}

impl NetworkSelection {
    pub(crate) fn new(
        mesh: MeshKind,
        mesh_url: &str,
        organization_id: &str,
        network_id: &str,
        auto_connect: bool,
    ) -> Self {
        Self {
            schema_version: NETWORK_SELECTION_SCHEMA,
            mesh,
            mesh_url: mesh_url.trim().trim_end_matches('/').to_owned(),
            organization_id: organization_id.trim().to_owned(),
            network_id: network_id.trim().to_owned(),
            auto_connect,
        }
    }

    /// Whether this selection is for exactly this Mesh endpoint and
    /// organization. A same-named network elsewhere never matches.
    pub(crate) fn is_for(&self, mesh_url: &str, organization_id: &str) -> bool {
        config::same_mesh_url(&self.mesh_url, mesh_url)
            && self.organization_id == organization_id.trim()
    }

    /// `cloud:work` or `local:work`.
    pub(crate) fn reference(&self) -> String {
        format!("{}:{}", self.mesh.prefix(), self.network_id)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == NETWORK_SELECTION_SCHEMA,
            "unsupported network selection schema {}; run `cw network clear`",
            self.schema_version
        );
        for (label, value) in [
            ("Mesh endpoint", &self.mesh_url),
            ("organization", &self.organization_id),
            ("network", &self.network_id),
        ] {
            anyhow::ensure!(
                !value.trim().is_empty() && value.trim() == value,
                "the saved network selection has an invalid {label}; run `cw network clear`"
            );
        }
        Ok(())
    }
}

pub(crate) fn network_selection_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NETWORK_SELECTION_FILE)
}

pub(crate) fn load_network_selection(data_dir: &Path) -> anyhow::Result<Option<NetworkSelection>> {
    #[cfg(target_os = "linux")]
    let data = {
        let Some(directory) = retained::StateDir::open(data_dir, false)? else {
            return Ok(None);
        };
        let Some(data) = directory.read(NETWORK_SELECTION_FILE)? else {
            return Ok(None);
        };
        data
    };
    #[cfg(not(target_os = "linux"))]
    let data = match fs::read(network_selection_path(data_dir)) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("read the saved network selection");
        }
    };
    let selection: NetworkSelection = serde_json::from_slice(&data)
        .context("parse the saved network selection; run `cw network clear`")?;
    selection.validate()?;
    Ok(Some(selection))
}

pub(crate) fn save_network_selection(
    data_dir: &Path,
    selection: &NetworkSelection,
) -> anyhow::Result<()> {
    selection.validate()?;
    let mut data = serde_json::to_vec_pretty(selection)?;
    data.push(b'\n');
    write_owner_only_mesh_file(data_dir, &network_selection_path(data_dir), &data)
}

/// Removes the saved selection; `false` when there was none.
pub(crate) fn remove_network_selection(data_dir: &Path) -> anyhow::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let Some(directory) = retained::StateDir::open(data_dir, false)? else {
            return Ok(false);
        };
        let present = directory.read(NETWORK_SELECTION_FILE)?.is_some();
        directory.remove(NETWORK_SELECTION_FILE, None)?;
        Ok(present)
    }
    #[cfg(not(target_os = "linux"))]
    match fs::remove_file(network_selection_path(data_dir)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("remove the saved network selection"),
    }
}

/// The network name an older cw saved without its Mesh, while no current
/// selection exists. It is never used; [`legacy_selection_notice`] names it.
pub(crate) fn legacy_network_selection(data_dir: &Path) -> Option<String> {
    if !matches!(load_network_selection(data_dir), Ok(None)) {
        return None;
    }
    let from_config = config::load_mesh_config(data_dir)
        .ok()
        .and_then(|config| config.mesh_selected_network)
        .and_then(|name| trimmed_str(&name).map(str::to_owned));
    from_config.or_else(|| {
        load_local_mesh_owner_context(data_dir)
            .ok()
            .flatten()
            .and_then(|owner| owner.selected_network)
            .and_then(|name| trimmed_str(&name).map(str::to_owned))
    })
}

pub(crate) fn legacy_selection_notice(name: &str) -> String {
    format!(
        "The saved network selection {name} is from an older cw and does not record its Mesh; run `cw --cloud network use {name}` or `cw --local network use {name}`."
    )
}

/// Says once on stderr that an older selection exists and is not used.
pub(crate) fn print_legacy_selection_notice(data_dir: &Path) {
    if let Some(name) = legacy_network_selection(data_dir) {
        eprintln!("{}", legacy_selection_notice(&terminal_text(&name)));
    }
}

/// The saved local network a starting local Mesh service at `base_url`
/// recreates: its catalog is in memory, and the selection outlives it.
pub(crate) fn local_selection_for(
    data_dir: &Path,
    base_url: &str,
    organization_id: &str,
) -> Option<String> {
    load_network_selection(data_dir)
        .ok()
        .flatten()
        .filter(|selection| {
            selection.mesh == MeshKind::Local && selection.is_for(base_url, organization_id)
        })
        .map(|selection| selection.network_id)
}

/// The running local Mesh service, from its retained record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalMeshService {
    pub(crate) base_url: String,
    pub(crate) organization_id: String,
}

/// The local Mesh service when it runs and its record is this user's own;
/// `Ok(None)` when it is not running.
pub(crate) fn running_local_mesh(data_dir: &Path) -> anyhow::Result<Option<LocalMeshService>> {
    let Some(runtime) = load_local_mesh_runtime(data_dir)? else {
        return Ok(None);
    };
    let owner = load_local_mesh_owner_context(data_dir)?
        .filter(|owner| owner.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal)
        .context(
            "the local Mesh service has no owner record; run `cw mesh down`, then `cw mesh up`",
        )?;
    #[cfg(target_os = "linux")]
    retained::validate_owner(&runtime, &owner)
        .context("the local Mesh service's state is unknown; run `cw mesh status`")?;
    #[cfg(not(target_os = "linux"))]
    {
        if !local_process_is_running(runtime.pid) {
            return Ok(None);
        }
        anyhow::ensure!(
            config::same_mesh_url(&owner.mesh_url, &runtime.base_url),
            "the local Mesh owner record differs from the running service; run `cw mesh down`, then `cw mesh up`"
        );
    }
    Ok(Some(LocalMeshService {
        base_url: runtime.base_url,
        organization_id: owner.organization_id,
    }))
}

/// The Mesh a network command talks to, with the organization that owns
/// new environments on it when one is known.
#[derive(Clone, Debug)]
pub(crate) struct NetworkMesh {
    /// `None` for an explicit endpoint that is neither the hosted Mesh nor
    /// the local Mesh service.
    pub(crate) kind: Option<MeshKind>,
    pub(crate) resolved: config::ResolvedMeshConfig,
    pub(crate) owner_organization: Option<String>,
}

impl NetworkMesh {
    pub(crate) fn url(&self) -> &str {
        &self.resolved.mesh_url
    }

    pub(crate) fn label(&self) -> &'static str {
        self.kind.map(MeshKind::label).unwrap_or("Mesh service")
    }

    /// The selector that reaches this Mesh again, for repair commands.
    pub(crate) fn selector(&self) -> String {
        match self.kind {
            Some(kind) => kind.flag().to_owned(),
            None => format!("--mesh-url {}", terminal_text(self.url())),
        }
    }

    /// `cw --cloud network ARGS`, or `cw network ARGS --mesh-url URL`.
    pub(crate) fn command(&self, args: &str) -> String {
        match self.kind {
            Some(kind) => format!("cw {} network {args}", kind.flag()),
            None => format!("cw network {args} {}", self.selector()),
        }
    }
}

/// Resolves the Mesh for a network command (see the module comment).
pub(crate) fn resolve_network_mesh(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    mesh_url: Option<String>,
) -> anyhow::Result<NetworkMesh> {
    let mesh_url = trimmed_optional(mesh_url);
    if let Some(placement) = globals.placement {
        anyhow::ensure!(
            mesh_url.is_none(),
            "--mesh-url names the Mesh endpoint itself; pass it without {}",
            MeshKind::from_placement(placement).flag()
        );
        return mesh_of_kind(globals, paths, env, MeshKind::from_placement(placement));
    }
    if let Some(url) = mesh_url.or_else(|| trimmed_optional(env.var(config::CODEWIRE_MESH_URL_ENV)))
    {
        return explicit_mesh(globals, paths, env, url);
    }
    if let Some(selection) = load_network_selection(&paths.mesh_data_dir)? {
        return mesh_of_kind(globals, paths, env, selection.mesh);
    }
    match available_mesh(globals, paths, env)? {
        Some(kind) => mesh_of_kind(globals, paths, env, kind),
        None => anyhow::bail!(
            "no Mesh is available: run `cw login` for Codewire Cloud Mesh, or `cw mesh up` for a local Mesh service"
        ),
    }
}

/// The one Mesh available without a selector: the running local service or
/// the signed-in cloud. Both available is ambiguous and refused.
pub(crate) fn available_mesh(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<Option<MeshKind>> {
    let local = running_local_mesh(&paths.mesh_data_dir)
        .ok()
        .flatten()
        .is_some();
    let cloud = resolve_platform(globals, paths, env).is_ok();
    match (local, cloud) {
        (true, true) => anyhow::bail!(
            "both the local Mesh service and Codewire Cloud Mesh are available; pass --local or --cloud"
        ),
        (true, false) => Ok(Some(MeshKind::Local)),
        (false, true) => Ok(Some(MeshKind::Cloud)),
        (false, false) => Ok(None),
    }
}

pub(crate) fn mesh_of_kind(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    kind: MeshKind,
) -> anyhow::Result<NetworkMesh> {
    match kind {
        MeshKind::Cloud => cloud_mesh(globals, paths, env),
        MeshKind::Local => local_mesh(paths),
    }
}

/// The hosted Mesh of the selected platform, authenticated only with the
/// platform's own credential.
fn cloud_mesh(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<NetworkMesh> {
    let platform = resolve_platform(globals, paths, env)
        .map_err(|error| anyhow::anyhow!("Codewire Cloud Mesh needs a sign-in: {error:#}"))?;
    let mesh_url = hosted_mesh_url(&platform)?;
    let auth_source = if platform.used_config_token {
        config::MeshAuthSource::PlatformConfig
    } else {
        config::MeshAuthSource::ApiKeyEnv
    };
    let resolved = config::resolve_mesh_with_token_provider(
        config::MeshResolveOptions {
            mesh_url: Some(mesh_url),
            auth_token: None,
            network_id: None,
            platform_server_url: Some(platform.server_url.clone()),
        },
        paths,
        env,
        platform.token_provider()?,
        auth_source,
    )?;
    Ok(NetworkMesh {
        kind: Some(MeshKind::Cloud),
        resolved,
        owner_organization: platform_owner_organization(paths, &platform),
    })
}

pub(crate) fn hosted_mesh_url(platform: &config::ResolvedPlatformConfig) -> anyhow::Result<String> {
    config::derive_hosted_mesh_url_for_server(&platform.server_url).with_context(|| {
        format!(
            "platform server {} has no hosted Mesh endpoint",
            terminal_text(&platform.server_url)
        )
    })
}

/// The organization new environments are owned by on this platform: the
/// saved default organization of this same server. Never searched for.
pub(crate) fn platform_owner_organization(
    paths: &ResolvePaths,
    platform: &config::ResolvedPlatformConfig,
) -> Option<String> {
    config::load_platform_config(&paths.platform_config_dir)
        .ok()
        .filter(|saved| config::same_server_url(&saved.server_url, &platform.server_url))
        .and_then(|saved| trimmed_str(&saved.default_org).map(str::to_owned))
}

/// The local Mesh service, authenticated with its own local key.
fn local_mesh(paths: &ResolvePaths) -> anyhow::Result<NetworkMesh> {
    let service = running_local_mesh(&paths.mesh_data_dir)?
        .context("the local Mesh service is not running; run `cw mesh up`")?;
    let identity = config::load_mesh_config(&paths.mesh_data_dir)?
        .local_identity
        .filter(|identity| {
            identity.is_complete() && identity.organization_id == service.organization_id
        })
        .context(
            "the local Mesh service's identity is missing; run `cw mesh down`, then `cw mesh up`",
        )?;
    let resolved = config::ResolvedMeshConfig::static_token_from(
        service.base_url.clone(),
        &identity.api_key,
        config::MeshAuthSource::MeshConfig,
    )?;
    Ok(NetworkMesh {
        kind: Some(MeshKind::Local),
        resolved,
        owner_organization: Some(service.organization_id),
    })
}

/// One exact endpoint. It is named as the hosted or local Mesh only when it
/// is exactly that endpoint.
fn explicit_mesh(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    url: String,
) -> anyhow::Result<NetworkMesh> {
    let resolved = config::resolve_mesh(
        config::MeshResolveOptions {
            mesh_url: Some(url.clone()),
            auth_token: None,
            network_id: None,
            platform_server_url: globals.server.clone(),
        },
        paths,
        env,
    )?;
    let (kind, owner_organization) = classify_endpoint(globals, paths, env, &url);
    Ok(NetworkMesh {
        kind,
        resolved,
        owner_organization,
    })
}

/// Which Mesh `url` is, by exact endpoint, with its owner organization.
pub(crate) fn classify_endpoint(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    url: &str,
) -> (Option<MeshKind>, Option<String>) {
    if let Ok(Some(service)) = running_local_mesh(&paths.mesh_data_dir)
        && config::same_mesh_url(&service.base_url, url)
    {
        return (Some(MeshKind::Local), Some(service.organization_id));
    }
    if let Ok(platform) = resolve_platform(globals, paths, env)
        && let Ok(hosted) = hosted_mesh_url(&platform)
        && config::same_mesh_url(&hosted, url)
    {
        return (
            Some(MeshKind::Cloud),
            platform_owner_organization(paths, &platform),
        );
    }
    (None, None)
}

/// The network a command acts on: `--network`, `CODEWIRE_MESH_NETWORK`, or
/// the saved selection when it is for this same endpoint and organization.
pub(crate) fn network_for(
    mesh: &NetworkMesh,
    paths: &ResolvePaths,
    env: &impl config::Env,
    organization_id: &str,
    requested: Option<String>,
) -> anyhow::Result<String> {
    if let Some(network) = trimmed_optional(requested)
        .or_else(|| trimmed_optional(env.var(config::CODEWIRE_MESH_NETWORK_ENV)))
    {
        return Ok(network);
    }
    if let Some(selection) = load_network_selection(&paths.mesh_data_dir)?
        && selection.is_for(mesh.url(), organization_id)
    {
        return Ok(selection.network_id);
    }
    print_legacy_selection_notice(&paths.mesh_data_dir);
    anyhow::bail!(
        "no network is selected for organization {} on {} ({}); pass --network NAME",
        terminal_text(organization_id),
        mesh.label(),
        terminal_text(mesh.url())
    )
}

/// A `--network` value on environment creation: `cloud:NAME`, `local:NAME`
/// or a bare NAME. Distinct from credential and secret references, whose
/// `platform:` prefix names a store, not a Mesh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetworkReference {
    pub(crate) mesh: Option<MeshKind>,
    pub(crate) network: String,
}

impl NetworkReference {
    pub(crate) fn parse(raw: &str) -> anyhow::Result<Self> {
        let raw = raw.trim();
        let (mesh, network) = match raw.split_once(':') {
            Some(("cloud", network)) => (Some(MeshKind::Cloud), network),
            Some(("local", network)) => (Some(MeshKind::Local), network),
            Some((prefix, _)) => anyhow::bail!(
                "network {raw:?} has an unknown Mesh {prefix:?}; use cloud:NAME, local:NAME or NAME"
            ),
            None => (None, raw),
        };
        let network = network.trim();
        anyhow::ensure!(
            !network.is_empty() && !network.contains(':'),
            "network reference {raw:?} must be cloud:NAME, local:NAME or NAME"
        );
        Ok(Self {
            mesh,
            network: network.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_references_name_their_mesh_or_none() {
        assert_eq!(
            NetworkReference::parse(" cloud:work ").unwrap(),
            NetworkReference {
                mesh: Some(MeshKind::Cloud),
                network: "work".into()
            }
        );
        assert_eq!(
            NetworkReference::parse("local:dev").unwrap(),
            NetworkReference {
                mesh: Some(MeshKind::Local),
                network: "dev".into()
            }
        );
        assert_eq!(
            NetworkReference::parse("work").unwrap(),
            NetworkReference {
                mesh: None,
                network: "work".into()
            }
        );
        for bad in ["platform:work", "cloud:", "local:a:b", "", "user/work:x"] {
            assert!(NetworkReference::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn selection_matches_only_its_endpoint_and_organization() {
        let selection = NetworkSelection::new(
            MeshKind::Cloud,
            "https://mesh.example.test/",
            "org-alpha",
            "work",
            false,
        );
        assert!(selection.is_for("https://mesh.example.test", "org-alpha"));
        assert!(!selection.is_for("http://127.0.0.1:18090", "org-alpha"));
        assert!(!selection.is_for("https://mesh.example.test", "org-beta"));
        assert_eq!(selection.reference(), "cloud:work");
    }
}
