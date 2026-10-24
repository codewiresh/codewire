//! The one environment inventory behind `cw ls`, the `cw use` picker and
//! `cw use ENV`: local VMs, cloud environments and trusted host
//! environments, each row with its location, state, allocated size,
//! credential profile reference and saved network attachment, and each
//! location's own outcome. A location that could not be listed is reported
//! as unavailable, never as empty.

use super::lifecycle_output::{credential_profile_names, credential_ref, listed_profile_name};
use super::progress::terminal_text;
use super::*;
use crate::config::selection::{EnvironmentSelection, SelectionLocation};
use crate::output::{Allocation, Capabilities, NetworkRef, OutputMode, SourceRef, Status, Style};

/// Where an inventory row runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Location {
    Local,
    Cloud,
    Host,
}

impl Location {
    /// The LOCATION column.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Location::Local => "local",
            Location::Cloud => "cloud",
            Location::Host => "host",
        }
    }

    /// What one row is: `local VM`, `cloud VM`, `trusted host`.
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Location::Local => "local VM",
            Location::Cloud => "cloud VM",
            Location::Host => "trusted host",
        }
    }

    /// What the location lists: `local VMs`, `cloud environments`.
    pub(crate) fn listing(self) -> &'static str {
        match self {
            Location::Local => "local VMs",
            Location::Cloud => "cloud environments",
            Location::Host => "trusted host environments",
        }
    }

    /// The global flag that selects this location, as a `cw` prefix.
    pub(crate) fn command_prefix(self) -> &'static str {
        match self {
            Location::Local => "cw --local",
            Location::Cloud => "cw --cloud",
            Location::Host => "cw",
        }
    }

    fn selection(self) -> SelectionLocation {
        match self {
            Location::Local => SelectionLocation::Local,
            Location::Cloud => SelectionLocation::Cloud,
            Location::Host => SelectionLocation::Host,
        }
    }

    pub(crate) fn from_selection(location: SelectionLocation) -> Self {
        match location {
            SelectionLocation::Local => Location::Local,
            SelectionLocation::Cloud => Location::Cloud,
            SelectionLocation::Host => Location::Host,
        }
    }
}

/// The global placement as the location prefix of a suggested command.
pub(crate) fn placement_prefix(placement: Option<EnvironmentPlacement>) -> &'static str {
    match placement {
        Some(EnvironmentPlacement::Local) => "cw --local",
        Some(EnvironmentPlacement::Platform) => "cw --cloud",
        None => "cw",
    }
}

/// One environment.
#[derive(Clone, Debug)]
pub(crate) struct InventoryEntry {
    /// The `cw ls --output json` row, unchanged from earlier releases.
    pub(crate) list: UnifiedEnvironmentListEntry,
    pub(crate) location: Location,
    pub(crate) organization_id: Option<String>,
    pub(crate) allocation: Allocation,
    pub(crate) credentials: SourceRef,
    pub(crate) network: NetworkRef,
}

impl InventoryEntry {
    pub(crate) fn name(&self) -> &str {
        &self.list.name
    }

    pub(crate) fn id(&self) -> &str {
        &self.list.id
    }

    pub(crate) fn state(&self) -> &str {
        &self.list.state
    }

    /// The selection `cw use` saves for this row: its canonical identity,
    /// never its name to resolve again.
    pub(crate) fn selection(&self) -> EnvironmentSelection {
        EnvironmentSelection {
            location: self.location.selection(),
            id: self.list.id.clone(),
            name: self.list.name.clone(),
            organization_id: self.organization_id.clone(),
        }
    }
}

/// How one location's listing went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocationStatus {
    /// Listed; it may have no environments.
    Listed,
    /// Not set up here (no local VM runtime, not logged in): no rows, and
    /// none expected.
    NotConfigured(String),
    /// Set up but could not be listed. Its rows are unknown, not absent.
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocationReport {
    pub(crate) location: Location,
    pub(crate) status: LocationStatus,
}

/// The environments a placement admits, sorted by name and location, and
/// how each location in scope was listed.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnvironmentInventory {
    pub(crate) entries: Vec<InventoryEntry>,
    pub(crate) locations: Vec<LocationReport>,
}

impl EnvironmentInventory {
    /// The locations that could not be listed, with why.
    pub(crate) fn unavailable(&self) -> Vec<(Location, &str)> {
        self.locations
            .iter()
            .filter_map(|report| match &report.status {
                LocationStatus::Unavailable(reason) => Some((report.location, reason.as_str())),
                _ => None,
            })
            .collect()
    }

    /// The locations that are not set up, with why.
    pub(crate) fn not_configured(&self) -> Vec<(Location, &str)> {
        self.locations
            .iter()
            .filter_map(|report| match &report.status {
                LocationStatus::NotConfigured(reason) => Some((report.location, reason.as_str())),
                _ => None,
            })
            .collect()
    }

    fn report(&mut self, location: Location, status: LocationStatus) {
        self.locations.push(LocationReport { location, status });
    }

    fn finish(mut self, state: Option<&str>) -> Self {
        if let Some(state) = state.and_then(trimmed_str) {
            self.entries
                .retain(|entry| entry.list.state.eq_ignore_ascii_case(state));
        }
        self.entries.sort_by(|left, right| {
            left.list
                .name
                .cmp(&right.list.name)
                .then(left.location.cmp(&right.location))
                .then(left.list.id.cmp(&right.list.id))
        });
        self
    }
}

/// What to list and how much detail to fetch.
#[derive(Clone, Debug, Default)]
pub(crate) struct InventoryOptions {
    /// `--type sandbox|host`.
    pub(crate) environment_type: Option<String>,
    /// `--state STATE`.
    pub(crate) state: Option<String>,
    /// `--all`: include destroyed cloud environments.
    pub(crate) include_destroyed: bool,
    /// Ask each running cloud environment and host for its daemon health
    /// (the `daemon_health` JSON field).
    pub(crate) daemon_health: bool,
    /// Resolve cloud credential profile IDs to names (one profile listing).
    pub(crate) credentials: bool,
    /// Include trusted host environments.
    pub(crate) hosts: bool,
}

impl InventoryOptions {
    /// The `cw ls` filters, with every detail its JSON reports.
    pub(crate) fn listing(args: &EnvListArgs) -> Self {
        Self {
            environment_type: args.environment_type.clone(),
            state: args.state.clone(),
            include_destroyed: args.all,
            daemon_health: true,
            credentials: false,
            hosts: true,
        }
    }
}

/// Every environment the placement admits. A location that is not set up
/// is skipped without a placement; one that fails to list is reported
/// unavailable and the others are still listed. An explicit `--cloud`
/// without a cloud login is unavailable, since it was asked for.
pub(crate) async fn environment_inventory(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    options: &InventoryOptions,
) -> anyhow::Result<EnvironmentInventory> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    // An unreadable selection only loses the marker; it never hides rows.
    let selection = config::selection::load(&paths.mesh_data_dir).ok().flatten();
    let selection = selection.as_ref();
    let mut inventory = EnvironmentInventory::default();
    let sandboxes = options.environment_type.as_deref() != Some("host");

    if placement != Some(EnvironmentPlacement::Platform) && sandboxes {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        match local_vms().await {
            Ok(Some(environments)) => {
                inventory.report(Location::Local, LocationStatus::Listed);
                inventory.entries.extend(
                    environments
                        .iter()
                        .map(|environment| local_entry(environment, selection)),
                );
            }
            Ok(None) => inventory.report(
                Location::Local,
                LocationStatus::NotConfigured("the local VM runtime is not set up".to_owned()),
            ),
            Err(error) => inventory.report(
                Location::Local,
                LocationStatus::Unavailable(format!("{error:#}")),
            ),
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        inventory.report(
            Location::Local,
            LocationStatus::NotConfigured("local VMs are not available on this platform".into()),
        );
    }

    if placement != Some(EnvironmentPlacement::Local) && sandboxes {
        match resolve_platform(globals, &paths, &env) {
            Ok(platform) => match cloud_listing(&platform, options).await {
                Ok(listing) => {
                    inventory.report(Location::Cloud, LocationStatus::Listed);
                    inventory
                        .entries
                        .extend(listing.entries(selection, options.credentials));
                }
                Err(error) => inventory.report(
                    Location::Cloud,
                    LocationStatus::Unavailable(format!("{error:#}")),
                ),
            },
            Err(error) => {
                let reason = cloud_not_configured(&error);
                inventory.report(
                    Location::Cloud,
                    if placement == Some(EnvironmentPlacement::Platform) {
                        LocationStatus::Unavailable(reason)
                    } else {
                        LocationStatus::NotConfigured(reason)
                    },
                );
            }
        }
    }

    #[cfg(unix)]
    if options.hosts
        && placement != Some(EnvironmentPlacement::Platform)
        && options.environment_type.as_deref() != Some("sandbox")
    {
        match host_environments() {
            Ok(hosts) => {
                inventory.report(Location::Host, LocationStatus::Listed);
                for environment in hosts {
                    let daemon_health = if options.daemon_health {
                        host_daemon_health(&environment).await
                    } else {
                        String::new()
                    };
                    inventory
                        .entries
                        .push(host_entry(environment, daemon_health, selection));
                }
            }
            Err(error) => inventory.report(
                Location::Host,
                LocationStatus::Unavailable(format!("{error:#}")),
            ),
        }
    }
    Ok(inventory.finish(options.state.as_deref()))
}

/// The local VMs, or `None` when the local VM runtime was never set up.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn local_vms() -> anyhow::Result<Option<Vec<codewire_local_vmm::control::v1::Environment>>> {
    if !native_state_exists()? {
        return Ok(None);
    }
    native_environments().await.map(Some)
}

/// Why the cloud is not set up, with its repair.
pub(crate) fn cloud_not_configured(error: &anyhow::Error) -> String {
    match error.downcast_ref::<config::ConfigError>() {
        Some(config::ConfigError::NoPlatformServer { .. }) => {
            "no Codewire server is set up (`cw login`)".to_owned()
        }
        Some(config::ConfigError::NoPlatformToken { .. }) => {
            "not logged in (`cw login`)".to_owned()
        }
        _ => format!("{error:#}"),
    }
}

/// One organization's cloud environments and, when asked, the names of the
/// credential profiles they reference.
#[derive(Debug, Default)]
pub(crate) struct CloudListing {
    pub(crate) organization_id: String,
    pub(crate) environments: Vec<(Environment, String)>,
    pub(crate) profiles: BTreeMap<String, String>,
}

impl CloudListing {
    pub(crate) fn entries(
        &self,
        selection: Option<&EnvironmentSelection>,
        resolve_credentials: bool,
    ) -> Vec<InventoryEntry> {
        self.environments
            .iter()
            .map(|(environment, daemon_health)| {
                cloud_entry(
                    environment,
                    daemon_health,
                    &self.organization_id,
                    resolve_credentials.then_some(&self.profiles),
                    selection,
                )
            })
            .collect()
    }
}

pub(crate) async fn cloud_listing(
    platform: &config::ResolvedPlatformConfig,
    options: &InventoryOptions,
) -> anyhow::Result<CloudListing> {
    let environment_client = EnvironmentClient::new(platform)?;
    let orgs = organization_client(platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let organization_id = current_org_id(platform, &orgs)?;
    let environments = environment_client
        .list_environments(&organization_id, options.include_destroyed)
        .await
        .context("list environments")?;
    let environments = filter_environments(
        &environments,
        options.environment_type.as_deref(),
        options.state.as_deref(),
        options.include_destroyed,
    );
    let environments = if options.daemon_health {
        platform_environment_daemon_health(&environment_client, &organization_id, environments)
            .await
    } else {
        environments
            .into_iter()
            .map(|environment| (environment, String::new()))
            .collect()
    };
    let wants_profiles = options.credentials
        && environments.iter().any(|(environment, _)| {
            environment
                .source_selection
                .as_ref()
                .is_some_and(|selection| selection.credentials.is_some())
        });
    let profiles = if wants_profiles {
        credential_profile_names(platform).await
    } else {
        BTreeMap::new()
    };
    Ok(CloudListing {
        organization_id,
        environments,
        profiles,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_entry(
    environment: &codewire_local_vmm::control::v1::Environment,
    selection: Option<&EnvironmentSelection>,
) -> InventoryEntry {
    use codewire_local_vmm::control::v1::EnvironmentState;
    InventoryEntry {
        list: UnifiedEnvironmentListEntry {
            environment_type: "sandbox".into(),
            name: environment.name.clone(),
            placement: "local".into(),
            selected: selection
                .is_some_and(|selected| selected.is_local_vm(&environment.id, &environment.name)),
            state: native_state_label(environment.state).to_owned(),
            daemon_health: if environment.state == EnvironmentState::Running as i32 {
                "ready".into()
            } else {
                "unavailable".into()
            },
            id: environment.id.clone(),
        },
        location: Location::Local,
        organization_id: None,
        allocation: Allocation::local(
            environment.vcpus,
            environment.memory_mib,
            environment.disk_bytes,
        ),
        credentials: local_vm_credentials(environment),
        network: network_ref(environment.mesh.as_ref()),
    }
}

pub(crate) fn cloud_entry(
    environment: &Environment,
    daemon_health: &str,
    organization_id: &str,
    profiles: Option<&BTreeMap<String, String>>,
    selection: Option<&EnvironmentSelection>,
) -> InventoryEntry {
    InventoryEntry {
        list: UnifiedEnvironmentListEntry {
            environment_type: "sandbox".into(),
            name: environment_display_name(environment).to_owned(),
            placement: "platform".into(),
            selected: selection.is_some_and(|selected| {
                selected.location == SelectionLocation::Cloud && selected.id == environment.id
            }),
            state: environment.state.clone(),
            daemon_health: daemon_health.to_owned(),
            id: environment.id.clone(),
        },
        location: Location::Cloud,
        organization_id: trimmed_str(organization_id)
            .or_else(|| trimmed_str(&environment.org_id))
            .map(str::to_owned),
        allocation: Allocation::cloud(
            environment.cpu_millicores,
            environment.memory_mb,
            environment.disk_gb,
        ),
        credentials: cloud_credentials(environment, profiles),
        network: NetworkRef::cloud(
            environment.network.as_deref(),
            environment.network_state.as_deref(),
            environment.network_failure.as_deref(),
        ),
    }
}

/// A cloud environment's profile: `platform:NAME` when the listing names
/// it, its canonical `platform:id:…` reference otherwise.
fn cloud_credentials(
    environment: &Environment,
    profiles: Option<&BTreeMap<String, String>>,
) -> SourceRef {
    let stored = environment
        .source_selection
        .as_ref()
        .and_then(|selection| selection.credentials.as_ref())
        .map(|binding| binding.profile.as_str());
    let name = stored
        .zip(profiles)
        .and_then(|(stored, profiles)| listed_profile_name(profiles, stored));
    credential_ref(stored, name)
}

#[cfg(unix)]
fn host_entry(
    environment: HostEnvironment,
    daemon_health: String,
    selection: Option<&EnvironmentSelection>,
) -> InventoryEntry {
    InventoryEntry {
        list: UnifiedEnvironmentListEntry {
            environment_type: "host".into(),
            name: environment.name,
            placement: "local".into(),
            selected: selection.is_some_and(|selected| {
                selected.location == SelectionLocation::Host && selected.id == environment.id
            }),
            state: environment.state,
            daemon_health,
            id: environment.id,
        },
        location: Location::Host,
        organization_id: None,
        allocation: Allocation::default(),
        credentials: SourceRef::None,
        network: NetworkRef::NotAttached,
    }
}

/// The environment `cw use ENV` names: an exact ID, an exact name, or a
/// unique cloud ID prefix. A name in more than one location, or in a
/// location that could not be listed, is refused with the spelling that
/// selects one, rather than guessed.
pub(crate) fn find_direct<'a>(
    inventory: &'a EnvironmentInventory,
    requested: &str,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<&'a InventoryEntry> {
    let requested = requested.trim();
    anyhow::ensure!(!requested.is_empty(), "name the environment: `cw use ENV`");
    if let Some(entry) = inventory
        .entries
        .iter()
        .find(|entry| entry.id() == requested)
    {
        return Ok(entry);
    }
    let named: Vec<&InventoryEntry> = inventory
        .entries
        .iter()
        .filter(|entry| entry.name() == requested)
        .collect();
    let unavailable = inventory.unavailable();
    match named.as_slice() {
        [entry] => {
            if let Some((location, reason)) = unavailable
                .iter()
                .find(|(location, _)| *location != entry.location)
            {
                anyhow::bail!(
                    "{} could not be listed ({reason}), so {requested:?} may also name one there; {}",
                    location.listing(),
                    select_one(entry, requested, false)
                );
            }
            return Ok(entry);
        }
        [] => {}
        several => {
            let mut locations: Vec<Location> = several.iter().map(|entry| entry.location).collect();
            locations.dedup();
            if locations.len() == 1 {
                let ids: Vec<&str> = several.iter().map(|entry| entry.id()).collect();
                anyhow::bail!(
                    "several {} are named {requested:?}; select one by ID: `cw use ID` ({})",
                    locations[0].listing(),
                    ids.join(", ")
                );
            }
            let hosted = locations.contains(&Location::Host);
            let choices: Vec<String> = several
                .iter()
                .map(|entry| select_one(entry, requested, hosted))
                .collect();
            anyhow::bail!(
                "{requested:?} names a {}; {}",
                several
                    .iter()
                    .map(|entry| entry.location.kind())
                    .collect::<Vec<_>>()
                    .join(" and a "),
                choices.join(", or ")
            );
        }
    }
    let prefixed: Vec<&InventoryEntry> = inventory
        .entries
        .iter()
        .filter(|entry| entry.location == Location::Cloud && entry.id().starts_with(requested))
        .collect();
    match prefixed.as_slice() {
        [entry] if unavailable.is_empty() => return Ok(entry),
        [] | [_] => {}
        several => {
            let ids: Vec<&str> = several.iter().map(|entry| entry.id()).collect();
            anyhow::bail!(
                "{requested:?} begins several cloud environment IDs; use a longer prefix ({})",
                ids.join(", ")
            );
        }
    }
    let failures: Vec<String> = unavailable
        .iter()
        .map(|(location, reason)| format!("{} could not be listed: {reason}", location.listing()))
        .collect();
    let searched = inventory
        .locations
        .iter()
        .any(|report| report.status == LocationStatus::Listed);
    // Nowhere could be searched: the failure is the answer.
    if !searched && !failures.is_empty() {
        anyhow::bail!(
            "{}; the current environment is unchanged",
            failures.join("; ")
        );
    }
    let mut message = match placement {
        Some(EnvironmentPlacement::Local) => {
            format!("no local VM is named {requested:?} (`cw --local ls` lists them)")
        }
        Some(EnvironmentPlacement::Platform) => {
            format!("no cloud environment is named {requested:?} (`cw --cloud ls` lists them)")
        }
        None => format!("no environment is named {requested:?} (`cw ls` lists them)"),
    };
    for failure in failures {
        message.push_str("; ");
        message.push_str(&failure);
    }
    if placement.is_none() {
        for (location, reason) in inventory.not_configured() {
            if location == Location::Cloud {
                message.push_str(&format!(
                    "; {} were not searched: {reason}",
                    location.listing()
                ));
            }
        }
    }
    anyhow::bail!(message)
}

/// The command that selects exactly this entry.
/// A trusted host shares the `--local` scope with local VMs, so a name a
/// host shares is settled by ID (`by_id`) rather than by placement.
fn select_one(entry: &InventoryEntry, requested: &str, by_id: bool) -> String {
    if by_id || entry.location == Location::Host {
        return format!(
            "`cw use {}` selects the {}",
            entry.id(),
            entry.location.kind()
        );
    }
    format!(
        "`{} use {requested}` selects the {}",
        entry.location.command_prefix(),
        entry.location.kind()
    )
}

/// The picker's rows: local VMs and cloud environments, never trusted
/// hosts.
pub(crate) fn picker_rows(
    inventory: &EnvironmentInventory,
    style: Style,
) -> (Vec<String>, Vec<usize>, Vec<crate::output::PickerRow>) {
    let header = [
        "NAME",
        "LOCATION",
        "STATE",
        "vCPU",
        "RAM",
        "DISK",
        "CREDENTIALS",
    ]
    .map(String::from)
    .to_vec();
    let dash = missing(style);
    let mut indices = Vec::new();
    let mut rows = Vec::new();
    for (index, entry) in inventory.entries.iter().enumerate() {
        if entry.location == Location::Host {
            continue;
        }
        let [cpu, memory, disk] = entry.allocation.cells();
        let credentials = entry.credentials.text();
        let cells = vec![
            entry.name().to_owned(),
            entry.location.label().to_owned(),
            display_str(entry.state()).to_owned(),
            cpu.unwrap_or_else(|| dash.to_owned()),
            memory.unwrap_or_else(|| dash.to_owned()),
            disk.unwrap_or_else(|| dash.to_owned()),
            credentials.clone(),
        ];
        let search = [
            entry.name(),
            entry.location.label(),
            entry.state(),
            credentials.as_str(),
        ]
        .join(" ");
        indices.push(index);
        rows.push(crate::output::PickerRow::new(cells, search));
    }
    (header, indices, rows)
}

fn missing(style: Style) -> &'static str {
    match style.charset() {
        crate::output::Charset::Unicode => "—",
        crate::output::Charset::Ascii => "-",
    }
}

/// One `cw ls` row: the environment, where it runs, its state and its
/// sessions. The JSON keeps every field the former `cw env list` rows
/// (`type`, `name`, `placement`, `selected`, `state`, `daemon_health`, `id`)
/// and `cw list` rows (`environment_id`, `environment`, `running`,
/// `sessions`, `error`) carried, so their consumers read it unchanged.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct InventoryRow {
    #[serde(flatten)]
    entry: UnifiedEnvironmentListEntry,
    environment_id: String,
    environment: String,
    running: bool,
    sessions: serde_json::Value,
    session_count: Option<usize>,
    error: Option<String>,
    #[serde(skip)]
    location: Location,
    #[serde(skip)]
    network: NetworkRef,
}

/// `cw ls`: one row per environment, running or not. A running environment
/// whose sessions cannot be read keeps its row, marked unavailable.
pub(crate) async fn handle_environment_inventory(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvListArgs,
) -> anyhow::Result<()> {
    let inventory =
        environment_inventory(globals, placement, &InventoryOptions::listing(&args)).await?;
    let mut rows = Vec::with_capacity(inventory.entries.len());
    for entry in &inventory.entries {
        let running = entry.state().eq_ignore_ascii_case("running");
        let target = inventory_target(&entry.list);
        let (sessions, error) = if running {
            match list_target_sessions(globals, target.clone()).await {
                Ok(sessions) => (sessions, None),
                Err(error) => (Vec::new(), Some(format!("{error:#}"))),
            }
        } else {
            (Vec::new(), None)
        };
        rows.push(InventoryRow {
            environment_id: target.target_ref,
            environment: entry.name().to_owned(),
            running,
            session_count: error.is_none().then_some(sessions.len()),
            sessions: sessions_json(&sessions)?,
            error,
            entry: entry.list.clone(),
            location: entry.location,
            network: entry.network.clone(),
        });
    }
    let unavailable = inventory.unavailable();
    if args.output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return inventory_outcome(&unavailable);
    }
    let caps = Capabilities::from_process(OutputMode::Text);
    // An unavailable location is not an empty list: with nothing listed,
    // only the failure is reported.
    if !(rows.is_empty() && !unavailable.is_empty()) {
        print!(
            "{}",
            format_environment_inventory(
                &rows,
                placement,
                &inventory.not_configured(),
                caps.stdout_style()
            )
        );
    }
    let style = caps.stderr_style();
    for row in rows.iter().filter(|row| row.error.is_some()) {
        eprintln!(
            "{} Sessions in {} could not be read: {}",
            style.status(Status::Attention),
            terminal_text(&row.environment),
            terminal_text(row.error.as_deref().unwrap_or_default())
        );
    }
    if !unavailable.is_empty() {
        eprint!(
            "{}",
            format_unavailable(&unavailable, !rows.is_empty(), style)
        );
    }
    inventory_outcome(&unavailable)
}

/// `cw ls` lists environments: it fails only when a location's environments
/// could not be listed, after printing every one it could. An environment
/// whose sessions are unreadable is still listed (SESSIONS `unavailable`),
/// so it does not change the outcome; `cw ls ENV` fails for that instead.
fn inventory_outcome(unavailable: &[(Location, &str)]) -> anyhow::Result<()> {
    if unavailable.is_empty() {
        return Ok(());
    }
    let locations: Vec<&str> = unavailable
        .iter()
        .map(|(location, _)| location.listing())
        .collect();
    anyhow::bail!(
        "environment inventory is partial: {} could not be listed",
        locations.join(" and ")
    )
}

/// The session target an inventory row names: local VMs by name, host and
/// cloud environments by ID.
fn inventory_target(entry: &UnifiedEnvironmentListEntry) -> config::CurrentTargetConfig {
    let (kind, target_ref) = match (entry.environment_type.as_str(), entry.placement.as_str()) {
        ("host", _) => ("host", entry.id.clone()),
        (_, "platform") => ("env", entry.id.clone()),
        _ => ("local", entry.name.clone()),
    };
    config::CurrentTargetConfig {
        kind: kind.to_owned(),
        target_ref,
        name: entry.name.clone(),
    }
}

/// The location failures after the rows, on stderr.
fn format_unavailable(unavailable: &[(Location, &str)], listed: bool, style: Style) -> String {
    let mut out = String::new();
    for (location, reason) in unavailable {
        let listing = location.listing();
        let mut heading = listing.to_owned();
        heading[..1].make_ascii_uppercase();
        out.push_str(&format!(
            "{} {heading} could not be listed: {}\n",
            style.status(Status::Attention),
            terminal_text(reason)
        ));
    }
    if listed {
        out.push_str(&format!(
            "  {}\n",
            style.paint(
                crate::output::Role::Dim,
                "The results above are complete for the other locations."
            )
        ));
    }
    for (location, _) in unavailable {
        let prefix = location.command_prefix();
        if *location != Location::Host {
            out.push_str(&format!(
                "{} Retry: {prefix} ls\n",
                style.status(Status::Next)
            ));
        }
    }
    out
}

/// The compact `cw ls` table:
///
/// ```text
///   NAME    LOCATION  STATE    SESSIONS  NETWORK
/// › app     local     running  1         cloud:work
///   review  cloud     stopped  —         —
///
///   › current environment · NETWORK is the saved attachment
///
/// → Sessions: cw ls app
/// ```
fn format_environment_inventory(
    rows: &[InventoryRow],
    placement: Option<EnvironmentPlacement>,
    not_configured: &[(Location, &str)],
    style: Style,
) -> String {
    let dim = |text: &str| style.paint(crate::output::Role::Dim, text);
    let mut notes = String::new();
    if placement.is_none() {
        for (location, reason) in not_configured {
            if *location == Location::Cloud {
                notes.push_str(&format!(
                    "  {}\n",
                    dim(&format!("Cloud environments are not listed: {reason}"))
                ));
            }
        }
    }
    if rows.is_empty() {
        let scope = match placement {
            Some(EnvironmentPlacement::Local) => "local ",
            Some(EnvironmentPlacement::Platform) => "cloud ",
            None => "",
        };
        let mut out = format!("No {scope}environments yet.\n");
        if !notes.is_empty() {
            out.push_str(&notes);
        }
        out.push_str(&format!(
            "\n{} {} run claude\n",
            style.status(Status::Next),
            placement_prefix(placement)
        ));
        return out;
    }
    let dash = missing(style);
    let cells: Vec<[String; 5]> = rows
        .iter()
        .map(|row| {
            let sessions = match (row.running, row.session_count) {
                (false, _) => dash.to_owned(),
                (true, Some(count)) => count.to_string(),
                (true, None) => "unavailable".to_owned(),
            };
            let network = if row.network.is_attached() {
                row.network.text()
            } else {
                dash.to_owned()
            };
            [
                terminal_text(&row.entry.name),
                row.location.label().to_owned(),
                terminal_text(display_str(&row.entry.state)),
                sessions,
                network,
            ]
        })
        .collect();
    let header = ["NAME", "LOCATION", "STATE", "SESSIONS", "NETWORK"].map(String::from);
    let widths: [usize; 4] = std::array::from_fn(|column| {
        std::iter::once(&header)
            .chain(&cells)
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    });
    let pad = |text: &str, width: usize| " ".repeat(width.saturating_sub(text.chars().count()));
    let mut out = String::new();
    let mut line = |marker: String, row: &[String; 5], state: String| {
        out.push_str(&marker);
        out.push(' ');
        for (column, width) in widths.iter().enumerate() {
            let text = if column == 2 {
                state.clone()
            } else {
                row[column].clone()
            };
            out.push_str(&text);
            out.push_str(&pad(&row[column], *width));
            out.push_str("  ");
        }
        out.push_str(&row[4]);
        out.push('\n');
    };
    line(" ".to_owned(), &header, header[2].clone());
    for (row, cells) in rows.iter().zip(&cells) {
        let marker = if row.entry.selected {
            style.status(Status::Selected)
        } else {
            " ".to_owned()
        };
        let state = match row.entry.state.to_ascii_lowercase().as_str() {
            "running" => style.paint(crate::output::Role::Success, &cells[2]),
            "error" | "failed" | "orphaned" => style.paint(crate::output::Role::Failure, &cells[2]),
            "starting" | "creating" | "stopping" => cells[2].clone(),
            _ => dim(&cells[2]),
        };
        line(marker, cells, state);
    }
    let mut legend = Vec::new();
    if rows.iter().any(|row| row.entry.selected) {
        legend.push(format!(
            "{} current environment",
            style.glyph(Status::Selected)
        ));
    }
    legend.push("NETWORK is the saved attachment".to_owned());
    out.push_str(&format!("\n  {}\n", dim(&legend.join(style.separator()))));
    out.push_str(&notes);
    let first = rows
        .iter()
        .find(|row| row.entry.selected)
        .unwrap_or(&rows[0]);
    let duplicated = rows
        .iter()
        .filter(|row| row.entry.name == first.entry.name)
        .count()
        > 1;
    // A shared name is named by its ID, which every location resolves.
    let target = if duplicated {
        &first.entry.id
    } else {
        &first.entry.name
    };
    out.push_str(&format!(
        "\n{} Sessions: cw ls {}\n",
        style.status(Status::Next),
        terminal_text(target)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Charset, SourcePlacement};

    const PLAIN: Style = Style::new(false, Charset::Unicode);
    const VM_ID: &str = "8f0c2b3e-4d5a-4b6c-9d7e-0f1a2b3c4d5e";
    const PROFILE_ID: &str = "d0f68b45-7c8b-43eb-9b8c-62a33b279c88";

    fn list(name: &str, placement: &str, kind: &str, state: &str) -> UnifiedEnvironmentListEntry {
        UnifiedEnvironmentListEntry {
            environment_type: kind.into(),
            name: name.into(),
            placement: placement.into(),
            selected: name == "app",
            state: state.into(),
            daemon_health: String::new(),
            id: format!(
                "{name}-{}-id",
                if kind == "host" { "host" } else { placement }
            ),
        }
    }

    fn entry(name: &str, location: Location, state: &str) -> InventoryEntry {
        let (placement, kind) = match location {
            Location::Local => ("local", "sandbox"),
            Location::Cloud => ("platform", "sandbox"),
            Location::Host => ("local", "host"),
        };
        InventoryEntry {
            list: list(name, placement, kind, state),
            location,
            organization_id: (location == Location::Cloud).then(|| "org-1".to_owned()),
            allocation: Allocation::default(),
            credentials: SourceRef::None,
            network: NetworkRef::NotAttached,
        }
    }

    fn inventory(
        entries: Vec<InventoryEntry>,
        locations: &[(Location, LocationStatus)],
    ) -> EnvironmentInventory {
        EnvironmentInventory {
            entries,
            locations: locations
                .iter()
                .map(|(location, status)| LocationReport {
                    location: *location,
                    status: status.clone(),
                })
                .collect(),
        }
        .finish(None)
    }

    fn listed() -> Vec<(Location, LocationStatus)> {
        vec![
            (Location::Local, LocationStatus::Listed),
            (Location::Cloud, LocationStatus::Listed),
            (Location::Host, LocationStatus::Listed),
        ]
    }

    fn row(entry: &InventoryEntry, count: Option<usize>, network: NetworkRef) -> InventoryRow {
        InventoryRow {
            entry: entry.list.clone(),
            environment_id: entry.name().to_owned(),
            environment: entry.name().to_owned(),
            running: entry.state() == "running",
            sessions: serde_json::Value::Array(Vec::new()),
            session_count: count,
            error: None,
            location: entry.location,
            network,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn vm(spec: serde_json::Value) -> codewire_local_vmm::control::v1::Environment {
        codewire_local_vmm::control::v1::Environment {
            id: VM_ID.into(),
            name: "app".into(),
            state: codewire_local_vmm::control::v1::EnvironmentState::Stopped as i32,
            vcpus: 2,
            memory_mib: 4096,
            disk_bytes: 40 << 30,
            selected: true,
            project_spec_json: serde_json::to_vec(&spec).unwrap(),
            ..Default::default()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_local_vm_row_carries_size_profile_network_and_explicit_selection_only() {
        use codewire_local_vmm::control::v1;
        let mut environment = vm(serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace",
            "credentials": {"profile": format!("platform:id:{PROFILE_ID}")}
        }));
        environment.access_profile = "user/work".into();
        environment.access_profile_id = PROFILE_ID.into();
        environment.access_profile_revision = 3;
        environment.mesh = Some(v1::MeshAttachment {
            network_id: "team".into(),
            auth_source: v1::MeshEnrollmentAuthSource::StandaloneLocal as i32,
            ..Default::default()
        });

        // The supervisor's own `selected` flag never selects it.
        let row = local_entry(&environment, None);
        assert!(!row.list.selected);
        assert_eq!(row.list.state, "stopped");
        assert_eq!(row.list.daemon_health, "unavailable");
        assert_eq!(
            row.allocation.cells(),
            [
                Some("2".into()),
                Some("4 GiB".into()),
                Some("40 GiB".into())
            ]
        );
        // The lifecycle summary's renderer: this spec carries no digest, so
        // the VM's reported scope/name reference is shown as is.
        assert_eq!(row.credentials, local_vm_credentials(&environment));
        assert_eq!(row.credentials.text(), "user/work");
        assert_eq!(row.network.text(), "local:team");
        assert_eq!(row.selection().id, VM_ID);
        assert_eq!(row.selection().location, SelectionLocation::Local);

        let selected = local_entry(&environment, Some(&row.selection()));
        assert!(selected.list.selected);
        let recreated = EnvironmentSelection {
            id: "0b6a1d5e-0000-4000-8000-000000000000".into(),
            ..row.selection()
        };
        assert!(!local_entry(&environment, Some(&recreated)).list.selected);
        // A selection an older cw saved names the VM.
        let by_name = EnvironmentSelection {
            id: "app".into(),
            ..row.selection()
        };
        assert!(local_entry(&environment, Some(&by_name)).list.selected);

        let mut local_profile = vm(serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace",
            "credentials": {"profile": format!("local:id:{PROFILE_ID}")}
        }));
        local_profile.access_profile = "user/personal".into();
        local_profile.access_profile_id = PROFILE_ID.into();
        local_profile.mesh = Some(v1::MeshAttachment {
            network_id: "work".into(),
            auth_source: v1::MeshEnrollmentAuthSource::HostedCurrent as i32,
            ..Default::default()
        });
        let row = local_entry(&local_profile, None);
        assert_eq!(row.network.text(), "cloud:work");

        let none = local_entry(&vm(serde_json::json!({})), None);
        assert_eq!(none.credentials, SourceRef::None);
        assert_eq!(none.network, NetworkRef::NotAttached);
    }

    #[test]
    fn a_cloud_row_names_its_profile_when_listed_and_keeps_the_reference_otherwise() {
        let mut environment = Environment {
            id: "env-review".into(),
            name: Some("review".into()),
            state: "stopped".into(),
            cpu_millicores: 4000,
            memory_mb: 8192,
            disk_gb: 80,
            source_selection: Some(crate::presentation::EnvironmentSourceSelection {
                credentials: Some(codewire_project::CredentialBinding {
                    profile: format!("platform:id:{PROFILE_ID}"),
                }),
                profile_revision: Some(2),
                ..Default::default()
            }),
            ..Environment::default()
        };
        let profiles = BTreeMap::from([(PROFILE_ID.to_owned(), "work".to_owned())]);
        let row = cloud_entry(&environment, "", "org-1", Some(&profiles), None);
        assert_eq!(row.location, Location::Cloud);
        assert_eq!(row.list.placement, "platform");
        assert!(!row.list.selected);
        assert_eq!(
            row.allocation.cells(),
            [
                Some("4".into()),
                Some("8 GiB".into()),
                Some("80 GiB".into())
            ]
        );
        assert_eq!(row.credentials.text(), "platform:work");
        assert_eq!(row.network, NetworkRef::NotAttached);
        assert_eq!(row.selection().organization_id.as_deref(), Some("org-1"));

        let unresolved = cloud_entry(&environment, "", "org-1", None, None);
        assert_eq!(
            unresolved.credentials.text(),
            format!("platform:id:{PROFILE_ID}")
        );
        assert!(
            cloud_entry(&environment, "", "org-1", None, Some(&row.selection()))
                .list
                .selected
        );

        environment.source_selection = None;
        environment.network = Some("team".into());
        let row = cloud_entry(&environment, "", "org-1", Some(&profiles), None);
        assert_eq!(row.credentials, SourceRef::None);
        assert_eq!(row.network.text(), "cloud:team");
    }

    /// The cloud half against a faked platform: one organization, its
    /// environments, and a profile listing only when names are wanted.
    #[tokio::test]
    async fn the_cloud_listing_reads_one_organization_and_names_profiles_once() {
        use buffa::Message as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let proto = |body: Vec<u8>| {
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(body)
        };
        let organizations = codewire_client::ListOrganizationsResponse {
            organizations: vec![codewire_client::OrganizationMembership {
                organization: Some(codewire_client::Organization {
                    id: "org_test".into(),
                    name: "Test".into(),
                    slug: "test".into(),
                    ..Default::default()
                })
                .into(),
                role: codewire_client::OrgRole::Owner.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let environments = codewire_client::ListEnvironmentsResponse {
            environments: vec![
                codewire_client::Environment {
                    id: "env-review".into(),
                    org_id: "org_test".into(),
                    name: "review".into(),
                    state: codewire_client::EnvironmentState::Stopped.into(),
                    cpu_millicores: 4000,
                    memory_mb: 8192,
                    disk_gb: 80,
                    source_selection: Some(codewire_client::EnvironmentSourceSelection {
                        credentials: Some(codewire_client::ProjectCredentialBinding {
                            profile: format!("platform:id:{PROFILE_ID}"),
                            ..Default::default()
                        })
                        .into(),
                        profile_revision: Some(2),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
                codewire_client::Environment {
                    id: "env-app".into(),
                    org_id: "org_test".into(),
                    name: "app".into(),
                    state: codewire_client::EnvironmentState::Running.into(),
                    network: "team".into(),
                    ..Default::default()
                },
                codewire_client::Environment {
                    id: "env-gone".into(),
                    org_id: "org_test".into(),
                    name: "gone".into(),
                    state: codewire_client::EnvironmentState::Destroyed.into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let profiles = codewire_client::ListAccessProfilesResponse {
            access_profiles: vec![codewire_client::AccessProfile {
                id: PROFILE_ID.into(),
                name: "work".into(),
                revision: 2,
                ..Default::default()
            }],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.OrganizationService/ListOrganizations"))
            .respond_with(proto(organizations.encode_to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.EnvironmentService/ListEnvironments"))
            .respond_with(proto(environments.encode_to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AccessProfileService/ListAccessProfiles"))
            .respond_with(proto(profiles.encode_to_vec()))
            .expect(1)
            .mount(&server)
            .await;
        let platform = config::ResolvedPlatformConfig::static_token(
            server.uri(),
            "synthetic-inventory-token",
            true,
            None,
        );

        let named = InventoryOptions {
            credentials: true,
            ..InventoryOptions::default()
        };
        let listing = cloud_listing(&platform, &named).await.unwrap();
        assert_eq!(listing.organization_id, "org_test");
        let selected = EnvironmentSelection {
            location: SelectionLocation::Cloud,
            id: "env-app".into(),
            name: "app".into(),
            organization_id: Some("org_test".into()),
        };
        let rows = listing.entries(Some(&selected), true);
        let summary: Vec<(&str, &str, bool, String, String)> = rows
            .iter()
            .map(|row| {
                (
                    row.name(),
                    row.state(),
                    row.list.selected,
                    row.credentials.text(),
                    row.network.text(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "review",
                    "stopped",
                    false,
                    "platform:work".into(),
                    "not attached".into()
                ),
                ("app", "running", true, "none".into(), "cloud:team".into()),
            ],
            "destroyed environments are left out without --all"
        );
        assert_eq!(
            rows[0].allocation.cells(),
            [
                Some("4".into()),
                Some("8 GiB".into()),
                Some("80 GiB".into())
            ]
        );
        assert_eq!(
            rows[0].selection().organization_id.as_deref(),
            Some("org_test")
        );

        // `cw ls` does not show profiles, so it does not list them.
        let listed = cloud_listing(&platform, &InventoryOptions::default())
            .await
            .unwrap();
        assert_eq!(
            listed.entries(None, false)[0].credentials.text(),
            format!("platform:id:{PROFILE_ID}")
        );

        // An unreachable platform is an error, which the inventory reports
        // as an unavailable location rather than an empty one.
        let closed = config::ResolvedPlatformConfig::static_token(
            "http://127.0.0.1:9",
            "synthetic-inventory-token",
            true,
            None,
        );
        assert!(cloud_listing(&closed, &named).await.is_err());
    }

    #[test]
    fn direct_selection_matches_id_then_name_then_cloud_id_prefix() {
        let inventory = inventory(
            vec![
                entry("app", Location::Local, "running"),
                entry("review", Location::Cloud, "stopped"),
            ],
            &listed(),
        );
        assert_eq!(
            find_direct(&inventory, "review-platform-id", None)
                .unwrap()
                .name(),
            "review"
        );
        assert_eq!(
            find_direct(&inventory, " app ", None).unwrap().location,
            Location::Local
        );
        assert_eq!(
            find_direct(&inventory, "review-plat", None).unwrap().name(),
            "review"
        );
        // A local VM is never matched by an ID prefix.
        assert!(find_direct(&inventory, "app-loc", None).is_err());
        assert_eq!(
            find_direct(&inventory, "missing", None)
                .unwrap_err()
                .to_string(),
            "no environment is named \"missing\" (`cw ls` lists them)"
        );
        assert_eq!(
            find_direct(&inventory, "missing", Some(EnvironmentPlacement::Local))
                .unwrap_err()
                .to_string(),
            "no local VM is named \"missing\" (`cw --local ls` lists them)"
        );
    }

    #[test]
    fn a_name_in_two_locations_needs_a_placement() {
        let both = inventory(
            vec![
                entry("app", Location::Local, "running"),
                entry("app", Location::Cloud, "stopped"),
            ],
            &listed(),
        );
        assert_eq!(
            find_direct(&both, "app", None).unwrap_err().to_string(),
            "\"app\" names a local VM and a cloud VM; `cw --local use app` selects the local VM, or `cw --cloud use app` selects the cloud VM"
        );
        let clouds = inventory(
            vec![
                entry("app", Location::Cloud, "running"),
                InventoryEntry {
                    list: UnifiedEnvironmentListEntry {
                        id: "second-id".into(),
                        ..entry("app", Location::Cloud, "stopped").list
                    },
                    ..entry("app", Location::Cloud, "stopped")
                },
            ],
            &listed(),
        );
        assert_eq!(
            find_direct(&clouds, "app", None).unwrap_err().to_string(),
            "several cloud environments are named \"app\"; select one by ID: `cw use ID` (app-platform-id, second-id)"
        );
        let host = inventory(
            vec![
                entry("box", Location::Local, "running"),
                entry("box", Location::Host, "running"),
            ],
            &listed(),
        );
        for placement in [None, Some(EnvironmentPlacement::Local)] {
            assert_eq!(
                find_direct(&host, "box", placement)
                    .unwrap_err()
                    .to_string(),
                "\"box\" names a local VM and a trusted host; `cw use box-local-id` selects the local VM, or `cw use box-host-id` selects the trusted host"
            );
        }
    }

    #[test]
    fn an_unlisted_location_never_makes_a_name_unambiguous() {
        let partial = inventory(
            vec![entry("app", Location::Local, "running")],
            &[
                (Location::Local, LocationStatus::Listed),
                (
                    Location::Cloud,
                    LocationStatus::Unavailable("connection refused".into()),
                ),
            ],
        );
        assert_eq!(
            find_direct(&partial, "app", None).unwrap_err().to_string(),
            "cloud environments could not be listed (connection refused), so \"app\" may also name one there; `cw --local use app` selects the local VM"
        );
        assert!(
            find_direct(&partial, "gone", None)
                .unwrap_err()
                .to_string()
                .ends_with("; cloud environments could not be listed: connection refused")
        );
        // With nothing listed, the listing failure is the whole answer.
        let nothing = inventory(
            Vec::new(),
            &[(
                Location::Cloud,
                LocationStatus::Unavailable("not logged in (`cw login`)".into()),
            )],
        );
        assert_eq!(
            find_direct(&nothing, "app", Some(EnvironmentPlacement::Platform))
                .unwrap_err()
                .to_string(),
            "cloud environments could not be listed: not logged in (`cw login`); the current environment is unchanged"
        );
        // Not logged in: there is nothing there to collide with.
        let local_only = inventory(
            vec![entry("app", Location::Local, "running")],
            &[
                (Location::Local, LocationStatus::Listed),
                (
                    Location::Cloud,
                    LocationStatus::NotConfigured("not logged in (`cw login`)".into()),
                ),
            ],
        );
        assert_eq!(find_direct(&local_only, "app", None).unwrap().name(), "app");
        assert_eq!(
            find_direct(&local_only, "gone", None)
                .unwrap_err()
                .to_string(),
            "no environment is named \"gone\" (`cw ls` lists them); cloud environments were not searched: not logged in (`cw login`)"
        );
    }

    #[test]
    fn picker_rows_show_size_and_profile_and_leave_out_hosts() {
        let mut app = entry("app", Location::Local, "running");
        app.allocation = Allocation::local(2, 4096, 40 << 30);
        app.credentials = SourceRef::Named {
            placement: SourcePlacement::Platform,
            name: "work".into(),
        };
        let mut review = entry("app", Location::Cloud, "stopped");
        review.allocation = Allocation::cloud(4000, 8192, 80);
        let inventory = inventory(
            vec![entry("box", Location::Host, "running"), review, app],
            &listed(),
        );
        let (header, indices, rows) = picker_rows(&inventory, PLAIN);
        assert_eq!(
            header.join(" "),
            "NAME LOCATION STATE vCPU RAM DISK CREDENTIALS"
        );
        assert_eq!(indices, [0, 1]);
        assert_eq!(inventory.entries[indices[0]].location, Location::Local);
        let picker = crate::output::Picker::new("Choose an environment", header, rows);
        assert_eq!(
            picker.render(PLAIN, 100, 10)[3..6],
            [
                "  NAME  LOCATION  STATE    vCPU  RAM    DISK    CREDENTIALS",
                "› app   local     running  2     4 GiB  40 GiB  platform:work",
                "  app   cloud     stopped  4     8 GiB  80 GiB  none",
            ]
        );
    }

    #[test]
    fn ls_shows_location_state_sessions_and_network_with_the_current_marker() {
        let app = entry("app", Location::Local, "running");
        let review = entry("review", Location::Cloud, "stopped");
        let team = entry("team", Location::Host, "running");
        let rows = [
            row(
                &app,
                Some(1),
                NetworkRef::Attached {
                    mesh: crate::output::MeshPlacement::Cloud,
                    network: "work".into(),
                },
            ),
            row(&review, None, NetworkRef::NotAttached),
            row(&team, None, NetworkRef::NotAttached),
        ];
        assert_eq!(
            format_environment_inventory(&rows, None, &[], PLAIN),
            concat!(
                "  NAME    LOCATION  STATE    SESSIONS     NETWORK\n",
                "› app     local     running  1            cloud:work\n",
                "  review  cloud     stopped  —            —\n",
                "  team    host      running  unavailable  —\n",
                "\n",
                "  › current environment · NETWORK is the saved attachment\n",
                "\n",
                "→ Sessions: cw ls app\n",
            )
        );
        let ascii =
            format_environment_inventory(&rows, None, &[], Style::new(false, Charset::Ascii));
        assert!(ascii.is_ascii(), "{ascii}");
        assert!(ascii.contains("\n> app "));
        let colored =
            format_environment_inventory(&rows, None, &[], Style::new(true, Charset::Unicode));
        assert!(colored.contains("\x1b[36m›\x1b[0m app     local     \x1b[32mrunning\x1b[0m  1"));
    }

    #[test]
    fn ls_empty_and_unconfigured_states_are_explicit() {
        assert_eq!(
            format_environment_inventory(&[], None, &[], PLAIN),
            "No environments yet.\n\n→ cw run claude\n"
        );
        assert_eq!(
            format_environment_inventory(&[], Some(EnvironmentPlacement::Local), &[], PLAIN),
            "No local environments yet.\n\n→ cw --local run claude\n"
        );
        assert_eq!(
            format_environment_inventory(
                &[],
                None,
                &[(Location::Cloud, "not logged in (`cw login`)")],
                PLAIN
            ),
            "No environments yet.\n  Cloud environments are not listed: not logged in (`cw login`)\n\n→ cw run claude\n"
        );
        let review = entry("review", Location::Cloud, "stopped");
        let mut duplicate = entry("review", Location::Local, "stopped");
        duplicate.list.selected = false;
        let text = format_environment_inventory(
            &[
                row(&duplicate, None, NetworkRef::NotAttached),
                row(&review, None, NetworkRef::NotAttached),
            ],
            None,
            &[],
            PLAIN,
        );
        assert!(
            text.contains("\n  NETWORK is the saved attachment\n"),
            "{text}"
        );
        assert!(
            text.ends_with("→ Sessions: cw ls review-local-id\n"),
            "{text}"
        );
    }

    #[test]
    fn ls_keeps_its_json_fields_and_fails_only_for_an_unlisted_location() {
        let app = entry("app", Location::Local, "running");
        let json = serde_json::to_value(row(&app, Some(2), NetworkRef::NotAttached)).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        let mut expected = [
            "type",
            "name",
            "placement",
            "selected",
            "state",
            "daemon_health",
            "id",
            "environment_id",
            "environment",
            "running",
            "sessions",
            "session_count",
            "error",
        ];
        expected.sort_unstable();
        assert_eq!(fields, expected);
        inventory_outcome(&[]).unwrap();
        assert_eq!(
            inventory_outcome(&[(Location::Cloud, "unavailable")])
                .unwrap_err()
                .to_string(),
            "environment inventory is partial: cloud environments could not be listed"
        );
        assert_eq!(
            inventory_outcome(&[(Location::Local, "supervisor"), (Location::Cloud, "server")])
                .unwrap_err()
                .to_string(),
            "environment inventory is partial: local VMs and cloud environments could not be listed"
        );
        assert_eq!(
            format_unavailable(&[(Location::Cloud, "connection closed")], true, PLAIN),
            "! Cloud environments could not be listed: connection closed\n  The results above are complete for the other locations.\n→ Retry: cw --cloud ls\n"
        );
        assert_eq!(inventory_target(&app.list).target_ref, "app");
        assert_eq!(
            inventory_target(&entry("r", Location::Cloud, "running").list).kind,
            "env"
        );
        assert_eq!(
            inventory_target(&entry("h", Location::Host, "running").list).kind,
            "host"
        );
    }

    #[test]
    fn the_state_filter_and_order_are_stable() {
        let inventory = EnvironmentInventory {
            entries: vec![
                entry("b", Location::Cloud, "running"),
                entry("a", Location::Cloud, "stopped"),
                entry("b", Location::Local, "Running"),
            ],
            locations: Vec::new(),
        }
        .finish(Some("running"));
        let order: Vec<(&str, Location)> = inventory
            .entries
            .iter()
            .map(|entry| (entry.name(), entry.location))
            .collect();
        assert_eq!(order, [("b", Location::Local), ("b", Location::Cloud)]);
    }
}
