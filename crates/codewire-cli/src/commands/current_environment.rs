//! `cw use` selects the current environment, from a name or a searchable
//! picker; `cw current` shows it. The selection is saved by canonical
//! identity (see [`crate::config::selection`]) and never starts anything.

use super::inventory::{self, EnvironmentInventory, InventoryEntry, InventoryOptions, Location};
use super::progress::terminal_text;
use super::*;
use crate::config::selection::{self, EnvironmentSelection, SelectionLocation};
use crate::output::{
    Capabilities, NetworkRef, OutputMode, Picker, PickerOutcome, Role, Status, Style, run_picker,
};

const CANCELED: &str = "selection canceled; the current environment is unchanged";

/// `cw use [ENV]`.
pub(crate) async fn handle_use_command(
    globals: &Globals,
    args: UseTargetArgs,
) -> anyhow::Result<()> {
    let placement = globals.placement;
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let caps = Capabilities::from_process(OutputMode::Text);
    let target = args.target.as_deref().and_then(trimmed_str);
    // Scripts never receive a picker: refuse before listing or writing.
    if target.is_none() && !picker_available(&caps) {
        anyhow::bail!(picker_unavailable(placement));
    }
    let options = InventoryOptions {
        credentials: true,
        hosts: true,
        ..InventoryOptions::default()
    };
    let inventory = inventory::environment_inventory(globals, placement, &options).await?;
    let entry = match target {
        Some(target) => inventory::find_direct(&inventory, target, placement)?.clone(),
        None => choose(globals, &inventory, placement, &caps).await?,
    };
    selection::save(&paths.mesh_data_dir, &entry.selection())
        .context("save the current environment")?;
    // Only `cw info`'s `selected` field still reports the supervisor's own
    // flag; nothing resolves a target from it. Best effort, after the save.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if entry.location == Location::Local {
        let _ = select_native_environment(entry.name()).await;
    }
    print!("{}", format_selected(&entry, caps.stdout_style()));
    Ok(())
}

fn picker_available(caps: &Capabilities) -> bool {
    cfg!(unix) && caps.interactive && caps.live
}

fn picker_unavailable(placement: Option<EnvironmentPlacement>) -> String {
    format!(
        "an environment is required outside an interactive terminal; the current environment is unchanged: `{} use ENV`",
        inventory::placement_prefix(placement)
    )
}

/// The picker over every environment the placement admits: local VMs,
/// cloud environments and trusted hosts. Locations that could not be listed
/// are reported above it, not shown as empty. With nothing to choose from
/// it offers to create an environment, which becomes the selection; when a
/// location could not be listed it explains that instead.
async fn choose(
    globals: &Globals,
    inventory: &EnvironmentInventory,
    placement: Option<EnvironmentPlacement>,
    caps: &Capabilities,
) -> anyhow::Result<InventoryEntry> {
    let style = caps.stderr_style();
    let (header, indices, rows) = inventory::picker_rows(inventory, style);
    let unavailable = inventory.unavailable();
    if rows.is_empty() {
        if !unavailable.is_empty() {
            anyhow::bail!(nothing_to_choose(inventory, placement));
        }
        eprintln!(
            "{} {}",
            style.status(Status::Attention),
            capitalized(&nothing_to_choose(inventory, placement))
        );
        return create_to_use(globals, placement).await;
    }
    for (location, reason) in &unavailable {
        eprintln!(
            "{} {} could not be listed: {}",
            style.status(Status::Attention),
            capitalized(location.listing()),
            terminal_text(reason)
        );
    }
    let picker = Picker::new("Choose an environment", header, rows);
    let caps = *caps;
    let outcome = tokio::task::spawn_blocking(move || run_picker(picker, &caps))
        .await
        .context("choose an environment")??;
    match outcome {
        PickerOutcome::Chosen(row) => Ok(inventory.entries[indices[row]].clone()),
        PickerOutcome::Canceled => anyhow::bail!(CANCELED),
        PickerOutcome::Unavailable => anyhow::bail!(picker_unavailable(placement)),
    }
}

/// The guided choice `cw run` offers when nothing is selected: create a
/// local or cloud environment, reviewed before it is made. What it creates
/// is listed again so the selection keeps its canonical identity.
async fn create_to_use(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<InventoryEntry> {
    let Command::Run(run) = Cli::try_parse_from(["cw", "run"])?.command else {
        anyhow::bail!("`cw run` parsed as another command");
    };
    let (target, _) = super::launch_setup::choose_run_environment(globals, &run).await?;
    let options = InventoryOptions {
        credentials: true,
        hosts: true,
        ..InventoryOptions::default()
    };
    let inventory = inventory::environment_inventory(globals, placement, &options).await?;
    Ok(inventory::find_direct(&inventory, &target.target_ref, placement)?.clone())
}

/// Why the picker has no rows, with the useful next step.
fn nothing_to_choose(
    inventory: &EnvironmentInventory,
    placement: Option<EnvironmentPlacement>,
) -> String {
    let unavailable = inventory.unavailable();
    if !unavailable.is_empty() {
        let reasons: Vec<String> = unavailable
            .iter()
            .map(|(location, reason)| {
                format!("{} could not be listed: {reason}", location.listing())
            })
            .collect();
        return format!(
            "{}; the current environment is unchanged",
            reasons.join("; ")
        );
    }
    let scope = match placement {
        Some(EnvironmentPlacement::Local) => "local ",
        Some(EnvironmentPlacement::Platform) => "cloud ",
        None => "",
    };
    let mut message = format!("no {scope}environments to choose from yet");
    if placement.is_none() {
        for (location, reason) in inventory.not_configured() {
            if location == Location::Cloud {
                message.push_str(&format!(
                    " (cloud environments were not searched: {reason})"
                ));
            }
        }
    }
    format!(
        "{message}; create one with `{} create`",
        inventory::placement_prefix(placement)
    )
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The `cw use` result:
///
/// ```text
/// ✓ Current environment: app
///   local VM · stopped
///   2 vCPU · 4 GiB RAM · 40 GiB disk
///   Credentials: platform:work
///
/// → cw --local shell app
/// ```
fn format_selected(entry: &InventoryEntry, style: Style) -> String {
    let dim = |text: &str| style.paint(Role::Dim, text);
    let name = terminal_text(entry.name());
    let mut out = format!(
        "{} Current environment: {name}\n  {}\n",
        style.status(Status::Done),
        dim(&format!(
            "{}{}{}",
            entry.location.kind(),
            style.separator(),
            terminal_text(display_str(entry.state()))
        ))
    );
    if let Some(size) = entry.allocation.render(style) {
        out.push_str(&format!("  {}\n", dim(&size)));
    }
    if entry.location != Location::Host {
        let credentials = entry.credentials.text();
        out.push_str(&format!(
            "  Credentials: {}\n",
            if entry.credentials.is_none() {
                dim(&credentials)
            } else {
                credentials
            }
        ));
    }
    out.push_str(&format!(
        "\n{} {} shell {name}\n",
        style.status(Status::Next),
        entry.location.command_prefix()
    ));
    out
}

/// What `cw current` found for the selection.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Lookup {
    Found {
        id: String,
        state: String,
        network: NetworkRef,
    },
    /// The selected environment no longer exists (a recreated local VM with
    /// the same name is a different environment).
    Missing,
    /// Its location could not be read.
    Unavailable(String),
}

/// `cw current`.
pub(crate) async fn handle_current_command(
    globals: &Globals,
    args: CurrentTargetArgs,
) -> anyhow::Result<()> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let selected = selection::load(&paths.mesh_data_dir)?;
    let current = match selected {
        Some(selected) => {
            let lookup = lookup(globals, &paths, &selected).await;
            Some((selected, lookup))
        }
        None => None,
    };
    let current = current
        .as_ref()
        .map(|(selected, lookup)| (selected, lookup));
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&current_json(current))?),
        OutputFormat::Text => {
            let caps = Capabilities::from_process(OutputMode::Text);
            print!(
                "{}",
                format_current(current, args.verbose, caps.stdout_style())
            );
        }
    }
    Ok(())
}

async fn lookup(
    globals: &Globals,
    paths: &ResolvePaths,
    selected: &EnvironmentSelection,
) -> Lookup {
    match selected.location {
        SelectionLocation::Local => lookup_local(selected).await,
        SelectionLocation::Cloud => lookup_cloud(globals, paths, selected)
            .await
            .unwrap_or_else(|error| Lookup::Unavailable(format!("{error:#}"))),
        SelectionLocation::Host => lookup_host(selected),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn lookup_local(selected: &EnvironmentSelection) -> Lookup {
    let listed = async {
        if !native_state_exists()? {
            return anyhow::Ok(Vec::new());
        }
        native_environments().await
    }
    .await;
    match listed {
        Ok(environments) => environments
            .iter()
            .find(|environment| selected.is_local_vm(&environment.id, &environment.name))
            .map(|environment| {
                let entry = inventory::local_entry(environment, Some(selected));
                Lookup::Found {
                    id: entry.list.id,
                    state: entry.list.state,
                    network: entry.network,
                }
            })
            .unwrap_or(Lookup::Missing),
        Err(error) => Lookup::Unavailable(format!("{error:#}")),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn lookup_local(_selected: &EnvironmentSelection) -> Lookup {
    Lookup::Unavailable("local VMs are not available on this platform".to_owned())
}

/// The selected cloud environment, looked up in the organization it was
/// selected in (the current one for a selection an older `cw` saved).
async fn lookup_cloud(
    globals: &Globals,
    paths: &ResolvePaths,
    selected: &EnvironmentSelection,
) -> anyhow::Result<Lookup> {
    let platform = match resolve_platform(globals, paths, &OsEnv) {
        Ok(platform) => platform,
        Err(error) => return Ok(Lookup::Unavailable(inventory::cloud_not_configured(&error))),
    };
    let organization_id = match selected.organization_id.as_deref().and_then(trimmed_str) {
        Some(organization_id) => organization_id.to_owned(),
        None => {
            let orgs = organization_client(&platform)?
                .list_orgs()
                .await
                .context("list orgs")?;
            current_org_id(&platform, &orgs)?
        }
    };
    let environments = EnvironmentClient::new(&platform)?
        .list_environments(&organization_id, false)
        .await
        .context("list environments")?;
    Ok(environments
        .iter()
        .find(|environment| environment.id == selected.id && environment.state != "destroyed")
        .map(|environment| {
            let entry = inventory::cloud_entry(environment, "", &organization_id, None, None);
            Lookup::Found {
                id: entry.list.id,
                state: entry.list.state,
                network: entry.network,
            }
        })
        .unwrap_or(Lookup::Missing))
}

#[cfg(unix)]
fn lookup_host(selected: &EnvironmentSelection) -> Lookup {
    match host_environment(&selected.id) {
        Ok(Some(environment)) if environment.id == selected.id => Lookup::Found {
            id: environment.id,
            state: environment.state,
            network: NetworkRef::NotAttached,
        },
        Ok(_) => Lookup::Missing,
        Err(error) => Lookup::Unavailable(format!("{error:#}")),
    }
}

#[cfg(not(unix))]
fn lookup_host(_selected: &EnvironmentSelection) -> Lookup {
    Lookup::Unavailable("trusted host environments are supported on Linux and macOS".to_owned())
}

/// `cw current`:
///
/// ```text
/// app · local VM · running
///   Network:     cloud:work
///
/// → cw --local info app
/// ```
fn format_current(
    current: Option<(&EnvironmentSelection, &Lookup)>,
    verbose: bool,
    style: Style,
) -> String {
    let dim = |text: &str| style.paint(Role::Dim, text);
    let Some((selected, lookup)) = current else {
        return format!(
            "No environment selected.\n\n{} cw use\n",
            style.status(Status::Next)
        );
    };
    let location = Location::from_selection(selected.location);
    let name = terminal_text(&selected.name);
    let mut out = String::new();
    match lookup {
        Lookup::Found { state, network, .. } => {
            out.push_str(&format!(
                "{name}{}\n",
                dim(&format!(
                    "{}{}{}{}",
                    style.separator(),
                    location.kind(),
                    style.separator(),
                    terminal_text(display_str(state))
                ))
            ));
            if location != Location::Host {
                let text = network.text();
                out.push_str(&format!(
                    "  {:<13}{}\n",
                    "Network:",
                    if network.is_attached() {
                        text
                    } else {
                        dim(&text)
                    }
                ));
            }
        }
        Lookup::Missing => {
            out.push_str(&format!(
                "{} {name}{} no longer exists\n  {}\n",
                style.status(Status::Attention),
                dim(&format!("{}{}", style.separator(), location.kind())),
                dim("It was removed or replaced; choose another environment.")
            ));
        }
        Lookup::Unavailable(reason) => {
            out.push_str(&format!(
                "{name}{}\n  {} State unknown: {}\n",
                dim(&format!("{}{}", style.separator(), location.kind())),
                style.status(Status::Attention),
                terminal_text(reason)
            ));
        }
    }
    if verbose {
        let id = match lookup {
            Lookup::Found { id, .. } => id.as_str(),
            _ => selected.id.as_str(),
        };
        out.push_str(&format!("  {:<13}{}\n", "ID:", terminal_text(id)));
        if let Some(organization_id) = &selected.organization_id {
            out.push_str(&format!(
                "  {:<13}{}\n",
                "Organization:",
                terminal_text(organization_id)
            ));
        }
    }
    let next = match lookup {
        Lookup::Found { .. } if location == Location::Host => None,
        Lookup::Found { .. } => Some(format!("{} info {name}", location.command_prefix())),
        Lookup::Missing => Some("cw use".to_owned()),
        Lookup::Unavailable(_) => None,
    };
    if let Some(next) = next {
        out.push_str(&format!("\n{} {next}\n", style.status(Status::Next)));
    }
    out
}

/// `cw current --output json`: `{"selected": false}`, or the selection
/// with `status` `found`, `missing` or `unavailable`.
fn current_json(current: Option<(&EnvironmentSelection, &Lookup)>) -> serde_json::Value {
    let Some((selected, lookup)) = current else {
        return serde_json::json!({ "selected": false });
    };
    let (status, id, state, network, error) = match lookup {
        Lookup::Found { id, state, network } => (
            "found",
            id.as_str(),
            Some(state.as_str()),
            network.is_attached().then(|| network.text()),
            None,
        ),
        Lookup::Missing => ("missing", selected.id.as_str(), None, None, None),
        Lookup::Unavailable(reason) => (
            "unavailable",
            selected.id.as_str(),
            None,
            None,
            Some(reason.as_str()),
        ),
    };
    serde_json::json!({
        "selected": true,
        "id": id,
        "name": selected.name,
        "location": Location::from_selection(selected.location).label(),
        "organization_id": selected.organization_id,
        "status": status,
        "state": state,
        "network": network,
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Allocation, Charset, MeshPlacement, SourcePlacement, SourceRef};

    const PLAIN: Style = Style::new(false, Charset::Unicode);
    const VM_ID: &str = "8f0c2b3e-4d5a-4b6c-9d7e-0f1a2b3c4d5e";

    fn local() -> EnvironmentSelection {
        EnvironmentSelection {
            location: SelectionLocation::Local,
            id: VM_ID.into(),
            name: "app".into(),
            organization_id: None,
        }
    }

    fn entry(location: Location, state: &str) -> InventoryEntry {
        InventoryEntry {
            list: UnifiedEnvironmentListEntry {
                environment_type: "sandbox".into(),
                name: "app".into(),
                placement: "local".into(),
                selected: false,
                state: state.into(),
                restarted: false,
                failed: None,
                daemon_health: String::new(),
                id: VM_ID.into(),
            },
            location,
            organization_id: None,
            allocation: Allocation::local(2, 4096, 40 << 30),
            credentials: SourceRef::Named {
                placement: SourcePlacement::Platform,
                name: "work".into(),
            },
            network: NetworkRef::NotAttached,
        }
    }

    #[test]
    fn the_use_result_names_location_state_size_profile_and_next_command() {
        assert_eq!(
            format_selected(&entry(Location::Local, "stopped"), PLAIN),
            concat!(
                "✓ Current environment: app\n",
                "  local VM · stopped\n",
                "  2 vCPU · 4 GiB RAM · 40 GiB disk\n",
                "  Credentials: platform:work\n",
                "\n",
                "→ cw --local shell app\n",
            )
        );
        let mut cloud = entry(Location::Cloud, "running");
        cloud.credentials = SourceRef::None;
        cloud.allocation = Allocation::default();
        assert_eq!(
            format_selected(&cloud, Style::new(false, Charset::Ascii)),
            concat!(
                "+ Current environment: app\n",
                "  cloud VM - running\n",
                "  Credentials: none\n",
                "\n",
                "-> cw --cloud shell app\n",
            )
        );
    }

    #[test]
    fn current_shows_the_selection_its_state_and_its_saved_network() {
        let selected = local();
        let found = Lookup::Found {
            id: VM_ID.into(),
            state: "running".into(),
            network: NetworkRef::Attached {
                mesh: MeshPlacement::Cloud,
                network: "work".into(),
            },
        };
        assert_eq!(
            format_current(Some((&selected, &found)), false, PLAIN),
            "app · local VM · running\n  Network:     cloud:work\n\n→ cw --local info app\n"
        );
        assert_eq!(
            format_current(Some((&selected, &found)), true, PLAIN),
            format!(
                "app · local VM · running\n  Network:     cloud:work\n  ID:          {VM_ID}\n\n→ cw --local info app\n"
            )
        );
        assert_eq!(
            format_current(Some((&selected, &Lookup::Missing)), false, PLAIN),
            "! app · local VM no longer exists\n  It was removed or replaced; choose another environment.\n\n→ cw use\n"
        );
        assert_eq!(
            format_current(
                Some((&selected, &Lookup::Unavailable("supervisor refused".into()))),
                false,
                PLAIN
            ),
            "app · local VM\n  ! State unknown: supervisor refused\n"
        );
        assert_eq!(
            format_current(None, false, PLAIN),
            "No environment selected.\n\n→ cw use\n"
        );
    }

    #[test]
    fn current_json_reports_the_selection_without_decoration() {
        assert_eq!(current_json(None), serde_json::json!({"selected": false}));
        let cloud = EnvironmentSelection {
            location: SelectionLocation::Cloud,
            id: "env-review".into(),
            name: "review".into(),
            organization_id: Some("org-1".into()),
        };
        let found = Lookup::Found {
            id: "env-review".into(),
            state: "stopped".into(),
            network: NetworkRef::NotAttached,
        };
        assert_eq!(
            current_json(Some((&cloud, &found))),
            serde_json::json!({
                "selected": true,
                "id": "env-review",
                "name": "review",
                "location": "cloud",
                "organization_id": "org-1",
                "status": "found",
                "state": "stopped",
                "network": null,
                "error": null,
            })
        );
        let missing = current_json(Some((&local(), &Lookup::Missing)));
        assert_eq!(missing["status"], "missing");
        assert_eq!(missing["state"], serde_json::Value::Null);
        let unavailable = current_json(Some((&local(), &Lookup::Unavailable("down".into()))));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["error"], "down");
    }

    #[test]
    fn refusals_explain_the_scope_and_the_repair() {
        assert_eq!(
            picker_unavailable(Some(EnvironmentPlacement::Local)),
            "an environment is required outside an interactive terminal; the current environment is unchanged: `cw --local use ENV`"
        );
        let empty = EnvironmentInventory::default();
        assert_eq!(
            nothing_to_choose(&empty, None),
            "no environments to choose from yet; create one with `cw create`"
        );
        assert_eq!(
            nothing_to_choose(&empty, Some(EnvironmentPlacement::Platform)),
            "no cloud environments to choose from yet; create one with `cw --cloud create`"
        );
        let logged_out = EnvironmentInventory {
            entries: Vec::new(),
            locations: vec![
                inventory::LocationReport {
                    location: Location::Local,
                    status: inventory::LocationStatus::Listed,
                },
                inventory::LocationReport {
                    location: Location::Cloud,
                    status: inventory::LocationStatus::NotConfigured(
                        "not logged in (`cw login`)".into(),
                    ),
                },
            ],
            recoveries: Vec::new(),
        };
        assert_eq!(
            nothing_to_choose(&logged_out, None),
            "no environments to choose from yet (cloud environments were not searched: not logged in (`cw login`)); create one with `cw create`"
        );
        let down = EnvironmentInventory {
            entries: Vec::new(),
            locations: vec![inventory::LocationReport {
                location: Location::Local,
                status: inventory::LocationStatus::Unavailable("supervisor refused".into()),
            }],
            recoveries: Vec::new(),
        };
        assert_eq!(
            nothing_to_choose(&down, Some(EnvironmentPlacement::Local)),
            "local VMs could not be listed: supervisor refused; the current environment is unchanged"
        );
        assert_eq!(capitalized("cloud environments"), "Cloud environments");
    }
}
