//! `cw snapshot`: local disk snapshots (#3046). A snapshot is a reusable
//! copy of a stopped local VM's disks on this host; `cw create --local
//! --snapshot NAME` starts environments from one, each with fresh identity.
//! Not a VM checkpoint, which would also save a running VM's memory.

// Snapshots are Linux only, so most of this module is unused on other
// targets.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use clap::{Args, Subcommand};
use serde::Serialize;

use super::*;

mod platform;
pub(crate) use platform::create_environments_from_platform_snapshot;

#[derive(Debug, Args)]
pub(crate) struct SnapshotArgs {
    #[command(subcommand)]
    pub(crate) command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotCommand {
    #[command(
        about = "Save a stopped environment's disks as a snapshot",
        after_help = "Examples:\n  cw stop app\n  cw snapshot create app --name good-toolchain\n  cw --cloud snapshot create app\n  cw create --local --snapshot good-toolchain --count 3\n\nThe VM must be stopped. Codewire's delivered sign-ins are removed from the copy; anything else on the disks, such as a .env file or shell history, is kept."
    )]
    Create(SnapshotCreateArgs),
    #[command(visible_alias = "list", about = "List this host's snapshots")]
    Ls(SnapshotListArgs),
    #[command(about = "Show one snapshot: its disks, space and source")]
    Inspect(SnapshotTargetArgs),
    #[command(about = "Remove a snapshot; environments made from it are unaffected")]
    Rm(SnapshotTargetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotCreateArgs {
    #[arg(help = "The stopped environment to snapshot; omit to choose interactively")]
    pub(crate) environment: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "The snapshot's name (default ENV-YYYYMMDD-HHMMSS)"
    )]
    pub(crate) name: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotTargetArgs {
    #[arg(help = "The snapshot, by name or ID")]
    pub(crate) snapshot: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

pub(crate) async fn handle_snapshot_command(
    globals: &Globals,
    mut args: SnapshotArgs,
) -> anyhow::Result<()> {
    let mut effective = globals.clone();
    if let SnapshotCommand::Create(create) = &mut args.command
        && create.environment.is_none()
    {
        super::guided::require_available(
            create.output,
            "name a stopped environment: `cw snapshot create ENV [--name NAME]`",
        )?;
        if effective.placement.is_none() {
            #[cfg(target_os = "linux")]
            {
                effective.placement = Some(
                    if super::guided::choose(
                        "Where is the stopped environment?",
                        &[
                            super::guided::Choice::new("On this computer", "Local disk snapshots"),
                            super::guided::Choice::new("In Codewire cloud", "Cloud disk snapshots"),
                        ],
                    )? == 0
                    {
                        EnvironmentPlacement::Local
                    } else {
                        EnvironmentPlacement::Platform
                    },
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                super::guided::choose(
                    "Where is the stopped environment?",
                    &[super::guided::Choice::new(
                        "In Codewire cloud",
                        "Local disk snapshots require Linux",
                    )],
                )?;
                effective.placement = Some(EnvironmentPlacement::Platform);
            }
        }
        if effective.placement == Some(EnvironmentPlacement::Local) && !cfg!(target_os = "linux") {
            anyhow::bail!(
                "local disk snapshots need a Linux host for now; use --cloud for cloud snapshots"
            );
        }
        let inventory = super::inventory::environment_inventory(
            &effective,
            effective.placement,
            &super::inventory::InventoryOptions {
                state: Some("stopped".to_owned()),
                ..Default::default()
            },
        )
        .await?;
        let entries = snapshot_candidates(&inventory)?;
        let choices = entries
            .iter()
            .map(|entry| {
                super::guided::Choice::new(
                    entry.name(),
                    format!("{} · {}", entry.location.kind(), entry.id()),
                )
            })
            .collect::<Vec<_>>();
        let entry =
            &entries[super::guided::choose("Choose a stopped environment to snapshot", &choices)?];
        create.environment = Some(entry.id().to_owned());
        if create.name.is_none() {
            create.name = Some(super::guided::text(
                "Snapshot name",
                Some(&default_snapshot_name(entry.name(), chrono::Utc::now())),
                super::guided::required,
            )?);
        }
        super::additions::review(
            "Create disk snapshot?",
            &[
                ("Environment", entry.name().to_owned()),
                ("Location", entry.location.kind().to_owned()),
                ("Snapshot", create.name.clone().unwrap_or_default()),
                (
                    "Contents",
                    "Disks, including workload files; delivered sign-ins are removed".to_owned(),
                ),
            ],
        )?;
    }
    let globals = &effective;
    if globals.placement == Some(EnvironmentPlacement::Platform) {
        return platform::handle_platform_snapshot_command(globals, args.command).await;
    }
    #[cfg(target_os = "linux")]
    {
        handle_local_snapshot_command(globals, args.command).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("local disk snapshots need a Linux host for now")
    }
}

fn snapshot_candidates(
    inventory: &super::inventory::EnvironmentInventory,
) -> anyhow::Result<&[super::inventory::InventoryEntry]> {
    if inventory.entries.is_empty() {
        let unavailable = inventory.unavailable();
        if !unavailable.is_empty() {
            for (_, reason) in unavailable {
                eprintln!("{}", progress::terminal_text(reason));
            }
            anyhow::bail!(
                "stopped environments could not be listed; resolve the error above and retry `cw snapshot create`"
            );
        }
        anyhow::bail!(
            "no eligible stopped environments; list environments with `cw ls`, then stop one with `cw stop ENV`"
        );
    }
    Ok(&inventory.entries)
}

#[cfg(target_os = "linux")]
async fn handle_local_snapshot_command(
    globals: &Globals,
    command: SnapshotCommand,
) -> anyhow::Result<()> {
    let status = |action: &'static str| {
        move |status: tonic::Status| anyhow::anyhow!("{action}: {}", status.message())
    };
    let client = native_client().await?;
    match command {
        SnapshotCommand::Create(args) => {
            let environment = args
                .environment
                .as_deref()
                .context("environment is required")?;
            let name = match args.name.as_deref().and_then(trimmed_str) {
                Some(name) => name.to_owned(),
                None => default_snapshot_name(environment, chrono::Utc::now()),
            };
            let account = native_signed_in_account(globals);
            let snapshot = client
                .create_snapshot(environment, &name, account)
                .await
                .map_err(status("snapshot create"))?;
            match args.output {
                OutputFormat::Json => print_json(&SnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!("{}", created_text(&snapshot));
                    print_warnings(&snapshot);
                    Ok(())
                }
            }
        }
        SnapshotCommand::Ls(args) => {
            let snapshots = client
                .list_snapshots()
                .await
                .map_err(status("snapshot ls"))?;
            match args.output {
                OutputFormat::Json => {
                    print_json(&snapshots.iter().map(SnapshotView::from).collect::<Vec<_>>())
                }
                OutputFormat::Text => {
                    println!("{}", list_text(&snapshots));
                    Ok(())
                }
            }
        }
        SnapshotCommand::Inspect(args) => {
            let snapshot = client
                .get_snapshot(&args.snapshot)
                .await
                .map_err(status("snapshot inspect"))?;
            match args.output {
                OutputFormat::Json => print_json(&SnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!("{}", inspect_text(&snapshot));
                    print_warnings(&snapshot);
                    Ok(())
                }
            }
        }
        SnapshotCommand::Rm(args) => {
            let snapshot = client
                .delete_snapshot(&args.snapshot)
                .await
                .map_err(status("snapshot rm"))?;
            match args.output {
                OutputFormat::Json => print_json(&SnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!(
                        "Removed snapshot {}; environments made from it are unaffected.",
                        terminal_text(&snapshot.name)
                    );
                    Ok(())
                }
            }
        }
    }
}

use crate::commands::progress::terminal_text;
use codewire_local_vmm::control::v1;

fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_warnings(snapshot: &v1::Snapshot) {
    for warning in &snapshot.warnings {
        eprintln!("Note: {}.", terminal_text(warning));
    }
}

/// `ENV-YYYYMMDD-HHMMSS`, in UTC.
fn default_snapshot_name(environment: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{environment}-{}", now.format("%Y%m%d-%H%M%S"))
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB)
}

fn created_at(unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| unix_ms.to_string())
}

fn allocated(snapshot: &v1::Snapshot) -> u64 {
    snapshot.disks.iter().map(|disk| disk.allocated_bytes).sum()
}

fn created_text(snapshot: &v1::Snapshot) -> String {
    let logins = match snapshot.removed_logins {
        0 => String::new(),
        1 => "; removed 1 delivered sign-in from the copy".to_owned(),
        removed => format!("; removed {removed} delivered sign-ins from the copy"),
    };
    format!(
        "Snapshot {} of {}: mode={} consistency={} disks={} apparent={} in {:.2} s{logins}",
        terminal_text(&snapshot.name),
        terminal_text(&snapshot.source_name),
        snapshot.mode,
        snapshot.consistency,
        snapshot.disks.len(),
        gib(snapshot.disks.iter().map(|disk| disk.bytes).sum()),
        snapshot.capture_milliseconds as f64 / 1000.0,
    )
}

fn list_text(snapshots: &[v1::Snapshot]) -> String {
    if snapshots.is_empty() {
        return "No snapshots. Make one from a stopped local VM with `cw snapshot create ENV`."
            .to_owned();
    }
    let rows = snapshots
        .iter()
        .map(|snapshot| {
            [
                terminal_text(&snapshot.name),
                terminal_text(&snapshot.source_name),
                created_at(snapshot.created_unix_ms),
                snapshot.disks.len().to_string(),
                terminal_text(&snapshot.image),
                snapshot.mode.clone(),
            ]
        })
        .collect::<Vec<_>>();
    let header = ["NAME", "SOURCE", "CREATED", "DISKS", "IMAGE", "MODE"];
    let widths = (0..header.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .chain([header[column].len()])
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    let line = |cells: Vec<String>| {
        cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    std::iter::once(line(header.iter().map(|cell| (*cell).to_owned()).collect()))
        .chain(rows.into_iter().map(|row| line(row.to_vec())))
        .collect::<Vec<_>>()
        .join("\n")
}

fn inspect_text(snapshot: &v1::Snapshot) -> String {
    let mut lines = vec![
        format!("Snapshot:     {}", terminal_text(&snapshot.name)),
        format!("ID:           {}", snapshot.id),
        format!(
            "Source:       {} ({})",
            terminal_text(&snapshot.source_name),
            snapshot.source_environment_id
        ),
        format!("Created:      {}", created_at(snapshot.created_unix_ms)),
        format!(
            "Consistency:  {}{}",
            snapshot.consistency,
            if snapshot.consistency == "crash" {
                " (what a power loss would have left: the VM was not shut down cleanly)"
            } else {
                ""
            }
        ),
        format!("Locations:    {}", snapshot.locations.join(", ")),
        format!(
            "Signed in:    {}",
            snapshot.account.as_ref().map_or_else(
                || "no platform account".to_owned(),
                |account| format!(
                    "user {} in organization {} at {}",
                    terminal_text(&account.user_id),
                    terminal_text(&account.organization_id),
                    terminal_text(&account.server_url)
                )
            )
        ),
        format!("Image:        {}", terminal_text(&snapshot.image)),
        format!(
            "Resources:    {} vCPU, {} MiB, {} disk{}",
            snapshot.vcpus,
            snapshot.memory_mib,
            gib(snapshot.disk_bytes),
            if snapshot.docker_disk_bytes == 0 {
                String::new()
            } else {
                format!(", {} Docker disk", gib(snapshot.docker_disk_bytes))
            }
        ),
        format!("Mode:         {}", snapshot.mode),
        "Disks:".to_owned(),
    ];
    for disk in &snapshot.disks {
        let shared = disk
            .shared_bytes
            .map(|shared| format!(", {} shared", gib(shared)))
            .unwrap_or_default();
        lines.push(format!(
            "  {:<7} {} apparent, {} allocated{shared} ({})",
            disk.role,
            gib(disk.bytes),
            gib(disk.allocated_bytes),
            disk.mode
        ));
    }
    lines.push(format!(
        "Holds:        {} allocated",
        gib(allocated(snapshot))
    ));
    if snapshot.direct_mounts {
        lines.push(
            "Direct mounts: its source mounts host folders directly; `cw create --snapshot` needs --share-mounts to mount them again".to_owned(),
        );
    }
    lines.push(
        "Secrets:      Codewire's delivered sign-ins were removed at capture; anything else the VM wrote, such as a .env file or shell history, is in the snapshot".to_owned(),
    );
    lines.join("\n")
}

/// `--output json`: what the snapshot is, never its project document.
#[derive(Debug, Serialize)]
struct SnapshotView {
    id: String,
    name: String,
    created_unix_ms: i64,
    source_environment_id: String,
    source_name: String,
    consistency: String,
    locations: Vec<String>,
    architecture: String,
    mode: String,
    image: String,
    vcpus: u32,
    memory_mib: u32,
    disk_bytes: u64,
    docker_disk_bytes: u64,
    disks: Vec<SnapshotDiskView>,
    direct_mounts: bool,
    removed_logins: u32,
    capture_milliseconds: u64,
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<AccountView>,
}

#[derive(Debug, Serialize)]
struct AccountView {
    server_url: String,
    organization_id: String,
    user_id: String,
}

#[derive(Debug, Serialize)]
struct SnapshotDiskView {
    role: String,
    bytes: u64,
    mode: String,
    allocated_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_bytes: Option<u64>,
}

impl From<&v1::Snapshot> for SnapshotView {
    fn from(snapshot: &v1::Snapshot) -> Self {
        Self {
            id: snapshot.id.clone(),
            name: snapshot.name.clone(),
            created_unix_ms: snapshot.created_unix_ms,
            source_environment_id: snapshot.source_environment_id.clone(),
            source_name: snapshot.source_name.clone(),
            consistency: snapshot.consistency.clone(),
            locations: snapshot.locations.clone(),
            architecture: snapshot.architecture.clone(),
            mode: snapshot.mode.clone(),
            image: snapshot.image.clone(),
            vcpus: snapshot.vcpus,
            memory_mib: snapshot.memory_mib,
            disk_bytes: snapshot.disk_bytes,
            docker_disk_bytes: snapshot.docker_disk_bytes,
            disks: snapshot
                .disks
                .iter()
                .map(|disk| SnapshotDiskView {
                    role: disk.role.clone(),
                    bytes: disk.bytes,
                    mode: disk.mode.clone(),
                    allocated_bytes: disk.allocated_bytes,
                    shared_bytes: disk.shared_bytes,
                })
                .collect(),
            direct_mounts: snapshot.direct_mounts,
            removed_logins: snapshot.removed_logins,
            capture_milliseconds: snapshot.capture_milliseconds,
            warnings: snapshot.warnings.clone(),
            account: snapshot.account.as_ref().map(|account| AccountView {
                server_url: account.server_url.clone(),
                organization_id: account.organization_id.clone(),
                user_id: account.user_id.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, clap::Parser)]
    struct Probe {
        #[command(subcommand)]
        command: SnapshotCommand,
    }

    #[test]
    fn snapshot_subcommands_parse() {
        let Probe {
            command: SnapshotCommand::Create(create),
        } = Probe::try_parse_from(["snapshot", "create", "app", "--name", "good-toolchain"])
            .unwrap()
        else {
            panic!("create");
        };
        assert_eq!(create.environment.as_deref(), Some("app"));
        assert_eq!(create.name.as_deref(), Some("good-toolchain"));
        assert!(matches!(
            Probe::try_parse_from(["snapshot", "ls", "--output", "json"])
                .unwrap()
                .command,
            SnapshotCommand::Ls(SnapshotListArgs {
                output: OutputFormat::Json
            })
        ));
        assert!(matches!(
            Probe::try_parse_from(["snapshot", "list"]).unwrap().command,
            SnapshotCommand::Ls(_)
        ));
        assert!(matches!(
            Probe::try_parse_from(["snapshot", "inspect", "s1"]).unwrap().command,
            SnapshotCommand::Inspect(SnapshotTargetArgs { snapshot, .. }) if snapshot == "s1"
        ));
        assert!(matches!(
            Probe::try_parse_from(["snapshot", "rm", "s1"]).unwrap().command,
            SnapshotCommand::Rm(SnapshotTargetArgs { snapshot, .. }) if snapshot == "s1"
        ));
        assert!(matches!(
            Probe::try_parse_from(["snapshot", "create"])
                .unwrap()
                .command,
            SnapshotCommand::Create(SnapshotCreateArgs {
                environment: None,
                ..
            })
        ));
        assert!(Probe::try_parse_from(["snapshot", "rm"]).is_err());
    }

    #[test]
    fn a_default_name_is_the_environment_and_the_utc_time() {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp(1_792_897_200, 0).unwrap();
        assert_eq!(default_snapshot_name("app", now), "app-20261025-030000");
    }

    fn snapshot() -> v1::Snapshot {
        v1::Snapshot {
            id: "6e3c1c39-0f5c-4b37-9d55-8d0e1f2a3b4c".to_owned(),
            name: "s1".to_owned(),
            source_name: "app".to_owned(),
            consistency: "clean".to_owned(),
            mode: "reflink".to_owned(),
            image: "ghcr.io/codewiresh/workspace".to_owned(),
            locations: vec!["local".to_owned()],
            disks: vec![v1::SnapshotDisk {
                role: "state".to_owned(),
                bytes: 4 * 1024 * 1024 * 1024,
                mode: "reflink".to_owned(),
                allocated_bytes: 1024 * 1024 * 1024,
                shared_bytes: Some(1024 * 1024 * 1024),
            }],
            removed_logins: 2,
            capture_milliseconds: 812,
            ..Default::default()
        }
    }

    #[test]
    fn text_output_names_the_mode_and_the_removed_sign_ins() {
        let text = created_text(&snapshot());
        assert!(text.contains("mode=reflink"), "{text}");
        assert!(text.contains("removed 2 delivered sign-ins"), "{text}");
        assert!(text.contains("in 0.81 s"), "{text}");
        let listing = list_text(&[snapshot()]);
        assert!(listing.starts_with("NAME"), "{listing}");
        assert!(listing.contains("s1"), "{listing}");
        assert!(list_text(&[]).starts_with("No snapshots"));
        let inspected = inspect_text(&snapshot());
        assert!(inspected.contains("1.0 GiB shared"), "{inspected}");
        assert!(inspected.contains(".env file"), "{inspected}");
        assert!(inspected.contains("no platform account"), "{inspected}");
    }

    #[test]
    fn unavailable_snapshot_inventory_is_not_reported_as_empty() {
        use super::super::inventory::{
            EnvironmentInventory, Location, LocationReport, LocationStatus,
        };
        let mut inventory = EnvironmentInventory::default();
        assert!(
            snapshot_candidates(&inventory)
                .unwrap_err()
                .to_string()
                .contains("no eligible stopped environments")
        );
        inventory.locations.push(LocationReport {
            location: Location::Cloud,
            status: LocationStatus::Unavailable("synthetic inventory failure".to_owned()),
        });
        let error = snapshot_candidates(&inventory).unwrap_err().to_string();
        assert!(error.contains("could not be listed"));
        assert!(!error.contains("no eligible"));
    }
}
