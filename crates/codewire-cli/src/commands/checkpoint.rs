//! `cw checkpoint`: VM checkpoints of running local VMs (#3046 R4). A VM
//! checkpoint saves a running VM's memory, device state and disks at one
//! instant, on this host; it is never exported. Hidden until restore and
//! forks land.

// VM checkpoints are Linux only, so most of this module is unused on other
// targets.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use clap::{Args, Subcommand};
use serde::Serialize;

use super::*;

#[derive(Debug, Args)]
pub(crate) struct CheckpointArgs {
    #[command(subcommand)]
    pub(crate) command: CheckpointCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CheckpointCommand {
    #[command(
        about = "Save a running local VM's memory, device state and disks",
        after_help = "Examples:\n  cw checkpoint create app --name before-refactor\n  cw checkpoint ls\n\nThe VM keeps running; it stands still for the moment its memory is written. A VM checkpoint holds everything its memory held, delivered sign-ins included, until they expire; it stays on this host."
    )]
    Create(CheckpointCreateArgs),
    #[command(visible_alias = "list", about = "List this host's VM checkpoints")]
    Ls(CheckpointListArgs),
    #[command(about = "Show one VM checkpoint: its memory, disks, timings and VMM")]
    Inspect(CheckpointTargetArgs),
    #[command(
        about = "Put a local VM back at a VM checkpoint's instant",
        after_help = "Examples:\n  cw checkpoint restore before-refactor\n  cw checkpoint restore before-refactor --yes\n\nThe VM checkpoint's own environment goes back: its running processes and every disk change since the checkpoint are discarded. To keep it and run the checkpoint beside it, fork it with `cw create --local --checkpoint NAME`."
    )]
    Restore(CheckpointRestoreArgs),
    #[command(about = "Remove a VM checkpoint")]
    Rm(CheckpointTargetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointRestoreArgs {
    #[arg(help = "The VM checkpoint, by name or ID")]
    pub(crate) checkpoint: String,
    #[arg(
        long,
        help = "Stop the running environment without asking; its running state and disk changes since the checkpoint are discarded"
    )]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointCreateArgs {
    #[arg(help = "The running local environment to checkpoint")]
    pub(crate) environment: String,
    #[arg(
        long,
        value_name = "NAME",
        help = "The VM checkpoint's name (default ENV-YYYYMMDDTHHMMSSZ)"
    )]
    pub(crate) name: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointListArgs {
    #[arg(
        long,
        value_name = "ENV",
        help = "Only this environment's VM checkpoints"
    )]
    pub(crate) env: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointTargetArgs {
    #[arg(help = "The VM checkpoint, by name or ID")]
    pub(crate) checkpoint: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

pub(crate) async fn handle_checkpoint_command(
    globals: &Globals,
    args: CheckpointArgs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        globals.placement != Some(EnvironmentPlacement::Platform),
        "VM checkpoints are local only for now; cloud environments cannot be checkpointed yet"
    );
    #[cfg(target_os = "linux")]
    {
        handle_local_checkpoint_command(globals, args.command).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("VM checkpoints need a Linux host for now")
    }
}

#[cfg(target_os = "linux")]
async fn handle_local_checkpoint_command(
    globals: &Globals,
    command: CheckpointCommand,
) -> anyhow::Result<()> {
    let status = |action: &'static str| {
        move |status: tonic::Status| anyhow::anyhow!("{action}: {}", status.message())
    };
    let mut client = native_client().await?;
    match command {
        CheckpointCommand::Create(args) => {
            // The supervisor names it by the UTC time when none is given.
            let name = args
                .name
                .as_deref()
                .and_then(trimmed_str)
                .unwrap_or_default()
                .to_owned();
            let account = native_signed_in_account(globals);
            let checkpoint = client
                .create_checkpoint(&args.environment, &name, account)
                .await
                .map_err(status("checkpoint create"))?;
            match args.output {
                OutputFormat::Json => print_json(&CheckpointView::from(&checkpoint)),
                OutputFormat::Text => {
                    println!("{}", created_text(&checkpoint));
                    print_warnings(&checkpoint);
                    Ok(())
                }
            }
        }
        CheckpointCommand::Ls(args) => {
            let checkpoints = client
                .list_checkpoints(args.env.as_deref().unwrap_or_default())
                .await
                .map_err(status("checkpoint ls"))?;
            match args.output {
                OutputFormat::Json => print_json(
                    &checkpoints
                        .iter()
                        .map(CheckpointView::from)
                        .collect::<Vec<_>>(),
                ),
                OutputFormat::Text => {
                    println!("{}", list_text(&checkpoints));
                    Ok(())
                }
            }
        }
        CheckpointCommand::Inspect(args) => {
            let checkpoint = client
                .get_checkpoint(&args.checkpoint)
                .await
                .map_err(status("checkpoint inspect"))?;
            match args.output {
                OutputFormat::Json => print_json(&CheckpointView::from(&checkpoint)),
                OutputFormat::Text => {
                    println!("{}", inspect_text(&checkpoint));
                    print_warnings(&checkpoint);
                    Ok(())
                }
            }
        }
        CheckpointCommand::Restore(args) => {
            let checkpoint = client
                .get_checkpoint(&args.checkpoint)
                .await
                .map_err(status("checkpoint restore"))?;
            let source = checkpoint.source_name.clone();
            let started = std::time::Instant::now();
            let environment = client
                .get(&source)
                .await
                .map_err(status("checkpoint restore"))?;
            let mut stopped = None;
            if environment.state != v1::EnvironmentState::Stopped as i32 {
                if !confirm_restore(&source, &checkpoint.name, args.yes)? {
                    anyhow::bail!("restore cancelled; {source} is unchanged");
                }
                let stopping = std::time::Instant::now();
                client
                    .stop(&source)
                    .await
                    .map_err(status("checkpoint restore: stop"))?;
                stopped = Some(stopping.elapsed());
            }
            let restoring = std::time::Instant::now();
            let account = native_signed_in_account(globals);
            let environment = client
                .restore_checkpoint_observed(&checkpoint.name, &source, account, &mut |_| {})
                .await
                .map_err(status("checkpoint restore"))?;
            let restored = restoring.elapsed();
            match args.output {
                OutputFormat::Json => print_json(&serde_json::json!({
                    "checkpoint": CheckpointView::from(&checkpoint),
                    "environment": environment.name,
                    "generation": environment.generation,
                    "stop_ms": stopped.map(|elapsed| elapsed.as_millis() as u64),
                    "restore_ms": restored.as_millis() as u64,
                    "total_ms": started.elapsed().as_millis() as u64,
                })),
                OutputFormat::Text => {
                    println!(
                        "Restored {} to VM checkpoint {}{} restore {:.2} s, total {:.2} s",
                        terminal_text(&environment.name),
                        terminal_text(&checkpoint.name),
                        stopped
                            .map(|elapsed| format!(": stop {:.2} s,", elapsed.as_secs_f64()))
                            .unwrap_or_else(|| ":".to_owned()),
                        restored.as_secs_f64(),
                        started.elapsed().as_secs_f64()
                    );
                    Ok(())
                }
            }
        }
        CheckpointCommand::Rm(args) => {
            let checkpoint = client
                .delete_checkpoint(&args.checkpoint)
                .await
                .map_err(status("checkpoint rm"))?;
            match args.output {
                OutputFormat::Json => print_json(&CheckpointView::from(&checkpoint)),
                OutputFormat::Text => {
                    println!("Removed VM checkpoint {}.", terminal_text(&checkpoint.name));
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

/// Ask before discarding a running environment's state, unless `yes`.
fn confirm_restore(source: &str, checkpoint: &str, yes: bool) -> anyhow::Result<bool> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    if yes {
        return Ok(true);
    }
    anyhow::ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "{source} is running; restoring discards its running state and every disk change since {checkpoint}: pass --yes to do it noninteractively"
    );
    let mut stderr = std::io::stderr().lock();
    write!(
        stderr,
        "Restore discards {source}'s running state and every disk change since {checkpoint}. Continue? [y/N]: "
    )?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn print_warnings(checkpoint: &v1::Checkpoint) {
    for warning in &checkpoint.warnings {
        eprintln!("Note: {}.", terminal_text(warning));
    }
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB)
}

fn milliseconds(micros: u64) -> String {
    format!("{:.0} ms", micros as f64 / 1000.0)
}

fn created_at(unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| unix_ms.to_string())
}

fn created_text(checkpoint: &v1::Checkpoint) -> String {
    let timings = checkpoint.timings.unwrap_or_default();
    format!(
        "VM checkpoint {} of {}: VM paused {}, workload frozen {}, total {}; memory {}, disks {}",
        terminal_text(&checkpoint.name),
        terminal_text(&checkpoint.source_name),
        milliseconds(timings.vm_paused_us),
        milliseconds(timings.workload_frozen_us),
        milliseconds(timings.total_us),
        gib(checkpoint.memory_bytes),
        checkpoint.disks.len(),
    )
}

fn list_text(checkpoints: &[v1::Checkpoint]) -> String {
    if checkpoints.is_empty() {
        return "No VM checkpoints. Make one of a running local VM with `cw checkpoint create ENV`."
            .to_owned();
    }
    let rows = checkpoints
        .iter()
        .map(|checkpoint| {
            [
                terminal_text(&checkpoint.name),
                terminal_text(&checkpoint.source_name),
                created_at(checkpoint.created_unix_ms),
                gib(checkpoint.memory_bytes),
                milliseconds(checkpoint.timings.unwrap_or_default().vm_paused_us),
                gib(checkpoint.memory_allocated_bytes
                    + checkpoint
                        .disks
                        .iter()
                        .map(|disk| disk.allocated_bytes)
                        .sum::<u64>()),
                if checkpoint.unrestorable_reason.is_empty() {
                    "ready".to_owned()
                } else {
                    "unrestorable".to_owned()
                },
            ]
        })
        .collect::<Vec<_>>();
    let header = [
        "NAME", "ENV", "CREATED", "MEMORY", "PAUSE", "BYTES", "STATE",
    ];
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

fn inspect_text(checkpoint: &v1::Checkpoint) -> String {
    let timings = checkpoint.timings.unwrap_or_default();
    let mut lines = vec![
        format!("VM checkpoint: {}", terminal_text(&checkpoint.name)),
        format!("ID:            {}", checkpoint.id),
        format!(
            "Source:        {} ({}), boot generation {}",
            terminal_text(&checkpoint.source_name),
            checkpoint.source_environment_id,
            checkpoint.source_generation
        ),
        format!("Created:       {}", created_at(checkpoint.created_unix_ms)),
        format!(
            "Consistency:   {} (its disks are exact with its memory)",
            checkpoint.consistency
        ),
        format!("Locations:     {}", checkpoint.locations.join(", ")),
        format!("Image:         {}", terminal_text(&checkpoint.image)),
        format!(
            "Resources:     {} vCPU, {} MiB, {} disk",
            checkpoint.vcpus,
            checkpoint.memory_mib,
            gib(checkpoint.disk_bytes)
        ),
        format!(
            "VMM:           Cloud Hypervisor {} (sha256 {})",
            terminal_text(&checkpoint.vmm_version),
            terminal_text(&checkpoint.vmm_sha256)
        ),
        format!(
            "Memory:        {} apparent, {} allocated",
            gib(checkpoint.memory_bytes),
            gib(checkpoint.memory_allocated_bytes)
        ),
        "Disks:".to_owned(),
    ];
    for disk in &checkpoint.disks {
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
        "Timings:       guest freeze {}, workload frozen {}, VM paused {}, memory write {}, disk clones {}, total {}",
        milliseconds(timings.guest_freeze_us),
        milliseconds(timings.workload_frozen_us),
        milliseconds(timings.vm_paused_us),
        milliseconds(timings.memory_write_us),
        milliseconds(timings.disk_clone_us),
        milliseconds(timings.total_us),
    ));
    lines.push(if checkpoint.unrestorable_reason.is_empty() {
        "State:         ready".to_owned()
    } else {
        format!(
            "State:         unrestorable: {}",
            terminal_text(&checkpoint.unrestorable_reason)
        )
    });
    lines.join("\n")
}

/// `--output json`.
#[derive(Debug, Serialize)]
struct CheckpointView {
    id: String,
    name: String,
    created_unix_ms: i64,
    source_environment_id: String,
    source_name: String,
    source_generation: u64,
    consistency: String,
    locations: Vec<String>,
    architecture: String,
    image: String,
    vcpus: u32,
    memory_mib: u32,
    memory_bytes: u64,
    memory_allocated_bytes: u64,
    disks: Vec<DiskView>,
    vmm_version: String,
    vmm_sha256: String,
    guest_checkpoint_abi: u32,
    timings: TimingsView,
    #[serde(skip_serializing_if = "String::is_empty")]
    unrestorable_reason: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiskView {
    role: String,
    bytes: u64,
    mode: String,
    allocated_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TimingsView {
    guest_freeze_us: u64,
    workload_frozen_us: u64,
    vm_paused_us: u64,
    memory_write_us: u64,
    disk_clone_us: u64,
    total_us: u64,
}

impl From<&v1::Checkpoint> for CheckpointView {
    fn from(checkpoint: &v1::Checkpoint) -> Self {
        let timings = checkpoint.timings.unwrap_or_default();
        Self {
            id: checkpoint.id.clone(),
            name: checkpoint.name.clone(),
            created_unix_ms: checkpoint.created_unix_ms,
            source_environment_id: checkpoint.source_environment_id.clone(),
            source_name: checkpoint.source_name.clone(),
            source_generation: checkpoint.source_generation,
            consistency: checkpoint.consistency.clone(),
            locations: checkpoint.locations.clone(),
            architecture: checkpoint.architecture.clone(),
            image: checkpoint.image.clone(),
            vcpus: checkpoint.vcpus,
            memory_mib: checkpoint.memory_mib,
            memory_bytes: checkpoint.memory_bytes,
            memory_allocated_bytes: checkpoint.memory_allocated_bytes,
            disks: checkpoint
                .disks
                .iter()
                .map(|disk| DiskView {
                    role: disk.role.clone(),
                    bytes: disk.bytes,
                    mode: disk.mode.clone(),
                    allocated_bytes: disk.allocated_bytes,
                    shared_bytes: disk.shared_bytes,
                })
                .collect(),
            vmm_version: checkpoint.vmm_version.clone(),
            vmm_sha256: checkpoint.vmm_sha256.clone(),
            guest_checkpoint_abi: checkpoint.guest_checkpoint_abi,
            timings: TimingsView {
                guest_freeze_us: timings.guest_freeze_us,
                workload_frozen_us: timings.workload_frozen_us,
                vm_paused_us: timings.vm_paused_us,
                memory_write_us: timings.memory_write_us,
                disk_clone_us: timings.disk_clone_us,
                total_us: timings.total_us,
            },
            unrestorable_reason: checkpoint.unrestorable_reason.clone(),
            warnings: checkpoint.warnings.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, clap::Parser)]
    struct Probe {
        #[command(subcommand)]
        command: CheckpointCommand,
    }

    #[test]
    fn checkpoint_subcommands_parse() {
        let Probe {
            command: CheckpointCommand::Create(create),
        } = Probe::try_parse_from(["checkpoint", "create", "app", "--name", "c1"]).unwrap()
        else {
            panic!("create");
        };
        assert_eq!(create.environment, "app");
        assert_eq!(create.name.as_deref(), Some("c1"));
        assert!(matches!(
            Probe::try_parse_from(["checkpoint", "ls", "--env", "app"])
                .unwrap()
                .command,
            CheckpointCommand::Ls(CheckpointListArgs { env: Some(env), .. }) if env == "app"
        ));
        assert!(matches!(
            Probe::try_parse_from(["checkpoint", "list"])
                .unwrap()
                .command,
            CheckpointCommand::Ls(_)
        ));
        assert!(matches!(
            Probe::try_parse_from(["checkpoint", "inspect", "c1"]).unwrap().command,
            CheckpointCommand::Inspect(CheckpointTargetArgs { checkpoint, .. }) if checkpoint == "c1"
        ));
        assert!(matches!(
            Probe::try_parse_from(["checkpoint", "rm", "c1"])
                .unwrap()
                .command,
            CheckpointCommand::Rm(_)
        ));
        assert!(matches!(
            Probe::try_parse_from(["checkpoint", "restore", "c1", "--yes"]).unwrap().command,
            CheckpointCommand::Restore(CheckpointRestoreArgs { checkpoint, yes: true, .. }) if checkpoint == "c1"
        ));
        assert!(Probe::try_parse_from(["checkpoint", "restore"]).is_err());
        assert!(Probe::try_parse_from(["checkpoint", "create"]).is_err());
    }

    fn checkpoint() -> v1::Checkpoint {
        v1::Checkpoint {
            id: "6e3c1c39-0f5c-4b37-9d55-8d0e1f2a3b4c".to_owned(),
            name: "c1".to_owned(),
            source_name: "app".to_owned(),
            consistency: "paired".to_owned(),
            memory_bytes: 4 * 1024 * 1024 * 1024,
            memory_allocated_bytes: 1024 * 1024 * 1024,
            timings: Some(v1::CheckpointTimings {
                vm_paused_us: 412_000,
                workload_frozen_us: 431_000,
                total_us: 900_000,
                ..Default::default()
            }),
            disks: vec![v1::SnapshotDisk {
                role: "state".to_owned(),
                bytes: 20 * 1024 * 1024 * 1024,
                mode: "reflink".to_owned(),
                allocated_bytes: 1024 * 1024 * 1024,
                shared_bytes: Some(1024 * 1024 * 1024),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn text_output_names_the_pause_and_the_memory() {
        let text = created_text(&checkpoint());
        assert!(text.contains("VM paused 412 ms"), "{text}");
        assert!(text.contains("memory 4.0 GiB"), "{text}");
        let listing = list_text(&[checkpoint()]);
        assert!(listing.starts_with("NAME"), "{listing}");
        assert!(listing.contains("ready"), "{listing}");
        assert!(list_text(&[]).starts_with("No VM checkpoints"));
        let mut unrestorable = checkpoint();
        unrestorable.unrestorable_reason = "it was taken on another CPU".to_owned();
        assert!(list_text(&[unrestorable.clone()]).contains("unrestorable"));
        assert!(inspect_text(&unrestorable).contains("another CPU"));
        assert!(inspect_text(&checkpoint()).contains("paired"));
    }
}
