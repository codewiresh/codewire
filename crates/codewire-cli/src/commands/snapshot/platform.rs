//! `cw --platform snapshot`: hosted disk snapshots (#3046). Capture runs in the
//! background on the platform; `create` waits for it, because a snapshot is
//! useful only once it is ready.

use std::time::Duration;

use codewire_client::{Snapshot, SnapshotState};
use serde::Serialize;

use super::super::*;
use super::{OutputFormat, SnapshotCommand, default_snapshot_name};
use crate::commands::progress::terminal_text;

/// A capture of the largest disk finishes well within this.
const CAPTURE_WAIT: Duration = Duration::from_secs(20 * 60);
const CAPTURE_POLL: Duration = Duration::from_secs(1);

/// What `--output json` prints: the fields that identify and describe one
/// snapshot, in the wire's own terms.
#[derive(Debug, Serialize)]
struct PlatformSnapshotView {
    id: String,
    name: String,
    source_environment_id: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<i64>,
    location: &'static str,
}

fn state_name(snapshot: &Snapshot) -> &'static str {
    match snapshot.state.as_known() {
        Some(SnapshotState::Capturing) => "capturing",
        Some(SnapshotState::Ready) => "ready",
        Some(SnapshotState::Failed) => "failed",
        Some(SnapshotState::Deleting) => "deleting",
        Some(SnapshotState::Unspecified) | None => "unknown",
    }
}

impl From<&Snapshot> for PlatformSnapshotView {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            id: snapshot.id.clone(),
            name: snapshot.name.clone(),
            source_environment_id: snapshot.source_environment_id.clone(),
            state: state_name(snapshot),
            failure_code: snapshot.failure_code.clone(),
            size_bytes: snapshot.size_bytes,
            location: "platform",
        }
    }
}

fn failure_text(code: Option<&str>) -> &'static str {
    match code {
        Some("environment_not_stopped") => "the environment was not stopped",
        Some("clearing_failed") => "its delivered sign-ins could not be cleared",
        _ => "the capture failed",
    }
}

fn list_text(snapshots: &[Snapshot]) -> String {
    if snapshots.is_empty() {
        return "No snapshots. Create one with: cw --platform snapshot create ENV".to_owned();
    }
    let mut lines = vec![format!(
        "{:<36}  {:<10}  {:>8}  NAME",
        "ID", "STATE", "SIZE"
    )];
    for snapshot in snapshots {
        lines.push(format!(
            "{:<36}  {:<10}  {:>8}  {}",
            snapshot.id,
            state_name(snapshot),
            snapshot.size_bytes.map_or_else(
                || "-".to_owned(),
                |bytes| super::gib(bytes.max(0).unsigned_abs())
            ),
            terminal_text(&snapshot.name),
        ));
    }
    lines.join("\n")
}

fn inspect_text(snapshot: &Snapshot) -> String {
    let mut lines = vec![
        format!("Snapshot {}", terminal_text(&snapshot.name)),
        format!("  ID:      {}", snapshot.id),
        format!("  State:   {}", state_name(snapshot)),
        format!(
            "  Source:  {}",
            terminal_text(&snapshot.source_environment_id)
        ),
    ];
    if let Some(bytes) = snapshot.size_bytes {
        lines.push(format!(
            "  Size:    {}",
            super::gib(bytes.max(0).unsigned_abs())
        ));
    }
    if snapshot.state.as_known() == Some(SnapshotState::Failed) {
        lines.push(format!(
            "  Failed:  {}",
            failure_text(snapshot.failure_code.as_deref())
        ));
    }
    lines.join("\n")
}

/// A snapshot by ID, or by the creator's own unique name.
async fn resolve_snapshot(
    client: &EnvironmentClient,
    org_id: &str,
    target: &str,
) -> anyhow::Result<Snapshot> {
    client
        .list_snapshots(org_id)
        .await?
        .into_iter()
        .find(|snapshot| snapshot.id == target || snapshot.name == target)
        .ok_or_else(|| anyhow::anyhow!("no snapshot named {}", terminal_text(target)))
}

async fn wait_for_capture(
    client: &EnvironmentClient,
    org_id: &str,
    snapshot_id: &str,
) -> anyhow::Result<Snapshot> {
    let wait = async {
        loop {
            let snapshot = client.get_snapshot(org_id, snapshot_id).await?;
            if snapshot.state.as_known() != Some(SnapshotState::Capturing) {
                return anyhow::Ok(snapshot);
            }
            tokio::time::sleep(CAPTURE_POLL).await;
        }
    };
    tokio::time::timeout(CAPTURE_WAIT, wait)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "snapshot {snapshot_id} is still being captured; check it with: \
                 cw --platform snapshot inspect {snapshot_id}"
            )
        })?
}

pub(super) async fn handle_platform_snapshot_command(
    globals: &Globals,
    command: SnapshotCommand,
) -> anyhow::Result<()> {
    let (org_id, _, client) = resolve_platform_context(globals).await?;
    match command {
        SnapshotCommand::Create(args) => {
            let environment_id =
                resolve_environment_id(&client, &org_id, &args.environment).await?;
            let name = match args.name.as_deref().and_then(trimmed_str) {
                Some(name) => name.to_owned(),
                None => default_snapshot_name(&args.environment, chrono::Utc::now()),
            };
            let created = client
                .create_snapshot(&org_id, &environment_id, &name)
                .await
                .context("snapshot create")?;
            let snapshot = wait_for_capture(&client, &org_id, &created.id).await?;
            if snapshot.state.as_known() != Some(SnapshotState::Ready) {
                anyhow::bail!(
                    "snapshot {} was not kept: {}",
                    terminal_text(&snapshot.name),
                    failure_text(snapshot.failure_code.as_deref())
                );
            }
            match args.output {
                OutputFormat::Json => super::print_json(&PlatformSnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!("Created snapshot {}.", terminal_text(&snapshot.name));
                    Ok(())
                }
            }
        }
        SnapshotCommand::Ls(args) => {
            let snapshots = client.list_snapshots(&org_id).await?;
            match args.output {
                OutputFormat::Json => super::print_json(
                    &snapshots
                        .iter()
                        .map(PlatformSnapshotView::from)
                        .collect::<Vec<_>>(),
                ),
                OutputFormat::Text => {
                    println!("{}", list_text(&snapshots));
                    Ok(())
                }
            }
        }
        SnapshotCommand::Inspect(args) => {
            let snapshot = resolve_snapshot(&client, &org_id, &args.snapshot).await?;
            match args.output {
                OutputFormat::Json => super::print_json(&PlatformSnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!("{}", inspect_text(&snapshot));
                    Ok(())
                }
            }
        }
        SnapshotCommand::Rm(args) => {
            let target = resolve_snapshot(&client, &org_id, &args.snapshot).await?;
            let snapshot = client.delete_snapshot(&org_id, &target.id).await?;
            match args.output {
                OutputFormat::Json => super::print_json(&PlatformSnapshotView::from(&snapshot)),
                OutputFormat::Text => {
                    println!(
                        "Removing snapshot {}; environments made from it are unaffected.",
                        terminal_text(&snapshot.name)
                    );
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(state: SnapshotState) -> Snapshot {
        Snapshot {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            name: "good-toolchain".into(),
            source_environment_id: "env-1".into(),
            state: state.into(),
            size_bytes: Some(80 * 1024 * 1024 * 1024),
            ..Default::default()
        }
    }

    #[test]
    fn a_list_names_each_snapshots_state_and_size() {
        let text = list_text(&[snapshot(SnapshotState::Ready)]);
        assert!(text.contains("good-toolchain"), "{text}");
        assert!(text.contains("ready"), "{text}");
        assert!(text.contains("80.0"), "{text}");
        assert!(list_text(&[]).contains("cw --platform snapshot create"));
    }

    #[test]
    fn a_failed_snapshot_says_why_in_plain_terms() {
        let mut failed = snapshot(SnapshotState::Failed);
        failed.failure_code = Some("clearing_failed".into());
        failed.size_bytes = None;
        let text = inspect_text(&failed);
        assert!(text.contains("could not be cleared"), "{text}");
        assert_eq!(
            failure_text(Some("environment_not_stopped")),
            "the environment was not stopped"
        );
        assert_eq!(failure_text(None), "the capture failed");
    }

    #[test]
    fn the_json_view_keeps_the_wire_state_and_placement() {
        let view = PlatformSnapshotView::from(&snapshot(SnapshotState::Capturing));
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["state"], "capturing");
        assert_eq!(json["location"], "platform");
        assert!(json.get("failure_code").is_none());
    }
}
