//! `cw --cloud snapshot`: hosted disk snapshots (#3046). Capture runs in the
//! background on the platform; `create` waits for it, because a snapshot is
//! useful only once it is ready.

use std::time::Duration;

use codewire_client::{ClientError, Snapshot, SnapshotState};
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
        return "No snapshots. Create one with: cw --cloud snapshot create ENV".to_owned();
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

/// Whether a failed poll says nothing about the capture. Capture is its own
/// workflow, so restarting the API, for a rollout or after a crash, interrupts
/// this wait and not the snapshot (observed on Dev, #3046).
fn poll_interrupted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ClientError>()
        .is_some_and(ClientError::is_retryable_transport_interruption)
}

async fn wait_for_capture(
    client: &EnvironmentClient,
    org_id: &str,
    snapshot_id: &str,
) -> anyhow::Result<Snapshot> {
    poll_capture(snapshot_id, || client.get_snapshot(org_id, snapshot_id)).await
}

async fn poll_capture<Poll, Polled>(snapshot_id: &str, mut poll: Poll) -> anyhow::Result<Snapshot>
where
    Poll: FnMut() -> Polled,
    Polled: std::future::Future<Output = anyhow::Result<Snapshot>>,
{
    let wait = async {
        loop {
            match poll().await {
                Ok(snapshot) if snapshot.state.as_known() != Some(SnapshotState::Capturing) => {
                    return anyhow::Ok(snapshot);
                }
                Ok(_) => {}
                Err(error) if poll_interrupted(&error) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(CAPTURE_POLL).await;
        }
    };
    tokio::time::timeout(CAPTURE_WAIT, wait)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "snapshot {snapshot_id} is still being captured; check it with: \
                 cw --cloud snapshot inspect {snapshot_id}"
            )
        })?
}

/// `--count` at most this many, as for a local snapshot.
const MAXIMUM_ENVIRONMENTS: u32 = 16;

fn platform_environment_names(
    snapshot: &str,
    name: Option<&str>,
    prefix: Option<&str>,
    count: u32,
) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        (1..=MAXIMUM_ENVIRONMENTS).contains(&count),
        "--count is 1 to {MAXIMUM_ENVIRONMENTS}"
    );
    if let Some(name) = name.and_then(trimmed_str) {
        anyhow::ensure!(
            count == 1,
            "--name names one environment; use --name-prefix with --count"
        );
        return Ok(vec![name.to_owned()]);
    }
    let prefix = prefix.and_then(trimmed_str).unwrap_or(snapshot);
    Ok((1..=count)
        .map(|index| format!("{prefix}-{index}"))
        .collect())
}

/// `cw --cloud create --snapshot S [--count N]`: each environment is an
/// ordinary create on a disk restored from the snapshot, with its own identity
/// and sign-ins. A snapshot holds a disk and no image, so one starts on the
/// workspace image unless told otherwise.
pub(crate) async fn create_environments_from_platform_snapshot(
    globals: &Globals,
    mut args: EnvCreateArgs,
) -> anyhow::Result<()> {
    reject_local_create_options(&args)?;
    anyhow::ensure!(
        args.repo_urls.is_empty()
            && args.repo_flags.is_empty()
            && args.branch.is_none()
            && args.file.is_empty()
            && !args.share_mounts,
        "--snapshot takes its files from the snapshot: it can't be used with a repository, \
         --branch, --file or --share-mounts"
    );
    let (org_id, _, client) = resolve_platform_context(globals).await?;
    let selector = args
        .snapshot
        .as_deref()
        .and_then(trimmed_str)
        .context("name the snapshot to create from: --snapshot NAME")?;
    let snapshot = resolve_snapshot(&client, &org_id, selector).await?;
    anyhow::ensure!(
        snapshot.state.as_known() == Some(SnapshotState::Ready),
        "snapshot {} is not ready",
        terminal_text(&snapshot.name)
    );
    let names = platform_environment_names(
        &snapshot.name,
        args.name.as_deref(),
        args.name_prefix.as_deref(),
        args.count,
    )?;
    args.snapshot = Some(snapshot.id);
    args.name_prefix = None;
    args.count = 1;
    args.no_file = true;
    args.image.get_or_insert_with(|| "workspace".to_owned());
    let mut created: Vec<&str> = Vec::new();
    for name in &names {
        let mut one = args.clone();
        one.name = Some(name.clone());
        let result = Box::pin(handle_platform_env_command(
            globals,
            EnvCommand::Create(Box::new(one)),
        ))
        .await;
        if let Err(error) = result {
            if !created.is_empty() {
                eprintln!("Already created: {}.", created.join(", "));
            }
            return Err(error);
        }
        created.push(name);
    }
    Ok(())
}

pub(super) async fn handle_platform_snapshot_command(
    globals: &Globals,
    command: SnapshotCommand,
) -> anyhow::Result<()> {
    let (org_id, _, client) = resolve_platform_context(globals).await?;
    match command {
        SnapshotCommand::Create(args) => {
            let environment = args
                .environment
                .as_deref()
                .context("environment is required")?;
            let environment_id = resolve_environment_id(&client, &org_id, environment).await?;
            let name = match args.name.as_deref().and_then(trimmed_str) {
                Some(name) => name.to_owned(),
                None => default_snapshot_name(environment, chrono::Utc::now()),
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
    use codewire_client::ErrorCode;

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

    fn scripted(
        script: Vec<anyhow::Result<Snapshot>>,
    ) -> impl FnMut() -> std::future::Ready<anyhow::Result<Snapshot>> {
        let mut script = script.into_iter();
        move || std::future::ready(script.next().expect("polled past the script"))
    }

    fn failure(code: ErrorCode) -> anyhow::Error {
        ClientError::new(code, "HTTP error").into()
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_outlasts_an_api_restart() {
        let done = poll_capture(
            "s",
            scripted(vec![
                Ok(snapshot(SnapshotState::Capturing)),
                Err(failure(ErrorCode::Unavailable)),
                Err(failure(ErrorCode::Unavailable)),
                Ok(snapshot(SnapshotState::Ready)),
            ]),
        )
        .await
        .expect("an interrupted poll isn't a failed capture");
        assert_eq!(done.state.as_known(), Some(SnapshotState::Ready));
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_stops_at_an_error_that_is_not_an_interruption() {
        for code in [
            ErrorCode::NotFound,
            ErrorCode::Unauthenticated,
            ErrorCode::PermissionDenied,
            ErrorCode::Internal,
        ] {
            let error = poll_capture(
                "s",
                scripted(vec![
                    Ok(snapshot(SnapshotState::Capturing)),
                    Err(failure(code)),
                ]),
            )
            .await
            .expect_err("this says something about the snapshot or the caller");
            assert!(!poll_interrupted(&error));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_api_that_stays_down_ends_the_wait_at_its_limit() {
        let error = poll_capture("s", || {
            std::future::ready(Err(failure(ErrorCode::Unavailable)))
        })
        .await
        .expect_err("the wait is bounded");
        assert!(error.to_string().contains("still being captured"));
    }

    #[test]
    fn environments_from_a_snapshot_are_named_as_for_a_local_one() {
        let names =
            |name, prefix, count| platform_environment_names("toolchain", name, prefix, count);
        assert_eq!(
            names(None, None, 2).unwrap(),
            ["toolchain-1", "toolchain-2"]
        );
        assert_eq!(names(None, Some("pr"), 2).unwrap(), ["pr-1", "pr-2"]);
        assert_eq!(names(Some("one"), None, 1).unwrap(), ["one"]);
        assert!(names(Some("one"), None, 2).is_err());
        assert!(names(None, None, 17).is_err());
    }

    #[test]
    fn the_flag_the_help_names_selects_the_platform() {
        use clap::Parser as _;
        let cli =
            crate::Cli::try_parse_from(["cw", "--cloud", "snapshot", "create", "app"]).unwrap();
        assert_eq!(
            cli.placement().unwrap(),
            Some(EnvironmentPlacement::Platform)
        );
    }

    #[test]
    fn a_list_names_each_snapshots_state_and_size() {
        let text = list_text(&[snapshot(SnapshotState::Ready)]);
        assert!(text.contains("good-toolchain"), "{text}");
        assert!(text.contains("ready"), "{text}");
        assert!(text.contains("80.0"), "{text}");
        assert!(list_text(&[]).contains("cw --cloud snapshot create"));
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
