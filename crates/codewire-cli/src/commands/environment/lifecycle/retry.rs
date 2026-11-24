//! `cw retry ENV` (#4767): run a cloud Sandbox's failed setup again, from the
//! step it failed at, and follow it to its end. The service decides whether
//! the Sandbox can retry and whether the retry clones the repositories again;
//! a retry that would delete their directories is asked about first.
//!
//! The retry is followed in the setup log after the newest row from before
//! the request. Its recorded failure is not watched: a retry that fails
//! quickly clears and sets it again within one poll.

use std::time::{Duration, Instant};

use clap::Args;
use codewire_client::environment_setup::RECLONE_UNCONFIRMED;
use serde::Serialize;

use super::*;
use crate::commands::progress::{EnvironmentLogFeed, FollowEnd, StageFailure};
use crate::error_report::with_next_step;

#[derive(Debug, Args)]
pub(crate) struct RetryArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(
        short,
        long,
        help = "Retry even when the retry clones the repositories again, deleting their directories"
    )]
    yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

/// The one sentence for `--local`: a local VM has no setup the service
/// can run again.
const LOCAL_REFUSAL: &str =
    "`cw retry` reruns a cloud Sandbox's setup; a local VM's setup can't be retried yet";

/// How long the retry may wait to start before `cw` says why.
const NOT_STARTED_AFTER: Duration = Duration::from_secs(120);
const NOT_STARTED: &str =
    "The retry hasn't started yet; it runs after the Sandbox's current operation";

/// The service's sentence ends by asking the dashboard's button to confirm;
/// `cw` asks in its own words.
const CONFIRM_SUFFIX: &str = "; confirm to retry";

/// What a retry's result reports in JSON.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct RetryResult {
    environment: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub(crate) async fn handle_retry(globals: &Globals, args: RetryArgs) -> anyhow::Result<()> {
    let began = Instant::now();
    if globals.placement == Some(EnvironmentPlacement::Local) {
        anyhow::bail!(LOCAL_REFUSAL);
    }
    let target =
        resolve_unified_environment_target(globals, globals.placement, &args.environment, "retry")
            .await?;
    let reference = match target {
        UnifiedEnvironmentTarget::Platform(id) => id,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(_) => anyhow::bail!(LOCAL_REFUSAL),
    };
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = EnvironmentClient::new(&platform)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = crate::commands::launch_setup::organization_for_setup(
        globals,
        &platform,
        &organization_client,
        &orgs,
        false,
    )
    .await?;
    let environment_id = resolve_environment_id(&client, &org_id, &reference).await?;
    let name = client
        .get_environment(&org_id, &environment_id)
        .await
        .map(|environment| terminal_text(&display_name(&environment)))
        .unwrap_or_else(|_| reference.clone());
    let caps = crate::commands::lifecycle_output::capabilities(args.output);
    let interactive =
        !caps.is_machine() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // Rows up to now belong to earlier runs, including the failed row that
    // would otherwise end the follow at once.
    let cursor = client
        .get_environment_logs(&org_id, &environment_id)
        .await
        .map(|logs| progress::last_log_id(&logs))
        .context("read the setup log")?;
    request_retry(
        &client,
        &org_id,
        &environment_id,
        &name,
        args.yes,
        interactive,
    )
    .await?;

    let feed = progress::PlatformLogFeed {
        client: &client,
        org_id: &org_id,
        environment_id: &environment_id,
    };
    let mut view = StartProgress::new(std::io::stderr(), &caps, began, "Retrying setup");
    let followed = crate::commands::lifecycle_output::unless_interrupted(
        !caps.is_machine(),
        follow_retry(
            &feed,
            &mut view,
            cursor,
            &FollowPolicy::default(),
            NOT_STARTED_AFTER,
        ),
    )
    .await;
    view.finish()?;
    let Some(followed) = followed else {
        let notice = InterruptNotice::new(VmLocation::Cloud, "setup retry", &name);
        return Err(notice.error(true));
    };
    let result = retry_result(&name, followed?);
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    if result.status != "complete" {
        return Err(setup_failed_error(
            &name,
            result.step.as_deref(),
            result.error.as_deref().unwrap_or_default(),
        ));
    }
    if !caps.is_machine() {
        let style = caps.stderr_style();
        eprintln!(
            "{} Setup complete for {name}",
            style.status(crate::output::Status::Done)
        );
    }
    Ok(())
}

/// Requests the retry. A retry that clones the repositories again is sent
/// confirmed with `--yes`, asked about at a terminal, and refused with the
/// flag that confirms it anywhere else.
async fn request_retry(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    name: &str,
    yes: bool,
    interactive: bool,
) -> anyhow::Result<()> {
    let retry = |confirm| {
        client
            .codewire()
            .retry_environment_setup(org_id, environment_id, confirm)
    };
    let error = match retry(yes).await {
        Ok(()) => return Ok(()),
        Err(error) if !yes && error.reason() == Some(RECLONE_UNCONFIRMED) => error,
        Err(error) => return Err(display_client_error(error)),
    };
    match unconfirmed(name, error.message(), interactive) {
        Unconfirmed::Refuse(error) => Err(error),
        Unconfirmed::Ask(deletes) => {
            let question = format!("{}. Retry?", capitalised(&deletes));
            if !crate::commands::collaboration::prompt_confirm_default_no(&question)? {
                anyhow::bail!("cancelled; setup was not retried");
            }
            retry(true).await.map_err(display_client_error)
        }
    }
}

/// What `cw` does with a retry the service won't run unconfirmed.
#[derive(Debug)]
enum Unconfirmed {
    /// Ask at the terminal, saying what the retry deletes.
    Ask(String),
    /// Refuse with what it deletes and the flag that confirms it.
    Refuse(anyhow::Error),
}

fn unconfirmed(name: &str, message: &str, interactive: bool) -> Unconfirmed {
    let deletes = reclone_detail(message);
    if interactive {
        Unconfirmed::Ask(deletes)
    } else {
        Unconfirmed::Refuse(with_next_step(
            anyhow::anyhow!("{deletes}"),
            format!("cw retry {name} --yes"),
        ))
    }
}

/// The service's reclone sentence without the dashboard's ask, in
/// lowercase as an error fragment.
fn reclone_detail(message: &str) -> String {
    let message = terminal_text(message);
    message
        .strip_suffix(CONFIRM_SUFFIX)
        .unwrap_or(&message)
        .to_owned()
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Follows the retry after `cursor` to its `complete` or `failed` row. When
/// no row has come after `note_after`, says once that the retry hasn't
/// started yet, and keeps following from the same row.
async fn follow_retry<F, W>(
    feed: &F,
    view: &mut StartProgress<W>,
    cursor: Option<String>,
    policy: &FollowPolicy,
    note_after: Duration,
) -> anyhow::Result<FollowEnd>
where
    F: EnvironmentLogFeed,
    W: std::io::Write,
{
    let before = cursor.clone();
    let mut cursor = cursor;
    let first = {
        let follow = progress::follow_start_progress(feed, view, &mut cursor, policy);
        tokio::select! {
            end = follow => Some(end),
            () = tokio::time::sleep(note_after) => None,
        }
    };
    if let Some(end) = first {
        return end;
    }
    if cursor == before {
        view.note(NOT_STARTED)?;
    }
    progress::follow_start_progress(feed, view, &mut cursor, policy).await
}

fn retry_result(name: &str, end: FollowEnd) -> RetryResult {
    match end {
        FollowEnd::Complete => RetryResult {
            environment: name.to_owned(),
            status: "complete",
            step: None,
            error: None,
        },
        FollowEnd::Failed(StageFailure { stage, message, .. }) => RetryResult {
            environment: name.to_owned(),
            status: "failed",
            step: Some(stage).filter(|stage| !stage.is_empty()),
            error: Some(message).filter(|message| !message.is_empty()),
        },
    }
}

/// A setup that failed, in the dashboard's words: the step it failed at and
/// why, that the Sandbox still runs, and where to fix it. `cw create` and
/// `cw retry` end with it; `cw start` keeps the failed stage's own words,
/// since a start's stage (the gateway, the daemon) isn't always setup.
pub(crate) fn setup_failed_error(name: &str, step: Option<&str>, error: &str) -> anyhow::Error {
    let error = terminal_text(error);
    let failed = match step {
        Some(step) if !error.is_empty() && error != step => format!(" at {step}: {error}"),
        Some(step) => format!(" at {step}"),
        None if !error.is_empty() => format!(": {error}"),
        None => String::new(),
    };
    with_next_step(
        anyhow::anyhow!(
            "setup failed{failed}; {name} is still running, so fix it there and run `cw retry {name}` (`cw logs {name} --setup` has the whole log)"
        ),
        format!("cw shell {name}"),
    )
}

#[cfg(test)]
mod tests;
