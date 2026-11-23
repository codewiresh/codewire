//! `cw update ENV --file` (#5949; SPEC.md, "Target, not shipped (#5949)",
//! and docs/journeys/cloud-sandbox.md `sandbox-update-startup`): gives an
//! existing cloud Sandbox the file's `startup_script`, added, changed or
//! removed, without recreating it.
//!
//! The file is compared with the Sandbox's saved settings as `cw export`
//! reads them. `startup_script` is the one setting it changes; any other
//! setting the file states differently refuses the whole update before
//! anything is sent. A setting the file leaves out is not compared: create
//! may have filled it from a preset, a flag or a default, and leaving it out
//! changes nothing. `startup_script` is the exception: a file without one
//! removes the saved script.

use std::collections::BTreeSet;

use codewire_client::EnvironmentState as WireState;
use serde::Serialize;

use super::*;
use crate::output::{Role, Status, Style};
use sources::PlatformDocument;

pub(super) async fn platform(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org_id: &str,
    args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    let source =
        project_file::select_from(&project_file::invoking_directory()?, &args.file, false)?;
    let mut document = sources::load_platform_document(&source.paths())?;
    let environment = client
        .get_environment(org_id, &args.environment)
        .await
        .context("get environment")?;
    let (saved, withheld) = client
        .get_environment_project_spec(org_id, &environment.id)
        .await
        .context("read the Sandbox's saved settings")?;
    resolve_sources(platform, client, org_id, &saved, &mut document.spec).await?;
    let target = Target {
        name: terminal_text(environment.name.as_deref().unwrap_or(&environment.id)),
        files: &args.file,
    };
    let found = differences(
        &document,
        &Saved {
            spec: &saved,
            withheld: &withheld,
            environment: &environment,
        },
    );
    if !found.is_empty() {
        return Err(refusal(&found, &target));
    }
    let caps = crate::commands::lifecycle_output::capabilities(args.output);
    let Some(change) = script_change(&saved.startup_script, &document.spec.startup_script) else {
        return print_unchanged(&target, &environment.id, args.output);
    };
    if matches!(args.output, OutputFormat::Text) {
        eprint!("{}", preview(&target, &change, caps.stderr_style()));
    }
    confirm(args.yes, args.output)?;
    let response = client
        .codewire()
        .set_environment_startup_script(org_id, &environment.id, change.script())
        .await
        .map_err(display_client_error)
        .context("save the startup script")?;
    if !response.changed {
        return print_unchanged(&target, &environment.id, args.output);
    }
    let running = response.state.as_known() == Some(WireState::Running);
    match args.output {
        OutputFormat::Json => print_json(&Outcome {
            environment_id: &environment.id,
            changed: true,
            change: Some(change.kind()),
            state: Some(if running { "running" } else { "stopped" }),
        })?,
        OutputFormat::Text => print!(
            "{}",
            saved_text(&target, &change, running, caps.stdout_style())
        ),
    }
    Ok(())
}

/// The Sandbox and the files as the user named them.
struct Target<'a> {
    name: String,
    files: &'a [PathBuf],
}

impl Target<'_> {
    fn files(&self) -> String {
        self.files
            .iter()
            .map(|file| file.display().to_string())
            .collect::<Vec<_>>()
            .join(" + ")
    }

    fn file_flags(&self) -> String {
        self.files
            .iter()
            .map(|file| format!("--file {}", file.display()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What the Sandbox saved, as `cw export` reads it: its spec with declared
/// environment values withheld, and its current size and idle stop.
struct Saved<'a> {
    spec: &'a codewire_project::ProjectSpec,
    withheld: &'a [String],
    environment: &'a Environment,
}

/// Where a setting other than the startup script changes instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// Create applies it once.
    NewSandbox,
    Secrets,
    Profile,
    Resize,
    IdleStop,
}

impl Route {
    fn where_it_changes(self, name: &str, pronoun: &str) -> String {
        match self {
            Route::NewSandbox => {
                format!("only a new Sandbox takes {pronoun}, since create applies {pronoun} once")
            }
            Route::Secrets => format!("change {pronoun} with `cw update {name} --secrets`"),
            Route::Profile => format!("change {pronoun} with `cw update {name} --profile`"),
            Route::Resize => format!("change {pronoun} with `cw resize {name}`"),
            Route::IdleStop => format!("change {pronoun} with `cw update {name} --idle-stop`"),
        }
    }

    fn next_step(self, target: &Target<'_>) -> String {
        let name = &target.name;
        match self {
            Route::NewSandbox => format!("cw --cloud create {}", target.file_flags()),
            Route::Secrets => format!("cw update {name} --secrets PROJECT"),
            Route::Profile => format!("cw update {name} --profile PROFILE"),
            Route::Resize => format!("cw resize {name} --cpu CPU --memory MEMORY"),
            Route::IdleStop => format!("cw update {name} --idle-stop DURATION"),
        }
    }
}

/// A setting the file states differently from the saved one, by its
/// codewire.yaml key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Difference {
    field: &'static str,
    route: Route,
}

/// Every setting but the startup script that the file states and the saved
/// settings don't match, in codewire.yaml's order.
fn differences(file: &PlatformDocument, saved: &Saved<'_>) -> Vec<Difference> {
    let (f, s, environment) = (&file.spec, saved.spec, saved.environment);
    let file_keys: BTreeSet<&str> = f.environment.keys().map(String::as_str).collect();
    let saved_keys: BTreeSet<&str> = saved.withheld.iter().map(String::as_str).collect();
    let size = |stated: Option<u64>, current: i32| {
        stated.is_none_or(|stated| u64::try_from(current).ok() == Some(stated))
    };
    let checks = [
        // (stated, same, field, route)
        (
            !f.preset.is_empty(),
            f.preset == s.preset,
            "preset",
            Route::NewSandbox,
        ),
        (
            !f.image.is_empty(),
            same_image(&f.image, &s.image),
            "image",
            Route::NewSandbox,
        ),
        (
            !f.repositories.is_empty(),
            f.repositories == s.repositories,
            "repositories",
            Route::NewSandbox,
        ),
        // Left out, it follows the repositories, compared above.
        (
            file.working_directory_explicit,
            f.working_directory == s.working_directory,
            "working_directory",
            Route::NewSandbox,
        ),
        (
            !f.install_command.is_empty(),
            f.install_command == s.install_command,
            "install_command",
            Route::NewSandbox,
        ),
        // Values are withheld from the saved settings, so only names compare.
        (
            !file_keys.is_empty(),
            file_keys == saved_keys,
            "environment",
            Route::NewSandbox,
        ),
        (
            !f.agents.is_empty(),
            f.agents == s.agents,
            "agents",
            Route::NewSandbox,
        ),
        (
            !f.skills.is_empty(),
            f.skills == s.skills,
            "skills",
            Route::NewSandbox,
        ),
        (
            !f.application_ports.is_empty(),
            f.application_ports == s.application_ports,
            "ports",
            Route::NewSandbox,
        ),
        (
            f.network.is_some(),
            f.network == s.network,
            "network",
            Route::NewSandbox,
        ),
        (
            !f.secrets.is_empty(),
            f.secrets == s.secrets,
            "secrets",
            Route::Secrets,
        ),
        (
            f.credentials.is_some(),
            f.credentials == s.credentials,
            "credentials",
            Route::Profile,
        ),
        (
            f.resources.cpu_millicores.is_some(),
            size(
                f.resources.cpu_millicores.map(u64::from),
                environment.cpu_millicores,
            ),
            "cpu",
            Route::Resize,
        ),
        (
            f.resources.memory_mib.is_some(),
            size(f.resources.memory_mib, environment.memory_mb),
            "memory",
            Route::Resize,
        ),
        (
            f.resources.disk_gib.is_some(),
            size(f.resources.disk_gib, environment.disk_gb),
            "disk",
            Route::Resize,
        ),
        (
            file.idle_stop_seconds.is_some(),
            file.idle_stop_seconds == Some(environment.idle_stop_seconds),
            "idle_stop",
            Route::IdleStop,
        ),
    ];
    checks
        .into_iter()
        .filter(|(stated, same, _, _)| *stated && !*same)
        .map(|(_, _, field, route)| Difference { field, route })
        .collect()
}

/// Two images are the same when they name the same reference, or both name
/// the Codewire workspace image: create saves the workspace image the server
/// pins, at whichever digest was current, whatever alias the file used.
fn same_image(file: &str, saved: &str) -> bool {
    file == saved || (workspace_image(file) && workspace_image(saved))
}

fn workspace_image(image: &str) -> bool {
    matches!(image, "workspace" | "codewiresh/workspace")
        || image == codewire_workspace_image::PUBLIC_REPOSITORY
        || image.split_once('@').is_some_and(|(repository, _)| {
            (repository == "workspace" || repository.ends_with("/workspace"))
                && codewire_workspace_image::is_canonical(image, repository)
        })
}

/// The file's secret project and credential profile as the saved settings
/// name them (`platform:id:…`), when the file names them another way.
async fn resolve_sources(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org_id: &str,
    saved: &codewire_project::ProjectSpec,
    file: &mut codewire_project::ProjectSpec,
) -> anyhow::Result<()> {
    if !file.secrets.project.is_empty() && file.secrets.project != saved.secrets.project {
        let projects = SecretClient::new(platform)?;
        let project = load_secret_project_by_name(&projects, org_id, &file.secrets.project).await?;
        file.secrets.project = format!("platform:id:{}", project.id);
    }
    if let Some(credentials) = file.credentials.as_mut()
        && Some(&*credentials) != saved.credentials.as_ref()
    {
        let profile = client
            .resolve_credential_profile(&credentials.profile)
            .await?;
        credentials.profile = format!("platform:id:{}", profile.id);
    }
    Ok(())
}

fn refusal(differences: &[Difference], target: &Target<'_>) -> anyhow::Error {
    let mut routes: Vec<Route> = Vec::new();
    for difference in differences {
        if !routes.contains(&difference.route) {
            routes.push(difference.route);
        }
    }
    let groups = routes
        .iter()
        .map(|route| {
            let fields: Vec<&str> = differences
                .iter()
                .filter(|difference| difference.route == *route)
                .map(|difference| difference.field)
                .collect();
            let pronoun = if fields.len() == 1 { "it" } else { "them" };
            format!(
                "{} ({})",
                and_list(&fields),
                route.where_it_changes(&target.name, pronoun)
            )
        })
        .collect::<Vec<_>>();
    let error = anyhow::anyhow!(
        "`cw update --file` changes only startup_script, and {} also changes {}; nothing was saved",
        target.files(),
        groups.join("; ")
    );
    crate::error_report::with_next_step(error, routes[0].next_step(target))
}

fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// How the saved script changes.
#[derive(Debug, PartialEq, Eq)]
enum ScriptChange<'a> {
    Added(&'a str),
    Changed { from: &'a str, to: &'a str },
    Removed(&'a str),
}

fn script_change<'a>(saved: &'a str, file: &'a str) -> Option<ScriptChange<'a>> {
    match (saved.is_empty(), file.is_empty()) {
        _ if saved == file => None,
        (true, _) => Some(ScriptChange::Added(file)),
        (_, true) => Some(ScriptChange::Removed(saved)),
        _ => Some(ScriptChange::Changed {
            from: saved,
            to: file,
        }),
    }
}

impl ScriptChange<'_> {
    /// The script to save; empty removes it.
    fn script(&self) -> &str {
        match self {
            ScriptChange::Added(script) | ScriptChange::Changed { to: script, .. } => script,
            ScriptChange::Removed(_) => "",
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            ScriptChange::Added(_) => "added",
            ScriptChange::Changed { .. } => "changed",
            ScriptChange::Removed(_) => "removed",
        }
    }
}

/// The script, each line indented and made safe to print.
fn indented(script: &str) -> String {
    script
        .lines()
        .map(|line| format!("  {}\n", terminal_text(line)))
        .collect()
}

/// What will change, before the prompt.
fn preview(target: &Target<'_>, change: &ScriptChange<'_>, style: Style) -> String {
    let name = style.paint(Role::Strong, &target.name);
    let files = target.files();
    match change {
        ScriptChange::Added(script) => format!(
            "Adds this startup script to {name}, from {files}:\n{}It runs at the next start, not now.\n",
            indented(script)
        ),
        ScriptChange::Changed { from, to } => format!(
            "Changes {name}'s startup script, from {files}. Now:\n{}New:\n{}The new one runs at the next start, not now.\n",
            indented(from),
            indented(to)
        ),
        ScriptChange::Removed(script) => format!(
            "Removes {name}'s startup script, since {files} has none:\n{}",
            indented(script)
        ),
    }
}

/// The result, with the next step: a running Sandbox runs the new script
/// only once it is stopped and started.
fn saved_text(
    target: &Target<'_>,
    change: &ScriptChange<'_>,
    running: bool,
    style: Style,
) -> String {
    let name = &target.name;
    let done = style.status(Status::Done);
    let next = style.status(Status::Next);
    let separator = style.separator();
    let restart = if running {
        format!("{next} cw --cloud stop {name} && cw --cloud start {name}\n")
    } else {
        format!("{next} cw --cloud start {name}\n")
    };
    let when = if running {
        "it runs at the next start, not now"
    } else {
        "it runs at the next start"
    };
    match change {
        ScriptChange::Added(_) => {
            format!("{done} Startup script added to {name}{separator}{when}\n{restart}")
        }
        ScriptChange::Changed { .. } => {
            format!("{done} Startup script changed on {name}{separator}{when}\n{restart}")
        }
        ScriptChange::Removed(_) => {
            format!(
                "{done} Startup script removed from {name}{separator}the next start runs none\n"
            )
        }
    }
}

fn unchanged_text(target: &Target<'_>) -> String {
    format!(
        "Nothing to change: {}'s settings already match {}.\n",
        target.name,
        target.files()
    )
}

fn print_unchanged(
    target: &Target<'_>,
    environment_id: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => print_json(&Outcome {
            environment_id,
            changed: false,
            change: None,
            state: None,
        }),
        OutputFormat::Text => {
            print!("{}", unchanged_text(target));
            Ok(())
        }
    }
}

/// `--output json`. It never carries the script.
#[derive(Debug, Serialize)]
struct Outcome<'a> {
    environment_id: &'a str,
    changed: bool,
    /// `added`, `changed` or `removed`.
    change: Option<&'static str>,
    /// `running` or `stopped`, when the script was saved.
    state: Option<&'static str>,
}

fn print_json(outcome: &Outcome<'_>) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(outcome)?);
    Ok(())
}

fn confirm(assume_yes: bool, output: OutputFormat) -> anyhow::Result<()> {
    if assume_yes {
        return Ok(());
    }
    let interactive = matches!(output, OutputFormat::Text)
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal();
    confirm_with(interactive, || {
        eprint!("Save it? [y/N]: ");
        std::io::stderr()
            .flush()
            .context("flush the confirmation")?;
        sources::read_confirmation(std::io::stdin().lock())
    })
}

fn confirm_with(
    interactive: bool,
    ask: impl FnOnce() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        interactive,
        "saving the startup script needs --yes when there's no terminal to confirm at; nothing was saved"
    );
    anyhow::ensure!(ask()?, "canceled; nothing was saved");
    Ok(())
}

#[cfg(test)]
mod tests;
