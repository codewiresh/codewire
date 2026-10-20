//! Lifecycle results shared by local and cloud environments: the
//! presentation an output format allows, the selected-source references a
//! summary names, the next useful command, and the result block for stop and
//! remove.
//!
//! Durable results go to stdout, the working context and progress to
//! stderr, and machine (JSON) output gets none of it. References only: no
//! credential material or secret value passes through here.

use std::future::Future;
use std::time::Duration;

use codewire_project::{SecretBindings, StoragePlacement, StorageReference};

use super::OutputFormat;
use crate::commands::progress::terminal_text;
use crate::output::{
    Capabilities, LifecycleSummary, OutputMode, Role, SourcePlacement, SourceRef, Status, Style,
    VmLocation,
};

/// The longest a best-effort name lookup may delay a lifecycle result. A
/// lookup that fails or runs out shows the canonical reference instead.
pub(crate) const NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// What `output` lets a lifecycle command draw on this process's streams.
pub(crate) fn capabilities(output: OutputFormat) -> Capabilities {
    Capabilities::from_process(match output {
        OutputFormat::Json => OutputMode::Machine,
        OutputFormat::Text => OutputMode::Text,
    })
}

pub(crate) fn placement_flag(location: VmLocation) -> &'static str {
    match location {
        VmLocation::Local => "--local",
        VmLocation::Cloud => "--cloud",
    }
}

/// The next step after an environment is ready: open Claude in it.
pub(crate) fn next_run_command(location: VmLocation, name: &str) -> String {
    format!("cw {} run claude --in {name}", placement_flag(location))
}

/// A command that names the environment, such as `cw --local start app`.
pub(crate) fn environment_command(location: VmLocation, command: &str, name: &str) -> String {
    format!("cw {} {command} {name}", placement_flag(location))
}

pub(crate) fn source_placement(placement: StoragePlacement) -> SourcePlacement {
    match placement {
        StoragePlacement::Local => SourcePlacement::Local,
        StoragePlacement::Platform => SourcePlacement::Platform,
    }
}

/// A named source from its stored reference: the placement prefix, and the
/// name from the reference itself or, for an exact `id:` reference, from
/// `name`. Without a usable name the stored reference shows as is.
fn named_ref(reference: StorageReference<'_>, stored: &str, name: Option<&str>) -> SourceRef {
    let name = match reference.selector.strip_prefix("id:") {
        Some(_) => name.map(str::trim).filter(|name| !name.is_empty()),
        None => Some(reference.selector),
    };
    match (reference.placement, name) {
        (Some(placement), Some(name)) => SourceRef::Named {
            placement: source_placement(placement),
            name: name.strip_prefix("user/").unwrap_or(name).to_owned(),
        },
        _ => SourceRef::Unresolved(stored.to_owned()),
    }
}

/// The credential profile a selection names: `platform:work` from the stored
/// `platform:id:…` reference and the profile's name (`work` or the logical
/// `user/work`), the stored reference when the name is unknown, or `none`.
pub(crate) fn credential_ref(stored: Option<&str>, name: Option<&str>) -> SourceRef {
    let Some(stored) = stored.map(str::trim).filter(|stored| !stored.is_empty()) else {
        return SourceRef::None;
    };
    match StorageReference::profile(stored) {
        Ok(reference) => named_ref(reference, stored, name),
        Err(_) => SourceRef::Unresolved(stored.to_owned()),
    }
}

/// The application-secret sources a selection names: the project (by name
/// when known), then the organization's and the person's own secrets.
pub(crate) fn secret_refs(secrets: &SecretBindings, project_name: Option<&str>) -> SourceRef {
    let project = secrets.project.trim();
    let mut references = Vec::new();
    if !project.is_empty() {
        references.push(match StorageReference::project(project) {
            Ok(reference) => named_ref(reference, project, project_name),
            Err(_) => SourceRef::Unresolved(project.to_owned()),
        });
    }
    if secrets.organization {
        references.push(SourceRef::Scope {
            placement: SourcePlacement::Platform,
            scope: "organization secrets",
        });
    }
    if let Some(placement) = secrets.user {
        references.push(SourceRef::Scope {
            placement: source_placement(placement),
            scope: "personal secrets",
        });
    }
    SourceRef::several(references)
}

/// The exact id of a stored `placement:id:<id>` reference, when it is one.
pub(crate) fn exact_reference_id(stored: &str) -> Option<(StoragePlacement, &str)> {
    let reference = StorageReference::project(stored)
        .or_else(|_| StorageReference::profile(stored))
        .ok()?;
    Some((
        reference.placement?,
        reference.selector.strip_prefix("id:")?,
    ))
}

/// Runs a best-effort lookup for at most [`NAME_LOOKUP_TIMEOUT`]; any
/// failure or timeout is `None`.
pub(crate) async fn bounded<T>(lookup: impl Future<Output = anyhow::Result<T>>) -> Option<T> {
    tokio::time::timeout(NAME_LOOKUP_TIMEOUT, lookup)
        .await
        .ok()?
        .ok()
}

/// The durable result on stdout, in text mode only.
pub(crate) fn print_summary(summary: &LifecycleSummary, caps: &Capabilities) {
    if !caps.is_machine() {
        print!("{}", summary.render(caps.stdout_style()));
    }
}

/// What the command works on, on stderr before its progress, in text mode
/// only.
pub(crate) fn print_context(summary: &LifecycleSummary, caps: &Capabilities) {
    if !caps.is_machine() {
        eprint!("{}", summary.render_context(caps.stderr_style()));
    }
}

/// A stop or remove result:
///
/// ```text
/// ✓ Environment app stopped
///   local VM · environment disk retained
///
/// → cw --local start app
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResultBlock {
    pub(crate) status: Status,
    pub(crate) headline: String,
    /// Quiet detail under the headline: location and what was observed.
    pub(crate) detail: Option<String>,
    /// A pending or partial part of the outcome, with its quiet detail.
    pub(crate) attention: Option<(String, String)>,
    pub(crate) next: Option<String>,
}

impl ResultBlock {
    pub(crate) fn new(status: Status, headline: impl Into<String>) -> Self {
        Self {
            status,
            headline: headline.into(),
            detail: None,
            attention: None,
            next: None,
        }
    }

    pub(crate) fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub(crate) fn attention(
        mut self,
        headline: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        self.attention = Some((headline.into(), detail.into()));
        self
    }

    pub(crate) fn next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    pub(crate) fn render(&self, style: Style) -> String {
        let mut out = format!(
            "{} {}\n",
            style.status(self.status),
            terminal_text(&self.headline)
        );
        if let Some(detail) = &self.detail {
            out.push_str(&format!(
                "  {}\n",
                style.paint(Role::Dim, &terminal_text(detail))
            ));
        }
        if let Some((headline, detail)) = &self.attention {
            out.push_str(&format!(
                "\n{} {}\n  {}\n",
                style.status(Status::Attention),
                terminal_text(headline),
                style.paint(Role::Dim, &terminal_text(detail))
            ));
        }
        if let Some(next) = &self.next {
            out.push_str(&format!(
                "\n{} {}\n",
                style.status(Status::Next),
                terminal_text(next)
            ));
        }
        out
    }

    /// Prints the block on stdout, in text mode only.
    pub(crate) fn print(&self, caps: &Capabilities) {
        if !caps.is_machine() {
            print!("{}", self.render(caps.stdout_style()));
        }
    }
}

/// The location word a result's detail line starts with.
pub(crate) fn location_label(location: VmLocation) -> &'static str {
    match location {
        VmLocation::Local => "local VM",
        VmLocation::Cloud => "cloud VM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    #[test]
    fn next_command_names_placement_agent_and_environment() {
        assert_eq!(
            next_run_command(VmLocation::Local, "app"),
            "cw --local run claude --in app"
        );
        assert_eq!(
            next_run_command(VmLocation::Cloud, "review"),
            "cw --cloud run claude --in review"
        );
        assert_eq!(
            environment_command(VmLocation::Local, "start", "app"),
            "cw --local start app"
        );
    }

    #[test]
    fn the_next_command_parses_as_a_claude_launch_in_the_environment() {
        use clap::Parser as _;
        for location in [VmLocation::Local, VmLocation::Cloud] {
            let next = next_run_command(location, "app");
            let cli = crate::Cli::try_parse_from(next.split_whitespace())
                .unwrap_or_else(|error| panic!("`{next}` does not parse: {error}"));
            assert_eq!(cli.local, location == VmLocation::Local, "{next}");
            assert_eq!(cli.cloud, location == VmLocation::Cloud, "{next}");
            let crate::Command::Run(args) = cli.command else {
                panic!("`{next}` is not `cw run`");
            };
            assert_eq!(
                args.native_agent,
                Some(crate::commands::NativeAgent::Claude),
                "{next}"
            );
            assert_eq!(args.environment.as_deref(), Some("app"), "{next}");
        }
    }

    #[test]
    fn credential_references_resolve_to_placement_and_name() {
        let id = "856b6b9e-a520-48c7-aab1-8ac915465f28";
        let stored = format!("platform:id:{id}");
        assert_eq!(
            credential_ref(Some(&stored), Some("user/work")).text(),
            "platform:work"
        );
        assert_eq!(
            credential_ref(Some(&format!("local:id:{id}")), Some("work")).text(),
            "local:work"
        );
        assert_eq!(credential_ref(Some(&stored), None).text(), stored);
        assert_eq!(credential_ref(Some(&stored), Some("  ")).text(), stored);
        assert_eq!(credential_ref(None, Some("work")), SourceRef::None);
        assert_eq!(credential_ref(Some(""), None), SourceRef::None);
        // A reference that already names its profile needs no lookup.
        assert_eq!(
            credential_ref(Some("local:work"), None).text(),
            "local:work"
        );
        assert_eq!(
            credential_ref(Some("not a reference!"), None).text(),
            "not a reference!"
        );
    }

    #[test]
    fn secret_references_list_project_then_scopes() {
        let id = "a6249c2e-2fa4-473b-b41a-8d0f08f39e51";
        let mut secrets = SecretBindings {
            project: format!("platform:id:{id}"),
            organization: false,
            user: None,
        };
        assert_eq!(
            secret_refs(&secrets, Some("app-dev")).text(),
            "platform:app-dev"
        );
        assert_eq!(
            secret_refs(&secrets, None).text(),
            format!("platform:id:{id}")
        );
        secrets.organization = true;
        secrets.user = Some(StoragePlacement::Local);
        assert_eq!(
            secret_refs(&secrets, Some("app-dev")).text(),
            "platform:app-dev, organization secrets (platform), personal secrets (local)"
        );
        secrets.project.clear();
        assert_eq!(
            secret_refs(&secrets, None).text(),
            "organization secrets (platform), personal secrets (local)"
        );
        assert!(secret_refs(&SecretBindings::default(), None).is_none());
    }

    #[test]
    fn exact_ids_come_only_from_qualified_id_references() {
        let id = "a6249c2e-2fa4-473b-b41a-8d0f08f39e51";
        assert_eq!(
            exact_reference_id(&format!("local:id:{id}")),
            Some((StoragePlacement::Local, id))
        );
        assert_eq!(exact_reference_id("platform:app-dev"), None);
        assert_eq!(exact_reference_id(&format!("id:{id}")), None);
    }

    #[test]
    fn result_blocks_render_outcome_detail_attention_and_next() {
        let block = ResultBlock::new(Status::Done, "Environment app removed")
            .detail("local VM · environment disk removed")
            .attention(
                "Cleanup needs inspection",
                "An unknown object remains quarantined; inspect it with `cw doctor local`.",
            )
            .next("cw ls");
        assert_eq!(
            block.render(PLAIN),
            "✓ Environment app removed\n  local VM · environment disk removed\n\n! Cleanup needs inspection\n  An unknown object remains quarantined; inspect it with `cw doctor local`.\n\n→ cw ls\n"
        );
        let ascii = block.render(Style::new(false, Charset::Ascii));
        assert!(ascii.starts_with("+ Environment app removed\n"));
        assert!(ascii.ends_with("\n-> cw ls\n"));
        let colour = ResultBlock::new(Status::Done, "Stop requested: app")
            .detail("cloud VM · state: stopping")
            .render(Style::new(true, Charset::Unicode));
        assert_eq!(
            colour,
            "\x1b[32m✓\x1b[0m Stop requested: app\n  \x1b[2mcloud VM · state: stopping\x1b[0m\n"
        );
        let hostile = ResultBlock::new(Status::Failed, "app\x1b[2J").render(PLAIN);
        assert!(!hostile.contains('\x1b'));
    }
}
