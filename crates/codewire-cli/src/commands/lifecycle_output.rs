//! Lifecycle results shared by local and cloud environments: the
//! presentation an output format allows, the selected-source references a
//! summary names, the next useful command, and the result block for stop and
//! remove.
//!
//! Durable results go to stdout, the working context and progress to
//! stderr, and machine (JSON) output gets none of it. References only: no
//! credential material or secret value passes through here.

use std::fmt;
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

/// One environment's credential profile name, from its stored exact
/// reference by one bounded lookup (a lifecycle summary). `None` when the
/// reference is not exact or the lookup fails or runs out.
pub(crate) async fn credential_profile_name(
    client: &crate::environment_client::EnvironmentClient,
    stored: &str,
) -> Option<String> {
    exact_reference_id(stored)?;
    bounded(client.resolve_credential_profile(stored))
        .await
        .map(|profile| profile.name)
}

/// The account's platform credential profile names by ID, from one bounded
/// listing, for many environments at once (the `cw use` picker). A failed
/// or slow listing leaves every name unknown, so each environment shows its
/// canonical reference.
pub(crate) async fn credential_profile_names(
    platform: &crate::config::ResolvedPlatformConfig,
) -> std::collections::BTreeMap<String, String> {
    bounded(async {
        let client = crate::environment_client::connect_client(platform)?;
        super::platform_profiles::list_profiles(&client).await
    })
    .await
    .map(|profiles| {
        profiles
            .into_iter()
            .map(|profile| (profile.id, profile.name))
            .collect()
    })
    .unwrap_or_default()
}

/// The name `names` (from [`credential_profile_names`]) gives a stored
/// exact profile reference.
pub(crate) fn listed_profile_name<'a>(
    names: &'a std::collections::BTreeMap<String, String>,
    stored: &str,
) -> Option<&'a str> {
    let (_, id) = exact_reference_id(stored)?;
    names.get(id).map(String::as_str)
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
    /// Pending or partial parts of the outcome, each with its quiet detail.
    pub(crate) attention: Vec<(String, String)>,
    pub(crate) next: Option<String>,
}

impl ResultBlock {
    pub(crate) fn new(status: Status, headline: impl Into<String>) -> Self {
        Self {
            status,
            headline: headline.into(),
            detail: None,
            attention: Vec::new(),
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
        self.attention.push((headline.into(), detail.into()));
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
        for (headline, detail) in &self.attention {
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

/// A lifecycle wait that Ctrl-C ended. Its text is the one line that says
/// what continues; `cw` exits 130, as a shell reports an interrupted process.
#[derive(Debug)]
pub(crate) struct Interrupted(String);

impl fmt::Display for Interrupted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Interrupted {}

/// The exit status of an interrupted lifecycle wait.
pub(crate) const INTERRUPTED_EXIT_CODE: i32 = 130;

/// What an interrupted lifecycle wait reports: which operation of which
/// environment, and where to check on it. Stopping the wait never cancels
/// the operation; the local runtime or the platform carries it on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterruptNotice {
    operation: &'static str,
    name: String,
    check: String,
}

impl InterruptNotice {
    /// `operation` names it as a noun: `creation`, `start`, `restart`,
    /// `stop` or `removal`.
    pub(crate) fn new(location: VmLocation, operation: &'static str, name: &str) -> Self {
        let name = terminal_text(name);
        let check = if operation == "removal" {
            format!("cw {} ls", placement_flag(location))
        } else {
            environment_command(location, "info", &name)
        };
        Self {
            operation,
            name,
            check,
        }
    }

    /// The error for an interrupt. `confirmed` says the local runtime or
    /// the platform reported the operation running before the interrupt.
    pub(crate) fn error(&self, confirmed: bool) -> anyhow::Error {
        let Self {
            operation,
            name,
            check,
        } = self;
        anyhow::Error::new(Interrupted(if confirmed {
            format!(
                "Interrupted. The {operation} of {name} continues in the background; check it with `{check}`."
            )
        } else {
            format!(
                "Interrupted. The {operation} of {name} was requested but not confirmed; check it with `{check}`."
            )
        }))
    }
}

/// The exit status for `error` when it is an interrupted lifecycle wait.
pub(crate) fn interrupted_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .any(|cause| cause.is::<Interrupted>())
        .then_some(INTERRUPTED_EXIT_CODE)
}

/// Awaits `work`, or, when `interruptible`, ends the wait at the first
/// Ctrl-C and returns `None`. Without a usable signal handler Ctrl-C keeps
/// its default behaviour. Dropping `work` stops only the waiting.
pub(crate) async fn unless_interrupted<T>(
    interruptible: bool,
    work: impl Future<Output = T>,
) -> Option<T> {
    if !interruptible {
        return Some(work.await);
    }
    tokio::pin!(work);
    tokio::select! {
        result = &mut work => Some(result),
        signal = tokio::signal::ctrl_c() => match signal {
            Ok(()) => None,
            Err(_) => Some(work.await),
        },
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
    fn interrupts_name_what_continues_and_where_to_check() {
        let start = InterruptNotice::new(VmLocation::Local, "start", "app");
        let error = start.error(true);
        assert_eq!(
            error.to_string(),
            "Interrupted. The start of app continues in the background; check it with `cw --local info app`."
        );
        assert_eq!(interrupted_exit_code(&error), Some(130));
        assert_eq!(
            InterruptNotice::new(VmLocation::Cloud, "stop", "review")
                .error(false)
                .to_string(),
            "Interrupted. The stop of review was requested but not confirmed; check it with `cw --cloud info review`."
        );
        assert_eq!(
            InterruptNotice::new(VmLocation::Local, "removal", "app")
                .error(false)
                .to_string(),
            "Interrupted. The removal of app was requested but not confirmed; check it with `cw --local ls`."
        );
        let wrapped = InterruptNotice::new(VmLocation::Cloud, "creation", "app")
            .error(true)
            .context("create environment");
        assert_eq!(interrupted_exit_code(&wrapped), Some(130));
        assert_eq!(interrupted_exit_code(&anyhow::anyhow!("other")), None);
        let hostile = InterruptNotice::new(VmLocation::Local, "start", "app\x1b[2J").error(true);
        assert!(!hostile.to_string().contains('\x1b'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_first_ctrl_c_ends_an_interruptible_wait() {
        // SIGINT reaches the whole test process, so this runs alone in a
        // child of this binary, where no other test's SIGINT listener can see
        // it (#3231).
        const ISOLATED: &str = "CODEWIRE_TEST_SIGINT_ISOLATED";
        const NAME: &str =
            "commands::lifecycle_output::tests::the_first_ctrl_c_ends_an_interruptible_wait";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(ISOLATED, "1")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed"),
                "isolated SIGINT test failed: {}\n{stdout}{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Without an interrupt the work's own result comes back. These run
        // before any SIGINT, so none is still in flight when they do.
        assert_eq!(unless_interrupted(false, async { 7 }).await, Some(7));
        assert_eq!(unless_interrupted(true, async { 8 }).await, Some(8));
        // A listener of our own keeps every SIGINT below from reaching the
        // default handler, whatever the order of registration.
        let _listener =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let wait = tokio::spawn(unless_interrupted(true, std::future::pending::<()>()));
        let pid = std::process::id().to_string();
        // The wait ends once the spawned wait has registered and taken a
        // SIGINT; the bound only turns a hang into a failure.
        let interrupted = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                std::process::Command::new("kill")
                    .args(["-INT", &pid])
                    .status()
                    .unwrap();
                if wait.is_finished() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            wait.await.unwrap()
        })
        .await
        .expect("Ctrl-C ended the wait");
        assert_eq!(interrupted, None);
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
