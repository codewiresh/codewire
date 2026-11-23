//! The preview and confirmation that `create` and `update` show before they
//! apply a secret project, secret scopes or a credential profile. Local and
//! cloud environments share it, so both say the same thing in the same
//! words, with the same `Credentials` and `Secrets` lines the result prints
//! (docs/dev/CLI-PARITY.md, R4). References only: no secret value or
//! credential passes through here.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::Context;
use codewire_project::SecretBindings;

use super::super::OutputFormat;
use super::{credential_ref, secret_refs};
use crate::commands::progress::terminal_text;
use crate::output::{SourceRef, VmLocation};

/// What the workload can see once sources are applied.
const VISIBILITY: &str = "Application secrets are visible to the workload. Credential profiles reach providers only through their handlers.";

/// One source selection as the preview shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceRows {
    credentials: SourceRef,
    revision: Option<u64>,
    secrets: SourceRef,
    /// The cloud server a local environment's cloud sources come from.
    cloud_server: Option<String>,
}

impl SourceRows {
    /// The rows for `secrets` and the stored profile reference `profile`,
    /// named by `project_name` and `profile_name` when they are known.
    pub(crate) fn new(
        secrets: &SecretBindings,
        project_name: Option<&str>,
        profile: Option<&str>,
        profile_name: Option<&str>,
        revision: Option<u64>,
    ) -> Self {
        Self {
            credentials: credential_ref(profile, profile_name),
            revision: profile.and(revision),
            secrets: secret_refs(secrets, project_name),
            cloud_server: None,
        }
    }

    /// The same rows, with the cloud server their cloud sources come from.
    pub(crate) fn with_cloud_server(mut self, server: Option<&str>) -> Self {
        self.cloud_server = server.map(terminal_text);
        self
    }

    fn render(&self) -> String {
        let revision = self
            .revision
            .map(|revision| format!(" · revision {revision}"))
            .unwrap_or_default();
        let mut text = format!(
            "  Credentials: {}{revision}\n  Secrets:     {}\n",
            self.credentials.text(),
            self.secrets.text()
        );
        if let Some(server) = &self.cloud_server {
            text.push_str(&format!("  Cloud:       {server}\n"));
        }
        text
    }
}

/// What applying an update does to the environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdateEffect {
    /// It is running, so it restarts with the new sources.
    Restart,
    /// It is stopped, so it uses them from its next start.
    NextStart,
}

fn location_text(location: VmLocation) -> &'static str {
    match location {
        VmLocation::Local => "local VM",
        VmLocation::Cloud => "cloud VM",
    }
}

/// The preview before a create that selects sources.
pub(crate) fn create_preview(name: &str, location: VmLocation, rows: &SourceRows) -> String {
    format!(
        "Create environment {} · {} with these sources:\n{}{VISIBILITY}\n",
        terminal_text(name),
        location_text(location),
        rows.render()
    )
}

/// The preview before an update that changes sources.
pub(crate) fn update_preview(
    name: &str,
    location: VmLocation,
    current: &SourceRows,
    replacement: &SourceRows,
    effect: UpdateEffect,
) -> String {
    format!(
        "Change the sources of environment {} · {}\nNow:\n{}Then:\n{}{}\n",
        terminal_text(name),
        location_text(location),
        current.render(),
        replacement.render(),
        match effect {
            UpdateEffect::Restart => "This restarts the environment; its workspace is kept.",
            UpdateEffect::NextStart => "The environment uses them from its next start.",
        }
    )
}

/// Said when an update would leave the sources as they are, as for
/// `--clear-secrets` with no secrets selected. Nothing is asked or sent.
pub(crate) fn report_unchanged(name: &str, output: OutputFormat) {
    if matches!(output, OutputFormat::Text) {
        eprintln!(
            "Environment {} already has these sources; nothing changed.",
            terminal_text(name)
        );
    }
}

/// The one result line after an update changed sources, and the command
/// that shows the environment.
pub(crate) fn print_result(name: &str, location: VmLocation, effect: UpdateEffect) {
    println!(
        "Sources changed for environment {}; {}\n→ {}",
        terminal_text(name),
        match effect {
            UpdateEffect::Restart => "it restarted with them.",
            UpdateEffect::NextStart => "it uses them from its next start.",
        },
        super::environment_command(location, "info", &terminal_text(name))
    );
}

/// Asks to apply the previewed sources at a terminal; `--yes` applies them
/// without asking. Without a terminal, or with JSON output, it refuses and
/// names `--yes`.
pub(crate) fn confirm(yes: bool, output: OutputFormat) -> anyhow::Result<()> {
    let interactive = !matches!(output, OutputFormat::Json)
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal();
    confirm_with(yes, interactive, || {
        eprint!("Apply these sources? [y/N]: ");
        std::io::stderr()
            .flush()
            .context("flush source confirmation")?;
        read_confirmation(std::io::stdin().lock())
    })
}

fn confirm_with(
    yes: bool,
    interactive: bool,
    prompt: impl FnOnce() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    if !interactive {
        return Err(crate::error_report::with_next_step(
            anyhow::anyhow!(
                "applying sources needs --yes outside an interactive terminal or with JSON output; nothing was changed"
            ),
            "--yes",
        ));
    }
    anyhow::ensure!(prompt()?, "canceled; nothing was changed");
    Ok(())
}

/// A yes from at most one line of input.
pub(crate) fn read_confirmation(reader: impl BufRead) -> anyhow::Result<bool> {
    let mut input = String::new();
    let count = reader
        .take(65)
        .read_line(&mut input)
        .context("read source confirmation")?;
    Ok(count > 0 && count < 65 && matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use codewire_project::StoragePlacement;

    use super::*;

    fn bindings(
        project: &str,
        organization: bool,
        user: Option<StoragePlacement>,
    ) -> SecretBindings {
        SecretBindings {
            project: project.to_owned(),
            organization,
            user,
        }
    }

    #[test]
    fn both_placements_preview_a_create_in_the_same_words() {
        let id = "856b6b9e-a520-48c7-aab1-8ac915465f28";
        let cloud = SourceRows::new(
            &bindings(&format!("platform:id:{id}"), true, None),
            Some("app-dev"),
            Some(&format!("platform:id:{id}")),
            Some("user/work"),
            Some(3),
        );
        assert_eq!(
            create_preview("app", VmLocation::Cloud, &cloud),
            "Create environment app · cloud VM with these sources:\n  Credentials: work (cloud) · revision 3\n  Secrets:     app-dev (cloud), organization secrets (cloud)\nApplication secrets are visible to the workload. Credential profiles reach providers only through their handlers.\n"
        );
        let local = SourceRows::new(
            &bindings(
                &format!("local:id:{id}"),
                false,
                Some(StoragePlacement::Local),
            ),
            Some("app-dev"),
            None,
            None,
            None,
        );
        assert_eq!(
            create_preview("app", VmLocation::Local, &local),
            "Create environment app · local VM with these sources:\n  Credentials: none\n  Secrets:     app-dev (local), personal secrets (local)\nApplication secrets are visible to the workload. Credential profiles reach providers only through their handlers.\n"
        );
        for preview in [
            create_preview("app", VmLocation::Cloud, &cloud),
            create_preview("app", VmLocation::Local, &local),
        ] {
            for internal in ["native", "platform", "Some(", id] {
                assert!(!preview.contains(internal), "{internal}: {preview}");
            }
        }
    }

    #[test]
    fn an_update_shows_now_then_and_what_happens() {
        let now = SourceRows::new(&bindings("", false, None), None, None, None, None);
        let then = SourceRows::new(
            &bindings("", false, Some(StoragePlacement::Platform)),
            None,
            None,
            None,
            None,
        )
        .with_cloud_server(Some("https://codewire.example"));
        assert_eq!(
            update_preview("app", VmLocation::Local, &now, &then, UpdateEffect::Restart),
            "Change the sources of environment app · local VM\nNow:\n  Credentials: none\n  Secrets:     none\nThen:\n  Credentials: none\n  Secrets:     personal secrets (cloud)\n  Cloud:       https://codewire.example\nThis restarts the environment; its workspace is kept.\n"
        );
        assert!(
            update_preview(
                "app",
                VmLocation::Cloud,
                &now,
                &then,
                UpdateEffect::NextStart
            )
            .ends_with("The environment uses them from its next start.\n")
        );
    }

    #[test]
    fn without_a_terminal_it_names_yes_and_never_asks() {
        let refused = confirm_with(false, false, || panic!("must not read input")).unwrap_err();
        assert_eq!(
            refused.root_cause().to_string(),
            "applying sources needs --yes outside an interactive terminal or with JSON output; nothing was changed"
        );
        assert!(confirm_with(true, false, || panic!("must not read input")).is_ok());
        assert_eq!(
            confirm_with(false, true, || Ok(false))
                .unwrap_err()
                .to_string(),
            "canceled; nothing was changed"
        );
        assert!(confirm_with(false, true, || Ok(true)).is_ok());
        for input in ["", "\n", "no\n", "yesterday\n"] {
            assert!(!read_confirmation(input.as_bytes()).unwrap());
        }
        assert!(read_confirmation("yes\n".as_bytes()).unwrap());
        assert!(!read_confirmation(format!("yes{}", " ".repeat(100)).as_bytes()).unwrap());
    }
}
