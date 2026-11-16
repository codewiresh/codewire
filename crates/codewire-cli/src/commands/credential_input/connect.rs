//! The one `cw credentials connect` flow, for both stores: the required name,
//! the existing connection it reconnects, one GitHub connection per user
//! (#4717, C3), one reconnect confirmation, and the order of the steps. A
//! store supplies only its own steps through [`ConnectStore`]: locally the
//! provider login runs in this process and the result is saved to the local
//! authority; in the cloud the credential service runs both.

use std::io::IsTerminal as _;

use anyhow::Context as _;
use codewire_credential_broker::provider_oauth::{ProviderRevocation, RevocationFailure};

use super::CredentialExecution;
use crate::commands::{
    CredentialConnectArgs, CredentialConnectProviderArg, prompt_confirm_default_no,
};

/// What a connect says when it stops before anything was saved.
pub(in crate::commands) const CANCELED: &str = "canceled; no credential was changed";

/// The provider a `connect` names, as both stores record it.
pub(in crate::commands) fn provider_id(provider: CredentialConnectProviderArg) -> &'static str {
    match provider {
        CredentialConnectProviderArg::Codex => "openai",
        CredentialConnectProviderArg::Github => "github",
        CredentialConnectProviderArg::Claude => "anthropic",
    }
}

/// What the provider still holds of a sign-in it approved that a cancel
/// discarded. `revoked` is OpenAI's answer when this process asked it; the
/// provider's own error never reaches the terminal.
/// Where a person ends every ChatGPT session (OpenAI help article 9243857).
/// OpenAI doesn't document that it ends a Codex sign-in, so `cw` names where
/// it is without claiming that, and without a link (cw-cli on #4908). #4908
/// adds the same words for `cw credentials delete`; one copy moves to the
/// other's home once both have landed.
const CHATGPT_SIGN_OUT: &str =
    "you can sign out of all ChatGPT devices in ChatGPT under Settings → Security";

pub(in crate::commands) fn discarded_sign_in(
    provider: CredentialConnectProviderArg,
    revoked: Option<ProviderRevocation>,
) -> Option<String> {
    let line = match (provider, revoked) {
        (CredentialConnectProviderArg::Codex, Some(ProviderRevocation::Confirmed)) => {
            "OpenAI revoked the Codex sign-in you approved.".to_owned()
        }
        (CredentialConnectProviderArg::Codex, Some(ProviderRevocation::Failed(failure))) => {
            // The reason in words; the status code only in parentheses
            // (cw-cli on #4908).
            let reason = match failure {
                RevocationFailure::Refused(status) => {
                    format!("OpenAI refused the request (HTTP {status})")
                }
                RevocationFailure::Unreadable => "the sign-in couldn't be read".to_owned(),
                // Unavailable; a Codex revocation never answers Expired.
                _ => "OpenAI couldn't be reached".to_owned(),
            };
            format!(
                "OpenAI didn't confirm revoking the Codex sign-in you approved: {reason}. It may stay valid until it expires; {CHATGPT_SIGN_OUT}."
            )
        }
        (CredentialConnectProviderArg::Codex, None) => return None,
        (CredentialConnectProviderArg::Github, _) => {
            "GitHub keeps the sign-in you approved until you revoke Codewire at https://github.com/settings/apps/authorizations.".to_owned()
        }
        (CredentialConnectProviderArg::Claude, _) => {
            "The Claude sign-in you approved expires on its own; you can remove it sooner in your Claude account settings.".to_owned()
        }
    };
    Some(line)
}

/// The provider's name in messages.
pub(in crate::commands) fn provider_label(provider: CredentialConnectProviderArg) -> &'static str {
    match provider {
        CredentialConnectProviderArg::Codex => "Codex",
        CredentialConnectProviderArg::Github => "GitHub",
        CredentialConnectProviderArg::Claude => "Claude",
    }
}

/// What the reconnect confirmation shows of an existing credential.
/// Metadata only.
pub(in crate::commands) struct Reconnecting {
    pub(in crate::commands) name: String,
    pub(in crate::commands) id: String,
    pub(in crate::commands) revision: u64,
    pub(in crate::commands) status: &'static str,
}

/// The credential a connect creates or reconnects. `existing` is the exact
/// revision the person confirmed; a store never resolves the name again.
pub(in crate::commands) struct ConnectTarget<R> {
    pub(in crate::commands) provider: CredentialConnectProviderArg,
    pub(in crate::commands) name: String,
    pub(in crate::commands) existing: Option<R>,
}

/// One store's side of a connect.
pub(in crate::commands) trait ConnectStore {
    /// The placement word in messages: `local` or `cloud`.
    const PLACEMENT: &'static str;
    type Record;
    /// What the provider handed back, held until the credential is saved.
    type Approval;

    /// The credential named `name` when it is this provider's connected
    /// kind. A credential of another provider or kind under that name is an
    /// error, never a target.
    async fn named(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<Option<Self::Record>>;

    /// Every credential of this provider's connected kind, whatever its name.
    async fn connections(
        &mut self,
        provider: CredentialConnectProviderArg,
    ) -> anyhow::Result<Vec<Self::Record>>;

    fn display_name(record: &Self::Record) -> &str;

    fn describe(record: &Self::Record) -> anyhow::Result<Reconnecting>;

    /// The provider step. Where this process waits for the provider it ends
    /// at the first Ctrl-C through `interrupt`.
    async fn approve(
        &mut self,
        target: &ConnectTarget<Self::Record>,
        interrupt: &mut Interrupt,
    ) -> anyhow::Result<Self::Approval>;

    /// A cancel came after the provider approved: revoke what it approved
    /// where this store can, and say what the provider still holds (#4904;
    /// cw-security on #4717). Nothing is saved.
    async fn discard(
        &mut self,
        provider: CredentialConnectProviderArg,
        approval: Self::Approval,
    ) -> Option<String>;

    /// Save the approved credential and print the result.
    async fn publish(
        &mut self,
        target: ConnectTarget<Self::Record>,
        approval: Self::Approval,
        interrupt: &mut Interrupt,
        execution: &mut CredentialExecution,
    ) -> anyhow::Result<()>;
}

/// `cw credentials connect` against `store`.
pub(in crate::commands) async fn connect<S: ConnectStore>(
    store: &mut S,
    args: CredentialConnectArgs,
    execution: &mut CredentialExecution,
) -> anyhow::Result<()> {
    let is_terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    connect_with(
        store,
        args,
        execution,
        is_terminal,
        prompt_confirm_default_no,
    )
    .await
}

async fn connect_with<S: ConnectStore>(
    store: &mut S,
    args: CredentialConnectArgs,
    execution: &mut CredentialExecution,
    is_terminal: bool,
    prompt: impl FnOnce(&str) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let provider = args.provider.context("credential provider is required")?;
    let name = crate::commands::trimmed_required(
        args.name
            .as_deref()
            .context("credential name is required")?,
        "credential name",
    )?
    .to_owned();
    let existing = existing_connection(store, provider, &name).await?;
    if let Some(record) = &existing {
        let reconnecting = S::describe(record)?;
        if !confirm_reconnect_with(
            S::PLACEMENT,
            provider,
            &reconnecting,
            args.yes,
            is_terminal,
            prompt,
        )? {
            eprintln!("Canceled; no credential was changed.");
            anyhow::ensure!(!args.guided, CANCELED);
            return Ok(());
        }
    }
    let target = ConnectTarget {
        provider,
        name,
        existing,
    };
    let mut interrupt = Interrupt::default();
    let approval = store.approve(&target, &mut interrupt).await?;
    // A Ctrl-C while the provider answered, or since, is a cancellation
    // (cw-security on #4798): nothing is saved after it, and what the
    // provider approved does not stay live where Codewire can revoke it.
    if interrupt.was_pressed() {
        if let Some(line) = store.discard(provider, approval).await {
            eprintln!("{line}");
        }
        anyhow::bail!(CANCELED);
    }
    store
        .publish(target, approval, &mut interrupt, execution)
        .await
}

/// The credential this connect reconnects, if any. GitHub is one connection
/// per user in both stores, as the credential service enforces: a second
/// one under another name is refused before any provider step.
async fn existing_connection<S: ConnectStore>(
    store: &mut S,
    provider: CredentialConnectProviderArg,
    name: &str,
) -> anyhow::Result<Option<S::Record>> {
    if matches!(provider, CredentialConnectProviderArg::Github) {
        let connections = store.connections(provider).await?;
        anyhow::ensure!(
            connections.len() <= 1,
            "more than one {} GitHub connection exists; delete all but one before reconnecting",
            S::PLACEMENT
        );
        if let Some(connected) = connections.first().map(S::display_name) {
            anyhow::ensure!(
                connected.eq_ignore_ascii_case(name),
                "GitHub is already connected as {connected}; run `cw credentials --{} connect github --name {} --yes` to reconnect it",
                S::PLACEMENT,
                crate::commands::platform_commands::shell_word(connected)
            );
        }
    }
    store.named(provider, name).await
}

fn confirm_reconnect_with(
    placement: &str,
    provider: CredentialConnectProviderArg,
    existing: &Reconnecting,
    yes: bool,
    is_terminal: bool,
    prompt: impl FnOnce(&str) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let label = provider_label(provider);
    let message = format!(
        "Reconnect {placement} {label} credential {:?} ({}, revision {}, status {})? Its identity and profile bindings will be kept; it will become active and its hard expiry will be preserved.",
        existing.name, existing.id, existing.revision, existing.status,
    );
    if yes {
        eprintln!("{message}");
        return Ok(true);
    }
    anyhow::ensure!(
        is_terminal,
        "reconnecting an existing {placement} {label} credential requires terminal confirmation or --yes"
    );
    prompt(&message)
}

/// Ctrl-C during a connect, from when this process first waits for the
/// provider. Listening starts only then, so Ctrl-C at an earlier prompt still
/// ends the process. Once listening, a press is remembered even while nothing
/// waits for it, so the press between the provider's answer and the save is
/// seen.
#[derive(Default)]
pub(in crate::commands) struct Interrupt {
    source: Option<Source>,
    #[cfg(test)]
    pressed_in_test: bool,
}

/// Where the press comes from. The sign-in screen's key watcher (#4885)
/// replaces this with its `KeyWatch`, which has the same three calls.
type Source = CtrlC;

impl Interrupt {
    /// Start listening, once.
    pub(in crate::commands) fn listen(&mut self) {
        self.source.get_or_insert_with(Source::new);
    }

    /// The first press since listening started.
    pub(in crate::commands) async fn pressed(&mut self) {
        self.listen();
        if let Some(source) = &self.source {
            source.cancelled().await;
        }
    }

    pub(in crate::commands) fn was_pressed(&self) -> bool {
        #[cfg(test)]
        if self.pressed_in_test {
            return true;
        }
        self.source.as_ref().is_some_and(Source::was_cancelled)
    }
}

/// A sticky Ctrl-C flag. Without a usable signal handler Ctrl-C keeps its
/// default behaviour and this never reads pressed. A second press ends the
/// process as Ctrl-C would, so a person never waits on a step after the
/// first one. Ctrl-C arrives as a signal only while the terminal is in its
/// normal mode, so that exit has no terminal mode to restore.
struct CtrlC {
    pressed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    woken: std::sync::Arc<tokio::sync::Notify>,
    listener: tokio::task::AbortHandle,
}

impl CtrlC {
    fn new() -> Self {
        let pressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let woken = std::sync::Arc::new(tokio::sync::Notify::new());
        let listener = tokio::spawn({
            let (pressed, woken) = (pressed.clone(), woken.clone());
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    pressed.store(true, std::sync::atomic::Ordering::SeqCst);
                    woken.notify_waiters();
                    if tokio::signal::ctrl_c().await.is_ok() {
                        std::process::exit(130);
                    }
                }
            }
        })
        .abort_handle();
        Self {
            pressed,
            woken,
            listener,
        }
    }

    async fn cancelled(&self) {
        loop {
            let woken = self.woken.notified();
            tokio::pin!(woken);
            // Registered before the flag is read, so a press between the two
            // still wakes this wait.
            woken.as_mut().enable();
            if self.was_cancelled() {
                return;
            }
            woken.await;
        }
    }

    fn was_cancelled(&self) -> bool {
        self.pressed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for CtrlC {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

#[cfg(test)]
mod tests;
