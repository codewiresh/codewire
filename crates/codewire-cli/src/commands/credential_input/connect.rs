//! The one `cw credentials connect` flow, for both stores: the required name,
//! the existing connection it reconnects, one GitHub connection per user
//! (#4717, C3), one reconnect confirmation, and the order of the steps. A
//! store supplies only its own steps through [`ConnectStore`]: locally the
//! provider login runs in this process and the result is saved to the local
//! authority; in the cloud the credential service runs both.

use std::io::IsTerminal as _;

use anyhow::Context as _;
use clap::{Args, ValueEnum};
use codewire_credential_broker::provider_oauth::{ProviderRevocation, RevocationFailure};

use super::CredentialExecution;
use crate::commands::{OutputFormat, prompt_confirm_default_no};

/// `cw credentials connect`'s arguments, the same flags as `add`'s. The
/// type's word is parsed into `credential_type`; [`super::types::route`]
/// hands a sign-in or token to this flow as `provider`, and any other type to
/// its own.
#[derive(Debug, Args)]
pub(crate) struct CredentialConnectArgs {
    #[arg(
        value_name = "PROVIDER",
        value_parser = super::types::type_parser(false),
        help = super::types::TYPE_HELP
    )]
    pub(crate) credential_type: Option<String>,
    #[arg(skip)]
    pub(crate) provider: Option<CredentialConnectProviderArg>,
    #[arg(long, value_name = "NAME", help = super::NAME_HELP)]
    pub(crate) name: Option<String>,
    #[arg(short, long, help = super::types::YES_HELP)]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(long, value_name = "DATE", value_parser = super::expiry_arg, help = super::EXPIRES_AT_HELP)]
    pub(crate) expires_at: Option<u64>,
    #[arg(long, value_name = "PATH", help = super::types::KEY_FILE_HELP)]
    pub(crate) key_file: Option<std::path::PathBuf>,
    #[arg(long, value_name = "HINT", hide = true)]
    pub(crate) account_hint: Option<String>,
    #[arg(skip)]
    pub(crate) guided: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CredentialConnectProviderArg {
    #[value(help = super::CODEX_DEVICE_AUTHORIZATION_GUIDANCE)]
    Codex,
    Github,
    #[value(help = super::CLAUDE_SIGN_IN_HELP)]
    Claude,
    #[value(help = super::CLAUDE_TOKEN_HELP)]
    ClaudeToken,
    #[value(help = super::ANTIGRAVITY_SIGN_IN_HELP)]
    Antigravity,
}

/// `add claude-subscription`, the setup token's name before #4945.
pub(in crate::commands) const CLAUDE_SUBSCRIPTION_ALIAS: &str = "claude-subscription";

/// `add claude-subscription` as the `connect claude-token` it now is, for one
/// release (#4945): one line names the new command, and the add's name
/// carries over. A token's expiry is always one year, so none is accepted.
pub(in crate::commands) fn claude_token_from_alias(
    placement: &str,
    args: &crate::commands::CredentialAddArgs,
) -> anyhow::Result<CredentialConnectArgs> {
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprintln!(
        "{}",
        claude_token_command_line(placement, args.name.as_deref().unwrap_or("NAME"), style)
    );
    anyhow::ensure!(
        args.key_file.is_none(),
        "--key-file is only valid for add ssh"
    );
    anyhow::ensure!(
        args.account_hint.is_none(),
        "a Claude token doesn't use --account-hint"
    );
    anyhow::ensure!(
        args.expires_at.is_none(),
        "a Claude token expires one year after it is saved; --expires-at is not accepted"
    );
    Ok(CredentialConnectArgs {
        credential_type: None,
        provider: Some(CredentialConnectProviderArg::ClaudeToken),
        name: args.name.clone(),
        yes: false,
        output: crate::commands::OutputFormat::Text,
        expires_at: None,
        key_file: None,
        account_hint: None,
        guided: args.guided,
    })
}

/// The one `→` line for the command that connects or replaces a Claude
/// token, ready to paste.
fn claude_token_command_line(placement: &str, name: &str, style: crate::output::Style) -> String {
    format!(
        "{} cw credentials --{placement} connect claude-token --name {name}",
        style.status(crate::output::Status::Next)
    )
}

/// `rotate` is for API keys: a Claude token is replaced by connecting it again
/// under its name, which asks first (#4945).
pub(in crate::commands) fn claude_token_rotate_refusal(
    placement: &str,
    name: &str,
) -> anyhow::Error {
    crate::error_report::with_next_step(
        anyhow::anyhow!("a Claude token is replaced by connecting it again, not with rotate"),
        format!("cw credentials --{placement} connect claude-token --name {name}"),
    )
}

/// What `delete` adds for a Claude token, in both placements: only Codewire's
/// copy is gone; the token itself works until it expires or is revoked.
pub(in crate::commands) const CLAUDE_TOKEN_DELETED: &str = "That removed Codewire's copy only: the token keeps working at Anthropic until it expires, or until you revoke it in your Claude account.";

/// The setup token's screen and hidden prompt, the same in both placements:
/// what is saved and where, how to get the token, then the token itself from
/// a no-echo prompt or a piped stdin, never argv.
pub(in crate::commands) fn read_claude_token(
    screen: crate::commands::login_screen::SignInScreen<'_>,
) -> anyhow::Result<codewire_protected_store::ProtectedValue> {
    let indent = crate::commands::login_screen::INDENT;
    eprintln!(
        "{}{indent}{}",
        screen.heading(),
        super::CLAUDE_TOKEN_GUIDANCE
    );
    super::prompt_hidden(super::CLAUDE_TOKEN_PROMPT, indent)
}

/// What a connect says when it stops before anything was saved.
pub(in crate::commands) const CANCELED: &str = "canceled; no credential was changed";

/// The provider a `connect` names, as both stores record it.
pub(in crate::commands) fn provider_id(provider: CredentialConnectProviderArg) -> &'static str {
    match provider {
        CredentialConnectProviderArg::Codex => "openai",
        CredentialConnectProviderArg::Github => "github",
        CredentialConnectProviderArg::Claude | CredentialConnectProviderArg::ClaudeToken => {
            "anthropic"
        }
        CredentialConnectProviderArg::Antigravity => "google",
    }
}

/// What a connect saves, in a sentence: "your {noun} wasn't saved".
pub(in crate::commands) fn connected_noun(provider: CredentialConnectProviderArg) -> &'static str {
    match provider {
        CredentialConnectProviderArg::Codex => "Codex sign-in",
        CredentialConnectProviderArg::Github => "GitHub sign-in",
        CredentialConnectProviderArg::Claude => "Claude sign-in",
        CredentialConnectProviderArg::ClaudeToken => "Claude token",
        CredentialConnectProviderArg::Antigravity => "Antigravity sign-in",
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
        // Anthropic publishes no way to revoke a setup token.
        (CredentialConnectProviderArg::ClaudeToken, _) => {
            "The Claude token you pasted stays valid until it expires; Codewire can't revoke it.".to_owned()
        }
        (CredentialConnectProviderArg::Antigravity, Some(ProviderRevocation::Confirmed)) => {
            "Google revoked the Antigravity sign-in you approved.".to_owned()
        }
        (CredentialConnectProviderArg::Antigravity, Some(ProviderRevocation::Failed(failure))) => {
            let reason = match failure {
                RevocationFailure::Refused(status) => {
                    format!("Google refused the request (HTTP {status})")
                }
                RevocationFailure::Unreadable => "the sign-in couldn't be read".to_owned(),
                _ => "Google couldn't be reached".to_owned(),
            };
            format!(
                "Google didn't confirm revoking the Antigravity sign-in you approved: {reason}. You can remove it in your Google Account permissions (https://myaccount.google.com/permissions)."
            )
        }
        (CredentialConnectProviderArg::Antigravity, None) => return None,
    };
    Some(line)
}

/// The provider's name in messages.
pub(in crate::commands) fn provider_label(provider: CredentialConnectProviderArg) -> &'static str {
    credential_type_of_arg(provider).label
}

/// The registry's row for a `connect` provider (#6286). Each provider is the
/// word of a registry `connect` type, as a test checks.
pub(in crate::commands) fn credential_type_of_arg(
    provider: CredentialConnectProviderArg,
) -> &'static codewire_access::CredentialType {
    let word = provider
        .to_possible_value()
        .expect("connect providers are never skipped");
    codewire_access::credential_type(word.get_name())
        .expect("every connect provider is a registry type")
}

/// What the reconnect confirmation shows of an existing credential.
/// Metadata only.
pub(in crate::commands) struct Reconnecting {
    pub(in crate::commands) name: String,
    pub(in crate::commands) status: &'static str,
}

/// The credential a connect creates or reconnects. `existing` is the exact
/// revision the person confirmed; a store never resolves the name again.
pub(in crate::commands) struct ConnectTarget<R> {
    pub(in crate::commands) provider: CredentialConnectProviderArg,
    pub(in crate::commands) name: String,
    pub(in crate::commands) existing: Option<R>,
    /// How the result prints: the one result line, or the credential as
    /// `list --output json` shows it.
    pub(in crate::commands) output: OutputFormat,
}

/// One store's side of a connect.
pub(in crate::commands) trait ConnectStore {
    /// The placement word in messages: `local` or `cloud`.
    const PLACEMENT: &'static str;
    type Record;
    /// What the provider handed back, held until the credential is saved.
    type Approval;

    /// This provider's credential named `name` (or `PROVIDER/NAME`) when it
    /// is the connected kind. Another provider's credential may share the
    /// name (#4928); this provider's credential of another kind under it is
    /// an error, never a target, as is a new name a store would refuse.
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

    /// Whether the store can save a credential now, asked just before the
    /// provider step so a sign-in is never spent on a store that would refuse
    /// it (#4826). The cloud asks nothing here: its service runs the provider
    /// step and the save together.
    async fn ready(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<()>;

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
    // A reconnect keeps the credential's own name, however it was typed.
    let name = existing
        .as_ref()
        .map_or(name, |record| S::display_name(record).to_owned());
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
        output: args.output,
    };
    store.ready(provider, &target.name).await?;
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
            let typed = super::CredentialName::parse(name);
            anyhow::ensure!(
                connected.eq_ignore_ascii_case(name)
                    || typed.qualified.is_some_and(|(prefix, name)| {
                        prefix == provider_id(provider) && connected.eq_ignore_ascii_case(name)
                    }),
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
    let place = if placement == "cloud" {
        "in your Codewire account"
    } else {
        "on this computer"
    };
    let status = match existing.status {
        "active" => String::new(),
        other => format!(" ({other})"),
    };
    let expiry = match provider {
        CredentialConnectProviderArg::ClaudeToken => "its one-year expiry restarts",
        _ => "its expiry is kept",
    };
    let credential = format!("{label} {:?}{status} {place}", existing.name);
    if yes {
        eprintln!(
            "Reconnecting {credential}: it stays in its profiles and becomes active; {expiry}."
        );
        return Ok(true);
    }
    anyhow::ensure!(
        is_terminal,
        "the {label} credential {:?} is already connected {place}; pass --yes to reconnect it without a terminal",
        existing.name
    );
    prompt(&format!(
        "Reconnect {credential}? It stays in its profiles and becomes active; {expiry}."
    ))
}

/// Ctrl-C during a connect, from when this process first waits for the
/// provider. Listening starts only then, so Ctrl-C at an earlier prompt still
/// ends the process. Once listening, a press is remembered even while nothing
/// waits for it, so the press between the provider's answer and the save is
/// seen.
#[derive(Default)]
pub(in crate::commands) struct Interrupt {
    source: std::sync::OnceLock<KeyWatch>,
    #[cfg(test)]
    pressed_in_test: bool,
}

/// Where the press comes from: the sign-in screen's key watch (#4850), a
/// sticky Ctrl-C flag heard as the signal, or as a key while it reads keys
/// at a terminal. A second press ends the process with 130, after the
/// terminal is given back.
type KeyWatch = crate::commands::login_screen::KeyWatch;

impl Interrupt {
    /// Start listening, once.
    pub(in crate::commands) fn listen(&self) {
        self.source.get_or_init(KeyWatch::new);
    }

    /// The first press since listening started.
    pub(in crate::commands) async fn pressed(&self) {
        self.listen();
        if let Some(source) = self.source.get() {
            source.cancelled().await;
        }
    }

    pub(in crate::commands) fn was_pressed(&self) -> bool {
        #[cfg(test)]
        if self.pressed_in_test {
            return true;
        }
        self.source.get().is_some_and(KeyWatch::was_cancelled)
    }

    /// While a device sign-in waits: `c` copies its link, and the waiting
    /// line shows, at an interactive terminal.
    pub(in crate::commands) fn watch_keys(&self, url: &str) {
        self.listen();
        if let Some(source) = self.source.get() {
            source.watch(url);
        }
    }

    /// The wait is over: the terminal is given back before anything prints.
    /// A Ctrl-C is still heard as the signal.
    pub(in crate::commands) fn stop_keys(&self) {
        if let Some(source) = self.source.get() {
            source.stop_keys();
        }
    }
}

#[cfg(test)]
mod tests;
