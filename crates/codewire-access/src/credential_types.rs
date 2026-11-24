//! The credential types Codewire takes, one row each (#6286;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Credential types"). What a person
//! sees reads these rows: `cw`'s pickers, accepted words and labels, and the
//! docs' "Add and connect" table. The boundary lists (the provider catalog,
//! the placeholder slots and the hosts) keep their own literals and golden
//! tests, and tests check each against these rows.

use crate::{
    ANTHROPIC_API_HOST, CHATGPT_HOST, CLAUDE_TOKEN_HOST, CODEX_TOKEN_HOST, CredentialAuthKind,
    GITHUB_HOSTS, HttpProvider, OPENAI_API_HOST,
};

/// What choosing a type runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFlow {
    /// A browser or device sign-in at the provider.
    SignIn,
    /// A key or token pasted at a hidden prompt or read from stdin.
    Paste,
    /// An SSH key Codewire generates, or an imported OpenSSH key file.
    SshKey,
}

/// The `cw credentials` subcommand whose flow runs a type. `add` and
/// `connect` both take every type and hand each to its own flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialVerb {
    Add,
    Connect,
}

/// What an agent holds in place of the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentHolds {
    /// A placeholder in this environment variable, which the front door swaps
    /// for the credential.
    Placeholder(&'static str),
    /// A fixed stand-in in this environment variable, beside a base URL that
    /// sends the client's requests through Codewire's route.
    StandIn(&'static str),
    /// Git's credential helper and `GH_TOKEN`, while GitHub's hosts are bound.
    GitHelper,
    /// A placeholder inside the login Codewire delivers to the client.
    InDeliveredLogin,
    /// The SSH agent socket; no key or placeholder is in the environment.
    SshAgent,
}

/// One credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialType {
    /// The CLI's word for it, as in `cw credentials connect codex`.
    pub word: &'static str,
    /// Its name in lists and messages, the glossary's kind name.
    pub label: &'static str,
    /// The provider's name in a sentence about several types.
    pub short: &'static str,
    pub provider: &'static str,
    pub form: CredentialAuthKind,
    /// The profile slots that take it.
    pub slots: &'static [&'static str],
    pub verb: CredentialVerb,
    pub flow: CredentialFlow,
    /// The broker's destination family for it; SSH has none.
    pub http: Option<HttpProvider>,
    pub agent: AgentHolds,
    /// The hosts the broker serves for `http`.
    pub hosts: &'static [&'static str],
    /// The picker's second column.
    pub detail: &'static str,
    /// The docs' "How" cell. Adjacent rows with the same text share a row.
    pub how: &'static str,
}

/// Every type, in picker order.
pub const CREDENTIAL_TYPES: [CredentialType; 7] = [
    CredentialType {
        word: "codex",
        label: "Codex",
        short: "Codex",
        provider: "openai",
        form: CredentialAuthKind::OAuth,
        slots: &["codex"],
        verb: CredentialVerb::Connect,
        flow: CredentialFlow::SignIn,
        http: Some(HttpProvider::CodexOAuth),
        agent: AgentHolds::InDeliveredLogin,
        hosts: &[CHATGPT_HOST, CODEX_TOKEN_HOST],
        detail: "sign in with your ChatGPT account",
        how: "ChatGPT device-code sign-in; enable device code authorization in ChatGPT's Security settings first",
    },
    CredentialType {
        word: "github",
        label: "GitHub",
        short: "GitHub",
        provider: "github",
        form: CredentialAuthKind::OAuth,
        slots: &["github"],
        verb: CredentialVerb::Connect,
        flow: CredentialFlow::SignIn,
        http: Some(HttpProvider::GitHubOAuth),
        agent: AgentHolds::GitHelper,
        hosts: &GITHUB_HOSTS,
        detail: "sign in with your GitHub account",
        how: "Device-code sign-in to the Codewire GitHub App; prints the installation link",
    },
    CredentialType {
        word: "claude",
        label: "Claude (sign-in)",
        short: "Claude",
        provider: "anthropic",
        form: CredentialAuthKind::ClaudeSignIn,
        slots: &["anthropic"],
        verb: CredentialVerb::Connect,
        flow: CredentialFlow::SignIn,
        http: Some(HttpProvider::AnthropicClaudeSignIn),
        agent: AgentHolds::InDeliveredLogin,
        hosts: &[ANTHROPIC_API_HOST, CLAUDE_TOKEN_HOST],
        detail: "your subscription; shows your plan and usage",
        how: "Claude (sign-in): your Claude subscription; browser sign-in, paste the code shown",
    },
    CredentialType {
        word: "claude-token",
        label: "Claude (token)",
        short: "Claude",
        provider: "anthropic",
        form: CredentialAuthKind::OAuth,
        slots: &["anthropic"],
        verb: CredentialVerb::Connect,
        flow: CredentialFlow::Paste,
        http: Some(HttpProvider::AnthropicSubscriptionToken),
        agent: AgentHolds::Placeholder("CLAUDE_CODE_OAUTH_TOKEN"),
        hosts: &[ANTHROPIC_API_HOST],
        detail: "your subscription; lasts a year, for automation, model requests only",
        how: "Claude (token): your Claude subscription; the token from `claude setup-token`, from a hidden prompt or stdin; one-year expiry recorded",
    },
    CredentialType {
        word: "anthropic",
        label: "Anthropic API key",
        short: "Anthropic",
        provider: "anthropic",
        form: CredentialAuthKind::ApiKey,
        slots: &["anthropic"],
        verb: CredentialVerb::Add,
        flow: CredentialFlow::Paste,
        http: Some(HttpProvider::AnthropicApiKey),
        agent: AgentHolds::Placeholder("ANTHROPIC_AUTH_TOKEN"),
        hosts: &[ANTHROPIC_API_HOST],
        detail: "paste a key from console.anthropic.com",
        how: "API key from stdin",
    },
    CredentialType {
        word: "openai",
        label: "OpenAI API key",
        short: "OpenAI",
        provider: "openai",
        form: CredentialAuthKind::ApiKey,
        slots: &["codex", "openai"],
        verb: CredentialVerb::Add,
        flow: CredentialFlow::Paste,
        http: Some(HttpProvider::OpenAiApiKey),
        agent: AgentHolds::StandIn("OPENAI_API_KEY"),
        hosts: &[OPENAI_API_HOST],
        detail: "paste a key from platform.openai.com",
        how: "API key from stdin",
    },
    CredentialType {
        word: "ssh",
        label: "SSH key",
        short: "SSH",
        provider: "ssh",
        form: CredentialAuthKind::SshKey,
        slots: &["ssh"],
        verb: CredentialVerb::Add,
        flow: CredentialFlow::SshKey,
        http: None,
        agent: AgentHolds::SshAgent,
        hosts: &[],
        detail: "generate one, or import an OpenSSH key file",
        how: "an Ed25519 key `cw` generates (public key printed), or an imported OpenSSH key file",
    },
];

/// The type the CLI calls `word`.
pub fn credential_type(word: &str) -> Option<&'static CredentialType> {
    CREDENTIAL_TYPES.iter().find(|row| row.word == word)
}

/// The type a stored credential of `provider` and `form` is.
pub fn credential_type_of(
    provider: &str,
    form: CredentialAuthKind,
) -> Option<&'static CredentialType> {
    CREDENTIAL_TYPES
        .iter()
        .find(|row| row.provider == provider && row.form == form)
}

/// The types whose flow is `verb`'s, in picker order.
pub fn credential_types_for(verb: CredentialVerb) -> impl Iterator<Item = &'static CredentialType> {
    CREDENTIAL_TYPES.iter().filter(move |row| row.verb == verb)
}

/// The docs' "Add and connect" table, generated from the rows.
pub fn credential_types_docs_table() -> String {
    let mut table = String::from("| Provider | How |\n| --- | --- |\n");
    let mut rows = CREDENTIAL_TYPES.iter().peekable();
    while let Some(row) = rows.next() {
        let mut words = vec![format!("`{}`", row.word)];
        while let Some(next) = rows.next_if(|next| next.how == row.how) {
            words.push(format!("`{}`", next.word));
        }
        table.push_str(&format!("| {} | {} |\n", words.join(", "), row.how));
    }
    table
}

#[cfg(test)]
mod tests;
