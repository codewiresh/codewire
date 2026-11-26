//! What `cw credentials` prints for a credential or a profile, in both
//! placements (#4717 C1): one table and one JSON shape, with the placement
//! as a field, so the same script reads `--local` and `--cloud`. The local
//! store's own facts (owner, protected store, timestamps) appear only in its
//! JSON. Nothing here prints secret material.

use std::collections::BTreeMap;

use codewire_access::{CredentialAuthKind, CredentialStatus, Owner};
use codewire_client as rpc;
use codewire_local_credentials::{
    AccessProfileRecord, AccessProfileRevisionRecord, CredentialRecord,
};
use codewire_protected_store::{ProtectedStoreBackend, ProtectedStorePersistence};
use serde::Serialize;

use super::super::OutputFormat;

/// One credential as both placements show it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct CredentialView {
    id: String,
    placement: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    provider: String,
    authentication_kind: &'static str,
    name: String,
    account_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_public_key: Option<codewire_access::SshPublicKeyMetadata>,
    status: &'static str,
    expires_at_unix: Option<u64>,
    revocation_generation: u64,
    /// The profiles that select it, by name.
    profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_store_persistence: Option<&'static str>,
    /// The local store's backend, where the listing knows it: `file` is not
    /// encrypted by cw (#5255).
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_store: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cleanup_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at_unix_ms: Option<u64>,
}

impl From<&CredentialRecord> for CredentialView {
    fn from(record: &CredentialRecord) -> Self {
        Self {
            id: record.metadata.id.to_string(),
            placement: "local",
            owner: Some(owner_label(&record.metadata.owner)),
            provider: record.metadata.provider.to_string(),
            authentication_kind: authentication_kind_label(record.metadata.authentication_kind),
            name: record.metadata.display_name.clone(),
            account_hint: record.metadata.account_hint.clone(),
            ssh_public_key: record.metadata.ssh_public_key.clone(),
            status: status_label(record.metadata.status),
            expires_at_unix: record.metadata.expires_at_unix,
            revocation_generation: record.metadata.revocation_generation,
            profiles: Vec::new(),
            protected_store_persistence: Some(persistence_label(record.persistence)),
            protected_store: None,
            cleanup_pending: Some(record.protected_store_cleanup_pending),
            created_at_unix_ms: Some(record.created_at_unix_ms),
            updated_at_unix_ms: Some(record.updated_at_unix_ms),
        }
    }
}

/// What kind of credential a provider and authentication kind make, as a
/// person names it: the registry type's label (#6286). A form no type has,
/// such as GitHub's App form, is named by its provider.
pub(in crate::commands) fn kind_label(provider: &str, authentication_kind: &str) -> String {
    let catalog_provider = if provider == "codex" {
        "openai"
    } else {
        provider
    };
    if let Some(row) = codewire_access::CREDENTIAL_TYPES.iter().find(|row| {
        row.provider == catalog_provider
            && authentication_kind_label(row.form) == authentication_kind
    }) {
        return row.label.to_owned();
    }
    match (provider, authentication_kind) {
        ("github", _) => "GitHub".to_owned(),
        (_, "ssh_key") => "SSH key".to_owned(),
        (provider, kind) => format!("{provider} {}", kind.replace('_', " ")),
    }
}

impl CredentialView {
    /// A cloud credential, refused when the service sent a kind or status
    /// this cw doesn't know.
    pub(in crate::commands) fn cloud(credential: &rpc::Credential) -> anyhow::Result<Self> {
        Ok(Self {
            id: credential.id.clone(),
            placement: "cloud",
            owner: None,
            provider: credential.provider.clone(),
            authentication_kind: cloud_kind(credential),
            name: credential.name.clone(),
            account_hint: credential.account_hint.clone(),
            ssh_public_key: credential.ssh_public_key.as_option().map(|key| {
                codewire_access::SshPublicKeyMetadata {
                    openssh: key.openssh.clone(),
                    fingerprint: key.fingerprint.clone(),
                }
            }),
            status: cloud_status(credential)?,
            expires_at_unix: credential.expires_at_unix,
            revocation_generation: credential.revocation_generation,
            profiles: Vec::new(),
            protected_store_persistence: None,
            protected_store: None,
            cleanup_pending: None,
            created_at_unix_ms: None,
            updated_at_unix_ms: None,
        })
    }

    /// What kind of credential it is, as a person names it.
    pub(in crate::commands) fn kind_label(&self) -> String {
        kind_label(&self.provider, self.authentication_kind)
    }

    /// The profiles that select it, from `uses`.
    pub(in crate::commands) fn using(mut self, uses: &Uses) -> Self {
        self.profiles = uses.get(&self.id).cloned().unwrap_or_default();
        self
    }

    /// The PROFILES cell: the cloud's GitHub connection is in every profile.
    fn profiles_cell(&self) -> String {
        if self.placement == "cloud" && self.authentication_kind == "github_app" {
            "every profile".to_owned()
        } else if self.profiles.is_empty() {
            "-".to_owned()
        } else {
            self.profiles.join(", ")
        }
    }

    /// The status a person reads: an active credential past its recorded
    /// hard expiry is withheld by the broker, so it reads expired.
    pub(in crate::commands) fn status_at(&self, now_unix: u64) -> &'static str {
        match (self.status, self.expires_at_unix) {
            ("active", Some(expiry)) if expiry <= now_unix => "expired",
            (status, _) => status,
        }
    }

    pub(in crate::commands) fn provider(&self) -> &str {
        &self.provider
    }

    /// The authentication kind's label, as [`authentication_kind_label`].
    pub(in crate::commands) fn authentication_kind(&self) -> &'static str {
        self.authentication_kind
    }
}

fn cloud_kind(credential: &rpc::Credential) -> &'static str {
    use rpc::CredentialAuthenticationKind as Kind;
    let kind = credential.authentication_kind;
    if kind == Kind::ApiKey {
        "api_key"
    } else if kind == Kind::Oauth {
        "oauth"
    } else if kind == Kind::AccessToken {
        "access_token"
    } else if kind == Kind::GithubApp {
        "github_app"
    } else if kind == Kind::SshKey {
        "ssh_key"
    } else if kind == Kind::ClaudeSignIn {
        "claude_sign_in"
    } else {
        // A kind a newer service added still lists.
        "unknown"
    }
}

fn cloud_status(credential: &rpc::Credential) -> anyhow::Result<&'static str> {
    use rpc::CredentialStatus as Status;
    let status = credential.status;
    Ok(if status == Status::Active {
        "active"
    } else if status == Status::Revoked {
        "revoked"
    } else if status == Status::Expired {
        "expired"
    } else if status == Status::RefreshFailed {
        "refresh_failed"
    } else {
        // A status a newer service added still lists, as a kind does.
        "unknown"
    })
}

pub(in crate::commands) fn owner_label(value: &Owner) -> String {
    match value {
        Owner::User(id) => format!("user/{id}"),
        Owner::Organization(id) => format!("organization/{id}"),
    }
}

pub(in crate::commands) fn authentication_kind_label(value: CredentialAuthKind) -> &'static str {
    match value {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
        CredentialAuthKind::SshKey => "ssh_key",
        CredentialAuthKind::ClaudeSignIn => "claude_sign_in",
    }
}

pub(in crate::commands) fn status_label(value: CredentialStatus) -> &'static str {
    match value {
        CredentialStatus::Active => "active",
        CredentialStatus::Expired => "expired",
        CredentialStatus::RefreshFailed => "refresh_failed",
        CredentialStatus::Revoked => "revoked",
    }
}

fn persistence_label(value: ProtectedStorePersistence) -> &'static str {
    match value {
        ProtectedStorePersistence::OperatingSystem => "operating_system",
        ProtectedStorePersistence::ProcessLifetime => "process_lifetime",
    }
}

/// The line after a credential is deleted, the same in both placements.
pub(in crate::commands) fn deleted(placement: &str, name: &str) -> String {
    let placement = capitalised(placement);
    format!("{placement} credential {name:?} deleted.")
}

/// The question before `delete`, the same in both placements: an active
/// credential is revoked first (#4717 C6).
pub(in crate::commands) fn delete_question(placement: &str, name: &str, active: bool) -> String {
    if active {
        format!("Revoke and delete {placement} credential {name:?}?")
    } else {
        format!("Delete {placement} credential {name:?}?")
    }
}

/// The question before `revoke`, the same in both placements.
pub(in crate::commands) fn revoke_question(placement: &str, name: &str) -> String {
    format!("Revoke {placement} credential {name:?}? Codewire stops using it.")
}

/// The line after a credential is revoked, the same in both placements;
/// `at_provider` says what its provider still holds.
pub(in crate::commands) fn revoked(placement: &str, name: &str) -> String {
    let placement = capitalised(placement);
    format!("{placement} credential {name:?} revoked in Codewire.")
}

/// Where a person ends every ChatGPT session (OpenAI help article 9243857).
/// OpenAI doesn't document that it ends a Codex sign-in, so `cw` names where
/// it is without claiming that, and without a link (#4908).
const CHATGPT_SIGN_OUT: &str =
    "you can sign out of all ChatGPT devices in ChatGPT under Settings → Security";

/// Where a person revokes Codewire's GitHub App authorization.
const GITHUB_AUTHORIZED_APPS: &str = "https://github.com/settings/apps/authorizations";

/// What a deleted credential's provider said when Codewire asked it to
/// revoke the credential too (#4717 C6).
pub(in crate::commands) enum ProviderAnswer {
    /// The provider confirmed it revoked the token.
    Confirmed,
    /// The provider didn't confirm, and why.
    NotConfirmed(NotConfirmedBecause),
    /// Codewire did not ask: the provider offers no revocation it can ask
    /// for, or this placement does not ask yet.
    NotAsked,
}

/// Why a provider didn't confirm a revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::commands) enum NotConfirmedBecause {
    /// It answered with this HTTP status; 0 when none was reported.
    Refused(u16),
    /// It couldn't be reached.
    Unreachable,
    /// Codewire couldn't read the stored token to send.
    Unreadable,
    /// The stored sign-in had expired.
    Expired,
}

/// The reason in words; the status code only in parentheses (#4908).
fn not_confirmed_because(provider: &str, because: NotConfirmedBecause) -> String {
    match because {
        NotConfirmedBecause::Refused(0) => format!("{provider} refused the request"),
        NotConfirmedBecause::Refused(status) => {
            format!("{provider} refused the request (HTTP {status})")
        }
        NotConfirmedBecause::Unreachable => format!("{provider} couldn't be reached"),
        NotConfirmedBecause::Unreadable => "its stored token couldn't be read".to_owned(),
        NotConfirmedBecause::Expired => "the stored sign-in had expired".to_owned(),
    }
}

/// The line after `revoked` or `deleted`: what the provider still holds,
/// the same sentences in both placements. It says a provider revoked a token only when
/// the provider confirmed it. Until #4896 shows whether a GitHub sign-in ends
/// with its access token, GitHub is said to keep it whatever it answered.
pub(in crate::commands) fn at_provider(
    provider: &str,
    kind: &str,
    answer: ProviderAnswer,
) -> Option<String> {
    let line = match (provider, kind, answer) {
        (_, "ssh_key", _) => return None,
        ("github", _, ProviderAnswer::Confirmed) => format!(
            "GitHub revoked its access token, but may keep its sign-in until you revoke Codewire at {GITHUB_AUTHORIZED_APPS}."
        ),
        ("github", _, _) => format!(
            "GitHub keeps its sign-in until you revoke Codewire at {GITHUB_AUTHORIZED_APPS}."
        ),
        ("openai", "oauth", ProviderAnswer::Confirmed) => {
            "OpenAI confirmed it revoked the ChatGPT sign-in.".to_owned()
        }
        ("openai", "oauth", ProviderAnswer::NotConfirmed(because)) => format!(
            "OpenAI didn't confirm revoking the ChatGPT sign-in: {}. It may stay valid until it expires; {CHATGPT_SIGN_OUT}.",
            not_confirmed_because("OpenAI", because)
        ),
        ("openai", "oauth", ProviderAnswer::NotAsked) => format!(
            "The ChatGPT sign-in stays valid at OpenAI until it expires; {CHATGPT_SIGN_OUT}."
        ),
        ("openai", "api_key", _) => {
            "The key still works at OpenAI until you revoke it at https://platform.openai.com/api-keys.".to_owned()
        }
        ("anthropic", "api_key", _) => {
            "The key still works at Anthropic until you revoke it at https://console.anthropic.com/settings/keys.".to_owned()
        }
        ("google", "api_key", _) => {
            "The key still works at Google until you revoke it at https://aistudio.google.com/apikey.".to_owned()
        }
        // A Claude subscription token (`claude setup-token`).
        ("anthropic", "oauth", _) => {
            "The token keeps working at Anthropic until it expires, or until you revoke it in your Claude account.".to_owned()
        }
        ("anthropic", _, _) => {
            "The Claude sign-in still works at Anthropic until it expires or you sign out of Claude.".to_owned()
        }
        _ => return None,
    };
    Some(line)
}

/// The line after `deleted`. A Claude token's is the connect screens'
/// sentence (#4985), which says only Codewire's copy is gone; every other
/// credential's is `at_provider`'s.
pub(in crate::commands) fn after_deleted(
    provider: &str,
    kind: &str,
    answer: ProviderAnswer,
) -> Option<String> {
    if (provider, kind) == ("anthropic", "oauth") {
        return Some(super::super::credential_input::connect::CLAUDE_TOKEN_DELETED.to_owned());
    }
    at_provider(provider, kind, answer)
}

/// The line after a credential profile is deleted, the same in both
/// placements.
pub(in crate::commands) fn profile_deleted(placement: &str, name: &str) -> String {
    let placement = capitalised(placement);
    format!("{placement} profile {name:?} deleted.")
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// What a key's rotation does, said before the replacement is read, the
/// same in both placements.
pub(in crate::commands) fn rotation_notice(
    placement: &str,
    name: &str,
    id: &str,
    revision: u64,
    expiry: Option<u64>,
) -> String {
    let deadline = expiry.map_or_else(
        || "clears the expiry date".to_owned(),
        |expiry| format!("sets the expiry date to {}", expiry_date(expiry)),
    );
    format!(
        "Rotating {placement} API key {name:?} ({id}, revision {revision}) sets its status to Active (including if revoked) and {deadline}. Enter the replacement key to proceed."
    )
}

pub(in crate::commands) mod save_refusal;
pub(in crate::commands) mod withheld;

/// The refusals both placements share (#4717 C4): one sentence each, with
/// the placement word the only difference, and the command that helps.
pub(in crate::commands) mod refusal {
    /// The person stopped: one sentence wherever a credentials command is
    /// cancelled (#4938).
    pub(in crate::commands) const CANCELLED: &str = "Cancelled; nothing was changed.";

    /// A prompt answered with nothing.
    pub(in crate::commands) const NOTHING_ENTERED: &str = "nothing was entered; nothing was saved";

    /// A profile slot given a credential of a kind it doesn't take.
    pub(in crate::commands) fn wrong_kind(
        name: &str,
        kind: &str,
        slot: &str,
        takes: &[String],
    ) -> String {
        let takes = takes.iter().map(|kind| a_kind(kind)).collect::<Vec<_>>();
        let takes = match takes.split_last() {
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
            None => "no credential".to_owned(),
        };
        format!(
            "{name:?} is {}; a profile's {slot} slot takes {takes}",
            a_kind(kind)
        )
    }

    /// A kind with its article: "an OpenAI API key", "a Codex credential".
    fn a_kind(kind: &str) -> String {
        if !kind.ends_with("key") {
            return format!("a {kind} credential");
        }
        let article = if kind.starts_with(['A', 'E', 'I', 'O', 'U', 'S']) {
            "an"
        } else {
            "a"
        };
        format!("{article} {kind}")
    }

    /// No credential by that name.
    pub(in crate::commands) fn not_found(placement: &str, name: &str) -> String {
        format!(
            "no {placement} credential is named {name:?}; `cw credentials --{placement} list` shows them"
        )
    }

    /// No profile by that name.
    pub(in crate::commands) fn profile_not_found(placement: &str, name: &str) -> String {
        format!(
            "no {placement} profile is named {name:?}; `cw credentials --{placement} profiles list` shows them"
        )
    }

    /// A name that matches more than one credential, refused before anything
    /// changes, the same in both placements (#4928). `matches` are each
    /// match's provider and name, sorted. When every match has the typed name
    /// only the providers are listed; when a name also reads as
    /// `PROVIDER/NAME` each match is named. The example names the first
    /// match that has the typed name, which `PROVIDER/NAME` then picks out.
    pub(in crate::commands) fn ambiguous_name(name: &str, matches: &[(String, String)]) -> String {
        let one_name = matches
            .iter()
            .all(|(_, held)| held.eq_ignore_ascii_case(name));
        let listed = matches
            .iter()
            .map(|(provider, held)| {
                if one_name {
                    provider.clone()
                } else {
                    format!("{provider} {held:?}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let example = matches
            .iter()
            .find(|(_, held)| held.eq_ignore_ascii_case(name))
            .or(matches.first())
            .map(|(provider, held)| format!("{provider}/{held}"))
            .unwrap_or_default();
        format!(
            "{name:?} names more than one credential ({listed}); name one, for example {example}"
        )
    }

    /// A new or renamed credential's name that another credential of the
    /// same provider holds (#4928): which one, and a name that is free in
    /// that provider. Another provider's credential may share the name.
    pub(in crate::commands) fn name_taken(
        provider: &str,
        held: &str,
        kind: &str,
        free: Option<&str>,
    ) -> String {
        let example = free.map_or_else(String::new, |free| format!(", for example {free}"));
        format!(
            "{held:?} is in use in {provider} by {}; choose another name{example}",
            a_kind(kind)
        )
    }

    /// The store refused a name as taken in `provider` when this command
    /// could read no credential that holds it, such as an organization's
    /// credential the caller may not read (cw-security on #4928): the
    /// provider only, never the holder.
    pub(in crate::commands) fn name_in_use(provider: &str) -> String {
        format!("that name is in use in {provider}; choose another name")
    }

    /// A new or renamed credential's name that starts with a provider id and
    /// `/`, which `PROVIDER/NAME` would read as another credential (#4928).
    pub(in crate::commands) fn reserved_name(name: &str) -> String {
        let prefix = name.split_once('/').map_or(name, |(prefix, _)| prefix);
        format!(
            "a credential's name can't start with {prefix}/, which reads as a provider; choose another name"
        )
    }

    /// `add` takes this provider's key from neither placement.
    pub(in crate::commands) fn add_unsupported(provider: &str) -> String {
        format!(
            "{provider} has no key to add; `add` takes an openai or anthropic API key, or an SSH key with `add ssh --key-file PATH`. Use `connect` for Codex, GitHub, Claude (sign-in) or Claude (token) (`connect claude-token`)"
        )
    }

    /// `--account-hint` on `add`, which neither placement records (#4717 C5).
    pub(in crate::commands) const ACCOUNT_HINT: &str = "`add` doesn't take --account-hint; a credential's account comes from its provider when you `connect`";

    /// `rotate` on an SSH key.
    pub(in crate::commands) const ROTATE_SSH: &str = "an SSH key isn't rotated in place; make a new one with `cw credentials generate ssh` or `add ssh`, then put it in the profile";

    /// `rotate` on a credential that comes from a provider sign-in.
    pub(in crate::commands) const ROTATE_CONNECTED: &str = "this credential comes from a provider sign-in, so it isn't pasted; reconnect it with `cw credentials connect` and its --name";

    /// `delete` of a credential a profile selects (#4717 C6).
    pub(in crate::commands) fn in_use(
        placement: &str,
        name: &str,
        profile: &str,
        slot: &str,
    ) -> String {
        format!(
            "{placement} credential {name:?} is selected by profile {profile:?}; free it with `cw credentials --{placement} --profile {profile} unset {slot}`"
        )
    }

    /// `delete` of a credential local VMs or cloud Sandboxes still use:
    /// each was made with an earlier revision of a profile that selected it,
    /// and keeps it until `cw update` moves it to the profile as it is now
    /// (#6128, #6211). `vms` is each one's name and its profile's.
    pub(in crate::commands) fn held_by_vms(
        placement: &str,
        name: &str,
        vms: &[(String, String)],
    ) -> String {
        let mut profiles: Vec<&str> = vms.iter().map(|(_, profile)| profile.as_str()).collect();
        profiles.sort_unstable();
        profiles.dedup();
        let names = vms.iter().map(|(vm, _)| vm.as_str()).collect::<Vec<_>>();
        let (one, several, prefix) = if placement == "local" {
            ("local VM", "local VMs", "local")
        } else {
            ("Sandbox", "Sandboxes", "platform")
        };
        let (noun, which, vm) = match names.as_slice() {
            [only] => (one, "it", *only),
            _ => (several, "each", "NAME"),
        };
        let (made_with, profile) = match profiles.as_slice() {
            [one] => (format!("an earlier version of profile {one:?}"), *one),
            _ => (
                format!(
                    "earlier versions of profiles {}",
                    profiles
                        .iter()
                        .map(|profile| format!("{profile:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "PROFILE",
            ),
        };
        format!(
            "{placement} credential {name:?} is still used by {noun} {}, made with {made_with}; move {which} to the profile as it is now with `cw update {vm} --profile {prefix}:{profile}`, or remove {which} with `cw rm {vm}`",
            names.join(", ")
        )
    }

    /// A cloud `delete` the service refused because something still uses the
    /// credential that the check before it did not find, such as a Sandbox
    /// in an organization this account can't list (#6211). Nothing changed.
    pub(in crate::commands) fn still_in_use(placement: &str, name: &str) -> String {
        format!(
            "{placement} credential {name:?} was not deleted: a profile or a Sandbox still uses it, and it was not revoked; free it, then delete it again"
        )
    }

    /// `revoke` or `delete` with nobody to ask and no `--yes`, as `cw rm`
    /// refuses.
    /// `what` is "credential" or "profile"; `command` is what
    /// follows the placement flag, ending in the verb.
    pub(in crate::commands) fn unconfirmed(
        placement: &str,
        what: &str,
        name: &str,
        command: &str,
        json: bool,
    ) -> String {
        let verb = command.rsplit(' ').next().unwrap_or(command);
        let why = if json {
            format!("`cw credentials --{placement} {command} --output json` never asks")
        } else {
            format!(
                "`cw credentials --{placement} {command}` asks first, and there is no terminal to ask at"
            )
        };
        format!("{placement} {what} {name:?} was not {verb}d: {why}; add `--yes` to {verb} it")
    }

    /// `delete` whose revoke succeeded and whose delete failed or may not
    /// have reached the store: running `delete` again finishes it either way.
    /// The command names it as `PROVIDER/NAME`, which another provider's
    /// credential of the same name can't make ambiguous (#4928).
    pub(in crate::commands) fn revoked_not_deleted(
        placement: &str,
        provider: &str,
        name: &str,
    ) -> String {
        let again = crate::commands::platform_commands::shell_word(&format!("{provider}/{name}"));
        format!(
            "{placement} credential {name:?} was revoked, but may not have been deleted; run `cw credentials --{placement} delete {again}` again"
        )
    }

    /// A local `delete` that revoked the credential and moved it out of the
    /// listing, then failed to remove its stored copy: the local credential
    /// store finishes that when it next starts (#6128).
    pub(in crate::commands) fn revoked_pending_removal(name: &str) -> String {
        format!(
            "local credential {name:?} was revoked and is no longer listed, but its stored copy may not have been removed yet; the local credential store removes it when it next starts"
        )
    }

    /// `unset` of a slot the profile doesn't select.
    pub(in crate::commands) fn slot_not_selected(
        placement: &str,
        profile: &str,
        slot: &str,
    ) -> String {
        format!("{placement} profile {profile:?} has no {slot} credential to unset")
    }
}

/// Which profiles select each credential: credential id to profile names.
pub(in crate::commands) type Uses = BTreeMap<String, Vec<String>>;

/// The heading over a placement's credentials.
pub(in crate::commands) fn heading(placement: &str) -> &'static str {
    if placement == "cloud" {
        "In your Codewire account"
    } else {
        "On this computer"
    }
}

/// Print credentials on stdout: the table, or JSON. A list of every store
/// puts each placement's heading over it. Ids, the provider, the account and
/// the revision are in the JSON. Without `uses` (a command's result, not a
/// listing) the PROFILES column is left out rather than guessed.
pub(in crate::commands) fn print_credentials(
    views: &[CredentialView],
    with_profiles: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(views)?),
        OutputFormat::Text => print!(
            "{}",
            format_credentials_text(views, with_profiles, now_unix())
        ),
    }
    Ok(())
}

pub(in crate::commands) fn print_local_credentials(
    records: &[CredentialRecord],
    store: Option<ProtectedStoreBackend>,
    uses: Option<&Uses>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    print_credentials(&local_views(records, store, uses), uses.is_some(), output)
}

/// Local records as listed, each naming its store's backend where the
/// listing knows it.
pub(in crate::commands) fn local_views(
    records: &[CredentialRecord],
    store: Option<ProtectedStoreBackend>,
    uses: Option<&Uses>,
) -> Vec<CredentialView> {
    let empty = Uses::new();
    records
        .iter()
        .map(|record| CredentialView {
            protected_store: store.map(ProtectedStoreBackend::as_str),
            ..CredentialView::from(record).using(uses.unwrap_or(&empty))
        })
        .collect()
}

pub(in crate::commands) fn print_cloud_credentials(
    credentials: &[rpc::Credential],
    uses: Option<&Uses>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let empty = Uses::new();
    let views = credentials
        .iter()
        .map(|credential| {
            CredentialView::cloud(credential).map(|view| view.using(uses.unwrap_or(&empty)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    print_credentials(&views, uses.is_some(), output)
}

/// Which local credentials each local profile selects.
pub(in crate::commands) fn local_uses(profiles: &[AccessProfileRecord]) -> Uses {
    let mut uses = Uses::new();
    for record in profiles {
        for credential in record.profile.entries.values() {
            uses.entry(credential.to_string())
                .or_default()
                .push(record.profile.name.to_string());
        }
    }
    uses
}

/// Which cloud credentials each cloud profile selects.
pub(in crate::commands) fn cloud_uses(profiles: &[rpc::AccessProfile]) -> Uses {
    let mut uses = Uses::new();
    for profile in profiles {
        for entry in &profile.entries {
            uses.entry(entry.credential_id.clone())
                .or_default()
                .push(profile.name.clone());
        }
    }
    uses
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A recorded hard expiry as a UTC date and time.
fn expiry_date(expiry: u64) -> String {
    i64::try_from(expiry)
        .ok()
        .and_then(|expiry| chrono::DateTime::<chrono::Utc>::from_timestamp(expiry, 0))
        .map_or_else(
            || expiry.to_string(),
            |at| at.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

/// The EXPIRES cell: how long a credential with a hard expiry has left.
fn expires_in(expiry: Option<u64>, now_unix: u64) -> String {
    match expiry {
        None => "-".to_owned(),
        Some(expiry) if expiry <= now_unix => "expired".to_owned(),
        Some(expiry) => match (expiry - now_unix) / 86_400 {
            0 => "today".to_owned(),
            1 => "in 1 day".to_owned(),
            days => format!("in {days} days"),
        },
    }
}

/// Rows as columns as wide as their content, two spaces apart.
fn table<const N: usize>(header: [&str; N], rows: &[[String; N]]) -> String {
    let mut widths = header.map(|title| title.chars().count());
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; N]| {
        let mut text = String::new();
        for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if index + 1 == N {
                text.push_str(cell);
            } else {
                text.push_str(&format!("{cell:<width$}  "));
            }
        }
        text.push('\n');
        text
    };
    let mut output = line(header);
    for row in rows {
        output.push_str(&line(row.each_ref().map(String::as_str)));
    }
    output
}

/// The table: name first, sorted by name then kind, no ids. One SSH key
/// shown alone gets its public key and fingerprint under it.
fn format_credentials_text(views: &[CredentialView], with_profiles: bool, now_unix: u64) -> String {
    if views.is_empty() {
        return "No credentials yet.\n→ cw credentials connect\n".to_owned();
    }
    let mut sorted: Vec<&CredentialView> = views.iter().collect();
    sorted.sort_by_key(|view| (view.name.to_lowercase(), view.kind_label()));
    let cells = |view: &CredentialView| {
        [
            view.name.clone(),
            view.kind_label(),
            view.status_at(now_unix).to_owned(),
            expires_in(view.expires_at_unix, now_unix),
        ]
    };
    let mut output = if with_profiles {
        let rows: Vec<[String; 5]> = sorted
            .iter()
            .map(|view| {
                let [name, kind, status, expires] = cells(view);
                [name, kind, status, expires, view.profiles_cell()]
            })
            .collect();
        table(["NAME", "KIND", "STATUS", "EXPIRES", "PROFILES"], &rows)
    } else {
        let rows: Vec<[String; 4]> = sorted.iter().map(|view| cells(view)).collect();
        table(["NAME", "KIND", "STATUS", "EXPIRES"], &rows)
    };
    if let [view] = views
        && let Some(key) = &view.ssh_public_key
    {
        output.push_str(&format!("  {}\n  {}\n", key.openssh, key.fingerprint));
    }
    output
}

/// One credential profile, or one revision of it, as both placements show it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct AccessProfileView {
    id: String,
    placement: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    name: String,
    revision: u64,
    /// The default profile, which `cw create` uses when no profile is
    /// named.
    #[serde(skip_serializing_if = "Option::is_none")]
    is_default: Option<bool>,
    /// Slot to credential id.
    entries: BTreeMap<String, String>,
    /// A cloud profile always includes the account's GitHub connection,
    /// which has no credential id.
    #[serde(skip_serializing_if = "Option::is_none")]
    github_connection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_created_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_created_at_unix_ms: Option<u64>,
}

impl AccessProfileView {
    pub(in crate::commands) fn current(record: &AccessProfileRecord) -> Self {
        Self::local(
            &record.profile,
            record.created_at_unix_ms,
            record.updated_at_unix_ms,
            record.is_default,
        )
    }

    pub(in crate::commands) fn revision(record: &AccessProfileRevisionRecord) -> Self {
        Self::local(
            &record.profile,
            record.profile_created_at_unix_ms,
            record.revision_created_at_unix_ms,
            record.is_default,
        )
    }

    fn local(
        profile: &codewire_access::AccessProfile,
        profile_created_at_unix_ms: u64,
        revision_created_at_unix_ms: u64,
        is_default: bool,
    ) -> Self {
        Self {
            id: profile.id.to_string(),
            placement: "local",
            owner: Some(owner_label(&profile.owner)),
            name: profile.name.to_string(),
            revision: profile.revision,
            is_default: Some(is_default),
            entries: profile
                .entries
                .iter()
                .map(|(slot, credential)| (slot.to_string(), credential.to_string()))
                .collect(),
            github_connection: None,
            profile_created_at_unix_ms: Some(profile_created_at_unix_ms),
            revision_created_at_unix_ms: Some(revision_created_at_unix_ms),
        }
    }

    /// A cloud profile: each selected slot's credential id, and the
    /// account's GitHub connection, which every personal profile includes.
    pub(in crate::commands) fn cloud(profile: &rpc::AccessProfile) -> Self {
        let entries = profile
            .entries
            .iter()
            .map(|entry| (entry.capability_slot.clone(), entry.credential_id.clone()))
            .collect();
        Self {
            id: profile.id.clone(),
            placement: "cloud",
            owner: None,
            name: profile.name.clone(),
            revision: profile.revision,
            is_default: Some(profile.is_default),
            entries,
            github_connection: Some(true),
            profile_created_at_unix_ms: None,
            revision_created_at_unix_ms: None,
        }
    }

    /// One revision of a cloud profile, with when the profile and this
    /// revision were made (#4717 C7).
    pub(in crate::commands) fn cloud_revision(
        profile: &rpc::AccessProfile,
        profile_created_at_unix_ms: u64,
        revision_created_at_unix_ms: u64,
    ) -> Self {
        Self {
            profile_created_at_unix_ms: Some(profile_created_at_unix_ms),
            revision_created_at_unix_ms: Some(revision_created_at_unix_ms),
            ..Self::cloud(profile)
        }
    }
}

/// Each credential's name, as a profile shows what it holds: its kind and
/// name, by credential id.
pub(in crate::commands) type Names = BTreeMap<String, String>;

pub(in crate::commands) fn local_names(records: &[CredentialRecord]) -> Names {
    records
        .iter()
        .map(|record| {
            let view = CredentialView::from(record);
            (
                view.id.clone(),
                format!("{}: {}", view.kind_label(), view.name),
            )
        })
        .collect()
}

pub(in crate::commands) fn cloud_names(credentials: &[rpc::Credential]) -> Names {
    credentials
        .iter()
        .filter_map(|credential| CredentialView::cloud(credential).ok())
        .map(|view| {
            (
                view.id.clone(),
                format!("{}: {}", view.kind_label(), view.name),
            )
        })
        .collect()
}

pub(in crate::commands) fn print_cloud_profiles(
    profiles: &[rpc::AccessProfile],
    names: &Names,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let views = profiles
        .iter()
        .map(AccessProfileView::cloud)
        .collect::<Vec<_>>();
    print_profile_views(&views, names, output)
}

/// Local profiles with the default first, as the cloud lists them.
pub(in crate::commands) fn print_local_profiles(
    records: &[AccessProfileRecord],
    names: &Names,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let mut views = records
        .iter()
        .map(AccessProfileView::current)
        .collect::<Vec<_>>();
    // The default first, as the cloud lists it.
    views.sort_by_key(|view| view.is_default != Some(true));
    print_profile_views(&views, names, output)
}

/// One profile's revisions: the revision first, then what each held.
pub(in crate::commands) fn print_local_profile_revisions(
    records: &[AccessProfileRevisionRecord],
    names: &Names,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let views = records
        .iter()
        .map(AccessProfileView::revision)
        .collect::<Vec<_>>();
    print_profile_revisions(&views, names, output)
}

/// One profile's revisions in either placement, oldest first.
pub(in crate::commands) fn print_profile_revisions(
    views: &[AccessProfileView],
    names: &Names,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(views)?),
        OutputFormat::Text => print!("{}", format_revisions_text(views, names)),
    }
    Ok(())
}

pub(in crate::commands) fn format_revisions_text(
    views: &[AccessProfileView],
    names: &Names,
) -> String {
    let rows: Vec<[String; 2]> = views
        .iter()
        .map(|view| [view.revision.to_string(), view.holds(names)])
        .collect();
    table(["REVISION", "CREDENTIALS"], &rows)
}

pub(in crate::commands) fn print_profile_views(
    views: &[AccessProfileView],
    names: &Names,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(views)?),
        OutputFormat::Text => print!("{}", format_profiles_text(views, names)),
    }
    Ok(())
}

impl AccessProfileView {
    /// The profile's name, marked when it is the default: `NAME (default)`,
    /// the one form everywhere a profile is named.
    fn label(&self) -> String {
        if self.is_default == Some(true) {
            format!("{} (default)", self.name)
        } else {
            self.name.clone()
        }
    }

    /// What it holds, by credential kind and name; an unknown id as itself.
    fn holds(&self, names: &Names) -> String {
        let mut held: Vec<String> = self
            .entries
            .iter()
            .map(|(slot, credential)| match names.get(credential) {
                Some(name) => name.clone(),
                None => format!("{slot}: {credential}"),
            })
            .collect();
        if self.github_connection == Some(true) && !self.entries.contains_key("github") {
            held.push("GitHub: account connection".to_owned());
        }
        if held.is_empty() {
            "none yet".to_owned()
        } else {
            held.join(", ")
        }
    }
}

/// The command that creates a profile, by putting a credential in it.
const PROFILE_SET: &str = "cw credentials --profile NAME set PROVIDER CREDENTIAL";

/// Profiles by name, default marked, with what each holds by name.
fn format_profiles_text(views: &[AccessProfileView], names: &Names) -> String {
    if views.is_empty() {
        return format!("No profiles yet.\n→ {PROFILE_SET}\n");
    }
    let rows: Vec<[String; 2]> = views
        .iter()
        .map(|view| [view.label(), view.holds(names)])
        .collect();
    table(["NAME", "CREDENTIALS"], &rows)
}

/// What a `set` that created the profile says.
pub(in crate::commands) fn profile_created(name: &str, credential: &str) -> String {
    format!("Created profile {name:?} with {credential}")
}

/// What a `set` into an existing profile says.
pub(in crate::commands) fn profile_now_holds(name: &str, credential: &str) -> String {
    format!("{credential} is now in profile {name:?}")
}

/// What an `unset` says.
pub(in crate::commands) fn profile_removed(name: &str, slot: &str) -> String {
    format!("Profile {name:?} no longer has a credential for {slot}")
}

/// A command's one-line result on stdout, marked done.
pub(in crate::commands) fn print_done(line: &str) {
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stdout_style();
    println!("{} {line}", style.status(crate::output::Status::Done));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloud_credential(kind: rpc::CredentialAuthenticationKind) -> rpc::Credential {
        rpc::Credential {
            id: "cred_1".into(),
            name: "work".into(),
            provider: "anthropic".into(),
            authentication_kind: kind.into(),
            account_hint: Some("person@example.test".into()),
            status: rpc::CredentialStatus::Active.into(),
            expires_at_unix: Some(2_000_000_000),
            revocation_generation: 3,
            ..Default::default()
        }
    }

    #[test]
    fn a_cloud_credential_has_the_local_json_fields_and_says_cloud() {
        let view =
            CredentialView::cloud(&cloud_credential(rpc::CredentialAuthenticationKind::ApiKey))
                .unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "id": "cred_1",
                "placement": "cloud",
                "provider": "anthropic",
                "authentication_kind": "api_key",
                "name": "work",
                "account_hint": "person@example.test",
                "status": "active",
                "expires_at_unix": 2_000_000_000u64,
                "revocation_generation": 3,
                "profiles": [],
            })
        );
    }

    #[test]
    fn the_list_is_names_kinds_status_expiry_and_profiles_with_no_ids() {
        let now = 2_000_000_000 - 364 * 86_400 - 100;
        let token =
            CredentialView::cloud(&cloud_credential(rpc::CredentialAuthenticationKind::Oauth))
                .unwrap()
                .using(&Uses::from([(
                    "cred_1".to_owned(),
                    vec!["personal".to_owned(), "work".to_owned()],
                )]));
        let mut github = cloud_credential(rpc::CredentialAuthenticationKind::GithubApp);
        github.id = "cred_2".into();
        github.name = "octocat".into();
        github.provider = "github".into();
        github.expires_at_unix = None;
        let github = CredentialView::cloud(&github).unwrap();
        assert_eq!(
            format_credentials_text(&[token, github], true, now),
            "NAME     KIND            STATUS  EXPIRES      PROFILES\n\
             octocat  GitHub          active  -            every profile\n\
             work     Claude (token)  active  in 364 days  personal, work\n"
        );
    }

    #[test]
    fn a_result_leaves_out_the_profiles_column_and_an_empty_list_says_so() {
        let sign_in = CredentialView::cloud(&cloud_credential(
            rpc::CredentialAuthenticationKind::ClaudeSignIn,
        ))
        .unwrap();
        let text = format_credentials_text(&[sign_in], false, 2_000_000_001);
        assert_eq!(
            text,
            "NAME  KIND              STATUS   EXPIRES\nwork  Claude (sign-in)  expired  expired\n"
        );
        assert!(!text.contains("cred_1"), "no ids: {text}");
        assert_eq!(
            format_credentials_text(&[], true, 0),
            "No credentials yet.\n→ cw credentials connect\n"
        );
        assert_eq!(heading("local"), "On this computer");
        assert_eq!(heading("cloud"), "In your Codewire account");
    }

    #[test]
    fn each_kind_reads_as_a_person_names_it() {
        let label = |provider: &str, kind| {
            let mut credential = cloud_credential(kind);
            credential.provider = provider.into();
            CredentialView::cloud(&credential).unwrap().kind_label()
        };
        use rpc::CredentialAuthenticationKind as Kind;
        assert_eq!(label("anthropic", Kind::ClaudeSignIn), "Claude (sign-in)");
        assert_eq!(label("anthropic", Kind::Oauth), "Claude (token)");
        assert_eq!(label("anthropic", Kind::ApiKey), "Anthropic API key");
        assert_eq!(label("openai", Kind::ApiKey), "OpenAI API key");
        assert_eq!(label("openai", Kind::Oauth), "Codex");
        assert_eq!(label("github", Kind::GithubApp), "GitHub");
        assert_eq!(label("ssh", Kind::SshKey), "SSH key");
    }

    /// The broker withholds a credential past its recorded hard expiry
    /// whatever its stored status, so an active one past it reads expired.
    #[test]
    fn listed_status_reads_expired_past_the_recorded_expiry_with_a_date() {
        let mut credential = cloud_credential(rpc::CredentialAuthenticationKind::Oauth);
        credential.expires_at_unix = Some(1_800_000_000);
        let view = CredentialView::cloud(&credential).unwrap();
        assert_eq!(view.status_at(1_799_999_999), "active");
        assert_eq!(view.status_at(1_800_000_000), "expired");
        credential.status = rpc::CredentialStatus::Revoked.into();
        assert_eq!(
            CredentialView::cloud(&credential)
                .unwrap()
                .status_at(1_900_000_000),
            "revoked"
        );
        credential.expires_at_unix = None;
        credential.status = rpc::CredentialStatus::Active.into();
        assert_eq!(
            CredentialView::cloud(&credential)
                .unwrap()
                .status_at(u64::MAX),
            "active"
        );
        assert_eq!(expiry_date(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(expiry_date(u64::MAX), u64::MAX.to_string());
    }

    #[test]
    fn a_deleted_credential_is_one_sentence_naming_its_placement() {
        assert_eq!(
            deleted("local", "work"),
            "Local credential \"work\" deleted."
        );
        assert_eq!(
            deleted("cloud", "work"),
            "Cloud credential \"work\" deleted."
        );
    }

    #[test]
    fn an_unknown_cloud_status_lists_as_unknown() {
        let mut credential = cloud_credential(rpc::CredentialAuthenticationKind::ApiKey);
        credential.status = rpc::CredentialStatus::Unspecified.into();
        assert_eq!(
            CredentialView::cloud(&credential).unwrap().status,
            "unknown"
        );
    }

    #[test]
    fn a_cloud_profile_lists_its_slots_in_the_same_shape() {
        let profile = rpc::AccessProfile {
            id: "prof_1".into(),
            name: "work".into(),
            revision: 4,
            is_default: true,
            entries: vec![rpc::AccessProfileEntry {
                capability_slot: "anthropic".into(),
                credential_id: "cred_1".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let view = AccessProfileView::cloud(&profile);
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({
                "id": "prof_1",
                "placement": "cloud",
                "name": "work",
                "revision": 4,
                "is_default": true,
                "entries": {"anthropic": "cred_1"},
                "github_connection": true,
            })
        );
        let names = cloud_names(&[cloud_credential(
            rpc::CredentialAuthenticationKind::ClaudeSignIn,
        )]);
        assert_eq!(
            format_profiles_text(&[view], &names),
            "NAME            CREDENTIALS\n\
             work (default)  Claude (sign-in): work, GitHub: account connection\n"
        );
        assert_eq!(
            format_profiles_text(&[], &names),
            "No profiles yet.\n→ cw credentials --profile NAME set PROVIDER CREDENTIAL\n"
        );
    }

    #[test]
    fn the_shared_sentences_read_as_the_glossary_says() {
        assert_eq!(refusal::CANCELLED, "Cancelled; nothing was changed.");
        assert_eq!(
            refusal::wrong_kind("ci", "Claude (token)", "ssh", &["SSH key".to_owned()]),
            "\"ci\" is a Claude (token) credential; a profile's ssh slot takes an SSH key"
        );
        assert_eq!(
            refusal::wrong_kind(
                "k",
                "SSH key",
                "codex",
                &["Codex".to_owned(), "OpenAI API key".to_owned()]
            ),
            "\"k\" is an SSH key; a profile's codex slot takes a Codex credential or an OpenAI API key"
        );
    }

    #[test]
    fn a_set_says_whether_it_created_the_profile() {
        assert_eq!(
            profile_created("work", "ci"),
            "Created profile \"work\" with ci"
        );
        assert_eq!(
            profile_now_holds("work", "ci"),
            "ci is now in profile \"work\""
        );
        assert_eq!(
            profile_removed("work", "anthropic"),
            "Profile \"work\" no longer has a credential for anthropic"
        );
    }
}

#[cfg(test)]
mod delete_tests {
    use super::*;

    #[test]
    fn a_deleted_credentials_provider_line_claims_only_what_the_provider_confirmed() {
        // GitHub keeps its sign-in in every case until #4896 is observed.
        for answer in [
            ProviderAnswer::Confirmed,
            ProviderAnswer::NotConfirmed(NotConfirmedBecause::Refused(404)),
            ProviderAnswer::NotAsked,
        ] {
            let line = at_provider("github", "oauth", answer).unwrap();
            assert!(line.contains(GITHUB_AUTHORIZED_APPS), "{line}");
            assert!(line.contains("keep"), "{line}");
        }
        assert_eq!(
            at_provider("openai", "oauth", ProviderAnswer::Confirmed).unwrap(),
            "OpenAI confirmed it revoked the ChatGPT sign-in."
        );
        let line = at_provider(
            "openai",
            "oauth",
            ProviderAnswer::NotConfirmed(NotConfirmedBecause::Refused(400)),
        )
        .unwrap();
        assert_eq!(
            line,
            "OpenAI didn't confirm revoking the ChatGPT sign-in: OpenAI refused the request (HTTP 400). It may stay valid until it expires; you can sign out of all ChatGPT devices in ChatGPT under Settings → Security."
        );
        // A refusal reported without a status names none.
        let line = at_provider(
            "openai",
            "oauth",
            ProviderAnswer::NotConfirmed(NotConfirmedBecause::Refused(0)),
        )
        .unwrap();
        assert!(
            line.contains("OpenAI refused the request. It may") && !line.contains("HTTP"),
            "{line}"
        );
        // Every answer short of a confirmation names where to sign out.
        assert!(line.contains(CHATGPT_SIGN_OUT), "{line}");
        assert!(
            at_provider("openai", "oauth", ProviderAnswer::NotAsked)
                .unwrap()
                .contains(CHATGPT_SIGN_OUT)
        );
        assert!(
            at_provider("openai", "oauth", ProviderAnswer::NotAsked)
                .unwrap()
                .contains("stays valid")
        );
        assert!(
            at_provider("openai", "api_key", ProviderAnswer::NotAsked)
                .unwrap()
                .contains("https://platform.openai.com/api-keys")
        );
        assert!(
            at_provider("anthropic", "api_key", ProviderAnswer::NotAsked)
                .unwrap()
                .contains("https://console.anthropic.com/settings/keys")
        );
        assert!(
            at_provider("anthropic", "claude_sign_in", ProviderAnswer::NotAsked)
                .unwrap()
                .contains("still works at Anthropic")
        );
        assert!(at_provider("github", "ssh_key", ProviderAnswer::NotAsked).is_none());
    }

    #[test]
    fn a_claude_token_says_only_codewires_copy_is_gone() {
        // Revoked: the token itself still works until it expires or is revoked.
        assert_eq!(
            at_provider("anthropic", "oauth", ProviderAnswer::NotAsked).unwrap(),
            "The token keeps working at Anthropic until it expires, or until you revoke it in your Claude account."
        );
        // Deleted: the connect screens' sentence, word for word (#4985).
        assert_eq!(
            after_deleted("anthropic", "oauth", ProviderAnswer::NotAsked).unwrap(),
            "That removed Codewire's copy only: the token keeps working at Anthropic until it expires, or until you revoke it in your Claude account."
        );
        // Every other credential's line after a delete is at_provider's.
        for (provider, kind) in [
            ("anthropic", "api_key"),
            ("anthropic", "claude_sign_in"),
            ("openai", "oauth"),
        ] {
            assert_eq!(
                after_deleted(provider, kind, ProviderAnswer::NotAsked),
                at_provider(provider, kind, ProviderAnswer::NotAsked)
            );
        }
    }

    #[test]
    fn delete_asks_and_refuses_in_the_placements_words() {
        assert_eq!(
            delete_question("local", "work", true),
            "Revoke and delete local credential \"work\"?"
        );
        assert_eq!(
            delete_question("cloud", "work", false),
            "Delete cloud credential \"work\"?"
        );
        assert_eq!(
            refusal::in_use("local", "work", "daily", "codex"),
            "local credential \"work\" is selected by profile \"daily\"; free it with `cw credentials --local --profile daily unset codex`"
        );
        // A VM made with an earlier revision (#6128): one VM, then several
        // across two profiles.
        let vm = |vm: &str, profile: &str| (vm.to_owned(), profile.to_owned());
        assert_eq!(
            refusal::held_by_vms("local", "work", &[vm("dev", "daily")]),
            "local credential \"work\" is still used by local VM dev, made with an earlier version of profile \"daily\"; move it to the profile as it is now with `cw update dev --profile local:daily`, or remove it with `cw rm dev`"
        );
        assert_eq!(
            refusal::held_by_vms("local", "work", &[vm("dev", "daily"), vm("web", "daily")]),
            "local credential \"work\" is still used by local VMs dev, web, made with an earlier version of profile \"daily\"; move each to the profile as it is now with `cw update NAME --profile local:daily`, or remove each with `cw rm NAME`"
        );
        assert_eq!(
            refusal::held_by_vms("local", "work", &[vm("dev", "same"), vm("web", "daily")]),
            "local credential \"work\" is still used by local VMs dev, web, made with earlier versions of profiles \"daily\", \"same\"; move each to the profile as it is now with `cw update NAME --profile local:PROFILE`, or remove each with `cw rm NAME`"
        );
        assert_eq!(
            refusal::held_by_vms("cloud", "work", &[vm("dev", "daily")]),
            "cloud credential \"work\" is still used by Sandbox dev, made with an earlier version of profile \"daily\"; move it to the profile as it is now with `cw update dev --profile platform:daily`, or remove it with `cw rm dev`"
        );
        assert_eq!(
            refusal::held_by_vms("cloud", "work", &[vm("dev", "daily"), vm("web", "daily")]),
            "cloud credential \"work\" is still used by Sandboxes dev, web, made with an earlier version of profile \"daily\"; move each to the profile as it is now with `cw update NAME --profile platform:daily`, or remove each with `cw rm NAME`"
        );
        assert_eq!(
            revoke_question("cloud", "work"),
            "Revoke cloud credential \"work\"? Codewire stops using it."
        );
        assert_eq!(
            revoked("local", "work"),
            "Local credential \"work\" revoked in Codewire."
        );
        assert_eq!(
            refusal::revoked_not_deleted("local", "openai", "work"),
            "local credential \"work\" was revoked, but may not have been deleted; run `cw credentials --local delete openai/work` again"
        );
    }
}
