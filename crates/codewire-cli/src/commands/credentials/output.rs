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
use codewire_protected_store::ProtectedStorePersistence;
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
            cleanup_pending: Some(record.protected_store_cleanup_pending),
            created_at_unix_ms: Some(record.created_at_unix_ms),
            updated_at_unix_ms: Some(record.updated_at_unix_ms),
        }
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
            cleanup_pending: None,
            created_at_unix_ms: None,
            updated_at_unix_ms: None,
        })
    }

    /// What kind of credential it is, as a person names it: the two Claude
    /// forms, Codex, GitHub, an SSH key or a provider's API key.
    fn kind_label(&self) -> String {
        match (self.provider.as_str(), self.authentication_kind) {
            ("anthropic", "claude_sign_in") => "Claude (sign-in)".to_owned(),
            ("anthropic", "oauth") => "Claude (token)".to_owned(),
            ("anthropic", "api_key") => "Anthropic API key".to_owned(),
            ("openai", "api_key") => "OpenAI API key".to_owned(),
            ("openai" | "codex", "oauth") => "Codex".to_owned(),
            ("github", _) => "GitHub".to_owned(),
            (_, "ssh_key") => "SSH key".to_owned(),
            (provider, kind) => format!("{provider} {}", kind.replace('_', " ")),
        }
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

/// The line after a credential profile is deleted, the same in both
/// placements.
pub(in crate::commands) fn profile_deleted(placement: &str, name: &str) -> String {
    let placement = capitalised(placement);
    format!("{placement} credential profile {name:?} deleted.")
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
        || "clears the hard expiry".to_owned(),
        |expiry| format!("sets the hard expiry to {}", expiry_date(expiry)),
    );
    format!(
        "Rotating {placement} API key {name:?} ({id}, revision {revision}) sets its status to Active (including if revoked) and {deadline}. Enter the replacement key to proceed."
    )
}

/// The refusals both placements share (#4717 C4): one sentence each, with
/// the placement word the only difference, and the command that helps.
pub(in crate::commands) mod refusal {
    /// No credential by that name.
    pub(in crate::commands) fn not_found(placement: &str, name: &str) -> String {
        format!(
            "no {placement} credential is named {name:?}; `cw credentials --{placement} list` shows them"
        )
    }

    /// No profile by that name.
    pub(in crate::commands) fn profile_not_found(placement: &str, name: &str) -> String {
        format!(
            "no {placement} credential profile is named {name:?}; `cw credentials --{placement} profiles list` shows them"
        )
    }

    /// A new credential's name is taken.
    pub(in crate::commands) fn name_in_use(placement: &str, name: &str) -> String {
        format!("a {placement} credential is already named {name:?}; choose another --name")
    }

    /// `add` takes this provider's key from neither placement.
    pub(in crate::commands) fn add_unsupported(provider: &str) -> String {
        format!(
            "{provider} has no key to add; `add` takes an openai or anthropic API key, or an SSH key with `add ssh --key-file PATH`. Use `connect` for Codex, GitHub, a Claude sign-in or a Claude token (`connect claude-token`)"
        )
    }

    /// `--account-hint` on `add`, which neither placement records (#4717 C5).
    pub(in crate::commands) const ACCOUNT_HINT: &str = "`add` doesn't take --account-hint; a credential's account comes from its provider when you `connect`";

    /// `rotate` on an SSH key.
    pub(in crate::commands) const ROTATE_SSH: &str = "an SSH key isn't rotated in place; make a new one with `cw credentials generate ssh` or `add ssh`, then select it in the credential profile";

    /// `rotate` on a credential that comes from a provider sign-in.
    pub(in crate::commands) const ROTATE_CONNECTED: &str = "this credential comes from a provider sign-in, so it isn't pasted; reconnect it with `cw credentials connect` and its --name";

    /// `unset` of a slot the profile doesn't select.
    pub(in crate::commands) fn slot_not_selected(
        placement: &str,
        profile: &str,
        slot: &str,
    ) -> String {
        format!("{placement} credential profile {profile:?} has no {slot} credential to unset")
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
    uses: Option<&Uses>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let empty = Uses::new();
    let views = records
        .iter()
        .map(|record| CredentialView::from(record).using(uses.unwrap_or(&empty)))
        .collect::<Vec<_>>();
    print_credentials(&views, uses.is_some(), output)
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
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&views)?),
        OutputFormat::Text => {
            let rows: Vec<[String; 2]> = views
                .iter()
                .map(|view| [view.revision.to_string(), view.holds(names)])
                .collect();
            print!("{}", table(["REVISION", "CREDENTIALS"], &rows));
        }
    }
    Ok(())
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
