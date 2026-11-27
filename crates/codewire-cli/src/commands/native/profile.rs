//! What a local VM's selected credential profile gives its agents: whether a
//! managed agent has a provider, and which credentials it can't use right now.
//!
//! A credential that was revoked, has expired or needs reconnecting withholds
//! only its own capability, so the VM still creates, starts and updates
//! (#5545). Each of those commands says which credentials its agents can't
//! use, one line per credential on stderr, with the command that fixes it.

use super::*;
use crate::commands::credentials::output::CredentialView;
use crate::commands::credentials::output::withheld::withheld_line;

/// Managed guests use a selected typed proxy, never the host agent's login.
/// A local VM qualifies a managed agent by the rule hosted Sandboxes use
/// ([`codewire_access::ManagedCredentialClients::managed_agent_client`]), over
/// the slots its selected profile pinned: a platform profile's slots as the
/// environment captured them, a local profile's from its exact revision. The
/// VM's native Codex home is configured for the client the rule picks, so a
/// profile with only the OpenAI API-key slot runs Codex through that route, as
/// a hosted managed Codex agent does.
pub(crate) async fn require_native_agent_profile(
    environment_id: &str,
    agent: codewire_access::ManagedAgent,
) -> anyhow::Result<()> {
    let environment_id = uuid::Uuid::parse_str(environment_id)?.to_string();
    let environment = native_environments()
        .await?
        .into_iter()
        .find(|environment| environment.id == environment_id)
        .context("the managed native environment no longer exists")?;
    let spec = sources::project_from_environment(&environment)?;
    let selected = spec.credentials.ok_or_else(|| {
        crate::commands::lifecycle_output::no_agent_profile(
            crate::output::VmLocation::Local,
            &environment.name,
        )
    })?;
    let clients = if selected.profile.starts_with("platform:") {
        pinned_platform_clients(&environment)?
    } else {
        let profile_id = codewire_access::AccessProfileId::parse(environment.access_profile_id)?;
        let mut credentials = connect_local_credential_authority().await?;
        let bound = credentials
            .get_profile_revision(&profile_id, environment.access_profile_revision)
            .await?;
        codewire_access::ManagedCredentialClients::from_profile_slots(
            bound.profile.entries.keys().map(|slot| slot.as_str()),
        )?
    };
    require_managed_agent_client(clients, agent)
}

/// The client slots a platform-profile environment pinned when its sources
/// were selected. They name provider identities only, never credentials.
pub(super) fn pinned_platform_clients(
    environment: &v1::Environment,
) -> anyhow::Result<codewire_access::ManagedCredentialClients> {
    let authority = environment
        .platform_source_authority
        .as_ref()
        .context("the native environment's platform profile has no pinned selection")?;
    Ok(
        codewire_access::ManagedCredentialClients::from_profile_slots(
            authority.profile_slots.iter().map(String::as_str),
        )?,
    )
}

pub(super) fn require_managed_agent_client(
    clients: codewire_access::ManagedCredentialClients,
    agent: codewire_access::ManagedAgent,
) -> anyhow::Result<()> {
    if clients.managed_agent_client(agent).is_none() {
        let provider = match agent {
            codewire_access::ManagedAgent::Codex => "Codex or OpenAI",
            codewire_access::ManagedAgent::Claude => "Anthropic",
            codewire_access::ManagedAgent::Agy => "Antigravity or Gemini",
        };
        anyhow::bail!(
            "the native environment's selected credential profile has no {provider} provider"
        );
    }
    Ok(())
}

/// The withheld credentials of `environment`, as [`withheld_lines`] says
/// them. Reading the profile is best effort: a VM that started is never failed
/// by this notice, so a read that fails says nothing.
pub(super) async fn withheld_credentials(environment: &v1::Environment) -> Vec<String> {
    withheld_lines(environment).await.unwrap_or_default()
}

/// Prints `lines` on stderr. A summary prints them with its credential lines,
/// before its next step.
pub(super) fn print_withheld(lines: &[String]) {
    for line in lines {
        eprintln!("{line}");
    }
}

/// One line per credential in the environment's local profile that its
/// agents can't use now, in the profile's slot order.
async fn withheld_lines(environment: &v1::Environment) -> anyhow::Result<Vec<String>> {
    if environment.access_profile_id.is_empty() || environment.access_profile_revision == 0 {
        return Ok(Vec::new());
    }
    let profile_id = codewire_access::AccessProfileId::parse(&environment.access_profile_id)?;
    let mut credentials = connect_local_credential_authority().await?;
    let bound = credentials
        .get_profile_revision(&profile_id, environment.access_profile_revision)
        .await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut lines = Vec::new();
    for (slot, credential_id) in &bound.profile.entries {
        let record = credentials.get_credential(credential_id).await?;
        lines.extend(withheld_line(
            &CredentialView::from(&record),
            bound.profile.name.as_str(),
            slot.as_str(),
            now,
        ));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use codewire_access::{CredentialAuthKind, CredentialMetadata, CredentialStatus};
    use codewire_local_credentials::CredentialRecord;
    use codewire_protected_store::ProtectedStorePersistence;

    use super::*;

    fn metadata(
        provider: &str,
        kind: CredentialAuthKind,
        status: CredentialStatus,
        expires: Option<u64>,
    ) -> CredentialMetadata {
        serde_json::from_value(serde_json::json!({
            "id": "0199aa11-bb22-cc33-dd44-556677889900",
            "placement": "local",
            "owner": {"kind": "user", "id": "owner"},
            "provider": provider,
            "authentication_kind": kind,
            "display_name": "walk",
            "status": status,
            "expires_at_unix": expires,
            "revocation_generation": 2,
        }))
        .expect("synthetic credential metadata")
    }

    /// The line a local credential gives at `now`, if it is withheld.
    fn line(metadata: CredentialMetadata, profile: &str, slot: &str, now: u64) -> Option<String> {
        let record = CredentialRecord {
            metadata,
            persistence: ProtectedStorePersistence::OperatingSystem,
            protected_store_cleanup_pending: false,
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
        };
        withheld_line(&CredentialView::from(&record), profile, slot, now)
    }

    #[test]
    fn a_withheld_credential_says_why_and_how_to_fix_it() {
        let revoked = metadata(
            "anthropic",
            CredentialAuthKind::ClaudeSignIn,
            CredentialStatus::Revoked,
            None,
        );
        assert_eq!(
            line(revoked, "work", "anthropic", 100).expect("revoked is withheld"),
            "Claude (sign-in) 'walk' in profile work is revoked; agents in this VM can't use it. \
             Reconnect with `cw credentials --local connect claude --name walk`."
        );
        let key = metadata(
            "openai",
            CredentialAuthKind::ApiKey,
            CredentialStatus::Active,
            Some(50),
        );
        assert_eq!(
            line(key, "work", "openai", 100).expect("past its expiry is withheld"),
            "OpenAI API key 'walk' in profile work has expired; agents in this VM can't use it. \
             Replace it with `cw credentials --local --profile work set openai NAME`."
        );
        let failed = metadata(
            "openai",
            CredentialAuthKind::OAuth,
            CredentialStatus::RefreshFailed,
            None,
        );
        assert!(
            line(failed, "work", "codex", 100)
                .expect("a failed refresh is withheld")
                .contains(" needs reconnecting; ")
        );
        let active = metadata(
            "openai",
            CredentialAuthKind::OAuth,
            CredentialStatus::Active,
            Some(200),
        );
        assert_eq!(line(active, "work", "codex", 100), None);
    }

    /// A name or profile a shell would split is quoted in the command, as the
    /// person pastes it (#5545).
    #[test]
    fn a_spaced_name_and_profile_are_quoted_in_the_fix() {
        let mut spaced = metadata(
            "anthropic",
            CredentialAuthKind::ClaudeSignIn,
            CredentialStatus::Revoked,
            None,
        );
        spaced.display_name = "my walk".into();
        assert_eq!(
            line(spaced, "team work", "anthropic", 100).expect("revoked is withheld"),
            "Claude (sign-in) 'my walk' in profile 'team work' is revoked; agents in this VM can't use \
             it. Reconnect with `cw credentials --local connect claude --name 'my walk'`."
        );
        let mut key = metadata(
            "openai",
            CredentialAuthKind::ApiKey,
            CredentialStatus::Revoked,
            None,
        );
        key.display_name = "it's mine".into();
        assert!(
            line(key, "team work", "openai", 100)
                .expect("revoked is withheld")
                .ends_with(
                    "Replace it with `cw credentials --local --profile 'team work' set openai NAME`."
                )
        );
    }
}
