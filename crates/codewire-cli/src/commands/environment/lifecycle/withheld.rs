//! The credentials a hosted Sandbox's profile selects that its agents can't
//! use, named as a local VM's are (#5594). A Sandbox withholds only those
//! capabilities and keeps the rest (#5545), so the result says which, before
//! its next step.

use codewire_client as rpc;
use codewire_project::StoragePlacement;

use crate::commands::credentials::output::CredentialView;
use crate::commands::credentials::output::withheld::withheld_line;
use crate::commands::lifecycle_output::{bounded, exact_reference_id};
use crate::config::ResolvedPlatformConfig;
use crate::presentation::EnvironmentSourceSelection;

/// One line per withheld credential in the Sandbox's pinned profile
/// revision, in the profile's entry order. Best effort and bounded: a
/// Sandbox that was created or updated is never failed by this notice, so a
/// read that fails or runs out says nothing.
pub(in crate::commands::environment) async fn withheld_credentials(
    platform: &ResolvedPlatformConfig,
    selection: Option<&EnvironmentSourceSelection>,
) -> Vec<String> {
    let Some(selection) = selection else {
        return Vec::new();
    };
    bounded(withheld_lines(platform, selection))
        .await
        .unwrap_or_default()
}

/// Prints `lines` on stderr, before the result's next step.
pub(in crate::commands::environment) fn print_withheld(lines: &[String]) {
    for line in lines {
        eprintln!("{line}");
    }
}

async fn withheld_lines(
    platform: &ResolvedPlatformConfig,
    selection: &EnvironmentSourceSelection,
) -> anyhow::Result<Vec<String>> {
    let (Some(binding), Some(revision)) = (&selection.credentials, selection.profile_revision)
    else {
        return Ok(Vec::new());
    };
    let Some((StoragePlacement::Platform, profile_id)) = exact_reference_id(&binding.profile)
    else {
        return Ok(Vec::new());
    };
    let client = crate::environment_client::connect_client(platform)?;
    let profile = client
        .get_access_profile(rpc::GetAccessProfileRequest {
            selector: Some(rpc::get_access_profile_request::Selector::AccessProfileId(
                profile_id.to_owned(),
            )),
            revision: Some(revision),
            ..Default::default()
        })
        .await?
        .access_profile
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("platform omitted credential profile metadata"))?;
    let credentials = crate::commands::platform_credentials::list_all(&client).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(lines(&profile, &credentials, now))
}

/// The lines for `profile`'s entries among `credentials`. An entry whose
/// credential isn't listed, or has a kind or status this cw doesn't know,
/// says nothing.
fn lines(profile: &rpc::AccessProfile, credentials: &[rpc::Credential], now: u64) -> Vec<String> {
    profile
        .entries
        .iter()
        .filter_map(|entry| {
            let credential = credentials
                .iter()
                .find(|credential| credential.id == entry.credential_id)?;
            withheld_line(
                &CredentialView::cloud(credential).ok()?,
                &profile.name,
                &entry.capability_slot,
                now,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(
        id: &str,
        provider: &str,
        kind: rpc::CredentialAuthenticationKind,
        status: rpc::CredentialStatus,
    ) -> rpc::Credential {
        rpc::Credential {
            id: id.into(),
            name: "walk".into(),
            provider: provider.into(),
            authentication_kind: kind.into(),
            status: status.into(),
            revocation_generation: 2,
            ..Default::default()
        }
    }

    /// A Sandbox names each credential of its profile its agents can't use,
    /// with the `--cloud` fix, as a local VM does with `--local` (#5594).
    #[test]
    fn a_sandbox_names_each_withheld_credential_with_its_cloud_fix() {
        use rpc::CredentialAuthenticationKind as Kind;
        use rpc::CredentialStatus as Status;
        let profile = rpc::AccessProfile {
            id: "prof_1".into(),
            name: "team work".into(),
            revision: 3,
            entries: vec![
                rpc::AccessProfileEntry {
                    capability_slot: "anthropic".into(),
                    credential_id: "sign_in".into(),
                    ..Default::default()
                },
                rpc::AccessProfileEntry {
                    capability_slot: "openai".into(),
                    credential_id: "key".into(),
                    ..Default::default()
                },
                rpc::AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: "codex".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let credentials = [
            credential("sign_in", "anthropic", Kind::ClaudeSignIn, Status::Revoked),
            credential("key", "openai", Kind::ApiKey, Status::Expired),
            credential("codex", "openai", Kind::Oauth, Status::Active),
        ];
        assert_eq!(
            lines(&profile, &credentials, 100),
            [
                "Claude (sign-in) 'walk' in profile 'team work' is revoked; agents in this Sandbox \
                 can't use it. Reconnect with `cw credentials --cloud connect claude --name walk`.",
                "OpenAI API key 'walk' in profile 'team work' has expired; agents in this Sandbox \
                 can't use it. Replace it with `cw credentials --cloud --profile 'team work' set \
                 openai NAME`.",
            ]
        );
        assert!(lines(&profile, &credentials[2..], 100).is_empty());
    }
}
