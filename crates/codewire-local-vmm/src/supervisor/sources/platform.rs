//! Material-free native consumers of a pinned platform source selection.
//!
//! The supervisor configures routing only. Authentication, live grant checks,
//! and recipient sealing happen through the existing credential authority.

use codewire_access::ManagedCredentialClients;
use codewire_local_credentials::PlatformCredentialBinding;
use codewire_project::{PlatformProjectionSelection, platform_projection_reserved_keys};

use super::*;

/// Validate every explicit source reference and classify whether any selected
/// profile or application scope needs the pinned platform authority. Provider
/// and application origins are independent; this is not a uniform-origin rule.
pub(in crate::supervisor) fn requires_platform_authority(
    project: &ProjectSpec,
) -> Result<bool, SupervisorError> {
    let project_placement = if project.secrets.project.is_empty() {
        None
    } else {
        Some(exact_reference(
            StorageReference::project(&project.secrets.project)
                .map_err(|_| SupervisorError::InvalidRequest)?,
        )?)
    };
    Ok(
        profile_placement(project)? == Some(StoragePlacement::Platform)
            || project_placement == Some(StoragePlacement::Platform)
            || project.secrets.user == Some(StoragePlacement::Platform)
            || project.secrets.organization,
    )
}

fn platform_project(
    environment: &EnvironmentRecord,
) -> Result<Option<ProjectSpec>, SupervisorError> {
    let json = environment
        .project_spec_json
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    let sha256 = environment
        .project_spec_sha256
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    validate_project_intent(json, sha256, None).map_err(|_| SupervisorError::InvalidState)?;
    let project: ProjectSpec =
        serde_json::from_slice(json).map_err(|_| SupervisorError::InvalidState)?;
    if !requires_platform_authority(&project)? {
        if environment.platform_source_authority.is_some() {
            return Err(SupervisorError::InvalidState);
        }
        return Ok(None);
    }
    let (profile_id, revision, reference) =
        match (&environment.access_binding, &environment.access_profile) {
            (Some(binding), Some(reference))
                if binding.environment_id == access_environment_id(environment.id)? =>
            {
                (
                    binding.profile_id.to_string(),
                    binding.profile_revision,
                    reference.to_string(),
                )
            }
            (None, None) => (String::new(), 0, String::new()),
            _ => return Err(SupervisorError::EnvironmentAccessUnavailable),
        };
    validate_source_metadata(
        &project,
        &profile_id,
        revision,
        &reference,
        environment
            .platform_source_authority
            .as_ref()
            .map(PlatformSourceAuthority::proto)
            .as_ref(),
    )
    .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
    Ok(Some(project))
}

pub(in crate::supervisor) fn managed_clients(
    environment: &EnvironmentRecord,
) -> Result<Option<ManagedCredentialClients>, SupervisorError> {
    let Some(project) = platform_project(environment)? else {
        return Ok(None);
    };
    if profile_placement(&project)? == Some(StoragePlacement::Local) {
        // The platform metadata above is still validated, but only the exact
        // local profile revision can choose local client slots. None preserves
        // that existing local-authority lookup instead of silently choosing an
        // empty platform client set.
        return Ok(None);
    }
    let authority = environment
        .platform_source_authority
        .as_ref()
        .ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
    // TODO(native-claude-subscription-form): the platform source authority
    // carries slot names only, so a platform profile whose Anthropic slot holds
    // a Claude subscription token projects the API-key form here. That is safe
    // (placeholder only; the platform broker injects the token) but runs Claude
    // Code in API-key mode. Carry the form and call
    // `with_anthropic_subscription_token` as hosted orchestration does.
    let clients = ManagedCredentialClients::from_profile_slots(
        authority.profile_slots.iter().map(String::as_str),
    )
    .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
    // Include runtime and GitHub names, not just the managed-client subset.
    let reserved = reserved_keys(authority)?;
    if project
        .environment
        .keys()
        .any(|name| reserved.contains(name))
    {
        return Err(SupervisorError::EnvironmentAccessUnavailable);
    }
    Ok(Some(clients))
}

/// The clients a platform-profile environment configures for one start: its
/// pinned clients, with GitHub only while the creator's connection is usable
/// at this start. Every personal profile pins GitHub, so its names are always
/// reserved, but the guest is configured for it exactly when the platform
/// would authorize it now, as a hosted Sandbox decides at its start. The
/// platform is asked (`github_connected`) only when GitHub is pinned. An
/// unanswered question (`None`) omits GitHub for this start; it never
/// fabricates it and never fails the start.
pub(in crate::supervisor) async fn clients_for_start<F>(
    pinned: ManagedCredentialClients,
    github_connected: impl FnOnce() -> F,
) -> ManagedCredentialClients
where
    F: std::future::Future<Output = Option<bool>>,
{
    if !pinned.contains(codewire_access::ManagedCredentialClient::GitHub) {
        return pinned;
    }
    if github_connected().await == Some(true) {
        pinned
    } else {
        pinned.without_github()
    }
}

pub(super) fn reserved_keys(
    authority: &PlatformSourceAuthority,
) -> Result<BTreeSet<String>, SupervisorError> {
    let mut reserved =
        platform_projection_reserved_keys(authority.profile_slots.iter().map(String::as_str))
            .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
    // Native agent home owns skill/session state even with no selected client.
    reserved.insert("CODEX_HOME".into());
    Ok(reserved)
}

pub(in crate::supervisor) fn broker_binding(
    environment: &EnvironmentRecord,
    config_directory: &Path,
) -> Result<Option<PlatformCredentialBinding>, SupervisorError> {
    let Some(project) = platform_project(environment)? else {
        return Ok(None);
    };
    let authority = environment
        .platform_source_authority
        .as_ref()
        .ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
    let reserved_keys = reserved_keys(authority)?;
    if project
        .environment
        .keys()
        .any(|key| reserved_keys.contains(key))
    {
        return Err(SupervisorError::EnvironmentAccessUnavailable);
    }
    let project_id = if project.secrets.project.is_empty() {
        None
    } else {
        let reference = StorageReference::project(&project.secrets.project)
            .map_err(|_| SupervisorError::InvalidState)?;
        if exact_reference(reference)? == StoragePlacement::Platform {
            Some(
                reference
                    .selector
                    .strip_prefix("id:")
                    .ok_or(SupervisorError::InvalidState)?
                    .to_owned(),
            )
        } else {
            None
        }
    };
    let profile = if profile_placement(&project)? == Some(StoragePlacement::Platform) {
        environment
            .access_binding
            .as_ref()
            .map(|binding| (binding.profile_id.to_string(), binding.profile_revision))
    } else {
        None
    };
    let binding = PlatformCredentialBinding {
        config_directory: config_directory.to_owned(),
        server_url: authority.server_url.clone(),
        selection: PlatformProjectionSelection {
            creator: authority.user_id.clone(),
            organization: authority.organization_id.clone(),
            organization_selected: project.secrets.organization,
            project_id,
            user_selected: project.secrets.user == Some(StoragePlacement::Platform),
            profile,
            ordinary_keys: project.environment.keys().cloned().collect(),
            reserved_keys,
        },
        // Reuse exact native intent; never create another lifecycle identity.
        selection_sha256: codewire_vmm_guest_probe::Sha256Value::parse_hex(
            environment
                .project_spec_sha256
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?
        .as_bytes(),
    };
    binding
        .validate()
        .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
    Ok(Some(binding))
}

/// Checkout precedes VM admission, but already owns the eventual create ID.
/// Only the explicit platform provider profile is delegated here: application
/// values are neither needed nor admitted by repository preparation.
pub(in crate::supervisor) fn repository_binding(
    request: &v1::CreateEnvironmentRequest,
    project: &ProjectSpec,
    environment_id: Uuid,
    config_directory: &Path,
) -> Result<Option<codewire_local_credentials::RepositoryPlatformAccess>, SupervisorError> {
    let selection = create_request_access_selection(request, project)?;
    if profile_placement(project)? != Some(StoragePlacement::Platform) {
        return Ok(None);
    }
    if environment_id.is_nil() {
        return Err(SupervisorError::InvalidRequest);
    }
    validate_project_intent(
        &request.project_spec_json,
        &request.project_spec_sha256,
        None,
    )
    .map_err(|_| SupervisorError::InvalidRequest)?;
    let (profile_id, revision, _) =
        selection.ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
    let authority = PlatformSourceAuthority::from_proto(
        request
            .platform_source_authority
            .as_ref()
            .ok_or(SupervisorError::EnvironmentAccessUnavailable)?,
    )?;
    let mut binding = PlatformCredentialBinding {
        config_directory: config_directory.to_owned(),
        server_url: authority.server_url.clone(),
        selection: PlatformProjectionSelection {
            creator: authority.user_id.clone(),
            organization: authority.organization_id.clone(),
            organization_selected: false,
            project_id: None,
            user_selected: false,
            profile: Some((profile_id.to_string(), revision)),
            ordinary_keys: project.environment.keys().cloned().collect(),
            reserved_keys: reserved_keys(&authority)?,
        },
        selection_sha256: codewire_vmm_guest_probe::Sha256Value::parse_hex(
            &request.project_spec_sha256,
        )
        .map_err(|_| SupervisorError::InvalidRequest)?
        .as_bytes(),
    };
    resolve_config_directory(&mut binding)?;
    Ok(Some(codewire_local_credentials::RepositoryPlatformAccess {
        environment_id: access_environment_id(environment_id)?,
        environment_generation: 1,
        binding,
    }))
}

/// Runtime config intentionally accepts explicit symlink aliases. Bind their
/// canonical directory once on the trusted host before the broker sees it;
/// never resolve saved login defaults or open credential files here.
pub(in crate::supervisor) fn resolve_config_directory(
    binding: &mut PlatformCredentialBinding,
) -> Result<(), SupervisorError> {
    binding.config_directory = fs::canonicalize(&binding.config_directory)
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?;
    if !binding.config_directory.is_dir() {
        return Err(SupervisorError::CredentialAuthorityUnavailable);
    }
    binding
        .validate()
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)
}

#[cfg(test)]
mod tests;
