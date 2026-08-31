use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AccessError, AccessProfile, AccessProfileId, CapabilitySlot, CredentialId, CredentialMetadata,
    CredentialStatus, EnvironmentAccessBinding, EnvironmentId, GrantPermission, Owner, OwnerId,
    Placement, ProviderCatalog,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantContext {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub placement: Placement,
    pub user_id: OwnerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<OwnerId>,
    pub allow_personal_credentials: bool,
    pub authorized_credentials: BTreeSet<CredentialId>,
}

impl GrantContext {
    fn validate(&self) -> Result<(), AccessError> {
        if self.environment_generation == 0 {
            return Err(AccessError::ZeroGeneration {
                field: "environment generation",
            });
        }
        if self.placement == Placement::Local && self.organization_id.is_some() {
            return Err(AccessError::LocalOrganizationUnsupported);
        }
        Ok(())
    }
}

/// Material-free grant evaluated for one exact environment and profile
/// generation. The broker resolves the credential ID inside its own trust
/// boundary and applies the named route/operation policy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DerivedGrant {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub profile_id: AccessProfileId,
    pub profile_revision: u64,
    pub capability_slot: CapabilitySlot,
    pub credential_id: CredentialId,
    pub credential_revocation_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub permissions: BTreeSet<GrantPermission>,
}

pub fn derive_grants(
    context: &GrantContext,
    binding: &EnvironmentAccessBinding,
    profile: &AccessProfile,
    credentials: &BTreeMap<CredentialId, CredentialMetadata>,
    catalog: &ProviderCatalog,
    now_unix: u64,
) -> Result<Vec<DerivedGrant>, AccessError> {
    context.validate()?;
    binding.validate()?;
    profile.validate()?;

    if binding.environment_id != context.environment_id
        || binding.profile_id != profile.id
        || binding.profile_revision != profile.revision
    {
        return Err(AccessError::BindingMismatch);
    }
    if profile.placement != context.placement {
        return Err(AccessError::PlacementMismatch {
            subject: "access profile",
        });
    }
    validate_profile_owner(context, &profile.owner)?;

    let mut grants = Vec::with_capacity(profile.entries.len());
    for (slot, credential_id) in &profile.entries {
        if !context.authorized_credentials.contains(credential_id) {
            return Err(AccessError::CredentialNotAuthorized {
                credential: credential_id.clone(),
            });
        }
        let credential =
            credentials
                .get(credential_id)
                .ok_or_else(|| AccessError::CredentialMissing {
                    credential: credential_id.clone(),
                })?;
        if &credential.id != credential_id {
            return Err(AccessError::CredentialIdentityMismatch {
                credential: credential_id.clone(),
            });
        }
        credential.validate()?;
        if credential.placement != context.placement {
            return Err(AccessError::PlacementMismatch {
                subject: "credential",
            });
        }
        validate_credential_owner(context, &profile.owner, credential)?;
        match credential.status {
            CredentialStatus::Active => {}
            CredentialStatus::Expired => {
                return Err(AccessError::CredentialExpired {
                    credential: credential_id.clone(),
                });
            }
            CredentialStatus::RefreshFailed | CredentialStatus::Revoked => {
                return Err(AccessError::CredentialInactive {
                    credential: credential_id.clone(),
                });
            }
        }
        if credential
            .expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix)
        {
            return Err(AccessError::CredentialExpired {
                credential: credential_id.clone(),
            });
        }

        let provider =
            catalog
                .get(&credential.provider)
                .ok_or_else(|| AccessError::ProviderUnavailable {
                    provider: credential.provider.clone(),
                })?;
        let policy =
            provider
                .capabilities
                .get(slot)
                .ok_or_else(|| AccessError::UnsupportedCapability {
                    provider: credential.provider.clone(),
                    slot: slot.clone(),
                })?;
        if !policy
            .authentication_kinds
            .contains(&credential.authentication_kind)
        {
            return Err(AccessError::UnsupportedCapability {
                provider: credential.provider.clone(),
                slot: slot.clone(),
            });
        }

        grants.push(DerivedGrant {
            environment_id: context.environment_id.clone(),
            environment_generation: context.environment_generation,
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
            capability_slot: slot.clone(),
            credential_id: credential_id.clone(),
            credential_revocation_generation: credential.revocation_generation,
            expires_at_unix: credential.expires_at_unix,
            permissions: policy.permissions.clone(),
        });
    }
    Ok(grants)
}

fn validate_profile_owner(context: &GrantContext, owner: &Owner) -> Result<(), AccessError> {
    match owner {
        Owner::Organization(owner_id) => {
            if context.placement == Placement::Local {
                return Err(AccessError::LocalOrganizationUnsupported);
            }
            if context.organization_id.as_ref() != Some(owner_id) {
                return Err(AccessError::ProfileOwnerMismatch);
            }
        }
        Owner::User(owner_id) => {
            if owner_id != &context.user_id {
                return Err(AccessError::ProfileOwnerMismatch);
            }
        }
    }
    Ok(())
}

fn validate_credential_owner(
    context: &GrantContext,
    profile_owner: &Owner,
    credential: &CredentialMetadata,
) -> Result<(), AccessError> {
    if context.placement == Placement::Local && credential.owner.is_organization() {
        return Err(AccessError::LocalOrganizationUnsupported);
    }
    let compatible = match (profile_owner, &credential.owner) {
        (Owner::User(profile_user), Owner::User(credential_user)) => {
            if context.organization_id.is_some() && !context.allow_personal_credentials {
                return Err(AccessError::PersonalCredentialsForbidden);
            }
            profile_user == credential_user
        }
        (Owner::User(_), Owner::Organization(credential_org)) => {
            context.placement == Placement::Platform
                && context.organization_id.as_ref() == Some(credential_org)
        }
        (Owner::Organization(profile_org), Owner::Organization(credential_org)) => {
            profile_org == credential_org
                && context.organization_id.as_ref() == Some(credential_org)
        }
        (Owner::Organization(_), Owner::User(_)) => false,
    };
    if !compatible {
        return Err(AccessError::CredentialOwnerMismatch {
            credential: credential.id.clone(),
        });
    }
    Ok(())
}
