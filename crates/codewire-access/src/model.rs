use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AccessError, AccessProfileId, AccessProfileName, BrokerOperationId, BrokerRouteId,
    CapabilitySlot, CredentialId, EnvironmentId, OwnerId, ProviderId,
};

const MAX_LABEL_BYTES: usize = 256;

fn validate_label(value: &str, field: &'static str) -> Result<(), AccessError> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AccessError::InvalidField { field });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    Local,
    Platform,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Owner {
    User(OwnerId),
    Organization(OwnerId),
}

impl Owner {
    pub fn id(&self) -> &OwnerId {
        match self {
            Self::User(id) | Self::Organization(id) => id,
        }
    }

    pub fn is_organization(&self) -> bool {
        matches!(self, Self::Organization(_))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CredentialAuthKind {
    OAuth,
    ApiKey,
    AccessToken,
    GitHubApp,
    SshPrivateKey,
    SshAgent,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Expired,
    RefreshFailed,
    Revoked,
}

/// Non-secret credential metadata. The corresponding protected-store entry is
/// intentionally absent and belongs to placement persistence.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub placement: Placement,
    pub owner: Owner,
    pub provider: ProviderId,
    pub authentication_kind: CredentialAuthKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_hint: Option<String>,
    pub status: CredentialStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub revocation_generation: u64,
}

impl CredentialMetadata {
    pub fn validate(&self) -> Result<(), AccessError> {
        validate_label(&self.display_name, "credential display name")?;
        if let Some(hint) = &self.account_hint {
            validate_label(hint, "credential account hint")?;
        }
        if self.revocation_generation == 0 {
            return Err(AccessError::ZeroGeneration {
                field: "credential revocation generation",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessProfile {
    pub id: AccessProfileId,
    pub placement: Placement,
    pub owner: Owner,
    pub name: AccessProfileName,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<CapabilitySlot, CredentialId>,
}

impl AccessProfile {
    pub fn validate(&self) -> Result<(), AccessError> {
        if self.revision == 0 {
            return Err(AccessError::ZeroGeneration {
                field: "access profile revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentAccessBinding {
    pub environment_id: EnvironmentId,
    pub profile_id: AccessProfileId,
    pub profile_revision: u64,
}

impl EnvironmentAccessBinding {
    pub fn validate(&self) -> Result<(), AccessError> {
        if self.profile_revision == 0 {
            return Err(AccessError::ZeroGeneration {
                field: "bound access profile revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct GrantPermission {
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicy {
    pub authentication_kinds: BTreeSet<CredentialAuthKind>,
    pub permissions: BTreeSet<GrantPermission>,
}

impl CapabilityPolicy {
    fn validate(&self) -> Result<(), AccessError> {
        if self.authentication_kinds.is_empty() {
            return Err(AccessError::EmptyCollection {
                field: "capability authentication kinds",
            });
        }
        if self.permissions.is_empty() {
            return Err(AccessError::EmptyCollection {
                field: "capability permissions",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderDefinition {
    pub id: ProviderId,
    /// Credential forms that may be persisted for this provider even when no
    /// runtime adapter for one of its capability slots has landed yet.
    pub authentication_kinds: BTreeSet<CredentialAuthKind>,
    pub capabilities: BTreeMap<CapabilitySlot, CapabilityPolicy>,
}

impl ProviderDefinition {
    fn validate(&self) -> Result<(), AccessError> {
        if self.authentication_kinds.is_empty() {
            return Err(AccessError::EmptyCollection {
                field: "provider authentication kinds",
            });
        }
        for policy in self.capabilities.values() {
            policy.validate()?;
            if let Some(kind) = policy
                .authentication_kinds
                .iter()
                .find(|kind| !self.authentication_kinds.contains(kind))
            {
                return Err(AccessError::UnsupportedAuthenticationKind {
                    provider: self.id.clone(),
                    kind: *kind,
                });
            }
        }
        Ok(())
    }

    pub fn supports_authentication_kind(&self, kind: CredentialAuthKind) -> bool {
        self.authentication_kinds.contains(&kind)
    }
}

/// Explicit provider capability matrix. A provider or authentication kind is
/// unsupported unless it appears here; adapters cannot infer support from an
/// ambient file or executable.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProviderCatalog(BTreeMap<ProviderId, ProviderDefinition>);

impl ProviderCatalog {
    pub fn from_definitions(
        definitions: impl IntoIterator<Item = ProviderDefinition>,
    ) -> Result<Self, AccessError> {
        let mut catalog = BTreeMap::new();
        for definition in definitions {
            definition.validate()?;
            let provider = definition.id.clone();
            if catalog.insert(provider.clone(), definition).is_some() {
                return Err(AccessError::DuplicateProvider { provider });
            }
        }
        Ok(Self(catalog))
    }

    pub fn get(&self, provider: &ProviderId) -> Option<&ProviderDefinition> {
        self.0.get(provider)
    }
}
