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
    SshKey,
}

/// Public registration information, derived from validated private material by
/// the credential authority. This type performs bounded shape checks only;
/// it neither parses private keys nor establishes a matching signing identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshPublicKeyMetadata {
    pub openssh: String,
    pub fingerprint: String,
}

impl SshPublicKeyMetadata {
    pub fn validate(&self) -> Result<(), AccessError> {
        let invalid = || AccessError::InvalidField {
            field: "SSH public key metadata",
        };
        let encoded = self
            .openssh
            .strip_prefix("ssh-ed25519 ")
            .or_else(|| self.openssh.strip_prefix("ssh-rsa "))
            .ok_or_else(invalid)?;
        let base64 = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/');
        let unpadded = encoded.trim_end_matches('=');
        if self.openssh.len() > 4096
            || encoded.len() < 20
            || !encoded.len().is_multiple_of(4)
            || encoded.len() - unpadded.len() > 2
            || !unpadded.bytes().all(base64)
        {
            return Err(invalid());
        }
        let digest = self
            .fingerprint
            .strip_prefix("SHA256:")
            .ok_or_else(invalid)?;
        if digest.len() != 43 || !digest.bytes().all(base64) {
            return Err(invalid());
        }
        Ok(())
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_public_key: Option<SshPublicKeyMetadata>,
    pub status: CredentialStatus,
    /// Hard deadline for credential use, including refresh. OAuth access-token
    /// expiry is a separate provider detail inside the protected material.
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
        if self.provider.as_str() == "ssh"
            || self.authentication_kind == CredentialAuthKind::SshKey
            || self.ssh_public_key.is_some()
        {
            if self.provider.as_str() != "ssh"
                || self.authentication_kind != CredentialAuthKind::SshKey
                || self.account_hint.is_some()
            {
                return Err(AccessError::InvalidField {
                    field: "SSH credential metadata",
                });
            }
            self.ssh_public_key
                .as_ref()
                .ok_or(AccessError::InvalidField {
                    field: "SSH public key metadata",
                })?
                .validate()?;
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
        // GitHub is the account's one connection. Every personal profile
        // includes it, so a profile never pins a GitHub credential ID.
        if self.entries.contains_key(&CapabilitySlot::github()) {
            return Err(AccessError::InvalidField {
                field: "access profile GitHub entry",
            });
        }
        Ok(())
    }

    /// Every personal profile includes the owner's one GitHub connection.
    /// Organizations cannot hold one.
    pub fn includes_github(&self) -> bool {
        matches!(self.owner, Owner::User(_))
    }

    /// Every capability slot whose environment names this profile reserves:
    /// the credential entries and, for a personal profile, GitHub, connected
    /// or not. A platform selection digest binds these names for the life of
    /// an environment operation, so they never follow the mutable connection.
    pub fn reserved_slots(&self) -> impl Iterator<Item = &str> {
        self.launch_slots(true)
    }

    /// The capability slots a launch selects: the credential entries and, for
    /// a personal profile whose owner has an active GitHub connection at
    /// launch, GitHub. A missing connection is omitted, never fabricated, so a
    /// profile without one launches without the managed GitHub client.
    pub fn launch_slots(&self, github_connected: bool) -> impl Iterator<Item = &str> {
        self.entries
            .keys()
            .map(CapabilitySlot::as_str)
            .chain((github_connected && self.includes_github()).then_some("github"))
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

/// Closed HTTP destination families selected from an authenticated profile.
/// This is routing metadata, not a credential lease or authorization proof.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HttpProvider {
    OpenAiApiKey,
    CodexOAuth,
    AnthropicApiKey,
    GitHubOAuth,
    /// Isolated GitHub App user-to-server authorization only. This is never
    /// selected by a Sandbox profile or exposed as a managed client route.
    #[serde(skip)]
    GitHubAppAuthorization,
}

impl HttpProvider {
    /// Environment names owned by the selected provider's workload adapter.
    /// These are collision guards, not inference of a value's secret type.
    pub fn reserved_environment_keys(self) -> &'static [&'static str] {
        match self {
            Self::OpenAiApiKey | Self::CodexOAuth => {
                &["CODEX_HOME", "OPENAI_BASE_URL", "OPENAI_API_KEY"]
            }
            Self::AnthropicApiKey => &[
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ],
            Self::GitHubOAuth => &[
                "GH_HOST",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ],
            Self::GitHubAppAuthorization => &[],
        }
    }

    /// Fixed token for the private broker launch contract, never a hostname.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiApiKey => "openai-api-key",
            Self::CodexOAuth => "codex-oauth",
            Self::AnthropicApiKey => "anthropic-api-key",
            Self::GitHubOAuth => "github-oauth",
            Self::GitHubAppAuthorization => "github-app-authorization",
        }
    }

    /// Decode only a supported profile-selected private launch token. The
    /// GitHub App callback transport is constructed directly by the isolated
    /// credential-service and is intentionally not an externally selectable
    /// broker destination.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "openai-api-key" => Some(Self::OpenAiApiKey),
            "codex-oauth" => Some(Self::CodexOAuth),
            "anthropic-api-key" => Some(Self::AnthropicApiKey),
            "github-oauth" => Some(Self::GitHubOAuth),
            _ => None,
        }
    }

    /// Resolve only the named, supported slot/provider/form combinations.
    /// Callers separately validate owner, placement, status, revisions and expiry.
    pub fn for_credential(slot: &CapabilitySlot, credential: &CredentialMetadata) -> Option<Self> {
        match (
            slot.as_str(),
            credential.provider.as_str(),
            credential.authentication_kind,
        ) {
            ("codex" | "openai", "openai", CredentialAuthKind::ApiKey) => Some(Self::OpenAiApiKey),
            ("codex", "openai", CredentialAuthKind::OAuth) => Some(Self::CodexOAuth),
            ("anthropic", "anthropic", CredentialAuthKind::ApiKey) => Some(Self::AnthropicApiKey),
            ("github", "github", CredentialAuthKind::OAuth) => Some(Self::GitHubOAuth),
            _ => None,
        }
    }
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
