//! Material-free platform launch selection. Both trusted bootstrap and broker
//! use this exact encoding; the digest is not authentication or a generation.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::is_valid_environment_key;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformProjectionSelection {
    pub creator: String,
    pub organization: String,
    pub organization_selected: bool,
    pub project_id: Option<String>,
    pub user_selected: bool,
    pub profile: Option<(String, u64)>,
    pub ordinary_keys: BTreeSet<String>,
    pub reserved_keys: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid platform environment projection selection")]
pub struct PlatformProjectionSelectionError;

/// Runtime-owned names for exact, already-selected capability slots. Both
/// platform bootstrap and the broker use this rule; no credential values or
/// key-name inference choose a provider.
pub fn platform_projection_reserved_keys<'a>(
    slots: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, PlatformProjectionSelectionError> {
    let mut reserved = crate::RESERVED_RUNTIME_ENVIRONMENT_KEYS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut selected = Vec::new();
    for slot in slots {
        // The closed catalog currently admits exactly these five slots. Bound
        // collection before validating via the same helper used by bootstrap.
        if selected.len() == 5 {
            return Err(PlatformProjectionSelectionError);
        }
        selected.push(slot);
    }
    let clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(selected.iter().copied())
            .map_err(|_| PlatformProjectionSelectionError)?;
    reserved.extend(
        clients
            .reserved_environment_keys()
            .into_iter()
            .map(str::to_owned),
    );
    if selected.contains(&"github") {
        reserved.extend(
            codewire_access::HttpProvider::GitHubOAuth
                .reserved_environment_keys()
                .iter()
                .map(|key| (*key).to_owned()),
        );
    }
    Ok(reserved)
}

impl PlatformProjectionSelection {
    /// Exact selected scope identities in precedence order. Both the remote
    /// reader and native composer compare complete inventories to this list;
    /// these paths alone do not authorize access.
    pub fn source_identities(
        &self,
    ) -> Vec<(codewire_workload_secrets::WorkloadSecretSource, String)> {
        use codewire_workload_secrets::WorkloadSecretSource;
        let mut sources = Vec::with_capacity(3);
        if self.organization_selected {
            sources.push((
                WorkloadSecretSource::Organization,
                format!("/org-secrets/{}", self.organization),
            ));
        }
        if let Some(project) = &self.project_id {
            sources.push((
                WorkloadSecretSource::Project,
                format!("/projects/{}/{project}", self.organization),
            ));
        }
        if self.user_selected {
            sources.push((
                WorkloadSecretSource::User,
                format!("/users/{}", self.creator),
            ));
        }
        sources
    }

    /// No values, display names, bearer tokens, Pod identity or additional
    /// lifecycle counter belong in this digest. The authenticated channel and
    /// existing ProjectionContext bind environment, generation and deadline.
    pub fn sha256(&self) -> Result<[u8; 32], PlatformProjectionSelectionError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"codewire/platform-environment-projection-selection/v1\0");
        field(&mut hash, self.creator.as_bytes());
        field(&mut hash, self.organization.as_bytes());
        hash.update([u8::from(self.organization_selected)]);
        match &self.project_id {
            None => hash.update([0]),
            Some(id) => {
                hash.update([1]);
                field(&mut hash, id.as_bytes());
            }
        }
        hash.update([u8::from(self.user_selected)]);
        match &self.profile {
            None => hash.update([0]),
            Some((id, revision)) => {
                hash.update([1]);
                field(&mut hash, id.as_bytes());
                hash.update(revision.to_be_bytes());
            }
        }
        for keys in [&self.ordinary_keys, &self.reserved_keys] {
            hash.update((keys.len() as u64).to_be_bytes());
            for key in keys {
                field(&mut hash, key.as_bytes());
            }
        }
        Ok(hash.finalize().into())
    }

    pub fn validate(&self) -> Result<(), PlatformProjectionSelectionError> {
        codewire_access::OwnerId::parse(&self.creator)
            .map_err(|_| PlatformProjectionSelectionError)?;
        codewire_access::OwnerId::parse(&self.organization)
            .map_err(|_| PlatformProjectionSelectionError)?;
        if self.project_id.as_ref().is_some_and(|id| !canonical_id(id))
            || self.profile.as_ref().is_some_and(|(id, revision)| {
                !canonical_id(id) || *revision == 0 || *revision > i64::MAX as u64
            })
            || [&self.ordinary_keys, &self.reserved_keys]
                .into_iter()
                .any(|keys| {
                    keys.len() > codewire_workload_secrets::MAX_WORKLOAD_SECRETS
                        || keys.iter().any(|key| !is_valid_environment_key(key))
                })
        {
            return Err(PlatformProjectionSelectionError);
        }
        Ok(())
    }
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> PlatformProjectionSelection {
        PlatformProjectionSelection {
            creator: "creator".into(),
            organization: "organization".into(),
            organization_selected: true,
            project_id: Some("a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417".into()),
            user_selected: true,
            profile: Some(("4646bcca-54bb-4881-9109-2f9c43da021a".into(), 7)),
            ordinary_keys: ["Z", "A"].map(str::to_owned).into(),
            reserved_keys: ["CODEX_HOME".into()].into(),
        }
    }

    #[test]
    fn platform_reserved_names_are_exactly_the_selected_slots_and_runtime_keys() {
        let runtime: BTreeSet<String> = crate::RESERVED_RUNTIME_ENVIRONMENT_KEYS
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(platform_projection_reserved_keys([]).unwrap(), runtime);
        // The managed GitHub client also owns the git config that routes
        // workspace git through it.
        let github: Vec<&str> = codewire_access::HttpProvider::GitHubOAuth
            .reserved_environment_keys()
            .iter()
            .copied()
            .chain(["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"])
            .collect();
        for (slot, keys) in [
            ("codex", &["CODEX_HOME"][..]),
            ("openai", &["OPENAI_BASE_URL", "OPENAI_API_KEY"][..]),
            (
                "anthropic",
                codewire_access::HttpProvider::AnthropicApiKey.reserved_environment_keys(),
            ),
            ("github", &github[..]),
            ("ssh", &["SSH_AUTH_SOCK"][..]),
        ] {
            let mut expected = runtime.clone();
            expected.extend(keys.iter().map(|key| (*key).to_owned()));
            assert_eq!(platform_projection_reserved_keys([slot]).unwrap(), expected);
        }
        assert!(platform_projection_reserved_keys(["github", "github"]).is_err());
        assert!(platform_projection_reserved_keys(["unregistered"]).is_err());
        assert_eq!(
            platform_projection_reserved_keys(["codex", "github"]).unwrap(),
            platform_projection_reserved_keys(["github", "codex"]).unwrap()
        );
    }

    #[test]
    fn platform_reserved_names_cover_all_selected_slots_and_distinct_api_key_clients() {
        let slots = ["codex", "openai", "anthropic", "github", "ssh"];
        let keys: [&[&str]; 5] = [
            &["CODEX_HOME"],
            &["OPENAI_BASE_URL", "OPENAI_API_KEY"],
            &[
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ],
            &[
                "GH_HOST",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            ],
            &["SSH_AUTH_SOCK"],
        ];
        for bits in 0..32 {
            let mut expected: BTreeSet<_> = crate::RESERVED_RUNTIME_ENVIRONMENT_KEYS
                .into_iter()
                .map(str::to_owned)
                .collect();
            let selected: Vec<_> = slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| {
                    if bits & (1 << index) == 0 {
                        return None;
                    }
                    expected.extend(keys[index].iter().map(|key| (*key).to_owned()));
                    Some(*slot)
                })
                .collect();
            assert_eq!(
                platform_projection_reserved_keys(selected).unwrap(),
                expected,
                "subset {bits}"
            );
        }
        for slot in slots {
            assert!(platform_projection_reserved_keys([slot, slot]).is_err());
        }
        assert!(
            platform_projection_reserved_keys([
                "codex",
                "openai",
                "anthropic",
                "github",
                "ssh",
                "extra"
            ])
            .is_err()
        );
        assert!(platform_projection_reserved_keys(["CODEX_HOME"]).is_err());
        assert!(platform_projection_reserved_keys(["openai-api-key"]).is_err());
    }

    #[test]
    fn platform_selection_digest_is_order_independent_and_binds_every_field() {
        let original = selection();
        let digest = original.sha256().unwrap();
        assert_eq!(
            digest.map(|byte| format!("{byte:02x}")).join(""),
            "3797f986452fd928ac76043ce935ab067c01f8b62286fe7c3051d3707af3c6f5"
        );
        let mut reordered = original.clone();
        reordered.ordinary_keys = ["A", "Z"].map(str::to_owned).into();
        assert_eq!(digest, reordered.sha256().unwrap());
        for index in 0..9 {
            let mut changed = original.clone();
            match index {
                0 => changed.creator.push('a'),
                1 => changed.organization.push('a'),
                2 => changed.organization_selected = false,
                3 => changed.project_id = None,
                4 => changed.user_selected = false,
                5 => changed.profile = None,
                6 => changed.profile.as_mut().unwrap().1 += 1,
                7 => {
                    changed.ordinary_keys.insert("B".into());
                }
                _ => {
                    changed.reserved_keys.insert("OPENAI_BASE_URL".into());
                }
            }
            assert_ne!(digest, changed.sha256().unwrap(), "field {index}");
        }
    }

    #[test]
    fn platform_selection_rejects_noncanonical_ids_and_unbounded_keys() {
        for index in 0..6 {
            let mut invalid = selection();
            match index {
                0 => invalid.creator = "../creator".into(),
                1 => invalid.project_id = Some("local:project".into()),
                2 => invalid.profile.as_mut().unwrap().1 = 0,
                3 => invalid.project_id = Some(uuid::Uuid::nil().to_string()),
                4 => {
                    invalid.ordinary_keys.insert("not-a-key".into());
                }
                _ => invalid.reserved_keys = (0..257).map(|n| format!("KEY_{n}")).collect(),
            }
            assert!(invalid.sha256().is_err(), "field {index}");
        }
    }
}
