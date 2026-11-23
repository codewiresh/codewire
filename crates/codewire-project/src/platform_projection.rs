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

/// One shipped set of reserved names: the runtime's own, and each managed
/// client slot's, GitHub's routing names included. These are the only inputs
/// to a selection digest that come from code rather than from the environment.
struct ReservedNames {
    runtime: &'static [&'static str],
    slots: [(&'static str, &'static [&'static str]); 5],
}

/// The slots' names, unchanged since claim-time binding shipped.
const SLOT_NAMES_1: [(&str, &[&str]); 5] = [
    ("codex", &["CODEX_HOME"]),
    ("openai", &["OPENAI_BASE_URL", "OPENAI_API_KEY"]),
    (
        "anthropic",
        &[
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ],
    ),
    (
        "github",
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
    ),
    ("ssh", &["SSH_AUTH_SOCK"]),
];

/// Every version of the reserved names a release has shipped, oldest first
/// (#6005). A binding captures its selection digest under the version current
/// when its Pod was bound, and the Sandbox keeps that version until its next
/// start: orchestration's bootstrap check and the credential service both
/// rebuild its selection under the version that reproduces the bound digest.
/// So a changed name is a new version appended here, never an edit to a
/// shipped one, and a version is removed only once a query shows no live
/// binding still needs it. A rollback to code without a version restarts the
/// Sandboxes bound under it, since that code cannot reproduce their digest.
const RESERVED_NAMES: [ReservedNames; 2] = [
    ReservedNames {
        runtime: &[
            "CODEWIRE_MESH_URL",
            "CODEWIRE_MESH_AUTH_TOKEN",
            "CODEWIRE_MESH_NETWORK",
            "CODEWIRE_MESH_INVITE_CODE",
            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
        ],
        slots: SLOT_NAMES_1,
    },
    // A standard Pod's hosted daemon's inherited listener (#5602).
    ReservedNames {
        runtime: &[
            "CODEWIRE_MESH_URL",
            "CODEWIRE_MESH_AUTH_TOKEN",
            "CODEWIRE_MESH_NETWORK",
            "CODEWIRE_MESH_INVITE_CODE",
            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
            "CODEWIRE_WORKSPACE_SHIM_LISTEN_FD",
        ],
        slots: SLOT_NAMES_1,
    },
];

/// One shipped version of the reserved names (#6005).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedNamesVersion(usize);

impl ReservedNamesVersion {
    /// The version every new capture uses.
    pub const CURRENT: Self = Self(RESERVED_NAMES.len() - 1);

    /// Every shipped version, newest first.
    pub fn newest_first() -> impl Iterator<Item = Self> {
        (0..RESERVED_NAMES.len()).rev().map(Self)
    }

    /// Its number, counted from 1.
    pub fn number(self) -> usize {
        self.0 + 1
    }
}

/// Runtime-owned names for exact, already-selected capability slots, as the
/// current version has them. Both platform bootstrap and the broker use this
/// rule; no credential values or key-name inference choose a provider.
pub fn platform_projection_reserved_keys<'a>(
    slots: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, PlatformProjectionSelectionError> {
    platform_projection_reserved_keys_at(ReservedNamesVersion::CURRENT, slots)
}

/// [`platform_projection_reserved_keys`] as `version` has them.
pub fn platform_projection_reserved_keys_at<'a>(
    version: ReservedNamesVersion,
    slots: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, PlatformProjectionSelectionError> {
    let mut selected = Vec::new();
    for slot in slots {
        // The closed catalog currently admits exactly these five slots. Bound
        // collection before validating via the same helper used by bootstrap.
        if selected.len() == 5 {
            return Err(PlatformProjectionSelectionError);
        }
        selected.push(slot);
    }
    codewire_access::ManagedCredentialClients::from_profile_slots(selected.iter().copied())
        .map_err(|_| PlatformProjectionSelectionError)?;
    let names = &RESERVED_NAMES[version.0];
    let mut reserved: BTreeSet<String> =
        names.runtime.iter().map(|key| (*key).to_owned()).collect();
    for (slot, keys) in names.slots {
        if selected.contains(&slot) {
            reserved.extend(keys.iter().map(|key| (*key).to_owned()));
        }
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

    /// The same selection with the reserved names `version` gives the slots
    /// its own came from. Its own must be exactly the current version's for
    /// some slots, as every capture makes them.
    pub fn at_reserved_version(
        &self,
        version: ReservedNamesVersion,
    ) -> Result<Self, PlatformProjectionSelectionError> {
        let slots: Vec<&str> = RESERVED_NAMES[ReservedNamesVersion::CURRENT.0]
            .slots
            .iter()
            .filter(|(_, keys)| keys.iter().all(|key| self.reserved_keys.contains(*key)))
            .map(|(slot, _)| *slot)
            .collect();
        if platform_projection_reserved_keys(slots.iter().copied())? != self.reserved_keys {
            return Err(PlatformProjectionSelectionError);
        }
        Ok(Self {
            reserved_keys: platform_projection_reserved_keys_at(version, slots)?,
            ..self.clone()
        })
    }

    /// The newest shipped version under which this selection's digest is
    /// `digest`, with the selection under it; `None` when none gives it.
    pub fn bound_to(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<(ReservedNamesVersion, Self)>, PlatformProjectionSelectionError> {
        for version in ReservedNamesVersion::newest_first() {
            let selection = self.at_reserved_version(version)?;
            if selection.sha256()? == *digest {
                return Ok(Some((version, selection)));
            }
        }
        Ok(None)
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

    /// The reserved names as the code derives them today, from the runtime's
    /// own names and each selected client's.
    fn reserved_names_from_code(slots: &[&str]) -> BTreeSet<String> {
        let clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
                .unwrap();
        let mut reserved: BTreeSet<String> = crate::RESERVED_RUNTIME_ENVIRONMENT_KEYS
            .into_iter()
            .chain(clients.reserved_environment_keys())
            .map(str::to_owned)
            .collect();
        if slots.contains(&"github") {
            reserved.extend(
                codewire_access::HttpProvider::GitHubOAuth
                    .reserved_environment_keys()
                    .iter()
                    .map(|key| (*key).to_owned()),
            );
        }
        reserved
    }

    fn slot_subsets() -> impl Iterator<Item = Vec<&'static str>> {
        let slots = ["codex", "openai", "anthropic", "github", "ssh"];
        (0..32).map(move |bits| {
            slots
                .iter()
                .enumerate()
                .filter(|(index, _)| bits & (1 << index) != 0)
                .map(|(_, slot)| *slot)
                .collect()
        })
    }

    #[test]
    fn the_current_reserved_names_are_the_codes() {
        for slots in slot_subsets() {
            assert_eq!(
                platform_projection_reserved_keys(slots.iter().copied()).unwrap(),
                reserved_names_from_code(&slots),
                "{slots:?}: a changed reserved name is a new version in RESERVED_NAMES (#6005)"
            );
        }
    }

    #[test]
    fn a_shipped_reserved_names_version_never_changes() {
        // Every name each version gives every subset of the slot catalog. A
        // running Sandbox's digest was computed under one of these, so a
        // change here restarts or refuses it (#6005).
        let shipped: Vec<String> = ReservedNamesVersion::newest_first()
            .map(|version| {
                let mut hash = Sha256::new();
                for slots in slot_subsets() {
                    for key in platform_projection_reserved_keys_at(version, slots).unwrap() {
                        field(&mut hash, key.as_bytes());
                    }
                    hash.update([0]);
                }
                hash.finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            })
            .collect();
        assert_eq!(
            shipped,
            [
                "70aa4d0a2e5b6e670cc367eb9aa223200df7e76689d83d76cd56a038573d7b17",
                "27584dc70eb8ae01d7bac830c16438c83d8cb6fac5ea2ae50e109575320114be",
            ]
        );
        assert_eq!(ReservedNamesVersion::CURRENT.number(), 2);
        // Version 1 is the code before #5924, which added only this name.
        let first = ReservedNamesVersion::newest_first().last().unwrap();
        for slots in slot_subsets() {
            let mut expected = platform_projection_reserved_keys(slots.iter().copied()).unwrap();
            assert!(expected.remove("CODEWIRE_WORKSPACE_SHIM_LISTEN_FD"));
            assert_eq!(
                platform_projection_reserved_keys_at(first, slots).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_selection_is_rebuilt_under_the_version_its_bound_digest_came_from() {
        let current = PlatformProjectionSelection {
            reserved_keys: platform_projection_reserved_keys(["codex", "github"]).unwrap(),
            ..selection()
        };
        let first = ReservedNamesVersion::newest_first().last().unwrap();
        let earlier = current.at_reserved_version(first).unwrap();
        let mut expected = current.reserved_keys.clone();
        expected.remove("CODEWIRE_WORKSPACE_SHIM_LISTEN_FD");
        assert_eq!(earlier.reserved_keys, expected);
        assert_ne!(earlier.sha256().unwrap(), current.sha256().unwrap());
        assert_eq!(
            current.bound_to(&earlier.sha256().unwrap()).unwrap(),
            Some((first, earlier.clone()))
        );
        assert_eq!(
            current.bound_to(&current.sha256().unwrap()).unwrap(),
            Some((ReservedNamesVersion::CURRENT, current.clone()))
        );
        // A selection change is never mistaken for an earlier version.
        let mut republished = earlier.clone();
        republished.ordinary_keys.insert("NEW".into());
        assert_eq!(
            current.bound_to(&republished.sha256().unwrap()).unwrap(),
            None
        );
        assert_eq!(current.bound_to(&[0; 32]).unwrap(), None);
        // Reserved names no version gives these slots are refused.
        assert!(selection().at_reserved_version(first).is_err());
        assert!(selection().bound_to(&[0; 32]).is_err());
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
