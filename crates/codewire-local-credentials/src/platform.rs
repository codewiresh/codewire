//! Owner-only selection for a platform-backed native broker. This metadata
//! never enters the isolated child; only canonical bridge frames cross FD3.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::pin::Pin;

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, PlatformBootBinding, PlatformBootRecord,
    PlatformBootSecret,
};
use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use codewire_project::PlatformProjectionSelection;
use futures::{Stream, future::BoxFuture};
use tokio::time::Instant;
use tonic::Status;

use crate::control::v1;

/// The supervisor supplies its explicitly configured directory, not ambient
/// process configuration. The connector must verify the saved origin and
/// original OAuth owner before using this immutable source selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformCredentialBinding {
    pub config_directory: PathBuf,
    pub server_url: String,
    pub selection: PlatformProjectionSelection,
    pub selection_sha256: [u8; 32],
    /// Whether this boot's broker serves a front-door session (#4909): its
    /// boot carries a front-door pairing secret. The delegation then asks the
    /// platform for one, and the logins it delivers are placeholders. Set by
    /// the authority from the boot, never carried on the wire.
    pub front_door: bool,
    /// The boot's sealed record of its platform sources' bound secrets
    /// (#4003), from its runner: its delegation's Open carries it back.
    /// `None` for a boot that has none.
    pub boot_record: Option<PlatformBootRecord>,
}

impl PlatformCredentialBinding {
    /// Bind what the authority takes from this boot, never from the wire: the
    /// keys reserved across the boot's sources, and whether its broker serves
    /// a front-door session (#4909).
    pub(crate) fn bind_boot(
        &mut self,
        reserved_keys: BTreeSet<String>,
        boot_secrets: &crate::BrokerBootSecrets,
    ) {
        self.selection.reserved_keys = reserved_keys;
        self.front_door = boot_secrets
            .get(crate::BootSecretPurpose::FrontDoorPairing)
            .is_some();
    }

    pub(crate) fn validate_local_projection(
        &self,
        local: &crate::LocalEnvironmentProjectionBinding,
    ) -> Result<(), Status> {
        local
            .validate()
            .map_err(|_| Status::invalid_argument("invalid local projection"))?;
        if local.selection_sha256 != self.selection_sha256
            || local.selection.overridden_keys != self.selection.ordinary_keys
            || local.selection.reserved_keys != self.selection.reserved_keys
            || (local.selection.project_id.is_none() && !local.selection.user)
            || (local.selection.project_id.is_some() && self.selection.project_id.is_some())
            || (local.selection.user && self.selection.user_selected)
        {
            return Err(Status::invalid_argument(
                "inconsistent projection source selection",
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Status> {
        let invalid = || Status::invalid_argument("invalid native platform credential binding");
        let origin = url::Url::parse(&self.server_url).map_err(|_| invalid())?;
        if !self.config_directory.is_absolute()
            || self.config_directory.parent().is_none()
            || self
                .config_directory
                .to_str()
                .is_none_or(|path| path.len() > 4096)
            || self.server_url.len() > 2048
            || !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !matches!(origin.path(), "" | "/")
            || self.selection_sha256 == [0; 32]
            || (self.selection.profile.is_none()
                && self.selection.project_id.is_none()
                && !self.selection.user_selected
                && !self.selection.organization_selected)
        {
            return Err(invalid());
        }
        self.selection.validate().map_err(|_| invalid())
    }

    pub(crate) fn into_proto(self) -> v1::PlatformCredentialBinding {
        let (profile_id, profile_revision) = self.selection.profile.unwrap_or_default();
        v1::PlatformCredentialBinding {
            config_directory: self.config_directory.to_string_lossy().into_owned(),
            server_url: self.server_url,
            owner_id: self.selection.creator,
            organization_id: self.selection.organization,
            organization_secrets: self.selection.organization_selected,
            project_id: self.selection.project_id,
            user_secrets: self.selection.user_selected,
            profile_id,
            profile_revision,
            ordinary_keys: self.selection.ordinary_keys.into_iter().collect(),
            reserved_keys: self.selection.reserved_keys.into_iter().collect(),
            selection_sha256: self.selection_sha256.to_vec(),
            boot_record: self.boot_record.map(boot_record_to_proto),
        }
    }

    pub(crate) fn from_proto(value: v1::PlatformCredentialBinding) -> Result<Self, Status> {
        let invalid = || Status::invalid_argument("invalid native platform credential binding");
        let names = |keys: Vec<String>| {
            let count = keys.len();
            let unique: std::collections::BTreeSet<_> = keys.into_iter().collect();
            if unique.len() != count {
                return Err(invalid());
            }
            Ok(unique)
        };
        let profile = match (value.profile_id.is_empty(), value.profile_revision) {
            (true, 0) => None,
            (false, revision) if revision > 0 => Some((value.profile_id, revision)),
            _ => return Err(invalid()),
        };
        let result = Self {
            config_directory: value.config_directory.into(),
            server_url: value.server_url,
            selection: PlatformProjectionSelection {
                creator: value.owner_id,
                organization: value.organization_id,
                organization_selected: value.organization_secrets,
                project_id: value.project_id,
                user_selected: value.user_secrets,
                profile,
                ordinary_keys: names(value.ordinary_keys)?,
                reserved_keys: names(value.reserved_keys)?,
            },
            selection_sha256: value.selection_sha256.try_into().map_err(|_| invalid())?,
            front_door: false,
            boot_record: value.boot_record.map(boot_record_from_proto),
        };
        result.validate()?;
        Ok(result)
    }
}

/// A boot's platform record on the authority's wire.
pub(crate) fn boot_record_to_proto(record: PlatformBootRecord) -> v1::PlatformBootRecord {
    v1::PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| v1::PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.map(|bound| v1::PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    }
}

/// A boot's platform record read back from the authority's wire. Its hosts
/// are checked where they are bound; its seal by the platform.
pub(crate) fn boot_record_from_proto(record: v1::PlatformBootRecord) -> PlatformBootRecord {
    PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.map(|bound| PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    }
}

/// Remaining frames AFTER the actual native guest Ready has been checked.
pub type PlatformCredentialInput =
    Pin<Box<dyn Stream<Item = Result<bridge::CredentialBridgeGuestMessage, Status>> + Send>>;
/// An admitted, output-owned connection; dropping it closes both directions.
/// It carries no private admission message or provider credential material.
pub type PlatformCredentialOutput =
    Pin<Box<dyn Stream<Item = Result<bridge::CredentialBridgeHostMessage, Status>> + Send>>;

/// Joins one admitted delegation's front door (#4909). The connector that
/// admitted the delegation keeps the epoch's handle inside the joiner;
/// nothing a join returns carries it, so it never leaves the authority.
pub trait PlatformFrontDoorJoiner: Send + Sync + 'static {
    /// Join with the epoch's own `ready` first; returns the front-door
    /// operations the join's admission names, and its output.
    fn join(
        &self,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<(Vec<String>, PlatformCredentialOutput), Status>>;
}

/// An admitted delegation's output, and its front-door joiner when the
/// platform offered one.
pub type PlatformCredentialConnection = (
    PlatformCredentialOutput,
    Option<std::sync::Arc<dyn PlatformFrontDoorJoiner>>,
);

/// CLI-owned authentication adapter injected into the existing authority. The
/// returned future must cover configuration, OAuth and exact public admission
/// under `deadline`. It may return only after the public selection echo; the
/// returned stream owns the input and upstream RPC, without a detached driver.
/// Errors must be value-blind. Drop/cancellation is NOT remote worker drain.
pub trait PlatformCredentialConnector: Send + Sync + 'static {
    fn connect(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialOutput, Status>>;

    /// [`Self::connect`], and also the delegation's front-door joiner when
    /// the platform offered one (#4909). The default offers none, so the
    /// boot's logins stay refused under interception.
    fn connect_joinable(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialConnection, Status>> {
        let connecting = self.connect(binding, ready, input, deadline);
        Box::pin(async move { Ok((connecting.await?, None)) })
    }

    /// Whether the selection's creator has an active, unexpired GitHub
    /// connection on the platform now, authenticated as that creator under
    /// `deadline`. Material-free: it reads credential metadata, never a token
    /// or provider material. A local VM configures its guest for GitHub at a
    /// start exactly when this holds, as a hosted Sandbox does at its start.
    /// A connector that cannot answer reports unavailable.
    fn github_connected(
        &self,
        _binding: PlatformCredentialBinding,
        _deadline: Instant,
    ) -> BoxFuture<'static, Result<bool, Status>> {
        Box::pin(async {
            Err(Status::unavailable(
                "platform GitHub connection state is unavailable",
            ))
        })
    }

    /// The seed placeholders of a boot whose credentials come from the
    /// platform (#4001): for each of `slots` the selection's profile grants,
    /// the placeholder that boot's delegation leases will carry, asked of the
    /// platform as the selection's creator under `deadline`.
    /// `environment_id` and `environment_generation` are the ones the boot's
    /// bridge Ready will carry, and the selection is sent exactly as the
    /// delegation's Open sends it. Only requested slots are answered, each at
    /// most once. A connector that cannot ask reports unavailable.
    fn environment_credential_placeholders(
        &self,
        _binding: PlatformCredentialBinding,
        _environment_id: String,
        _environment_generation: u64,
        _slots: Vec<CapabilitySlot>,
        _deadline: Instant,
    ) -> BoxFuture<'static, Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status>> {
        Box::pin(async {
            Err(Status::unavailable(
                "platform credential placeholders are unavailable",
            ))
        })
    }

    /// The sealed record of a platform boot's platform sources' bound
    /// secrets (#4003), asked of the platform as the selection's creator
    /// under `deadline`, with the selection sent exactly as the delegation's
    /// Open sends it, and no record. `None` when the platform keeps no
    /// record, as one that predates it or has no seal key answers. The
    /// default keeps none.
    fn environment_bound_secrets(
        &self,
        _binding: PlatformCredentialBinding,
        _environment_id: String,
        _environment_generation: u64,
        _deadline: Instant,
    ) -> BoxFuture<'static, Result<Option<PlatformBootRecord>, Status>> {
        Box::pin(async { Ok(None) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> PlatformCredentialBinding {
        PlatformCredentialBinding {
            config_directory: PathBuf::from("/synthetic/config"),
            server_url: "https://platform.invalid".into(),
            selection: PlatformProjectionSelection {
                creator: "synthetic-owner".into(),
                organization: "synthetic-org".into(),
                organization_selected: false,
                project_id: None,
                user_selected: true,
                profile: None,
                ordinary_keys: ["APP_MODE".into()].into(),
                reserved_keys: ["CODEX_HOME".into()].into(),
            },
            selection_sha256: [11; 32],
            front_door: false,
            boot_record: None,
        }
    }

    #[test]
    fn owner_binding_round_trips_without_provider_material_or_ambient_defaults() {
        let mut expected = binding();
        assert_eq!(
            PlatformCredentialBinding::from_proto(expected.clone().into_proto()).unwrap(),
            expected
        );
        expected.selection.profile = Some((uuid::Uuid::new_v4().to_string(), 3));
        expected.selection.project_id = Some(uuid::Uuid::new_v4().to_string());
        expected.selection.organization_selected = true;
        assert_eq!(
            PlatformCredentialBinding::from_proto(expected.clone().into_proto()).unwrap(),
            expected
        );
        // The boot's sealed platform record rides the binding unchanged.
        expected.boot_record = Some(PlatformBootRecord {
            secrets: vec![PlatformBootSecret {
                path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                key: "FANCY_TOKEN".into(),
                binding_generation: 2,
                bound: Some(PlatformBootBinding {
                    binding_id: uuid::Uuid::new_v4().to_string(),
                    prefix: Some("ft_".into()),
                    hosts: vec!["api.fancy.example".into()],
                }),
            }],
            seal: "vault:v1:synthetic".into(),
        });
        assert_eq!(
            PlatformCredentialBinding::from_proto(expected.clone().into_proto()).unwrap(),
            expected
        );
    }

    #[test]
    fn wire_rejects_duplicate_names_partial_profiles_and_invalid_hashes() {
        let original = binding().into_proto();
        let mut invalid = original.clone();
        invalid.ordinary_keys.push(invalid.ordinary_keys[0].clone());
        assert!(PlatformCredentialBinding::from_proto(invalid).is_err());
        let mut invalid = original.clone();
        invalid.reserved_keys.push(invalid.reserved_keys[0].clone());
        assert!(PlatformCredentialBinding::from_proto(invalid).is_err());
        for (profile, revision) in [
            ("".into(), 3),
            (uuid::Uuid::new_v4().to_string(), 0),
            ("not-a-uuid".into(), 2),
        ] {
            let mut invalid = original.clone();
            invalid.profile_id = profile;
            invalid.profile_revision = revision;
            assert!(PlatformCredentialBinding::from_proto(invalid).is_err());
        }
        for hash in [vec![], vec![0; 32], vec![1; 31], vec![1; 33]] {
            let mut invalid = original.clone();
            invalid.selection_sha256 = hash;
            assert!(PlatformCredentialBinding::from_proto(invalid).is_err());
        }
    }

    #[test]
    fn only_explicit_bounded_origins_and_directories_can_select_platform_sources() {
        for origin in [
            "file:///config",
            "https://owner@platform.invalid",
            "https://platform.invalid/api",
            "https://platform.invalid?token=x",
            "https://platform.invalid#x",
        ] {
            let mut invalid = binding();
            invalid.server_url = origin.into();
            assert!(invalid.validate().is_err(), "{origin}");
        }
        for directory in ["/", "relative/config", ""] {
            let mut invalid = binding();
            invalid.config_directory = directory.into();
            assert!(invalid.validate().is_err());
        }
        let mut invalid = binding();
        invalid.selection.user_selected = false;
        assert!(invalid.validate().is_err());
        let mut invalid = binding();
        invalid.selection.ordinary_keys = (0..=codewire_workload_secrets::MAX_WORKLOAD_SECRETS)
            .map(|i| format!("KEY_{i}"))
            .collect();
        assert!(invalid.validate().is_err());
    }
}
