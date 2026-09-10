//! Owner-only selection for a platform-backed native broker. This metadata
//! never enters the isolated child; only canonical bridge frames cross FD3.

use std::path::PathBuf;
use std::pin::Pin;

use codewire_gateway_proto::codewire::bridge::v1 as bridge;
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
}

impl PlatformCredentialBinding {
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
        };
        result.validate()?;
        Ok(result)
    }
}

/// Remaining frames AFTER the actual native guest Ready has been checked.
pub type PlatformCredentialInput =
    Pin<Box<dyn Stream<Item = Result<bridge::CredentialBridgeGuestMessage, Status>> + Send>>;
/// An admitted, output-owned connection; dropping it closes both directions.
/// It carries no private admission message or provider credential material.
pub type PlatformCredentialOutput =
    Pin<Box<dyn Stream<Item = Result<bridge::CredentialBridgeHostMessage, Status>> + Send>>;

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
