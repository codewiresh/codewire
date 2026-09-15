//! Pinned platform source authority metadata and its canonical codec.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::control::v1;

use super::super::SupervisorError;
use super::valid_identity;

/// Pinned platform authority, not a cached credential or delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlatformSourceAuthority {
    pub(super) server_url: String,
    pub(super) organization_id: String,
    pub(super) user_id: String,
    #[serde(with = "canonical_profile_slots")]
    pub(super) profile_slots: BTreeSet<String>,
}

impl PlatformSourceAuthority {
    pub(in crate::supervisor) fn from_proto(
        value: &v1::PlatformSourceAuthority,
    ) -> Result<Self, SupervisorError> {
        let profile_slots = value.profile_slots.iter().cloned().collect::<BTreeSet<_>>();
        if profile_slots.len() != value.profile_slots.len()
            || value
                .profile_slots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(SupervisorError::InvalidRequest);
        }
        let result = Self {
            server_url: value.server_url.clone(),
            organization_id: value.organization_id.clone(),
            user_id: value.user_id.clone(),
            profile_slots,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn validate(&self) -> Result<(), SupervisorError> {
        let server =
            url::Url::parse(&self.server_url).map_err(|_| SupervisorError::InvalidRequest)?;
        if self.server_url.len() > 2048
            || !matches!(server.scheme(), "https" | "http")
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.password().is_some()
            || server.query().is_some()
            || server.fragment().is_some()
            || !matches!(server.path(), "" | "/")
            || !valid_identity(&self.organization_id)
            || !valid_identity(&self.user_id)
            || codewire_access::ManagedCredentialClients::from_profile_slots(
                self.profile_slots.iter().map(String::as_str),
            )
            .is_err()
        {
            return Err(SupervisorError::InvalidRequest);
        }
        Ok(())
    }

    pub(in crate::supervisor) fn proto(&self) -> v1::PlatformSourceAuthority {
        v1::PlatformSourceAuthority {
            server_url: self.server_url.clone(),
            organization_id: self.organization_id.clone(),
            user_id: self.user_id.clone(),
            profile_slots: self.profile_slots.iter().cloned().collect(),
        }
    }
}

mod canonical_profile_slots {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S>(slots: &BTreeSet<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        slots.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(D::Error::custom(
                "platform profile slots must be unique and sorted",
            ));
        }
        Ok(values.into_iter().collect())
    }
}

#[cfg(test)]
mod tests;
