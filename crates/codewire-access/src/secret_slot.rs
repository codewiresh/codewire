//! The slot a host-bound application secret's placeholder is derived for
//! (#4003): `secret/<scope>/<collection id>/<key>`. The collection ID is the
//! opaque UUID of the set that stores the key, never a name, so a rename, or
//! sets added under a project later (#6314), changes no existing slot. A
//! [`crate::CapabilitySlot`] cannot contain `/`, so no secret slot equals a
//! provider slot.

use std::fmt;

use thiserror::Error;

const NAMESPACE: &str = "secret";
const MAX_KEY_BYTES: usize = 255;
const UUID_LENGTH: usize = 36;

/// Who a secret belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretScope {
    User,
    Organization,
    Project,
}

impl SecretScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Organization => "organization",
            Self::Project => "project",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "organization" => Some(Self::Organization),
            "project" => Some(Self::Project),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("not a secret slot")]
pub struct InvalidSecretSlot;

/// `secret/<scope>/<collection id>/<key>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretSlot {
    scope: SecretScope,
    collection: String,
    key: String,
}

impl SecretSlot {
    /// The slot for `key` in the collection `collection`, a canonical
    /// lowercase hyphenated UUID that is not nil.
    pub fn new(scope: SecretScope, collection: &str, key: &str) -> Result<Self, InvalidSecretSlot> {
        if !is_canonical_uuid(collection) || !is_secret_key(key) {
            return Err(InvalidSecretSlot);
        }
        Ok(Self {
            scope,
            collection: collection.to_owned(),
            key: key.to_owned(),
        })
    }

    /// Accept exactly the form [`fmt::Display`] writes, and nothing that
    /// parses as another namespace's slot.
    pub fn parse(value: &str) -> Result<Self, InvalidSecretSlot> {
        let mut parts = value.split('/');
        let (Some(NAMESPACE), Some(scope), Some(collection), Some(key), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(InvalidSecretSlot);
        };
        let scope = SecretScope::parse(scope).ok_or(InvalidSecretSlot)?;
        Self::new(scope, collection, key)
    }

    pub fn scope(&self) -> SecretScope {
        self.scope
    }

    pub fn collection(&self) -> &str {
        &self.collection
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for SecretSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{NAMESPACE}/{}/{}/{}",
            self.scope.as_str(),
            self.collection,
            self.key
        )
    }
}

/// The workload-secret key grammar both stores keep
/// (`codewire_workload_secrets::validate_workload_secret_key`).
fn is_secret_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    !key.is_empty()
        && key.len() <= MAX_KEY_BYTES
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == UUID_LENGTH
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value.bytes().any(|byte| byte != b'-' && byte != b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilitySlot;

    const COLLECTION: &str = "0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b";

    #[test]
    fn a_slot_round_trips_through_its_text() {
        let slot = SecretSlot::new(SecretScope::Project, COLLECTION, "FANCY_TOKEN").unwrap();
        let text = slot.to_string();
        assert_eq!(text, format!("secret/project/{COLLECTION}/FANCY_TOKEN"));
        assert_eq!(SecretSlot::parse(&text).unwrap(), slot);
    }

    #[test]
    fn parse_refuses_every_other_shape() {
        for value in [
            "anthropic",
            "codex",
            "github",
            "git_ssh",
            "bound/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b",
            "secret",
            "secret/project",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b",
            "secret/team/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/KEY",
            "secret/project/0F8A4C1E-3B2D-4E5F-8A9B-1C2D3E4F5A6B/KEY",
            "secret/project/00000000-0000-0000-0000-000000000000/KEY",
            "secret/project/myapp/KEY",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/1KEY",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/KEY/extra",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/",
            "Secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/KEY",
        ] {
            assert_eq!(SecretSlot::parse(value), Err(InvalidSecretSlot), "{value}");
        }
    }

    #[test]
    fn no_secret_slot_is_a_capability_slot() {
        for scope in [
            SecretScope::User,
            SecretScope::Organization,
            SecretScope::Project,
        ] {
            for key in ["a", "FANCY_TOKEN", "_x9"] {
                let slot = SecretSlot::new(scope, COLLECTION, key).unwrap().to_string();
                assert!(CapabilitySlot::parse(slot.clone()).is_err(), "{slot}");
            }
        }
        for slot in [
            CapabilitySlot::anthropic(),
            CapabilitySlot::codex(),
            CapabilitySlot::github(),
            CapabilitySlot::openai(),
            CapabilitySlot::git_ssh(),
        ] {
            assert!(SecretSlot::parse(slot.as_str()).is_err());
        }
    }
}
