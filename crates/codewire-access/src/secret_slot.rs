//! The slot a host-bound application secret's placeholder is derived for
//! (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "The placeholder"):
//! `secret/<kind>/<collection id>/<key>`. The kind is the kind of set that
//! stores the key, and the collection ID is that set's stable opaque ID,
//! never a name, in one spelling per kind. So one ID string in two kinds
//! never gives one slot, and one set never has two. A set whose stored ID
//! isn't its kind's spelling has no slot. A [`crate::CapabilitySlot`] cannot
//! contain `/`, so no secret slot equals a provider slot.

use std::fmt;

use thiserror::Error;

const NAMESPACE: &str = "secret";
const MAX_KEY_BYTES: usize = 255;
const UUID_LENGTH: usize = 36;
const HEX_ID_LENGTH: usize = 32;

/// The kind of set a secret is stored in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKind {
    /// A project: its UUID, lowercase and hyphenated, not nil.
    Project,
    /// An organization's own secrets: its ID as stored, 32 lowercase hex.
    Organization,
    /// A user's personal secrets on the platform: their ID as stored, 32
    /// lowercase hex.
    User,
    /// A local VM owner's personal secrets: the local authority's ID, 32
    /// lowercase hex.
    Local,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Organization => "organization",
            Self::User => "user",
            Self::Local => "local",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "project" => Some(Self::Project),
            "organization" => Some(Self::Organization),
            "user" => Some(Self::User),
            "local" => Some(Self::Local),
            _ => None,
        }
    }

    /// Whether `collection` is this kind's one spelling of a set's ID.
    fn spells(self, collection: &str) -> bool {
        match self {
            Self::Project => is_canonical_uuid(collection),
            Self::Organization | Self::User | Self::Local => is_hex_id(collection),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("not a secret slot")]
pub struct InvalidSecretSlot;

/// `secret/<kind>/<collection id>/<key>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretSlot {
    kind: SecretKind,
    collection: String,
    key: String,
}

impl SecretSlot {
    /// The slot for `key` in the set `collection` of `kind`, refused unless
    /// `collection` is that kind's spelling.
    pub fn new(kind: SecretKind, collection: &str, key: &str) -> Result<Self, InvalidSecretSlot> {
        if !kind.spells(collection) || !is_secret_key(key) {
            return Err(InvalidSecretSlot);
        }
        Ok(Self {
            kind,
            collection: collection.to_owned(),
            key: key.to_owned(),
        })
    }

    /// Accept exactly the form [`fmt::Display`] writes, and nothing that
    /// parses as another namespace's slot.
    pub fn parse(value: &str) -> Result<Self, InvalidSecretSlot> {
        let mut parts = value.split('/');
        let (Some(NAMESPACE), Some(kind), Some(collection), Some(key), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(InvalidSecretSlot);
        };
        let kind = SecretKind::parse(kind).ok_or(InvalidSecretSlot)?;
        Self::new(kind, collection, key)
    }

    /// The slot of `key` stored at a platform tenant-secret path, by its
    /// set's kind and stable ID: an organization's own secrets
    /// (`/org-secrets/<organization>`), a project's
    /// (`/projects/<organization>/<project>`, its UUID) and a user's
    /// (`/users/<user>`). Refused for any other path, and for a set whose
    /// stored ID isn't its kind's spelling, which has no slot.
    pub fn for_platform_path(path: &str, key: &str) -> Result<Self, InvalidSecretSlot> {
        let segments: Vec<&str> = path
            .strip_prefix('/')
            .ok_or(InvalidSecretSlot)?
            .split('/')
            .collect();
        let (kind, collection) = match segments.as_slice() {
            ["org-secrets", organization] => (SecretKind::Organization, *organization),
            ["projects", _, project] => (SecretKind::Project, *project),
            ["users", user] => (SecretKind::User, *user),
            _ => return Err(InvalidSecretSlot),
        };
        Self::new(kind, collection, key)
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
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
            self.kind.as_str(),
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

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == UUID_LENGTH
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => is_lower_hex(byte),
        })
        && value.bytes().any(|byte| byte != b'-' && byte != b'0')
}

fn is_hex_id(value: &str) -> bool {
    value.len() == HEX_ID_LENGTH && value.bytes().all(is_lower_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilitySlot;

    const PROJECT: &str = "0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b";
    const HEX: &str = "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
    const KINDS: [SecretKind; 4] = [
        SecretKind::Project,
        SecretKind::Organization,
        SecretKind::User,
        SecretKind::Local,
    ];

    fn collection(kind: SecretKind) -> &'static str {
        match kind {
            SecretKind::Project => PROJECT,
            _ => HEX,
        }
    }

    #[test]
    fn a_slot_round_trips_through_its_text() {
        for kind in KINDS {
            let slot = SecretSlot::new(kind, collection(kind), "FANCY_TOKEN").unwrap();
            let text = slot.to_string();
            assert_eq!(
                text,
                format!("secret/{}/{}/FANCY_TOKEN", kind.as_str(), collection(kind))
            );
            assert_eq!(SecretSlot::parse(&text).unwrap(), slot);
        }
    }

    #[test]
    fn one_id_in_two_kinds_gives_two_slots() {
        let organization = SecretSlot::new(SecretKind::Organization, HEX, "KEY").unwrap();
        let user = SecretSlot::new(SecretKind::User, HEX, "KEY").unwrap();
        let local = SecretSlot::new(SecretKind::Local, HEX, "KEY").unwrap();
        assert_ne!(organization.to_string(), user.to_string());
        assert_ne!(user.to_string(), local.to_string());
        assert_ne!(organization.to_string(), local.to_string());
    }

    /// Each kind has one spelling: the other spelling of the same ID, an
    /// uppercase one, and a stored ID of another shape (a seeded owner such
    /// as `local-user`) have no slot.
    #[test]
    fn a_second_spelling_of_one_set_is_refused() {
        let hyphenated_hex = PROJECT;
        let bare_uuid = HEX;
        for (kind, collection) in [
            (SecretKind::Project, bare_uuid),
            (SecretKind::Project, "0F8A4C1E-3B2D-4E5F-8A9B-1C2D3E4F5A6B"),
            (SecretKind::Project, "00000000-0000-0000-0000-000000000000"),
            (SecretKind::Organization, hyphenated_hex),
            (SecretKind::Organization, "0F8A4C1E3B2D4E5F8A9B1C2D3E4F5A6B"),
            (SecretKind::User, hyphenated_hex),
            (SecretKind::User, "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6"),
            (SecretKind::User, "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6bc"),
            (SecretKind::User, "user-1"),
            (SecretKind::Local, "local-user"),
            (SecretKind::Local, hyphenated_hex),
            (SecretKind::Local, "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6g"),
        ] {
            assert_eq!(
                SecretSlot::new(kind, collection, "KEY"),
                Err(InvalidSecretSlot),
                "{kind:?} {collection}"
            );
        }
    }

    #[test]
    fn a_platform_path_gives_its_sets_kind_and_stable_id() {
        for (path, kind, collection) in [
            (format!("/org-secrets/{HEX}"), SecretKind::Organization, HEX),
            (
                format!("/projects/{HEX}/{PROJECT}"),
                SecretKind::Project,
                PROJECT,
            ),
            (format!("/users/{HEX}"), SecretKind::User, HEX),
        ] {
            assert_eq!(
                SecretSlot::for_platform_path(&path, "KEY"),
                SecretSlot::new(kind, collection, "KEY"),
                "{path}"
            );
        }
        for path in [
            "/users/synthetic-creator".to_owned(),
            "/org-secrets/bound-org".to_owned(),
            format!("/projects/{HEX}/development"),
            format!("/projects/{HEX}"),
            format!("/users/{HEX}/extra"),
            format!("users/{HEX}"),
            format!("/local/{HEX}"),
        ] {
            assert_eq!(
                SecretSlot::for_platform_path(&path, "KEY"),
                Err(InvalidSecretSlot),
                "{path}"
            );
        }
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
            "secret/scope/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b/KEY",
            "secret/project/myapp/KEY",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/1KEY",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/KEY/extra",
            "secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/",
            "secret/local/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b/",
            "Secret/project/0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b/KEY",
            "secret/Local/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b/KEY",
        ] {
            assert_eq!(SecretSlot::parse(value), Err(InvalidSecretSlot), "{value}");
        }
    }

    #[test]
    fn no_secret_slot_is_a_capability_slot() {
        for kind in KINDS {
            for key in ["a", "FANCY_TOKEN", "_x9"] {
                let slot = SecretSlot::new(kind, collection(kind), key)
                    .unwrap()
                    .to_string();
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
