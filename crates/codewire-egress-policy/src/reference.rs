//! Network policy references, with the same origin rules as secret projects
//! and credential profiles (#2537).
//!
//! `local:NAME` and `platform:NAME` name the store; a bare name must be unique
//! across the stores a placement may use; `local:id:UUID` and
//! `platform:id:UUID` are the exact form an environment binds. A bare `open`
//! or `locked` is the built-in. Syntax lives here; resolution takes the
//! candidates an authenticated store adapter listed, so a bare name never
//! silently chooses a store.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::builtin::{BuiltinPolicy, is_reserved_policy_name};

/// The longest reference accepted, as for other store selections.
pub const MAX_POLICY_REFERENCE_BYTES: usize = 1024;
/// The longest policy name, the library's identifier ceiling.
pub const MAX_POLICY_NAME_BYTES: usize = 64;

/// The store a policy lives in, independent of where an environment runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyStore {
    Local,
    Platform,
}

impl PolicyStore {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Platform => "platform",
        }
    }
}

/// Where the environment selecting a policy runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyPlacement {
    /// A local VM: either store.
    Local,
    /// A hosted Sandbox: the platform store only.
    Hosted,
}

impl PolicyPlacement {
    pub const fn accepts(self, store: PolicyStore) -> bool {
        match self {
            Self::Local => true,
            Self::Hosted => matches!(store, PolicyStore::Platform),
        }
    }
}

/// A stored policy's name: lowercase ASCII letters and digits, with `-`, `_`
/// or `.` inside, at most [`MAX_POLICY_NAME_BYTES`], never a built-in's name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyName(String);

impl PolicyName {
    pub fn parse(value: &str) -> Result<Self, PolicyReferenceError> {
        let edge = |byte: Option<u8>| {
            byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        };
        if value.len() > MAX_POLICY_NAME_BYTES
            || !edge(value.bytes().next())
            || !edge(value.bytes().last())
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(PolicyReferenceError::InvalidName);
        }
        if is_reserved_policy_name(value) {
            return Err(PolicyReferenceError::ReservedName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A stored policy's identifier: a canonical, lowercase, non-nil UUID.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn parse(value: &str) -> Result<Self, PolicyReferenceError> {
        let canonical = value.len() == 36
            && value != "00000000-0000-0000-0000-000000000000"
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                }
            });
        if !canonical {
            return Err(PolicyReferenceError::Invalid);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One parsed selection, before resolution.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PolicyReference {
    /// A bare `open` or `locked`.
    Builtin(BuiltinPolicy),
    /// `NAME`, `local:NAME` or `platform:NAME`.
    Name {
        store: Option<PolicyStore>,
        name: PolicyName,
    },
    /// `local:id:UUID` or `platform:id:UUID`.
    Id { store: PolicyStore, id: PolicyId },
}

impl PolicyReference {
    pub fn parse(value: &str) -> Result<Self, PolicyReferenceError> {
        if value.is_empty()
            || value.len() > MAX_POLICY_REFERENCE_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(PolicyReferenceError::Invalid);
        }
        let (store, selector) = if let Some(selector) = value.strip_prefix("local:") {
            (Some(PolicyStore::Local), selector)
        } else if let Some(selector) = value.strip_prefix("platform:") {
            (Some(PolicyStore::Platform), selector)
        } else {
            (None, value)
        };
        if let Some(id) = selector.strip_prefix("id:") {
            let store = store.ok_or(PolicyReferenceError::Invalid)?;
            return Ok(Self::Id {
                store,
                id: PolicyId::parse(id)?,
            });
        }
        if let Some(builtin) = BuiltinPolicy::from_name(selector) {
            return match store {
                None => Ok(Self::Builtin(builtin)),
                Some(_) => Err(PolicyReferenceError::QualifiedBuiltin(builtin)),
            };
        }
        let name = PolicyName::parse(selector).map_err(|error| match error {
            PolicyReferenceError::InvalidName => PolicyReferenceError::Invalid,
            other => other,
        })?;
        Ok(Self::Name { store, name })
    }

    /// The store the reference names, if it names one.
    pub fn store(&self) -> Option<PolicyStore> {
        match self {
            Self::Builtin(_) => None,
            Self::Name { store, .. } => *store,
            Self::Id { store, .. } => Some(*store),
        }
    }

    /// Refuse a reference the placement cannot use before any store I/O: a
    /// hosted Sandbox never selects `local:`.
    pub fn check_placement(&self, placement: PolicyPlacement) -> Result<(), PolicyReferenceError> {
        match self.store() {
            Some(store) if !placement.accepts(store) => Err(PolicyReferenceError::LocalOnHosted),
            _ => Ok(()),
        }
    }

    /// Resolve against the policies the eligible stores listed. Candidates
    /// from a store the placement cannot use are ignored, and a name must
    /// match exactly one remaining candidate.
    pub fn resolve<'a>(
        &self,
        placement: PolicyPlacement,
        candidates: impl IntoIterator<Item = &'a PolicyCandidate>,
    ) -> Result<ResolvedPolicy, PolicyReferenceError> {
        self.check_placement(placement)?;
        if let Self::Builtin(builtin) = self {
            return Ok(ResolvedPolicy::Builtin(*builtin));
        }
        let mut matches = candidates.into_iter().filter(|candidate| {
            placement.accepts(candidate.store)
                && self.store().is_none_or(|store| store == candidate.store)
                && match self {
                    Self::Builtin(_) => false,
                    Self::Name { name, .. } => candidate.name == *name,
                    Self::Id { id, .. } => candidate.id == *id,
                }
        });
        let selected = matches.next().ok_or(PolicyReferenceError::NotFound)?;
        if matches.next().is_some() {
            return Err(PolicyReferenceError::Ambiguous);
        }
        Ok(ResolvedPolicy::Stored {
            store: selected.store,
            id: selected.id.clone(),
        })
    }
}

impl FromStr for PolicyReference {
    type Err = PolicyReferenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for PolicyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(builtin) => formatter.write_str(builtin.name()),
            Self::Name { store: None, name } => formatter.write_str(name.as_str()),
            Self::Name {
                store: Some(store),
                name,
            } => write!(formatter, "{}:{name}", store.prefix()),
            Self::Id { store, id } => write!(formatter, "{}:id:{id}", store.prefix()),
        }
    }
}

/// One policy a store adapter listed for resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCandidate {
    pub store: PolicyStore,
    pub id: PolicyId,
    pub name: PolicyName,
}

/// What an environment binds: a built-in, or one stored policy by exact id,
/// never a display name alone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedPolicy {
    Builtin(BuiltinPolicy),
    Stored { store: PolicyStore, id: PolicyId },
}

impl ResolvedPolicy {
    /// The exact reference that selects this policy again.
    pub fn reference(&self) -> PolicyReference {
        match self {
            Self::Builtin(builtin) => PolicyReference::Builtin(*builtin),
            Self::Stored { store, id } => PolicyReference::Id {
                store: *store,
                id: id.clone(),
            },
        }
    }
}

impl fmt::Display for ResolvedPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reference().fmt(formatter)
    }
}

/// Errors never repeat the input, which may be anything a caller passed.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyReferenceError {
    #[error(
        "invalid network policy reference: expected a name or exact id, optionally qualified with local: or platform:"
    )]
    Invalid,
    #[error(
        "invalid network policy name: use lowercase letters, digits, '-', '_' or '.', starting and ending with a letter or digit, at most 64 bytes"
    )]
    InvalidName,
    #[error("network policy names open and locked are reserved for the built-in policies")]
    ReservedName,
    #[error("{0} is a built-in network policy; select it without local: or platform:")]
    QualifiedBuiltin(BuiltinPolicy),
    #[error(
        "the network policy reference is local-only and is not supported by platform placement"
    )]
    LocalOnHosted,
    #[error("network policy was not found in the eligible stores")]
    NotFound,
    #[error(
        "network policy name or ID is ambiguous; qualify it with local: or platform: and, if needed, an exact id:"
    )]
    Ambiguous,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_ID: &str = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
    const PLATFORM_ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn parse(value: &str) -> PolicyReference {
        PolicyReference::parse(value).unwrap()
    }

    fn name(value: &str) -> PolicyName {
        PolicyName::parse(value).unwrap()
    }

    fn id(value: &str) -> PolicyId {
        PolicyId::parse(value).unwrap()
    }

    #[test]
    fn references_name_a_store_an_exact_id_or_a_builtin() {
        for (value, expected) in [
            (
                "work",
                PolicyReference::Name {
                    store: None,
                    name: name("work"),
                },
            ),
            (
                "local:work",
                PolicyReference::Name {
                    store: Some(PolicyStore::Local),
                    name: name("work"),
                },
            ),
            (
                "platform:team.web_2",
                PolicyReference::Name {
                    store: Some(PolicyStore::Platform),
                    name: name("team.web_2"),
                },
            ),
            (
                &format!("local:id:{LOCAL_ID}"),
                PolicyReference::Id {
                    store: PolicyStore::Local,
                    id: id(LOCAL_ID),
                },
            ),
            (
                &format!("platform:id:{PLATFORM_ID}"),
                PolicyReference::Id {
                    store: PolicyStore::Platform,
                    id: id(PLATFORM_ID),
                },
            ),
            ("open", PolicyReference::Builtin(BuiltinPolicy::Open)),
            ("locked", PolicyReference::Builtin(BuiltinPolicy::Locked)),
        ] {
            let parsed = parse(value);
            assert_eq!(parsed, expected, "{value}");
            assert_eq!(parsed.to_string(), value);
            assert_eq!(value.parse::<PolicyReference>().unwrap(), parsed);
        }
    }

    #[test]
    fn invalid_references_fail_without_reflecting_input() {
        let long = "a".repeat(MAX_POLICY_NAME_BYTES + 1);
        let huge = "a".repeat(MAX_POLICY_REFERENCE_BYTES + 1);
        for value in [
            "",
            "local:",
            "platform:",
            "local: work",
            "platform:work ",
            " work",
            "Work",
            "unknown:work",
            "platform:local:work",
            "local:id:",
            "id:6bf8d155-e84c-4fc5-b479-b17022fe41dd",
            "local:id:not-a-uuid",
            "local:id:00000000-0000-0000-0000-000000000000",
            "platform:id:6BF8D155-E84C-4FC5-B479-B17022FE41DD",
            "platform:id:6bf8d155e84c4fc5b479b17022fe41dd",
            "work\n",
            "user/work",
            "work@7",
            "-work",
            "work-",
            "credential-canary.example/",
            long.as_str(),
            huge.as_str(),
        ] {
            let error = PolicyReference::parse(value).unwrap_err();
            assert_eq!(error, PolicyReferenceError::Invalid, "{value:?}");
            assert!(!error.to_string().contains("canary"));
        }
    }

    #[test]
    fn builtins_are_bare_and_their_names_are_reserved() {
        for (value, builtin) in [
            ("local:open", BuiltinPolicy::Open),
            ("platform:open", BuiltinPolicy::Open),
            ("local:locked", BuiltinPolicy::Locked),
            ("platform:locked", BuiltinPolicy::Locked),
        ] {
            let error = PolicyReference::parse(value).unwrap_err();
            assert_eq!(error, PolicyReferenceError::QualifiedBuiltin(builtin));
            assert_eq!(
                error.to_string(),
                format!(
                    "{} is a built-in network policy; select it without local: or platform:",
                    builtin.name()
                )
            );
        }
        for reserved in ["open", "locked"] {
            assert_eq!(
                PolicyName::parse(reserved),
                Err(PolicyReferenceError::ReservedName)
            );
        }
        // hosted-default is no built-in here: locally it is an ordinary name,
        // which only the platform store reserves (#4000).
        assert_eq!(name("hosted-default").as_str(), "hosted-default");
        assert_eq!(
            PolicyName::parse("Open"),
            Err(PolicyReferenceError::InvalidName)
        );
        assert_eq!(name("opened").as_str(), "opened");
        assert_eq!(
            PolicyName::parse(&"a".repeat(MAX_POLICY_NAME_BYTES))
                .unwrap()
                .as_str()
                .len(),
            MAX_POLICY_NAME_BYTES
        );
    }

    #[test]
    fn a_hosted_placement_refuses_local_references() {
        for value in ["local:work".to_owned(), format!("local:id:{LOCAL_ID}")] {
            let reference = parse(&value);
            assert_eq!(
                reference.check_placement(PolicyPlacement::Hosted),
                Err(PolicyReferenceError::LocalOnHosted)
            );
            assert_eq!(
                reference.resolve(PolicyPlacement::Hosted, &[]),
                Err(PolicyReferenceError::LocalOnHosted)
            );
            assert_eq!(reference.check_placement(PolicyPlacement::Local), Ok(()));
        }
        for value in ["work", "platform:work", "open", "locked"] {
            assert_eq!(
                parse(value).check_placement(PolicyPlacement::Hosted),
                Ok(())
            );
        }
        assert_eq!(
            PolicyReferenceError::LocalOnHosted.to_string(),
            "the network policy reference is local-only and is not supported by platform placement"
        );
    }

    #[test]
    fn resolution_binds_one_exact_policy_or_explains_why_not() {
        let candidates = [
            PolicyCandidate {
                store: PolicyStore::Local,
                id: id(LOCAL_ID),
                name: name("work"),
            },
            PolicyCandidate {
                store: PolicyStore::Platform,
                id: id(PLATFORM_ID),
                name: name("work"),
            },
            PolicyCandidate {
                store: PolicyStore::Platform,
                id: id(OTHER_ID),
                name: name("other"),
            },
        ];
        let local = ResolvedPolicy::Stored {
            store: PolicyStore::Local,
            id: id(LOCAL_ID),
        };
        let platform = ResolvedPolicy::Stored {
            store: PolicyStore::Platform,
            id: id(PLATFORM_ID),
        };

        let ambiguous = parse("work")
            .resolve(PolicyPlacement::Local, &candidates)
            .unwrap_err();
        assert_eq!(ambiguous, PolicyReferenceError::Ambiguous);
        assert_eq!(
            ambiguous.to_string(),
            "network policy name or ID is ambiguous; qualify it with local: or platform: and, if needed, an exact id:"
        );
        // A hosted Sandbox never sees the local store, so the name is unique.
        assert_eq!(
            parse("work").resolve(PolicyPlacement::Hosted, &candidates),
            Ok(platform.clone())
        );
        assert_eq!(
            parse("local:work").resolve(PolicyPlacement::Local, &candidates),
            Ok(local.clone())
        );
        assert_eq!(
            parse("platform:work").resolve(PolicyPlacement::Local, &candidates),
            Ok(platform.clone())
        );
        assert_eq!(
            parse(&format!("local:id:{LOCAL_ID}")).resolve(PolicyPlacement::Local, &candidates),
            Ok(local.clone())
        );
        for missing in [
            "missing".to_owned(),
            "local:other".to_owned(),
            format!("platform:id:{LOCAL_ID}"),
        ] {
            assert_eq!(
                parse(&missing).resolve(PolicyPlacement::Local, &candidates),
                Err(PolicyReferenceError::NotFound),
                "{missing}"
            );
        }
        for builtin in BuiltinPolicy::ALL {
            assert_eq!(
                parse(builtin.name()).resolve(PolicyPlacement::Hosted, &candidates),
                Ok(ResolvedPolicy::Builtin(builtin))
            );
        }

        // The bound form is the exact reference and selects the same policy.
        assert_eq!(local.to_string(), format!("local:id:{LOCAL_ID}"));
        assert_eq!(
            parse(&local.to_string()).resolve(PolicyPlacement::Local, &candidates),
            Ok(local.clone())
        );
        assert_eq!(
            platform.reference(),
            parse(&format!("platform:id:{PLATFORM_ID}"))
        );
        assert_eq!(
            ResolvedPolicy::Builtin(BuiltinPolicy::Open).to_string(),
            "open"
        );
    }
}
