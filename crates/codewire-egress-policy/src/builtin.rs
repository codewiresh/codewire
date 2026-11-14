//! The built-in policies, compiled into every placement (#2537).
//!
//! `open` is the developer baseline every environment had before network
//! policies existed, and stays the default. `locked` has no rules, so it
//! admits no workload egress. Built-ins are never stored and cannot be
//! edited; a bare `open` or `locked` always names one of them, so a stored
//! policy may not take either name.
//!
//! `hosted-default` is what a hosted Sandbox that selects no policy enforces
//! (codewire#3997, D2). It is not a selectable built-in: an environment is on
//! it by selecting nothing, so it stays out of [`BuiltinPolicy`]. Only the
//! platform store reserves its name; a local store may hold a policy by that
//! name, as it could before this document existed (#4000).

use std::fmt;

use crate::{
    CompiledPolicy, DEVELOPER_BASELINE_DIGEST, DEVELOPER_BASELINE_ID, DEVELOPER_BASELINE_YAML,
    PolicyDocument,
};

pub const LOCKED_ID: &str = "codewire-locked-v1";
pub const LOCKED_POLICY_DIGEST: &str =
    "145641138b37aaf7724fb49bc3dd5f59c515ff34e60a2cfbdc7d51d4da9b16ca";
pub const LOCKED_POLICY_YAML: &[u8] = include_bytes!("../policies/locked-v1.yaml");

/// The name a hosted Sandbox reports when it selects no policy.
pub const HOSTED_DEFAULT_NAME: &str = "hosted-default";
pub const HOSTED_DEFAULT_ID: &str = "codewire-hosted-default-v1";
pub const HOSTED_DEFAULT_DIGEST: &str =
    "384ad64a6b4de41783c369f74ae4a4265617de1c7da2c97c14f5fb9b4e40090f";
pub const HOSTED_DEFAULT_YAML: &[u8] = include_bytes!("../policies/hosted-default-v1.yaml");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinPolicy {
    Open,
    Locked,
}

impl BuiltinPolicy {
    pub const ALL: [Self; 2] = [Self::Open, Self::Locked];

    /// The name users select it by.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
        }
    }

    /// The stable identifier of its document.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Open => DEVELOPER_BASELINE_ID,
            Self::Locked => LOCKED_ID,
        }
    }

    /// The canonical digest its document must compile to.
    pub const fn digest_hex(self) -> &'static str {
        match self {
            Self::Open => DEVELOPER_BASELINE_DIGEST,
            Self::Locked => LOCKED_POLICY_DIGEST,
        }
    }

    pub const fn document_yaml(self) -> &'static [u8] {
        match self {
            Self::Open => DEVELOPER_BASELINE_YAML,
            Self::Locked => LOCKED_POLICY_YAML,
        }
    }

    pub fn compile(self) -> CompiledPolicy {
        PolicyDocument::parse_yaml(self.document_yaml())
            .expect("a built-in egress policy must remain valid")
    }

    /// The built-in a bare, exact name selects.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|builtin| builtin.name() == name)
    }
}

impl fmt::Display for BuiltinPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Whether a stored policy may not use `name`, in any letter case, because a
/// bare reference to it already means a built-in.
pub fn is_reserved_policy_name(name: &str) -> bool {
    BuiltinPolicy::ALL
        .into_iter()
        .any(|builtin| builtin.name().eq_ignore_ascii_case(name))
}
