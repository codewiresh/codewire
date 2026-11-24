//! The built-in policies, compiled into every placement (#2537, #3997).
//!
//! `open` is the default, for a local VM and a hosted Sandbox alike: DNS, and
//! TCP on any port to public addresses. `web` is DNS and TCP on 22, 80 and
//! 443, which `open` allowed before #3997. `locked` has no rules, so it admits
//! no workload egress. Built-ins are never stored and cannot be edited; a
//! bare `open`, `web` or `locked` always names one of them, so no stored
//! policy may be created with any of those names.
//!
//! A selection stores a built-in by name, never by digest, so a selection of
//! `open` made before #3997 enforces today's `open`.

use std::fmt;

use crate::{CompiledPolicy, PolicyDocument};

pub const OPEN_ID: &str = "codewire-open-v1";
pub const OPEN_POLICY_DIGEST: &str =
    "384ad64a6b4de41783c369f74ae4a4265617de1c7da2c97c14f5fb9b4e40090f";
pub const OPEN_POLICY_YAML: &[u8] = include_bytes!("../policies/open-v1.yaml");

pub const WEB_ID: &str = "codewire-web-v1";
pub const WEB_POLICY_DIGEST: &str =
    "fab8151c7bffd0d0fe6ca1a9397ae6b60fa1e0ae650a967f9c9445ac3dd4189f";
pub const WEB_POLICY_YAML: &[u8] = include_bytes!("../policies/web-v1.yaml");

pub const LOCKED_ID: &str = "codewire-locked-v1";
pub const LOCKED_POLICY_DIGEST: &str =
    "145641138b37aaf7724fb49bc3dd5f59c515ff34e60a2cfbdc7d51d4da9b16ca";
pub const LOCKED_POLICY_YAML: &[u8] = include_bytes!("../policies/locked-v1.yaml");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinPolicy {
    Open,
    Web,
    Locked,
}

impl BuiltinPolicy {
    pub const ALL: [Self; 3] = [Self::Open, Self::Web, Self::Locked];

    /// The name users select it by.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Web => "web",
            Self::Locked => "locked",
        }
    }

    /// The stable identifier of its document.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Open => OPEN_ID,
            Self::Web => WEB_ID,
            Self::Locked => LOCKED_ID,
        }
    }

    /// The canonical digest its document must compile to.
    pub const fn digest_hex(self) -> &'static str {
        match self {
            Self::Open => OPEN_POLICY_DIGEST,
            Self::Web => WEB_POLICY_DIGEST,
            Self::Locked => LOCKED_POLICY_DIGEST,
        }
    }

    pub const fn document_yaml(self) -> &'static [u8] {
        match self {
            Self::Open => OPEN_POLICY_YAML,
            Self::Web => WEB_POLICY_YAML,
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

/// Whether a stored policy may not take `name`, in any letter case, because a
/// bare reference to it already means a built-in.
pub fn is_reserved_policy_name(name: &str) -> bool {
    BuiltinPolicy::ALL
        .into_iter()
        .any(|builtin| builtin.name().eq_ignore_ascii_case(name))
}
