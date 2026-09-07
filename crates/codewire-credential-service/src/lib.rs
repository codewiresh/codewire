//! Concrete, material-free authority for the private platform credential bridge.
//!
//! The `enrollment` feature includes the isolated service runtime; constructing
//! an authority alone activates no listener. Its owner supplies an isolated
//! PostgreSQL pool and Kubernetes client. The
//! pool needs only current scope/profile metadata SELECT and the existing fixed
//! owner/environment/profile SHARE helpers: no owner, environment or profile
//! DML, credential material, OAuth journal, generic secrets or authentication
//! tables are read here.
//!
//! The first supported scope is an environment creator's personally owned,
//! exactly bound and explicitly confirmed profile. Current organization
//! membership is required even for that creator. Organization-owned profiles
//! are deliberately not activated by this authority.

mod authority;
#[cfg(feature = "enrollment")]
pub mod mutation;
mod objects;
#[cfg(feature = "enrollment")]
pub mod runtime;

pub use authority::{KubernetesPlatformBridgeAuthenticator, KubernetesPlatformRuntimeAuthority};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../../codewire-platform-credentials/tests/support/mod.rs"]
#[allow(dead_code)]
mod platform_test_support;
