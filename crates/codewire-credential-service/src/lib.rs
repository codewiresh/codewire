//! Concrete authority for the private platform credential bridge.
//!
//! The `enrollment` feature includes the isolated service runtime; constructing
//! an authority alone activates no listener. Its owner supplies an isolated
//! PostgreSQL pool and Kubernetes client. The
//! pool reads narrowly granted scope/profile metadata and encrypted tenant
//! envelopes; fixed SHARE helpers fence authority without owner/environment/
//! profile or application-secret DML. Full project_spec/configuration values
//! are not readable. No public or arbitrary plaintext getter is provided.
//!
//! App-only identity is independent of an optional, exactly pinned credential
//! profile. Personal profiles require the creator's saved confirmation; an
//! organization profile must belong to the exact current organization. Current
//! membership is required even for the creator. The private projector seals
//! only the runtime's selected application winners to one actual launcher.

// Predates this workspace lint; #4125 tracks removing the allow.
#![allow(clippy::unwrap_used)]

mod authority;
#[cfg(feature = "enrollment")]
pub mod delegation;
#[cfg(feature = "enrollment")]
pub mod mutation;
mod objects;
mod projection;
#[cfg(feature = "enrollment")]
mod repositories;
#[cfg(feature = "enrollment")]
pub mod runtime;

pub use authority::{KubernetesPlatformBridgeAuthenticator, KubernetesPlatformRuntimeAuthority};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../../codewire-platform-credentials/tests/support/mod.rs"]
#[allow(dead_code)]
mod platform_test_support;
