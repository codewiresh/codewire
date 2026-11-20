//! cw-egress: the per-node egress supervisor for hosted sandboxes (#4000).
//!
//! A sandbox's guest opens one stream to the cw-egress on its own node and
//! sends a [`hello::GuestHello`] with its Pod-bound egress token. cw-egress
//! forwards the token to orchestration, which admits the stream only for a
//! broker-mode Pod on cw-egress's node, and returns the Pod's assignment.
//! cw-egress keys the stream's network session ([`key`]) and runs one
//! confined worker and broker pair for it, and for a Pod whose assignment
//! intercepts its agent hosts, a confined front door beside them
//! ([`interception`], #4001). A newer stream for the same Pod replaces the
//! older, and every start counts against a limit per peer address, checked
//! before orchestration is asked ([`replacement`]).

#![forbid(unsafe_code)]

pub mod admission;
pub mod admitted;
#[cfg(target_os = "linux")]
pub mod children;
pub mod drain;
#[cfg(target_os = "linux")]
pub mod front_door;
#[cfg(target_os = "linux")]
pub mod front_door_session;
pub mod interception;
#[cfg(target_os = "linux")]
pub mod launch;
pub mod leaves;
#[cfg(target_os = "linux")]
pub mod node;
pub mod orchestration;
pub mod replacement;
pub mod reporter;
pub mod settings;
pub mod supervisor;

/// The stream's hello and key are the session protocol's, shared with the
/// guest that dials cw-egress.
pub use codewire_network_session::hosted::{hello, key};
