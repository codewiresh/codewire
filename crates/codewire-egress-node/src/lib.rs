//! cw-egress: the per-node egress supervisor for hosted sandboxes (#4000).
//!
//! A sandbox's guest opens one stream to the cw-egress on its own node and
//! sends a [`hello::GuestHello`] with its Pod-bound egress token. cw-egress
//! forwards the token to orchestration, which admits the stream only for a
//! broker-mode Pod on cw-egress's node, and returns the Pod's assignment.
//! cw-egress keys the stream's network session ([`key`]) and runs one
//! confined worker and broker pair for it. A newer stream for the same Pod
//! replaces the older, and every start counts against a limit per peer
//! address, checked before orchestration is asked ([`replacement`]).

#![forbid(unsafe_code)]

pub mod hello;
pub mod key;
pub mod replacement;
