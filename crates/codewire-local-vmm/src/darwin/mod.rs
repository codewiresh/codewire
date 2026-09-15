//! Native host primitives for the existing local runtime.
//!
//! This module does not enable local CLI routing, supervisor replay, or a VM.

mod acl;
pub mod path;
pub mod process;

#[cfg(test)]
mod path_capability_tests;
