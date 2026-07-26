//! Codewire platform integration
//!
//! This module provides authentication and API access to the Codewire platform.

#[cfg(not(target_arch = "wasm32"))]
mod auth;
mod client;

#[cfg(not(target_arch = "wasm32"))]
pub use auth::{CodewireAuthManager, TokenInfo};
pub use client::CodewireClient;
