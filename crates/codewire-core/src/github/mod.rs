//! GitHub App authentication and API client
//!
//! Provides GitHub App user-to-server authentication and a client for
//! listing installation-scoped repositories. Users install the GitHub
//! App and select which repos to expose.

mod auth;
mod client;

pub use auth::{DeviceCodeResponse, GitHubAuthManager, GitHubToken};
pub use client::{GitHubClient, GitHubRepo};
