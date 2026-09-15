//! Credential-free durable workspace source enums shared by persisted records.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSourceMode {
    Clone,
    Copy,
}
