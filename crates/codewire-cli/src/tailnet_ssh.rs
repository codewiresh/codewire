//! CLI adapter for the shared native Tailnet transport.
//!
//! The client core owns transport setup and diagnostics so native consumers
//! use one implementation. This module preserves the CLI's internal path.

pub(crate) use codewire_client::{
    EnvironmentTailnetDiagnostic, ExpectedTransport, SshTransportMode, TailnetDiagnosticOptions,
    TailnetPathDiagnostic, diagnose_environment_tailnet, parse_duration, pipe_shell_stdio,
};

#[cfg(test)]
pub(crate) use codewire_client::{
    TailnetDerpMapDiagnostic, TailnetDiagnosticStage, TailnetPeerDiagnostic,
};
