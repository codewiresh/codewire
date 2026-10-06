pub mod binding;
pub mod config;
pub mod credentials;
pub mod docker_proxy;
mod hosted_bridge;
pub mod metrics;
pub mod readiness;
pub mod runtime;
pub mod tailnet;

// The SSH stack moved to `codewire-workspace-access`, which the workspace
// daemon also serves; these keep the gateway's paths until it is deleted.
pub use codewire_workspace_access::{daemon, daemon_credential, host_key, scp, sftp, ssh};
