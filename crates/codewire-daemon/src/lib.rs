#[cfg(target_os = "linux")]
pub mod claude_home;
pub mod client;
#[cfg(unix)]
pub mod codex_home;
pub mod config;
mod credential_bridge;
mod durable_session;
pub mod env;
pub mod execution;
pub mod files;
#[cfg(target_os = "linux")]
pub mod host_control;
#[cfg(unix)]
mod host_process;
#[cfg(unix)]
pub mod hosted_state;
mod lifecycle;
#[cfg(target_os = "linux")]
pub mod platform_managed;
#[cfg(unix)]
mod private_files;
pub mod server;
pub mod service;
pub mod session;

pub use codewire_gateway_proto::{DaemonAuthToken, HOSTED_EXEC_AMBIGUOUS_EXIT_CODE};
pub use config::{
    BindResponseFields, Config, ConfigError, CredentialBridgeConfig, CredentialBridgeTransport,
    DEFAULT_HOME_ROOT, DEFAULT_LISTEN_ADDR, DEFAULT_WORKSPACE_ROOT, HOME_ROOT_ENV, HostConfig,
    HostedDaemonMode, InvalidWorkspaceBinding, LaunchProjectionConfig,
    NativeLaunchProjectionConfig, SHIM_ADDR_ENV, WORKSPACE_ROOT_ENV, WorkspaceBinding,
    WorkspaceBindingConfig,
};
pub use server::serve_grpc_with_incoming;
#[cfg(target_os = "linux")]
pub use server::serve_host_control_grpc_with_incoming;
#[cfg(target_os = "linux")]
pub use server::serve_hosted_grpc_with_incoming;
