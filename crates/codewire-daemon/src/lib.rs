pub mod access;
#[cfg(target_os = "linux")]
mod agent_login;
pub mod app_ports;
#[cfg(target_os = "linux")]
pub mod claude_home;
pub mod client;
#[cfg(unix)]
pub mod codex_home;
pub mod config;
mod confirm;
mod credential_bridge;
mod durable_session;
pub mod env;
pub mod execution;
pub mod files;
mod forward;
#[cfg(target_os = "linux")]
pub mod gh_config;
#[cfg(target_os = "linux")]
pub mod host_control;
#[cfg(unix)]
mod host_process;
#[cfg(unix)]
pub mod hosted_state;
mod lifecycle;
pub mod local_transport;
#[cfg(target_os = "linux")]
pub mod login_cleanup;
#[cfg(target_os = "linux")]
pub mod platform_managed;
#[cfg(unix)]
mod private_files;
pub mod server;
pub mod service;
pub mod session;
#[cfg(target_os = "linux")]
pub mod ssh_known_hosts;
pub mod stop_evidence;

pub use codewire_daemon_proto::{DaemonAuthToken, HOSTED_EXEC_AMBIGUOUS_EXIT_CODE};
pub use config::{
    BindResponseFields, CODEX_LOGIN_CHECK_PERIOD, CODEX_LOGIN_CHECK_PERIOD_ENV,
    CODEX_LOGIN_CHECK_PERIOD_MIN, Config, ConfigError, CredentialBridgeConfig,
    CredentialBridgeTransport, DEFAULT_HOME_ROOT, DEFAULT_LISTEN_ADDR, DEFAULT_WORKSPACE_ROOT,
    HOME_ROOT_ENV, HostConfig, HostedDaemonMode, InvalidWorkspaceBinding, LaunchProjectionConfig,
    MeasuredAnchors, NativeLaunchProjectionConfig, SHIM_ADDR_ENV, WORKSPACE_ROOT_ENV,
    WorkspaceBinding, WorkspaceBindingConfig, codex_login_check_period,
};
pub use durable_session::NeverRestarts;
pub use server::serve_grpc_with_incoming;
#[cfg(target_os = "linux")]
pub use server::{
    serve_bound_hosted_grpc_with_incoming, serve_hosted_grpc_with_incoming,
    serve_native_grpc_with_incoming,
};
#[cfg(target_os = "linux")]
pub use server::{serve_host_control_grpc_with_incoming, serve_host_control_grpc_within};
