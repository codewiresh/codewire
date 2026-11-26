// Predates these workspace lints; #4125 tracks removing the allow.
#![allow(clippy::undocumented_unsafe_blocks, clippy::unwrap_used)]

pub mod access;
pub mod activity;
#[cfg(target_os = "linux")]
mod agent_login;
#[cfg(target_os = "linux")]
pub mod antigravity_home;
pub mod app_ports;
pub mod auth_rotation;
#[cfg(target_os = "linux")]
pub mod claude_home;
pub mod client;
#[cfg(unix)]
pub mod codex_home;
pub mod config;
mod confirm;
mod credential_bridge;
pub mod delivered_logins;
mod desktop;
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
pub mod identity_files;
#[cfg(unix)]
pub mod identity_socket;
mod launch;
mod lifecycle;
pub mod local_transport;
#[cfg(target_os = "linux")]
pub mod login_cleanup;
pub mod login_readiness;
#[cfg(target_os = "linux")]
pub mod platform_managed;
pub mod platform_refusal;
#[cfg(unix)]
pub mod platform_sockets;
#[cfg(unix)]
mod private_files;
pub mod recent_log;
pub mod server;
pub mod service;
pub mod session;
#[cfg(unix)]
pub mod shared_repositories;
#[cfg(target_os = "linux")]
pub mod snapshot_clearing;
#[cfg(target_os = "linux")]
pub mod ssh_known_hosts;
pub mod stop_evidence;
pub mod suspend;
#[cfg(unix)]
pub mod unix_forward;
#[cfg(unix)]
pub mod workspace_defaults;

pub use codewire_daemon_proto::{DaemonAuthToken, HOSTED_EXEC_AMBIGUOUS_EXIT_CODE};
pub use config::{
    BindResponseFields, BrokerPlatform, CODEX_LOGIN_CHECK_PERIOD, CODEX_LOGIN_CHECK_PERIOD_ENV,
    CODEX_LOGIN_CHECK_PERIOD_MIN, Config, ConfigError, CredentialBridgeConfig,
    CredentialBridgeTransport, DEFAULT_HOME_ROOT, DEFAULT_LISTEN_ADDR, DEFAULT_WORKSPACE_ROOT,
    DeclaredMount, DerpAddress, HOME_ROOT_ENV, HostConfig, HostedDaemonMode,
    InvalidWorkspaceBinding, LaunchProjectionConfig, MeasuredAnchors, NativeLaunchProjectionConfig,
    SHIM_ADDR_ENV, WORKSPACE_ROOT_ENV, WorkspaceBinding, WorkspaceBindingConfig,
    codex_login_check_period,
};
pub use durable_session::NeverRestarts;
pub use server::serve_grpc_with_incoming;
#[cfg(target_os = "linux")]
pub use server::{
    serve_bound_hosted_grpc_with_incoming, serve_hosted_grpc_with_incoming,
    serve_native_grpc_with_incoming,
};
#[cfg(target_os = "linux")]
pub use server::{
    serve_host_control_grpc_replying_within, serve_host_control_grpc_with_incoming,
    serve_host_control_grpc_within,
};
