pub mod client;
pub mod config;
mod credential_bridge;
mod durable_session;
pub mod env;
pub mod execution;
pub mod files;
mod lifecycle;
pub mod server;
pub mod service;
pub mod session;

pub use codewire_gateway_proto::{DaemonAuthToken, HOSTED_EXEC_AMBIGUOUS_EXIT_CODE};
pub use config::{
    Config, ConfigError, CredentialBridgeConfig, CredentialBridgeTransport, DEFAULT_HOME_ROOT,
    DEFAULT_LISTEN_ADDR, DEFAULT_WORKSPACE_ROOT, HOME_ROOT_ENV, LaunchProjectionConfig,
    NativeLaunchProjectionConfig, SHIM_ADDR_ENV, WORKSPACE_ROOT_ENV,
};
pub use server::serve_grpc_with_incoming;
