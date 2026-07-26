//! Error types for codewire

use thiserror::Error;

/// Core error type
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CoreError {
    #[error("Network error: {message}")]
    Network { message: String },

    #[error("API error: {message}")]
    Api { message: String },

    #[error("IO error: {message}")]
    Io { message: String },

    #[error("Serialization error: {message}")]
    Serialization { message: String },

    #[error("Workspace not found: {id}")]
    WorkspaceNotFound { id: String },

    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    #[error("Stream cancelled")]
    StreamCancelled,

    #[error("Provider not found: {id}")]
    ProviderNotFound { id: String },

    #[error("Authentication required for provider: {provider_name}")]
    AuthRequired { provider_name: String },

    #[error("Authentication failed: {message}")]
    AuthFailed { message: String },

    #[error("SSH error: {message}")]
    Ssh { message: String },

    #[error("Session not found: {name}")]
    SessionNotFound { name: String },

    #[error("Keychain error: {message}")]
    Keychain { message: String },
}

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        CoreError::Io {
            message: err.to_string(),
        }
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(err: serde_json::Error) -> Self {
        CoreError::Serialization {
            message: err.to_string(),
        }
    }
}
