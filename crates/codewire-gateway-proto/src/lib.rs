use std::fmt;

use tonic::metadata::{Ascii, MetadataValue};

pub const DAEMON_AUTH_TOKEN_HEADER: &str = "x-codewire-daemon-token";
/// Exact Kubernetes projected-token audience for the gateway-binding RPC.
///
/// The audience is deliberately distinct from both Kubernetes' API audience
/// and every Codewire HMAC capability scope. A token projected for this
/// audience can authenticate only the single cluster-local binding exchange.
pub const GATEWAY_BINDING_TOKEN_AUDIENCE: &str = "codewire.internal.gateway-binding.v1";
pub const GATEWAY_BINDING_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/gateway-binding";
pub const GATEWAY_BINDING_TOKEN_PATH: &str = "/var/run/secrets/codewire/gateway-binding/token";
pub const GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS: i64 = 600;
pub const GATEWAY_BINDING_SERVICE_ACCOUNT: &str = "codewire-sandbox";
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_MINIMUM_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_CAPABILITY_EXEC: &str = "exec.v1";
pub const DAEMON_CAPABILITY_PTY: &str = "pty.v1";
pub const DAEMON_CAPABILITY_FILES: &str = "files.v1";
pub const DAEMON_CAPABILITY_HEALTH: &str = "health.v1";
pub const DAEMON_CAPABILITY_SESSIONS: &str = "sessions.v1";
pub const DAEMON_CAPABILITY_ATTACH: &str = "attach.v1";
pub const DAEMON_CAPABILITY_CREDENTIAL_BRIDGE: &str = "credential_bridge.v1";
pub const CREDENTIAL_BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const CREDENTIAL_BRIDGE_LOOPBACK_PORT: u16 = 38_081;
pub const CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES: usize = 64 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_HEADERS: usize = 64;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES: usize = 128;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_BYTES: usize = 64 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_IN_FLIGHT: usize = 16;
pub const CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES: usize =
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + CREDENTIAL_BRIDGE_MAX_HEADER_BYTES + 128 * 1024;
pub const DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_EXEC,
    DAEMON_CAPABILITY_PTY,
    DAEMON_CAPABILITY_FILES,
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
];

/// Validated credential for the private environment-daemon RPC boundary.
///
/// The token is deliberately not optional: every daemon transport, including
/// the private hosted TCP/ClusterIP adapter, must authenticate each RPC. Its
/// `Debug` representation never exposes credential bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct DaemonAuthToken(String);

impl DaemonAuthToken {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidDaemonAuthToken> {
        let value = value.into();
        if value.is_empty() || !value.is_ascii() || value.trim() != value {
            return Err(InvalidDaemonAuthToken);
        }
        MetadataValue::<Ascii>::try_from(value.as_str()).map_err(|_| InvalidDaemonAuthToken)?;
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DaemonAuthToken {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}

impl fmt::Debug for DaemonAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DaemonAuthToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDaemonAuthToken;

impl fmt::Display for InvalidDaemonAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("daemon auth token must be nonblank canonical ASCII metadata")
    }
}

impl std::error::Error for InvalidDaemonAuthToken {}

pub mod daemon {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/daemon.v1.rs"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_auth_token_is_mandatory_canonical_and_redacted() {
        for invalid in ["", " ", " token", "token ", "line\nbreak", "tökén"] {
            assert_eq!(
                DaemonAuthToken::new(invalid),
                Err(InvalidDaemonAuthToken),
                "accepted {invalid:?}"
            );
        }

        let marker = "daemon-auth-token-marker";
        let token = DaemonAuthToken::new(marker).expect("valid token");
        assert_eq!(token.expose_secret(), marker);
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
    }
}
