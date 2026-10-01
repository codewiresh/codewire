use std::fmt;

use tonic::metadata::{Ascii, MetadataValue};

pub const DAEMON_AUTH_TOKEN_HEADER: &str = "x-codewire-daemon-token";
/// Fixed-purpose hosted exec could not certify a clean terminal child status.
/// Lifecycle callers must recover the exact Pod on this status, conservatively
/// including a real child that exits with the same code.
pub const HOSTED_EXEC_AMBIGUOUS_EXIT_CODE: i32 = 125;
/// Exact Kubernetes projected-token audience for the gateway-binding RPC.
///
/// The audience is deliberately distinct from both Kubernetes' API audience
/// and every Codewire HMAC capability scope. A token projected for this
/// audience can authenticate only the single cluster-local binding exchange.
pub const GATEWAY_BINDING_TOKEN_AUDIENCE: &str = "codewire.internal.gateway-binding.v1";
/// Exact projected-token purpose for a gateway authenticating to the isolated
/// credential broker. This does not authorize workload or binding-bootstrap use.
pub const CREDENTIAL_GATEWAY_TOKEN_AUDIENCE: &str = "codewire.internal.credential-gateway.v1";
/// Exact projected-token purpose for a workspace authenticating credential
/// access through its per-environment gateway, not the Kubernetes API.
pub const CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE: &str = "codewire.internal.credential-workspace.v1";
pub const GATEWAY_BINDING_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/gateway-binding";
pub const GATEWAY_BINDING_TOKEN_PATH: &str = "/var/run/secrets/codewire/gateway-binding/token";
pub const GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS: i64 = 600;
pub const GATEWAY_BINDING_SERVICE_ACCOUNT: &str = "codewire-sandbox";
/// Exact projected-token purpose for an identity-free workspace Pod fetching
/// its own binding from the dedicated workspace-binding listener. It is
/// distinct from the gateway-binding and credential audiences, so a token
/// projected for this purpose cannot be replayed against any other exchange.
pub const WORKSPACE_BINDING_TOKEN_AUDIENCE: &str = "codewire.internal.workspace-binding.v1";
pub const WORKSPACE_BINDING_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/workspace-binding";
pub const WORKSPACE_BINDING_TOKEN_PATH: &str = "/var/run/secrets/codewire/workspace-binding/token";
pub const WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// Dedicated orchestration listener that serves only `WorkspaceBindingService`.
pub const WORKSPACE_BINDING_PORT: u16 = 8087;
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_MINIMUM_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_CAPABILITY_EXEC: &str = "exec.v1";
pub const DAEMON_CAPABILITY_PTY: &str = "pty.v1";
pub const DAEMON_CAPABILITY_FILES: &str = "files.v1";
pub const DAEMON_CAPABILITY_HEALTH: &str = "health.v1";
pub const DAEMON_CAPABILITY_SESSIONS: &str = "sessions.v1";
pub const DAEMON_CAPABILITY_ATTACH: &str = "attach.v1";
pub const DAEMON_CAPABILITY_CREDENTIAL_BRIDGE: &str = "credential_bridge.v1";
// Version4 uses the current complete recipient-sealed projection bundle. Old
// single-ciphertext peers fail admission instead of discovering it at launch.
pub const CREDENTIAL_BRIDGE_PROTOCOL_VERSION: u32 = 4;
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

/// Material-free framing checks for the closed selected-key SSH transport.
pub mod ssh;

/// Canonical names-only framing for fixed-role native projection composition.
pub mod projection;

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

/// Neutral material-free credential bridge frames shared by native and
/// platform transports. The package deliberately carries no service authority.
pub mod codewire {
    pub mod bridge {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/codewire.bridge.v1.rs"));
        }
    }
}

pub mod daemon {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/daemon.v1.rs"));
    }
}

/// Private gateway-initiated credential-broker transport. This service imports
/// the neutral material-free bridge frames but no daemon service authority.
pub mod broker {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/broker.v1.rs"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn projected_token_audiences_are_pairwise_distinct_and_mounts_do_not_overlap() {
        let audiences = [
            GATEWAY_BINDING_TOKEN_AUDIENCE,
            CREDENTIAL_GATEWAY_TOKEN_AUDIENCE,
            CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            WORKSPACE_BINDING_TOKEN_AUDIENCE,
        ];
        for (index, audience) in audiences.iter().enumerate() {
            assert!(audience.starts_with("codewire.internal.") && audience.ends_with(".v1"));
            for other in &audiences[index + 1..] {
                assert_ne!(audience, other);
            }
        }
        assert_eq!(
            WORKSPACE_BINDING_TOKEN_PATH,
            format!("{WORKSPACE_BINDING_TOKEN_MOUNT_PATH}/token")
        );
        assert!(!WORKSPACE_BINDING_TOKEN_MOUNT_PATH.starts_with(GATEWAY_BINDING_TOKEN_MOUNT_PATH));
        assert!(!GATEWAY_BINDING_TOKEN_MOUNT_PATH.starts_with(WORKSPACE_BINDING_TOKEN_MOUNT_PATH));
        assert_eq!(
            WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS,
            GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS
        );
        assert_eq!(WORKSPACE_BINDING_PORT, 8087);
    }

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

    #[test]
    fn neutral_bridge_frames_preserve_pre_extraction_wire_bytes() {
        use codewire::bridge::v1 as bridge_v1;

        // Captured from the former daemon.v1 messages before their package-only
        // extraction. Protobuf package names do not participate in these bytes.
        let previous_open = [0x0a, 0x07, 0x08, 0x03, 0x12, 0x01, b'e', 0x18, 0x07];
        let open = bridge_v1::CredentialBridgeHostMessage {
            payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                bridge_v1::CredentialBridgeOpen {
                    protocol_version: 3,
                    environment_id: "e".to_owned(),
                    environment_generation: 7,
                },
            )),
        };
        assert_eq!(open.encode_to_vec(), previous_open);
        assert_eq!(
            bridge_v1::CredentialBridgeHostMessage::decode(previous_open.as_slice()).unwrap(),
            open
        );

        let previous_ssh = [
            0x2a, 0x0d, 0x0a, 0x01, b'r', 0x10, 0x01, 0x22, 0x06, 0x0a, 0x01, 0x01, 0x12, 0x01,
            0x02,
        ];
        let ssh = bridge_v1::CredentialBridgeGuestMessage {
            payload: Some(bridge_v1::credential_bridge_guest_message::Payload::Ssh(
                bridge_v1::CredentialSshRequest {
                    request_id: "r".to_owned(),
                    deadline_unix_ms: 1,
                    operation: Some(bridge_v1::credential_ssh_request::Operation::Sign(
                        bridge_v1::CredentialSshSignRequest {
                            public_key_blob: vec![1],
                            data: vec![2],
                            flags: 0,
                        },
                    )),
                },
            )),
        };
        assert_eq!(ssh.encode_to_vec(), previous_ssh);
        assert_eq!(
            bridge_v1::CredentialBridgeGuestMessage::decode(previous_ssh.as_slice()).unwrap(),
            ssh
        );

        let previous_projection_failure = [0x32, 0x05, 0x0a, 0x01, b'r', 0x18, 0x01];
        let projection_failure = bridge_v1::CredentialBridgeHostMessage {
            payload: Some(
                bridge_v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                    bridge_v1::EnvironmentProjectionResponse {
                        request_id: "r".to_owned(),
                        result: Some(bridge_v1::environment_projection_response::Result::Failure(
                            bridge_v1::CredentialBridgeFailureReason::Denied as i32,
                        )),
                    },
                ),
            ),
        };
        assert_eq!(
            projection_failure.encode_to_vec(),
            previous_projection_failure
        );
        assert_eq!(
            bridge_v1::CredentialBridgeHostMessage::decode(previous_projection_failure.as_slice())
                .unwrap(),
            projection_failure
        );
    }
}
