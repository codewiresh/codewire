use std::fmt;

use tonic::metadata::{Ascii, MetadataValue};

pub const DAEMON_AUTH_TOKEN_HEADER: &str = "x-codewire-daemon-token";
/// Fixed-purpose hosted exec could not certify a clean terminal child status.
/// Lifecycle callers must recover the exact Pod on this status, conservatively
/// including a real child that exits with the same code.
pub const HOSTED_EXEC_AMBIGUOUS_EXIT_CODE: i32 = 125;
/// Exact projected-token purpose for a workspace authenticating credential
/// access through the credential relay, not the Kubernetes API.
pub const CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE: &str = "codewire.internal.credential-workspace.v1";
/// Exact projected-token purpose for orchestration relaying a bound
/// workspace daemon's credential bridge to the isolated credential broker.
/// The broker pins it to [`CREDENTIAL_RELAY_SERVICE_ACCOUNT`] in its own
/// (server) namespace; it authorizes no other exchange.
pub const CREDENTIAL_RELAY_TOKEN_AUDIENCE: &str = "codewire.internal.credential-relay.v1";
/// The only service account that may present a credential-relay token.
pub const CREDENTIAL_RELAY_SERVICE_ACCOUNT: &str = "codewire-orchestration";
pub const CREDENTIAL_RELAY_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/credential-relay";
pub const CREDENTIAL_RELAY_TOKEN_PATH: &str = "/var/run/secrets/codewire/credential-relay/token";
pub const CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// The public UDP relay's data-plane port, the one relay port a workspace may
/// reach.
pub const UDP_RELAY_DATA_PORT: u16 = 41641;
/// The DERP servers' STUN port, the one DERP port a workspace may reach
/// directly; DERP itself is reached through the public edge.
pub const DERP_STUN_PORT: u16 = 3478;
/// The service account every workspace Pod runs as. A workspace-binding token
/// is accepted only for it.
pub const SANDBOX_SERVICE_ACCOUNT: &str = "codewire-sandbox";
/// Orchestration's internal Connect listener behind TLS, which Mesh calls.
pub const ORCHESTRATION_INTERNAL_TLS_PORT: u16 = 8088;
/// Exact projected-token purpose for an identity-free workspace Pod fetching
/// its own binding from the dedicated workspace-binding listener. It is
/// distinct from the credential audiences, so a token
/// projected for this purpose cannot be replayed against any other exchange.
pub const WORKSPACE_BINDING_TOKEN_AUDIENCE: &str = "codewire.internal.workspace-binding.v1";
pub const WORKSPACE_BINDING_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/workspace-binding";
pub const WORKSPACE_BINDING_TOKEN_PATH: &str = "/var/run/secrets/codewire/workspace-binding/token";
pub const WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// Dedicated orchestration listener that serves only `WorkspaceBindingService`.
pub const WORKSPACE_BINDING_PORT: u16 = 8087;
/// Selects the hosted daemon's binding mode: the URL of the dedicated
/// workspace-binding listener. A binding-mode Pod carries no environment
/// identity; it comes only from the bind response.
pub const WORKSPACE_BINDING_URL_ENV: &str = "CODEWIRE_WORKSPACE_BINDING_URL";
/// The public roots the workspace daemon verifies the binding listener's TLS
/// identity with: orchestration's internal CA, the single key `ca.crt` of the
/// sandbox-namespace ConfigMap `codewire-orchestration-internal-roots`,
/// mounted read-only into the workspace container of every Pod whose binding
/// URL is rendered.
pub const WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH: &str =
    "/run/codewire-orchestration-internal-roots";
pub const WORKSPACE_BINDING_TLS_ROOTS_FILE: &str =
    "/run/codewire-orchestration-internal-roots/ca.crt";
/// The workspace Pod's own UID from the downward API. The daemon compares it
/// with the reviewed Pod UID in the bind response.
pub const WORKSPACE_POD_UID_ENV: &str = "CODEWIRE_POD_UID";
/// Owner-only (0700) daemon state directory under the Pod's `/codewire/run`.
pub const HOSTED_DAEMON_STATE_DIRECTORY: &str = "/codewire/run/daemon";
/// Local readiness marker: the daemon process is up and its binding loop
/// runs. It never depends on binding, because orchestration binds a Pod only
/// after the Pod is Ready.
pub const HOSTED_DAEMON_READY_FILE: &str = "/codewire/run/daemon/ready";
/// Owner-read-only (0400) copy of a bound daemon's credential, read by the
/// fixed-purpose hosted exec instead of its inherited environment.
pub const HOSTED_DAEMON_CREDENTIAL_FILE: &str = "/codewire/run/daemon/credential";
/// Workspace access is ready: the daemon is bound, its SSH server listens on
/// [`WORKSPACE_SSH_PORT`] and its host key is recorded. Tailnet comes up
/// after, asynchronously, and is not part of this marker.
pub const HOSTED_DAEMON_ACCESS_READY_FILE: &str = "/codewire/run/daemon/access-ready";
/// The bound daemon's SSH listener in the workspace Pod. Only orchestration
/// (its SSH proxy and setup health check) may reach it.
pub const WORKSPACE_SSH_PORT: u16 = 2222;
/// The bound daemon's tailnet direct-UDP port in the workspace Pod: the
/// target of the environment's direct-UDP LoadBalancer, reachable from the
/// world only.
pub const WORKSPACE_TAILNET_UDP_PORT: u16 = 31000;
/// Extra roots the bound daemon trusts for the public coordinator, beside
/// the WebPKI roots: a PEM bundle mounted read-only only by a local cluster
/// whose coordinator edge has a cluster-owned authority. Dev and Production
/// never mount it. A present but malformed bundle fails closed.
pub const COORDINATOR_EXTRA_ROOTS_MOUNT_PATH: &str = "/run/codewire-coordinator-extra-roots";
pub const COORDINATOR_EXTRA_ROOTS_FILE: &str = "/run/codewire-coordinator-extra-roots/ca.crt";
/// The only ConfigMap that may supply those extra roots, and only where
/// orchestration is configured to mount it (`SANDBOX_COORDINATOR_EXTRA_ROOTS`,
/// a local cluster). Dev and Production never mount it.
pub const COORDINATOR_EXTRA_ROOTS_CONFIGMAP: &str = "codewire-coordinator-extra-roots";
/// Server-side long-poll requested by an unbound daemon; the listener clamps
/// it to its own maximum.
pub const WORKSPACE_BINDING_WAIT_SECONDS: u32 = 20;
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_MINIMUM_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_CAPABILITY_EXEC: &str = "exec.v1";
pub const DAEMON_CAPABILITY_PTY: &str = "pty.v1";
pub const DAEMON_CAPABILITY_FILES: &str = "files.v1";
pub const DAEMON_CAPABILITY_HEALTH: &str = "health.v1";
pub const DAEMON_CAPABILITY_SESSIONS: &str = "sessions.v1";
pub const DAEMON_CAPABILITY_ATTACH: &str = "attach.v1";
pub const DAEMON_CAPABILITY_SESSION_INPUT: &str = "session_input.v1";
pub const DAEMON_CAPABILITY_SESSION_METADATA: &str = "session_metadata.v1";
pub const SESSION_INPUT_MAX_BYTES: usize = 64 * 1024;
pub const SESSION_INPUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
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
/// Response header on the broker's admitted `CredentialBridge` stream: one
/// value per optional operation this broker serves. The relay copies the
/// known values into the daemon's `CredentialBridgeOpen.capabilities`.
pub const CREDENTIAL_BRIDGE_CAPABILITIES_HEADER: &str = "x-codewire-credential-bridge-capabilities";
/// Response header on the broker's admitted `CredentialBridge` stream: the
/// epoch's verified identity expiry, in decimal Unix seconds. The broker ends
/// the epoch then. The relay uses it only to schedule and check the next
/// epoch's admission before this one ends.
pub const CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER: &str = "x-codewire-credential-bridge-expires-at";
/// The broker serves `CodexLoginRequest` on this epoch. A daemon sends that
/// frame only when its epoch's Open lists this value: an older broker or
/// relay ends the epoch on an unknown frame.
pub const CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN: &str = "codex-login";
/// The broker serves `ClaudeLoginRequest` on this epoch, under the same rule.
pub const CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN: &str = "claude-login";
/// Every optional operation a current host may list. Unknown values are
/// ignored by the relay; an Open is bounded to this many entries.
pub const CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES: &[&str] = &[
    CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
    CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
];
pub const CREDENTIAL_BRIDGE_MAX_CAPABILITIES: usize = 8;
pub const CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES: usize = 64;

/// A bounded, canonical capability name: lowercase ASCII letters, digits,
/// `-` and `.`. Shape only; a listed capability confers no authority.
pub fn valid_credential_bridge_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
}
pub const CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES: usize =
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + CREDENTIAL_BRIDGE_MAX_HEADER_BYTES + 128 * 1024;
pub const DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_EXEC,
    DAEMON_CAPABILITY_PTY,
    DAEMON_CAPABILITY_FILES,
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSION_INPUT,
    DAEMON_CAPABILITY_SESSION_METADATA,
];

pub const HOST_DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSION_INPUT,
    DAEMON_CAPABILITY_SESSION_METADATA,
];

/// Empty means unnamed. Named sessions use a bounded, shell-safe label.
pub fn valid_session_name(name: &str) -> bool {
    name.is_empty()
        || (name.len() <= 64
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

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

/// Private relay-initiated credential-broker transport. This service imports
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
            CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            CREDENTIAL_RELAY_TOKEN_AUDIENCE,
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
        assert_eq!(
            CREDENTIAL_RELAY_TOKEN_PATH,
            format!("{CREDENTIAL_RELAY_TOKEN_MOUNT_PATH}/token")
        );
        assert_ne!(CREDENTIAL_RELAY_SERVICE_ACCOUNT, SANDBOX_SERVICE_ACCOUNT);
        assert_eq!(
            CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS,
            WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS
        );
        assert_eq!(WORKSPACE_BINDING_PORT, 8087);
        assert_eq!(ORCHESTRATION_INTERNAL_TLS_PORT, 8088);
    }

    #[test]
    fn hosted_daemon_binding_state_lives_in_one_owner_directory() {
        assert_eq!(WORKSPACE_BINDING_URL_ENV, "CODEWIRE_WORKSPACE_BINDING_URL");
        assert_eq!(
            WORKSPACE_BINDING_TLS_ROOTS_FILE,
            format!("{WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH}/ca.crt")
        );
        assert_eq!(
            COORDINATOR_EXTRA_ROOTS_FILE,
            format!("{COORDINATOR_EXTRA_ROOTS_MOUNT_PATH}/ca.crt")
        );
        assert_eq!(WORKSPACE_POD_UID_ENV, "CODEWIRE_POD_UID");
        assert_eq!(HOSTED_DAEMON_STATE_DIRECTORY, "/codewire/run/daemon");
        for file in [HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_CREDENTIAL_FILE] {
            let (directory, name) = file.rsplit_once('/').unwrap();
            assert_eq!(directory, HOSTED_DAEMON_STATE_DIRECTORY);
            assert!(!name.is_empty());
        }
        assert_ne!(HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_CREDENTIAL_FILE);
        // The wait stays well inside the listener's 35s connection deadline.
        assert!((1..=20).contains(&WORKSPACE_BINDING_WAIT_SECONDS));
    }

    #[test]
    fn credential_bridge_capabilities_are_bounded_canonical_names() {
        for capability in [
            CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
            CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
        ] {
            assert!(valid_credential_bridge_capability(capability));
            assert!(CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.contains(&capability));
        }
        for known in CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES {
            assert!(valid_credential_bridge_capability(known));
        }
        assert!(CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITIES);
        let too_long = "a".repeat(CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES + 1);
        for invalid in [
            "",
            "Codex-Login",
            "codex login",
            "codex_login",
            "cödex",
            &too_long,
        ] {
            assert!(!valid_credential_bridge_capability(invalid), "{invalid:?}");
        }
        assert_eq!(
            CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
            CREDENTIAL_BRIDGE_CAPABILITIES_HEADER.to_ascii_lowercase()
        );
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
                    capabilities: Vec::new(),
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

/// Closed private platform managed-agent framing; authority remains with the caller.
pub mod platform_managed;
