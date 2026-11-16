//! The guest network agent's failures and statuses as the host reads them:
//! each boot stage and network status it may record, and which a failed
//! handshake records.

use codewire_network_session::guest::GuestHandshakeError;

pub(super) const NETWORK_AGENT_FAILURE_STAGES: &[&str] = &[
    "workspace-net-seed-failed",
    "workspace-net-tun-open-failed",
    "workspace-net-tun-attach-failed",
    "workspace-net-loopback-failed",
    "workspace-net-link-failed",
    "workspace-net-address-failed",
    "workspace-net-route-failed",
    "workspace-net-ipv-six-failed",
    "workspace-net-topology-failed",
    "workspace-net-async-failed",
    "workspace-net-vsock-failed",
    "workspace-net-caps-failed",
    "workspace-net-ready-failed",
    "workspace-net-publish-failed",
    "workspace-net-peer-failed",
    "workspace-net-handshake-timeout",
    "workspace-net-hello-read-failed",
    "workspace-net-hello-auth-failed",
    "workspace-net-ack-write-failed",
    "workspace-net-ready-read-failed",
    "workspace-net-ready-auth-failed",
    "workspace-net-session-failed",
    "workspace-net-trust-read-failed",
    "workspace-net-trust-auth-failed",
];
pub(super) const NETWORK_AGENT_GENERIC_FAILURE_STAGE: &str = "workspace-net-start-failed";
pub(super) const NETWORK_AGENT_HOST_FAILURE_STAGE: &str = "workspace-net-host-failed";
pub(super) const NETWORK_STATUS_VALUES: &[&str] = &[
    "network-listening",
    "network-peer-rejected",
    "network-handshake-timeout",
    "network-hello-read-failed",
    "network-hello-auth-failed",
    "network-ack-write-failed",
    "network-ready-read-failed",
    "network-ready-auth-failed",
    "network-session-failed",
    "network-trust-read-failed",
    "network-trust-auth-failed",
    "network-authenticated",
];

/// The guest's network status for a failed handshake.
pub(super) fn handshake_status(error: GuestHandshakeError) -> &'static str {
    match error {
        GuestHandshakeError::ReadHello => "network-hello-read-failed",
        GuestHandshakeError::AuthenticateHello => "network-hello-auth-failed",
        GuestHandshakeError::WriteAcknowledgement => "network-ack-write-failed",
        GuestHandshakeError::ReadReady => "network-ready-read-failed",
        GuestHandshakeError::AuthenticateReady => "network-ready-auth-failed",
        GuestHandshakeError::Session => "network-session-failed",
        GuestHandshakeError::ReadEgressTrust => "network-trust-read-failed",
        GuestHandshakeError::AuthenticateEgressTrust => "network-trust-auth-failed",
    }
}

/// The boot stage a failed handshake records.
pub(super) fn handshake_failure_stage(error: GuestHandshakeError) -> &'static str {
    match error {
        GuestHandshakeError::ReadHello => "workspace-net-hello-read-failed",
        GuestHandshakeError::AuthenticateHello => "workspace-net-hello-auth-failed",
        GuestHandshakeError::WriteAcknowledgement => "workspace-net-ack-write-failed",
        GuestHandshakeError::ReadReady => "workspace-net-ready-read-failed",
        GuestHandshakeError::AuthenticateReady => "workspace-net-ready-auth-failed",
        GuestHandshakeError::Session => "workspace-net-session-failed",
        GuestHandshakeError::ReadEgressTrust => "workspace-net-trust-read-failed",
        GuestHandshakeError::AuthenticateEgressTrust => "workspace-net-trust-auth-failed",
    }
}
