//! A refusal's reason alone, without what its variant carries: what a log of
//! refusals keeps (#5058). Each is one code of the spec's list.

use super::Refusal;

/// The reason of a [`Refusal`]: a closed set, so a log never holds free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefusalCode {
    CredentialRevoked,
    CredentialExpired,
    CredentialNeedsReconnect,
    NoCredentialSelected,
    CredentialUnavailable,
    CredentialConflict,
    PathNotServed,
    WebsocketNotServed,
    RouteNotServed,
    RequestNotForwarded,
    BodyTooLarge,
    Busy,
    UpstreamFailed,
    NameNotAllowed,
    SelectedCredentialOnly,
    CredentialRefreshRateLimited,
    Unavailable,
    Denied,
    CredentialOwnerDeparted,
    CredentialOwnerDisabled,
}

impl RefusalCode {
    /// Every code, in a fixed order a wire may index.
    pub const ALL: [Self; 20] = [
        Self::CredentialRevoked,
        Self::CredentialExpired,
        Self::CredentialNeedsReconnect,
        Self::NoCredentialSelected,
        Self::CredentialUnavailable,
        Self::CredentialConflict,
        Self::PathNotServed,
        Self::WebsocketNotServed,
        Self::RouteNotServed,
        Self::RequestNotForwarded,
        Self::BodyTooLarge,
        Self::Busy,
        Self::UpstreamFailed,
        Self::NameNotAllowed,
        Self::SelectedCredentialOnly,
        Self::CredentialRefreshRateLimited,
        Self::Unavailable,
        Self::Denied,
        // Appended: a wire indexes this order.
        Self::CredentialOwnerDeparted,
        Self::CredentialOwnerDisabled,
    ];

    /// The `Codewire-Refusal` value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialRevoked => "credential_revoked",
            Self::CredentialExpired => "credential_expired",
            Self::CredentialNeedsReconnect => "credential_needs_reconnect",
            Self::NoCredentialSelected => "no_credential_selected",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::CredentialConflict => "credential_conflict",
            Self::PathNotServed => "path_not_served",
            Self::WebsocketNotServed => "websocket_not_served",
            Self::RouteNotServed => "route_not_served",
            Self::RequestNotForwarded => "request_not_forwarded",
            Self::BodyTooLarge => "body_too_large",
            Self::Busy => "busy",
            Self::UpstreamFailed => "upstream_failed",
            Self::NameNotAllowed => "name_not_allowed",
            Self::SelectedCredentialOnly => "selected_credential_only",
            Self::CredentialRefreshRateLimited => "credential_refresh_rate_limited",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
            Self::CredentialOwnerDeparted => "credential_owner_departed",
            Self::CredentialOwnerDisabled => "credential_owner_disabled",
        }
    }

    /// The reason in words, as `cw policy log` prints it.
    pub const fn description(self) -> &'static str {
        match self {
            Self::CredentialRevoked => "credential revoked",
            Self::CredentialExpired => "credential expired",
            Self::CredentialNeedsReconnect => "credential needs reconnecting",
            Self::NoCredentialSelected => "no credential selected",
            Self::CredentialUnavailable => "credential unavailable",
            Self::CredentialConflict => "credential conflict",
            Self::PathNotServed => "path not served",
            Self::WebsocketNotServed => "WebSocket not carried",
            Self::RouteNotServed => "route not served",
            Self::RequestNotForwarded => "request not forwarded",
            Self::BodyTooLarge => "body too large",
            Self::Busy => "busy",
            Self::UpstreamFailed => "provider failed",
            Self::NameNotAllowed => "name not allowed",
            Self::SelectedCredentialOnly => "selected credential only",
            Self::CredentialRefreshRateLimited => "refresh rate-limited",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
            Self::CredentialOwnerDeparted => "creator left the organization",
            Self::CredentialOwnerDisabled => "creator's account disabled",
        }
    }

    /// The code `value` names, or `None` for anything else.
    pub fn from_code(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    /// This code's position in [`Self::ALL`].
    pub fn index(self) -> u8 {
        Self::ALL
            .iter()
            .position(|code| *code == self)
            .and_then(|index| u8::try_from(index).ok())
            .expect("every code is in RefusalCode::ALL, which has fewer than 256")
    }

    /// The code at `index` in [`Self::ALL`].
    pub fn at(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

impl Refusal {
    /// This refusal's reason alone.
    pub const fn code(self) -> RefusalCode {
        match self {
            Self::CredentialRevoked => RefusalCode::CredentialRevoked,
            Self::CredentialExpired => RefusalCode::CredentialExpired,
            Self::CredentialNeedsReconnect => RefusalCode::CredentialNeedsReconnect,
            Self::NoCredentialSelected => RefusalCode::NoCredentialSelected,
            Self::CredentialUnavailable => RefusalCode::CredentialUnavailable,
            Self::CredentialConflict => RefusalCode::CredentialConflict,
            Self::PathNotServed => RefusalCode::PathNotServed,
            Self::WebsocketNotServed => RefusalCode::WebsocketNotServed,
            Self::RouteNotServed => RefusalCode::RouteNotServed,
            Self::RequestNotForwarded(_) => RefusalCode::RequestNotForwarded,
            Self::BodyTooLarge => RefusalCode::BodyTooLarge,
            Self::Busy => RefusalCode::Busy,
            Self::UpstreamFailed(_) => RefusalCode::UpstreamFailed,
            Self::NameNotAllowed => RefusalCode::NameNotAllowed,
            Self::SelectedCredentialOnly => RefusalCode::SelectedCredentialOnly,
            Self::CredentialRefreshRateLimited { .. } => RefusalCode::CredentialRefreshRateLimited,
            Self::Unavailable => RefusalCode::Unavailable,
            Self::Denied => RefusalCode::Denied,
            Self::CredentialOwnerDeparted => RefusalCode::CredentialOwnerDeparted,
            Self::CredentialOwnerDisabled => RefusalCode::CredentialOwnerDisabled,
        }
    }
}
