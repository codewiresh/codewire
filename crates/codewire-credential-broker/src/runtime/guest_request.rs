//! A credential bridge request, parsed once at the broker's edge into the
//! fields every rule reads.

use codewire_access::{BrokerRouteId, CapabilitySlot};
use codewire_daemon_proto::codewire::bridge::v1;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use uuid::Uuid;

use super::{BrokerRequestError, bound_secret, entry, routed};
use crate::bridge::BridgeEntry;
use crate::network::RouteHost;

pub(super) struct ValidatedGuestRequest {
    pub(super) request_id: Uuid,
    pub(super) slot: CapabilitySlot,
    pub(super) route: BrokerRouteId,
    pub(super) method: Method,
    pub(super) path: String,
    pub(super) query: Option<String>,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
    /// Set only on a front-door session, whose credential the swap rule
    /// handles (#3999).
    pub(super) intercepted_host: Option<RouteHost>,
    /// A front-door request to a name under a routed suffix, served only at
    /// the origin its session recorded (#3999, `runtime/routed.rs`).
    pub(super) routed: Option<routed::RoutedDial>,
    /// A front-door request to a host-bound secret's host (#4003,
    /// `runtime/bound_secret.rs`): set exactly when its slot is that route's.
    pub(super) bound: Option<bound_secret::BoundDial>,
}

impl ValidatedGuestRequest {
    /// `body_stream` says whether the bridge handed over a streamed body; the
    /// request must agree. Only a GitHub request streams: a Git one on either
    /// entry, and behind a front door any GitHub request, which may be
    /// forwarded as it was sent.
    pub(super) fn parse(
        entry: BridgeEntry,
        request: v1::CredentialBridgeRequest,
        body_stream: bool,
    ) -> Result<Self, BrokerRequestError> {
        if request.streamed_body != body_stream
            || (request.streamed_body
                && (request.capability_slot != "github"
                    || (request.route != "github-https" && entry != BridgeEntry::FrontDoor)
                    || !request.body.is_empty()))
        {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let (intercepted_host, routed) = entry::intercepted(entry, &request)?;
        let bound = entry::bound_dial(entry, &request)?;
        if !(bound.is_some()
            || matches!(
                (request.capability_slot.as_str(), request.route.as_str()),
                ("codex" | "openai", "openai-api")
                    | ("anthropic", "anthropic-api" | "claude-oauth-token")
                    | ("github", "github-api" | "github-https")
                    | ("gemini", "gemini-api")
                    | ("antigravity", "antigravity-api" | "antigravity-oauth-token")
            ))
            || request.body.len() > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES
            || request.headers.len() > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_HEADERS
            || request.path.len() > 2048
            || request.query.len() > 4096
        {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let slot = CapabilitySlot::parse(request.capability_slot)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(request.route).map_err(|_| BrokerRequestError::InvalidRequest)?;
        let request_id =
            Uuid::parse_str(&request.request_id).map_err(|_| BrokerRequestError::InvalidRequest)?;
        if request_id.is_nil() || request_id.to_string() != request.request_id {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        if request.path.is_empty() || !request.path.starts_with('/') {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let query = (!request.query.is_empty()).then_some(request.query);
        let mut headers = HeaderMap::new();
        let mut header_bytes = 0_usize;
        for header in request.headers {
            if header.name.len() > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
                || header.value.len()
                    > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
            {
                return Err(BrokerRequestError::InvalidRequest);
            }
            header_bytes = header_bytes
                .checked_add(header.name.len() + header.value.len())
                .filter(|bytes| *bytes <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_HEADER_BYTES)
                .ok_or(BrokerRequestError::InvalidRequest)?;
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            let value = HeaderValue::from_bytes(&header.value)
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            headers.append(name, value);
        }
        Ok(Self {
            request_id,
            slot,
            route,
            method,
            path: request.path,
            query,
            headers,
            body: request.body,
            intercepted_host,
            routed,
            bound,
        })
    }
}
