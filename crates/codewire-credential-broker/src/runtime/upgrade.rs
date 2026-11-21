//! A front door's WebSocket handshake (#3999).
//!
//! Only the paths in [`UPGRADABLE`] may upgrade; any other is refused before
//! a lease. The handshake is an ordinary front-door request under the swap
//! rule: with this environment's placeholder its credential is swapped, a
//! 401 is refreshed and retried once, and a refusal's reply is redacted.
//! Without one it is forwarded untouched. The swap applies to the handshake
//! only: once the provider answers `101`, the socket's bytes are never read.
//! The `101`'s headers pass the route's response policy, keep only what a
//! client needs to finish its handshake, and fail the upgrade if any echoes
//! the injected credential. A swapped socket carries a [`SocketGrant`] that
//! the bridge leases again while the socket is open.

use bytes::Bytes;
use codewire_access::{BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId};
use codewire_daemon_proto::codewire::bridge::v1;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use uuid::Uuid;

use super::openai_serve::redacted_openai;
use super::swap::{Presented, credential_conflict_response, forwarded_body};
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestError, BrokerUpgradedStream,
    BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport, BrokerUpstreamUpgrade,
    OPENAI_OPERATION, OPENAI_ROUTE, OpenAiBroker, Phase, ValidatedGuestRequest, map_adapter_error,
    map_lease_error, map_upstream_error, timing, validate_http_lease_coordinates,
};
use crate::bridge::BridgeEntry;
use crate::openai::{ForwardedOpenAiRequest, ValidatedOpenAiRequest};
use crate::transparent::without_framing;
use crate::{BrokerCredentialLease as _, PreparedOpenAiRequest, PreparedOpenAiResponse};

/// The slot, host and path of every handshake that may upgrade: Codex's
/// model call, which the pinned Codex opens as a WebSocket and falls back to
/// HTTPS POST for. Token endpoints never upgrade.
const UPGRADABLE: [(&str, &str, &str); 1] =
    [("codex", "chatgpt.com", "/backend-api/codex/responses")];

/// The handshake headers the client sends and the provider must see. The
/// broker frames the request itself: `Connection` and `Upgrade` are its own.
const HANDSHAKE_REQUEST_HEADERS: [HeaderName; 4] = [
    header::SEC_WEBSOCKET_KEY,
    header::SEC_WEBSOCKET_VERSION,
    header::SEC_WEBSOCKET_PROTOCOL,
    header::SEC_WEBSOCKET_EXTENSIONS,
];

/// The `101` headers a client needs to finish its handshake, kept whatever
/// the route's response policy allows.
const HANDSHAKE_RESPONSE_HEADERS: [HeaderName; 3] = [
    header::SEC_WEBSOCKET_ACCEPT,
    header::SEC_WEBSOCKET_PROTOCOL,
    header::SEC_WEBSOCKET_EXTENSIONS,
];

/// Whose credential a swapped socket was opened with. While the socket is
/// open the bridge leases it again; a refusal, another credential or a newer
/// revocation ends it.
pub(crate) struct SocketGrant {
    slot: CapabilitySlot,
    operation: BrokerOperationId,
    route: BrokerRouteId,
    credential: CredentialId,
    revocation_generation: u64,
}

#[cfg(test)]
impl SocketGrant {
    /// A Codex grant, for tests of the bridge that renews it.
    pub(crate) fn for_tests() -> Self {
        Self {
            slot: CapabilitySlot::codex(),
            operation: BrokerOperationId::parse(OPENAI_OPERATION).expect("operation"),
            route: BrokerRouteId::parse(OPENAI_ROUTE).expect("route"),
            credential: CredentialId::parse("11111111-1111-4111-8111-111111111111")
                .expect("credential"),
            revocation_generation: 7,
        }
    }
}

/// How a front door's handshake ended.
pub(crate) enum BrokerUpgradeOutcome {
    /// The provider switched: the headers for the client's `101`, the
    /// provider's socket, and the grant to renew when the credential is ours.
    Switched {
        headers: HeaderMap,
        stream: BrokerUpgradedStream,
        grant: Option<SocketGrant>,
    },
    /// Any other answer, as the reply to an ordinary request.
    Response(BrokerHttpResponse),
}

/// A swapped handshake as the provider answered it.
enum Sent {
    Switched {
        headers: HeaderMap,
        stream: BrokerUpgradedStream,
        policy: PreparedOpenAiResponse,
        injected: Option<HeaderValue>,
    },
    Refused(BrokerUpstreamResponse, PreparedOpenAiResponse),
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A WebSocket handshake on a front-door session. Only the front-door
    /// bridge runner calls it.
    pub(crate) async fn execute_front_door_upgrade(
        &self,
        upgrade: v1::CredentialBridgeUpgrade,
    ) -> Result<BrokerUpgradeOutcome, BrokerRequestError> {
        let upgradable = upgrade.method == "GET"
            && UPGRADABLE.iter().any(|(slot, host, path)| {
                upgrade.capability_slot == *slot
                    && upgrade.intercepted_host == *host
                    && upgrade.path == *path
            });
        if !upgradable {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let mut request = ValidatedGuestRequest::parse(
            BridgeEntry::FrontDoor,
            v1::CredentialBridgeRequest {
                request_id: upgrade.request_id,
                method: upgrade.method,
                path: upgrade.path,
                query: upgrade.query,
                headers: upgrade.headers,
                body: Vec::new(),
                capability_slot: upgrade.capability_slot,
                route: upgrade.route,
                intercepted_host: upgrade.intercepted_host,
                // An upgrade frame names no admitted address (#3999).
                destination_ip: String::new(),
                streamed_body: false,
                intercept_decision: upgrade.intercept_decision,
            },
            false,
        )?;
        // As for a request: a provider with no address is not asked (#5286).
        if self.upstream.slot_unserved(request.slot.as_str()) {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let handshake = take_handshake(&mut request.headers)?;
        let presented = match Presented::of(&request.headers) {
            Presented::Conflict => {
                return Ok(BrokerUpgradeOutcome::Response(
                    credential_conflict_response(),
                ));
            }
            Presented::Foreign => None,
            Presented::Placeholder(placeholder) => Some(placeholder),
        };
        let provider_request = self
            .oauth_adapter
            .validate_front_door(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let Some(presented) = presented else {
            return self.forward_upgrade(provider_request, &handshake).await;
        };
        if self.placeholders.known_foreign(&request.slot, &presented) {
            return self.forward_upgrade(provider_request, &handshake).await;
        }
        let operation = BrokerOperationId::parse(OPENAI_OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(OPENAI_ROUTE).map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                request.slot.clone(),
                operation.clone(),
                route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &route)?;
        self.placeholders
            .remember(&request.slot, lease.placeholder());
        if !lease
            .placeholder()
            .is_some_and(|ours| ours.ct_eq(&presented))
        {
            drop(lease);
            return self.forward_upgrade(provider_request, &handshake).await;
        }
        if lease.credential_metadata().authentication_kind
            != codewire_access::CredentialAuthKind::OAuth
        {
            return Err(BrokerRequestError::Denied);
        }
        let credential = lease.credential_metadata().id.clone();
        let revocation_generation = lease.credential_metadata().revocation_generation;
        let (prepared, retry) = self
            .prepare_openai(
                request.request_id,
                &request.slot,
                &operation,
                &route,
                lease,
                provider_request,
            )
            .await?;
        let mut sent = self.upgrade_prepared(prepared, &handshake).await?;
        if let Some(retry) = retry {
            sent = match sent {
                Sent::Refused(upstream, policy)
                    if upstream.status() == StatusCode::UNAUTHORIZED =>
                {
                    match self
                        .after_unauthorized(
                            request.request_id,
                            operation.clone(),
                            route.clone(),
                            retry,
                            upstream,
                        )
                        .await?
                    {
                        (_, Some(prepared)) => self.upgrade_prepared(prepared, &handshake).await?,
                        (upstream, None) => Sent::Refused(upstream, policy),
                    }
                }
                sent => sent,
            };
        }
        match sent {
            Sent::Switched {
                headers,
                stream,
                policy,
                injected,
            } => Ok(BrokerUpgradeOutcome::Switched {
                headers: switched_headers(&headers, policy, injected.as_ref())?,
                stream,
                grant: Some(SocketGrant {
                    slot: request.slot,
                    operation,
                    route,
                    credential,
                    revocation_generation,
                }),
            }),
            Sent::Refused(upstream, policy) => Ok(BrokerUpgradeOutcome::Response(redacted_openai(
                upstream, policy,
            )?)),
        }
    }

    /// Whether `grant` still leases the credential its socket was opened
    /// with. Any doubt is a no: a refused lease, an error, another credential,
    /// or a revocation since.
    pub(crate) async fn socket_grant_holds(&self, grant: &SocketGrant) -> bool {
        match self
            .leases
            .lease_operation(
                Uuid::new_v4(),
                grant.slot.clone(),
                grant.operation.clone(),
                grant.route.clone(),
            )
            .await
        {
            Ok(lease) => {
                validate_http_lease_coordinates(&lease, &grant.slot, &grant.operation, &grant.route)
                    .is_ok()
                    && lease.credential_metadata().id == grant.credential
                    && lease.credential_metadata().revocation_generation
                        == grant.revocation_generation
            }
            Err(_) => false,
        }
    }

    /// A swapped handshake sent to the provider.
    async fn upgrade_prepared(
        &self,
        prepared: PreparedOpenAiRequest,
        handshake: &HeaderMap,
    ) -> Result<Sent, BrokerRequestError> {
        let (method, target, headers, _body, policy) = prepared.into_parts();
        let injected = headers.get(header::AUTHORIZATION).cloned();
        let upgraded = timing::timed(
            Phase::Provider,
            self.upstream.upgrade(BrokerUpstreamRequest {
                method,
                target,
                headers: handshake_request(&headers, handshake),
                body: Vec::new(),
                body_stream: None,
                pinned: None,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        Ok(match upgraded {
            BrokerUpstreamUpgrade::Switched { headers, stream } => Sent::Switched {
                headers,
                stream,
                policy,
                injected,
            },
            BrokerUpstreamUpgrade::Response(response) => Sent::Refused(response, policy),
        })
    }

    /// A handshake carrying no placeholder of this environment's: sent as the
    /// environment sent it, framing aside, and answered unredacted, since
    /// nothing of ours was injected. Its socket carries no grant.
    async fn forward_upgrade(
        &self,
        provider_request: ValidatedOpenAiRequest,
        handshake: &HeaderMap,
    ) -> Result<BrokerUpgradeOutcome, BrokerRequestError> {
        // A handshake names no admitted address, so it is never pinned; the
        // transport refuses a routed name it would have to resolve (#3999).
        let ForwardedOpenAiRequest {
            method,
            target,
            headers,
            pinned,
            ..
        } = provider_request
            .into_forwarded()
            .map_err(map_adapter_error)?;
        self.untouched_forward_allowed(&target, false)?;
        let upgraded = timing::timed(
            Phase::Provider,
            self.upstream.upgrade(BrokerUpstreamRequest {
                method,
                target,
                headers: handshake_request(&headers, handshake),
                body: Vec::new(),
                body_stream: None,
                pinned,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        Ok(match upgraded {
            BrokerUpstreamUpgrade::Switched { headers, stream } => BrokerUpgradeOutcome::Switched {
                headers: with_handshake(without_framing(&headers), &headers),
                stream,
                grant: None,
            },
            BrokerUpstreamUpgrade::Response(response) => {
                let (status, headers, body) = response.into_parts();
                BrokerUpgradeOutcome::Response(BrokerHttpResponse::new(
                    status,
                    without_framing(&headers),
                    forwarded_body(body, crate::openai::MAX_RESPONSE_BYTES),
                ))
            }
        })
    }
}

/// The client's handshake headers, taken out of `headers` so the route's
/// request checks see an ordinary GET. A key and a version are required.
fn take_handshake(headers: &mut HeaderMap) -> Result<HeaderMap, BrokerRequestError> {
    let mut handshake = HeaderMap::new();
    for name in HANDSHAKE_REQUEST_HEADERS {
        for value in headers.get_all(&name) {
            handshake.append(name.clone(), value.clone());
        }
        headers.remove(&name);
    }
    if handshake.get_all(header::SEC_WEBSOCKET_KEY).iter().count() != 1
        || handshake.get(header::SEC_WEBSOCKET_VERSION).is_none()
    {
        return Err(BrokerRequestError::InvalidRequest);
    }
    Ok(handshake)
}

/// The provider request for a handshake: `prepared` without framing, plus
/// the broker's own `Connection` and `Upgrade` and the client's handshake.
fn handshake_request(prepared: &HeaderMap, handshake: &HeaderMap) -> HeaderMap {
    let mut headers = without_framing(prepared);
    for name in [header::HOST, header::CONTENT_LENGTH, header::CONTENT_TYPE] {
        headers.remove(name);
    }
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    for (name, value) in handshake {
        headers.append(name.clone(), value.clone());
    }
    headers
}

/// The `101` headers sent to the front door for a swapped socket: the
/// route's response policy, then the handshake's own headers. A `101` that echoes the
/// injected credential fails the upgrade rather than reach the environment.
fn switched_headers(
    raw: &HeaderMap,
    policy: PreparedOpenAiResponse,
    injected: Option<&HeaderValue>,
) -> Result<HeaderMap, BrokerRequestError> {
    if let Some(secret) = injected.map(credential_value)
        && !secret.is_empty()
        && raw
            .values()
            .any(|value| contains(value.as_bytes(), &secret))
    {
        return Err(BrokerRequestError::UpstreamFailed);
    }
    let (headers, _redactor) = policy.begin(raw).map_err(map_adapter_error)?;
    let mut headers = headers;
    headers.remove(header::SET_COOKIE);
    Ok(with_handshake(headers, raw))
}

/// `headers` with the provider's handshake headers from `raw`. `Connection`
/// and `Upgrade` never cross the bridge: the front door frames the client's
/// `101` itself.
fn with_handshake(mut headers: HeaderMap, raw: &HeaderMap) -> HeaderMap {
    headers.remove(header::CONNECTION);
    headers.remove(header::UPGRADE);
    for name in HANDSHAKE_RESPONSE_HEADERS {
        headers.remove(&name);
        for value in raw.get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers
}

/// The credential in an `authorization` value, without its scheme.
fn credential_value(value: &HeaderValue) -> Bytes {
    let bytes = value.as_bytes();
    let token = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .map_or(bytes, |space| &bytes[space + 1..]);
    Bytes::copy_from_slice(token)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests;
