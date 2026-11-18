//! A request's session entry, which the runner the admitting host called
//! chose, reaching request validation (#3999).

use codewire_daemon_proto::codewire::bridge::v1;

use super::claude_token::CLAUDE_TOKEN_ROUTE;
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestBodyStream, BrokerRequestError,
    BrokerUpstreamTransport, OpenAiBroker, ValidatedGuestRequest,
};
use crate::bridge::BridgeEntry;
use crate::network::RouteHost;
use crate::network_policy;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// [`Self::execute`] for a request on a front-door session, which only
    /// the host process that admitted that session may call. The request must
    /// name the host it was intercepted for, one its slot's route sends to.
    /// It is then served by the swap rule (`runtime/swap.rs`): this
    /// environment's placeholder is replaced with the leased credential,
    /// anything else is forwarded untouched, and a placeholder beside another
    /// credential is refused. The only way in from outside this crate is the
    /// front-door bridge runner.
    pub(crate) async fn execute_front_door(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_on(BridgeEntry::FrontDoor, request, None).await
    }

    /// [`Self::execute_front_door`] for a request whose body streams: only a
    /// request to one of GitHub's two hosts.
    pub(crate) async fn execute_front_door_streamed(
        &self,
        request: v1::CredentialBridgeRequest,
        body: BrokerRequestBodyStream,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_on(BridgeEntry::FrontDoor, request, Some(body))
            .await
    }

    pub(super) async fn execute_on(
        &self,
        entry: BridgeEntry,
        request: v1::CredentialBridgeRequest,
        body: Option<BrokerRequestBodyStream>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let request = ValidatedGuestRequest::parse(entry, request, body.is_some())?;
        let slot = request.slot.clone();
        // A loopback request never passed the environment's network policy,
        // so the policy's answer for GitHub is applied here, before any
        // lease. A front-door request carries its own decision.
        if entry == BridgeEntry::Loopback
            && slot.as_str() == network_policy::GITHUB_SLOT
            && !self.network_policy_allows_github
        {
            return Ok(network_policy::github_refused_response(
                request.route.as_str(),
            ));
        }
        // A provider this broker has no address for is not asked, and no
        // credential is leased for it (#5286).
        if self.upstream.slot_unserved(slot.as_str()) {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let result = match body {
            body if request.intercepted_host.is_some() => {
                self.execute_intercepted(request, body).await
            }
            None => self.execute_validated(request).await,
            Some(body) => self.execute_github(request, Some(body)).await,
        };
        match result {
            Err(
                error
                @ (BrokerRequestError::ReconnectRequired(_) | BrokerRequestError::NotSelected),
            ) => Ok(crate::reconnect::refusal_response(error.refusal(), &slot)),
            result => result,
        }
    }
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Whether the environment's network policy allows GitHub's hosts by
    /// rule (#4926). Whoever holds the policy decides and says so at launch;
    /// a launch that does not say passes `false`. Without this call the
    /// broker serves the GitHub slot, as the hosted credential service does,
    /// which has no network policy in hand.
    pub fn with_network_policy_allowing_github(mut self, allowed: bool) -> Self {
        self.network_policy_allows_github = allowed;
        self
    }

    /// A front-door request, under the swap rule. The Anthropic route, Codex
    /// at `chatgpt.com` and GitHub's two hosts have it; any other front-door
    /// request is refused before a lease, never served by always injecting.
    /// Claude's token host is answered or forwarded by its own rule
    /// (`claude_token.rs`), and GitHub's hosts by theirs
    /// (`github_front_door.rs`). Only a GitHub request may stream its body.
    async fn execute_intercepted(
        &self,
        request: ValidatedGuestRequest,
        body: Option<BrokerRequestBodyStream>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        match (request.slot.as_str(), request.intercepted_host) {
            ("github", Some(host @ (RouteHost::GitHub | RouteHost::GitHubApi))) => {
                self.execute_github_intercepted(host, request, body).await
            }
            _ if body.is_some() => Err(BrokerRequestError::InvalidRequest),
            ("anthropic", _) if request.route.as_str() == CLAUDE_TOKEN_ROUTE => {
                self.execute_claude_token(request).await
            }
            ("anthropic", _) => self.execute_swap(request).await,
            ("codex", Some(RouteHost::ChatGpt)) => self.execute_codex_swap(request).await,
            _ => Err(BrokerRequestError::InvalidRequest),
        }
    }
}

/// The host a request on `entry` was intercepted for, checked before any
/// credential lease. A loopback request names none: the environment controls
/// every field of it. A front-door request must name one of its route's hosts.
/// Claude's token route exists only behind the front door: a loopback
/// request for it is refused.
pub(super) fn intercepted_host(
    entry: BridgeEntry,
    request: &v1::CredentialBridgeRequest,
) -> Result<Option<RouteHost>, BrokerRequestError> {
    match entry {
        BridgeEntry::Loopback
            if request.intercepted_host.is_empty() && request.route != CLAUDE_TOKEN_ROUTE =>
        {
            Ok(None)
        }
        BridgeEntry::Loopback => Err(BrokerRequestError::InvalidRequest),
        BridgeEntry::FrontDoor => RouteHost::intercepted(
            &request.capability_slot,
            &request.route,
            &request.intercepted_host,
        )
        .map(Some)
        .ok_or(BrokerRequestError::InvalidRequest),
    }
}

#[cfg(test)]
mod tests;
