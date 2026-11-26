//! A request's session entry, which the runner the admitting host called
//! chose, reaching request validation (#3999).

use std::net::IpAddr;
use std::sync::Arc;

use codewire_daemon_proto::codewire::bridge::v1;

use super::antigravity_token::ANTIGRAVITY_TOKEN_ROUTE;
use super::claude_token::CLAUDE_TOKEN_ROUTE;
use super::routed::FrontDoorSession;
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestBodyStream, BrokerRequestError,
    BrokerUpstreamTransport, OpenAiBroker, ValidatedGuestRequest,
};
use crate::bridge::BridgeEntry;
use crate::network::{RouteHost, routed_host};
use crate::network_policy;
use url::Url;

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
    /// credential is refused. `session` holds this front-door session's
    /// routing (#3999). The only way in from outside this crate is the
    /// front-door bridge runner.
    pub(crate) async fn execute_front_door_in(
        &self,
        request: v1::CredentialBridgeRequest,
        session: &Arc<FrontDoorSession>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_on(BridgeEntry::FrontDoor, request, None, Some(session))
            .await
    }

    /// [`Self::execute_front_door_in`] on a session of its own, which has
    /// recorded no routing.
    #[cfg(test)]
    pub(crate) async fn execute_front_door(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_front_door_in(request, &Arc::default()).await
    }

    /// [`Self::execute_front_door_in`] for a request whose body streams: only
    /// a request to one of GitHub's two hosts.
    pub(crate) async fn execute_front_door_streamed(
        &self,
        request: v1::CredentialBridgeRequest,
        body: BrokerRequestBodyStream,
        session: &Arc<FrontDoorSession>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_on(BridgeEntry::FrontDoor, request, Some(body), Some(session))
            .await
    }

    pub(super) async fn execute_on(
        &self,
        entry: BridgeEntry,
        request: v1::CredentialBridgeRequest,
        body: Option<BrokerRequestBodyStream>,
        session: Option<&Arc<FrontDoorSession>>,
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
                let session = session.ok_or(BrokerRequestError::InvalidRequest)?;
                self.execute_intercepted(request, body, session).await
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
    /// What a front-door request to the OpenAI API host is answered, before
    /// any lease, grant or credential read: the hosted untouched-forward
    /// rule's `selected_credential_only`, and elsewhere what any other
    /// front-door request without a swap rule is answered (#5215).
    fn openai_api_refusal(&self) -> BrokerRequestError {
        let target = Url::parse("https://api.openai.com/").expect("a fixed URL");
        match self.untouched_forward_allowed(&target, false) {
            Err(BrokerRequestError::SelectedCredentialOnly) => {
                BrokerRequestError::SelectedCredentialOnly
            }
            _ => BrokerRequestError::InvalidRequest,
        }
    }

    /// A front-door request, under the swap rule. The Anthropic route, Codex
    /// at `chatgpt.com` and GitHub's two hosts have it; any other front-door
    /// request is refused before a lease, never served by always injecting.
    /// The OpenAI API host is bound for a selected OpenAI API key, whose key
    /// is served only by the base URL's loopback route: in a hosted Sandbox
    /// it is refused by name (`selected_credential_only`, #5215).
    /// Claude's token host is answered or forwarded by its own rule
    /// (`claude_token.rs`), Codex's by its own (`codex_token.rs`), and
    /// GitHub's hosts by theirs (`github_front_door.rs`). Only a GitHub
    /// request may stream its body.
    async fn execute_intercepted(
        &self,
        request: ValidatedGuestRequest,
        body: Option<BrokerRequestBodyStream>,
        session: &Arc<FrontDoorSession>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        // Only Codex's model call goes to a routed origin.
        if request.routed.is_some() && request.slot.as_str() != "codex" {
            return Err(BrokerRequestError::InvalidRequest);
        }
        match (request.slot.as_str(), request.intercepted_host) {
            ("github", Some(host @ (RouteHost::GitHub | RouteHost::GitHubApi))) => {
                self.execute_github_intercepted(host, request, body).await
            }
            _ if body.is_some() => Err(BrokerRequestError::InvalidRequest),
            ("anthropic", _) if request.route.as_str() == CLAUDE_TOKEN_ROUTE => {
                self.execute_claude_token(request).await
            }
            ("anthropic", _) => self.execute_swap(request).await,
            ("codex", Some(RouteHost::ChatGpt)) => self.execute_codex_swap(request, session).await,
            ("codex", Some(RouteHost::CodexToken)) => self.execute_codex_token(request).await,
            ("gemini", Some(RouteHost::GeminiApi)) => self.execute_gemini_swap(request).await,
            (
                "antigravity",
                Some(host @ (RouteHost::AntigravityDaily | RouteHost::AntigravityProd)),
            ) => self.execute_antigravity_swap(host, request).await,
            ("antigravity", Some(RouteHost::AntigravityOAuth)) => {
                self.execute_antigravity_token(request).await
            }
            ("openai" | "codex", Some(RouteHost::OpenAiApi)) => Err(self.openai_api_refusal()),
            _ => Err(BrokerRequestError::InvalidRequest),
        }
    }
}

/// The host a request on `entry` was intercepted for, and for a name under a
/// routed suffix its dial, checked before any credential lease. A loopback
/// request names neither, nor an admitted address: the environment controls
/// every field of it. A front-door request must name one of its route's
/// hosts, or for Codex a name under a routed suffix, which takes the
/// ChatGPT host's route and is served only at its session's recorded origin.
/// Claude's token route and front-door-only providers (such as Gemini, #6555)
/// exist only behind the front door: a loopback request for them is refused.
pub(super) fn intercepted(
    entry: BridgeEntry,
    request: &v1::CredentialBridgeRequest,
) -> Result<(Option<RouteHost>, Option<super::routed::RoutedDial>), BrokerRequestError> {
    let invalid = BrokerRequestError::InvalidRequest;
    let destination = match request.destination_ip.as_str() {
        "" => None,
        _ if entry == BridgeEntry::Loopback => return Err(invalid),
        address => Some(address.parse::<IpAddr>().map_err(|_| invalid)?),
    };
    match entry {
        BridgeEntry::Loopback
            if request.intercepted_host.is_empty()
                && request.route != CLAUDE_TOKEN_ROUTE
                && request.capability_slot != "gemini"
                && request.route != crate::gemini::ROUTE
                && request.capability_slot != "antigravity"
                && request.route != crate::antigravity::ROUTE
                && request.route != ANTIGRAVITY_TOKEN_ROUTE =>
        {
            Ok((None, None))
        }
        BridgeEntry::Loopback => Err(invalid),
        BridgeEntry::FrontDoor => {
            let host = request.intercepted_host.as_str();
            if let Some(bound) =
                RouteHost::intercepted(&request.capability_slot, &request.route, host)
            {
                return Ok((Some(bound), None));
            }
            if (request.capability_slot.as_str(), request.route.as_str()) == ("codex", "openai-api")
                && routed_host(host)
            {
                let dial = super::routed::RoutedDial {
                    host: host.to_owned(),
                    destination,
                };
                return Ok((Some(RouteHost::ChatGpt), Some(dial)));
            }
            Err(invalid)
        }
    }
}

#[cfg(test)]
mod tests;
