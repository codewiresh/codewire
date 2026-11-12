//! A request's session entry, which the runner the admitting host called
//! chose, reaching request validation (#3999).

use codewire_daemon_proto::codewire::bridge::v1;

use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestError, BrokerUpstreamTransport,
    OpenAiBroker, ValidatedGuestRequest,
};
use crate::bridge::BridgeEntry;
use crate::network::RouteHost;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// [`Self::execute`] for a request on a front-door session, which only
    /// the host process that admitted that session may call. The request must
    /// name the host it was intercepted for, one its slot's route sends to,
    /// and is then served exactly as [`Self::execute`] serves it. The only way
    /// in from outside this crate is the front-door bridge runner.
    pub(crate) async fn execute_front_door(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute_on(BridgeEntry::FrontDoor, request).await
    }

    pub(super) async fn execute_on(
        &self,
        entry: BridgeEntry,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let request = ValidatedGuestRequest::parse(entry, request)?;
        let slot = request.slot.clone();
        match self.execute_validated(request).await {
            Err(BrokerRequestError::ReconnectRequired) => {
                Ok(crate::reconnect::reconnect_required_response(&slot))
            }
            result => result,
        }
    }
}

/// The host a request on `entry` was intercepted for, checked before any
/// credential lease. A loopback request names none: the environment controls
/// every field of it. A front-door request must name one of its route's hosts.
pub(super) fn intercepted_host(
    entry: BridgeEntry,
    request: &v1::CredentialBridgeRequest,
) -> Result<Option<RouteHost>, BrokerRequestError> {
    match entry {
        BridgeEntry::Loopback if request.intercepted_host.is_empty() => Ok(None),
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
