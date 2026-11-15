//! The broker's end of a front-door session (#3999): the TLS front door
//! outside the environment speaks the guest side of the bridge on a socket
//! the supervisor gave both processes, and its requests take the front-door
//! validation (`BridgeEntry::FrontDoor`).

use std::sync::Arc;

use async_trait::async_trait;
use codewire_credential_bridge::{
    BridgeIdentity, FrontDoorHostSender, FrontDoorHostSession, SessionStream,
};
use codewire_daemon_proto::codewire::bridge::v1;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    AdmittedCredentialBridge, BrokerBridgeError, BrokerRequestExecutor,
    CredentialBridgeResponseSink, CredentialBridgeTransport, run_managed_bridge,
};
use crate::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestBodyStream, BrokerRequestError,
    BrokerUpstreamTransport, OpenAiBroker,
};

/// The host side of a front-door session. Its entry comes from which socket
/// the caller opened it on, never from anything the front door sends.
pub struct FrontDoorTransport {
    session: FrontDoorHostSession,
    stop: CancellationToken,
}

/// Sends a front-door session's responses, in order, with backpressure.
#[derive(Clone)]
pub struct FrontDoorResponseSink(FrontDoorHostSender);

impl FrontDoorTransport {
    /// Open a front-door session for this broker's own environment on
    /// `stream`, the front door's end of the supervisor's socket. Admit it
    /// with [`super::admit_credential_bridge`] like any bridge.
    pub async fn open<S: SessionStream>(
        stream: S,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<Self, BrokerBridgeError> {
        if environment_id.is_nil() || environment_generation == 0 {
            return Err(BrokerBridgeError::InvalidIdentity);
        }
        let identity = BridgeIdentity {
            environment_id,
            environment_generation,
        };
        let session = FrontDoorHostSession::open(stream, identity)
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)?;
        Ok(Self {
            session,
            stop: CancellationToken::new(),
        })
    }
}

#[async_trait]
impl CredentialBridgeTransport for FrontDoorTransport {
    type ResponseSink = FrontDoorResponseSink;

    fn response_sink(&self) -> Self::ResponseSink {
        FrontDoorResponseSink(self.session.sender())
    }

    /// Ends, as the front door closing would, once [`Self::stop`] is
    /// cancelled, so the runner drains its started operations.
    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        tokio::select! {
            biased;
            () = self.stop.cancelled() => Ok(None),
            message = self.session.receive() => {
                message.map_err(|_| BrokerBridgeError::Unavailable)
            }
        }
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for FrontDoorResponseSink {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError> {
        // The session writes Open itself, first, and refuses another.
        if matches!(
            payload,
            v1::credential_bridge_host_message::Payload::Open(_)
        ) {
            return Err(BrokerBridgeError::InvalidProtocol);
        }
        self.0
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

/// Serve an environment's loopback session and its front door's session on
/// one broker, so both share its leases and its one refresh at a time. Ends
/// when the loopback session ends, with its result; the front-door session is
/// then ended and drained. A front-door session that fails first leaves the
/// loopback one serving: the front door fails closed on its own.
pub async fn run_admitted_credential_bridges<P, U, B>(
    broker: OpenAiBroker<P, U>,
    loopback: AdmittedCredentialBridge<B>,
    front_door: AdmittedCredentialBridge<FrontDoorTransport>,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
{
    let broker = Arc::new(broker);
    let stop = front_door.bridge.stop.clone();
    let loopback = async {
        let result = run_managed_bridge(Arc::clone(&broker), loopback.bridge).await;
        stop.cancel();
        result
    };
    let front_door = async {
        let stopped = front_door.bridge.stop.clone();
        let result = run_admitted_front_door_bridge(Arc::clone(&broker), front_door).await;
        // A runner reports every end as an error; only an end the loopback
        // session did not cause is worth a line.
        if let Err(error) = result
            && !stopped.is_cancelled()
        {
            tracing::warn!(%error, "front-door credential session ended");
        }
    };
    let (result, ()) = tokio::join!(loopback, front_door);
    result
}

/// [`super::run_admitted_credential_bridge`] for a front-door session
/// (`BridgeEntry::FrontDoor`). Only the host process that accepted this
/// session from its own front door outside the environment may call it, never
/// for a session a peer inside an environment opened. Each request must name
/// a host its route sends to and is then served as on a loopback session; no
/// other operation is served.
pub async fn run_admitted_front_door_bridge<P, U, B>(
    broker: Arc<OpenAiBroker<P, U>>,
    bridge: AdmittedCredentialBridge<B>,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
{
    let broker = Arc::new(FrontDoorExecutor(broker));
    run_managed_bridge(broker, bridge.bridge).await
}

/// A front-door session's executor: its HTTP requests take the front-door
/// validation. SSH, projections and logins keep the trait's denial, since
/// only a daemon inside an environment asks for them.
pub(crate) struct FrontDoorExecutor<P, U>(pub(crate) Arc<OpenAiBroker<P, U>>);

#[async_trait]
impl<P, U> BrokerRequestExecutor for FrontDoorExecutor<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    async fn execute_request(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.0.execute_front_door(request).await
    }

    async fn execute_streamed_request(
        &self,
        request: v1::CredentialBridgeRequest,
        body: BrokerRequestBodyStream,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.0.execute_front_door_streamed(request, body).await
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.0.wait_for_active_operations().await
    }
}
