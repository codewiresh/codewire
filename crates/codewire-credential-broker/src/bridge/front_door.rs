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
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    AdmittedCredentialBridge, BrokerBridgeError, BrokerRequestExecutor,
    CredentialBridgeResponseSink, CredentialBridgeTransport, run_managed_bridge,
};
use crate::runtime::FrontDoorSession;
use crate::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestBodyStream, BrokerRequestError,
    BrokerUpstreamTransport, OpenAiBroker,
};

/// Whether [`FrontDoorExecutor`] serves WebSocket upgrades. The Open a
/// [`FrontDoorTransport`] writes, before any executor exists, lists them from
/// this same value, so the two cannot disagree (#4973).
const FRONT_DOOR_SERVES_UPGRADES: bool = true;

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
        let session = FrontDoorHostSession::open(
            stream,
            identity,
            &codewire_credential_bridge::front_door_capabilities(FRONT_DOOR_SERVES_UPGRADES),
        )
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
    // One session from the start: the joining runner with a single join.
    let (joins, joining) = mpsc::channel(1);
    joins
        .try_send(front_door)
        .map_err(|_| BrokerBridgeError::Unavailable)?;
    drop(joins);
    // A local front door cannot open another session: it never idles out.
    run_admitted_credential_bridge_with_front_doors(
        broker.paired_with_front_door(),
        loopback,
        joining,
        None,
    )
    .await
}

/// [`run_admitted_credential_bridges`] for front-door sessions that join a
/// running loopback session, such as one relayed into a hosted epoch
/// (#4001). They are served one at a time, each as it arrives on `joins`; one
/// that ends, or fails, leaves the loopback session serving and the next may
/// join. When the loopback session ends, the front-door session then serving
/// is ended and drained, and no other joins. The caller admits at most one
/// session at a time; a later one waits here until the current one ends.
/// `idle` ends a front-door session with nothing in flight after that long,
/// and is only for peers that can open another (#4963).
pub async fn run_admitted_credential_bridge_with_front_doors<P, U, B, F>(
    broker: OpenAiBroker<P, U>,
    loopback: AdmittedCredentialBridge<B>,
    mut joins: mpsc::Receiver<AdmittedCredentialBridge<F>>,
    idle: Option<std::time::Duration>,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
    F: CredentialBridgeTransport,
{
    // The invariant (cw-security, 2026-11-17, #4001): a front door is never
    // served beside an agent's real login, however this runner was reached.
    if broker.login_delivery() == crate::runtime::LoginDelivery::Real {
        tracing::error!("credential bridge refused: a front door beside a real agent login");
        return Err(BrokerBridgeError::Unavailable);
    }
    let broker = Arc::new(broker);
    let ended = CancellationToken::new();
    let loopback = async {
        let result = run_managed_bridge(Arc::clone(&broker), loopback.bridge, None).await;
        ended.cancel();
        result
    };
    let front_doors = async {
        loop {
            let joined = tokio::select! {
                biased;
                () = ended.cancelled() => break,
                joined = joins.recv() => joined,
            };
            let Some(session) = joined else {
                // No more joins: keep serving loopback alone.
                ended.cancelled().await;
                break;
            };
            let stop = ended.child_token();
            let result = run_admitted_front_door_bridge(
                Arc::clone(&broker),
                session.stoppable(stop.clone()),
                idle,
            )
            .await;
            // A runner reports every end as an error; only an end the
            // loopback session did not cause is worth a line.
            if let Err(error) = result
                && !stop.is_cancelled()
            {
                tracing::warn!(%error, "front-door credential session ended");
            }
        }
        // Nothing joins once loopback has ended.
        joins.close();
    };
    let (result, ()) = tokio::join!(loopback, front_doors);
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
    idle: Option<std::time::Duration>,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
{
    let broker = Arc::new(FrontDoorExecutor::new(broker));
    run_managed_bridge(broker, bridge.bridge, idle).await
}

/// A front-door session's executor: its HTTP requests take the front-door
/// validation, and only it serves WebSocket handshakes. SSH, projections and
/// logins keep the trait's denial, since only a daemon inside an environment
/// asks for them. It holds this session's routing, made fresh for each
/// session and gone with it (#3999).
pub(crate) struct FrontDoorExecutor<P, U> {
    broker: Arc<OpenAiBroker<P, U>>,
    session: Arc<FrontDoorSession>,
}

impl<P, U> FrontDoorExecutor<P, U> {
    pub(crate) fn new(broker: Arc<OpenAiBroker<P, U>>) -> Self {
        Self {
            broker,
            session: Arc::default(),
        }
    }
}

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
        self.broker
            .execute_front_door_in(request, &self.session)
            .await
    }

    async fn execute_streamed_request(
        &self,
        request: v1::CredentialBridgeRequest,
        body: BrokerRequestBodyStream,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.broker
            .execute_front_door_streamed(request, body, &self.session)
            .await
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.broker.wait_for_active_operations().await
    }

    fn serves_upgrades(&self) -> bool {
        FRONT_DOOR_SERVES_UPGRADES
    }

    async fn execute_upgrade(
        &self,
        upgrade: v1::CredentialBridgeUpgrade,
    ) -> Result<crate::runtime::upgrade::BrokerUpgradeOutcome, BrokerRequestError> {
        self.broker.execute_front_door_upgrade(upgrade).await
    }

    async fn socket_grant_holds(&self, grant: &crate::runtime::upgrade::SocketGrant) -> bool {
        self.broker.socket_grant_holds(grant).await
    }
}
