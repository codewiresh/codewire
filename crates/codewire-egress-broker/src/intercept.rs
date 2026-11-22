//! Handing an intercepted dial to the environment's front door (#3999).

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::atomic::Ordering;

use codewire_egress_policy::PolicyDecision;
use codewire_egress_policy::lease::{EgressLeaseTable, TcpInterception};
use codewire_egress_policy::record::{Destination, Transport};

use crate::{
    BrokerAdapterFailure, BrokerClock, BrokerConnection, BrokerError, BrokerTcpConnection,
    DnsResolver, PolicyEgressBroker, TcpAuthorization, TcpConnector,
};

/// Where an intercepted dial goes instead of being dialled: the environment's
/// front door. It returns the worker's end of a new byte stream whose other
/// end it has handed over; it never opens a network connection.
pub trait InterceptHandoff: Send + Sync + 'static {
    fn hand_off(&self, interception: &TcpInterception) -> Result<OwnedFd, BrokerAdapterFailure>;
}

/// Which interception set a dial was admitted under. A flow is recorded only
/// if the set has not been replaced since, so a replacement never misses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterceptRevision(pub(crate) u64);

impl<R, C, K> PolicyEgressBroker<R, C, K>
where
    R: DnsResolver,
    C: TcpConnector,
    K: BrokerClock,
{
    /// Admit a dial again, then dial it, or hand it to the front door when the
    /// table intercepts it. Without a hand-off, or when the hand-off fails, an
    /// intercepted dial is refused and counted as
    /// [`RefusalReason::InterceptUnavailable`]; it is never dialled.
    ///
    /// [`RefusalReason::InterceptUnavailable`]: codewire_egress_policy::lease::RefusalReason::InterceptUnavailable
    pub async fn connect_or_intercept(
        &self,
        destination: SocketAddr,
    ) -> Result<BrokerConnection<C::Stream>, BrokerError> {
        match self.admit_tcp(destination).await? {
            (TcpAuthorization::Dial(admission), revision) => {
                let stream = self
                    .connector
                    .connect(destination)
                    .await
                    .map_err(BrokerError::Connector)?;
                Ok(BrokerConnection::Dialled(BrokerTcpConnection {
                    stream,
                    admission,
                    revision,
                }))
            }
            (TcpAuthorization::Intercept(interception), revision) => {
                let Some(handoff) = self.handoff.as_ref() else {
                    let state = self.state.lock().await;
                    return Err(BrokerError::Denied(
                        self.refuse_interception(&state, interception),
                    ));
                };
                match handoff.hand_off(&interception) {
                    Ok(stream) => Ok(BrokerConnection::Intercepted {
                        stream,
                        interception,
                        revision,
                    }),
                    Err(_) => {
                        let state = self.state.lock().await;
                        Err(BrokerError::Denied(
                            self.refuse_interception(&state, interception),
                        ))
                    }
                }
            }
        }
    }

    /// Read only while `state` is held, so it matches the table it is read
    /// with.
    pub(crate) fn current_intercept_revision(&self) -> InterceptRevision {
        InterceptRevision(self.intercept_revision.load(Ordering::Acquire))
    }

    pub(crate) fn intercept_or_refuse(
        &self,
        state: &EgressLeaseTable,
        interception: TcpInterception,
    ) -> Result<TcpAuthorization, BrokerError> {
        if self.handoff.is_some() {
            Ok(TcpAuthorization::Intercept(interception))
        } else {
            Err(BrokerError::Denied(
                self.refuse_interception(state, interception),
            ))
        }
    }

    /// Refuses an intercepted dial as `intercept_unavailable`, recorded
    /// under the bound name it was for.
    pub(crate) fn refuse_interception(
        &self,
        state: &EgressLeaseTable,
        interception: TcpInterception,
    ) -> PolicyDecision {
        let destination = Destination::checked_name(interception.hostname());
        let (address, port) = (interception.address(), interception.port());
        let refusal = state.refuse_interception(interception);
        self.note(
            destination,
            Some(address),
            Transport::Tcp { port },
            &refusal,
        )
    }
}
