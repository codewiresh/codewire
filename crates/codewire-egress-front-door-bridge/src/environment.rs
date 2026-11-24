//! One environment's front door, as its own process runs it (#3999).
//!
//! It starts before the environment boots: it generates the environment's
//! CA for its interception bindings and gives the supervisor only the CA
//! certificate. Later the supervisor hands it two sockets. On the credential
//! broker's it serves the guest side of a front-door bridge session, and so on
//! each successor broker's as it pairs; on the egress broker's it receives the
//! streams the guest dialled to a bound host, terminates TLS for that host and
//! hands each request to the bridge. It holds no credentials and opens no
//! connection.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use codewire_credential_bridge::{
    CredentialBridge, FrontDoorSessionError, SessionStream, serve_front_door_session,
};
use codewire_egress_front_door::{
    Accepted, CaError, EnvironmentCa, FrontDoor, FrontDoorConfig, FrontDoorError, HandBackReason,
    LeafSource,
};
use codewire_egress_policy::intercept::InterceptSet;
use tokio::net::UnixStream;
use tokio::task::JoinSet;
use uuid::Uuid;

use codewire_egress_policy::handoff::InterceptedStreamHeader;

use crate::handoff::{HandoffSocket, Received};

use crate::{CredentialRouteBackend, RefusalSink, RouteTable};

/// The only port a binding may name: the front door serves TLS.
pub const INTERCEPT_PORT: u16 = codewire_access::INTERCEPT_PORT;
/// How long one acknowledgement may wait for room on the hand-off socket.
pub const ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a front door could not start. Carries no secret.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("a front door needs at least one interception binding")]
    NoBindings,
    #[error("an interception binding names a port other than 443")]
    Port,
    #[error("the environment identity is invalid")]
    Identity,
    #[error("the environment CA could not be generated: {0}")]
    Ca(#[from] CaError),
}

/// How a running front door ended. Either way it has stopped serving.
#[derive(Debug, thiserror::Error)]
pub enum Ended {
    #[error("the egress broker closed the hand-off socket")]
    HandoffClosed,
    #[error("the hand-off socket failed")]
    Handoff(#[source] std::io::Error),
    #[error("no further credential session can arrive")]
    SessionsClosed,
}

/// One environment's front door. See the module documentation. Its leaves
/// come from its own CA on a local VM, and from the credential service's
/// signer on hosted ([`codewire_egress_front_door::SignedLeaves`], #4001).
pub struct EnvironmentFrontDoor<L = EnvironmentCa> {
    /// The identity the egress broker stamps on each stream it hands over.
    handoff_identity: String,
    intercepts: InterceptSet,
    bridge: CredentialBridge,
    door: Arc<FrontDoor<CredentialRouteBackend, L>>,
    /// Places for streams waiting for the front door to be able to serve
    /// ([`ready`]), as many as its connections: a waiting stream holds no
    /// connection permit yet, so this bounds them instead.
    waiting: Arc<tokio::sync::Semaphore>,
}

impl EnvironmentFrontDoor {
    /// Generate the environment's CA for the bound names. Nothing is served
    /// until [`Self::serve`].
    pub fn start(
        environment_id: Uuid,
        environment_generation: u64,
        intercepts: InterceptSet,
    ) -> Result<Self, StartError> {
        Self::start_reporting(environment_id, environment_generation, intercepts, None)
    }

    /// [`Self::start`], reporting every refusal to `refusals` when given
    /// (#5058).
    pub fn start_reporting(
        environment_id: Uuid,
        environment_generation: u64,
        intercepts: InterceptSet,
        refusals: Option<Arc<dyn RefusalSink>>,
    ) -> Result<Self, StartError> {
        check_intercepts(&intercepts)?;
        // Bindings are sorted by name, so each name is listed once.
        let mut names: Vec<&str> = intercepts
            .bindings()
            .iter()
            .map(|binding| binding.hostname())
            .collect();
        names.dedup();
        let suffixes = intercepts.suffixes().iter().map(|suffix| suffix.suffix());
        let ca = EnvironmentCa::generate_with_suffixes(names, suffixes)?;
        Self::build(
            environment_id,
            environment_generation,
            intercepts,
            ca,
            refusals,
        )
    }

    /// The CA certificate the guest trusts, in DER: all the supervisor gets.
    pub fn ca_certificate_der(&self) -> &[u8] {
        self.door.ca().certificate_der().as_ref()
    }
}

/// The bindings a front door may serve: at least one, each name and suffix
/// on 443.
fn check_intercepts(intercepts: &InterceptSet) -> Result<(), StartError> {
    if intercepts.is_empty() {
        return Err(StartError::NoBindings);
    }
    if intercepts
        .bindings()
        .iter()
        .any(|binding| binding.port() != INTERCEPT_PORT)
        || intercepts
            .suffixes()
            .iter()
            .any(|suffix| suffix.port() != INTERCEPT_PORT)
    {
        return Err(StartError::Port);
    }
    Ok(())
}

impl<L: LeafSource> EnvironmentFrontDoor<L> {
    /// A front door serving `intercepts` with `leaves`. A host `leaves` holds
    /// no current leaf for fails closed at its handshake. Nothing is served
    /// until [`Self::serve`].
    pub fn with_leaves(
        environment_id: Uuid,
        environment_generation: u64,
        intercepts: InterceptSet,
        leaves: L,
    ) -> Result<Self, StartError> {
        Self::build(
            environment_id,
            environment_generation,
            intercepts,
            leaves,
            None,
        )
    }

    fn build(
        environment_id: Uuid,
        environment_generation: u64,
        intercepts: InterceptSet,
        leaves: L,
        refusals: Option<Arc<dyn RefusalSink>>,
    ) -> Result<Self, StartError> {
        check_intercepts(&intercepts)?;
        let bridge = CredentialBridge::new(environment_id, environment_generation)
            .map_err(|_| StartError::Identity)?;
        // Each route follows its binding: the boot chain binds exactly the
        // hosts its selected credentials name (`RouteTable::for_clients`,
        // #5215), so the front door routes those and no others.
        let routes = RouteTable::serving(|host| intercepts.binds(host, INTERCEPT_PORT))
            .ok_or(StartError::NoBindings)?;
        let backend = CredentialRouteBackend::new(routes, bridge.clone());
        let backend = match refusals {
            Some(sink) => backend.reporting_refusals(sink),
            None => backend,
        };
        let door = FrontDoor::new(leaves, backend, FrontDoorConfig::default());
        Ok(Self {
            handoff_identity: environment_id.to_string(),
            intercepts,
            bridge,
            door: Arc::new(door),
            waiting: Arc::new(tokio::sync::Semaphore::new(
                codewire_egress_front_door::DEFAULT_MAX_CONNECTIONS,
            )),
        })
    }

    /// Admit only streams the egress broker stamps with `identity` rather
    /// than the environment's: a hosted Pod's broker is bound to the Pod,
    /// whose own front door this is (#4001).
    #[must_use]
    pub fn handed_off_as(mut self, identity: Uuid) -> Self {
        self.handoff_identity = identity.to_string();
        self
    }

    /// At most `places` streams waiting at once, for a test of the bound.
    #[cfg(test)]
    fn waiting_at_most(mut self, places: usize) -> Self {
        self.waiting = Arc::new(tokio::sync::Semaphore::new(places));
        self
    }

    /// Serve until the egress broker closes the hand-off socket or `later`
    /// ends, then close every live connection. A front door that stops fails
    /// closed: the guest's next dial to a bound host reaches nothing.
    ///
    /// `credentials` is the first credential broker's session, and `later`
    /// yields each successor's as it pairs: the credential authority replaces
    /// a generation's broker every few minutes (#3999). Each new session takes
    /// all new work while the one it replaces finishes the requests already
    /// sent on it. A session that ends without a successor leaves requests
    /// failing closed at the bridge until one pairs, and so does starting
    /// with none, as a hosted front door does until its session opens.
    ///
    /// The caller has admitted every socket before this: each is a connected
    /// Unix stream that closes on exec, and each peer's role tag has been
    /// read and checked, the egress broker's first frame on `handoff` and the
    /// credential broker's first byte on each session. So a swapped pair
    /// never reaches here. The front-door process does that admission; this
    /// only checks that `handoff` is a connected Unix stream.
    pub async fn serve<S: SessionStream>(
        self,
        handoff: OwnedFd,
        credentials: Option<S>,
        mut later: tokio::sync::mpsc::Receiver<S>,
    ) -> Ended {
        let mut handoff = match HandoffSocket::new(handoff) {
            Ok(handoff) => handoff,
            Err(error) => return Ended::Handoff(error),
        };
        let mut streams = JoinSet::new();
        let mut sessions = Sessions::default();
        if let Some(credentials) = credentials {
            sessions.attach(&self.bridge, credentials);
        }
        let ended = loop {
            tokio::select! {
                next = later.recv() => match next {
                    Some(credentials) => sessions.attach(&self.bridge, credentials),
                    None => break Ended::SessionsClosed,
                },
                Some(ended) = sessions.next_ended() => {
                    let outcome = match ended {
                        Ok(Ok(())) => "ended",
                        Ok(Err(_)) => "failed",
                        Err(error) if error.is_cancelled() => "replaced",
                        Err(_) => "panicked",
                    };
                    tracing::info!(outcome, "credential session");
                }
                received = handoff.receive() => match received {
                    Ok(Received::Stream(header, stream)) => {
                        // Acknowledged before any check: the descriptor is
                        // held here now, whatever becomes of it. A broker that
                        // stops reading acknowledgements fails the front door
                        // closed rather than hanging it.
                        let acknowledged = tokio::time::timeout(
                            ACKNOWLEDGEMENT_TIMEOUT,
                            handoff.acknowledge(header.stream_id),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "hand-off acknowledgement timed out",
                            ))
                        });
                        if let Err(error) = acknowledged {
                            break Ended::Handoff(error);
                        }
                        self.admit(&mut streams, header, stream);
                    }
                    Ok(Received::Closed) => break Ended::HandoffClosed,
                    Err(error) => break Ended::Handoff(error),
                },
                Some(_) = streams.join_next() => {}
            }
        };
        self.door.close();
        sessions.live.shutdown().await;
        streams.shutdown().await;
        ended
    }

    /// Serve one handed-over stream if it is for this environment and one of
    /// its own bindings; the broker is never trusted for either.
    fn admit(&self, streams: &mut JoinSet<()>, header: InterceptedStreamHeader, stream: OwnedFd) {
        let stream_id = header.stream_id;
        if header.environment_id != self.handoff_identity {
            tracing::warn!(stream_id, outcome = "other_environment");
            return;
        }
        if !self.intercepts.binds(&header.hostname, header.port) {
            tracing::warn!(stream_id, outcome = "unbound_host");
            return;
        }
        // The other bound names at the dialled address, of which the client
        // may have asked for any (#3999); only this front door's own count.
        let mut names = vec![header.hostname.clone()];
        names.extend(
            header
                .aliases
                .iter()
                .filter(|alias| self.intercepts.binds(alias, header.port))
                .cloned(),
        );
        let stream = match unix_stream(stream) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(stream_id, %error, outcome = "stream_unusable");
                return;
            }
        };
        let door = Arc::clone(&self.door);
        let bridge = self.bridge.clone();
        // A stream with no place to wait is accepted at once, and fails closed
        // as it would have before the front door could serve.
        let waiting = Arc::clone(&self.waiting).try_acquire_owned().ok();
        streams.spawn(async move {
            let host = header.hostname;
            let destination = std::net::IpAddr::V4(header.destination_ip);
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            if let Some(place) = waiting {
                ready(&door, &bridge).await;
                drop(place);
            }
            match door.accept_to(stream, &names, Some(destination)).await {
                Ok(Accepted::Served(_)) => {}
                // No hand-back: the guest dialled a bound address, so another
                // server name is refused, not passed. Dropping closes it.
                Ok(Accepted::HandBack { reason, .. }) => {
                    let outcome = match reason {
                        HandBackReason::OtherServerName => "other_server_name",
                        HandBackReason::NoServerName => "no_server_name",
                        HandBackReason::NotClientHello => "not_client_hello",
                    };
                    tracing::info!(stream_id, host, outcome);
                }
                Err(FrontDoorError::AtCapacity) => {
                    tracing::warn!(stream_id, host, outcome = "at_capacity");
                }
                Err(error) => tracing::debug!(stream_id, host, %error),
            }
        });
    }
}

/// The most credential sessions served at once: a renewed broker's
/// predecessor, draining, and its successor.
const MAX_SESSIONS: usize = 2;

/// How long a hosted front door's stream waits for it to be able to serve:
/// the first leaves installed and a credential epoch active (#6267). A
/// freshly bound Pod has both within seconds of its bind; this stays under
/// the 10 seconds common TLS clients allow a connection to set up.
pub const FIRST_SERVE_WAIT: Duration = Duration::from_secs(8);

/// For a front door whose leaves arrive after it starts, as a hosted one's
/// do, waits at most [`FIRST_SERVE_WAIT`] in all for its first install and
/// its first credential epoch; once each has happened it is not waited for
/// again. Then the stream is accepted whatever the outcome: a host with no
/// leaf still fails closed at its handshake, and a request with no epoch is
/// still refused. A front door that holds its leaves from the start, as a
/// local VM's does, never waits.
async fn ready<L: LeafSource>(
    door: &FrontDoor<CredentialRouteBackend, L>,
    bridge: &CredentialBridge,
) {
    let Some(mut installed) = door.ca().first_installed() else {
        return;
    };
    let deadline = tokio::time::Instant::now() + FIRST_SERVE_WAIT;
    let _ = tokio::time::timeout_at(deadline, installed.wait_for(|installed| *installed)).await;
    bridge.wait_for_first_epoch(deadline).await;
}

/// The live credential sessions, oldest first.
#[derive(Default)]
struct Sessions {
    live: JoinSet<Result<(), FrontDoorSessionError>>,
    order: std::collections::VecDeque<tokio::task::AbortHandle>,
    /// Sessions ended because a third paired, counted for the log.
    replaced: u64,
}

impl Sessions {
    /// Serve one broker's session beside the one it replaces. Past
    /// [`MAX_SESSIONS`] the oldest is ended first, so a broker that keeps
    /// pairing cannot pile sessions up, and a stuck predecessor never locks
    /// out its successor.
    fn attach<S: SessionStream>(&mut self, bridge: &CredentialBridge, credentials: S) {
        if self.order.len() >= MAX_SESSIONS
            && let Some(oldest) = self.order.pop_front()
        {
            oldest.abort();
            self.replaced += 1;
            tracing::warn!(
                replaced = self.replaced,
                outcome = "oldest_ended",
                "credential session"
            );
        }
        let bridge = bridge.clone();
        let session = self
            .live
            .spawn(async move { serve_front_door_session(&bridge, credentials).await });
        self.order.push_back(session);
    }

    /// The next session to end, and how; `None` while none is live.
    async fn next_ended(
        &mut self,
    ) -> Option<Result<Result<(), FrontDoorSessionError>, tokio::task::JoinError>> {
        let ended = self.live.join_next_with_id().await?;
        let id = match &ended {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        self.order.retain(|session| session.id() != id);
        Some(ended.map(|(_, result)| result))
    }
}

/// A received descriptor as a non-blocking byte stream. Its peer address is
/// never read: the broker's end is a socket pair, not the guest's dial.
fn unix_stream(descriptor: OwnedFd) -> std::io::Result<UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(descriptor);
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

#[cfg(test)]
mod tests;
