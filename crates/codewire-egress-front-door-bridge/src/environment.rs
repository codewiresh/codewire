//! One environment's front door, as its own process runs it (#3999).
//!
//! It starts before the environment boots: it generates the environment's
//! CA for its interception bindings and gives the supervisor only the CA
//! certificate. Later the supervisor hands it two sockets. On the credential
//! broker's it serves the guest side of a front-door bridge session; on the
//! egress broker's it receives the streams the guest dialled to a bound host,
//! terminates TLS for that host and hands each request to the bridge. It
//! holds no credentials and opens no connection.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use codewire_credential_bridge::{
    CredentialBridge, FrontDoorSessionError, SessionStream, serve_front_door_session,
};
use codewire_egress_front_door::{
    Accepted, CaError, EnvironmentCa, FrontDoor, FrontDoorConfig, FrontDoorError, HandBackReason,
};
use codewire_egress_policy::intercept::InterceptSet;
use tokio::net::UnixStream;
use tokio::task::JoinSet;
use uuid::Uuid;

use codewire_egress_policy::handoff::InterceptedStreamHeader;

use crate::handoff::{HandoffSocket, Received};
use crate::{CLAUDE_TOKEN_HOST, CredentialRouteBackend, GITHUB_HOSTS, RouteTable};

/// The only port a binding may name: the front door serves TLS.
pub const INTERCEPT_PORT: u16 = 443;
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
    #[error("the credential session ended")]
    Session(#[source] Option<FrontDoorSessionError>),
}

/// One environment's front door. See the module documentation.
pub struct EnvironmentFrontDoor {
    environment_id: String,
    intercepts: InterceptSet,
    bridge: CredentialBridge,
    door: Arc<FrontDoor<CredentialRouteBackend>>,
}

impl EnvironmentFrontDoor {
    /// Generate the environment's CA for the bound names. Nothing is served
    /// until [`Self::serve`].
    pub fn start(
        environment_id: Uuid,
        environment_generation: u64,
        intercepts: InterceptSet,
    ) -> Result<Self, StartError> {
        if intercepts.is_empty() {
            return Err(StartError::NoBindings);
        }
        if intercepts
            .bindings()
            .iter()
            .any(|binding| binding.port() != INTERCEPT_PORT)
        {
            return Err(StartError::Port);
        }
        let bridge = CredentialBridge::new(environment_id, environment_generation)
            .map_err(|_| StartError::Identity)?;
        // Bindings are sorted by name, so each name is listed once.
        let mut names: Vec<&str> = intercepts
            .bindings()
            .iter()
            .map(|binding| binding.hostname())
            .collect();
        names.dedup();
        let ca = EnvironmentCa::generate(names)?;
        // Claude's token host is bound only for a Claude sign-in and
        // GitHub's hosts only with a GitHub connection, once the boot chain
        // builds its intercepts from `RouteTable::for_clients` (#4809); each
        // route follows its binding. GitHub's two are bound together.
        let routes = RouteTable::with_optional_hosts(
            intercepts.binds(CLAUDE_TOKEN_HOST, INTERCEPT_PORT),
            GITHUB_HOSTS
                .iter()
                .all(|host| intercepts.binds(host, INTERCEPT_PORT)),
        );
        let backend = CredentialRouteBackend::new(routes, bridge.clone());
        let door = FrontDoor::new(ca, backend, FrontDoorConfig::default());
        Ok(Self {
            environment_id: environment_id.to_string(),
            intercepts,
            bridge,
            door: Arc::new(door),
        })
    }

    /// The CA certificate the guest trusts, in DER: all the supervisor gets.
    pub fn ca_certificate_der(&self) -> &[u8] {
        self.door.ca().certificate_der().as_ref()
    }

    /// Serve until the egress broker closes the hand-off socket or the
    /// credential session ends, then close every live connection. A front
    /// door that stops fails closed: the guest's next dial to a bound host
    /// reaches nothing.
    ///
    /// The caller has admitted both sockets before this: each is a connected
    /// Unix stream that closes on exec, and each peer's role tag has been
    /// read and checked, the egress broker's first frame on `handoff` and the
    /// credential broker's first byte on `credentials`. So a swapped pair
    /// never reaches here. The front-door process does that admission; this
    /// only checks that `handoff` is a connected Unix stream.
    pub async fn serve<S: SessionStream>(self, handoff: OwnedFd, credentials: S) -> Ended {
        let mut handoff = match HandoffSocket::new(handoff) {
            Ok(handoff) => handoff,
            Err(error) => return Ended::Handoff(error),
        };
        let mut streams = JoinSet::new();
        let session = serve_front_door_session(&self.bridge, credentials);
        tokio::pin!(session);
        let ended = loop {
            tokio::select! {
                result = &mut session => break Ended::Session(result.err()),
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
        streams.shutdown().await;
        ended
    }

    /// Serve one handed-over stream if it is for this environment and one of
    /// its own bindings; the broker is never trusted for either.
    fn admit(&self, streams: &mut JoinSet<()>, header: InterceptedStreamHeader, stream: OwnedFd) {
        let stream_id = header.stream_id;
        if header.environment_id != self.environment_id {
            tracing::warn!(stream_id, outcome = "other_environment");
            return;
        }
        if !self.intercepts.binds(&header.hostname, header.port) {
            tracing::warn!(stream_id, outcome = "unbound_host");
            return;
        }
        let stream = match unix_stream(stream) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(stream_id, %error, outcome = "stream_unusable");
                return;
            }
        };
        let door = Arc::clone(&self.door);
        streams.spawn(async move {
            let host = header.hostname;
            match door.accept(stream, &host).await {
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

/// A received descriptor as a non-blocking byte stream. Its peer address is
/// never read: the broker's end is a socket pair, not the guest's dial.
fn unix_stream(descriptor: OwnedFd) -> std::io::Result<UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(descriptor);
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

#[cfg(test)]
mod tests;
