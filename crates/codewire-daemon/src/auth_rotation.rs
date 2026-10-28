//! A local guest daemon's rotating authority (#3046 R4).
//!
//! A local VM restored from a VM checkpoint resumes with the capturing boot's
//! daemon in memory. Before the workload thaws, the guest moves that daemon to
//! the restored boot's identity: a new daemon token, and a new credential
//! bridge identity (environment id and generation). Each rotation bumps the
//! token's epoch and ends every connection accepted under an older epoch, so
//! no stream admitted with the old token outlives it, and the old token is
//! refused from then on. Durable sessions belong to the session engine, not
//! to a connection: they keep running and a client reattaches with the new
//! token. Hosted daemons never rotate.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};

use codewire_credential_bridge::CredentialBridge as SharedCredentialBridge;
use codewire_daemon_proto::DaemonAuthToken;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tonic::Status;
use tonic::transport::server::Connected;
use uuid::Uuid;

/// The identity a restored boot rotates the daemon to.
pub struct RotatedIdentity {
    pub token: DaemonAuthToken,
    pub environment_id: Uuid,
    pub environment_generation: u64,
}

/// The daemon token in force and the epoch it was admitted in.
#[derive(Clone)]
pub(crate) struct DaemonAuth {
    current: Arc<RwLock<Current>>,
}

struct Current {
    token: DaemonAuthToken,
    epoch: u64,
    /// Cancelled when this epoch ends; connections accepted in it end too.
    ended: CancellationToken,
}

impl DaemonAuth {
    pub(crate) fn new(token: DaemonAuthToken) -> Self {
        Self {
            current: Arc::new(RwLock::new(Current {
                token,
                epoch: 0,
                ended: CancellationToken::new(),
            })),
        }
    }

    /// Checks a presented token against the current one in constant time.
    pub(crate) fn authorize(&self, presented: Option<&str>) -> Result<(), Status> {
        let Some(presented) = presented else {
            return Err(Status::unauthenticated("missing daemon auth token"));
        };
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        if !bool::from(
            presented
                .as_bytes()
                .ct_eq(current.token.expose_secret().as_bytes()),
        ) {
            return Err(Status::unauthenticated("invalid daemon auth token"));
        }
        Ok(())
    }

    /// How many times the token has rotated.
    #[cfg(test)]
    pub(crate) fn epoch(&self) -> u64 {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .epoch
    }

    /// Wraps a connection accepted now, so it ends with the current epoch.
    pub(crate) fn bind_connection<IO>(&self, inner: IO) -> EpochIo<IO> {
        let ended = self
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .ended
            .clone();
        EpochIo {
            inner,
            waiting: Box::pin(ended.clone().cancelled_owned()),
            ended,
        }
    }

    /// Replaces the token and ends the epoch it was admitted in, returning
    /// the new epoch.
    fn rotate(&self, token: DaemonAuthToken) -> u64 {
        let (epoch, ended) = {
            let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
            current.token = token;
            current.epoch += 1;
            let ended = std::mem::replace(&mut current.ended, CancellationToken::new());
            (current.epoch, ended)
        };
        ended.cancel();
        epoch
    }
}

type RotationReply = oneshot::Sender<Result<u64, Status>>;

/// The guest's handle for rotating its daemon. Each rotation returns the new
/// epoch once the bridge and the token have both moved.
#[derive(Clone)]
pub struct AuthRotation {
    requests: mpsc::Sender<(RotatedIdentity, RotationReply)>,
}

/// The daemon's end of [`AuthRotation`], given to
/// [`crate::serve_native_grpc_with_incoming`].
pub struct RotationRequests {
    receiver: mpsc::Receiver<(RotatedIdentity, RotationReply)>,
}

/// A connected rotation handle and the daemon's end of it.
pub fn rotation_channel() -> (AuthRotation, RotationRequests) {
    let (requests, receiver) = mpsc::channel(1);
    (AuthRotation { requests }, RotationRequests { receiver })
}

impl AuthRotation {
    /// Rotates the serving daemon to `identity`. On success the old token is
    /// refused, every connection admitted with it has ended, and the
    /// credential bridge serves only `identity`. On an error nothing changed.
    pub async fn rotate(&self, identity: RotatedIdentity) -> Result<u64, Status> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send((identity, reply))
            .await
            .map_err(|_| Status::unavailable("the daemon is not serving"))?;
        answer
            .await
            .map_err(|_| Status::unavailable("the daemon stopped during rotation"))?
    }
}

/// Serves rotations for one daemon until every [`AuthRotation`] is dropped.
pub(crate) async fn serve_rotations(
    mut requests: RotationRequests,
    auth: DaemonAuth,
    bridge: Option<SharedCredentialBridge>,
) {
    while let Some((identity, reply)) = requests.receiver.recv().await {
        let _ = reply.send(rotate(&auth, bridge.as_ref(), identity).await);
    }
}

async fn rotate(
    auth: &DaemonAuth,
    bridge: Option<&SharedCredentialBridge>,
    identity: RotatedIdentity,
) -> Result<u64, Status> {
    if identity.environment_id.is_nil() || identity.environment_generation == 0 {
        return Err(Status::invalid_argument("rotated identity is invalid"));
    }
    // The bridge moves first: every request of the old identity has failed
    // before the new token can admit anyone.
    if let Some(bridge) = bridge {
        bridge
            .rotate_identity(identity.environment_id, identity.environment_generation)
            .await?;
    }
    Ok(auth.rotate(identity.token))
}

/// A connection that ends when the epoch it was accepted in ends.
pub(crate) struct EpochIo<IO> {
    inner: IO,
    ended: CancellationToken,
    waiting: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl<IO> EpochIo<IO> {
    fn poll_ended(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if self.ended.is_cancelled() || self.waiting.as_mut().poll(cx).is_ready() {
            return Poll::Ready(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the daemon token this connection used was rotated",
            ));
        }
        Poll::Pending
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for EpochIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_ended(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for EpochIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_ended(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_ended(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_ended(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<IO: Connected> Connected for EpochIo<IO> {
    type ConnectInfo = IO::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn token(value: &str) -> DaemonAuthToken {
        DaemonAuthToken::new(value).unwrap()
    }

    #[test]
    fn the_old_token_is_refused_after_a_rotation() {
        let auth = DaemonAuth::new(token("synthetic-before"));
        auth.authorize(Some("synthetic-before")).unwrap();
        assert_eq!(
            auth.authorize(None).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(auth.rotate(token("synthetic-after")), 1);
        assert_eq!(auth.epoch(), 1);
        assert_eq!(
            auth.authorize(Some("synthetic-before")).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        auth.authorize(Some("synthetic-after")).unwrap();
    }

    #[tokio::test]
    async fn connections_of_an_older_epoch_end_and_newer_ones_do_not() {
        let auth = DaemonAuth::new(token("synthetic-before"));
        let (old, mut old_peer) = tokio::io::duplex(64);
        let mut old = auth.bind_connection(old);
        old_peer.write_all(b"x").await.unwrap();
        let mut byte = [0_u8; 1];
        old.read_exact(&mut byte).await.unwrap();

        // A read already waiting on the old connection is woken by the end.
        let pending = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let result = old.read_exact(&mut byte).await;
            (result, old)
        });
        tokio::task::yield_now().await;
        auth.rotate(token("synthetic-after"));
        let (result, mut old) = tokio::time::timeout(std::time::Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            old.write_all(b"y").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );

        let (new, mut new_peer) = tokio::io::duplex(64);
        let mut new = auth.bind_connection(new);
        new_peer.write_all(b"z").await.unwrap();
        new.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"z");
        new.write_all(b"w").await.unwrap();
    }

    #[tokio::test]
    async fn rotation_moves_the_bridge_before_the_token() {
        let environment = Uuid::new_v4();
        let bridge = SharedCredentialBridge::new(environment, 3).unwrap();
        let auth = DaemonAuth::new(token("synthetic-before"));
        let (rotation, requests) = rotation_channel();
        let server = tokio::spawn(serve_rotations(
            requests,
            auth.clone(),
            Some(bridge.clone()),
        ));

        let fork = Uuid::new_v4();
        let epoch = rotation
            .rotate(RotatedIdentity {
                token: token("synthetic-after"),
                environment_id: fork,
                environment_generation: 1,
            })
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(bridge.identity().environment_id, fork);
        assert_eq!(bridge.identity().environment_generation, 1);
        auth.authorize(Some("synthetic-after")).unwrap();

        // An invalid identity changes nothing.
        let error = rotation
            .rotate(RotatedIdentity {
                token: token("synthetic-never"),
                environment_id: Uuid::nil(),
                environment_generation: 2,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(auth.epoch(), 1);
        auth.authorize(Some("synthetic-after")).unwrap();
        assert_eq!(bridge.identity().environment_id, fork);

        drop(rotation);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
