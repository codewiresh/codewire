//! `OpenHostTunnel` (#3609, slice 2): the host's half of a tunnel that one
//! of its sessions was asked for ([`crate::api::host_tunnels`]).
//!
//! Every frame is untrusted until proven. The first must be `open`, naming
//! a tunnel this replica is waiting for, for that host, signed with the
//! host's key over the nonce it was sent. Anything else ends the stream
//! with the same `unauthenticated`. Then exactly one `ready`, carrying the
//! daemon capability, or one `failed`; only then do bytes flow. The tunnel
//! ends with either side, or with the session that asked for it.

use std::time::Duration;

use codewire_proto::codewire::v1::{
    OpenHostTunnelRequest, OpenHostTunnelResponse, open_host_tunnel_request,
    open_host_tunnel_response,
};
use connectrpc::{ConnectError, InboundStream};
use futures::StreamExt as _;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::api::host_session::{attaching_host, proves_tunnel};
use crate::api::host_tunnels::{HostTunnels, OpenedTunnel, Pending, TUNNEL_OPEN_SECS, TunnelError};

/// A daemon capability is short; anything longer is not one.
const MAX_CAPABILITY_BYTES: usize = 512;
/// A host's reason a tunnel failed, as recorded.
const MAX_REASON_BYTES: usize = 1024;
/// Buffered between the tunnel and its caller, each way.
const TUNNEL_BUFFER_BYTES: usize = 64 * 1024;
/// The largest data frame sent to the host.
const MAX_FRAME_BYTES: usize = 32 * 1024;

type Outbound = mpsc::Sender<Result<OpenHostTunnelResponse, ConnectError>>;

fn unrecognised() -> ConnectError {
    ConnectError::unauthenticated("the tunnel is not recognised")
}

pub(super) async fn run(
    pool: PgPool,
    tunnels: Arc<HostTunnels>,
    mut requests: InboundStream<OpenHostTunnelRequest>,
    tx: Outbound,
) {
    if let Err(error) = tunnel(&pool, &tunnels, &mut requests, &tx).await {
        // The host may already be gone; then nobody is told.
        let _ = tx.send(Err(error)).await;
    }
}

/// The next frame by `deadline`, or `None` at the end of the stream.
async fn next_input(
    requests: &mut InboundStream<OpenHostTunnelRequest>,
    deadline: Instant,
) -> Result<Option<open_host_tunnel_request::Input>, ConnectError> {
    let next = tokio::time::timeout_at(deadline, requests.next())
        .await
        .map_err(|_| unrecognised())?;
    match next {
        None => Ok(None),
        Some(Err(error)) => Err(error),
        Some(Ok(request)) => Ok(request.to_owned_message().input),
    }
}

async fn tunnel(
    pool: &PgPool,
    tunnels: &HostTunnels,
    requests: &mut InboundStream<OpenHostTunnelRequest>,
    tx: &Outbound,
) -> Result<(), ConnectError> {
    let deadline = Instant::now() + Duration::from_secs(TUNNEL_OPEN_SECS);
    let Some(open_host_tunnel_request::Input::Open(open)) = next_input(requests, deadline).await?
    else {
        return Err(unrecognised());
    };
    let pending = admit(
        pool,
        tunnels,
        &open.host_id,
        &open.tunnel_id,
        &open.signature,
    )
    .await?;
    let daemon_capability = match next_input(requests, deadline).await? {
        Some(open_host_tunnel_request::Input::Ready(ready)) => {
            let capability = Zeroizing::new(ready.daemon_capability);
            if capability.is_empty() || capability.len() > MAX_CAPABILITY_BYTES {
                return Err(ConnectError::invalid_argument(
                    "the daemon capability is malformed",
                ));
            }
            capability
        }
        Some(open_host_tunnel_request::Input::Failed(failure)) => {
            let reason = bounded(&format!("{}: {}", failure.code, failure.message));
            // The caller may have given up already; then nobody is told.
            let _ = pending.opened.send(Err(TunnelError::Refused(reason)));
            return Ok(());
        }
        _ => return Err(ConnectError::invalid_argument("expected ready or failed")),
    };
    let (ours, theirs) = tokio::io::duplex(TUNNEL_BUFFER_BYTES);
    let opened = OpenedTunnel {
        stream: theirs,
        daemon_capability,
    };
    if pending.opened.send(Ok(opened)).is_err() {
        // The caller stopped waiting: nothing to carry.
        return Ok(());
    }
    pump(ours, requests, tx, &pending.session).await
}

/// The pending tunnel `tunnel_id`, when the host proves it was asked for it.
/// Every refusal looks the same.
async fn admit(
    pool: &PgPool,
    tunnels: &HostTunnels,
    host_id: &str,
    tunnel_id: &str,
    signature: &[u8],
) -> Result<Pending, ConnectError> {
    // Checked before the tunnel is taken, so an open that fails them spends
    // nothing.
    let (pending_host, nonce) = tunnels.pending_proof(tunnel_id).ok_or_else(unrecognised)?;
    if pending_host != host_id {
        return Err(unrecognised());
    }
    let host = attaching_host(pool, host_id).await.map_err(|error| {
        tracing::error!(error = %error, "host tunnel storage failed");
        ConnectError::internal("host tunnel storage failed")
    })?;
    match host {
        Some(host)
            if host.revoked_at.is_none() && proves_tunnel(&host, tunnel_id, &nonce, signature) =>
        {
            tunnels.take_pending(tunnel_id).ok_or_else(unrecognised)
        }
        _ => Err(unrecognised()),
    }
}

fn bounded(text: &str) -> String {
    let mut end = text.len().min(MAX_REASON_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Carries bytes between the caller's end of the tunnel and the host until
/// either ends, or the session that asked for it does.
async fn pump(
    stream: DuplexStream,
    requests: &mut InboundStream<OpenHostTunnelRequest>,
    tx: &Outbound,
    session: &CancellationToken,
) -> Result<(), ConnectError> {
    let (mut from_caller, mut to_caller) = tokio::io::split(stream);
    let mut buffer = vec![0; MAX_FRAME_BYTES];
    let mut host_open = true;
    loop {
        tokio::select! {
            () = session.cancelled() => return Ok(()),
            read = from_caller.read(&mut buffer) => {
                let read = read.map_err(|_| ConnectError::internal("host tunnel I/O failed"))?;
                if read == 0 {
                    return Ok(());
                }
                let frame = OpenHostTunnelResponse {
                    output: Some(open_host_tunnel_response::Output::Data(buffer[..read].to_vec())),
                    ..Default::default()
                };
                if tx.send(Ok(frame)).await.is_err() {
                    return Ok(());
                }
            }
            input = requests.next(), if host_open => match input {
                // The host ended its side; the caller still reads what came.
                None => {
                    host_open = false;
                    // Already closed by the caller is the same end.
                    let _ = to_caller.shutdown().await;
                }
                Some(Err(error)) => return Err(error),
                Some(Ok(request)) => match request.to_owned_message().input {
                    Some(open_host_tunnel_request::Input::Data(bytes)) => {
                        if to_caller.write_all(&bytes).await.is_err() {
                            return Ok(());
                        }
                    }
                    _ => return Err(ConnectError::invalid_argument("expected data")),
                },
            },
        }
    }
}
