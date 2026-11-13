//! Streamed request bodies (#4280). A GitHub Git POST on an epoch whose host
//! lists [`CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM`] sends its body
//! in bounded chunks under the host's frame credit instead of collecting it
//! whole, so an HTTPS push has no size limit and neither side holds more than
//! a window of it. Every other request, and every request on an older host's
//! epoch, carries its whole body in the request frame as before.
//!
//! Time bounds the stream instead of size: the client must send a byte, and
//! the host must grant credit, within [`CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT`];
//! once the body is complete the host may take up to
//! [`CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT`] to answer.

use std::future::Future;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, StatusCode};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT, CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES, CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
    CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT,
};
use tokio::sync::{Semaphore, oneshot};
use tokio_stream::StreamExt as _;

use super::{GuestOutput, HOST_SEND_TIMEOUT, guest_message, v1};

/// The only route whose requests stream their body: the GitHub Git family.
const STREAMED_ROUTE: &str = "github-https";

/// How long after the body is complete this side waits for the response to
/// start. It outlasts the host's own bound so the host's failure answers first.
const FIRST_RESPONSE_AFTER_BODY: std::time::Duration =
    CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT
        .saturating_add(std::time::Duration::from_secs(30));

/// Whether a host's Open lists streamed request bodies.
pub(super) fn listed(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM)
}

/// Whether this request would stream its body on an epoch that lists it.
pub(super) fn streamable(route: &str, method: &Method) -> bool {
    route == STREAMED_ROUTE && method == Method::POST
}

/// The frames a streamed request may still send: the host's unspent credit.
#[derive(Clone)]
pub(super) struct RequestCredit(Arc<Semaphore>);

impl RequestCredit {
    pub(super) fn new() -> Self {
        Self(Arc::new(Semaphore::new(0)))
    }

    /// Add a host grant. A host never has more than one window outstanding,
    /// so a grant past it is an invalid frame.
    pub(super) fn grant(&self, frames: u32) -> Result<(), ()> {
        let window = CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES as usize;
        let frames = frames as usize;
        if frames == 0 || self.0.available_permits().saturating_add(frames) > window {
            return Err(());
        }
        self.0.add_permits(frames);
        Ok(())
    }

    async fn spend(&self) -> Result<(), UploadFailure> {
        let permit = tokio::time::timeout(CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT, self.0.acquire())
            .await
            .map_err(|_| UploadFailure::HostStalled)?
            .map_err(|_| UploadFailure::HostLost)?;
        permit.forget();
        Ok(())
    }
}

/// Why a streamed body did not reach the host whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UploadFailure {
    /// The client sent no byte for the idle bound.
    ClientStalled,
    /// The client's body failed.
    ClientFailed,
    /// The host granted no credit for the idle bound.
    HostStalled,
    /// The epoch's output closed or stayed full.
    HostLost,
}

impl UploadFailure {
    pub(super) fn status(self) -> StatusCode {
        match self {
            Self::ClientStalled => StatusCode::REQUEST_TIMEOUT,
            Self::ClientFailed => StatusCode::BAD_REQUEST,
            Self::HostStalled => StatusCode::GATEWAY_TIMEOUT,
            Self::HostLost => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Why no response started for a streamed request.
pub(super) enum StartFailure {
    Upload(UploadFailure),
    TimedOut,
}

/// Send `body` in chunks under `credit`, then end it. The client's reads and
/// the host's credit are each bounded by the idle timeout.
pub(super) async fn upload(
    body: Body,
    output: GuestOutput,
    credit: RequestCredit,
    request_id: String,
) -> Result<(), UploadFailure> {
    use v1::credential_bridge_guest_message::Payload;

    let mut body = body.into_data_stream();
    loop {
        let next = tokio::time::timeout(CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT, body.next())
            .await
            .map_err(|_| UploadFailure::ClientStalled)?;
        let bytes = match next {
            None => break,
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => return Err(UploadFailure::ClientFailed),
        };
        for chunk in bytes.chunks(CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES) {
            credit.spend().await?;
            send(
                &output,
                Payload::RequestBody(v1::CredentialBridgeRequestBody {
                    request_id: request_id.clone(),
                    data: chunk.to_vec(),
                }),
            )
            .await?;
        }
    }
    send(
        &output,
        Payload::RequestEnd(v1::CredentialBridgeRequestEnd { request_id }),
    )
    .await
}

async fn send(
    output: &GuestOutput,
    payload: v1::credential_bridge_guest_message::Payload,
) -> Result<(), UploadFailure> {
    match tokio::time::timeout(HOST_SEND_TIMEOUT, output.send(Ok(guest_message(payload)))).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(UploadFailure::HostLost),
    }
}

/// A streamed body on its way to the host.
pub(super) type Upload = std::pin::Pin<Box<dyn Future<Output = Result<(), UploadFailure>> + Send>>;

/// Drive `upload` until the response starts. Once the body is complete, the
/// response must start within the streamed first-response bound. A host may
/// answer before the body is complete: a provider such as `git http-backend`
/// sends its headers first and reads the body after, and a refusal can come
/// before any lease. The rest of the upload is then returned with the start,
/// and the caller keeps sending it while the response streams.
pub(super) async fn await_start<T>(
    mut upload: Upload,
    start: oneshot::Receiver<T>,
) -> Result<(Result<T, oneshot::error::RecvError>, Option<Upload>), StartFailure> {
    tokio::pin!(start);
    tokio::select! {
        biased;
        started = &mut start => return Ok((started, Some(upload))),
        uploaded = &mut upload => uploaded.map_err(StartFailure::Upload)?,
    }
    let started = tokio::time::timeout(FIRST_RESPONSE_AFTER_BODY, start)
        .await
        .map_err(|_| StartFailure::TimedOut)?;
    Ok((started, None))
}

#[cfg(test)]
mod tests;
