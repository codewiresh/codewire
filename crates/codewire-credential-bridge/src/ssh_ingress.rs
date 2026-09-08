//! One already-authenticated OpenSSH agent stream, without listener ownership,
//! credential selection or a second pending-request ledger.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_gateway_proto::codewire::bridge::v1;
use codewire_gateway_proto::ssh::{
    MAX_DEADLINE, SshOperation, agent, remaining_deadline, validate_request, validate_response,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tonic::Status;
use uuid::Uuid;

use crate::CredentialBridge;

/// Typed material-free relay for an already-authorized transport. Request IDs
/// and original deadlines must be preserved; the backend still owns credential
/// authorization, exact-key/algorithm checks and its existing request lifetime.
///
/// Dropping this future cancels delivery/the waiter, not necessarily remote
/// work. An implementation must retain admitted work and arrange cancellation
/// and cleanup independently of its dropped waiter. Neither this trait nor
/// the byte-stream adapter acknowledges remote signing drain.
#[tonic::async_trait]
pub trait SshAgentRelay: Send + Sync {
    async fn relay_ssh(
        &self,
        request: v1::CredentialSshRequest,
    ) -> Result<v1::CredentialSshResponse, Status>;
}

#[tonic::async_trait]
impl SshAgentRelay for CredentialBridge {
    async fn relay_ssh(
        &self,
        request: v1::CredentialSshRequest,
    ) -> Result<v1::CredentialSshResponse, Status> {
        CredentialBridge::relay_ssh(self, request).await
    }
}

/// Serve one owned, authenticated agent stream using a typed relay.
/// The caller owns peer authentication, selection, connection capacity and the
/// shutdown signal. This function binds no listener and spawns no tasks.
///
/// Each sequential request has one original deadline covering idle/framing,
/// relay queueing and the terminal write. Unsupported bounded frames receive
/// the fixed agent failure; oversized, truncated or pipelined frames close the
/// stream. EOF while awaiting a response cancels that request, not a half-close.
///
/// Cancellation (including dropping this future) drops the typed relay waiter.
/// [`CredentialBridge`] retains its existing cancellation/tombstone behavior;
/// other backends must uphold [`SshAgentRelay`]'s retained-cleanup contract.
/// Returning is not acknowledgement that remote signing has drained. No error
/// includes request or response contents.
pub async fn serve_ssh_agent<R, S, F>(relay: &R, stream: S, shutdown: F) -> Result<(), Status>
where
    R: SshAgentRelay + ?Sized,
    S: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    serve(relay, stream, shutdown, MAX_DEADLINE).await
}

async fn serve<R, S, F>(relay: &R, stream: S, shutdown: F, timeout: Duration) -> Result<(), Status>
where
    R: SshAgentRelay + ?Sized,
    S: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    tokio::pin!(shutdown);
    loop {
        let deadline_unix_ms = deadline(timeout)?;
        let end = tokio::time::Instant::now() + remaining_deadline(deadline_unix_ms)?;
        let more = tokio::select! {
            biased;
            () = &mut shutdown => return Err(Status::cancelled("SSH agent stream stopped")),
            () = tokio::time::sleep_until(end) => {
                return Err(Status::deadline_exceeded("SSH agent stream expired"));
            }
            result = exchange(relay, &mut reader, &mut writer, deadline_unix_ms) => result?,
        };
        if !more {
            return Ok(());
        }
    }
}

async fn exchange<T, R, W>(
    relay: &T,
    reader: &mut R,
    writer: &mut W,
    deadline_unix_ms: u64,
) -> Result<bool, Status>
where
    T: SshAgentRelay + ?Sized,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(payload) = read_frame(reader).await? else {
        return Ok(false);
    };
    let operation = match agent::decode_request(&payload) {
        Ok(operation) => operation,
        Err(_) => {
            write_failure(writer).await?;
            return Ok(true);
        }
    };
    let request = v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string(),
        deadline_unix_ms,
        operation: Some(operation),
    };
    let kind = validate_request(&request)?;
    let request_id = request.request_id.clone();
    // OpenSSH's agent protocol is request/response. Read only one byte while
    // awaiting the authority: detect peer loss without buffering another frame
    // or accepting more than one operation on this connection at a time.
    let mut ahead = [0; 1];
    let response = tokio::select! {
        biased;
        read = reader.read(&mut ahead) => {
            return match read {
                Ok(0) => Ok(false),
                Ok(_) => Err(invalid_frame()),
                Err(_) => Err(transport_failed()),
            };
        }
        result = relay.relay_ssh(request) => result,
    };
    remaining_deadline(deadline_unix_ms)
        .map_err(|_| Status::deadline_exceeded("SSH agent stream expired"))?;
    match response {
        Ok(response) => {
            // Alternate transports do not necessarily use the shared bridge
            // ledger. Validate correlation/type/bounds here before encoding.
            if response.request_id != request_id {
                return Err(invalid_frame());
            }
            validate_response(&response, kind).map_err(|_| invalid_frame())?;
            let result = response.result.as_ref().ok_or_else(invalid_frame)?;
            let payload = agent::encode_response(result, kind).map_err(|_| invalid_frame())?;
            write_frame(writer, &payload).await?;
        }
        Err(_) => write_failure(writer).await?,
    }
    Ok(true)
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>, Status> {
    let mut prefix = [0; 4];
    if reader
        .read(&mut prefix[..1])
        .await
        .map_err(|_| transport_failed())?
        == 0
    {
        return Ok(None);
    }
    reader
        .read_exact(&mut prefix[1..])
        .await
        .map_err(|_| invalid_frame())?;
    let count = u32::from_be_bytes(prefix) as usize;
    if count == 0 || count > agent::MAX_PAYLOAD_BYTES {
        return Err(invalid_frame());
    }
    // The outer length is admitted before any payload allocation or read.
    let mut payload = vec![0; count];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| invalid_frame())?;
    Ok(Some(payload))
}

async fn write_failure<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), Status> {
    let payload = agent::encode_response(
        &v1::credential_ssh_response::Result::Failure(
            v1::CredentialBridgeFailureReason::Denied as i32,
        ),
        SshOperation::Identities,
    )
    .map_err(|_| invalid_frame())?;
    write_frame(writer, &payload).await
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<(), Status> {
    let count = u32::try_from(payload.len()).map_err(|_| invalid_frame())?;
    writer
        .write_all(&count.to_be_bytes())
        .await
        .map_err(|_| transport_failed())?;
    writer
        .write_all(payload)
        .await
        .map_err(|_| transport_failed())?;
    writer.flush().await.map_err(|_| transport_failed())
}

fn deadline(timeout: Duration) -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| now.checked_add(timeout))
        .and_then(|end| end.as_millis().try_into().ok())
        .ok_or_else(|| Status::unavailable("SSH agent deadline clock is unavailable"))
}

fn invalid_frame() -> Status {
    Status::invalid_argument("SSH agent frame is invalid")
}

fn transport_failed() -> Status {
    Status::unavailable("SSH agent stream failed")
}

#[cfg(test)]
mod tests;
