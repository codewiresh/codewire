//! The runner's control channel to its confined egress broker (#2614, #2537).
//!
//! The runner sends host address frames (`CWHA`, [`crate::host_addresses`])
//! and policy replacements (`CWPR`: the canonical document and its digest).
//! The broker answers each replacement with one acknowledgement (`CWPA`)
//! carrying the digest it enforces from then on. Anything malformed ends the
//! channel, and the broker fails closed with it.

use std::io;
use std::time::Duration;

use codewire_egress_policy::{
    CompiledPolicy, MAX_POLICY_DOCUMENT_BYTES, PolicyDigest, PolicyDocument,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};

use crate::host_addresses::{
    HOST_ADDRESS_FRAME_MAGIC, HostAddressSet, encode_frame, read_frame_after_magic,
};

const POLICY_FRAME_MAGIC: [u8; 4] = *b"CWPR";
const POLICY_ACK_MAGIC: [u8; 4] = *b"CWPA";
const FRAME_VERSION: u8 = 1;
const DIGEST_LEN: usize = 32;
/// How long the runner waits for the broker to acknowledge a replacement.
pub(crate) const POLICY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// One frame the broker reads from the runner.
#[derive(Debug)]
pub enum ControlFrame {
    HostAddresses(HostAddressSet),
    ReplacePolicy(CompiledPolicy),
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.to_string())
}

/// A replacement frame: magic, version, digest, then the canonical document's
/// length and bytes.
pub fn encode_policy_frame(policy: &CompiledPolicy) -> io::Result<Vec<u8>> {
    let document = policy
        .canonical_json()
        .map_err(|_| invalid("policy has no canonical document"))?;
    if document.is_empty() || document.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(invalid("policy document exceeds its bound"));
    }
    let mut frame = Vec::with_capacity(4 + 1 + DIGEST_LEN + 4 + document.len());
    frame.extend_from_slice(&POLICY_FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.extend_from_slice(policy.digest().as_bytes());
    frame.extend_from_slice(
        &u32::try_from(document.len())
            .expect("bounded policy document")
            .to_be_bytes(),
    );
    frame.extend_from_slice(&document);
    Ok(frame)
}

/// Read one frame from the runner. A replacement is compiled and must match
/// the digest it names.
pub async fn read_control_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<ControlFrame> {
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    if magic == HOST_ADDRESS_FRAME_MAGIC {
        return read_frame_after_magic(reader)
            .await
            .map(ControlFrame::HostAddresses);
    }
    if magic != POLICY_FRAME_MAGIC {
        return Err(invalid("control frame has an unknown header"));
    }
    let mut header = [0_u8; 1 + DIGEST_LEN + 4];
    reader.read_exact(&mut header).await?;
    if header[0] != FRAME_VERSION {
        return Err(invalid("policy frame has an unknown version"));
    }
    let digest = PolicyDigest::from_bytes(
        header[1..1 + DIGEST_LEN]
            .try_into()
            .expect("fixed policy digest length"),
    );
    let length = usize::try_from(u32::from_be_bytes(
        header[1 + DIGEST_LEN..]
            .try_into()
            .expect("fixed policy length field"),
    ))
    .map_err(|_| invalid("policy frame length is invalid"))?;
    if length == 0 || length > MAX_POLICY_DOCUMENT_BYTES {
        return Err(invalid("policy frame exceeds its bound"));
    }
    let mut document = vec![0_u8; length];
    reader.read_exact(&mut document).await?;
    let document: PolicyDocument =
        serde_json::from_slice(&document).map_err(|_| invalid("policy frame is not a policy"))?;
    let policy =
        CompiledPolicy::compile(document).map_err(|_| invalid("policy frame does not compile"))?;
    if policy.digest() != digest {
        return Err(invalid("policy frame does not match its digest"));
    }
    Ok(ControlFrame::ReplacePolicy(policy))
}

/// The broker's acknowledgement: the digest it now enforces.
pub fn encode_policy_ack(digest: PolicyDigest) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 1 + DIGEST_LEN);
    frame.extend_from_slice(&POLICY_ACK_MAGIC);
    frame.push(FRAME_VERSION);
    frame.extend_from_slice(digest.as_bytes());
    frame
}

pub async fn read_policy_ack<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<PolicyDigest> {
    let mut frame = [0_u8; 4 + 1 + DIGEST_LEN];
    reader.read_exact(&mut frame).await?;
    if frame[..4] != POLICY_ACK_MAGIC || frame[4] != FRAME_VERSION {
        return Err(invalid("policy acknowledgement has an unknown header"));
    }
    Ok(PolicyDigest::from_bytes(
        frame[5..].try_into().expect("fixed policy digest length"),
    ))
}

/// One replacement for the runner's control task to deliver.
pub struct PolicyReplacementRequest {
    pub policy: CompiledPolicy,
    /// The digest the broker acknowledged. Dropped unanswered when the
    /// channel fails.
    pub reply: oneshot::Sender<PolicyDigest>,
}

/// The runner's end of the channel: send each host address update and each
/// replacement in turn, and wait for every replacement's acknowledgement
/// before the next frame. It ends when the host address monitor stops, the
/// broker closes the channel, or an acknowledgement is late or wrong; the
/// channel then closes and the broker fails closed.
pub async fn serve_runner_control<S: AsyncRead + AsyncWrite + Unpin>(
    mut control: S,
    mut addresses: mpsc::Receiver<HostAddressSet>,
    mut replacements: mpsc::Receiver<PolicyReplacementRequest>,
    ack_timeout: Duration,
) -> io::Result<()> {
    let mut replacements_open = true;
    loop {
        tokio::select! {
            set = addresses.recv() => {
                let Some(set) = set else { return Ok(()); };
                control.write_all(&encode_frame(&set)).await?;
                control.flush().await?;
            }
            request = replacements.recv(), if replacements_open => {
                let Some(request) = request else {
                    replacements_open = false;
                    continue;
                };
                let expected = request.policy.digest();
                control.write_all(&encode_policy_frame(&request.policy)?).await?;
                control.flush().await?;
                let enforced = tokio::time::timeout(ack_timeout, read_policy_ack(&mut control))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "policy acknowledgement timed out"))??;
                if enforced != expected {
                    return Err(invalid("broker acknowledged another policy"));
                }
                let _ = request.reply.send(enforced);
            }
        }
    }
}

#[cfg(test)]
mod tests;
