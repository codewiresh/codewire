//! The runner's control channel to its confined egress broker (#2614, #2537).
//!
//! The runner sends host address frames (`CWHA`, [`crate::host_addresses`])
//! and policy replacements (`CWPR`: the canonical document and its digest).
//! The broker answers each replacement with one acknowledgement (`CWPA`)
//! carrying the digest it enforces from then on. Interception bindings
//! (`CWIR`, #3999) replace the broker's set; a broker started with a
//! front-door hand-off reads one right after the first host addresses.
//! Up the channel, besides each acknowledgement, the broker reports its
//! refusals (`CWRL`, [`refusals`], #5058) at most once a second.
//! Anything malformed ends the channel, and the broker fails closed with it.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use codewire_egress_policy::intercept::{
    InterceptBinding, InterceptSet, InterceptSuffix, MAX_INTERCEPT_BINDINGS, MAX_INTERCEPT_SUFFIXES,
};
use codewire_egress_policy::{
    CompiledPolicy, MAX_POLICY_DOCUMENT_BYTES, PolicyDigest, PolicyDocument,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};

use crate::host_addresses::{
    HOST_ADDRESS_FRAME_MAGIC, HostAddressSet, encode_frame, read_frame_after_magic,
};

mod refusals;
pub use refusals::{
    MAX_REFUSAL_FRAME_BYTES, MAX_REFUSAL_FRAME_ROWS, REFUSAL_REPORT_INTERVAL, RefusalLogSnapshot,
    RunnerRefusalLog, decode_refusal_body, encode_refusal_frame, now_unix_ms, report_refusals,
};

const POLICY_FRAME_MAGIC: [u8; 4] = *b"CWPR";
const POLICY_ACK_MAGIC: [u8; 4] = *b"CWPA";
const INTERCEPT_FRAME_MAGIC: [u8; 4] = *b"CWIR";
const FRAME_VERSION: u8 = 1;
/// Version 2 adds the suffixes after the exact bindings (#3999).
const INTERCEPT_FRAME_VERSION: u8 = 2;
const DIGEST_LEN: usize = 32;
/// How long the runner waits for the broker to acknowledge a replacement.
pub const POLICY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// One frame the broker reads from the runner.
#[derive(Debug)]
pub enum ControlFrame {
    HostAddresses(HostAddressSet),
    ReplacePolicy(CompiledPolicy),
    ReplaceIntercepts(InterceptSet),
}

/// An interception frame: magic, version, the binding count, then each
/// binding's hostname length (one byte), hostname and big-endian port; then
/// the suffix count and each suffix the same way. A set or name too large for
/// its one-byte count is refused.
pub fn encode_intercept_frame(intercepts: &InterceptSet) -> io::Result<Vec<u8>> {
    let too_large = || io::Error::new(io::ErrorKind::InvalidInput, "interception set too large");
    let mut frame = vec![];
    frame.extend_from_slice(&INTERCEPT_FRAME_MAGIC);
    frame.push(INTERCEPT_FRAME_VERSION);
    let mut push = |names: Vec<(&str, u16)>| -> io::Result<()> {
        frame.push(u8::try_from(names.len()).map_err(|_| too_large())?);
        for (name, port) in names {
            frame.push(u8::try_from(name.len()).map_err(|_| too_large())?);
            frame.extend_from_slice(name.as_bytes());
            frame.extend_from_slice(&port.to_be_bytes());
        }
        Ok(())
    };
    push(
        intercepts
            .bindings()
            .iter()
            .map(|binding| (binding.hostname(), binding.port()))
            .collect(),
    )?;
    push(
        intercepts
            .suffixes()
            .iter()
            .map(|suffix| (suffix.suffix(), suffix.port()))
            .collect(),
    )?;
    Ok(frame)
}

async fn read_intercept_frame_after_magic<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<InterceptSet> {
    if reader.read_u8().await? != INTERCEPT_FRAME_VERSION {
        return Err(invalid("interception frame has an unknown version"));
    }
    let bindings = read_names(reader, MAX_INTERCEPT_BINDINGS, |name, port| {
        InterceptBinding::new(name, port)
            .map(|binding| (binding.hostname() == name).then_some(binding))
    })
    .await?;
    let suffixes = read_names(reader, MAX_INTERCEPT_SUFFIXES, |name, port| {
        InterceptSuffix::new(name, port).map(|suffix| (suffix.suffix() == name).then_some(suffix))
    })
    .await?;
    let (binding_count, suffix_count) = (bindings.len(), suffixes.len());
    let set = InterceptSet::with_suffixes(bindings, suffixes)
        .map_err(|_| invalid("interception set is invalid"))?;
    if set.len() != binding_count || set.suffixes().len() != suffix_count {
        return Err(invalid("interception frame repeats a binding"));
    }
    Ok(set)
}

/// One counted list of names and ports, each made by `make`: `Ok(None)` for
/// a name it would canonicalize differently, which was not sent by us.
async fn read_names<R, T, E>(
    reader: &mut R,
    maximum: usize,
    make: impl Fn(&str, u16) -> Result<Option<T>, E>,
) -> io::Result<Vec<T>>
where
    R: AsyncRead + Unpin,
{
    let count = usize::from(reader.read_u8().await?);
    if count > maximum {
        return Err(invalid("interception frame exceeds its bound"));
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(reader.read_u8().await?);
        let mut name = vec![0_u8; length];
        reader.read_exact(&mut name).await?;
        let port = reader.read_u16().await?;
        let name =
            std::str::from_utf8(&name).map_err(|_| invalid("interception hostname is not text"))?;
        match make(name, port) {
            Ok(Some(made)) => names.push(made),
            // Only canonical names travel; anything else was not ours.
            Ok(None) => return Err(invalid("interception hostname is not canonical")),
            Err(_) => return Err(invalid("interception binding is invalid")),
        }
    }
    Ok(names)
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
    if magic == INTERCEPT_FRAME_MAGIC {
        return read_intercept_frame_after_magic(reader)
            .await
            .map(ControlFrame::ReplaceIntercepts);
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

/// An acknowledgement alone, for a channel that carries nothing else.
pub async fn read_policy_ack<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<PolicyDigest> {
    match read_broker_frame(reader).await? {
        BrokerFrame::PolicyAck(digest) => Ok(digest),
        BrokerFrame::Refusals(_) => {
            Err(invalid("broker sent a frame other than an acknowledgement"))
        }
    }
}

/// One frame the runner reads from the broker.
#[derive(Debug)]
pub enum BrokerFrame {
    PolicyAck(PolicyDigest),
    Refusals(codewire_egress_broker::refusals::RefusalBatch),
}

pub async fn read_broker_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<BrokerFrame> {
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    if magic == refusals::REFUSAL_FRAME_MAGIC {
        return refusals::read_refusal_frame_after_magic(reader)
            .await
            .map(BrokerFrame::Refusals);
    }
    let mut frame = [0_u8; 1 + DIGEST_LEN];
    reader.read_exact(&mut frame).await?;
    if magic != POLICY_ACK_MAGIC || frame[0] != FRAME_VERSION {
        return Err(invalid("broker frame has an unknown header"));
    }
    Ok(BrokerFrame::PolicyAck(PolicyDigest::from_bytes(
        frame[1..].try_into().expect("fixed policy digest length"),
    )))
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
/// before the next frame, while every refusal report the broker sends is
/// filed in `refusals`, the log of the environment this runner serves. It
/// ends when the host address monitor stops, the broker closes the channel,
/// sends a malformed or oversized frame, or an acknowledgement is late,
/// wrong or unasked for; the channel then closes and the broker fails
/// closed.
pub async fn serve_runner_control<S: AsyncRead + AsyncWrite + Unpin>(
    control: S,
    addresses: mpsc::Receiver<HostAddressSet>,
    replacements: mpsc::Receiver<PolicyReplacementRequest>,
    ack_timeout: Duration,
    refusals: Arc<RunnerRefusalLog>,
) -> io::Result<()> {
    let (reader, writer) = tokio::io::split(control);
    let (acks, acknowledged) = mpsc::channel(1);
    tokio::select! {
        result = read_from_broker(reader, acks, &refusals) => result,
        result = write_to_broker(writer, addresses, replacements, acknowledged, ack_timeout) => result,
    }
}

async fn read_from_broker<R: AsyncRead + Unpin>(
    mut reader: R,
    acks: mpsc::Sender<PolicyDigest>,
    refusals: &RunnerRefusalLog,
) -> io::Result<()> {
    loop {
        match read_broker_frame(&mut reader).await? {
            BrokerFrame::PolicyAck(digest) => acks
                .try_send(digest)
                .map_err(|_| invalid("broker acknowledged a replacement twice"))?,
            BrokerFrame::Refusals(batch) => refusals.file(batch, now_unix_ms()),
        }
    }
}

async fn write_to_broker<W: AsyncWrite + Unpin>(
    mut control: W,
    mut addresses: mpsc::Receiver<HostAddressSet>,
    mut replacements: mpsc::Receiver<PolicyReplacementRequest>,
    mut acknowledged: mpsc::Receiver<PolicyDigest>,
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
                if acknowledged.try_recv().is_ok() {
                    return Err(invalid("broker acknowledged a replacement nobody sent"));
                }
                let expected = request.policy.digest();
                control.write_all(&encode_policy_frame(&request.policy)?).await?;
                control.flush().await?;
                let enforced = tokio::time::timeout(ack_timeout, acknowledged.recv())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "policy acknowledgement timed out"))?
                    .ok_or_else(|| invalid("broker control channel closed"))?;
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
