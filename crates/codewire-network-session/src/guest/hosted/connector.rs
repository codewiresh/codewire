//! The Pod's [`EgressConnector`]: one stream to cw-egress (#4000). It reads
//! the egress token fresh for every stream, sends the hello with a new nonce,
//! reads the node's nonce, derives the stream key from both and the Pod's UID,
//! and runs the guest's side of the session handshake. The stream leaves by
//! the Pod interface (`hosted::pod_interface`), never the TUN.

use std::io;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{EgressConnector, VersionRefused};
use crate::NETWORK_PROTOCOL_VERSION;
use crate::NetworkError;
use crate::guest::{GuestHandshakeError, GuestSession, authenticate_guest};
use crate::hosted::hello::{
    ANSWER_MAGIC_LEN, Answer, GuestHello, HelloError, NONCE_LEN, answer_tail_len, decode_answer,
};
use crate::hosted::key::{StreamKeyInput, stream_key};
use crate::hosted::{HOSTED_GENERATION, HOSTED_POD_INTERFACE, pod_interface};

/// Where one stream comes from.
#[derive(Clone, Debug)]
pub struct PodConnector {
    /// cw-egress's stream address (`CODEWIRE_EGRESS_STREAM_ADDR`).
    pub stream_addr: SocketAddrV4,
    /// The projected egress token, read fresh for every stream.
    pub token_path: PathBuf,
    /// This Pod's UID (`CODEWIRE_POD_UID`).
    pub pod_uid: Uuid,
    /// How long one dial and handshake may take.
    pub bound: Duration,
    /// The interface the stream leaves by: the Pod's, except in tests.
    interface: &'static str,
}

impl PodConnector {
    pub fn new(
        stream_addr: SocketAddrV4,
        token_path: PathBuf,
        pod_uid: Uuid,
        bound: Duration,
    ) -> Self {
        Self {
            stream_addr,
            token_path,
            pod_uid,
            bound,
            interface: HOSTED_POD_INTERFACE,
        }
    }
}

/// Why no stream was opened.
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("the egress token could not be read")]
    Token(#[source] io::Error),
    #[error("no nonce could be drawn")]
    Nonce(#[source] io::Error),
    #[error("dialling cw-egress failed")]
    Dial(#[source] io::Error),
    #[error("the hello could not be sent")]
    Hello(#[source] HelloError),
    #[error("the hello or its answer could not be exchanged")]
    Exchange(#[source] io::Error),
    #[error("cw-egress's answer was refused")]
    Answer(#[source] HelloError),
    /// cw-egress speaks other session versions than this daemon. Only an
    /// update of one of them cures it.
    #[error(
        "cw-egress accepts session versions {lowest} to {highest}, and this daemon speaks {spoken}"
    )]
    VersionRefused {
        lowest: u16,
        highest: u16,
        spoken: u16,
    },
    #[error("the stream key could not be derived")]
    Key(#[source] NetworkError),
    #[error("the session handshake failed")]
    Handshake(#[source] GuestHandshakeError),
    #[error("the dial and handshake took longer than their bound")]
    TimedOut,
}

impl EgressConnector for PodConnector {
    type Stream = TcpStream;
    type Error = ConnectError;

    fn version_refused(error: &ConnectError) -> Option<VersionRefused> {
        match *error {
            ConnectError::VersionRefused {
                lowest,
                highest,
                spoken,
            } => Some(VersionRefused {
                lowest,
                highest,
                spoken,
            }),
            _ => None,
        }
    }

    async fn connect(&self) -> Result<GuestSession<TcpStream>, ConnectError> {
        tokio::time::timeout(self.bound, self.open())
            .await
            .unwrap_or(Err(ConnectError::TimedOut))
    }
}

impl PodConnector {
    async fn open(&self) -> Result<GuestSession<TcpStream>, ConnectError> {
        let token = Zeroizing::new(
            tokio::fs::read_to_string(&self.token_path)
                .await
                .map_err(ConnectError::Token)?
                .trim()
                .to_owned(),
        );
        let nonce = random_nonce()?;
        let mut stream = pod_interface::connect_tcp_by(self.stream_addr, self.interface)
            .await
            .map_err(ConnectError::Dial)?;
        // Each frame carries whole packets; Nagle would only delay them. A
        // refusal leaves a working, slower stream.
        let _ = stream.set_nodelay(true);
        let hello = GuestHello {
            version: NETWORK_PROTOCOL_VERSION,
            token: token.clone(),
            nonce,
        }
        .encode()
        .map_err(ConnectError::Hello)?;
        stream
            .write_all(&hello)
            .await
            .map_err(ConnectError::Exchange)?;
        // The two answers differ in length: the magic says which follows.
        let mut magic = [0_u8; ANSWER_MAGIC_LEN];
        stream
            .read_exact(&mut magic)
            .await
            .map_err(ConnectError::Exchange)?;
        let mut tail = vec![0_u8; answer_tail_len(&magic).map_err(ConnectError::Answer)?];
        stream
            .read_exact(&mut tail)
            .await
            .map_err(ConnectError::Exchange)?;
        let node_nonce = match decode_answer(&magic, &tail).map_err(ConnectError::Answer)? {
            Answer::Admitted { nonce } => nonce,
            Answer::VersionRefused { lowest, highest } => {
                return Err(ConnectError::VersionRefused {
                    lowest,
                    highest,
                    spoken: NETWORK_PROTOCOL_VERSION,
                });
            }
        };
        let key = stream_key(&StreamKeyInput {
            token: &token,
            guest_nonce: &nonce,
            node_nonce: &node_nonce,
            pod_uid: self.pod_uid,
        })
        .map_err(ConnectError::Key)?;
        authenticate_guest(stream, &key, self.pod_uid, HOSTED_GENERATION)
            .await
            .map_err(ConnectError::Handshake)
    }
}

/// A nonce from the kernel's random source, never reused across streams.
fn random_nonce() -> Result<[u8; NONCE_LEN], ConnectError> {
    let mut nonce = [0_u8; NONCE_LEN];
    let mut filled = 0;
    while filled < NONCE_LEN {
        filled +=
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|error| ConnectError::Nonce(error.into()))?;
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests;
