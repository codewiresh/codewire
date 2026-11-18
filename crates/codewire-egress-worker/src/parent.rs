//! The parent's side of starting a worker or a broker: reading the status
//! lines the child writes on its bootstrap socket, passing it descriptors,
//! and making the broker's IPC key. The local runner and cw-egress's
//! supervisor both start the two processes this way.

use std::io;
use std::os::fd::{AsRawFd as _, RawFd};

use codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN;
use rand::{RngCore as _, rngs::OsRng};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Why a step of a child's start did not complete.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartError {
    #[error("the child did not answer before the deadline")]
    Timeout,
    /// The socket closed or failed, or the child wrote something that is not
    /// a status line.
    #[error("the child's bootstrap socket failed or carried no status line")]
    Bootstrap,
}

/// Reads one status line: ASCII, ended by a newline, at most `maximum`
/// bytes with it. Anything else, a closed socket included, is an error.
pub async fn read_status_frame(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, StartError> {
    let mut frame = Vec::with_capacity(maximum);
    loop {
        if frame.len() == maximum {
            return Err(StartError::Bootstrap);
        }
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout_at(deadline, stream.read(&mut byte))
            .await
            .map_err(|_| StartError::Timeout)?
            .map_err(|_| StartError::Bootstrap)?;
        if read == 0 {
            return Err(StartError::Bootstrap);
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
        if byte[0] == b'\r' || !byte[0].is_ascii() {
            return Err(StartError::Bootstrap);
        }
    }
}

/// Passes the child a descriptor with `transfer`, one of the worker's
/// descriptor sends given the bootstrap socket, waiting for the socket to
/// take it.
pub async fn transfer_descriptor(
    bootstrap: &UnixStream,
    deadline: Instant,
    transfer: impl Fn(RawFd) -> io::Result<()>,
) -> Result<(), StartError> {
    tokio::time::timeout_at(deadline, async {
        loop {
            bootstrap.writable().await?;
            match transfer(bootstrap.as_raw_fd()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| StartError::Timeout)?
    .map_err(|_| StartError::Bootstrap)
}

/// A fresh key for one broker's IPC sessions. An all-zero key is refused by
/// the bootstrap, so it is never returned.
pub fn fresh_egress_broker_key() -> Zeroizing<[u8; BROKER_IPC_KEY_LEN]> {
    loop {
        let mut key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
        OsRng.fill_bytes(key.as_mut());
        if key.iter().any(|byte| *byte != 0) {
            return key;
        }
    }
}
