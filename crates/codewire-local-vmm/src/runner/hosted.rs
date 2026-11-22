//! A standard Pod's hosted control exchange (#5602): the host's side of
//! `codewire_vmm_guest_probe::hosted_control`. The boot's daemon token keys
//! it and never leaves this process.

use std::time::Duration;

use codewire_vmm_guest_probe::hosted_control::{
    HOSTED_CONTROL_VSOCK_PORT, HOSTED_HELLO_LEN, HOSTED_REPLY_LEN, HostedControlError,
    HostedControlKey, HostedMessage, decode_hello, decode_reply,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::RunningVm;
use crate::hybrid_vsock::{HybridVsockError, connect_hybrid_vsock};

/// One exchange: the guest's hello, the message and its reply.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum HostedSendError {
    #[error("connect to the guest's hosted control port: {0}")]
    Connect(#[from] HybridVsockError),
    #[error("the hosted control exchange failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the hosted control exchange did not finish in time")]
    Timeout,
    #[error(transparent)]
    Protocol(#[from] HostedControlError),
    #[error("the guest did not apply the hosted message")]
    NotApplied,
}

impl RunningVm {
    /// Sends one message to this boot's guest and returns once the guest
    /// has answered that it applied it.
    pub async fn send_hosted(&self, message: &HostedMessage) -> Result<(), HostedSendError> {
        let key = HostedControlKey::derive(&self.token, self.vm_id(), self.generation())?;
        let exchange = async {
            let mut stream =
                connect_hybrid_vsock(&self.paths().vsock_socket, HOSTED_CONTROL_VSOCK_PORT).await?;
            let mut hello = [0_u8; HOSTED_HELLO_LEN];
            stream.read_exact(&mut hello).await?;
            let challenge = decode_hello(&hello)?;
            stream.write_all(&message.encode(&key, &challenge)?).await?;
            stream.flush().await?;
            let mut reply = [0_u8; HOSTED_REPLY_LEN];
            stream.read_exact(&mut reply).await?;
            if !decode_reply(&reply, &key, &challenge)? {
                return Err(HostedSendError::NotApplied);
            }
            Ok(())
        };
        tokio::time::timeout(EXCHANGE_TIMEOUT, exchange)
            .await
            .map_err(|_| HostedSendError::Timeout)?
    }
}
