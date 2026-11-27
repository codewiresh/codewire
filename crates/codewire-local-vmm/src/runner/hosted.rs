//! A standard Pod's hosted control exchange (#5602): the host's side of
//! `codewire_vmm_guest_probe::hosted_control`. The boot's daemon token keys
//! it and never leaves this process.

use std::time::Duration;

use std::path::{Path, PathBuf};

use codewire_vmm_guest_probe::hosted_control::{
    HOSTED_CONTROL_VSOCK_PORT, HOSTED_HELLO_LEN, HOSTED_REPLY_LEN, HostedControlError,
    HostedControlKey, HostedMessage, decode_hello, decode_reply,
};
use codewire_vmm_guest_probe::{
    CHECKPOINT_HOST_ENTROPY_LEN, CheckpointAction, CheckpointRequest, CheckpointStatus,
    GUEST_CHECKPOINT_ABI,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{RunnerError, RunningVm};
use crate::ch_api::ChApiClient;
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
        send_hosted_to(
            &self.paths().vsock_socket,
            &self.token,
            self.vm_id(),
            self.generation(),
            message,
        )
        .await
    }

    /// What a standard Pod's runtime needs to suspend and wake this boot
    /// from tasks that don't own it (#5529): the VMM's API, the guest's
    /// checkpoint hook and hosted control, and this boot's identity.
    pub fn suspend_control(&self) -> SuspendControl {
        SuspendControl {
            api: self.api.clone(),
            socket: self.paths().vsock_socket.clone(),
            token: self.token.clone(),
            vm_id: self.vm_id(),
            generation: self.generation(),
        }
    }
}

/// A boot's suspend and wake (#5529), held apart from its [`RunningVm`] so the
/// Pod runtime's listeners can wake it. Every call is the host's: the guest
/// can ask for a pause, never for a resume.
#[derive(Clone)]
pub struct SuspendControl {
    api: ChApiClient,
    socket: PathBuf,
    token: Zeroizing<String>,
    vm_id: Uuid,
    generation: u64,
}

impl SuspendControl {
    /// Freezes the workload through PID 1's checkpoint hook, then pauses
    /// every vCPU. A refused freeze leaves the VM running and thawed; a
    /// failed pause thaws it again.
    pub async fn freeze_and_pause(&self, operation: Uuid) -> Result<(), RunnerError> {
        let freeze = self.hook(CheckpointAction::Freeze, operation).await?;
        if freeze.status != CheckpointStatus::Done {
            return Err(RunnerError::Checkpoint(
                "the guest could not freeze its workload for a suspend",
            ));
        }
        if let Err(error) = self.api.pause().await {
            let _ = self.hook(CheckpointAction::Thaw, operation).await;
            return Err(error.into());
        }
        Ok(())
    }

    /// Resumes every vCPU. The workload stays frozen until [`Self::thaw`].
    pub async fn resume(&self) -> Result<(), RunnerError> {
        Ok(self.api.resume().await?)
    }

    /// Thaws the workload. A Linux guest's clock runs on through a pause
    /// (kvm-clock), so the thaw is the checkpoints' ABI 1, which carries no
    /// clock to step.
    pub async fn thaw(&self, operation: Uuid) -> Result<(), RunnerError> {
        self.hook(CheckpointAction::Thaw, operation).await.map(drop)
    }

    /// [`RunningVm::send_hosted`], for this boot.
    pub async fn send_hosted(&self, message: &HostedMessage) -> Result<(), HostedSendError> {
        send_hosted_to(
            &self.socket,
            &self.token,
            self.vm_id,
            self.generation,
            message,
        )
        .await
    }

    async fn hook(
        &self,
        action: CheckpointAction,
        operation_id: Uuid,
    ) -> Result<codewire_vmm_guest_probe::CheckpointReply, RunnerError> {
        super::checkpoint::hook_exchange(
            &self.socket,
            &self.token,
            CheckpointRequest {
                abi: GUEST_CHECKPOINT_ABI,
                action,
                operation_id,
                vm_id: self.vm_id,
                generation: self.generation,
                host_entropy: [0; CHECKPOINT_HOST_ENTROPY_LEN],
                host_time_ns: 0,
            },
        )
        .await
    }
}

/// One hosted control exchange with the guest of boot `vm_id`/`generation`
/// over its hybrid vsock `socket`, keyed by the boot's daemon `token`.
pub(super) async fn send_hosted_to(
    socket: &Path,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    message: &HostedMessage,
) -> Result<(), HostedSendError> {
    let key = HostedControlKey::derive(token, vm_id, generation)?;
    let exchange = async {
        let mut stream = connect_hybrid_vsock(socket, HOSTED_CONTROL_VSOCK_PORT).await?;
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
