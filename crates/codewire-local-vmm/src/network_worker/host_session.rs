//! The local VM worker's packet session: the portable engine's, with the
//! bound a local VM's vsock session has always had.

use super::*;

/// Preserve the Linux worker entrypoint while delegating the complete packet
/// session to the portable engine. Linux descriptor validation and confinement
/// remain in the inherited-worker wrappers above.
pub async fn run_host_session<S, B, R>(
    stream: S,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
    ready: R,
) -> Result<(), NetworkWorkerError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: EgressBroker,
    R: FnOnce() -> io::Result<()> + Send,
{
    // A local VM's session over vsock keeps the bound and MTU it always had.
    run_network_session(
        stream,
        key,
        vm_id,
        generation,
        codewire_network_session::SessionLimits::LOCAL,
        broker,
        ready,
    )
    .await
    .map_err(NetworkWorkerError::from)
}

pub(super) async fn run_host_session_with_ingress<S, B, R>(
    stream: S,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
    inbound: Option<mpsc::Receiver<InboundGuestStream>>,
    ready: R,
) -> Result<(), NetworkWorkerError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: EgressBroker,
    R: FnOnce() -> io::Result<()> + Send,
{
    run_portable_network_session_with_ingress(
        stream,
        key,
        vm_id,
        generation,
        codewire_network_session::SessionLimits::LOCAL,
        broker,
        inbound,
        ready,
    )
    .await
    .map_err(NetworkWorkerError::from)
}

impl From<NetworkSessionError> for NetworkWorkerError {
    fn from(error: NetworkSessionError) -> Self {
        match error {
            NetworkSessionError::InvalidIdentity => Self::InvalidIdentity,
            NetworkSessionError::HelloWriteTimeout => Self::HelloWriteTimeout,
            NetworkSessionError::HelloWriteIo => Self::HelloWriteIo,
            NetworkSessionError::AcknowledgementReadTimeout => Self::AcknowledgementReadTimeout,
            NetworkSessionError::AcknowledgementReadIo => Self::AcknowledgementReadIo,
            NetworkSessionError::AcknowledgementInvalid => Self::AcknowledgementInvalid,
            NetworkSessionError::HostReadyIo => Self::HostReadyIo,
            NetworkSessionError::ReadyIo => Self::StatusIo,
            NetworkSessionError::Protocol => Self::Protocol,
            NetworkSessionError::FrameIo => Self::FrameIo,
            NetworkSessionError::Engine => Self::Engine,
        }
    }
}
