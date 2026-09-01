//! Isolated host-side worker for one local microVM raw-IP stream.
//!
//! The worker has no dial authority. TCP and DNS are available only through an
//! injected broker implementation; the product entrypoint uses [`DenyBroker`]
//! until the policy broker is attached. The process receives an already-open
//! hybrid-vsock stream and a derived generation key on inherited AF_UNIX
//! descriptors, never the guest daemon token.

use std::collections::HashMap;
use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use async_trait::async_trait;
use codewire_netstack::{
    DnsAnswer, DnsQuestion, Netstack, NetstackConfig, NetstackLimits, TcpListener,
    build_ipv4_dns_response, parse_canonical_ipv4_tcp_packet, parse_ipv4_dns_question,
};
use codewire_vmm_guest_probe::{
    NETWORK_FRAME_HEADER_LEN, NETWORK_GUEST_ACK_LEN, NETWORK_KEY_LEN, NETWORK_MAX_PACKET_BYTES,
    NetworkGuestAck, NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
};
use rand::{RngCore as _, rngs::OsRng};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const NETWORK_BOOTSTRAP_FD: RawFd = 4;
pub const WORKER_PREPARED_MESSAGE: &[u8] = b"CWNETW1 prepared\n";
pub const WORKER_READY_MESSAGE: &[u8] = b"CWNETW1 ready\n";
pub const WORKER_STATUS_MAX_BYTES: usize = 64;
const WORKER_NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const WORKER_CONTROL_BYTES: usize = 64;

#[cfg(target_env = "musl")]
type ControlLength = libc::socklen_t;
#[cfg(not(target_env = "musl"))]
type ControlLength = libc::size_t;

#[cfg(target_env = "musl")]
fn encode_control_length(value: usize) -> Option<ControlLength> {
    value.try_into().ok()
}

#[cfg(not(target_env = "musl"))]
fn encode_control_length(value: usize) -> Option<ControlLength> {
    Some(value)
}

#[cfg(target_env = "musl")]
fn decode_control_length(value: ControlLength) -> usize {
    value as usize
}

#[cfg(not(target_env = "musl"))]
fn decode_control_length(value: ControlLength) -> usize {
    value
}

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWNETB1\0";
const BOOTSTRAP_LEN: usize = 64;
const PACKET_QUEUE: usize = 256;
const NETWORK_MTU: usize = 1_500;
const DNS_MESSAGE_LIMIT: usize = 1_232;
const BROKER_TIMEOUT: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_HANDLED_ACCESS_FS_V3: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

pub type BoxedBrokerStream = Pin<Box<dyn AsyncReadWrite + Send + Sync + Unpin + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkWorkerStartupFailure {
    InvalidIdentity,
    InheritedDescriptor,
    AmbientEnvironment,
    ThreadConfinement,
    BootstrapIo,
    InvalidBootstrap,
    FilesystemConfinement,
    SyscallConfinement,
    HelloWriteTimeout,
    HelloWriteIo,
    AcknowledgementReadTimeout,
    AcknowledgementReadIo,
    AcknowledgementInvalid,
    PreparedIo,
    HostReadyIo,
    StatusIo,
    Protocol,
    FrameIo,
    Engine,
}

impl NetworkWorkerStartupFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "invalid-identity",
            Self::InheritedDescriptor => "inherited-descriptor",
            Self::AmbientEnvironment => "ambient-environment",
            Self::ThreadConfinement => "thread-confinement",
            Self::BootstrapIo => "bootstrap-io",
            Self::InvalidBootstrap => "invalid-bootstrap",
            Self::FilesystemConfinement => "filesystem-confinement",
            Self::SyscallConfinement => "syscall-confinement",
            Self::HelloWriteTimeout => "hello-write-timeout",
            Self::HelloWriteIo => "hello-write-io",
            Self::AcknowledgementReadTimeout => "ack-read-timeout",
            Self::AcknowledgementReadIo => "ack-read-io",
            Self::AcknowledgementInvalid => "ack-invalid",
            Self::PreparedIo => "prepared-io",
            Self::HostReadyIo => "host-ready-io",
            Self::StatusIo => "status-io",
            Self::Protocol => "protocol",
            Self::FrameIo => "frame-io",
            Self::Engine => "engine",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidIdentity => 20,
            Self::InheritedDescriptor => 21,
            Self::AmbientEnvironment => 22,
            Self::ThreadConfinement => 23,
            Self::BootstrapIo => 24,
            Self::InvalidBootstrap => 25,
            Self::FilesystemConfinement => 26,
            Self::SyscallConfinement => 27,
            Self::HelloWriteTimeout => 28,
            Self::HelloWriteIo => 29,
            Self::AcknowledgementReadTimeout => 30,
            Self::AcknowledgementReadIo => 31,
            Self::AcknowledgementInvalid => 32,
            Self::PreparedIo => 33,
            Self::HostReadyIo => 34,
            Self::StatusIo => 35,
            Self::Protocol => 36,
            Self::FrameIo => 37,
            Self::Engine => 38,
        }
    }

    pub fn from_exit_code(code: i32) -> Option<Self> {
        Some(match code {
            20 => Self::InvalidIdentity,
            21 => Self::InheritedDescriptor,
            22 => Self::AmbientEnvironment,
            23 => Self::ThreadConfinement,
            24 => Self::BootstrapIo,
            25 => Self::InvalidBootstrap,
            26 => Self::FilesystemConfinement,
            27 => Self::SyscallConfinement,
            28 => Self::HelloWriteTimeout,
            29 => Self::HelloWriteIo,
            30 => Self::AcknowledgementReadTimeout,
            31 => Self::AcknowledgementReadIo,
            32 => Self::AcknowledgementInvalid,
            33 => Self::PreparedIo,
            34 => Self::HostReadyIo,
            35 => Self::StatusIo,
            36 => Self::Protocol,
            37 => Self::FrameIo,
            38 => Self::Engine,
            _ => return None,
        })
    }

    fn message(self) -> &'static [u8] {
        match self {
            Self::InvalidIdentity => b"CWNETW1 failed-invalid-identity\n",
            Self::InheritedDescriptor => b"CWNETW1 failed-inherited-descriptor\n",
            Self::AmbientEnvironment => b"CWNETW1 failed-ambient-environment\n",
            Self::ThreadConfinement => b"CWNETW1 failed-thread-confinement\n",
            Self::BootstrapIo => b"CWNETW1 failed-bootstrap-io\n",
            Self::InvalidBootstrap => b"CWNETW1 failed-invalid-bootstrap\n",
            Self::FilesystemConfinement => b"CWNETW1 failed-filesystem-confinement\n",
            Self::SyscallConfinement => b"CWNETW1 failed-syscall-confinement\n",
            Self::HelloWriteTimeout => b"CWNETW1 failed-hello-write-timeout\n",
            Self::HelloWriteIo => b"CWNETW1 failed-hello-write-io\n",
            Self::AcknowledgementReadTimeout => b"CWNETW1 failed-ack-read-timeout\n",
            Self::AcknowledgementReadIo => b"CWNETW1 failed-ack-read-io\n",
            Self::AcknowledgementInvalid => b"CWNETW1 failed-ack-invalid\n",
            Self::PreparedIo => b"CWNETW1 failed-prepared-io\n",
            Self::HostReadyIo => b"CWNETW1 failed-host-ready-io\n",
            Self::StatusIo => b"CWNETW1 failed-status-io\n",
            Self::Protocol => b"CWNETW1 failed-protocol\n",
            Self::FrameIo => b"CWNETW1 failed-frame-io\n",
            Self::Engine => b"CWNETW1 failed-engine\n",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkWorkerStartupStatus {
    Ready,
    Failed(NetworkWorkerStartupFailure),
}

pub fn decode_worker_startup_status(bytes: &[u8]) -> Option<NetworkWorkerStartupStatus> {
    if bytes == WORKER_READY_MESSAGE {
        return Some(NetworkWorkerStartupStatus::Ready);
    }
    [
        NetworkWorkerStartupFailure::InvalidIdentity,
        NetworkWorkerStartupFailure::InheritedDescriptor,
        NetworkWorkerStartupFailure::AmbientEnvironment,
        NetworkWorkerStartupFailure::ThreadConfinement,
        NetworkWorkerStartupFailure::BootstrapIo,
        NetworkWorkerStartupFailure::InvalidBootstrap,
        NetworkWorkerStartupFailure::FilesystemConfinement,
        NetworkWorkerStartupFailure::SyscallConfinement,
        NetworkWorkerStartupFailure::HelloWriteTimeout,
        NetworkWorkerStartupFailure::HelloWriteIo,
        NetworkWorkerStartupFailure::AcknowledgementReadTimeout,
        NetworkWorkerStartupFailure::AcknowledgementReadIo,
        NetworkWorkerStartupFailure::AcknowledgementInvalid,
        NetworkWorkerStartupFailure::PreparedIo,
        NetworkWorkerStartupFailure::HostReadyIo,
        NetworkWorkerStartupFailure::StatusIo,
        NetworkWorkerStartupFailure::Protocol,
        NetworkWorkerStartupFailure::FrameIo,
        NetworkWorkerStartupFailure::Engine,
    ]
    .into_iter()
    .find(|failure| bytes == failure.message())
    .map(NetworkWorkerStartupStatus::Failed)
}

#[repr(C)]
union WorkerControlBuffer {
    alignment: libc::cmsghdr,
    bytes: [u8; WORKER_CONTROL_BYTES],
}

pub(crate) fn send_worker_network_descriptor(bootstrap: RawFd, network: RawFd) -> io::Result<()> {
    validate_inherited_unix_socket(bootstrap).map_err(io::Error::other)?;
    validate_inherited_unix_socket(network).map_err(io::Error::other)?;
    let mut marker = [WORKER_NETWORK_DESCRIPTOR_MARKER];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let mut control = WorkerControlBuffer {
        bytes: [0_u8; WORKER_CONTROL_BYTES],
    };
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    if control_space > WORKER_CONTROL_BYTES {
        return Err(io::Error::other(
            "network descriptor control record is too large",
        ));
    }
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = encode_control_length(control_space)
        .ok_or_else(|| io::Error::other("network descriptor control record is too large"))?;
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    if header.is_null() {
        return Err(io::Error::other(
            "network descriptor control header is absent",
        ));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            encode_control_length(libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize)
                .ok_or_else(|| {
                    io::Error::other("network descriptor control record is too large")
                })?;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), network);
    }
    let sent = unsafe { libc::sendmsg(bootstrap, &raw const message, libc::MSG_NOSIGNAL) };
    if sent == marker.len() as isize {
        Ok(())
    } else if sent == -1 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "network descriptor transfer was incomplete",
        ))
    }
}

fn receive_worker_network_descriptor(bootstrap: RawFd) -> Result<OwnedFd, NetworkWorkerError> {
    let mut marker = [0_u8; 1];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let mut control = WorkerControlBuffer {
        bytes: [0_u8; WORKER_CONTROL_BYTES],
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = encode_control_length(WORKER_CONTROL_BYTES)
        .ok_or(NetworkWorkerError::InheritedDescriptor)?;
    let received = unsafe { libc::recvmsg(bootstrap, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != marker.len() as isize
        || marker[0] != WORKER_NETWORK_DESCRIPTOR_MARKER
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }

    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !header.is_null() {
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level != libc::SOL_SOCKET || header_ref.cmsg_type != libc::SCM_RIGHTS {
            return Err(NetworkWorkerError::InheritedDescriptor);
        }
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        let header_len = decode_control_length(header_ref.cmsg_len);
        if header_len < minimum {
            return Err(NetworkWorkerError::InheritedDescriptor);
        }
        let payload = header_len - minimum;
        if payload == 0 || !payload.is_multiple_of(std::mem::size_of::<RawFd>()) {
            return Err(NetworkWorkerError::InheritedDescriptor);
        }
        let count = payload / std::mem::size_of::<RawFd>();
        let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
        for index in 0..count {
            let descriptor = unsafe { *data.add(index) };
            if descriptor < 0 {
                return Err(NetworkWorkerError::InheritedDescriptor);
            }
            descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
        }
        header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
    }
    if descriptors.len() != 1 {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    let descriptor = descriptors
        .pop()
        .ok_or(NetworkWorkerError::InheritedDescriptor)?;
    validate_inherited_unix_socket(descriptor.as_raw_fd())?;
    Ok(descriptor)
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlow {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[async_trait]
pub trait EgressBroker: Send + Sync + 'static {
    /// Cheap policy admission before the worker binds an AnyIP listener.
    async fn authorize_tcp(&self, flow: TcpFlow) -> io::Result<()>;

    /// Return an already-connected stream for one accepted guest flow.
    async fn connect_tcp(&self, flow: TcpFlow) -> io::Result<BoxedBrokerStream>;

    /// Resolve one already-parsed canonical DNS question.
    async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<DnsAnswer>;
}

#[derive(Debug, Default)]
pub struct DenyBroker;

#[async_trait]
impl EgressBroker for DenyBroker {
    async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
        Err(denied())
    }

    async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
        Err(denied())
    }

    async fn resolve_dns(&self, _question: &DnsQuestion) -> io::Result<DnsAnswer> {
        Err(denied())
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "network broker denied request",
    )
}

/// Encode the fixed private bootstrap record written by the runner.
pub fn encode_worker_bootstrap(
    vm_id: Uuid,
    generation: u64,
    key: &NetworkKey,
) -> Result<Zeroizing<[u8; BOOTSTRAP_LEN]>, NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    let mut bytes = Zeroizing::new([0_u8; BOOTSTRAP_LEN]);
    bytes[..8].copy_from_slice(BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(vm_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_le_bytes());
    key.with_bytes(|key| bytes[32..].copy_from_slice(key));
    Ok(bytes)
}

/// Entrypoint used only by the hidden `cw` worker command.
pub async fn run_inherited_worker(vm_id: Uuid, generation: u64) -> Result<(), NetworkWorkerError> {
    run_inherited_worker_with_broker(vm_id, generation, Arc::new(DenyBroker)).await
}

/// Run the inherited worker with one explicitly injected broker.
///
/// The product entrypoint above always supplies [`DenyBroker`]. The qualified
/// hardware smoke supplies a socket-free fixture broker so the same confined
/// process and guest seam can prove allowed DNS/TCP without creating a hidden
/// host dial path.
pub async fn run_inherited_worker_with_broker<B: EgressBroker>(
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
) -> Result<(), NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    let mut bootstrap = inherited_std_unix_stream(NETWORK_BOOTSTRAP_FD)?;
    let prepared = (|| {
        bootstrap
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        bootstrap
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        if std::env::vars_os().next().is_some() {
            return Err(NetworkWorkerError::AmbientEnvironment);
        }
        require_single_threaded_process()?;
        let mut bytes = Zeroizing::new([0_u8; BOOTSTRAP_LEN]);
        bootstrap
            .read_exact(bytes.as_mut())
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        let key = decode_worker_bootstrap(bytes.as_ref(), vm_id, generation)?;
        Ok(key)
    })();
    let key = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let confinement =
        install_deny_all_filesystem_domain().and_then(|()| install_network_worker_seccomp());
    if let Err(error) = confinement {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    bootstrap
        .set_read_timeout(None)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    write_worker_control_message(&bootstrap, WORKER_PREPARED_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    let descriptor = match receive_worker_network_descriptor(bootstrap.as_raw_fd()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let network = match transferred_unix_stream(descriptor) {
        Ok(network) => network,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let status = Arc::new(StdMutex::new(Some(bootstrap)));
    let ready_status = Arc::clone(&status);
    let result = run_host_session(network, key, vm_id, generation, broker, move || {
        publish_worker_status(&ready_status, WORKER_READY_MESSAGE)
    })
    .await;
    if let Err(error) = &result {
        let _ = publish_worker_status(&status, error.startup_failure().message());
    }
    result
}

struct TransferredUnixStream {
    descriptor: AsyncFd<OwnedFd>,
}

fn transferred_unix_stream(
    descriptor: OwnedFd,
) -> Result<TransferredUnixStream, NetworkWorkerError> {
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } == -1
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    let descriptor =
        AsyncFd::new(descriptor).map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    Ok(TransferredUnixStream { descriptor })
}

impl AsyncRead for TransferredUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut ready = match self.descriptor.poll_read_ready_mut(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            let unfilled = buffer.initialize_unfilled();
            match ready
                .try_io(|descriptor| read_worker_bytes(descriptor.get_ref().as_raw_fd(), unfilled))
            {
                Ok(Ok(read)) => {
                    buffer.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for TransferredUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut ready = match self.descriptor.poll_write_ready_mut(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            match ready
                .try_io(|descriptor| send_worker_bytes(descriptor.get_ref().as_raw_fd(), buffer))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if unsafe { libc::shutdown(self.descriptor.get_ref().as_raw_fd(), libc::SHUT_WR) } == -1 {
            Poll::Ready(Err(io::Error::last_os_error()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

fn publish_worker_status(
    status: &StdMutex<Option<StdUnixStream>>,
    message: &[u8],
) -> io::Result<()> {
    let stream = status
        .lock()
        .map_err(|_| io::Error::other("network worker status lock failed"))?
        .take()
        .ok_or_else(|| io::Error::other("network worker status was already published"))?;
    write_worker_control_message(&stream, message)
}

fn write_worker_control_message(stream: &StdUnixStream, message: &[u8]) -> io::Result<()> {
    if message.is_empty() || message.len() > WORKER_STATUS_MAX_BYTES || !message.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid network worker control message",
        ));
    }
    let mut written = 0_usize;
    while written < message.len() {
        let sent = send_worker_bytes(stream.as_raw_fd(), &message[written..])?;
        if sent == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        written += sent;
    }
    Ok(())
}

fn read_worker_bytes(descriptor: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read >= 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn send_worker_bytes(descriptor: RawFd, buffer: &[u8]) -> io::Result<usize> {
    loop {
        let mut vector = libc::iovec {
            iov_base: buffer.as_ptr().cast_mut().cast(),
            iov_len: buffer.len(),
        };
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &raw mut vector;
        header.msg_iovlen = 1;
        let sent = unsafe { libc::sendmsg(descriptor, &raw const header, libc::MSG_NOSIGNAL) };
        if sent >= 0 {
            return Ok(sent as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn require_single_threaded_process() -> Result<(), NetworkWorkerError> {
    let mut tasks =
        std::fs::read_dir("/proc/self/task").map_err(|_| NetworkWorkerError::ThreadConfinement)?;
    let first = tasks
        .next()
        .transpose()
        .map_err(|_| NetworkWorkerError::ThreadConfinement)?;
    let second = tasks
        .next()
        .transpose()
        .map_err(|_| NetworkWorkerError::ThreadConfinement)?;
    if first.is_none() || second.is_some() {
        return Err(NetworkWorkerError::ThreadConfinement);
    }
    Ok(())
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

/// Enter a Landlock v3 domain with no filesystem rules. The worker needs only
/// its inherited descriptors after bootstrap, so every handled path operation
/// is denied. Linux preflight already requires Landlock ABI 3 or newer.
fn install_deny_all_filesystem_domain() -> Result<(), NetworkWorkerError> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(NetworkWorkerError::FilesystemConfinement);
    }
    let attributes = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_HANDLED_ACCESS_FS_V3,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attributes,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0_u32,
        )
    };
    if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
        return Err(NetworkWorkerError::FilesystemConfinement);
    }
    // SAFETY: a successful create_ruleset call returns one new descriptor and
    // this is its sole owner.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) };
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            std::os::fd::AsRawFd::as_raw_fd(&descriptor),
            0_u32,
        )
    } != 0
    {
        return Err(NetworkWorkerError::FilesystemConfinement);
    }
    Ok(())
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

const NETWORK_WORKER_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_sendto,
    libc::SYS_sendmmsg,
    libc::SYS_recvfrom,
    libc::SYS_recvmmsg,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_process_madvise,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_reboot,
];

// AArch64 exposes process creation through clone/clone3 and has no distinct
// fork or vfork syscall numbers. Keep the legacy x86_64 entry points denied
// where they exist without making the release build depend on absent libc
// constants on AArch64.
#[cfg(target_arch = "x86_64")]
const NETWORK_WORKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const NETWORK_WORKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

const fn bpf_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn bpf_equal(value: u32, equal: u8, unequal: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: equal,
        jf: unequal,
        k: value,
    }
}

/// Install the worker's dedicated syscall layer only after the exact
/// single-threaded Tokio runtime has created its private internal wakeup
/// descriptor. No guest-controlled byte is read before this filter is active.
fn install_network_worker_seccomp() -> Result<(), NetworkWorkerError> {
    let mut filter = vec![
        bpf_statement(BPF_LD_W_ABS, 4),
        bpf_equal(AUDIT_ARCH_NATIVE, 1, 0),
        bpf_statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        bpf_statement(BPF_LD_W_ABS, 0),
    ];
    for syscall in NETWORK_WORKER_DENIED_SYSCALLS
        .iter()
        .chain(NETWORK_WORKER_ARCH_DENIED_SYSCALLS)
    {
        filter.push(bpf_equal(*syscall as u32, 0, 1));
        filter.push(bpf_statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    filter.push(bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 1_u32, 0_u32, &raw const program) } != 0 {
        return Err(NetworkWorkerError::SyscallConfinement);
    }
    Ok(())
}

fn inherited_std_unix_stream(descriptor: RawFd) -> Result<StdUnixStream, NetworkWorkerError> {
    validate_inherited_unix_socket(descriptor)?;
    // SAFETY: the hidden worker owns each fixed inherited descriptor exactly
    // once after exec, and this function is the only constructor for it.
    Ok(unsafe { StdUnixStream::from_raw_fd(descriptor) })
}

fn validate_inherited_unix_socket(descriptor: RawFd) -> Result<(), NetworkWorkerError> {
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }

    let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            descriptor,
            (&raw mut peer).cast::<libc::sockaddr>(),
            &mut peer_len,
        )
    } == -1
        || peer_len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t
        || peer_len as usize > std::mem::size_of::<libc::sockaddr_un>()
        || peer.sun_family as i32 != libc::AF_UNIX
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    Ok(())
}

fn socket_option(descriptor: RawFd, option: i32) -> Result<i32, NetworkWorkerError> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &mut length,
        )
    } == -1
        || length as usize != std::mem::size_of::<i32>()
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    Ok(value)
}

fn decode_worker_bootstrap(
    bytes: &[u8],
    expected_vm_id: Uuid,
    expected_generation: u64,
) -> Result<NetworkKey, NetworkWorkerError> {
    validate_identity(expected_vm_id, expected_generation)?;
    if bytes.len() != BOOTSTRAP_LEN || &bytes[..8] != BOOTSTRAP_MAGIC {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let vm_id =
        Uuid::from_slice(&bytes[8..24]).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let generation = u64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .expect("fixed worker bootstrap generation"),
    );
    if vm_id != expected_vm_id || generation != expected_generation {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut key = Zeroizing::new([0_u8; NETWORK_KEY_LEN]);
    key.copy_from_slice(&bytes[32..]);
    NetworkKey::from_derived_bytes(*key).map_err(|_| NetworkWorkerError::InvalidBootstrap)
}

fn validate_identity(vm_id: Uuid, generation: u64) -> Result<(), NetworkWorkerError> {
    if vm_id.is_nil() || generation == 0 {
        return Err(NetworkWorkerError::InvalidIdentity);
    }
    Ok(())
}

/// Run one authenticated generation-bound worker over an injected stream.
/// `ready` is called only after the bounded engine exists and the guest has
/// accepted the authenticated host-ready proof.
pub async fn run_host_session<S, B, R>(
    mut stream: S,
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
    validate_identity(vm_id, generation)?;
    // Build the fixed-size engine before beginning the guest handshake. Once
    // the guest acknowledges the hello, the worker has no setup work left
    // that can consume the guest's bounded authentication window.
    let limits = NetstackLimits::default();
    let (to_stack, stack_packets) = mpsc::channel(PACKET_QUEUE);
    let (from_stack, outbound_packets) = mpsc::channel(PACKET_QUEUE);
    let stack = Netstack::with_config_and_limits(
        NetstackConfig {
            local_ip: IpAddr::V4(WORKER_IP),
            prefix_len: 30,
            mtu: NETWORK_MTU,
            verify_rx_checksums: true,
            accept_any_ip: true,
            default_gateway: None,
        },
        limits,
        stack_packets,
        from_stack.clone(),
    )
    .map_err(|_| NetworkWorkerError::Engine)?;

    let nonce = network_nonce();
    let hello = NetworkHostHello::new(vm_id, generation, nonce)
        .map_err(|_| NetworkWorkerError::Protocol)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&hello.encode(&key)))
        .await
        .map_err(|_| NetworkWorkerError::HelloWriteTimeout)?
        .map_err(|_| NetworkWorkerError::HelloWriteIo)?;
    let mut ack = [0_u8; NETWORK_GUEST_ACK_LEN];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .map_err(|_| NetworkWorkerError::AcknowledgementReadTimeout)?
        .map_err(|_| NetworkWorkerError::AcknowledgementReadIo)?;
    NetworkGuestAck::decode(&ack, &key, &nonce)
        .map_err(|_| NetworkWorkerError::AcknowledgementInvalid)?;

    stream
        .write_all(
            &NetworkHostReady::new(nonce)
                .map_err(|_| NetworkWorkerError::Protocol)?
                .encode(&key),
        )
        .await
        .map_err(|_| NetworkWorkerError::HostReadyIo)?;
    stream
        .flush()
        .await
        .map_err(|_| NetworkWorkerError::HostReadyIo)?;
    ready().map_err(|_| NetworkWorkerError::StatusIo)?;

    let session = Arc::new(Mutex::new(
        NetworkSession::new(&key, &nonce, NetworkRole::Host)
            .map_err(|_| NetworkWorkerError::Protocol)?,
    ));
    let (stream_read, stream_write) = tokio::io::split(stream);
    let (guest_packet_tx, guest_packets) = mpsc::channel(PACKET_QUEUE);
    let reader = read_authenticated_frames(stream_read, Arc::clone(&session), guest_packet_tx);
    let writer = write_authenticated_frames(stream_write, session, outbound_packets);
    let dispatcher = dispatch_packets(guest_packets, stack, to_stack, from_stack, broker);
    tokio::pin!(reader, writer, dispatcher);
    tokio::select! {
        result = &mut reader => result,
        result = &mut writer => result,
        result = &mut dispatcher => result,
    }
}

fn network_nonce() -> [u8; 32] {
    loop {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce.iter().any(|byte| *byte != 0) {
            return nonce;
        }
    }
}

async fn read_authenticated_frames<R>(
    mut stream: R,
    session: Arc<Mutex<NetworkSession>>,
    packets: mpsc::Sender<Vec<u8>>,
) -> Result<(), NetworkWorkerError>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        let frame_len =
            encoded_network_frame_len(&header).map_err(|_| NetworkWorkerError::Protocol)?;
        let mut frame = vec![0_u8; frame_len];
        frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
        stream
            .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        let packet = session
            .lock()
            .await
            .decode_packet(&frame)
            .map_err(|_| NetworkWorkerError::Protocol)?;
        packets
            .send(packet)
            .await
            .map_err(|_| NetworkWorkerError::Engine)?;
    }
}

async fn write_authenticated_frames<W>(
    mut stream: W,
    session: Arc<Mutex<NetworkSession>>,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<(), NetworkWorkerError>
where
    W: AsyncWrite + Unpin,
{
    while let Some(packet) = packets.recv().await {
        if packet.is_empty() || packet.len() > NETWORK_MAX_PACKET_BYTES {
            return Err(NetworkWorkerError::Engine);
        }
        let frame = session
            .lock()
            .await
            .encode_packet(&packet)
            .map_err(|_| NetworkWorkerError::Protocol)?;
        stream
            .write_all(&frame)
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
    }
    Err(NetworkWorkerError::Engine)
}

async fn dispatch_packets<B: EgressBroker>(
    mut packets: mpsc::Receiver<Vec<u8>>,
    stack: Netstack,
    to_stack: mpsc::Sender<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    broker: Arc<B>,
) -> Result<(), NetworkWorkerError> {
    let mut listeners = HashMap::<SocketAddr, tokio::task::JoinHandle<()>>::new();
    while let Some(packet) = packets.recv().await {
        if let Ok(question) = parse_ipv4_dns_question(&packet, WORKER_IP, DNS_MESSAGE_LIMIT) {
            if question.source.ip() != IpAddr::V4(GUEST_IP) {
                continue;
            }
            let answer =
                match tokio::time::timeout(BROKER_TIMEOUT, broker.resolve_dns(&question)).await {
                    Ok(Ok(answer)) => answer,
                    Ok(Err(_)) | Err(_) => continue,
                };
            let response = build_ipv4_dns_response(&question, answer, 30, NETWORK_MTU)
                .map_err(|_| NetworkWorkerError::Engine)?;
            outbound
                .send(response)
                .await
                .map_err(|_| NetworkWorkerError::Engine)?;
            continue;
        }

        let Ok(tcp) = parse_canonical_ipv4_tcp_packet(&packet) else {
            // UDP other than canonical virtual-resolver DNS, ICMP, IPv6, and
            // malformed/fragmented packets are intentionally not admitted.
            continue;
        };
        if tcp.source.ip() != IpAddr::V4(GUEST_IP) || tcp.destination.ip() == IpAddr::V4(WORKER_IP)
        {
            continue;
        }
        if listeners.contains_key(&tcp.destination) {
            to_stack
                .send(packet)
                .await
                .map_err(|_| NetworkWorkerError::Engine)?;
            continue;
        }
        if !tcp.initial_syn {
            continue;
        }
        let flow = TcpFlow {
            source: tcp.source,
            destination: tcp.destination,
        };
        match tokio::time::timeout(BROKER_TIMEOUT, broker.authorize_tcp(flow)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => continue,
        }
        let listener = match stack.bind_endpoint(tcp.destination).await {
            Ok(listener) => listener,
            Err(_) => continue,
        };
        let listener_broker = Arc::clone(&broker);
        listeners.insert(
            tcp.destination,
            tokio::spawn(async move {
                serve_listener(listener, listener_broker).await;
            }),
        );
        to_stack
            .send(packet)
            .await
            .map_err(|_| NetworkWorkerError::Engine)?;
    }
    Err(NetworkWorkerError::FrameIo)
}

async fn serve_listener<B: EgressBroker>(mut listener: TcpListener, broker: Arc<B>) {
    let mut bridges = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Some(mut guest) = accepted else { return; };
                let flow = TcpFlow {
                    source: guest.peer_addr(),
                    destination: guest.local_addr(),
                };
                let connected = tokio::time::timeout(BROKER_TIMEOUT, broker.connect_tcp(flow)).await;
                let Ok(Ok(mut connected)) = connected else { continue; };
                bridges.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut guest, &mut connected).await;
                    let _ = guest.shutdown().await;
                    let _ = connected.shutdown().await;
                });
            }
            completed = bridges.join_next(), if !bridges.is_empty() => {
                let _ = completed;
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkWorkerError {
    #[error("network worker identity is invalid")]
    InvalidIdentity,
    #[error("network worker inherited descriptor is invalid")]
    InheritedDescriptor,
    #[error("network worker refuses an ambient environment")]
    AmbientEnvironment,
    #[error("network worker requires an exact single-threaded runtime")]
    ThreadConfinement,
    #[error("network worker bootstrap I/O failed")]
    BootstrapIo,
    #[error("network worker bootstrap is invalid")]
    InvalidBootstrap,
    #[error("network worker filesystem confinement failed")]
    FilesystemConfinement,
    #[error("network worker syscall confinement failed")]
    SyscallConfinement,
    #[error("network worker hello write timed out")]
    HelloWriteTimeout,
    #[error("network worker hello write failed")]
    HelloWriteIo,
    #[error("network worker acknowledgement read timed out")]
    AcknowledgementReadTimeout,
    #[error("network worker acknowledgement read failed")]
    AcknowledgementReadIo,
    #[error("network worker acknowledgement authentication failed")]
    AcknowledgementInvalid,
    #[error("network worker prepared-status I/O failed")]
    PreparedIo,
    #[error("network worker host-ready proof I/O failed")]
    HostReadyIo,
    #[error("network worker final startup-status I/O failed")]
    StatusIo,
    #[error("network worker protocol authentication failed")]
    Protocol,
    #[error("network worker frame I/O failed")]
    FrameIo,
    #[error("network worker engine failed")]
    Engine,
}

impl NetworkWorkerError {
    pub fn exit_code(&self) -> i32 {
        self.startup_failure().exit_code()
    }

    fn startup_failure(&self) -> NetworkWorkerStartupFailure {
        match self {
            Self::InvalidIdentity => NetworkWorkerStartupFailure::InvalidIdentity,
            Self::InheritedDescriptor => NetworkWorkerStartupFailure::InheritedDescriptor,
            Self::AmbientEnvironment => NetworkWorkerStartupFailure::AmbientEnvironment,
            Self::ThreadConfinement => NetworkWorkerStartupFailure::ThreadConfinement,
            Self::BootstrapIo => NetworkWorkerStartupFailure::BootstrapIo,
            Self::InvalidBootstrap => NetworkWorkerStartupFailure::InvalidBootstrap,
            Self::FilesystemConfinement => NetworkWorkerStartupFailure::FilesystemConfinement,
            Self::SyscallConfinement => NetworkWorkerStartupFailure::SyscallConfinement,
            Self::HelloWriteTimeout => NetworkWorkerStartupFailure::HelloWriteTimeout,
            Self::HelloWriteIo => NetworkWorkerStartupFailure::HelloWriteIo,
            Self::AcknowledgementReadTimeout => {
                NetworkWorkerStartupFailure::AcknowledgementReadTimeout
            }
            Self::AcknowledgementReadIo => NetworkWorkerStartupFailure::AcknowledgementReadIo,
            Self::AcknowledgementInvalid => NetworkWorkerStartupFailure::AcknowledgementInvalid,
            Self::PreparedIo => NetworkWorkerStartupFailure::PreparedIo,
            Self::HostReadyIo => NetworkWorkerStartupFailure::HostReadyIo,
            Self::StatusIo => NetworkWorkerStartupFailure::StatusIo,
            Self::Protocol => NetworkWorkerStartupFailure::Protocol,
            Self::FrameIo => NetworkWorkerStartupFailure::FrameIo,
            Self::Engine => NetworkWorkerStartupFailure::Engine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::Ipv6Addr;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use codewire_netstack::DnsRecordType;
    use codewire_vmm_guest_probe::{NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkError};
    use tokio::io::{DuplexStream, duplex};

    const TOKEN: &str = "local-worker-test-token-0123456789abcdef";
    const TEST_DESTINATION: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 19)), 4_443);
    const TEST_DNS_NAME: &str = "fixture.codewire.test";
    const TEST_DNS_ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    #[test]
    fn startup_status_is_one_exact_bounded_fixed_message() {
        assert!(WORKER_PREPARED_MESSAGE.len() <= WORKER_STATUS_MAX_BYTES);
        assert_eq!(decode_worker_startup_status(WORKER_PREPARED_MESSAGE), None);
        assert_eq!(
            decode_worker_startup_status(WORKER_READY_MESSAGE),
            Some(NetworkWorkerStartupStatus::Ready)
        );
        for failure in [
            NetworkWorkerStartupFailure::InvalidIdentity,
            NetworkWorkerStartupFailure::InheritedDescriptor,
            NetworkWorkerStartupFailure::AmbientEnvironment,
            NetworkWorkerStartupFailure::ThreadConfinement,
            NetworkWorkerStartupFailure::BootstrapIo,
            NetworkWorkerStartupFailure::InvalidBootstrap,
            NetworkWorkerStartupFailure::FilesystemConfinement,
            NetworkWorkerStartupFailure::SyscallConfinement,
            NetworkWorkerStartupFailure::HelloWriteTimeout,
            NetworkWorkerStartupFailure::HelloWriteIo,
            NetworkWorkerStartupFailure::AcknowledgementReadTimeout,
            NetworkWorkerStartupFailure::AcknowledgementReadIo,
            NetworkWorkerStartupFailure::AcknowledgementInvalid,
            NetworkWorkerStartupFailure::PreparedIo,
            NetworkWorkerStartupFailure::HostReadyIo,
            NetworkWorkerStartupFailure::StatusIo,
            NetworkWorkerStartupFailure::Protocol,
            NetworkWorkerStartupFailure::FrameIo,
            NetworkWorkerStartupFailure::Engine,
        ] {
            assert!(failure.message().len() <= WORKER_STATUS_MAX_BYTES);
            assert_eq!(
                NetworkWorkerStartupFailure::from_exit_code(failure.exit_code()),
                Some(failure)
            );
            assert_eq!(
                decode_worker_startup_status(failure.message()),
                Some(NetworkWorkerStartupStatus::Failed(failure))
            );
            let mut trailing = failure.message().to_vec();
            trailing.push(b'x');
            assert_eq!(decode_worker_startup_status(&trailing), None);
        }
        assert_eq!(
            decode_worker_startup_status(b"CWNETW1 failed-forged\n"),
            None
        );
    }

    #[test]
    fn network_descriptor_is_transferred_once_with_close_on_exec() {
        let (bootstrap_sender, bootstrap_receiver) = StdUnixStream::pair().unwrap();
        let (mut network_peer, network_sender) = StdUnixStream::pair().unwrap();
        network_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        send_worker_network_descriptor(bootstrap_sender.as_raw_fd(), network_sender.as_raw_fd())
            .unwrap();
        let descriptor = receive_worker_network_descriptor(bootstrap_receiver.as_raw_fd())
            .expect("worker rejected transferred network descriptor");
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(network_sender);
        let mut transferred = StdUnixStream::from(descriptor);
        transferred
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        network_peer.write_all(b"from-runner").unwrap();
        let mut received = [0_u8; 11];
        transferred.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"from-runner");

        transferred.write_all(b"from-worker").unwrap();
        let mut returned = [0_u8; 11];
        network_peer.read_exact(&mut returned).unwrap();
        assert_eq!(&returned, b"from-worker");
    }

    #[test]
    fn network_descriptor_transfer_rejects_a_marker_without_rights() {
        let (mut bootstrap_sender, bootstrap_receiver) = StdUnixStream::pair().unwrap();
        bootstrap_sender
            .write_all(&[WORKER_NETWORK_DESCRIPTOR_MARKER])
            .unwrap();
        assert!(matches!(
            receive_worker_network_descriptor(bootstrap_receiver.as_raw_fd()),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));
    }

    #[test]
    fn inherited_descriptor_must_be_a_connected_unix_stream() {
        let (stream, _peer) = StdUnixStream::pair().unwrap();
        assert!(validate_inherited_unix_socket(stream.as_raw_fd()).is_ok());

        let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(matches!(
            validate_inherited_unix_socket(datagram.as_raw_fd()),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let directory = tempfile::tempdir().unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.path().join("listener")).unwrap();
        assert!(matches!(
            validate_inherited_unix_socket(listener.as_raw_fd()),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let file = tempfile::tempfile().unwrap();
        assert!(matches!(
            validate_inherited_unix_socket(file.as_raw_fd()),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));
    }

    struct FixtureBroker {
        allowed_destination: Option<SocketAddr>,
        connector: StdMutex<Option<DuplexStream>>,
        allowed: AtomicUsize,
        connected: AtomicUsize,
        resolved: AtomicUsize,
        denied: StdMutex<Vec<SocketAddr>>,
    }

    impl FixtureBroker {
        fn new(allowed_destination: Option<SocketAddr>, connector: Option<DuplexStream>) -> Self {
            Self {
                allowed_destination,
                connector: StdMutex::new(connector),
                allowed: AtomicUsize::new(0),
                connected: AtomicUsize::new(0),
                resolved: AtomicUsize::new(0),
                denied: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl EgressBroker for FixtureBroker {
        async fn authorize_tcp(&self, flow: TcpFlow) -> io::Result<()> {
            if flow.source.ip() == IpAddr::V4(GUEST_IP)
                && Some(flow.destination) == self.allowed_destination
            {
                self.allowed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            } else {
                self.denied.lock().unwrap().push(flow.destination);
                Err(denied())
            }
        }

        async fn connect_tcp(&self, flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            if flow.source.ip() != IpAddr::V4(GUEST_IP)
                || Some(flow.destination) != self.allowed_destination
            {
                return Err(denied());
            }
            let connector = self.connector.lock().unwrap().take().ok_or_else(denied)?;
            self.connected.fetch_add(1, Ordering::Relaxed);
            Ok(Box::pin(connector))
        }

        async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<DnsAnswer> {
            if question.source.ip() != IpAddr::V4(GUEST_IP)
                || question.server != SocketAddr::new(IpAddr::V4(WORKER_IP), 53)
                || question.name != TEST_DNS_NAME
                || question.record_type != DnsRecordType::A
            {
                return Err(denied());
            }
            self.resolved.fetch_add(1, Ordering::Relaxed);
            Ok(DnsAnswer::Ipv4(TEST_DNS_ANSWER))
        }
    }

    #[test]
    fn bootstrap_is_identity_bound_and_contains_only_the_derived_key() {
        let (vm_id, generation) = identity();
        let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let bytes = encode_worker_bootstrap(vm_id, generation, &key).unwrap();
        assert!(decode_worker_bootstrap(bytes.as_ref(), vm_id, generation).is_ok());
        assert!(decode_worker_bootstrap(bytes.as_ref(), vm_id, generation + 1).is_err());
        assert!(
            !bytes
                .windows(TOKEN.len())
                .any(|window| window == TOKEN.as_bytes())
        );
    }

    #[tokio::test]
    async fn authenticated_worker_bridges_only_the_injected_tcp_stream() {
        let (vm_id, generation) = identity();
        let (host_endpoint, guest_endpoint) = duplex(128 * 1024);
        let (connector, mut upstream) = duplex(8 * 1024);
        let broker = Arc::new(FixtureBroker::new(Some(TEST_DESTINATION), Some(connector)));
        let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let host_broker = Arc::clone(&broker);
        let host = tokio::spawn(run_host_session(
            host_endpoint,
            host_key,
            vm_id,
            generation,
            host_broker,
            || Ok(()),
        ));

        let (guest_outbound, guest_packets) = mpsc::channel(PACKET_QUEUE);
        let (to_guest, guest_inbound) = mpsc::channel(PACKET_QUEUE);
        let guest = Netstack::with_config(
            NetstackConfig {
                local_ip: IpAddr::V4(GUEST_IP),
                prefix_len: 30,
                mtu: NETWORK_MTU,
                verify_rx_checksums: true,
                accept_any_ip: false,
                default_gateway: Some(IpAddr::V4(WORKER_IP)),
            },
            guest_inbound,
            guest_outbound,
        )
        .unwrap();
        let guest_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let guest_transport = tokio::spawn(run_guest_packet_transport(
            guest_endpoint,
            guest_key,
            vm_id,
            generation,
            guest_packets,
            to_guest,
        ));

        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), guest.connect(TEST_DESTINATION))
                .await
                .expect("guest TCP connect timed out")
                .expect("guest TCP connect failed");
        let request = b"synthetic request through the injected connector";
        stream.write_all(request).await.unwrap();
        let mut received = vec![0_u8; request.len()];
        tokio::time::timeout(Duration::from_secs(5), upstream.read_exact(&mut received))
            .await
            .expect("injected connector did not receive guest bytes")
            .unwrap();
        assert_eq!(received, request);

        let response = b"synthetic broker response";
        upstream.write_all(response).await.unwrap();
        let mut returned = vec![0_u8; response.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut returned))
            .await
            .expect("guest did not receive injected connector bytes")
            .unwrap();
        assert_eq!(returned, response);
        assert_eq!(broker.allowed.load(Ordering::Relaxed), 1);
        assert_eq!(broker.connected.load(Ordering::Relaxed), 1);
        assert!(broker.denied.lock().unwrap().is_empty());

        guest_transport.abort();
        assert!(guest_transport.await.unwrap_err().is_cancelled());
        let result = tokio::time::timeout(Duration::from_secs(2), host)
            .await
            .expect("worker did not fail closed after transport loss")
            .unwrap();
        assert!(matches!(result, Err(NetworkWorkerError::FrameIo)));
    }

    #[tokio::test]
    async fn dns_is_local_and_every_unbrokered_packet_class_is_dropped() {
        let (vm_id, generation) = identity();
        let (host_endpoint, mut guest_endpoint) = duplex(128 * 1024);
        let broker = Arc::new(FixtureBroker::new(None, None));
        let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let host_broker = Arc::clone(&broker);
        let host = tokio::spawn(run_host_session(
            host_endpoint,
            host_key,
            vm_id,
            generation,
            host_broker,
            || Ok(()),
        ));
        let guest_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let mut session =
            authenticate_guest_endpoint(&mut guest_endpoint, &guest_key, vm_id, generation)
                .await
                .unwrap();

        let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        write_guest_packet(&mut guest_endpoint, &mut session, &query)
            .await
            .unwrap();
        let response = read_guest_packet(&mut guest_endpoint, &mut session)
            .await
            .unwrap();
        assert_dns_response(&response);
        assert_eq!(broker.resolved.load(Ordering::Relaxed), 1);

        let denied_destinations = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
        ];
        let denied_packets = [
            dns_query_packet(Ipv4Addr::new(8, 8, 8, 8), 53, TEST_DNS_NAME),
            dns_query_packet(WORKER_IP, 5_353, TEST_DNS_NAME),
            tcp_syn_packet(denied_destinations[0]),
            tcp_syn_packet(denied_destinations[1]),
            ipv4_packet(GUEST_IP, WORKER_IP, 1, &[8, 0, 0, 0, 0, 0, 0, 0]),
            ipv6_packet(),
            vec![0_u8; 20],
        ];
        for packet in denied_packets {
            write_guest_packet(&mut guest_endpoint, &mut session, &packet)
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if broker.denied.lock().unwrap().len() == denied_destinations.len() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker did not inspect denied TCP destinations");
        assert_eq!(
            broker.denied.lock().unwrap().as_slice(),
            denied_destinations
        );
        assert_eq!(broker.resolved.load(Ordering::Relaxed), 1);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                read_guest_packet(&mut guest_endpoint, &mut session),
            )
            .await
            .is_err(),
            "denied packet unexpectedly produced a guest response"
        );

        drop(guest_endpoint);
        let result = tokio::time::timeout(Duration::from_secs(2), host)
            .await
            .expect("worker did not terminate after guest transport loss")
            .unwrap();
        assert!(matches!(result, Err(NetworkWorkerError::FrameIo)));
    }

    #[test]
    fn deny_all_landlock_blocks_new_path_access() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_NETWORK_WORKER_LANDLOCK";
        if std::env::var_os(CHILD_MARKER).is_some() {
            install_deny_all_filesystem_domain().unwrap();
            let error = std::fs::File::open("/etc/passwd").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EACCES));
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("network_worker::tests::deny_all_landlock_blocks_new_path_access")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn seccomp_denies_dial_process_and_async_io_authority() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_NETWORK_WORKER_SECCOMP";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let (control, peer) = StdUnixStream::pair().unwrap();
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            install_network_worker_seccomp().unwrap();
            write_worker_control_message(&control, WORKER_PREPARED_MESSAGE).unwrap();
            let mut received = [0_u8; WORKER_PREPARED_MESSAGE.len()];
            assert_eq!(
                unsafe {
                    libc::read(
                        peer.as_raw_fd(),
                        received.as_mut_ptr().cast(),
                        received.len(),
                    )
                },
                received.len() as isize
            );
            assert_eq!(&received, WORKER_PREPARED_MESSAGE);
            assert_eq!(
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0_u32) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_io_uring_setup,
                        0_u32,
                        std::ptr::null::<libc::c_void>(),
                    )
                },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("network_worker::tests::seccomp_denies_dial_process_and_async_io_authority")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    async fn authenticate_guest_endpoint(
        stream: &mut DuplexStream,
        key: &NetworkKey,
        vm_id: Uuid,
        generation: u64,
    ) -> Result<NetworkSession, NetworkError> {
        let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
        stream.read_exact(&mut hello).await.unwrap();
        let hello = NetworkHostHello::decode(&hello, key, vm_id, generation)?;
        stream
            .write_all(&NetworkGuestAck::new(hello.nonce)?.encode(key))
            .await
            .unwrap();
        let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
        stream.read_exact(&mut ready).await.unwrap();
        NetworkHostReady::decode(&ready, key, &hello.nonce)?;
        NetworkSession::new(key, &hello.nonce, NetworkRole::Guest)
    }

    async fn run_guest_packet_transport(
        mut stream: DuplexStream,
        key: NetworkKey,
        vm_id: Uuid,
        generation: u64,
        mut outbound: mpsc::Receiver<Vec<u8>>,
        inbound: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), NetworkWorkerError> {
        let session = authenticate_guest_endpoint(&mut stream, &key, vm_id, generation)
            .await
            .map_err(|_| NetworkWorkerError::Protocol)?;
        let session = Arc::new(Mutex::new(session));
        let (mut reader, mut writer) = tokio::io::split(stream);
        let inbound_session = Arc::clone(&session);
        let read = async move {
            loop {
                let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
                reader
                    .read_exact(&mut header)
                    .await
                    .map_err(|_| NetworkWorkerError::FrameIo)?;
                let length =
                    encoded_network_frame_len(&header).map_err(|_| NetworkWorkerError::Protocol)?;
                let mut frame = vec![0_u8; length];
                frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
                reader
                    .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
                    .await
                    .map_err(|_| NetworkWorkerError::FrameIo)?;
                let packet = inbound_session
                    .lock()
                    .await
                    .decode_packet(&frame)
                    .map_err(|_| NetworkWorkerError::Protocol)?;
                inbound
                    .send(packet)
                    .await
                    .map_err(|_| NetworkWorkerError::Engine)?;
            }
        };
        let outbound_session = Arc::clone(&session);
        let write = async move {
            while let Some(packet) = outbound.recv().await {
                let frame = outbound_session
                    .lock()
                    .await
                    .encode_packet(&packet)
                    .map_err(|_| NetworkWorkerError::Protocol)?;
                writer
                    .write_all(&frame)
                    .await
                    .map_err(|_| NetworkWorkerError::FrameIo)?;
            }
            Err(NetworkWorkerError::Engine)
        };
        tokio::pin!(read, write);
        tokio::select! {
            result = &mut read => result,
            result = &mut write => result,
        }
    }

    async fn write_guest_packet(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
        packet: &[u8],
    ) -> io::Result<()> {
        let frame = session.encode_packet(packet).map_err(io::Error::other)?;
        stream.write_all(&frame).await
    }

    async fn read_guest_packet(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
    ) -> io::Result<Vec<u8>> {
        let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let length = encoded_network_frame_len(&header).map_err(io::Error::other)?;
        let mut frame = vec![0_u8; length];
        frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
        stream
            .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
            .await?;
        session.decode_packet(&frame).map_err(io::Error::other)
    }

    fn dns_query_packet(server: Ipv4Addr, port: u16, name: &str) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&0x1234_u16.to_be_bytes());
        dns.extend_from_slice(&0x0100_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0_u8; 6]);
        for label in name.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        udp_packet(GUEST_IP, server, 53_000, port, &dns)
    }

    fn udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = 8 + payload.len();
        let mut udp = vec![0_u8; length];
        udp[..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        let checksum = transport_checksum(source, destination, 17, &udp);
        udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
        ipv4_packet(source, destination, 17, &udp)
    }

    fn tcp_syn_packet(destination: SocketAddr) -> Vec<u8> {
        let IpAddr::V4(destination_ip) = destination.ip() else {
            unreachable!()
        };
        let mut tcp = vec![0_u8; 20];
        tcp[..2].copy_from_slice(&40_000_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
        let checksum = transport_checksum(GUEST_IP, destination_ip, 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        ipv4_packet(GUEST_IP, destination_ip, 6, &tcp)
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + payload.len()];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(payload);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[6] = 59;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet
    }

    fn transport_checksum(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + payload.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.push(0);
        pseudo.push(protocol);
        pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(payload);
        internet_checksum(&pseudo)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn assert_dns_response(packet: &[u8]) {
        assert!(packet.len() >= 32);
        assert_eq!(&packet[12..16], &WORKER_IP.octets());
        assert_eq!(&packet[16..20], &GUEST_IP.octets());
        assert_eq!(packet[9], 17);
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 53);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 53_000);
        assert_eq!(u16::from_be_bytes([packet[28], packet[29]]), 0x1234);
        assert_ne!(u16::from_be_bytes([packet[30], packet[31]]) & 0x8000, 0);
        assert!(packet.ends_with(&TEST_DNS_ANSWER.octets()));
        assert_eq!(internet_checksum(&packet[..20]), 0);
    }
}
