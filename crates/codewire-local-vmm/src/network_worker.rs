//! Isolated host-side worker for one local microVM raw-IP stream.
//!
//! The worker has no dial authority. TCP and DNS are available only through an
//! authenticated capability to the separate egress broker. Verification may
//! inject a socket-free broker through a separate explicit entrypoint. The
//! process receives already-open streams and generation keys on inherited
//! AF_UNIX descriptors, never the guest daemon token or provider credentials.

use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use async_trait::async_trait;
use codewire_egress_broker::DnsRecordFamily;
use codewire_egress_broker::ipc::{
    BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS, BrokerIpcBinding, BrokerIpcClient,
    BrokerIpcDnsResponse, BrokerIpcError, BrokerIpcKey,
};
use codewire_egress_policy::CompiledPolicy;
use codewire_netstack::{DnsAnswer, DnsQuestion, DnsRecordType};
use codewire_vmm_guest_probe::{NETWORK_KEY_LEN, NetworkKey};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::host_port::{
    HOST_PORT_CONTROL_FRAME_LEN, HOST_PORT_CONTROL_KEY_LEN, HostPortBinding,
    HostPortControlReceiver, is_host_port_control_frame,
};
#[cfg(target_os = "linux")]
use crate::linux::confinement::{
    install_denied_syscalls, install_deny_all_filesystem_domain as restrict_filesystem,
    lock_exec_process_privileges, require_single_threaded_process as require_single_thread,
};
use crate::mesh_ingress::{
    MAX_MESH_INGRESS_PORTS, MESH_INGRESS_CONTROL_KEY_LEN, MeshIngressControlReceiver,
    is_mesh_ingress_control_frame, validate_canonical_mesh_ingress_ports,
};
pub use crate::network_session::{
    AsyncReadWrite, BoxedBrokerStream, BrokerDnsAnswer, DenyBroker, EgressBroker, TcpFlow,
};
use crate::network_session::{
    InboundGuestStream, MAX_INBOUND_STREAM_FLOWS, NetworkSessionError, run_network_session,
    run_network_session_with_ingress as run_portable_network_session_with_ingress,
};
#[cfg(test)]
use crate::network_session::{NETWORK_MTU, PACKET_QUEUE};

#[cfg(test)]
use codewire_netstack::{Netstack, NetstackConfig};
#[cfg(test)]
use codewire_vmm_guest_probe::{
    NETWORK_FRAME_HEADER_LEN, NetworkGuestAck, NetworkHostHello, NetworkHostReady, NetworkRole,
    NetworkSession, encoded_network_frame_len,
};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::sync::Mutex;

pub const NETWORK_BOOTSTRAP_FD: RawFd = 4;
pub const WORKER_PREPARED_MESSAGE: &[u8] = b"CWNETW1 prepared\n";
pub const WORKER_BROKER_READY_MESSAGE: &[u8] = b"CWNETW1 broker-ready\n";
pub const WORKER_READY_MESSAGE: &[u8] = b"CWNETW1 ready\n";
pub const WORKER_STATUS_MAX_BYTES: usize = 64;
const WORKER_BROKER_DESCRIPTOR_MARKER: u8 = b'B';
const WORKER_NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const WORKER_HOST_PORT_DESCRIPTOR_MARKER: u8 = b'P';
const WORKER_MESH_INGRESS_DESCRIPTOR_MARKER: u8 = b'M';
const WORKER_CONTROL_BYTES: usize = 64;

#[cfg(any(target_env = "musl", target_os = "macos"))]
type ControlLength = libc::socklen_t;
#[cfg(not(any(target_env = "musl", target_os = "macos")))]
type ControlLength = libc::size_t;

#[cfg(any(target_env = "musl", target_os = "macos"))]
fn encode_control_length(value: usize) -> Option<ControlLength> {
    value.try_into().ok()
}

#[cfg(not(any(target_env = "musl", target_os = "macos")))]
fn encode_control_length(value: usize) -> Option<ControlLength> {
    Some(value)
}

#[cfg(any(target_env = "musl", target_os = "macos"))]
fn decode_control_length(value: ControlLength) -> usize {
    value as usize
}

#[cfg(not(any(target_env = "musl", target_os = "macos")))]
fn decode_control_length(value: ControlLength) -> usize {
    value
}

// Darwin has neither MSG_NOSIGNAL nor MSG_CMSG_CLOEXEC: the sender sets
// SO_NOSIGPIPE, and each received descriptor is marked close-on-exec at once.
#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(target_os = "macos")]
const SEND_FLAGS: libc::c_int = 0;
#[cfg(target_os = "linux")]
const RECEIVE_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(target_os = "macos")]
const RECEIVE_FLAGS: libc::c_int = 0;

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWNETB1\0";
const BOOTSTRAP_LEN: usize = 64;
const PRODUCT_BOOTSTRAP_MAGIC: &[u8; 8] = b"CWNETB3\0";
const PRODUCT_BOOTSTRAP_LEN: usize = 336;
const PRODUCT_POLICY_DIGEST_OFFSET: usize = 64;
const PRODUCT_BROKER_KEY_OFFSET: usize = 96;
const PRODUCT_HOST_PORT_KEY_OFFSET: usize = 128;
const PRODUCT_MESH_INGRESS_KEY_OFFSET: usize = 160;
const PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET: usize = 192;
const PRODUCT_MESH_INGRESS_PORTS_OFFSET: usize = 194;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
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
    PrivilegeConfinement,
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
            Self::PrivilegeConfinement => "privilege-confinement",
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
            Self::PrivilegeConfinement => 39,
        }
    }

    pub(crate) fn runner_error_code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "network_worker_invalid_identity",
            Self::InheritedDescriptor => "network_worker_inherited_descriptor",
            Self::AmbientEnvironment => "network_worker_ambient_environment",
            Self::ThreadConfinement => "network_worker_thread_confinement",
            Self::BootstrapIo => "network_worker_bootstrap_io",
            Self::InvalidBootstrap => "network_worker_invalid_bootstrap",
            Self::FilesystemConfinement => "network_worker_filesystem_confinement",
            Self::SyscallConfinement => "network_worker_syscall_confinement",
            Self::HelloWriteTimeout => "network_worker_hello_write_timeout",
            Self::HelloWriteIo => "network_worker_hello_write_io",
            Self::AcknowledgementReadTimeout => "network_worker_acknowledgement_read_timeout",
            Self::AcknowledgementReadIo => "network_worker_acknowledgement_read_io",
            Self::AcknowledgementInvalid => "network_worker_acknowledgement_invalid",
            Self::PreparedIo => "network_worker_prepared_io",
            Self::HostReadyIo => "network_worker_host_ready_io",
            Self::StatusIo => "network_worker_status_io",
            Self::Protocol => "network_worker_protocol",
            Self::FrameIo => "network_worker_frame_io",
            Self::Engine => "network_worker_engine",
            Self::PrivilegeConfinement => "network_worker_privilege_confinement",
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
            39 => Self::PrivilegeConfinement,
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
            Self::PrivilegeConfinement => b"CWNETW1 failed-privilege-confinement\n",
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
        NetworkWorkerStartupFailure::PrivilegeConfinement,
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
    validate_inherited_unix_socket(network).map_err(io::Error::other)?;
    send_worker_descriptor(bootstrap, network, WORKER_NETWORK_DESCRIPTOR_MARKER)
}

pub(crate) fn send_worker_broker_descriptor(bootstrap: RawFd, broker: RawFd) -> io::Result<()> {
    validate_inherited_unix_socket(broker).map_err(io::Error::other)?;
    send_worker_descriptor(bootstrap, broker, WORKER_BROKER_DESCRIPTOR_MARKER)
}

pub(crate) fn send_worker_host_port_descriptor(bootstrap: RawFd, stream: RawFd) -> io::Result<()> {
    validate_connected_ipv4_stream(stream, None).map_err(io::Error::other)?;
    send_worker_descriptor(bootstrap, stream, WORKER_HOST_PORT_DESCRIPTOR_MARKER)
}

pub(crate) fn send_mesh_ingress_descriptor(bootstrap: RawFd, stream: RawFd) -> io::Result<()> {
    validate_inherited_unix_socket(stream).map_err(io::Error::other)?;
    send_worker_descriptor(bootstrap, stream, WORKER_MESH_INGRESS_DESCRIPTOR_MARKER)
}

fn send_worker_descriptor(bootstrap: RawFd, descriptor: RawFd, marker: u8) -> io::Result<()> {
    validate_inherited_unix_socket(bootstrap).map_err(io::Error::other)?;
    if descriptor < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid transferred descriptor",
        ));
    }
    let mut marker = [marker];
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
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }
    #[cfg(target_os = "macos")]
    {
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                bootstrap,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw const enabled).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let sent = unsafe { libc::sendmsg(bootstrap, &raw const message, SEND_FLAGS) };
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
    let descriptor = receive_worker_descriptor(bootstrap, WORKER_NETWORK_DESCRIPTOR_MARKER)
        .map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    validate_inherited_unix_socket(descriptor.as_raw_fd())?;
    Ok(descriptor)
}

fn receive_worker_broker_descriptor(bootstrap: RawFd) -> Result<OwnedFd, NetworkWorkerError> {
    let descriptor = receive_worker_descriptor(bootstrap, WORKER_BROKER_DESCRIPTOR_MARKER)
        .map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    validate_inherited_unix_socket(descriptor.as_raw_fd())?;
    Ok(descriptor)
}

pub(crate) async fn receive_mesh_ingress_descriptor(
    control: &tokio::net::UnixStream,
) -> Result<OwnedFd, NetworkWorkerError> {
    loop {
        control
            .readable()
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        match receive_worker_descriptor(control.as_raw_fd(), WORKER_MESH_INGRESS_DESCRIPTOR_MARKER)
        {
            Ok(descriptor) => {
                validate_inherited_unix_socket(descriptor.as_raw_fd())?;
                return Ok(descriptor);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(NetworkWorkerError::InheritedDescriptor),
        }
    }
}

fn receive_worker_descriptor(bootstrap: RawFd, expected_marker: u8) -> io::Result<OwnedFd> {
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid control length"))?;
    let received = unsafe { libc::recvmsg(bootstrap, &raw mut message, RECEIVE_FLAGS) };
    if received == -1 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }

    let mut descriptors = Vec::new();
    let mut valid_control = true;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !header.is_null() {
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level != libc::SOL_SOCKET || header_ref.cmsg_type != libc::SCM_RIGHTS {
            valid_control = false;
            header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
            continue;
        }
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        let header_len = decode_control_length(header_ref.cmsg_len);
        if header_len < minimum {
            valid_control = false;
            break;
        }
        let payload = header_len - minimum;
        if payload == 0 || !payload.is_multiple_of(std::mem::size_of::<RawFd>()) {
            valid_control = false;
            break;
        }
        let count = payload / std::mem::size_of::<RawFd>();
        let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
        for index in 0..count {
            let descriptor = unsafe { *data.add(index) };
            if descriptor < 0 {
                valid_control = false;
                continue;
            }
            descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
            #[cfg(target_os = "macos")]
            if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                valid_control = false;
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
    }
    if received != marker.len() as isize
        || marker[0] != expected_marker
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || !valid_control
        || descriptors.len() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid transferred descriptor record",
        ));
    }
    descriptors
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "descriptor is absent"))
}

pub struct IpcEgressBroker {
    client: BrokerIpcClient,
}

impl IpcEgressBroker {
    fn new(
        streams: Vec<tokio::net::UnixStream>,
        binding: BrokerIpcBinding,
        key: BrokerIpcKey,
    ) -> Result<Self, NetworkWorkerError> {
        Ok(Self {
            client: BrokerIpcClient::new(streams, binding, key)
                .map_err(|_| NetworkWorkerError::InheritedDescriptor)?,
        })
    }

    /// Prove every session's authenticated binding without opening a network
    /// connection: the compiled policy refuses each verification request.
    async fn verify_binding(&self) -> Result<(), NetworkWorkerError> {
        self.client
            .verify_sessions()
            .await
            .map_err(|_| NetworkWorkerError::Protocol)
    }

    fn admit_guest_flow(flow: TcpFlow) -> io::Result<SocketAddr> {
        if flow.source.ip() != IpAddr::V4(GUEST_IP)
            || flow.source.port() == 0
            || flow.destination.port() == 0
        {
            return Err(denied());
        }
        Ok(flow.destination)
    }
}

#[async_trait]
impl EgressBroker for IpcEgressBroker {
    async fn authorize_tcp(&self, flow: TcpFlow) -> io::Result<()> {
        let destination = Self::admit_guest_flow(flow)?;
        self.client
            .authorize_tcp(destination)
            .await
            .map_err(ipc_broker_error)
    }

    async fn connect_tcp(&self, flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
        let destination = Self::admit_guest_flow(flow)?;
        let descriptor = self
            .client
            .connect_tcp(destination)
            .await
            .map_err(ipc_broker_error)?;
        let stream = transferred_stream(descriptor)?;
        Ok(Box::pin(stream))
    }

    async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
        if question.source.ip() != IpAddr::V4(GUEST_IP)
            || question.source.port() == 0
            || question.server != SocketAddr::new(IpAddr::V4(WORKER_IP), 53)
        {
            return Err(denied());
        }
        let family = match question.record_type {
            DnsRecordType::A => DnsRecordFamily::Ipv4,
            DnsRecordType::Aaaa => DnsRecordFamily::Ipv6,
        };
        match self
            .client
            .resolve_dns(&question.name, family)
            .await
            .map_err(ipc_broker_error)?
        {
            BrokerIpcDnsResponse::Addresses {
                addresses,
                ttl_seconds,
            } => {
                let address = addresses
                    .into_iter()
                    .next()
                    .ok_or_else(|| io::Error::other("egress broker returned no DNS address"))?;
                let answer = match (question.record_type, address) {
                    (DnsRecordType::A, IpAddr::V4(address)) => DnsAnswer::Ipv4(address),
                    (DnsRecordType::Aaaa, IpAddr::V6(address)) => DnsAnswer::Ipv6(address),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "egress broker returned the wrong DNS family",
                        ));
                    }
                };
                Ok(BrokerDnsAnswer {
                    answer,
                    ttl_seconds,
                })
            }
            BrokerIpcDnsResponse::NoData => Ok(BrokerDnsAnswer {
                answer: DnsAnswer::NoData,
                ttl_seconds: 30,
            }),
            BrokerIpcDnsResponse::NameError => Ok(BrokerDnsAnswer {
                answer: DnsAnswer::NameError,
                ttl_seconds: 30,
            }),
        }
    }
}

fn ipc_broker_error(error: BrokerIpcError) -> io::Error {
    let kind = match error {
        BrokerIpcError::Denied => io::ErrorKind::PermissionDenied,
        BrokerIpcError::RemoteUnavailable => io::ErrorKind::ConnectionRefused,
        BrokerIpcError::SessionBusy => io::ErrorKind::WouldBlock,
        _ => io::ErrorKind::ConnectionAborted,
    };
    io::Error::new(kind, "authenticated egress broker request failed")
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

/// Encode the product bootstrap containing one generation network key, one
/// policy digest, separate non-provider ingress/broker HMAC keys, and the
/// immutable Mesh guest-port allowlist.
pub fn encode_product_worker_bootstrap(
    vm_id: Uuid,
    generation: u64,
    network_key: &NetworkKey,
    broker_key: &[u8; BROKER_IPC_KEY_LEN],
    host_port_key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
    mesh_ingress_key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    mesh_ingress_ports: &[u16],
) -> Result<Zeroizing<[u8; PRODUCT_BOOTSTRAP_LEN]>, NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    if broker_key.iter().all(|byte| *byte == 0)
        || host_port_key.iter().all(|byte| *byte == 0)
        || mesh_ingress_key.iter().all(|byte| *byte == 0)
        || validate_canonical_mesh_ingress_ports(mesh_ingress_ports).is_err()
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let policy = CompiledPolicy::developer_baseline();
    let mut bytes = Zeroizing::new([0_u8; PRODUCT_BOOTSTRAP_LEN]);
    bytes[..8].copy_from_slice(PRODUCT_BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(vm_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_le_bytes());
    network_key.with_bytes(|key| bytes[32..64].copy_from_slice(key));
    bytes[PRODUCT_POLICY_DIGEST_OFFSET..PRODUCT_BROKER_KEY_OFFSET]
        .copy_from_slice(policy.digest().as_bytes());
    bytes[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_HOST_PORT_KEY_OFFSET].copy_from_slice(broker_key);
    bytes[PRODUCT_HOST_PORT_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET]
        .copy_from_slice(host_port_key);
    bytes[PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET]
        .copy_from_slice(mesh_ingress_key);
    bytes[PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET..PRODUCT_MESH_INGRESS_PORTS_OFFSET]
        .copy_from_slice(&(mesh_ingress_ports.len() as u16).to_le_bytes());
    for (index, port) in mesh_ingress_ports.iter().enumerate() {
        let offset = PRODUCT_MESH_INGRESS_PORTS_OFFSET + index * std::mem::size_of::<u16>();
        bytes[offset..offset + std::mem::size_of::<u16>()].copy_from_slice(&port.to_le_bytes());
    }
    Ok(bytes)
}

struct ProductWorkerBootstrap {
    network_key: NetworkKey,
    broker_binding: BrokerIpcBinding,
    broker_key: BrokerIpcKey,
    host_port_key: Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>,
    mesh_ingress_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    mesh_ingress_ports: Vec<u16>,
}

struct ProductWorkerSession {
    network_key: NetworkKey,
    host_port_key: Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>,
    mesh_ingress_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    mesh_ingress_ports: Vec<u16>,
}

/// Entrypoint used only by the hidden product `cw` worker command.
pub async fn run_inherited_worker(vm_id: Uuid, generation: u64) -> Result<(), NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    let mut bootstrap = inherited_std_unix_stream(NETWORK_BOOTSTRAP_FD)?;
    let prepared = (|| {
        bootstrap
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        bootstrap
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        if ambient_environment_present() {
            return Err(NetworkWorkerError::AmbientEnvironment);
        }
        require_single_threaded_process()?;
        let mut bytes = Zeroizing::new([0_u8; PRODUCT_BOOTSTRAP_LEN]);
        bootstrap
            .read_exact(bytes.as_mut())
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation)
    })();
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let confinement = drop_process_privileges()
        .and_then(|()| install_deny_all_filesystem_domain())
        .and_then(|()| install_network_worker_seccomp());
    if let Err(error) = confinement {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    bootstrap
        .set_read_timeout(None)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    write_worker_control_message(&bootstrap, WORKER_PREPARED_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    // One descriptor per broker IPC session, in session order (#2638).
    let broker_streams = (0..BROKER_IPC_SESSIONS)
        .map(|_| {
            receive_worker_broker_descriptor(bootstrap.as_raw_fd())
                .and_then(transferred_tokio_unix_stream)
        })
        .collect::<Result<Vec<_>, NetworkWorkerError>>()
        .and_then(|streams| {
            IpcEgressBroker::new(streams, prepared.broker_binding, prepared.broker_key)
        });
    let broker = match broker_streams {
        Ok(broker) => Arc::new(broker),
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    if let Err(error) = broker.verify_binding().await {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    write_worker_control_message(&bootstrap, WORKER_BROKER_READY_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    run_prepared_product_worker(
        bootstrap,
        ProductWorkerSession {
            network_key: prepared.network_key,
            host_port_key: prepared.host_port_key,
            mesh_ingress_key: prepared.mesh_ingress_key,
            mesh_ingress_ports: prepared.mesh_ingress_ports,
        },
        vm_id,
        generation,
        broker,
    )
    .await
}

/// Run the inherited worker with one explicitly injected broker.
///
/// The qualified hardware smoke supplies a socket-free fixture broker so the
/// same confined process and guest seam can prove allowed DNS/TCP without
/// creating a hidden host dial path.
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
        if ambient_environment_present() {
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
    let confinement = drop_process_privileges()
        .and_then(|()| install_deny_all_filesystem_domain())
        .and_then(|()| install_network_worker_seccomp());
    if let Err(error) = confinement {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    bootstrap
        .set_read_timeout(None)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    write_worker_control_message(&bootstrap, WORKER_PREPARED_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    run_prepared_worker(bootstrap, key, vm_id, generation, broker).await
}

async fn run_prepared_product_worker<B: EgressBroker>(
    bootstrap: StdUnixStream,
    session: ProductWorkerSession,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
) -> Result<(), NetworkWorkerError> {
    let descriptor = match receive_worker_network_descriptor(bootstrap.as_raw_fd()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let network = match transferred_stream(descriptor) {
        Ok(network) => network,
        Err(_) => {
            let error = NetworkWorkerError::InheritedDescriptor;
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    bootstrap
        .set_nonblocking(true)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let control =
        tokio::net::UnixStream::from_std(bootstrap).map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let (inbound_tx, inbound_rx) = mpsc::channel(MAX_INBOUND_STREAM_FLOWS);
    let (status_tx, status_rx) = oneshot::channel::<&'static [u8]>();
    let status = Arc::new(StdMutex::new(Some(status_tx)));
    let ready_status = Arc::clone(&status);
    let mut control_task = tokio::spawn(run_ingress_control(
        control,
        status_rx,
        inbound_tx,
        IngressControlKeys {
            host_port: session.host_port_key,
            mesh: session.mesh_ingress_key,
        },
        session.mesh_ingress_ports,
        vm_id,
        generation,
    ));
    let session = run_host_session_with_ingress(
        network,
        session.network_key,
        vm_id,
        generation,
        broker,
        Some(inbound_rx),
        move || publish_product_worker_status(&ready_status, WORKER_READY_MESSAGE),
    );
    tokio::pin!(session);
    tokio::select! {
        result = &mut session => {
            if let Err(error) = &result {
                let _ = publish_product_worker_status(&status, error.startup_failure().message());
            }
            let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, &mut control_task).await;
            result
        }
        result = &mut control_task => {
            result
                .map_err(|_| NetworkWorkerError::Engine)?
        }
    }
}

fn publish_product_worker_status(
    status: &StdMutex<Option<oneshot::Sender<&'static [u8]>>>,
    message: &'static [u8],
) -> io::Result<()> {
    status
        .lock()
        .map_err(|_| io::Error::other("network worker status lock failed"))?
        .take()
        .ok_or_else(|| io::Error::other("network worker status was already published"))?
        .send(message)
        .map_err(|_| io::Error::other("network worker status channel closed"))
}

struct IngressControlKeys {
    host_port: Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>,
    mesh: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
}

async fn run_ingress_control(
    control: tokio::net::UnixStream,
    status: oneshot::Receiver<&'static [u8]>,
    inbound: mpsc::Sender<InboundGuestStream>,
    keys: IngressControlKeys,
    mesh_ingress_ports: Vec<u16>,
    vm_id: Uuid,
    generation: u64,
) -> Result<(), NetworkWorkerError> {
    let status = status.await.map_err(|_| NetworkWorkerError::StatusIo)?;
    write_worker_control_descriptor(control.as_raw_fd(), status)
        .map_err(|_| NetworkWorkerError::StatusIo)?;
    if status != WORKER_READY_MESSAGE {
        return Err(NetworkWorkerError::Protocol);
    }

    let mut host_port_receiver = HostPortControlReceiver::new(vm_id, generation)
        .map_err(|_| NetworkWorkerError::Protocol)?;
    let mut mesh_receiver = MeshIngressControlReceiver::new(vm_id, generation, &mesh_ingress_ports)
        .map_err(|_| NetworkWorkerError::Protocol)?;
    loop {
        let mut frame = [0_u8; HOST_PORT_CONTROL_FRAME_LEN];
        read_worker_control_exact(&control, &mut frame).await?;
        let (guest_port, descriptor) = if is_host_port_control_frame(&frame) {
            let frame = host_port_receiver
                .decode(&frame, &keys.host_port)
                .map_err(|_| NetworkWorkerError::Protocol)?;
            let descriptor = receive_worker_host_port_descriptor(&control, frame.binding).await?;
            (frame.binding.guest_port, descriptor)
        } else if is_mesh_ingress_control_frame(&frame) {
            let frame = mesh_receiver
                .decode(&frame, &keys.mesh)
                .map_err(|_| NetworkWorkerError::Protocol)?;
            let descriptor = receive_mesh_ingress_descriptor(&control).await?;
            (frame.binding.guest_port, descriptor)
        } else {
            return Err(NetworkWorkerError::Protocol);
        };
        let stream =
            transferred_stream(descriptor).map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
        inbound
            .send(InboundGuestStream {
                guest_port,
                stream: Box::pin(stream),
            })
            .await
            .map_err(|_| NetworkWorkerError::Engine)?;
    }
}

pub(crate) async fn receive_worker_host_port_descriptor(
    control: &tokio::net::UnixStream,
    binding: HostPortBinding,
) -> Result<OwnedFd, NetworkWorkerError> {
    loop {
        control
            .readable()
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        match receive_worker_descriptor(control.as_raw_fd(), WORKER_HOST_PORT_DESCRIPTOR_MARKER) {
            Ok(descriptor) => {
                validate_connected_ipv4_stream(descriptor.as_raw_fd(), Some(binding))?;
                return Ok(descriptor);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(NetworkWorkerError::InheritedDescriptor),
        }
    }
}

async fn read_worker_control_exact(
    control: &tokio::net::UnixStream,
    mut bytes: &mut [u8],
) -> Result<(), NetworkWorkerError> {
    // Tokio's AsyncRead implementation for UnixStream uses recvfrom(2), which
    // this worker intentionally denies. Keep that confinement boundary and use
    // the already-audited read(2) helper for this fixed-size control record.
    while !bytes.is_empty() {
        let read = control
            .async_io(Interest::READABLE, || {
                read_worker_bytes(control.as_raw_fd(), bytes)
            })
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        if read == 0 {
            return Err(NetworkWorkerError::FrameIo);
        }
        bytes = &mut bytes[read..];
    }
    Ok(())
}

async fn run_prepared_worker<B: EgressBroker>(
    bootstrap: StdUnixStream,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
) -> Result<(), NetworkWorkerError> {
    let descriptor = match receive_worker_network_descriptor(bootstrap.as_raw_fd()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let network = match transferred_stream(descriptor) {
        Ok(network) => network,
        Err(_) => {
            let error = NetworkWorkerError::InheritedDescriptor;
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

fn transferred_tokio_unix_stream(
    descriptor: OwnedFd,
) -> Result<tokio::net::UnixStream, NetworkWorkerError> {
    let stream = StdUnixStream::from(descriptor);
    stream
        .set_nonblocking(true)
        .map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    tokio::net::UnixStream::from_std(stream).map_err(|_| NetworkWorkerError::InheritedDescriptor)
}

struct TransferredStream {
    /// Present until drop, which hands the descriptor away to be closed.
    descriptor: Option<AsyncFd<OwnedFd>>,
}

impl TransferredStream {
    fn descriptor(&mut self) -> &mut AsyncFd<OwnedFd> {
        self.descriptor
            .as_mut()
            .expect("a transferred stream holds its descriptor until drop")
    }
}

impl Drop for TransferredStream {
    /// On macOS, close the descriptor off the runtime thread. A network content
    /// filter (Little Snitch, a VPN or an endpoint agent) can hold `close()` for
    /// up to `net.cfil.close_wait_timeout`, 1 s by default. The worker's runtime
    /// has one thread, so closing inline stopped all of the VM's traffic for
    /// about a second per closed connection (#2714). Linux has no such hold,
    /// and its confined worker may not start threads, so it closes inline.
    fn drop(&mut self) {
        let Some(descriptor) = self.descriptor.take() else {
            return;
        };
        let descriptor = descriptor.into_inner();
        #[cfg(target_os = "macos")]
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn_blocking(move || drop(descriptor)));
            return;
        }
        drop(descriptor);
    }
}

fn transferred_stream(descriptor: OwnedFd) -> io::Result<TransferredStream> {
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
        return Err(io::Error::last_os_error());
    }
    let descriptor = AsyncFd::new(descriptor)?;
    Ok(TransferredStream {
        descriptor: Some(descriptor),
    })
}

impl AsyncRead for TransferredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut ready = match self.descriptor().poll_read_ready_mut(context) {
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

impl AsyncWrite for TransferredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut ready = match self.descriptor().poll_write_ready_mut(context) {
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        if unsafe { libc::shutdown(self.descriptor().get_ref().as_raw_fd(), libc::SHUT_WR) } == -1 {
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
    write_worker_control_descriptor(stream.as_raw_fd(), message)
}

fn write_worker_control_descriptor(descriptor: RawFd, message: &[u8]) -> io::Result<()> {
    if message.is_empty() || message.len() > WORKER_STATUS_MAX_BYTES || !message.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid network worker control message",
        ));
    }
    let mut written = 0_usize;
    while written < message.len() {
        let sent = send_worker_bytes(descriptor, &message[written..])?;
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

/// Whether this process inherited any environment variable. On macOS,
/// CoreFoundation (which cw links) sets `__CF_USER_TEXT_ENCODING` itself while
/// the process loads, from the user ID rather than from the parent, so that
/// one name is not ambient input.
pub(crate) fn ambient_environment_present() -> bool {
    std::env::vars_os()
        .any(|(name, _)| !(cfg!(target_os = "macos") && name == "__CF_USER_TEXT_ENCODING"))
}

fn send_worker_bytes(descriptor: RawFd, buffer: &[u8]) -> io::Result<usize> {
    loop {
        let written = unsafe { libc::write(descriptor, buffer.as_ptr().cast(), buffer.len()) };
        if written >= 0 {
            return Ok(written as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
fn require_single_threaded_process() -> Result<(), NetworkWorkerError> {
    require_single_thread().map_err(|_| NetworkWorkerError::ThreadConfinement)
}

#[cfg(target_os = "linux")]
fn install_deny_all_filesystem_domain() -> Result<(), NetworkWorkerError> {
    restrict_filesystem().map_err(|_| NetworkWorkerError::FilesystemConfinement)
}

/// Drop every capability set in the worker itself. The runner drops them
/// before exec, but exec gives root its full set again and keeps any
/// inheritable capability of the launching process. The worker stays
/// inspectable by its parent, which admits its executable.
#[cfg(target_os = "linux")]
fn drop_process_privileges() -> Result<(), NetworkWorkerError> {
    lock_exec_process_privileges().map_err(|_| NetworkWorkerError::PrivilegeConfinement)
}

/// Darwin has no capability sets to drop.
#[cfg(target_os = "macos")]
fn drop_process_privileges() -> Result<(), NetworkWorkerError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_single_threaded_process() -> Result<(), NetworkWorkerError> {
    crate::host::sandbox::require_single_thread().map_err(|_| NetworkWorkerError::ThreadConfinement)
}

/// Darwin replaces Landlock with a deny-all Seatbelt profile: the worker
/// keeps only the descriptors it already holds or later receives.
#[cfg(target_os = "macos")]
fn install_deny_all_filesystem_domain() -> Result<(), NetworkWorkerError> {
    crate::host::sandbox::deny_all().map_err(|_| NetworkWorkerError::FilesystemConfinement)
}

/// The deny-all Seatbelt profile already refuses dials, binds, process
/// creation and signals, which the Linux syscall layer adds to Landlock. It
/// leaves only unnamed socketpairs, which reach nothing. There is no separate
/// layer to install.
#[cfg(target_os = "macos")]
fn install_network_worker_seccomp() -> Result<(), NetworkWorkerError> {
    Ok(())
}

#[cfg(target_os = "linux")]
const NETWORK_WORKER_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_sendto,
    libc::SYS_sendmsg,
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
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NETWORK_WORKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const NETWORK_WORKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

/// Install the worker's dedicated syscall layer only after the exact
/// single-threaded Tokio runtime has created its private internal wakeup
/// descriptor. No guest-controlled byte is read before this filter is active.
#[cfg(target_os = "linux")]
fn install_network_worker_seccomp() -> Result<(), NetworkWorkerError> {
    install_denied_syscalls(
        NETWORK_WORKER_DENIED_SYSCALLS,
        NETWORK_WORKER_ARCH_DENIED_SYSCALLS,
    )
    .map_err(|_| NetworkWorkerError::SyscallConfinement)
}

fn inherited_std_unix_stream(descriptor: RawFd) -> Result<StdUnixStream, NetworkWorkerError> {
    validate_inherited_unix_socket(descriptor)?;
    // SAFETY: the hidden worker owns each fixed inherited descriptor exactly
    // once after exec, and this function is the only constructor for it.
    Ok(unsafe { StdUnixStream::from_raw_fd(descriptor) })
}

fn validate_inherited_unix_socket(descriptor: RawFd) -> Result<(), NetworkWorkerError> {
    // Darwin has no SO_DOMAIN and cannot read SO_ACCEPTCONN; the connected
    // AF_UNIX peer address below proves the domain and that it is no listener.
    #[cfg(target_os = "linux")]
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    if socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM {
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

fn validate_connected_ipv4_stream(
    descriptor: RawFd,
    expected: Option<HostPortBinding>,
) -> Result<(SocketAddrV4, SocketAddrV4), NetworkWorkerError> {
    // Darwin has no SO_DOMAIN and cannot read SO_ACCEPTCONN; the AF_INET
    // local and peer addresses below prove the domain and a connection.
    #[cfg(target_os = "linux")]
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_INET
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    if socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    let local = ipv4_socket_address(descriptor, false)?;
    let peer = ipv4_socket_address(descriptor, true)?;
    if !local.ip().is_loopback()
        || !peer.ip().is_loopback()
        || local.port() == 0
        || peer.port() == 0
        || expected.is_some_and(|binding| local.port() != binding.host_port)
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    Ok((local, peer))
}

fn ipv4_socket_address(descriptor: RawFd, peer: bool) -> Result<SocketAddrV4, NetworkWorkerError> {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let result = if peer {
        unsafe {
            libc::getpeername(
                descriptor,
                (&raw mut address).cast::<libc::sockaddr>(),
                &mut length,
            )
        }
    } else {
        unsafe {
            libc::getsockname(
                descriptor,
                (&raw mut address).cast::<libc::sockaddr>(),
                &mut length,
            )
        }
    };
    if result == -1
        || length as usize != std::mem::size_of::<libc::sockaddr_in>()
        || address.sin_family as i32 != libc::AF_INET
    {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
        u16::from_be(address.sin_port),
    ))
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

fn decode_product_worker_bootstrap(
    bytes: &[u8],
    expected_vm_id: Uuid,
    expected_generation: u64,
) -> Result<ProductWorkerBootstrap, NetworkWorkerError> {
    validate_identity(expected_vm_id, expected_generation)?;
    if bytes.len() != PRODUCT_BOOTSTRAP_LEN || &bytes[..8] != PRODUCT_BOOTSTRAP_MAGIC {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let vm_id =
        Uuid::from_slice(&bytes[8..24]).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let generation = u64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .expect("fixed product worker bootstrap generation"),
    );
    if vm_id != expected_vm_id || generation != expected_generation {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut network_key = Zeroizing::new([0_u8; NETWORK_KEY_LEN]);
    network_key.copy_from_slice(&bytes[32..64]);
    let network_key = NetworkKey::from_derived_bytes(*network_key)
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let policy = CompiledPolicy::developer_baseline();
    if bytes[PRODUCT_POLICY_DIGEST_OFFSET..PRODUCT_BROKER_KEY_OFFSET] != *policy.digest().as_bytes()
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let broker_binding = BrokerIpcBinding::new(vm_id, generation, policy.digest())
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let mut broker_key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
    broker_key.copy_from_slice(&bytes[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_HOST_PORT_KEY_OFFSET]);
    let broker_key =
        BrokerIpcKey::from_bytes(*broker_key).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let mut host_port_key = Zeroizing::new([0_u8; HOST_PORT_CONTROL_KEY_LEN]);
    host_port_key
        .copy_from_slice(&bytes[PRODUCT_HOST_PORT_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET]);
    if host_port_key.iter().all(|byte| *byte == 0) {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut mesh_ingress_key = Zeroizing::new([0_u8; MESH_INGRESS_CONTROL_KEY_LEN]);
    mesh_ingress_key.copy_from_slice(
        &bytes[PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET],
    );
    if mesh_ingress_key.iter().all(|byte| *byte == 0) {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let port_count = u16::from_le_bytes(
        bytes[PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET..PRODUCT_MESH_INGRESS_PORTS_OFFSET]
            .try_into()
            .expect("fixed Mesh ingress port count"),
    ) as usize;
    if port_count > MAX_MESH_INGRESS_PORTS {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut mesh_ingress_ports = Vec::with_capacity(port_count);
    for index in 0..port_count {
        let offset = PRODUCT_MESH_INGRESS_PORTS_OFFSET + index * std::mem::size_of::<u16>();
        mesh_ingress_ports.push(u16::from_le_bytes(
            bytes[offset..offset + std::mem::size_of::<u16>()]
                .try_into()
                .expect("fixed Mesh ingress port"),
        ));
    }
    let used_ports_end =
        PRODUCT_MESH_INGRESS_PORTS_OFFSET + port_count * std::mem::size_of::<u16>();
    if bytes[used_ports_end..].iter().any(|byte| *byte != 0)
        || validate_canonical_mesh_ingress_ports(&mesh_ingress_ports).is_err()
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    Ok(ProductWorkerBootstrap {
        network_key,
        broker_binding,
        broker_key,
        host_port_key,
        mesh_ingress_key,
        mesh_ingress_ports,
    })
}

fn validate_identity(vm_id: Uuid, generation: u64) -> Result<(), NetworkWorkerError> {
    if vm_id.is_nil() || generation == 0 {
        return Err(NetworkWorkerError::InvalidIdentity);
    }
    Ok(())
}

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
    run_network_session(stream, key, vm_id, generation, broker, ready)
        .await
        .map_err(NetworkWorkerError::from)
}

async fn run_host_session_with_ingress<S, B, R>(
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
        stream, key, vm_id, generation, broker, inbound, ready,
    )
    .await
    .map_err(NetworkWorkerError::from)
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
    #[error("network worker privilege confinement failed")]
    PrivilegeConfinement,
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
            Self::PrivilegeConfinement => NetworkWorkerStartupFailure::PrivilegeConfinement,
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

    use crate::host_port::HostPortControlFrame;
    use crate::mesh_ingress::{MeshIngressBinding, MeshIngressControlFrame};

    /// #2714: a dropped stream's descriptor is still closed (by the blocking
    /// pool on macOS, inline elsewhere), so the peer sees end of file and
    /// nothing leaks. (Whether `close()`
    /// blocks depends on the host's content filters; the Mac battery's
    /// connect-burst rows are the observed proof.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_transferred_stream_is_closed() {
        let (ours, peer) = StdUnixStream::pair().unwrap();
        drop(transferred_stream(OwnedFd::from(ours)).unwrap());
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let read = tokio::task::spawn_blocking(move || {
            let mut byte = [0_u8; 1];
            std::io::Read::read(&mut &peer, &mut byte)
        })
        .await
        .unwrap();
        assert_eq!(read.unwrap(), 0, "the peer saw end of file");
    }

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
        assert!(WORKER_BROKER_READY_MESSAGE.len() <= WORKER_STATUS_MAX_BYTES);
        assert_eq!(decode_worker_startup_status(WORKER_PREPARED_MESSAGE), None);
        assert_eq!(
            decode_worker_startup_status(WORKER_BROKER_READY_MESSAGE),
            None
        );
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
            NetworkWorkerStartupFailure::PrivilegeConfinement,
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
            assert!(failure.runner_error_code().len() <= 64);
            assert!(
                failure
                    .runner_error_code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
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
    fn transferred_descriptor_markers_are_role_bound() {
        let (bootstrap_sender, bootstrap_receiver) = StdUnixStream::pair().unwrap();
        let (_peer, descriptor) = StdUnixStream::pair().unwrap();
        send_worker_broker_descriptor(bootstrap_sender.as_raw_fd(), descriptor.as_raw_fd())
            .unwrap();
        assert!(matches!(
            receive_worker_network_descriptor(bootstrap_receiver.as_raw_fd()),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        send_worker_network_descriptor(bootstrap_sender.as_raw_fd(), descriptor.as_raw_fd())
            .unwrap();
        assert!(matches!(
            receive_worker_broker_descriptor(bootstrap_receiver.as_raw_fd()),
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

    #[tokio::test]
    async fn mesh_descriptor_is_role_bound_and_must_be_a_connected_unix_stream() {
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (_peer, bridge) = StdUnixStream::pair().unwrap();

        send_worker_descriptor(
            runner.as_raw_fd(),
            bridge.as_raw_fd(),
            WORKER_HOST_PORT_DESCRIPTOR_MARKER,
        )
        .unwrap();
        assert!(matches!(
            receive_mesh_ingress_descriptor(&worker).await,
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        send_worker_descriptor(
            runner.as_raw_fd(),
            accepted.as_raw_fd(),
            WORKER_MESH_INGRESS_DESCRIPTOR_MARKER,
        )
        .unwrap();
        assert!(matches!(
            receive_mesh_ingress_descriptor(&worker).await,
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(send_mesh_ingress_descriptor(runner.as_raw_fd(), datagram.as_raw_fd()).is_err());
    }

    #[test]
    fn host_port_descriptor_must_be_the_exact_connected_loopback_stream() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let binding = HostPortBinding::new(host_port, 3_000).unwrap();
        let client_address = match client.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("IPv4 listener returned an IPv6 client address"),
        };

        assert_eq!(
            validate_connected_ipv4_stream(accepted.as_raw_fd(), Some(binding)).unwrap(),
            (
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_port),
                client_address,
            )
        );
        assert!(matches!(
            validate_connected_ipv4_stream(
                accepted.as_raw_fd(),
                Some(HostPortBinding::new(host_port.saturating_sub(1), 3_000).unwrap())
            ),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));
        assert!(matches!(
            validate_connected_ipv4_stream(listener.as_raw_fd(), Some(binding)),
            Err(NetworkWorkerError::InheritedDescriptor)
        ));
    }

    #[tokio::test]
    async fn authenticated_host_port_control_delivers_the_matching_stream() {
        let (vm_id, generation) = identity();
        let key = [0xa5; HOST_PORT_CONTROL_KEY_LEN];
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let mut runner = tokio::net::UnixStream::from_std(runner).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = oneshot::channel();
        let control = tokio::spawn(run_ingress_control(
            worker,
            status_rx,
            inbound_tx,
            IngressControlKeys {
                host_port: Zeroizing::new(key),
                mesh: Zeroizing::new([0x4d; MESH_INGRESS_CONTROL_KEY_LEN]),
            },
            Vec::new(),
            vm_id,
            generation,
        ));
        status_tx.send(WORKER_READY_MESSAGE).unwrap();
        let mut ready = [0_u8; WORKER_READY_MESSAGE.len()];
        runner.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, WORKER_READY_MESSAGE);

        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = std::net::TcpStream::connect(address).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let binding = HostPortBinding::new(address.port(), 3_000).unwrap();
        let frame = HostPortControlFrame::encode(vm_id, generation, 1, binding, &key).unwrap();
        runner.write_all(&frame).await.unwrap();
        runner.flush().await.unwrap();
        send_worker_host_port_descriptor(runner.as_raw_fd(), accepted.as_raw_fd()).unwrap();

        let mut incoming = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("control did not deliver the stream")
            .expect("control closed the host-port channel");
        assert_eq!(incoming.guest_port, binding.guest_port);
        client.write_all(b"transferred").unwrap();
        let mut received = [0_u8; 11];
        incoming.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"transferred");

        drop(runner);
        assert!(matches!(
            control.await.unwrap(),
            Err(NetworkWorkerError::FrameIo)
        ));
    }

    #[tokio::test]
    async fn authenticated_mesh_control_delivers_only_an_allowed_unix_stream() {
        let (vm_id, generation) = identity();
        let mesh_key = [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
        let guest_port = 3_000;
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let mut runner = tokio::net::UnixStream::from_std(runner).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = oneshot::channel();
        let control = tokio::spawn(run_ingress_control(
            worker,
            status_rx,
            inbound_tx,
            IngressControlKeys {
                host_port: Zeroizing::new([0xa5; HOST_PORT_CONTROL_KEY_LEN]),
                mesh: Zeroizing::new(mesh_key),
            },
            vec![guest_port],
            vm_id,
            generation,
        ));
        status_tx.send(WORKER_READY_MESSAGE).unwrap();
        let mut ready = [0_u8; WORKER_READY_MESSAGE.len()];
        runner.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, WORKER_READY_MESSAGE);

        let binding = MeshIngressBinding::new(guest_port).unwrap();
        let frame =
            MeshIngressControlFrame::encode(vm_id, generation, 1, binding, &mesh_key).unwrap();
        runner.write_all(&frame).await.unwrap();
        runner.flush().await.unwrap();
        let (mut mesh_peer, bridge) = StdUnixStream::pair().unwrap();
        send_mesh_ingress_descriptor(runner.as_raw_fd(), bridge.as_raw_fd()).unwrap();

        let mut incoming = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("control did not deliver the Mesh stream")
            .expect("control closed the ingress channel");
        assert_eq!(incoming.guest_port, guest_port);
        mesh_peer.write_all(b"mesh-stream").unwrap();
        let mut received = [0_u8; 11];
        incoming.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"mesh-stream");

        drop(runner);
        assert!(matches!(
            control.await.unwrap(),
            Err(NetworkWorkerError::FrameIo)
        ));
    }

    struct FixtureBroker {
        allowed_destination: Option<SocketAddr>,
        connector: StdMutex<Option<DuplexStream>>,
        allowed: AtomicUsize,
        connected: AtomicUsize,
        resolved: AtomicUsize,
        dns_delay: Duration,
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
                dns_delay: Duration::ZERO,
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

        async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            if question.source.ip() != IpAddr::V4(GUEST_IP)
                || question.server != SocketAddr::new(IpAddr::V4(WORKER_IP), 53)
                || question.name != TEST_DNS_NAME
                || question.record_type != DnsRecordType::A
            {
                return Err(denied());
            }
            self.resolved.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.dns_delay).await;
            Ok(BrokerDnsAnswer {
                answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
                ttl_seconds: 30,
            })
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

    #[test]
    fn product_bootstrap_binds_network_broker_and_policy_to_one_generation() {
        let (vm_id, generation) = identity();
        let network_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let broker_key = [0x5a; BROKER_IPC_KEY_LEN];
        let host_port_key = [0xa5; HOST_PORT_CONTROL_KEY_LEN];
        let mesh_ingress_key = [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
        let mesh_ingress_ports = [22, 3_000];
        let bytes = encode_product_worker_bootstrap(
            vm_id,
            generation,
            &network_key,
            &broker_key,
            &host_port_key,
            &mesh_ingress_key,
            &mesh_ingress_ports,
        )
        .unwrap();
        let decoded = decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation).unwrap();
        assert_eq!(decoded.broker_binding.environment_id(), vm_id);
        assert_eq!(decoded.broker_binding.generation(), generation);
        assert_eq!(
            decoded.broker_binding.policy_digest(),
            CompiledPolicy::developer_baseline().digest()
        );
        network_key.with_bytes(|expected| {
            decoded
                .network_key
                .with_bytes(|actual| assert_eq!(actual, expected));
        });
        assert_eq!(decoded.mesh_ingress_ports, mesh_ingress_ports);
        assert!(decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation + 1).is_err());

        let mut wrong_policy = bytes.clone();
        wrong_policy[PRODUCT_POLICY_DIGEST_OFFSET] ^= 1;
        assert!(decode_product_worker_bootstrap(wrong_policy.as_ref(), vm_id, generation).is_err());
        let mut zero_broker_key = bytes.clone();
        zero_broker_key[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_HOST_PORT_KEY_OFFSET].fill(0);
        assert!(
            decode_product_worker_bootstrap(zero_broker_key.as_ref(), vm_id, generation).is_err()
        );
        assert!(
            encode_product_worker_bootstrap(
                vm_id,
                generation,
                &network_key,
                &[0_u8; BROKER_IPC_KEY_LEN],
                &host_port_key,
                &mesh_ingress_key,
                &mesh_ingress_ports,
            )
            .is_err()
        );
        let mut zero_host_port_key = bytes.clone();
        zero_host_port_key[PRODUCT_HOST_PORT_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET].fill(0);
        assert!(
            decode_product_worker_bootstrap(zero_host_port_key.as_ref(), vm_id, generation)
                .is_err()
        );
        let mut zero_mesh_ingress_key = bytes.clone();
        zero_mesh_ingress_key
            [PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET]
            .fill(0);
        assert!(
            decode_product_worker_bootstrap(zero_mesh_ingress_key.as_ref(), vm_id, generation)
                .is_err()
        );
        let mut noncanonical_mesh_ports = bytes.clone();
        noncanonical_mesh_ports[PRODUCT_MESH_INGRESS_PORTS_OFFSET
            ..PRODUCT_MESH_INGRESS_PORTS_OFFSET + std::mem::size_of::<u16>()]
            .copy_from_slice(&3_000_u16.to_le_bytes());
        noncanonical_mesh_ports[PRODUCT_MESH_INGRESS_PORTS_OFFSET + std::mem::size_of::<u16>()
            ..PRODUCT_MESH_INGRESS_PORTS_OFFSET + 2 * std::mem::size_of::<u16>()]
            .copy_from_slice(&22_u16.to_le_bytes());
        assert!(
            decode_product_worker_bootstrap(noncanonical_mesh_ports.as_ref(), vm_id, generation)
                .is_err()
        );
        let mut nonzero_padding = bytes.clone();
        nonzero_padding[PRODUCT_MESH_INGRESS_PORTS_OFFSET
            + mesh_ingress_ports.len() * std::mem::size_of::<u16>()] = 1;
        assert!(
            decode_product_worker_bootstrap(nonzero_padding.as_ref(), vm_id, generation).is_err()
        );
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
    async fn authenticated_host_port_bridges_loopback_to_the_exact_guest_port() {
        let (vm_id, generation) = identity();
        let network_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let (host_endpoint, guest_endpoint) = duplex(128 * 1024);
        let broker = Arc::new(FixtureBroker::new(None, None));
        let (inbound_tx, inbound_rx) = mpsc::channel(MAX_INBOUND_STREAM_FLOWS);
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut host = tokio::spawn(run_host_session_with_ingress(
            host_endpoint,
            network_key,
            vm_id,
            generation,
            broker,
            Some(inbound_rx),
            move || {
                ready_tx
                    .send(())
                    .map_err(|_| io::Error::other("host-port readiness receiver closed"))
            },
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
        let guest_port = 3_000;
        let mut guest_listener = guest
            .bind_endpoint(SocketAddr::new(IpAddr::V4(GUEST_IP), guest_port))
            .await
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

        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("worker did not become ready for host ports")
            .unwrap();

        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(address).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop(listener);
        client.set_nonblocking(true).unwrap();
        let mut client = tokio::net::TcpStream::from_std(client).unwrap();
        let binding = HostPortBinding::new(address.port(), guest_port).unwrap();
        inbound_tx
            .send(InboundGuestStream {
                guest_port: binding.guest_port,
                stream: Box::pin(transferred_stream(OwnedFd::from(accepted)).unwrap()),
            })
            .await
            .unwrap();

        let request = b"host-to-guest";
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut guest_stream = tokio::select! {
            accepted = guest_listener.accept() => accepted.expect("guest listener closed"),
            result = &mut host => panic!("network worker exited before host-port delivery: {result:?}"),
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("guest did not receive the host-port connection")
            }
        };
        let mut received = [0_u8; 13];
        tokio::time::timeout(
            Duration::from_secs(5),
            guest_stream.read_exact(&mut received),
        )
        .await
        .expect("guest did not receive host bytes")
        .unwrap();
        assert_eq!(&received, request);
        let mut eof = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), guest_stream.read(&mut eof))
                .await
                .expect("guest did not observe the host half-close")
                .unwrap(),
            0
        );

        let response = b"guest-to-host";
        guest_stream.write_all(response).await.unwrap();
        let mut returned = [0_u8; 13];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut returned))
            .await
            .expect("host did not receive guest bytes")
            .unwrap();
        assert_eq!(&returned, response);

        guest_stream.shutdown().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client.read(&mut eof))
                .await
                .expect("host did not observe the guest half-close")
                .unwrap(),
            0
        );

        drop(inbound_tx);
        guest_transport.abort();
        assert!(guest_transport.await.unwrap_err().is_cancelled());
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), host)
                .await
                .expect("network worker did not fail closed after transport loss")
                .unwrap(),
            Err(NetworkWorkerError::FrameIo)
        ));
    }

    #[tokio::test]
    async fn dns_keeps_the_broker_transaction_budget_after_two_seconds() {
        let (vm_id, generation) = identity();
        let (host_endpoint, mut guest_endpoint) = duplex(128 * 1024);
        let mut fixture = FixtureBroker::new(None, None);
        fixture.dns_delay = Duration::from_millis(2_100);
        let broker = Arc::new(fixture);
        let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let host = tokio::spawn(run_host_session(
            host_endpoint,
            host_key,
            vm_id,
            generation,
            Arc::clone(&broker),
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
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            read_guest_packet(&mut guest_endpoint, &mut session),
        )
        .await
        .expect("valid DNS operation was cancelled by an outer worker deadline")
        .unwrap();
        assert_dns_response(&response);
        assert_eq!(broker.resolved.load(Ordering::Relaxed), 1);
        drop(guest_endpoint);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), host)
                .await
                .unwrap()
                .unwrap(),
            Err(NetworkWorkerError::FrameIo)
        ));
    }

    /// DNS is answered locally. A SYN to a destination the policy refuses is
    /// answered with RST, so the guest sees the refusal at once (#3003); every
    /// other unbrokered packet class is dropped without a response.
    #[tokio::test]
    async fn dns_is_local_refused_syns_get_rst_and_every_other_unbrokered_packet_is_dropped() {
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
        for destination in denied_destinations {
            let refusal = tokio::time::timeout(
                Duration::from_secs(2),
                read_guest_packet(&mut guest_endpoint, &mut session),
            )
            .await
            .expect("a refused SYN is answered")
            .unwrap();
            assert_eq!(refusal[9], 6, "the refusal is TCP");
            assert_eq!(refusal[20 + 13], 0x14, "RST and ACK");
            assert_eq!(
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        refusal[12],
                        refusal[13],
                        refusal[14],
                        refusal[15]
                    )),
                    u16::from_be_bytes([refusal[20], refusal[21]]),
                ),
                destination,
                "the refusal comes from the refused destination"
            );
        }
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

    /// The confined worker still completes its descriptor protocol: status
    /// writes, SCM_RIGHTS receipt and Tokio I/O on a received stream.
    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_confined_worker_keeps_its_descriptor_protocol() {
        use std::io::Read as _;
        use tokio::io::AsyncReadExt as _;

        const CHILD_MARKER: &str = "CODEWIRE_TEST_NETWORK_WORKER_SEATBELT";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            let (control, mut runner) = StdUnixStream::pair().unwrap();
            let (broker, mut broker_peer) = StdUnixStream::pair().unwrap();
            install_deny_all_filesystem_domain().unwrap();
            install_network_worker_seccomp().unwrap();
            control.set_read_timeout(None).unwrap();
            write_worker_control_message(&control, WORKER_PREPARED_MESSAGE).unwrap();
            let mut prepared = [0_u8; WORKER_PREPARED_MESSAGE.len()];
            runner.read_exact(&mut prepared).unwrap();
            assert_eq!(&prepared, WORKER_PREPARED_MESSAGE);
            send_worker_broker_descriptor(runner.as_raw_fd(), broker.as_raw_fd()).unwrap();
            drop(broker);
            let received = receive_worker_broker_descriptor(control.as_raw_fd()).unwrap();
            runtime.block_on(async {
                let mut stream = transferred_tokio_unix_stream(received).unwrap();
                broker_peer.write_all(b"ok").unwrap();
                let mut bytes = [0_u8; 2];
                tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes, b"ok");
            });
            assert!(std::fs::File::open("/etc/hosts").is_err());
            assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err());
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("network_worker::tests::seatbelt_confined_worker_keeps_its_descriptor_protocol")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// The deny-all worker reads and writes a connected TCP stream it receives
    /// after confinement (the broker's dials and host-port connections), and
    /// still cannot dial one itself.
    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_confined_worker_uses_a_received_tcp_stream() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_NETWORK_WORKER_SEATBELT_TCP";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            let (control, runner) = StdUnixStream::pair().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            install_deny_all_filesystem_domain().unwrap();
            install_network_worker_seccomp().unwrap();
            send_worker_host_port_descriptor(runner.as_raw_fd(), client.as_raw_fd()).unwrap();
            drop(client);
            let received =
                receive_worker_descriptor(control.as_raw_fd(), WORKER_HOST_PORT_DESCRIPTOR_MARKER)
                    .unwrap();
            let mut transferred = {
                let _runtime_context = runtime.enter();
                transferred_stream(received).unwrap()
            };
            runtime.block_on(async {
                transferred.write_all(b"worker-to-peer").await.unwrap();
                let mut received = [0_u8; 14];
                std::io::Read::read_exact(&mut peer, &mut received).unwrap();
                assert_eq!(&received, b"worker-to-peer");
                std::io::Write::write_all(&mut peer, b"peer-to-worker").unwrap();
                let mut returned = [0_u8; 14];
                tokio::time::timeout(
                    Duration::from_secs(2),
                    transferred.read_exact(&mut returned),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&returned, b"peer-to-worker");
            });
            assert!(std::net::TcpStream::connect(listener.local_addr().unwrap()).is_err());
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("network_worker::tests::seatbelt_confined_worker_uses_a_received_tcp_stream")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
            let message: libc::msghdr = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sendmsg(control.as_raw_fd(), &raw const message, 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            let mut recv_byte = [0_u8; 1];
            assert_eq!(
                unsafe {
                    libc::recvfrom(
                        control.as_raw_fd(),
                        recv_byte.as_mut_ptr().cast(),
                        recv_byte.len(),
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                },
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

    #[cfg(target_os = "linux")]
    #[test]
    fn confined_transferred_tcp_stream_uses_only_read_write_authority() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_TRANSFERRED_TCP_SECCOMP";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            drop(listener);
            client.set_nonblocking(true).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            install_network_worker_seccomp().unwrap();
            let descriptor = OwnedFd::from(client);
            let mut transferred = {
                let _runtime_context = runtime.enter();
                transferred_stream(descriptor).unwrap()
            };
            runtime.block_on(async {
                transferred.write_all(b"worker-to-broker").await.unwrap();
                let mut received = [0_u8; 16];
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
                assert_eq!(&received, b"worker-to-broker");

                assert_eq!(
                    unsafe {
                        libc::write(
                            peer.as_raw_fd(),
                            b"broker-to-worker".as_ptr().cast(),
                            b"broker-to-worker".len(),
                        )
                    },
                    b"broker-to-worker".len() as isize
                );
                let mut returned = [0_u8; 16];
                transferred.read_exact(&mut returned).await.unwrap();
                assert_eq!(&returned, b"broker-to-worker");
            });
            assert_eq!(
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "network_worker::tests::confined_transferred_tcp_stream_uses_only_read_write_authority",
            )
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
