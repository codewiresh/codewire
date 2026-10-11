//! Private, generation-bound control records for native local host ports.
//!
//! The per-environment runner owns loopback listeners. For each accepted TCP
//! connection it sends one authenticated binding record and the connected
//! descriptor to the already-confined network worker. The worker never gets a
//! listening descriptor or host socket creation authority.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub const HOST_PORT_CONTROL_KEY_LEN: usize = 32;
pub const HOST_PORT_CONTROL_FRAME_LEN: usize = 80;
pub const MAX_HOST_PORT_BINDINGS: usize = 64;
pub const RESERVED_GUEST_DAEMON_PORT: u16 = 7_777;

const HOST_PORT_CONTROL_MAGIC: &[u8; 8] = b"CWHOSTP1";
const HOST_PORT_CONTROL_TAG_OFFSET: usize = 48;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn is_host_port_control_frame(frame: &[u8; HOST_PORT_CONTROL_FRAME_LEN]) -> bool {
    &frame[..HOST_PORT_CONTROL_MAGIC.len()] == HOST_PORT_CONTROL_MAGIC
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct HostPortBinding {
    pub host_port: u16,
    pub guest_port: u16,
}

impl HostPortBinding {
    pub fn new(host_port: u16, guest_port: u16) -> Result<Self, HostPortError> {
        let binding = Self {
            host_port,
            guest_port,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(self) -> Result<(), HostPortError> {
        if self.host_port == 0
            || self.guest_port == 0
            || self.guest_port == RESERVED_GUEST_DAEMON_PORT
        {
            return Err(HostPortError::InvalidBinding);
        }
        Ok(())
    }
}

/// Sort and validate one complete immutable environment binding set.
pub fn canonical_host_port_bindings(
    mut bindings: Vec<HostPortBinding>,
) -> Result<Vec<HostPortBinding>, HostPortError> {
    if bindings.len() > MAX_HOST_PORT_BINDINGS {
        return Err(HostPortError::TooManyBindings);
    }
    bindings.sort_unstable();
    validate_canonical_host_port_bindings(&bindings)?;
    Ok(bindings)
}

/// Validate an already-canonical binding set without silently rewriting it.
pub fn validate_canonical_host_port_bindings(
    bindings: &[HostPortBinding],
) -> Result<(), HostPortError> {
    if bindings.len() > MAX_HOST_PORT_BINDINGS {
        return Err(HostPortError::TooManyBindings);
    }
    let mut host_ports = BTreeSet::new();
    let mut guest_ports = BTreeSet::new();
    let mut prior = None;
    for binding in bindings {
        binding.validate()?;
        if prior.is_some_and(|prior| prior >= *binding)
            || !host_ports.insert(binding.host_port)
            || !guest_ports.insert(binding.guest_port)
        {
            return Err(HostPortError::DuplicateBinding);
        }
        prior = Some(*binding);
    }
    Ok(())
}

/// Bind the runner's listener for one host port on 127.0.0.1 only.
///
/// Rust sets SO_REUSEADDR, so a port whose earlier connections linger in
/// TIME_WAIT can be bound again at once, for example on a restart right after
/// a stop. On Linux the kernel still refuses the bind while any other socket
/// holds the port on the wildcard address.
pub(crate) fn bind_loopback_listener(port: u16) -> io::Result<TcpListener> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = TcpListener::bind(address)?;
    #[cfg(target_os = "macos")]
    refuse_wildcard_holder(port)?;
    if listener.local_addr()? != address.into() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "host port listener is not on the requested loopback address",
        ));
    }
    Ok(listener)
}

/// macOS lets a SO_REUSEADDR bind of 127.0.0.1:P succeed beside another
/// process's wildcard socket on *:P, including a dual-stack [::]:P server, and
/// would then take that server's loopback clients. Binding without
/// SO_REUSEADDR would refuse this, but would also refuse the port for 30
/// seconds after any of our connections closed first. So, with our listener
/// already bound, try to bind *:P itself: only another wildcard socket makes
/// that fail, never our loopback listener or a TIME_WAIT connection. The probe
/// never listens and is closed at once.
#[cfg(target_os = "macos")]
fn refuse_wildcard_holder(port: u16) -> io::Result<()> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    // SAFETY: plain socket creation; the descriptor is owned at once.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and is owned only here.
    let probe = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let enabled: libc::c_int = 1;
    let wildcard = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_ANY,
        },
        sin_zero: [0; 8],
    };
    // SAFETY: the option value and address are live, correctly sized locals.
    let bound = unsafe {
        libc::setsockopt(
            probe.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const enabled).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
            && libc::bind(
                probe.as_raw_fd(),
                (&raw const wildcard).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) == 0
    };
    if bound {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPortControlFrame {
    pub binding: HostPortBinding,
    pub sequence: u64,
}

impl HostPortControlFrame {
    pub fn encode(
        vm_id: Uuid,
        generation: u64,
        sequence: u64,
        binding: HostPortBinding,
        key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
    ) -> Result<[u8; HOST_PORT_CONTROL_FRAME_LEN], HostPortError> {
        validate_control_identity(vm_id, generation, sequence, key)?;
        binding.validate()?;
        let mut frame = [0_u8; HOST_PORT_CONTROL_FRAME_LEN];
        frame[..8].copy_from_slice(HOST_PORT_CONTROL_MAGIC);
        frame[8..24].copy_from_slice(vm_id.as_bytes());
        frame[24..32].copy_from_slice(&generation.to_le_bytes());
        frame[32..40].copy_from_slice(&sequence.to_le_bytes());
        frame[40..42].copy_from_slice(&binding.host_port.to_le_bytes());
        frame[42..44].copy_from_slice(&binding.guest_port.to_le_bytes());
        let tag = authenticate(&frame[..HOST_PORT_CONTROL_TAG_OFFSET], key)?;
        frame[HOST_PORT_CONTROL_TAG_OFFSET..].copy_from_slice(&tag);
        Ok(frame)
    }
}

pub struct HostPortControlReceiver {
    vm_id: Uuid,
    generation: u64,
    next_sequence: u64,
}

impl HostPortControlReceiver {
    pub fn new(vm_id: Uuid, generation: u64) -> Result<Self, HostPortError> {
        if vm_id.is_nil() || generation == 0 {
            return Err(HostPortError::InvalidIdentity);
        }
        Ok(Self {
            vm_id,
            generation,
            next_sequence: 1,
        })
    }

    pub fn decode(
        &mut self,
        frame: &[u8; HOST_PORT_CONTROL_FRAME_LEN],
        key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
    ) -> Result<HostPortControlFrame, HostPortError> {
        if &frame[..8] != HOST_PORT_CONTROL_MAGIC
            || frame[44..HOST_PORT_CONTROL_TAG_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            || key.iter().all(|byte| *byte == 0)
        {
            return Err(HostPortError::InvalidFrame);
        }
        let vm_id = Uuid::from_slice(&frame[8..24]).map_err(|_| HostPortError::InvalidFrame)?;
        let generation = u64::from_le_bytes(
            frame[24..32]
                .try_into()
                .expect("fixed host-port generation"),
        );
        let sequence =
            u64::from_le_bytes(frame[32..40].try_into().expect("fixed host-port sequence"));
        if vm_id != self.vm_id || generation != self.generation || sequence != self.next_sequence {
            return Err(HostPortError::InvalidFrame);
        }
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HostPortError::InvalidKey)?;
        mac.update(&frame[..HOST_PORT_CONTROL_TAG_OFFSET]);
        mac.verify_slice(&frame[HOST_PORT_CONTROL_TAG_OFFSET..])
            .map_err(|_| HostPortError::Authentication)?;
        let binding = HostPortBinding::new(
            u16::from_le_bytes(frame[40..42].try_into().expect("fixed host port")),
            u16::from_le_bytes(frame[42..44].try_into().expect("fixed guest port")),
        )?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(HostPortError::SequenceOverflow)?;
        Ok(HostPortControlFrame { binding, sequence })
    }
}

fn validate_control_identity(
    vm_id: Uuid,
    generation: u64,
    sequence: u64,
    key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
) -> Result<(), HostPortError> {
    if vm_id.is_nil() || generation == 0 || sequence == 0 {
        return Err(HostPortError::InvalidIdentity);
    }
    if key.iter().all(|byte| *byte == 0) {
        return Err(HostPortError::InvalidKey);
    }
    Ok(())
}

fn authenticate(
    message: &[u8],
    key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
) -> Result<[u8; 32], HostPortError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HostPortError::InvalidKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostPortError {
    #[error("host-port binding is invalid")]
    InvalidBinding,
    #[error("too many host-port bindings")]
    TooManyBindings,
    #[error("host-port bindings are duplicated or not canonical")]
    DuplicateBinding,
    #[error("host-port control identity is invalid")]
    InvalidIdentity,
    #[error("host-port control key is invalid")]
    InvalidKey,
    #[error("host-port control frame is invalid")]
    InvalidFrame,
    #[error("host-port control authentication failed")]
    Authentication,
    #[error("host-port control sequence overflowed")]
    SequenceOverflow,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn key() -> [u8; HOST_PORT_CONTROL_KEY_LEN] {
        [0x42; HOST_PORT_CONTROL_KEY_LEN]
    }

    #[test]
    fn bindings_are_sorted_unique_bounded_and_reserve_the_daemon() {
        let bindings = canonical_host_port_bindings(vec![
            HostPortBinding::new(18_081, 3_001).unwrap(),
            HostPortBinding::new(18_080, 3_000).unwrap(),
        ])
        .unwrap();
        assert_eq!(bindings[0].host_port, 18_080);
        assert_eq!(bindings[1].host_port, 18_081);
        assert_eq!(
            canonical_host_port_bindings(vec![
                HostPortBinding::new(18_080, 3_000).unwrap(),
                HostPortBinding::new(18_080, 3_001).unwrap(),
            ]),
            Err(HostPortError::DuplicateBinding)
        );
        assert_eq!(
            HostPortBinding::new(18_080, RESERVED_GUEST_DAEMON_PORT),
            Err(HostPortError::InvalidBinding)
        );
    }

    /// A free loopback port below the Linux and macOS ephemeral ranges. A
    /// concurrent test's bind(0) or connect() is never handed such a port, so
    /// a test can close its own sockets on it and bind it again.
    pub(crate) fn free_loopback_port() -> u16 {
        (0..64)
            .map(|_| 20_000 + rand::random::<u16>() % 12_000)
            .find(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).is_ok())
            .expect("a free loopback port below the ephemeral range")
    }

    /// Bind a loopback port this test has just closed. Other tests in this
    /// process fork children concurrently, and each child holds copies of our
    /// descriptors until it execs, so the port can stay bound for a moment. A
    /// port still held after two seconds fails the test.
    pub(crate) fn once_released<T, E: std::fmt::Debug>(
        mut bind: impl FnMut() -> Result<T, E>,
    ) -> T {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match bind() {
                Ok(value) => return value,
                Err(error) if std::time::Instant::now() >= deadline => {
                    panic!("loopback port was not released: {error:?}")
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }

    #[test]
    fn loopback_listener_never_shares_a_port_held_on_the_wildcard_address() {
        let wildcard = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = wildcard.local_addr().unwrap().port();
        assert!(bind_loopback_listener(port).is_err());
        drop(wildcard);

        let listener = once_released(|| bind_loopback_listener(port));
        assert_eq!(
            listener.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
        );
        assert!(bind_loopback_listener(port).is_err());
    }

    /// A restart right after a stop must get its port back even though the
    /// stopped environment closed connections first and left them in
    /// TIME_WAIT on that port.
    #[test]
    fn loopback_listener_rebinds_over_its_own_time_wait_connections() {
        let port = free_loopback_port();
        let listener = once_released(|| bind_loopback_listener(port));
        let client = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop(accepted);
        let mut byte = [0_u8; 1];
        assert_eq!(std::io::Read::read(&mut &client, &mut byte).unwrap(), 0);
        drop(client);
        drop(listener);
        let rebound = once_released(|| bind_loopback_listener(port));
        assert_eq!(
            rebound.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
        );
    }

    /// Node and many other servers listen on a dual-stack [::]:P socket, which
    /// also serves IPv4 loopback clients.
    #[cfg(target_os = "macos")]
    #[test]
    fn loopback_listener_never_shadows_a_dual_stack_server() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

        let descriptor = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        assert!(descriptor >= 0);
        let server = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let disabled: libc::c_int = 0;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    server.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    (&raw const disabled).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            },
            0
        );
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        assert_eq!(
            unsafe {
                libc::bind(
                    server.as_raw_fd(),
                    (&raw const address).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            },
            0
        );
        assert_eq!(unsafe { libc::listen(server.as_raw_fd(), 4) }, 0);
        let server = TcpListener::from(server);
        let port = server.local_addr().unwrap().port();
        assert!(bind_loopback_listener(port).is_err());
    }

    #[test]
    fn control_frames_bind_identity_mapping_sequence_and_mac() {
        let vm_id = Uuid::new_v4();
        let binding = HostPortBinding::new(18_080, 3_000).unwrap();
        let mut receiver = HostPortControlReceiver::new(vm_id, 7).unwrap();
        let frame = HostPortControlFrame::encode(vm_id, 7, 1, binding, &key()).unwrap();
        assert_eq!(receiver.decode(&frame, &key()).unwrap().binding, binding);
        assert_eq!(
            receiver.decode(&frame, &key()),
            Err(HostPortError::InvalidFrame)
        );

        let mut wrong_binding = frame;
        wrong_binding[42] ^= 1;
        let mut fresh = HostPortControlReceiver::new(vm_id, 7).unwrap();
        assert_eq!(
            fresh.decode(&wrong_binding, &key()),
            Err(HostPortError::Authentication)
        );

        let mut fresh = HostPortControlReceiver::new(vm_id, 7).unwrap();
        assert_eq!(
            fresh.decode(&frame, &[0x24; HOST_PORT_CONTROL_KEY_LEN]),
            Err(HostPortError::Authentication)
        );

        let wrong_generation = HostPortControlFrame::encode(vm_id, 8, 1, binding, &key()).unwrap();
        let mut fresh = HostPortControlReceiver::new(vm_id, 7).unwrap();
        assert_eq!(
            fresh.decode(&wrong_generation, &key()),
            Err(HostPortError::InvalidFrame)
        );

        let skipped_sequence = HostPortControlFrame::encode(vm_id, 7, 2, binding, &key()).unwrap();
        let mut fresh = HostPortControlReceiver::new(vm_id, 7).unwrap();
        assert_eq!(
            fresh.decode(&skipped_sequence, &key()),
            Err(HostPortError::InvalidFrame)
        );
    }
}
