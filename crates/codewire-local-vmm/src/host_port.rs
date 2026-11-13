//! Native local host ports: the bindings a local environment publishes and
//! their `127.0.0.1` listeners.
//!
//! The per-environment runner owns the listeners and carries each accepted
//! connection into the guest through the daemon's `ForwardTcp`
//! (`runner/host_port_forward.rs`, #4347). The confined network worker never
//! sees a host connection, a listening descriptor or host socket authority.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use serde::{Deserialize, Serialize};

pub const MAX_HOST_PORT_BINDINGS: usize = 64;
pub const RESERVED_GUEST_DAEMON_PORT: u16 = 7_777;

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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostPortError {
    #[error("host-port binding is invalid")]
    InvalidBinding,
    #[error("too many host-port bindings")]
    TooManyBindings,
    #[error("host-port bindings are duplicated or not canonical")]
    DuplicateBinding,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
                    panic!("released resource was not available again within 2 s: {error:?}")
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

    /// #4347: a published port is reachable only from this machine. Its
    /// listener holds `127.0.0.1` alone, so the host's own network address on
    /// that port refuses, and loopback-only guest servers stay local-only.
    #[test]
    fn a_published_port_listens_on_loopback_only() {
        let port = free_loopback_port();
        let listener = once_released(|| bind_loopback_listener(port));
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback(), "{address}");
        assert_eq!(address, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into());
        // The address this host would send from; no packet leaves for it.
        let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let routable = probe
            .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
            .and_then(|()| probe.local_addr())
            .ok()
            .map(|address| address.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified());
        if let Some(ip) = routable {
            assert!(
                std::net::TcpStream::connect((ip, port)).is_err(),
                "{ip}:{port} reached a loopback-only listener"
            );
        }
    }
}
