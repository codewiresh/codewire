use std::fs::OpenOptions;
use std::io::{self, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::{Duration, Instant};

use super::{PUBLIC_ADDRESS, destination};
use crate::macos_console_pair_fixture::{Result, invalid};

const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_BUFFER_LEN: usize = 64 * 1024;
const NETLINK_MAX_MESSAGES: usize = 1024;
const NETLINK_MAX_TOTAL_BYTES: usize = 256 * 1024;
const NLMSG_HEADER_LEN: usize = 16;
const RTATTR_HEADER_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const IFADDR_LEN: usize = 8;
const RTMSG_LEN: usize = 12;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

const ARPHRD_LOOPBACK: u16 = 772;
const RT_TABLE_LOCAL: u32 = 255;
const RTPROT_KERNEL: u8 = 2;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;
const RTN_LOCAL: u8 = 2;
const RTN_BROADCAST: u8 = 3;
const NS_PER_MILLISECOND: libc::c_long = 1_000_000;

const LOOPBACK_ADDRESS: [u8; 4] = [127, 0, 0, 1];
const LOOPBACK_NETWORK: [u8; 4] = [127, 0, 0, 0];
const LOOPBACK_BROADCAST: [u8; 4] = [127, 255, 255, 255];

const IPV6_DISABLE_PATHS: [&str; 3] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Link {
    index: u32,
    kind: u16,
    flags: u32,
    pub(super) name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Address {
    family: u8,
    prefix_len: u8,
    scope: u8,
    index: u32,
    address: Vec<u8>,
    local: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    family: u8,
    prefix_len: u8,
    table: u32,
    protocol: u8,
    scope: u8,
    kind: u8,
    destination: Option<Vec<u8>>,
    gateway: Option<Vec<u8>>,
    preferred_source: Option<Vec<u8>>,
    output_index: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Inventory {
    links: Vec<Link>,
    addresses: Vec<Address>,
    routes: Vec<Route>,
}

/// The sole listener admitted by the fixed guest-only topology.
pub(in crate::macos_console_pair_fixture) struct PreparedTopology {
    listener: OwnedFd,
}

impl PreparedTopology {
    pub(in crate::macos_console_pair_fixture) fn into_listener(self) -> OwnedFd {
        self.listener
    }
}

/// Configure the entire disposable service VM network namespace.
///
/// This operation is intentionally unavailable to a workstation process. The
/// native owner has already admitted a no-NIC VM; PID 1 repeats that property
/// from the actual namespace before creating one local TCP endpoint.
pub(in crate::macos_console_pair_fixture) fn prepare_service_topology() -> Result<PreparedTopology>
{
    if unsafe { libc::getpid() } != 1 || unsafe { libc::geteuid() } != 0 {
        return Err(invalid());
    }
    let mut route = RouteSocket::open()?;
    let initial = route.inventory()?;
    let loopback_index = validate_initial_inventory(&initial)?;

    disable_ipv6()?;
    route.set_link_up(loopback_index)?;
    route.add_public_address(loopback_index)?;
    let configured = route.inventory()?;
    validate_configured_inventory(&configured, loopback_index)?;
    verify_ipv6_disabled()?;

    let listener = open_listener(destination())?;
    Ok(PreparedTopology { listener })
}

fn disable_ipv6() -> Result<()> {
    for path in IPV6_DISABLE_PATHS {
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(b"1\n")?;
    }
    Ok(())
}

fn verify_ipv6_disabled() -> Result<()> {
    for path in IPV6_DISABLE_PATHS {
        let mut value = [0_u8; 3];
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let length = file.read(&mut value)?;
        if &value[..length] != b"1\n" {
            return Err(invalid());
        }
    }
    Ok(())
}

fn open_listener(expected: SocketAddr) -> Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let listener = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = socket_address(expected)?;
    if unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
        || unsafe { libc::listen(listener.as_raw_fd(), 1) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    validate_listener(listener.as_raw_fd(), expected)?;
    Ok(listener)
}

pub(super) fn validate_listener(listener: RawFd, expected: SocketAddr) -> Result<()> {
    let flags = unsafe { libc::fcntl(listener, libc::F_GETFL) };
    let descriptor_flags = unsafe { libc::fcntl(listener, libc::F_GETFD) };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & libc::O_NONBLOCK == 0
        || descriptor_flags < 0
        || descriptor_flags & libc::FD_CLOEXEC == 0
    {
        return Err(invalid());
    }
    for (option, value) in [
        (libc::SO_DOMAIN, libc::AF_INET),
        (libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_ACCEPTCONN, 1),
        (libc::SO_PROTOCOL, libc::IPPROTO_TCP),
    ] {
        let mut actual: libc::c_int = -1;
        let mut length = std::mem::size_of_val(&actual) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                listener,
                libc::SOL_SOCKET,
                option,
                (&raw mut actual).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&actual)
            || actual != value
        {
            return Err(invalid());
        }
    }
    if local_address(listener)? != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn local_address(socket: RawFd) -> Result<SocketAddr> {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe { libc::getsockname(socket, (&raw mut address).cast(), &mut length) } != 0
        || length as usize != std::mem::size_of_val(&address)
        || address.sin_family as libc::c_int != libc::AF_INET
    {
        return Err(invalid());
    }
    Ok(SocketAddr::from((
        address.sin_addr.s_addr.to_ne_bytes(),
        u16::from_be(address.sin_port),
    )))
}

fn socket_address(address: SocketAddr) -> Result<libc::sockaddr_in> {
    let SocketAddr::V4(address) = address else {
        return Err(invalid());
    };
    Ok(libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    })
}

fn validate_initial_inventory(inventory: &Inventory) -> Result<u32> {
    let [link] = inventory.links.as_slice() else {
        return Err(invalid());
    };
    if link.index == 0
        || link.kind != ARPHRD_LOOPBACK
        || link.name != "lo"
        || link.flags & libc::IFF_LOOPBACK as u32 == 0
        || link.flags & libc::IFF_UP as u32 != 0
        || !inventory.addresses.is_empty()
        || !inventory.routes.is_empty()
    {
        return Err(invalid());
    }
    Ok(link.index)
}

fn validate_configured_inventory(inventory: &Inventory, loopback_index: u32) -> Result<()> {
    let [link] = inventory.links.as_slice() else {
        return Err(invalid());
    };
    if link.index != loopback_index
        || link.kind != ARPHRD_LOOPBACK
        || link.name != "lo"
        || link.flags & (libc::IFF_LOOPBACK | libc::IFF_UP) as u32
            != (libc::IFF_LOOPBACK | libc::IFF_UP) as u32
    {
        return Err(invalid());
    }
    if inventory.addresses.len() != 2
        || !inventory
            .addresses
            .iter()
            .any(|address| address_matches(address, loopback_index, 8, LOOPBACK_ADDRESS))
        || !inventory
            .addresses
            .iter()
            .any(|address| address_matches(address, loopback_index, 32, PUBLIC_ADDRESS.octets()))
    {
        return Err(invalid());
    }
    if inventory.routes.len() != 4
        || !inventory.routes.iter().any(|route| {
            route_matches(
                route,
                loopback_index,
                32,
                RT_SCOPE_HOST,
                RTN_LOCAL,
                LOOPBACK_ADDRESS,
                LOOPBACK_ADDRESS,
            )
        })
        || !inventory.routes.iter().any(|route| {
            route_matches(
                route,
                loopback_index,
                8,
                RT_SCOPE_HOST,
                RTN_LOCAL,
                LOOPBACK_NETWORK,
                LOOPBACK_ADDRESS,
            )
        })
        || !inventory.routes.iter().any(|route| {
            route_matches(
                route,
                loopback_index,
                32,
                RT_SCOPE_LINK,
                RTN_BROADCAST,
                LOOPBACK_BROADCAST,
                LOOPBACK_ADDRESS,
            )
        })
        || !inventory.routes.iter().any(|route| {
            route_matches(
                route,
                loopback_index,
                32,
                RT_SCOPE_HOST,
                RTN_LOCAL,
                PUBLIC_ADDRESS.octets(),
                PUBLIC_ADDRESS.octets(),
            )
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn address_matches(address: &Address, index: u32, prefix_len: u8, expected: [u8; 4]) -> bool {
    address.family == libc::AF_INET as u8
        && address.prefix_len == prefix_len
        && address.scope == RT_SCOPE_HOST
        && address.index == index
        && address.address == expected
        && address.local.as_deref() == Some(expected.as_slice())
}

fn route_matches(
    route: &Route,
    index: u32,
    prefix_len: u8,
    scope: u8,
    kind: u8,
    destination: [u8; 4],
    preferred_source: [u8; 4],
) -> bool {
    route.family == libc::AF_INET as u8
        && route.prefix_len == prefix_len
        && route.table == RT_TABLE_LOCAL
        && route.protocol == RTPROT_KERNEL
        && route.scope == scope
        && route.kind == kind
        && route.destination.as_deref() == Some(destination.as_slice())
        && route.gateway.is_none()
        && route.preferred_source.as_deref() == Some(preferred_source.as_slice())
        && route.output_index == Some(index)
}

struct RouteSocket {
    descriptor: OwnedFd,
    port_id: u32,
    sequence: u32,
}

impl RouteSocket {
    fn open() -> Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&raw const address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&local) as libc::socklen_t;
        if unsafe {
            libc::getsockname(descriptor.as_raw_fd(), (&raw mut local).cast(), &mut length)
        } != 0
            || length as usize != std::mem::size_of_val(&local)
            || local.nl_family as libc::c_int != libc::AF_NETLINK
            || local.nl_pid == 0
            || local.nl_groups != 0
        {
            return Err(invalid());
        }
        Ok(Self {
            descriptor,
            port_id: local.nl_pid,
            sequence: 1,
        })
    }

    fn inventory(&mut self) -> Result<Inventory> {
        let mut inventory = Inventory::default();
        for (kind, family) in [
            (RTM_GETLINK, libc::AF_UNSPEC as u8),
            (RTM_GETADDR, libc::AF_UNSPEC as u8),
            (RTM_GETROUTE, libc::AF_UNSPEC as u8),
        ] {
            let payload = match kind {
                RTM_GETLINK => {
                    let mut bytes = vec![0; IFINFO_LEN];
                    bytes[0] = family;
                    bytes
                }
                RTM_GETADDR => {
                    let mut bytes = vec![0; IFADDR_LEN];
                    bytes[0] = family;
                    bytes
                }
                _ => {
                    let mut bytes = vec![0; RTMSG_LEN];
                    bytes[0] = family;
                    bytes
                }
            };
            for message in self.dump(kind, &payload)? {
                match message.kind {
                    RTM_NEWLINK => inventory.links.push(parse_link(&message.payload)?),
                    RTM_NEWADDR => inventory.addresses.push(parse_address(&message.payload)?),
                    RTM_NEWROUTE => inventory.routes.push(parse_route(&message.payload)?),
                    _ => return Err(invalid()),
                }
            }
        }
        inventory.links.sort_by_key(|link| link.index);
        inventory
            .addresses
            .sort_by_key(|address| (address.family, address.index, address.prefix_len));
        inventory.routes.sort_by_key(|route| {
            (
                route.family,
                route.table,
                route.prefix_len,
                route.output_index,
            )
        });
        Ok(inventory)
    }

    fn set_link_up(&mut self, index: u32) -> Result<()> {
        let request = encode_set_link(self.next_sequence()?, self.port_id, index)?;
        self.ack(&request)
    }

    fn add_public_address(&mut self, index: u32) -> Result<()> {
        let request = encode_add_address(self.next_sequence()?, self.port_id, index)?;
        self.ack(&request)
    }

    fn next_sequence(&mut self) -> Result<u32> {
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        Ok(sequence)
    }

    fn dump(&mut self, kind: u16, payload: &[u8]) -> Result<Vec<NetlinkMessage>> {
        let sequence = self.next_sequence()?;
        let request = encode_message(
            kind,
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            self.port_id,
            payload,
        )?;
        self.send(&request)?;
        self.receive(&request, true)
    }

    fn ack(&self, request: &[u8]) -> Result<()> {
        self.send(request)?;
        if self.receive(request, false)?.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    fn send(&self, request: &[u8]) -> Result<()> {
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                self.descriptor.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const kernel).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        Ok(())
    }

    fn receive(&self, request: &[u8], dump: bool) -> Result<Vec<NetlinkMessage>> {
        let sequence = read_u32(request, 8)?;
        let deadline = Instant::now() + NETLINK_TIMEOUT;
        let mut messages = Vec::new();
        let mut total = 0_usize;
        loop {
            let mut pollfd = libc::pollfd {
                fd: self.descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: ((deadline - now).as_millis().clamp(1, 50) as libc::c_long)
                    * NS_PER_MILLISECOND,
            };
            let polled =
                unsafe { libc::ppoll(&raw mut pollfd, 1, &raw const timeout, std::ptr::null()) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if polled == 0 {
                continue;
            }
            if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(invalid());
            }
            let mut buffer = [0_u8; NETLINK_BUFFER_LEN];
            let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut vector = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
            header.msg_name = (&raw mut source).cast();
            header.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
            header.msg_iov = &raw mut vector;
            header.msg_iovlen = 1;
            let received = unsafe {
                libc::recvmsg(
                    self.descriptor.as_raw_fd(),
                    &raw mut header,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(error);
            }
            if received == 0
                || received as usize > buffer.len()
                || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || header.msg_namelen as usize != std::mem::size_of_val(&source)
                || source.nl_family as libc::c_int != libc::AF_NETLINK
                || source.nl_pid != 0
                || source.nl_groups != 0
            {
                return Err(invalid());
            }
            total = total.checked_add(received as usize).ok_or_else(invalid)?;
            if total > NETLINK_MAX_TOTAL_BYTES {
                return Err(invalid());
            }
            let parsed = parse_datagram(&buffer[..received as usize], sequence, self.port_id)?;
            let parsed_length = parsed.len();
            for (index, message) in parsed.into_iter().enumerate() {
                if message.flags & NLM_F_DUMP_INTR != 0 {
                    return Err(invalid());
                }
                match message.kind {
                    NLMSG_ERROR => {
                        let error = parse_netlink_error(&message.payload, request)?;
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                        if dump || !messages.is_empty() || index + 1 != parsed_length {
                            return Err(invalid());
                        }
                        return Ok(messages);
                    }
                    NLMSG_DONE => {
                        if !dump
                            || index + 1 != parsed_length
                            || message.payload.iter().any(|byte| *byte != 0)
                        {
                            return Err(invalid());
                        }
                        return Ok(messages);
                    }
                    _ => {
                        if !dump || message.flags & NLM_F_MULTI == 0 {
                            return Err(invalid());
                        }
                        messages.push(message);
                        if messages.len() > NETLINK_MAX_MESSAGES {
                            return Err(invalid());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetlinkMessage {
    kind: u16,
    flags: u16,
    payload: Vec<u8>,
}

fn encode_set_link(sequence: u32, port_id: u32, index: u32) -> Result<Vec<u8>> {
    if index == 0 {
        return Err(invalid());
    }
    let mut payload = vec![0; IFINFO_LEN];
    payload[0] = libc::AF_UNSPEC as u8;
    payload[4..8].copy_from_slice(&(index as i32).to_ne_bytes());
    payload[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    payload[12..16].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    encode_message(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        sequence,
        port_id,
        &payload,
    )
}

fn encode_add_address(sequence: u32, port_id: u32, index: u32) -> Result<Vec<u8>> {
    if index == 0 {
        return Err(invalid());
    }
    let mut payload = vec![0; IFADDR_LEN];
    payload[0] = libc::AF_INET as u8;
    payload[1] = 32;
    payload[3] = RT_SCOPE_HOST;
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    append_attribute(&mut payload, IFA_LOCAL, &PUBLIC_ADDRESS.octets())?;
    append_attribute(&mut payload, IFA_ADDRESS, &PUBLIC_ADDRESS.octets())?;
    encode_message(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        sequence,
        port_id,
        &payload,
    )
}

fn encode_message(
    kind: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(invalid)?;
    let encoded_length = u32::try_from(length).map_err(|_| invalid())?;
    let mut bytes = vec![0; align4(length)];
    bytes[0..4].copy_from_slice(&encoded_length.to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[12..16].copy_from_slice(&port_id.to_ne_bytes());
    bytes[NLMSG_HEADER_LEN..length].copy_from_slice(payload);
    Ok(bytes)
}

fn append_attribute(bytes: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<()> {
    let length = RTATTR_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(invalid)?;
    let encoded_length = u16::try_from(length).map_err(|_| invalid())?;
    let start = bytes.len();
    bytes.resize(start.checked_add(align4(length)).ok_or_else(invalid)?, 0);
    bytes[start..start + 2].copy_from_slice(&encoded_length.to_ne_bytes());
    bytes[start + 2..start + 4].copy_from_slice(&kind.to_ne_bytes());
    bytes[start + RTATTR_HEADER_LEN..start + length].copy_from_slice(payload);
    Ok(())
}

fn parse_datagram(bytes: &[u8], sequence: u32, port_id: u32) -> Result<Vec<NetlinkMessage>> {
    if bytes.is_empty() {
        return Err(invalid());
    }
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < NLMSG_HEADER_LEN {
            return Err(invalid());
        }
        let length = read_u32(bytes, offset)? as usize;
        if length < NLMSG_HEADER_LEN || length > bytes.len() - offset {
            return Err(invalid());
        }
        let aligned = align4(length);
        if aligned > bytes.len() - offset {
            return Err(invalid());
        }
        let kind = read_u16(bytes, offset + 4)?;
        let flags = read_u16(bytes, offset + 6)?;
        let message_port = read_u32(bytes, offset + 12)?;
        if read_u32(bytes, offset + 8)? != sequence
            || (message_port != 0 && message_port != port_id)
        {
            return Err(invalid());
        }
        messages.push(NetlinkMessage {
            kind,
            flags,
            payload: bytes[offset + NLMSG_HEADER_LEN..offset + length].to_vec(),
        });
        offset += aligned;
    }
    Ok(messages)
}

fn parse_link(bytes: &[u8]) -> Result<Link> {
    if bytes.len() < IFINFO_LEN {
        return Err(invalid());
    }
    let signed_index = read_i32(bytes, 4)?;
    if signed_index <= 0 {
        return Err(invalid());
    }
    let mut name = None;
    for attribute in attributes(&bytes[IFINFO_LEN..])? {
        if attribute.kind == IFLA_IFNAME {
            if name.is_some()
                || attribute.value.len() < 2
                || attribute.value.len() > libc::IF_NAMESIZE
                || attribute.value.last() != Some(&0)
                || attribute.value[..attribute.value.len() - 1].contains(&0)
            {
                return Err(invalid());
            }
            name = Some(
                std::str::from_utf8(&attribute.value[..attribute.value.len() - 1])
                    .map_err(|_| invalid())?
                    .to_owned(),
            );
        }
    }
    Ok(Link {
        index: signed_index as u32,
        kind: read_u16(bytes, 2)?,
        flags: read_u32(bytes, 8)?,
        name: name.ok_or_else(invalid)?,
    })
}

fn parse_address(bytes: &[u8]) -> Result<Address> {
    if bytes.len() < IFADDR_LEN {
        return Err(invalid());
    }
    let family = bytes[0];
    let expected = address_length(family)?;
    let mut address = None;
    let mut local = None;
    for attribute in attributes(&bytes[IFADDR_LEN..])? {
        let destination = match attribute.kind {
            IFA_ADDRESS => &mut address,
            IFA_LOCAL => &mut local,
            _ => continue,
        };
        if destination.is_some() || attribute.value.len() != expected {
            return Err(invalid());
        }
        *destination = Some(attribute.value.to_vec());
    }
    let address = address.or_else(|| local.clone()).ok_or_else(invalid)?;
    Ok(Address {
        family,
        prefix_len: bytes[1],
        scope: bytes[3],
        index: read_u32(bytes, 4)?,
        address,
        local,
    })
}

fn parse_route(bytes: &[u8]) -> Result<Route> {
    if bytes.len() < RTMSG_LEN {
        return Err(invalid());
    }
    let family = bytes[0];
    let address_length = address_length(family)?;
    let mut table = u32::from(bytes[4]);
    let mut destination = None;
    let mut gateway = None;
    let mut preferred_source = None;
    let mut output_index = None;
    for attribute in attributes(&bytes[RTMSG_LEN..])? {
        match attribute.kind {
            RTA_DST | RTA_GATEWAY | RTA_PREFSRC => {
                if attribute.value.len() != address_length {
                    return Err(invalid());
                }
                let target = match attribute.kind {
                    RTA_DST => &mut destination,
                    RTA_GATEWAY => &mut gateway,
                    _ => &mut preferred_source,
                };
                if target.replace(attribute.value.to_vec()).is_some() {
                    return Err(invalid());
                }
            }
            RTA_OIF => {
                if attribute.value.len() != 4 || output_index.is_some() {
                    return Err(invalid());
                }
                output_index = Some(read_u32(attribute.value, 0)?);
            }
            RTA_TABLE => {
                if attribute.value.len() != 4 {
                    return Err(invalid());
                }
                let extended = read_u32(attribute.value, 0)?;
                if table != 0 && table != extended {
                    return Err(invalid());
                }
                table = extended;
            }
            _ => {}
        }
    }
    Ok(Route {
        family,
        prefix_len: bytes[1],
        table,
        protocol: bytes[5],
        scope: bytes[6],
        kind: bytes[7],
        destination,
        gateway,
        preferred_source,
        output_index,
    })
}

struct Attribute<'a> {
    kind: u16,
    value: &'a [u8],
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < RTATTR_HEADER_LEN {
            return Err(invalid());
        }
        let length = read_u16(bytes, 0)? as usize;
        if length < RTATTR_HEADER_LEN || length > bytes.len() {
            return Err(invalid());
        }
        let aligned = align4(length);
        if aligned > bytes.len() {
            return Err(invalid());
        }
        result.push(Attribute {
            kind: read_u16(bytes, 2)? & 0x3fff,
            value: &bytes[RTATTR_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn parse_netlink_error(bytes: &[u8], request: &[u8]) -> Result<i32> {
    // `nlmsgerr` always contains the error and at least the original request
    // header. ACK TLVs may follow it; they do not relax this minimum binding.
    if bytes.len() < 4 + NLMSG_HEADER_LEN
        || request.len() < NLMSG_HEADER_LEN
        || read_u32(request, 0)? as usize != request.len()
        || bytes[4..4 + NLMSG_HEADER_LEN] != request[..NLMSG_HEADER_LEN]
    {
        return Err(invalid());
    }
    let error = read_i32(bytes, 0)?;
    if !(-4095..=0).contains(&error) {
        return Err(invalid());
    }
    Ok(error)
}

fn address_length(family: u8) -> Result<usize> {
    match family as libc::c_int {
        libc::AF_INET => Ok(4),
        libc::AF_INET6 => Ok(16),
        _ => Err(invalid()),
    }
}

const fn align4(length: usize) -> usize {
    (length + 3) & !3
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(u32::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(i32::from_ne_bytes(value))
}

#[cfg(test)]
pub(super) mod fixtures {
    use super::*;

    pub(in crate::macos_console_pair_fixture::product_network) fn validate_kernel_inventory_dump()
    -> Result<()> {
        let mut route = RouteSocket::open()?;
        let inventory = route.inventory()?;
        if inventory.links.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn initial_inventory() -> Inventory {
        Inventory {
            links: vec![Link {
                index: 1,
                kind: ARPHRD_LOOPBACK,
                flags: libc::IFF_LOOPBACK as u32,
                name: "lo".into(),
            }],
            ..Inventory::default()
        }
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_inventory() -> Inventory
    {
        Inventory {
            links: vec![Link {
                index: 1,
                kind: ARPHRD_LOOPBACK,
                flags: (libc::IFF_LOOPBACK | libc::IFF_UP) as u32,
                name: "lo".into(),
            }],
            addresses: vec![
                fixed_address(8, LOOPBACK_ADDRESS),
                fixed_address(32, PUBLIC_ADDRESS.octets()),
            ],
            routes: vec![
                fixed_route(
                    32,
                    RT_SCOPE_HOST,
                    RTN_LOCAL,
                    LOOPBACK_ADDRESS,
                    LOOPBACK_ADDRESS,
                ),
                fixed_route(
                    8,
                    RT_SCOPE_HOST,
                    RTN_LOCAL,
                    LOOPBACK_NETWORK,
                    LOOPBACK_ADDRESS,
                ),
                fixed_route(
                    32,
                    RT_SCOPE_LINK,
                    RTN_BROADCAST,
                    LOOPBACK_BROADCAST,
                    LOOPBACK_ADDRESS,
                ),
                fixed_route(
                    32,
                    RT_SCOPE_HOST,
                    RTN_LOCAL,
                    PUBLIC_ADDRESS.octets(),
                    PUBLIC_ADDRESS.octets(),
                ),
            ],
        }
    }

    fn fixed_address(prefix_len: u8, address: [u8; 4]) -> Address {
        Address {
            family: libc::AF_INET as u8,
            prefix_len,
            scope: RT_SCOPE_HOST,
            index: 1,
            address: address.to_vec(),
            local: Some(address.to_vec()),
        }
    }

    fn fixed_route(
        prefix_len: u8,
        scope: u8,
        kind: u8,
        destination: [u8; 4],
        preferred_source: [u8; 4],
    ) -> Route {
        Route {
            family: libc::AF_INET as u8,
            prefix_len,
            table: RT_TABLE_LOCAL,
            protocol: RTPROT_KERNEL,
            scope,
            kind,
            destination: Some(destination.to_vec()),
            gateway: None,
            preferred_source: Some(preferred_source.to_vec()),
            output_index: Some(1),
        }
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn validate_initial(
        inventory: &Inventory,
    ) -> Result<u32> {
        validate_initial_inventory(inventory)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn validate_configured(
        inventory: &Inventory,
        index: u32,
    ) -> Result<()> {
        validate_configured_inventory(inventory, index)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn initial_rejects_preconfigured_link()
    -> bool {
        let mut inventory = initial_inventory();
        inventory.links[0].flags |= libc::IFF_UP as u32;
        validate_initial_inventory(&inventory).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_rejects_extra_link()
    -> bool {
        let mut inventory = configured_inventory();
        inventory.links.push(Link {
            index: 2,
            kind: 1,
            flags: libc::IFF_UP as u32,
            name: "eth0".into(),
        });
        validate_configured_inventory(&inventory, 1).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_rejects_extra_address()
    -> bool {
        let mut inventory = configured_inventory();
        inventory.addresses.push(fixed_address(32, [127, 0, 0, 2]));
        validate_configured_inventory(&inventory, 1).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_rejects_wrong_route()
    -> bool {
        let mut inventory = configured_inventory();
        inventory.routes[2].scope = RT_SCOPE_HOST;
        validate_configured_inventory(&inventory, 1).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_rejects_default_route()
    -> bool {
        let mut inventory = configured_inventory();
        inventory.routes.push(Route {
            family: libc::AF_INET as u8,
            prefix_len: 0,
            table: 254,
            protocol: 3,
            scope: 0,
            kind: 1,
            destination: None,
            gateway: Some([10, 0, 0, 1].to_vec()),
            preferred_source: None,
            output_index: Some(1),
        });
        validate_configured_inventory(&inventory, 1).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn configured_rejects_ipv6() -> bool
    {
        let mut inventory = configured_inventory();
        inventory.addresses.push(Address {
            family: libc::AF_INET6 as u8,
            prefix_len: 128,
            scope: RT_SCOPE_HOST,
            index: 1,
            address: vec![0; 16],
            local: None,
        });
        validate_configured_inventory(&inventory, 1).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn encode_link(
        sequence: u32,
        index: u32,
    ) -> Result<Vec<u8>> {
        encode_set_link(sequence, 41, index)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn encode_address(
        sequence: u32,
        index: u32,
    ) -> Result<Vec<u8>> {
        encode_add_address(sequence, 41, index)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn encoded_link_is_exact(
        bytes: &[u8],
        sequence: u32,
        index: u32,
    ) -> bool {
        read_u32(bytes, 0).ok() == Some((NLMSG_HEADER_LEN + IFINFO_LEN) as u32)
            && read_u16(bytes, 4).ok() == Some(RTM_NEWLINK)
            && read_u16(bytes, 6).ok() == Some(NLM_F_REQUEST | NLM_F_ACK)
            && read_u32(bytes, 8).ok() == Some(sequence)
            && read_u32(bytes, 12).ok() == Some(41)
            && read_i32(bytes, NLMSG_HEADER_LEN + 4).ok() == Some(index as i32)
            && read_u32(bytes, NLMSG_HEADER_LEN + 8).ok() == Some(libc::IFF_UP as u32)
            && read_u32(bytes, NLMSG_HEADER_LEN + 12).ok() == Some(libc::IFF_UP as u32)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn encoded_address_is_exact(
        bytes: &[u8],
        sequence: u32,
        index: u32,
    ) -> bool {
        let Some(length) = read_u32(bytes, 0).ok().map(|value| value as usize) else {
            return false;
        };
        let Ok(attributes) = attributes(&bytes[NLMSG_HEADER_LEN + IFADDR_LEN..length]) else {
            return false;
        };
        read_u16(bytes, 4).ok() == Some(RTM_NEWADDR)
            && read_u16(bytes, 6).ok()
                == Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
            && read_u32(bytes, 8).ok() == Some(sequence)
            && read_u32(bytes, 12).ok() == Some(41)
            && bytes.get(NLMSG_HEADER_LEN) == Some(&(libc::AF_INET as u8))
            && bytes.get(NLMSG_HEADER_LEN + 1) == Some(&32)
            && bytes.get(NLMSG_HEADER_LEN + 3) == Some(&RT_SCOPE_HOST)
            && read_u32(bytes, NLMSG_HEADER_LEN + 4).ok() == Some(index)
            && attributes.len() == 2
            && attributes[0].kind == IFA_LOCAL
            && attributes[0].value == PUBLIC_ADDRESS.octets()
            && attributes[1].kind == IFA_ADDRESS
            && attributes[1].value == PUBLIC_ADDRESS.octets()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn roundtrip_link_message(
        sequence: u32,
    ) -> Result<Link> {
        let mut payload = vec![0; IFINFO_LEN];
        payload[2..4].copy_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
        payload[4..8].copy_from_slice(&1_i32.to_ne_bytes());
        payload[8..12].copy_from_slice(&(libc::IFF_LOOPBACK as u32).to_ne_bytes());
        append_attribute(&mut payload, IFLA_IFNAME, b"lo\0")?;
        let encoded = encode_message(RTM_NEWLINK, NLM_F_MULTI, sequence, 41, &payload)?;
        let [message] = parse_datagram(&encoded, sequence, 41)?
            .try_into()
            .map_err(|_| invalid())?;
        parse_link(&message.payload)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn rejects_datagram(
        bytes: &[u8],
        sequence: u32,
    ) -> bool {
        parse_datagram(bytes, sequence, 41).is_err()
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn ack_payload(
        request: &[u8],
        error: i32,
    ) -> Result<Vec<u8>> {
        if request.len() < NLMSG_HEADER_LEN {
            return Err(invalid());
        }
        let mut payload = Vec::with_capacity(4 + NLMSG_HEADER_LEN);
        payload.extend_from_slice(&error.to_ne_bytes());
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        Ok(payload)
    }

    pub(in crate::macos_console_pair_fixture::product_network) fn parse_ack(
        payload: &[u8],
        request: &[u8],
    ) -> Result<i32> {
        parse_netlink_error(payload, request)
    }
}
