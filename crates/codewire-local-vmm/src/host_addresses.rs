//! The addresses local to this host, kept current for the egress broker
//! (#2614).
//!
//! The broker dials from the host's network position, so an address that is
//! public but local to that position would pass the fixed protected ranges:
//! the host's own interface addresses, and the public address its network is
//! seen from (a router or firewall answers LAN-originated traffic to its own
//! public address). The unconfined runner computes them and pushes them to
//! the confined broker over a one-way control socket; the broker refuses
//! guest connections to them.
//!
//! - Interface addresses come from `getifaddrs`, polled every five seconds.
//! - The public address is learned with a STUN binding request (RFC 5389) to
//!   `stun.codewire.sh:3478` at start, on any interface change and every five
//!   minutes. Learned addresses accumulate for the runner's lifetime, so a
//!   flapping network never unprotects one. Learning is best effort: until an
//!   address is learned, only interface addresses are refused.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use codewire_egress_policy::classify_address;
pub use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::host_addresses::{
    MAX_HOST_INTERFACE_ADDRESSES, MAX_NETWORK_PUBLIC_ADDRESSES,
};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const INTERFACE_POLL: Duration = Duration::from_secs(5);
pub const PUBLIC_RELEARN: Duration = Duration::from_secs(300);
pub const STUN_SERVERS_ENV: &str = "CODEWIRE_LOCAL_STUN_SERVERS";
pub const DEFAULT_STUN_SERVER: &str = "stun.codewire.sh:3478";
const STUN_TIMEOUT: Duration = Duration::from_secs(2);
const STUN_TRIES: usize = 3;

const FRAME_MAGIC: [u8; 4] = *b"CWHA";
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 9;
const ENTRY_LEN: usize = 17;
pub const MAX_FRAME_LEN: usize =
    FRAME_HEADER_LEN + (MAX_HOST_INTERFACE_ADDRESSES + MAX_NETWORK_PUBLIC_ADDRESSES) * ENTRY_LEN;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;

/// One control frame carrying the complete set.
pub fn encode_frame(set: &HostAddressSet) -> Vec<u8> {
    let interfaces: Vec<IpAddr> = set.interfaces().collect();
    let public: Vec<IpAddr> = set.public().collect();
    let mut frame =
        Vec::with_capacity(FRAME_HEADER_LEN + (interfaces.len() + public.len()) * ENTRY_LEN);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.extend_from_slice(&(interfaces.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(public.len() as u16).to_be_bytes());
    for address in interfaces.iter().chain(&public) {
        match address {
            IpAddr::V4(v4) => {
                frame.push(4);
                frame.extend_from_slice(&v4.to_ipv6_mapped().octets());
            }
            IpAddr::V6(v6) => {
                frame.push(6);
                frame.extend_from_slice(&v6.octets());
            }
        }
    }
    frame
}

/// Read one complete control frame. Anything malformed is an error, and the
/// broker fails closed on it.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<HostAddressSet> {
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    if magic != FRAME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host address frame has an unknown header",
        ));
    }
    read_frame_after_magic(reader).await
}

/// The magic that starts a host address frame on the broker control channel.
pub(crate) const HOST_ADDRESS_FRAME_MAGIC: [u8; 4] = FRAME_MAGIC;

/// Read the rest of a host address frame whose magic was already read.
pub(crate) async fn read_frame_after_magic<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<HostAddressSet> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    header[..4].copy_from_slice(&FRAME_MAGIC);
    reader.read_exact(&mut header[4..]).await?;
    let invalid = |reason: &str| io::Error::new(io::ErrorKind::InvalidData, reason.to_string());
    if header[4] != FRAME_VERSION {
        return Err(invalid("host address frame has an unknown header"));
    }
    let interfaces = usize::from(u16::from_be_bytes([header[5], header[6]]));
    let public = usize::from(u16::from_be_bytes([header[7], header[8]]));
    if interfaces > MAX_HOST_INTERFACE_ADDRESSES || public > MAX_NETWORK_PUBLIC_ADDRESSES {
        return Err(invalid("host address frame exceeds its bounds"));
    }
    let mut body = vec![0_u8; (interfaces + public) * ENTRY_LEN];
    reader.read_exact(&mut body).await?;
    let mut addresses = Vec::with_capacity(interfaces + public);
    for entry in body.as_chunks::<ENTRY_LEN>().0 {
        let octets: [u8; 16] = entry[1..].try_into().expect("entry length");
        let v6 = Ipv6Addr::from(octets);
        addresses.push(match entry[0] {
            4 => IpAddr::V4(
                v6.to_ipv4_mapped()
                    .ok_or_else(|| invalid("host address frame has a bad IPv4 entry"))?,
            ),
            6 => IpAddr::V6(v6),
            _ => return Err(invalid("host address frame has an unknown family")),
        });
    }
    let public_addresses = addresses.split_off(interfaces);
    HostAddressSet::new(addresses, public_addresses).map_err(|error| invalid(&error.to_string()))
}

/// This host's interface addresses that the fixed protected ranges do not
/// already cover, at most `MAX_HOST_INTERFACE_ADDRESSES` of them.
pub fn interface_addresses() -> io::Result<Vec<IpAddr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with an owned linked list freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: every node in the list is valid until freeifaddrs.
        let entry = unsafe { &*cursor };
        if let Some(address) = unsafe { socket_address(entry.ifa_addr) }
            && classify_address(address).is_none()
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `list` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(list) };
    addresses.sort();
    if addresses.len() > MAX_HOST_INTERFACE_ADDRESSES {
        eprintln!(
            "codewire-runner: {} public interface addresses; only the first {MAX_HOST_INTERFACE_ADDRESSES} are refused to guests",
            addresses.len()
        );
        addresses.truncate(MAX_HOST_INTERFACE_ADDRESSES);
    }
    Ok(addresses)
}

/// SAFETY: `address` is null or points to a sockaddr of its family's size.
unsafe fn socket_address(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match i32::from(unsafe { (*address).sa_family }) {
        libc::AF_INET => {
            let v4 = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let v6 = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn binding_request(transaction: &[u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut request = [0_u8; STUN_HEADER_LEN];
    request[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(transaction);
    request
}

/// The XOR-MAPPED-ADDRESS of a binding success for exactly `transaction`.
fn mapped_address(response: &[u8], transaction: &[u8; 12]) -> Option<IpAddr> {
    if response.len() < STUN_HEADER_LEN
        || u16::from_be_bytes([response[0], response[1]]) != STUN_BINDING_SUCCESS
        || u32::from_be_bytes(response[4..8].try_into().ok()?) != STUN_MAGIC_COOKIE
        || response[8..20] != transaction[..]
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([response[2], response[3]]));
    let attributes = response.get(STUN_HEADER_LEN..STUN_HEADER_LEN + length)?;
    let mut offset = 0;
    while offset + 4 <= attributes.len() {
        let kind = u16::from_be_bytes([attributes[offset], attributes[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([
            attributes[offset + 2],
            attributes[offset + 3],
        ]));
        let value = attributes.get(offset + 4..offset + 4 + size)?;
        if kind == STUN_XOR_MAPPED_ADDRESS && value.len() >= 4 {
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            return match (value[1], value.len()) {
                (0x01, 8) => {
                    let mut octets = [0_u8; 4];
                    for (index, byte) in octets.iter_mut().enumerate() {
                        *byte = value[4 + index] ^ cookie[index];
                    }
                    Some(IpAddr::V4(Ipv4Addr::from(octets)))
                }
                (0x02, 20) => {
                    let mut key = [0_u8; 16];
                    key[..4].copy_from_slice(&cookie);
                    key[4..].copy_from_slice(transaction);
                    let mut octets = [0_u8; 16];
                    for (index, byte) in octets.iter_mut().enumerate() {
                        *byte = value[4 + index] ^ key[index];
                    }
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                }
                _ => None,
            };
        }
        offset += 4 + size.div_ceil(4) * 4;
    }
    None
}

/// The public address this host is seen from by one STUN server.
pub async fn stun_mapped_address(server: SocketAddr, timeout: Duration) -> Option<IpAddr> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    socket.connect(server).await.ok()?;
    for _ in 0..STUN_TRIES {
        let mut transaction = [0_u8; 12];
        OsRng.fill_bytes(&mut transaction);
        socket.send(&binding_request(&transaction)).await.ok()?;
        let mut response = [0_u8; 512];
        let deadline = tokio::time::Instant::now() + timeout;
        while let Ok(Ok(length)) =
            tokio::time::timeout_at(deadline, socket.recv(&mut response)).await
        {
            if let Some(address) = mapped_address(&response[..length], &transaction) {
                return Some(address);
            }
        }
    }
    None
}

/// Where the monitor reads the host's addresses; the system one in product.
#[async_trait::async_trait]
pub trait HostAddressSource: Send + Sync {
    fn interfaces(&self) -> io::Result<Vec<IpAddr>>;
    async fn public(&self) -> Option<IpAddr>;
}

pub struct SystemHostAddressSource {
    stun_servers: Vec<String>,
}

impl SystemHostAddressSource {
    /// STUN servers from `CODEWIRE_LOCAL_STUN_SERVERS` (comma-separated
    /// host:port), or Codewire's.
    pub fn from_environment() -> Self {
        let configured = std::env::var(STUN_SERVERS_ENV).unwrap_or_default();
        let mut stun_servers: Vec<String> = configured
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(str::to_string)
            .collect();
        if stun_servers.is_empty() {
            stun_servers.push(DEFAULT_STUN_SERVER.to_string());
        }
        Self { stun_servers }
    }
}

#[async_trait::async_trait]
impl HostAddressSource for SystemHostAddressSource {
    fn interfaces(&self) -> io::Result<Vec<IpAddr>> {
        interface_addresses()
    }

    async fn public(&self) -> Option<IpAddr> {
        for server in &self.stun_servers {
            let Ok(Ok(resolved)) =
                tokio::time::timeout(STUN_TIMEOUT, tokio::net::lookup_host(server.as_str())).await
            else {
                continue;
            };
            for address in resolved {
                if let Some(mapped) = stun_mapped_address(address, STUN_TIMEOUT).await {
                    return Some(mapped);
                }
            }
        }
        None
    }
}

/// The runner's view of its host's addresses; it pushes each change to the
/// broker.
pub struct HostAddressMonitor<S> {
    source: S,
    interfaces: Vec<IpAddr>,
    learned: VecDeque<IpAddr>,
    warned: bool,
}

impl<S: HostAddressSource> HostAddressMonitor<S> {
    /// The monitor and its first set: the interface addresses, read now.
    pub fn start(source: S) -> io::Result<(Self, HostAddressSet)> {
        let interfaces = source.interfaces()?;
        let monitor = Self {
            source,
            interfaces,
            learned: VecDeque::new(),
            warned: false,
        };
        let set = monitor.set()?;
        Ok((monitor, set))
    }

    fn set(&self) -> io::Result<HostAddressSet> {
        HostAddressSet::new(
            self.interfaces.iter().copied(),
            self.learned.iter().copied(),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    async fn learn(&mut self) {
        match self.source.public().await {
            Some(address) => {
                self.learned.retain(|known| *known != address);
                self.learned.push_back(address);
                while self.learned.len() > MAX_NETWORK_PUBLIC_ADDRESSES {
                    self.learned.pop_front();
                }
            }
            None if self.learned.is_empty() && !self.warned => {
                self.warned = true;
                eprintln!(
                    "codewire-runner: the network's public address could not be learned with STUN; until it is, guests are refused only the host's own interface addresses"
                );
            }
            None => {}
        }
    }

    /// Keep the broker current: learn the public address now, then poll
    /// interfaces every `poll` and relearn on any change and every `relearn`.
    /// Each changed set goes to the runner's broker control task
    /// ([`crate::broker_control`]). The runner aborts it with the broker; it
    /// ends when that task has stopped.
    pub async fn run(
        mut self,
        updates: tokio::sync::mpsc::Sender<HostAddressSet>,
        mut current: HostAddressSet,
        poll: Duration,
        relearn: Duration,
    ) -> io::Result<()> {
        let mut learn = true;
        let mut learned_at = tokio::time::Instant::now();
        loop {
            if learn {
                self.learn().await;
                learned_at = tokio::time::Instant::now();
            }
            let next = self.set()?;
            if next != current {
                updates
                    .send(next.clone())
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                current = next;
            }
            tokio::time::sleep(poll).await;
            match self.source.interfaces() {
                Ok(interfaces) if interfaces != self.interfaces => {
                    self.interfaces = interfaces;
                    learn = true;
                }
                // A failed read keeps the last interfaces: never fewer refused.
                Ok(_) | Err(_) => learn = learned_at.elapsed() >= relearn,
            }
        }
    }
}

#[cfg(test)]
mod tests;
