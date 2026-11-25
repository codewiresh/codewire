//! Addresses local to the host a broker dials from (#2614).
//!
//! The fixed protected ranges cannot know them: the host's own interface
//! addresses, and the public addresses its network is seen from (a router or
//! firewall answers LAN-originated traffic to its own public address). A
//! guest connection to any of them is refused like a private address.
//!
//! A public entry may be a whole prefix, so a hosted cluster refuses each of
//! its servers' routed blocks, not one address in it (#4000).

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

use crate::AddressClass;

/// At most this many interface addresses are protected.
pub const MAX_HOST_INTERFACE_ADDRESSES: usize = 256;
/// At most this many public addresses or prefixes are protected.
pub const MAX_NETWORK_PUBLIC_ADDRESSES: usize = 64;
/// The widest public prefixes: the smallest blocks routed on the Internet, so
/// a wider one is a whole network, never a cluster's own (#4000).
pub const WIDEST_IPV4_PREFIX: u8 = 24;
pub const WIDEST_IPV6_PREFIX: u8 = 48;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAddressSet {
    interfaces: BTreeSet<IpAddr>,
    public: BTreeSet<AddressPrefix>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostAddressError {
    #[error("too many host interface addresses")]
    TooManyInterfaceAddresses,
    #[error("{0} network public entries, over the cap of {MAX_NETWORK_PUBLIC_ADDRESSES}")]
    TooManyPublicAddresses(usize),
}

impl HostAddressSet {
    pub fn new(
        interfaces: impl IntoIterator<Item = IpAddr>,
        public: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, HostAddressError> {
        Self::with_prefixes(interfaces, public.into_iter().map(AddressPrefix::host))
    }

    pub fn with_prefixes(
        interfaces: impl IntoIterator<Item = IpAddr>,
        public: impl IntoIterator<Item = AddressPrefix>,
    ) -> Result<Self, HostAddressError> {
        let interfaces: BTreeSet<IpAddr> = interfaces.into_iter().map(canonical).collect();
        let public: BTreeSet<AddressPrefix> = public.into_iter().collect();
        if interfaces.len() > MAX_HOST_INTERFACE_ADDRESSES {
            return Err(HostAddressError::TooManyInterfaceAddresses);
        }
        if public.len() > MAX_NETWORK_PUBLIC_ADDRESSES {
            return Err(HostAddressError::TooManyPublicAddresses(public.len()));
        }
        Ok(Self { interfaces, public })
    }

    /// The class of `address` if it is local to the host, in either IPv6 form
    /// of an IPv4 address.
    pub fn classify(&self, address: IpAddr) -> Option<AddressClass> {
        let address = canonical(address);
        if self.interfaces.contains(&address) {
            Some(AddressClass::HostInterface)
        } else if self.public.iter().any(|prefix| prefix.contains(address)) {
            Some(AddressClass::NetworkPublic)
        } else {
            None
        }
    }

    pub fn interfaces(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.interfaces.iter().copied()
    }

    pub fn public(&self) -> impl Iterator<Item = AddressPrefix> + '_ {
        self.public.iter().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty() && self.public.is_empty()
    }
}

/// A network public entry: an address and the length of its prefix, with no
/// bits set past it. An IPv4 prefix written in IPv6's mapped form is the IPv4
/// one, so either form of an address inside it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressPrefix {
    network: IpAddr,
    length: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrefixError {
    #[error("is not an IP address or prefix")]
    Malformed,
    #[error("has bits set past its /{0}")]
    HostBits(u8),
    #[error("is wider than /{0}, the widest allowed")]
    TooWide(u8),
}

impl AddressPrefix {
    /// One address, the whole of its own prefix.
    pub fn host(address: IpAddr) -> Self {
        let network = canonical(address);
        Self {
            network,
            length: full_length(network),
        }
    }

    pub fn new(network: IpAddr, length: u8) -> Result<Self, PrefixError> {
        let (network, length) = match network {
            IpAddr::V6(v6) if length >= 96 => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), length - 96),
                None => (network, length),
            },
            _ => (network, length),
        };
        let (widest, full) = match network {
            IpAddr::V4(_) => (WIDEST_IPV4_PREFIX, 32),
            IpAddr::V6(_) => (WIDEST_IPV6_PREFIX, 128),
        };
        if length > full {
            return Err(PrefixError::Malformed);
        }
        if length < widest {
            return Err(PrefixError::TooWide(widest));
        }
        if bits(network) & !mask(length, full) != 0 {
            return Err(PrefixError::HostBits(length));
        }
        Ok(Self { network, length })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn length(&self) -> u8 {
        self.length
    }

    /// Whether `address`, in either IPv6 form of an IPv4 address, is inside.
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = canonical(address);
        let full = full_length(self.network);
        full == full_length(address)
            && bits(address) & mask(self.length, full) == bits(self.network)
    }
}

impl FromStr for AddressPrefix {
    type Err = PrefixError;

    fn from_str(text: &str) -> Result<Self, PrefixError> {
        match text.split_once('/') {
            None => text
                .parse()
                .map(Self::host)
                .map_err(|_| PrefixError::Malformed),
            Some((address, length)) => {
                let address = address.parse().map_err(|_| PrefixError::Malformed)?;
                let length = length.parse().map_err(|_| PrefixError::Malformed)?;
                Self::new(address, length)
            }
        }
    }
}

impl fmt::Display for AddressPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn full_length(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// The address's bits, right-aligned.
fn bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// The first `length` of `full` bits set, right-aligned.
fn mask(length: u8, full: u8) -> u128 {
    let all = if full == 128 {
        u128::MAX
    } else {
        (1_u128 << full) - 1
    };
    all & !all.checked_shr(u32::from(length)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn prefix(text: &str) -> AddressPrefix {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn host_addresses_classify_in_either_form_of_an_ipv4_address() {
        let interface = IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0, 0, 0, 0, 0, 1));
        let public = IpAddr::V4(Ipv4Addr::new(87, 0, 0, 180));
        let set = HostAddressSet::new(
            [interface],
            [IpAddr::V6(Ipv4Addr::new(87, 0, 0, 180).to_ipv6_mapped())],
        )
        .unwrap();
        assert_eq!(set.classify(interface), Some(AddressClass::HostInterface));
        assert_eq!(set.classify(public), Some(AddressClass::NetworkPublic));
        assert_eq!(
            set.classify(IpAddr::V6(Ipv4Addr::new(87, 0, 0, 180).to_ipv6_mapped())),
            Some(AddressClass::NetworkPublic)
        );
        assert_eq!(set.classify(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None);
        assert_eq!(
            set.public().collect::<Vec<_>>(),
            [AddressPrefix::host(public)]
        );
        assert!(HostAddressSet::default().is_empty());
    }

    #[test]
    fn host_address_sets_are_bounded() {
        let many = |count: u32| (0..count).map(|n| IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n)));
        assert!(HostAddressSet::new(many(MAX_HOST_INTERFACE_ADDRESSES as u32), []).is_ok());
        assert_eq!(
            HostAddressSet::new(many(MAX_HOST_INTERFACE_ADDRESSES as u32 + 1), []),
            Err(HostAddressError::TooManyInterfaceAddresses)
        );
        assert!(HostAddressSet::new([], many(MAX_NETWORK_PUBLIC_ADDRESSES as u32)).is_ok());
        assert_eq!(
            HostAddressSet::new([], many(MAX_NETWORK_PUBLIC_ADDRESSES as u32 + 1)),
            Err(HostAddressError::TooManyPublicAddresses(
                MAX_NETWORK_PUBLIC_ADDRESSES + 1
            ))
        );
    }

    #[test]
    fn a_refused_prefix_covers_its_block_and_nothing_past_it() {
        // A server's routed /64: its own address, another in the block, and
        // the first address on either side.
        let set = HostAddressSet::with_prefixes(
            [],
            [prefix("2001:db8:5:7::/64"), prefix("203.0.113.64/26")],
        )
        .unwrap();
        for inside in [
            "2001:db8:5:7::1",
            "2001:db8:5:7:ffff:ffff:ffff:ffff",
            "2001:db8:5:7:abcd::9",
            "203.0.113.64",
            "203.0.113.127",
            "::ffff:203.0.113.77",
        ] {
            assert_eq!(
                set.classify(ip(inside)),
                Some(AddressClass::NetworkPublic),
                "{inside}"
            );
        }
        for outside in [
            "2001:db8:5:8::",
            "2001:db8:5:6:ffff:ffff:ffff:ffff",
            "203.0.113.128",
            "203.0.113.63",
            "::ffff:203.0.113.128",
        ] {
            assert_eq!(set.classify(ip(outside)), None, "{outside}");
        }
    }

    #[test]
    fn a_prefix_in_the_mapped_form_is_the_ipv4_one() {
        assert_eq!(prefix("::ffff:203.0.113.0/120"), prefix("203.0.113.0/24"));
        assert_eq!(prefix("::ffff:203.0.113.9"), prefix("203.0.113.9/32"));
        assert_eq!(
            prefix("203.0.113.9"),
            AddressPrefix::host(ip("203.0.113.9"))
        );
        assert_eq!(prefix("2001:db8::1").length(), 128);
        assert_eq!(prefix("2001:db8:5:7::/64").to_string(), "2001:db8:5:7::/64");
    }

    #[test]
    fn each_bad_entry_is_refused_by_the_rule_it_breaks() {
        for (entry, error) in [
            ("api.example.com", PrefixError::Malformed),
            ("203.0.113.0/", PrefixError::Malformed),
            ("203.0.113.0/33", PrefixError::Malformed),
            ("2001:db8::/129", PrefixError::Malformed),
            ("203.0.113.0/x", PrefixError::Malformed),
            ("203.0.113.9/24", PrefixError::HostBits(24)),
            ("2001:db8:5:7::1/64", PrefixError::HostBits(64)),
            ("10.0.0.0/23", PrefixError::TooWide(WIDEST_IPV4_PREFIX)),
            ("0.0.0.0/0", PrefixError::TooWide(WIDEST_IPV4_PREFIX)),
            ("2001:db8::/47", PrefixError::TooWide(WIDEST_IPV6_PREFIX)),
            (
                "::ffff:10.0.0.0/119",
                PrefixError::TooWide(WIDEST_IPV4_PREFIX),
            ),
        ] {
            assert_eq!(entry.parse::<AddressPrefix>(), Err(error), "{entry}");
        }
        assert!("203.0.113.0/24".parse::<AddressPrefix>().is_ok());
        assert!("2001:db8::/48".parse::<AddressPrefix>().is_ok());
    }
}
