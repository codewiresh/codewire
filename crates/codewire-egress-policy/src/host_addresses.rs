//! Addresses local to the host a broker dials from (#2614).
//!
//! The fixed protected ranges cannot know them: the host's own interface
//! addresses, and the public addresses its network is seen from (a router or
//! firewall answers LAN-originated traffic to its own public address). A
//! guest connection to any of them is refused like a private address.

use std::collections::BTreeSet;
use std::net::IpAddr;

use thiserror::Error;

use crate::AddressClass;

/// At most this many interface addresses are protected.
pub const MAX_HOST_INTERFACE_ADDRESSES: usize = 256;
/// At most this many learned public addresses are protected.
pub const MAX_NETWORK_PUBLIC_ADDRESSES: usize = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAddressSet {
    interfaces: BTreeSet<IpAddr>,
    public: BTreeSet<IpAddr>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostAddressError {
    #[error("too many host interface addresses")]
    TooManyInterfaceAddresses,
    #[error("too many network public addresses")]
    TooManyPublicAddresses,
}

impl HostAddressSet {
    pub fn new(
        interfaces: impl IntoIterator<Item = IpAddr>,
        public: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, HostAddressError> {
        let interfaces: BTreeSet<IpAddr> = interfaces.into_iter().map(canonical).collect();
        let public: BTreeSet<IpAddr> = public.into_iter().map(canonical).collect();
        if interfaces.len() > MAX_HOST_INTERFACE_ADDRESSES {
            return Err(HostAddressError::TooManyInterfaceAddresses);
        }
        if public.len() > MAX_NETWORK_PUBLIC_ADDRESSES {
            return Err(HostAddressError::TooManyPublicAddresses);
        }
        Ok(Self { interfaces, public })
    }

    /// The class of `address` if it is local to the host, in either IPv6 form
    /// of an IPv4 address.
    pub fn classify(&self, address: IpAddr) -> Option<AddressClass> {
        let address = canonical(address);
        if self.interfaces.contains(&address) {
            Some(AddressClass::HostInterface)
        } else if self.public.contains(&address) {
            Some(AddressClass::NetworkPublic)
        } else {
            None
        }
    }

    pub fn interfaces(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.interfaces.iter().copied()
    }

    pub fn public(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.public.iter().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty() && self.public.is_empty()
    }
}

fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

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
        assert_eq!(set.public().collect::<Vec<_>>(), [public]);
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
        assert_eq!(
            HostAddressSet::new([], many(MAX_NETWORK_PUBLIC_ADDRESSES as u32 + 1)),
            Err(HostAddressError::TooManyPublicAddresses)
        );
    }
}
