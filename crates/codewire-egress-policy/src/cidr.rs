use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        if value.is_empty() || value.len() > 64 || value.trim() != value {
            return Err("CIDR must be a bounded canonical value");
        }
        let (address, prefix) = value
            .split_once('/')
            .ok_or("CIDR must include a prefix length")?;
        if prefix.is_empty()
            || prefix.starts_with('+')
            || (prefix.len() > 1 && prefix.starts_with('0'))
        {
            return Err("CIDR prefix length is not canonical");
        }
        let address = IpAddr::from_str(address).map_err(|_| "CIDR address is invalid")?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "CIDR prefix length is invalid")?;
        match address {
            IpAddr::V4(address) => {
                if prefix > 32 {
                    return Err("IPv4 CIDR prefix exceeds 32");
                }
                let raw = u32::from(address);
                let mask = prefix_mask_v4(prefix);
                if raw & mask != raw {
                    return Err("IPv4 CIDR contains host bits");
                }
                Ok(Self::V4 {
                    network: raw,
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                if prefix > 128 {
                    return Err("IPv6 CIDR prefix exceeds 128");
                }
                let raw = u128::from(address);
                let mask = prefix_mask_v6(prefix);
                if raw & mask != raw {
                    return Err("IPv6 CIDR contains host bits");
                }
                Ok(Self::V6 {
                    network: raw,
                    prefix,
                })
            }
        }
    }

    pub(crate) fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                u32::from(address) & prefix_mask_v4(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                u128::from(address) & prefix_mask_v6(prefix) == network
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4 { network, prefix } => {
                write!(formatter, "{}/{}", Ipv4Addr::from(network), prefix)
            }
            Self::V6 { network, prefix } => {
                write!(formatter, "{}/{}", Ipv6Addr::from(network), prefix)
            }
        }
    }
}

const fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_networks_round_trip_and_match_only_their_family() {
        let v4 = IpNetwork::parse("203.0.113.0/24").unwrap();
        assert_eq!(v4.to_string(), "203.0.113.0/24");
        assert!(v4.contains("203.0.113.42".parse().unwrap()));
        assert!(!v4.contains("203.0.114.1".parse().unwrap()));
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));

        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(v6.to_string(), "2001:db8::/32");
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:4860::1".parse().unwrap()));
    }

    #[test]
    fn noncanonical_or_invalid_networks_are_rejected() {
        for invalid in [
            "203.0.113.1/24",
            "2001:db8::1/32",
            "10.0.0.0/033",
            "10.0.0.0/+8",
            "10.0.0.0",
            " 10.0.0.0/8",
            "10.0.0.0/8 ",
            "::/129",
        ] {
            assert!(IpNetwork::parse(invalid).is_err(), "accepted {invalid}");
        }
    }
}
