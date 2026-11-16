//! How large a packet one network session carries (#4000). The host fixes
//! the bound, sends it in its authenticated hello, and the guest accepts it
//! explicitly in its acknowledgement, so neither side assumes the other's
//! (cw-network, 2026-11-14). A local VM keeps today's bound; a hosted
//! sandbox's stream to cw-egress carries jumbo packets, which S0 measured
//! as matching direct egress.

use crate::NetworkError;

/// The smallest bound a session accepts: the one every session had before
/// the bound was negotiated.
pub const MIN_PACKET_BOUND: usize = 2_048;
/// The largest: a frame's packet length is a u16.
pub const MAX_PACKET_BOUND: usize = 65_535;
/// The smallest MTU either side may use, IPv4's minimum datagram size.
const MIN_MTU: usize = 576;

/// The most bytes one packet in a session may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketBound(u16);

impl PacketBound {
    pub fn new(bytes: usize) -> Result<Self, NetworkError> {
        if !(MIN_PACKET_BOUND..=MAX_PACKET_BOUND).contains(&bytes) {
            return Err(NetworkError::InvalidPacketBound);
        }
        u16::try_from(bytes)
            .map(Self)
            .map_err(|_| NetworkError::InvalidPacketBound)
    }

    pub fn bytes(self) -> usize {
        usize::from(self.0)
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub(crate) fn from_le_bytes(bytes: [u8; 2]) -> Result<Self, NetworkError> {
        Self::new(usize::from(u16::from_le_bytes(bytes)))
    }
}

/// One side's limits for a session: the bound the host sends, and the MTU
/// its own end of the path uses (the host's netstack, or the guest's TUN).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    packet_bound: PacketBound,
    mtu: usize,
}

impl SessionLimits {
    /// A local VM's session over vsock, as before the bound was negotiated.
    pub const LOCAL: Self = Self {
        packet_bound: PacketBound(2_048),
        mtu: 1_500,
    };
    /// A hosted sandbox's session over its stream to cw-egress (S0, #4000).
    pub const HOSTED: Self = Self {
        packet_bound: PacketBound(65_535),
        mtu: Self::HOSTED_MTU,
    };
    pub(crate) const HOSTED_MTU: usize = 65_000;

    pub fn new(packet_bound: PacketBound, mtu: usize) -> Result<Self, NetworkError> {
        if !(MIN_MTU..=packet_bound.bytes()).contains(&mtu) {
            return Err(NetworkError::InvalidPacketBound);
        }
        Ok(Self { packet_bound, mtu })
    }

    pub fn packet_bound(self) -> PacketBound {
        self.packet_bound
    }

    pub fn mtu(self) -> usize {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_is_between_the_old_fixed_bound_and_a_u16() {
        assert!(PacketBound::new(MIN_PACKET_BOUND).is_ok());
        assert!(PacketBound::new(MAX_PACKET_BOUND).is_ok());
        assert_eq!(
            PacketBound::new(MIN_PACKET_BOUND - 1),
            Err(NetworkError::InvalidPacketBound)
        );
        assert_eq!(
            PacketBound::new(MAX_PACKET_BOUND + 1),
            Err(NetworkError::InvalidPacketBound)
        );
    }

    #[test]
    fn an_mtu_fits_inside_its_bound() {
        let bound = PacketBound::new(2_048).unwrap();
        assert!(SessionLimits::new(bound, 1_500).is_ok());
        assert!(SessionLimits::new(bound, 2_049).is_err());
        assert!(SessionLimits::new(bound, 575).is_err());
        for limits in [SessionLimits::LOCAL, SessionLimits::HOSTED] {
            assert_eq!(
                SessionLimits::new(limits.packet_bound(), limits.mtu()),
                Ok(limits)
            );
        }
    }
}
