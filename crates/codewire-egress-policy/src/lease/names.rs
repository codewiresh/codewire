//! The name a refused dial is recorded under (#5058): the address's lease,
//! when one names it.

use std::net::IpAddr;

use super::EgressLeaseTable;
use crate::RouteClass;

impl EgressLeaseTable {
    /// The first kept lease's name for `address`, active or expired, in the
    /// table's order; `None` when no lease names the address.
    pub fn lease_name_at(&self, address: IpAddr, route_class: RouteClass) -> Option<&str> {
        self.leases_at(address, route_class)
            .next()
            .map(|lease| lease.name.as_str())
    }
}
