//! A hosted guest's routing (#4000; `designs/hosted-egress.md`, "The Sandbox
//! side" and "What leaves by the Pod interface, and how"), made once by the
//! init container (`cw __hosted-egress-tun`) and read back by the daemon's
//! self-check.
//!
//! - IPv6 is off: the TUN, the table and the rules are IPv4 only.
//! - The TUN `cwegress0` has its /30 and its MTU and is up.
//! - The Pod table's default leaves by eth0's own gateway, and three rules
//!   send traffic there: source port 31000 (the daemon's direct tailnet
//!   socket), output interface eth0 (a socket bound to it, as every platform
//!   dial is through [`super::pod_interface`]), and eth0's own address as
//!   source (replies to what arrives on eth0).
//! - The main table's one default goes into the TUN.
//!
//! This is the guest's egress path, not a boundary: anything in the Pod's
//! network namespace with NET_ADMIN could rewrite it, and the boundary is the
//! host's. [`verify`] catches infrastructure, or a stray container, leaving it
//! wrong, at the next self-check. Its errors name which part, never what the
//! kernel read back.

mod netlink;

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, Nla as _};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::rule::{
    RuleAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange,
};
use netlink_packet_route::{AddressFamily, IpProtocol, RouteNetlinkMessage};
use thiserror::Error;

use super::{
    HOSTED_GATEWAY, HOSTED_GUEST_ADDRESS, HOSTED_POD_INTERFACE, HOSTED_POD_ROUTE_TABLE,
    HOSTED_POD_RULE_PRIORITIES, HOSTED_PREFIX_LEN, HOSTED_TUN_MTU, HOSTED_TUN_NAME,
    TAILNET_DIRECT_SOURCE_PORT,
};
use netlink::RouteSocket;

/// Where the routing could not be made or read back.
#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("the route netlink socket failed")]
    Netlink(#[source] io::Error),
    #[error("the kernel refused to {step}")]
    Kernel {
        step: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("the kernel sent a netlink message this cw can't read")]
    Malformed,
    #[error("the interface {0} has {1}")]
    PodInterface(&'static str, &'static str),
    #[error("IPv6 could not be turned off ({0})")]
    Ipv6(&'static str),
    #[error("the routing read back without {0}")]
    Readback(&'static str),
    #[error("the kernel did not answer within the routing's time bound")]
    TimedOut,
}

/// How long the init container's whole configuration may take.
const CONFIGURE_BOUND: Duration = Duration::from_secs(5);
/// How long a readback may take: a small part of the self-check's 8 s.
const VERIFY_BOUND: Duration = Duration::from_secs(2);

/// The IPv6 switches that must read `1`.
const IPV6_DISABLED: [&str; 2] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
];

/// Make the routing, the TUN already created, then read it all back.
pub fn configure() -> Result<(), RoutingError> {
    disable_ipv6()?;
    let mut socket = RouteSocket::open(Instant::now() + CONFIGURE_BOUND)?;
    let plan = plan(&mut socket)?;
    address_and_link(&mut socket, &plan)?;
    socket.request(
        "add the Pod table's default route",
        RouteNetlinkMessage::NewRoute(default_route(
            HOSTED_POD_ROUTE_TABLE,
            plan.pod_gateway,
            plan.pod,
            true,
        )),
        NLM_F_CREATE | NLM_F_REPLACE,
    )?;
    for (priority, selectors, _) in rule_selectors(&plan) {
        ensure_rule(&mut socket, priority, selectors)?;
    }
    main_default_into_tun(&mut socket, &plan)?;
    read_back(&mut socket, &plan)?;
    ipv6_off()
}

/// The routing is as [`configure`] made it.
///
/// The Pod table's gateway is the one that table already holds, so its
/// check here is circular: it proves the table has one default by eth0, not
/// which gateway that is. Only `configure` reads the Pod's own default.
pub fn verify() -> Result<(), RoutingError> {
    ipv6_off()?;
    let mut socket = RouteSocket::open(Instant::now() + VERIFY_BOUND)?;
    let plan = plan(&mut socket)?;
    read_back(&mut socket, &plan)
}

fn disable_ipv6() -> Result<(), RoutingError> {
    for path in IPV6_DISABLED {
        match std::fs::write(path, b"1") {
            Ok(()) => {}
            // A kernel without IPv6 has no switch to turn.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(RoutingError::Ipv6("the guest refused the setting")),
        }
    }
    Ok(())
}

fn ipv6_off() -> Result<(), RoutingError> {
    for path in IPV6_DISABLED {
        match std::fs::read(path) {
            Ok(value) if value.trim_ascii() == b"1" => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(RoutingError::Readback("IPv6 off")),
        }
    }
    Ok(())
}

/// The kernel's main table.
const MAIN_TABLE: u32 = 254;

/// What one boot's routing must hold, from the fixed shape and the Pod's
/// own interface.
struct Plan {
    tun: u32,
    pod: u32,
    pod_address: Ipv4Addr,
    pod_gateway: Ipv4Addr,
}

fn plan(socket: &mut RouteSocket) -> Result<Plan, RoutingError> {
    let links = socket.dump(RouteNetlinkMessage::GetLink(LinkMessage::default()))?;
    let index = |name: &str| {
        links.iter().find_map(|message| match message {
            RouteNetlinkMessage::NewLink(link)
                if link.attributes.iter().any(
                    |attribute| matches!(attribute, LinkAttribute::IfName(n) if n == name),
                ) =>
            {
                Some(link.header.index)
            }
            _ => None,
        })
    };
    let tun = index(HOSTED_TUN_NAME).ok_or(RoutingError::PodInterface(
        HOSTED_TUN_NAME,
        "not been created",
    ))?;
    let pod = index(HOSTED_POD_INTERFACE)
        .ok_or(RoutingError::PodInterface(HOSTED_POD_INTERFACE, "no link"))?;

    let mut request = AddressMessage::default();
    request.header.family = AddressFamily::Inet;
    let addresses = socket.dump(RouteNetlinkMessage::GetAddress(request))?;
    let mut pod_addresses = addresses.iter().filter_map(|message| match message {
        RouteNetlinkMessage::NewAddress(address) if address.header.index == pod => address
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(IpAddr::V4(ip)) => Some(*ip),
                _ => None,
            }),
        _ => None,
    });
    let pod_address = pod_addresses.next().ok_or(RoutingError::PodInterface(
        HOSTED_POD_INTERFACE,
        "no IPv4 address",
    ))?;
    if pod_addresses.next().is_some() {
        return Err(RoutingError::PodInterface(
            HOSTED_POD_INTERFACE,
            "more than one IPv4 address",
        ));
    }

    let pod_gateway = pod_gateway(&routes(socket)?, pod)?;
    Ok(Plan {
        tun,
        pod,
        pod_address,
        pod_gateway,
    })
}

/// The Pod's gateway: before the first run the main table's default by the
/// Pod's interface, after it the Pod table's.
fn pod_gateway(routes: &[RouteMessage], pod: u32) -> Result<Ipv4Addr, RoutingError> {
    [MAIN_TABLE, HOSTED_POD_ROUTE_TABLE]
        .into_iter()
        .find_map(|table| {
            routes
                .iter()
                .filter(|route| is_default_in(route, table) && oif(route) == Some(pod))
                .find_map(gateway)
        })
        .ok_or(RoutingError::PodInterface(
            HOSTED_POD_INTERFACE,
            "no default gateway",
        ))
}

fn address_and_link(socket: &mut RouteSocket, plan: &Plan) -> Result<(), RoutingError> {
    let mut address = AddressMessage::default();
    address.header.family = AddressFamily::Inet;
    address.header.prefix_len = HOSTED_PREFIX_LEN;
    address.header.index = plan.tun;
    address.attributes = vec![
        AddressAttribute::Local(IpAddr::V4(HOSTED_GUEST_ADDRESS)),
        AddressAttribute::Address(IpAddr::V4(HOSTED_GUEST_ADDRESS)),
    ];
    socket.request(
        "address the TUN",
        RouteNetlinkMessage::NewAddress(address),
        NLM_F_CREATE | NLM_F_REPLACE,
    )?;
    let mut link = LinkMessage::default();
    link.header.index = plan.tun;
    link.header.flags = LinkFlags::Up;
    link.header.change_mask = LinkFlags::Up;
    link.attributes = vec![LinkAttribute::Mtu(
        u32::try_from(HOSTED_TUN_MTU).expect("the hosted MTU fits a u32"),
    )];
    socket.request(
        "set the TUN's MTU and bring it up",
        RouteNetlinkMessage::SetLink(link),
        0,
    )
}

/// The three rules into the Pod table: priority, selectors, and what the
/// readback calls a missing one.
fn rule_selectors(plan: &Plan) -> [(u32, Vec<RuleAttribute>, &'static str); 3] {
    [
        (
            HOSTED_POD_RULE_PRIORITIES[0],
            // The daemon's direct tailnet socket is UDP; a TCP connection
            // from the same port stays on the TUN.
            vec![
                RuleAttribute::IpProtocol(IpProtocol::Udp),
                RuleAttribute::SourcePortRange(RulePortRange {
                    start: TAILNET_DIRECT_SOURCE_PORT,
                    end: TAILNET_DIRECT_SOURCE_PORT,
                }),
            ],
            "the source-port rule",
        ),
        (
            HOSTED_POD_RULE_PRIORITIES[1],
            vec![RuleAttribute::Oifname(HOSTED_POD_INTERFACE.to_owned())],
            "the Pod-interface rule",
        ),
        (
            HOSTED_POD_RULE_PRIORITIES[2],
            vec![RuleAttribute::Source(IpAddr::V4(plan.pod_address))],
            "the Pod-address rule",
        ),
    ]
}

/// Add the rule at `priority` unless it is already there as wanted; a
/// different rule at that priority is replaced.
fn ensure_rule(
    socket: &mut RouteSocket,
    priority: u32,
    selectors: Vec<RuleAttribute>,
) -> Result<(), RoutingError> {
    let existing = rules(socket)?;
    let at_priority: Vec<&RuleMessage> = existing
        .iter()
        .filter(|rule| rule_priority(rule) == Some(priority))
        .collect();
    if at_priority
        .iter()
        .any(|rule| rule_is(rule, priority, &selectors))
    {
        return Ok(());
    }
    for stale in at_priority {
        socket.request(
            "remove a stale rule at a fixed priority",
            RouteNetlinkMessage::DelRule(stale.clone()),
            0,
        )?;
    }
    socket.request(
        "add a rule into the Pod table",
        RouteNetlinkMessage::NewRule(rule(priority, selectors)),
        NLM_F_CREATE | NLM_F_EXCL,
    )
}

/// The main table's default goes into the TUN, and no other default stays.
fn main_default_into_tun(socket: &mut RouteSocket, plan: &Plan) -> Result<(), RoutingError> {
    for route in routes(socket)? {
        if is_default_in(&route, MAIN_TABLE) && oif(&route) != Some(plan.tun) {
            socket.request(
                "remove the Pod's own default route from the main table",
                RouteNetlinkMessage::DelRoute(route),
                0,
            )?;
        }
    }
    socket.request(
        "make the TUN the default route",
        RouteNetlinkMessage::NewRoute(default_route(MAIN_TABLE, HOSTED_GATEWAY, plan.tun, false)),
        NLM_F_CREATE | NLM_F_REPLACE,
    )
}

fn read_back(socket: &mut RouteSocket, plan: &Plan) -> Result<(), RoutingError> {
    let rules = rules(socket)?;
    let routes = routes(socket)?;
    check(&rules, &routes, plan)
}

/// The dumped rules and routes are exactly the routing `plan` describes.
fn check(rules: &[RuleMessage], routes: &[RouteMessage], plan: &Plan) -> Result<(), RoutingError> {
    for (priority, selectors, what) in rule_selectors(plan) {
        if !rules.iter().any(|rule| rule_is(rule, priority, &selectors)) {
            return Err(RoutingError::Readback(what));
        }
    }
    let defaults_in = |table| -> Vec<&RouteMessage> {
        routes
            .iter()
            .filter(|route| is_default_in(route, table))
            .collect()
    };
    let pod_table = defaults_in(HOSTED_POD_ROUTE_TABLE);
    if !matches!(pod_table.as_slice(), [route] if oif(route) == Some(plan.pod) && gateway(route) == Some(plan.pod_gateway))
    {
        return Err(RoutingError::Readback(
            "the Pod table's one default via the Pod's gateway",
        ));
    }
    let main = defaults_in(MAIN_TABLE);
    if !matches!(main.as_slice(), [route] if oif(route) == Some(plan.tun) && gateway(route) == Some(HOSTED_GATEWAY))
    {
        return Err(RoutingError::Readback(
            "the main table's one default into the TUN",
        ));
    }
    Ok(())
}

fn default_route(table: u32, gateway: Ipv4Addr, interface: u32, on_link: bool) -> RouteMessage {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 0;
    route.header.table = table_header(table);
    route.header.protocol = RouteProtocol::Static;
    route.header.scope = RouteScope::Universe;
    route.header.kind = RouteType::Unicast;
    if on_link {
        // The Pod's gateway is reached on its interface whether or not a
        // subnet route for it is in this table.
        route.header.flags = RouteFlags::Onlink;
    }
    route.attributes = vec![
        RouteAttribute::Table(table),
        RouteAttribute::Gateway(RouteAddress::Inet(gateway)),
        RouteAttribute::Oif(interface),
    ];
    route
}

fn rule(priority: u32, selectors: Vec<RuleAttribute>) -> RuleMessage {
    let mut rule = RuleMessage::default();
    rule.header.family = AddressFamily::Inet;
    rule.header.table = table_header(HOSTED_POD_ROUTE_TABLE);
    rule.header.action = RuleAction::ToTable;
    rule.header.src_len = source_length(&selectors);
    rule.attributes = vec![
        RuleAttribute::Priority(priority),
        RuleAttribute::Table(HOSTED_POD_ROUTE_TABLE),
    ];
    rule.attributes.extend(selectors);
    rule
}

/// A source selector is one address.
fn source_length(selectors: &[RuleAttribute]) -> u8 {
    if selectors
        .iter()
        .any(|selector| matches!(selector, RuleAttribute::Source(_)))
    {
        32
    } else {
        0
    }
}

/// A port mask that keeps every bit, which matches as no mask does.
fn full_port_mask(attribute: &RuleAttribute) -> bool {
    let RuleAttribute::Other(nla) = attribute else {
        return false;
    };
    if !matches!(nla.kind(), FRA_SPORT_MASK | FRA_DPORT_MASK) || nla.value_len() != 2 {
        return false;
    }
    let mut mask = [0_u8; 2];
    nla.emit_value(&mut mask);
    u16::from_ne_bytes(mask) == u16::MAX
}

/// A table above 255 travels as an attribute, with the header's byte unset.
fn table_header(table: u32) -> u8 {
    u8::try_from(table).unwrap_or(0)
}

fn routes(socket: &mut RouteSocket) -> Result<Vec<RouteMessage>, RoutingError> {
    let mut request = RouteMessage::default();
    request.header.address_family = AddressFamily::Inet;
    Ok(socket
        .dump(RouteNetlinkMessage::GetRoute(request))?
        .into_iter()
        .filter_map(|message| match message {
            RouteNetlinkMessage::NewRoute(route) => Some(route),
            _ => None,
        })
        .collect())
}

fn rules(socket: &mut RouteSocket) -> Result<Vec<RuleMessage>, RoutingError> {
    let mut request = RuleMessage::default();
    request.header.family = AddressFamily::Inet;
    Ok(socket
        .dump(RouteNetlinkMessage::GetRule(request))?
        .into_iter()
        .filter_map(|message| match message {
            RouteNetlinkMessage::NewRule(rule) => Some(rule),
            _ => None,
        })
        .collect())
}

fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
}

fn is_default_in(route: &RouteMessage, table: u32) -> bool {
    route.header.destination_prefix_length == 0 && route_table(route) == table
}

fn oif(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn gateway(route: &RouteMessage) -> Option<Ipv4Addr> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(ip)) => Some(*ip),
            _ => None,
        })
}

fn rule_priority(rule: &RuleMessage) -> Option<u32> {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
}

fn rule_table(rule: &RuleMessage) -> u32 {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(rule.header.table))
}

/// `FRA_SPORT_MASK` and `FRA_DPORT_MASK` (`linux/fib_rules.h`), which this
/// crate version does not name. Newer kernels report a port rule's mask,
/// full when none was given.
const FRA_SPORT_MASK: u16 = 28;
const FRA_DPORT_MASK: u16 = 29;

/// The rule at `priority` is exactly the one written: `selectors` and
/// nothing else, not inverted, into the Pod table. What the kernel adds to
/// what was written selects nothing more: the rule's protocol, the unset
/// suppress values (-1), and a full port mask (seen on Linux 7.2).
fn rule_is(rule: &RuleMessage, priority: u32, selectors: &[RuleAttribute]) -> bool {
    let theirs: Vec<&RuleAttribute> = rule
        .attributes
        .iter()
        .filter(|attribute| {
            !matches!(
                attribute,
                RuleAttribute::Priority(_)
                    | RuleAttribute::Table(_)
                    | RuleAttribute::Protocol(_)
                    | RuleAttribute::SuppressPrefixLen(u32::MAX)
                    | RuleAttribute::SuppressIfGroup(u32::MAX)
            ) && !full_port_mask(attribute)
        })
        .collect();
    rule_priority(rule) == Some(priority)
        && rule.header.action == RuleAction::ToTable
        && !rule.header.flags.contains(RuleFlags::Invert)
        && rule.header.src_len == source_length(selectors)
        && rule.header.dst_len == 0
        && rule.header.tos == 0
        && rule_table(rule) == HOSTED_POD_ROUTE_TABLE
        && theirs.len() == selectors.len()
        && selectors.iter().all(|selector| theirs.contains(&selector))
}

#[cfg(test)]
mod tests;
