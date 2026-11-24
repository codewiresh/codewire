use super::*;

fn plan() -> Plan {
    Plan {
        tun: 7,
        pod: 2,
        pod_address: Ipv4Addr::new(10, 1, 2, 3),
        pod_gateway: Ipv4Addr::new(169, 254, 1, 1),
    }
}

/// The rules and routes as the kernel would dump them after `configure`.
fn configured() -> (Vec<RuleMessage>, Vec<RouteMessage>) {
    let plan = plan();
    let rules = rule_selectors(&plan)
        .into_iter()
        .map(|(priority, selectors, _)| rule(priority, selectors))
        .collect();
    let routes = vec![
        default_route(HOSTED_POD_ROUTE_TABLE, plan.pod_gateway, plan.pod, true),
        default_route(MAIN_TABLE, HOSTED_GATEWAY, plan.tun, false),
    ];
    (rules, routes)
}

fn readback(rules: &[RuleMessage], routes: &[RouteMessage]) -> Option<&'static str> {
    match check(rules, routes, &plan()) {
        Ok(()) => None,
        Err(RoutingError::Readback(what)) => Some(what),
        Err(other) => panic!("not a readback error: {other}"),
    }
}

#[test]
fn the_routing_as_configured_reads_back() {
    let (rules, routes) = configured();
    assert_eq!(readback(&rules, &routes), None);
    // The kernel adds the rule's protocol and its unset suppress values
    // (Linux 7.2 dumps them for every rule); none of them is a selector.
    let mut dumped = rules.clone();
    for rule in &mut dumped {
        rule.attributes.extend([
            RuleAttribute::Protocol(netlink_packet_route::route::RouteProtocol::Unspec),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
            RuleAttribute::SuppressIfGroup(u32::MAX),
        ]);
    }
    assert_eq!(readback(&dumped, &routes), None);
    // A set suppress value changes what the rule does.
    let mut suppressing = rules.clone();
    suppressing[1]
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(0));
    assert_eq!(
        readback(&suppressing, &routes),
        Some("the Pod-interface rule")
    );
    // A newer kernel reports the source-port rule's full mask (seen on
    // Linux 7.2); that is the same rule. Any other mask narrows it.
    let mask = |value: u16| {
        RuleAttribute::Other(netlink_packet_core::DefaultNla::new(
            FRA_SPORT_MASK,
            value.to_ne_bytes().to_vec(),
        ))
    };
    let mut full = rules.clone();
    full[0].attributes.push(mask(u16::MAX));
    assert_eq!(readback(&full, &routes), None);
    let mut narrowed = rules.clone();
    narrowed[0].attributes.push(mask(0xff00));
    assert_eq!(readback(&narrowed, &routes), Some("the source-port rule"));
}

#[test]
fn a_missing_or_altered_rule_is_named() {
    let (rules, routes) = configured();
    let without = |priority| -> Vec<RuleMessage> {
        rules
            .iter()
            .filter(|rule| rule_priority(rule) != Some(priority))
            .cloned()
            .collect()
    };
    assert_eq!(
        readback(&without(1_000), &routes),
        Some("the source-port rule")
    );
    assert_eq!(
        readback(&without(1_001), &routes),
        Some("the Pod-interface rule")
    );
    assert_eq!(
        readback(&without(1_002), &routes),
        Some("the Pod-address rule")
    );

    let altered = |change: &dyn Fn(&mut RuleMessage)| -> Option<&'static str> {
        let mut rules = rules.clone();
        change(&mut rules[1]);
        readback(&rules, &routes)
    };
    let pod_interface = Some("the Pod-interface rule");
    assert_eq!(
        altered(&|rule| {
            rule.attributes
                .retain(|a| !matches!(a, RuleAttribute::Table(_)));
            rule.attributes.push(RuleAttribute::Table(MAIN_TABLE));
        }),
        pod_interface,
        "another table"
    );
    assert_eq!(
        altered(&|rule| rule.header.flags = RuleFlags::Invert),
        pod_interface,
        "inverted"
    );
    assert_eq!(
        altered(&|rule| rule.header.action = RuleAction::Unreachable),
        pod_interface,
        "another action"
    );
    assert_eq!(
        altered(&|rule| rule.attributes.push(RuleAttribute::FwMark(1))),
        pod_interface,
        "an extra selector"
    );
}

#[test]
fn the_source_port_rule_takes_only_udp() {
    let (priority, selectors, _) = rule_selectors(&plan())[0].clone();
    assert_eq!(priority, 1_000);
    assert!(selectors.contains(&RuleAttribute::IpProtocol(IpProtocol::Udp)));
    // The same port without the protocol is a different rule.
    let port_only: Vec<RuleAttribute> = selectors
        .iter()
        .filter(|selector| !matches!(selector, RuleAttribute::IpProtocol(_)))
        .cloned()
        .collect();
    assert!(!rule_is(&rule(priority, port_only), priority, &selectors));
}

#[test]
fn each_table_has_exactly_its_one_default() {
    let (rules, routes) = configured();
    let pod_table = Some("the Pod table's one default via the Pod's gateway");
    let main_table = Some("the main table's one default into the TUN");

    let mut two_main = routes.clone();
    two_main.push(default_route(
        MAIN_TABLE,
        plan().pod_gateway,
        plan().pod,
        false,
    ));
    assert_eq!(readback(&rules, &two_main), main_table);

    let mut main_by_eth0 = routes.clone();
    main_by_eth0[1] = default_route(MAIN_TABLE, plan().pod_gateway, plan().pod, false);
    assert_eq!(readback(&rules, &main_by_eth0), main_table);

    assert_eq!(readback(&rules, &routes[1..]), pod_table);
    let mut pod_by_tun = routes.clone();
    pod_by_tun[0] = default_route(HOSTED_POD_ROUTE_TABLE, plan().pod_gateway, plan().tun, true);
    assert_eq!(readback(&rules, &pod_by_tun), pod_table);
}

#[test]
fn the_gateway_comes_from_the_pods_default_before_and_after_the_first_run() {
    let plan = plan();
    // The Pod as the platform made it: the main table's default by eth0.
    let fresh = [default_route(MAIN_TABLE, plan.pod_gateway, plan.pod, false)];
    assert_eq!(pod_gateway(&fresh, plan.pod).unwrap(), plan.pod_gateway);
    // After a run the main default goes into the TUN; the Pod table has it.
    let (_, configured) = configured();
    assert_eq!(
        pod_gateway(&configured, plan.pod).unwrap(),
        plan.pod_gateway
    );
    // A default on another interface is not the Pod's.
    let elsewhere = [default_route(MAIN_TABLE, plan.pod_gateway, plan.tun, false)];
    assert!(matches!(
        pod_gateway(&elsewhere, plan.pod),
        Err(RoutingError::PodInterface(_, "no default gateway"))
    ));
    // A default by eth0 with no gateway gives none.
    let mut no_gateway = default_route(MAIN_TABLE, plan.pod_gateway, plan.pod, false);
    no_gateway
        .attributes
        .retain(|a| !matches!(a, RouteAttribute::Gateway(_)));
    assert!(matches!(
        pod_gateway(&[no_gateway], plan.pod),
        Err(RoutingError::PodInterface(_, "no default gateway"))
    ));
}

#[test]
fn a_default_route_names_its_table_gateway_and_interface() {
    let pod = default_route(HOSTED_POD_ROUTE_TABLE, plan().pod_gateway, plan().pod, true);
    assert!(is_default_in(&pod, HOSTED_POD_ROUTE_TABLE));
    assert_eq!(pod.header.table, 0, "a table over 255 goes by attribute");
    assert_eq!(oif(&pod), Some(plan().pod));
    assert_eq!(gateway(&pod), Some(plan().pod_gateway));
    assert_eq!(pod.header.flags, RouteFlags::Onlink);
    let main = default_route(MAIN_TABLE, HOSTED_GATEWAY, plan().tun, false);
    assert!(is_default_in(&main, MAIN_TABLE));
    assert_eq!(main.header.table, 254);
    assert!(!is_default_in(&main, HOSTED_POD_ROUTE_TABLE));
    let by_address = rule(
        1_002,
        vec![RuleAttribute::Source(IpAddr::V4(plan().pod_address))],
    );
    assert_eq!(by_address.header.src_len, 32);
}

/// Against a real kernel: run by hand as root of a network namespace that
/// `cw __hosted-egress-tun` configured, before and after changing its
/// routing (`scripts/dev/hosted-egress-routing-namespace.sh`).
#[test]
#[ignore = "reads the routing of the namespace it runs in"]
fn this_namespace_verifies() {
    verify().unwrap();
}

/// Where a packet leaves under the rules [`rule_selectors`] makes, by the
/// kernel's order: the first rule whose every selector matches sends it to
/// the Pod table, whose default is `eth0`; otherwise the main table, where a
/// destination inside an interface's own /30 goes to that interface and
/// anything else follows the default into the TUN. A model of the routing,
/// not the kernel's; the Kind walk checks the kernel.
fn leaves_by(
    plan: &Plan,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    udp_source_port: Option<u16>,
    bound_to_pod: bool,
) -> &'static str {
    let matches = |selector: &RuleAttribute| match selector {
        RuleAttribute::IpProtocol(IpProtocol::Udp) => udp_source_port.is_some(),
        RuleAttribute::SourcePortRange(range) => {
            udp_source_port.is_some_and(|port| (range.start..=range.end).contains(&port))
        }
        RuleAttribute::Oifname(name) => bound_to_pod && name == HOSTED_POD_INTERFACE,
        RuleAttribute::Source(IpAddr::V4(address)) => source == *address,
        _ => false,
    };
    if rule_selectors(plan)
        .iter()
        .any(|(_, selectors, _)| selectors.iter().all(matches))
    {
        return HOSTED_POD_INTERFACE;
    }
    let same_slash_30 = |a: Ipv4Addr, b: Ipv4Addr| u32::from(a) >> 2 == u32::from(b) >> 2;
    if same_slash_30(destination, HOSTED_GUEST_ADDRESS) {
        HOSTED_TUN_NAME
    } else if same_slash_30(destination, plan.pod_address) {
        HOSTED_POD_INTERFACE
    } else {
        HOSTED_TUN_NAME
    }
}

fn standard_broker_plan(pod_address: Ipv4Addr, pod_gateway: Ipv4Addr) -> Plan {
    Plan {
        tun: 7,
        pod: 2,
        pod_address,
        pod_gateway,
    }
}

/// A broker-mode standard guest (#5602): its `eth0` holds the /30 beside
/// `cwegress0`'s, so the workload's packets, from `cwegress0`'s address,
/// and its DNS at the netstack leave by `cwegress0`, while the daemon's
/// platform dials, bound to `eth0`, and its direct tailnet socket leave by
/// `eth0` (cw-egress's review, #5602 comment 139460).
#[test]
fn a_broker_mode_standard_guests_workload_leaves_by_the_tun() {
    let plan = standard_broker_plan(
        super::super::HOSTED_BROKER_POD_ADDRESS,
        super::super::HOSTED_BROKER_POD_GATEWAY,
    );
    let public = Ipv4Addr::new(203, 0, 113, 7);
    assert_eq!(
        leaves_by(&plan, HOSTED_GUEST_ADDRESS, public, None, false),
        HOSTED_TUN_NAME
    );
    assert_eq!(
        leaves_by(
            &plan,
            HOSTED_GUEST_ADDRESS,
            HOSTED_GATEWAY,
            Some(53_000),
            false
        ),
        HOSTED_TUN_NAME
    );
    let platform_peer = Ipv4Addr::new(10, 44, 0, 89);
    assert_eq!(
        leaves_by(&plan, plan.pod_address, platform_peer, None, true),
        HOSTED_POD_INTERFACE
    );
    assert_eq!(
        leaves_by(
            &plan,
            HOSTED_GUEST_ADDRESS,
            public,
            Some(TAILNET_DIRECT_SOURCE_PORT),
            false
        ),
        HOSTED_POD_INTERFACE
    );
}
