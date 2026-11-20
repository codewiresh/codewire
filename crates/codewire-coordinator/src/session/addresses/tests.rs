use std::net::Ipv6Addr;

use codewire_tailnet::node::{DiscoPublic, Prefix};

use super::*;

fn env_id() -> Uuid {
    Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap()
}

fn key(byte: u8) -> NodePublic {
    NodePublic::from_raw([byte; 32])
}

fn node(id: Uuid, key: NodePublic, addresses: Vec<Prefix>) -> Node {
    Node {
        id,
        as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
        key,
        disco_key: DiscoPublic::from_raw([0x22; 32]),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses,
    }
}

fn client(id: Uuid, key: NodePublic) -> Node {
    node(id, key, vec![prefix_from_uuid(&id)])
}

fn check_client(node: &Node) -> Result<(), AddressRefusal> {
    check(PeerKind::Client, env_id(), node, &mut None)
}

#[test]
fn a_client_carries_one_host_address_under_the_prefix_that_is_not_its_environments() {
    let id = Uuid::new_v4();
    let own = prefix_from_uuid(&id);
    assert_eq!(check_client(&client(id, key(1))), Ok(()));

    let two = node(id, key(1), vec![own, prefix_from_uuid(&Uuid::new_v4())]);
    let none = node(id, key(1), Vec::new());
    let broader = node(id, key(1), vec![Prefix::new(own.addr(), 64)]);
    let outside = node(
        id,
        key(1),
        vec![Prefix::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            128,
        )],
    );
    let ipv4 = node(
        id,
        key(1),
        vec![Prefix::new(
            IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1)),
            32,
        )],
    );
    for refused in [two, none, broader, outside, ipv4] {
        assert_eq!(
            check_client(&refused),
            Err(AddressRefusal::Shape),
            "{:?}",
            refused.addresses
        );
    }
    let environments = node(id, key(1), vec![prefix_from_uuid(&env_id())]);
    assert_eq!(
        check_client(&environments),
        Err(AddressRefusal::EnvironmentsOwn)
    );
}

#[test]
fn a_client_keeps_its_first_address_for_its_session() {
    let id = Uuid::new_v4();
    let mut pinned = None;
    let first = client(id, key(1));
    assert_eq!(
        check(PeerKind::Client, env_id(), &first, &mut pinned),
        Ok(())
    );
    assert_eq!(
        check(PeerKind::Client, env_id(), &first, &mut pinned),
        Ok(())
    );
    let moved = node(id, key(1), vec![prefix_from_uuid(&Uuid::new_v4())]);
    assert_eq!(
        check(PeerKind::Client, env_id(), &moved, &mut pinned),
        Err(AddressRefusal::Changed)
    );
}

#[test]
fn an_environment_announces_the_address_of_its_id() {
    let own = node(env_id(), key(9), vec![prefix_from_uuid(&env_id())]);
    assert_eq!(check(PeerKind::Sidecar, env_id(), &own, &mut None), Ok(()));
    let other = node(env_id(), key(9), vec![prefix_from_uuid(&Uuid::new_v4())]);
    assert_eq!(
        check(PeerKind::Sidecar, env_id(), &other, &mut None),
        Err(AddressRefusal::NotEnvironmentsOwn)
    );
}

#[test]
fn the_first_live_holder_keeps_an_address_until_it_is_released() {
    let mut holders = AddressHolders::default();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let held = client(first, key(1));
    let squatter = node(second, key(2), held.addresses.clone());

    assert_eq!(holders.admit(env_id(), vec![held.clone()]).len(), 1);
    // The registry repeats every local client in each update.
    let forwarded = holders.admit(env_id(), vec![held.clone(), squatter.clone()]);
    assert_eq!(
        forwarded.iter().map(|node| node.id).collect::<Vec<_>>(),
        [first]
    );

    holders.release(first);
    assert_eq!(holders.admit(env_id(), vec![squatter]).len(), 1);
}

#[test]
fn the_same_key_replaces_its_holder_even_before_the_old_node_is_removed() {
    let mut holders = AddressHolders::default();
    let old = Uuid::new_v4();
    let new = Uuid::new_v4();
    let before = client(old, key(1));
    let reconnect = node(new, key(1), before.addresses.clone());
    let other = node(Uuid::new_v4(), key(2), before.addresses.clone());

    assert_eq!(holders.admit(env_id(), vec![before]).len(), 1);
    assert_eq!(holders.admit(env_id(), vec![reconnect.clone()]).len(), 1);
    // The old session's removal arrives after its successor's node.
    holders.release(old);
    assert_eq!(holders.admit(env_id(), vec![other]).len(), 0);
    assert_eq!(holders.admit(env_id(), vec![reconnect]).len(), 1);
}

#[test]
fn a_node_from_an_unchecked_replica_is_checked_before_it_is_forwarded() {
    let mut holders = AddressHolders::default();
    let id = Uuid::new_v4();
    let wide = node(
        id,
        key(1),
        vec![Prefix::new(prefix_from_uuid(&id).addr(), 48)],
    );
    let environments = node(id, key(1), vec![prefix_from_uuid(&env_id())]);
    assert!(holders.admit(env_id(), vec![wide, environments]).is_empty());
}
