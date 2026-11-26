use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;

use super::*;

const SANDBOXES: &str = "dev-sandboxes";
const SERVER: &str = "dev";
const NODE: &str = "runtime-a";

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 92, 4, 7))
}

fn guest_identity() -> Reviewed<'static> {
    Reviewed {
        namespace: SANDBOXES,
        pod_name: "workspace-1",
        pod_uid: "guest-uid",
    }
}

fn caller_identity() -> Reviewed<'static> {
    Reviewed {
        namespace: SERVER,
        pod_name: "codewire-egress-x",
        pod_uid: "caller-uid",
    }
}

fn facts(identity: Reviewed<'_>, account: &str, labels: &[(&str, &str)]) -> MemberFacts {
    MemberFacts {
        name: Some(identity.pod_name.to_owned()),
        namespace: Some(identity.namespace.to_owned()),
        uid: Some(identity.pod_uid.to_owned()),
        terminating: false,
        service_account: Some(account.to_owned()),
        controllers: Vec::new(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<BTreeMap<_, _>>(),
        annotations: BTreeMap::new(),
        has_spec: true,
        volumes: Vec::new(),
        containers: Vec::new(),
        init_containers: Vec::new(),
        image_ids: Vec::new(),
        ip: peer().to_string(),
        ips: vec![peer().to_string()],
        phase: Some("Running".to_owned()),
        node_name: Some(NODE.to_owned()),
        spec_json: Value::Null,
    }
}

fn guest() -> MemberFacts {
    facts(
        guest_identity(),
        SANDBOX_SERVICE_ACCOUNT,
        &[
            (LABEL_TYPE, "workspace"),
            (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
        ],
    )
}

fn caller() -> MemberFacts {
    facts(caller_identity(), EGRESS_NODE_SERVICE_ACCOUNT, &[])
}

fn admit(guest: &MemberFacts, peer: IpAddr) -> Result<(), GuestRefusal> {
    admit_guest(guest_identity(), guest, NODE, peer, SANDBOXES)
}

#[test]
fn the_callers_node_comes_from_its_own_live_pod() {
    for used in [CallerUse::NewStream, CallerUse::HeldStream] {
        assert_eq!(
            caller_node(caller_identity(), &caller(), SERVER, used).unwrap(),
            NODE
        );
    }
}

#[test]
fn a_caller_in_another_namespace_or_under_another_account_is_refused() {
    for used in [CallerUse::NewStream, CallerUse::HeldStream] {
        let elsewhere = Reviewed {
            namespace: "other",
            ..caller_identity()
        };
        assert_eq!(
            caller_node(elsewhere, &caller(), SERVER, used),
            Err(CallerRefusal::WrongNamespace)
        );
        let as_sandbox = facts(caller_identity(), SANDBOX_SERVICE_ACCOUNT, &[]);
        assert_eq!(
            caller_node(caller_identity(), &as_sandbox, SERVER, used),
            Err(CallerRefusal::NotTheCaller)
        );
        let mut replaced = caller();
        replaced.uid = Some("other-uid".to_owned());
        assert_eq!(
            caller_node(caller_identity(), &replaced, SERVER, used),
            Err(CallerRefusal::NotTheCaller)
        );
        let mut unscheduled = caller();
        unscheduled.node_name = None;
        assert_eq!(
            caller_node(caller_identity(), &unscheduled, SERVER, used),
            Err(CallerRefusal::NotTheCaller)
        );
    }
}

#[test]
fn a_draining_caller_keeps_the_streams_it_holds_but_admits_no_new_one() {
    let mut draining = caller();
    draining.terminating = true;
    assert_eq!(
        caller_node(caller_identity(), &draining, SERVER, CallerUse::NewStream),
        Err(CallerRefusal::Draining)
    );
    assert_eq!(
        caller_node(caller_identity(), &draining, SERVER, CallerUse::HeldStream).unwrap(),
        NODE
    );
    // Draining excuses nothing else: a replaced caller is still refused.
    draining.uid = Some("other-uid".to_owned());
    assert_eq!(
        caller_node(caller_identity(), &draining, SERVER, CallerUse::HeldStream),
        Err(CallerRefusal::NotTheCaller)
    );
}

#[test]
fn a_running_broker_mode_workspace_on_the_callers_node_from_its_own_address_is_admitted() {
    assert_eq!(admit(&guest(), peer()), Ok(()));
}

#[test]
fn a_pod_on_another_node_is_refused() {
    let mut elsewhere = guest();
    elsewhere.node_name = Some("runtime-b".to_owned());
    assert_eq!(
        admit(&elsewhere, peer()),
        Err(GuestRefusal::PodOnAnotherNode)
    );
}

#[test]
fn a_pod_without_the_label_is_refused_with_a_valid_token_node_and_address() {
    let mut unlabelled = guest();
    unlabelled.labels.remove(EGRESS_MODE_LABEL);
    assert_eq!(admit(&unlabelled, peer()), Err(GuestRefusal::NotBrokerMode));
    let mut other = guest();
    other
        .labels
        .insert(EGRESS_MODE_LABEL.to_owned(), "direct".to_owned());
    assert_eq!(admit(&other, peer()), Err(GuestRefusal::NotBrokerMode));
}

#[test]
fn a_recycled_address_or_a_replaced_pod_is_refused() {
    let other = IpAddr::V4(Ipv4Addr::new(10, 92, 4, 8));
    assert_eq!(admit(&guest(), other), Err(GuestRefusal::PeerIsNotThePod));
    let mut replaced = guest();
    replaced.uid = Some("new-uid".to_owned());
    assert_eq!(admit(&replaced, peer()), Err(GuestRefusal::PodReplaced));
}

#[test]
fn a_terminating_or_non_workspace_pod_is_refused() {
    let mut ending = guest();
    ending.terminating = true;
    assert_eq!(admit(&ending, peer()), Err(GuestRefusal::PodTerminating));
    let mut pending = guest();
    pending.phase = Some("Pending".to_owned());
    assert_eq!(
        admit(&pending, peer()),
        Err(GuestRefusal::NotARunningWorkspace)
    );
    let mut not_workspace = guest();
    not_workspace.labels.remove(LABEL_TYPE);
    assert_eq!(
        admit(&not_workspace, peer()),
        Err(GuestRefusal::NotARunningWorkspace)
    );
    let as_orchestration = facts(
        guest_identity(),
        "codewire-orchestration",
        &[
            (LABEL_TYPE, "workspace"),
            (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
        ],
    );
    assert_eq!(
        admit(&as_orchestration, peer()),
        Err(GuestRefusal::NotARunningWorkspace)
    );
}

#[test]
fn a_guest_token_from_outside_the_sandbox_namespace_is_refused() {
    let elsewhere = Reviewed {
        namespace: SERVER,
        ..guest_identity()
    };
    assert_eq!(
        admit_guest(elsewhere, &guest(), NODE, peer(), SANDBOXES),
        Err(GuestRefusal::WrongNamespace)
    );
}
