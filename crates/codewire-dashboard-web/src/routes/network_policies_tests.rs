use askama::Template as _;

use super::*;
use crate::network_policies_connect::{CheckAnswer, RuleRow, Usage};
use crate::view::OrganizationRow;

/// The not-enforced sentence as rendered; askama escapes its apostrophe.
const NOT_ENFORCED_SHOWN: &str =
    "enforce network policies yet, so a policy here changes nothing a Sandbox can reach.";

fn organization(can_admin: bool) -> OrganizationContext {
    OrganizationContext::from_row(&OrganizationRow {
        id: "org-test".into(),
        name: "Test organization".into(),
        slug: "acme".into(),
        billing_plan: "none".into(),
        role: if can_admin { "Owner" } else { "Member" },
        can_admin,
        url: "/acme/".into(),
        joined: String::new(),
        only_owner: false,
        agent_chat: false,
    })
}

fn policy(name: &str, rules: &[(&str, &[u32])], usage: Usage) -> PolicyRow {
    PolicyRow {
        id: format!("id-{name}"),
        name: name.into(),
        revision: 3,
        digest: String::new(),
        rules: rules
            .iter()
            .map(|(target, ports)| RuleRow {
                target: (*target).into(),
                ports: ports.to_vec(),
            })
            .collect(),
        saved: "4m ago".into(),
        usage,
    }
}

fn usage(sandboxes: u32, names: &[&str]) -> Usage {
    Usage {
        sandboxes,
        names: names.iter().map(|name| (*name).into()).collect(),
    }
}

fn list_page(store: StoreState, list: PolicyList, can_admin: bool) -> String {
    NetworkPoliciesTemplate {
        view: &DashboardView::default(),
        organization: &organization(can_admin),
        page: &ListPageView {
            store,
            list,
            csrf_token: "csrf".into(),
            message: "",
            error: "",
            create: CreateForm::default(),
        },
        active_tab: "network-policies",
    }
    .render()
    .expect("render the list")
}

#[test]
fn ports_parse_as_the_cli_takes_them() {
    assert_eq!(parse_ports(""), Ok(vec![]));
    assert_eq!(parse_ports("443"), Ok(vec![443]));
    assert_eq!(parse_ports(" 22, 80 ,443 "), Ok(vec![22, 80, 443]));
    assert!(parse_ports("0").is_err());
    assert!(parse_ports("65536").is_err());
    assert!(parse_ports("https").is_err());
}

#[test]
fn only_a_name_the_store_could_hold_is_a_policy_page() {
    assert!(valid_name("docs-and-crates"));
    assert!(valid_name("a.b_c"));
    assert!(!valid_name(""));
    assert!(!valid_name("Docs"));
    assert!(!valid_name("../x"));
    assert!(!valid_name(&"a".repeat(65)));
}

#[test]
fn an_empty_organization_shows_the_built_ins_and_its_hint_below_create() {
    let html = list_page(StoreState::Ready, PolicyList::default(), true);
    assert!(html.contains("No policies yet"));
    assert!(html.contains("By default, Sandboxes with no policy can reach any public address."));
    assert!(html.contains(r#"<p class="cw-empty-hint">Or from a terminal:"#));
    assert!(html.contains(NOT_ENFORCED_SHOWN));
    assert!(html.contains("cw-page-header--stacked"));
    assert!(html.contains(r#"id="create-network-policy""#));
}

#[test]
fn used_by_is_a_number_and_its_popover_names_ten_then_the_rest() {
    let names: Vec<String> = (0..10).map(|n| format!("sandbox-{n:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let list = PolicyList {
        policies: vec![
            policy("web", &[("docs.rs", &[443])], usage(12, &refs)),
            policy("idle", &[], usage(0, &[])),
        ],
        ..Default::default()
    };
    let html = list_page(StoreState::Ready, list, true);
    assert!(html.contains(r#"popovertarget="used-id-web" popovertargetaction="show" data-field-help-trigger>12<span class="cw-sr-only"> Sandboxes use web</span>"#));
    assert!(html.contains("<li>sandbox-09</li>"));
    assert!(html.contains("and 2 more"));
    assert!(html.contains(r#"<span class="cw-network-policy-count">0</span>"#));
    assert!(html.contains("docs.rs (443)"));
}

#[test]
fn a_member_reads_and_cannot_change() {
    let list = PolicyList {
        policies: vec![policy("web", &[("docs.rs", &[443])], usage(0, &[]))],
        ..Default::default()
    };
    let html = list_page(StoreState::Ready, list, false);
    assert!(html.contains("Owners and admins change them."));
    assert!(!html.contains("create-network-policy"));
}

#[test]
fn a_switched_off_store_and_a_failed_read_say_so_in_plain_words() {
    let off = list_page(StoreState::SwitchedOff, PolicyList::default(), true);
    assert!(off.contains("Network policies aren't available here yet"));
    assert!(!off.contains(NOT_ENFORCED_SHOWN));
    let failed = list_page(StoreState::Unavailable, PolicyList::default(), true);
    assert!(failed.contains("This doesn't mean you have none."));
    assert!(failed.contains(">Retry</a>"));
}

#[test]
fn the_policy_page_shows_the_check_in_the_cli_words_and_keeps_a_refused_edit() {
    let page = PolicyPageView {
        policy: policy(
            "web",
            &[("*.crates.io", &[22, 80, 443])],
            usage(1, &["api"]),
        ),
        csrf_token: "csrf".into(),
        message: "",
        error: String::new(),
        allow: AllowForm {
            target: "10.0.0.0/8".into(),
            ports: "443".into(),
            error: "the range includes protected addresses".into(),
        },
        check_input: "pypi.org:443".into(),
        check: Some(CheckAnswer {
            destination: "pypi.org:443".into(),
            allowed: false,
            detail: "name not allowed".into(),
            within: String::new(),
        }),
        check_error: "",
    };
    let html = NetworkPolicyTemplate {
        view: &DashboardView::default(),
        organization: &organization(true),
        page: &page,
        active_tab: "network-policies",
    }
    .render()
    .expect("render the policy");
    assert!(html.contains("by web rev 3 (name not allowed)"));
    assert!(html.contains(r#"value="10.0.0.0/8""#));
    assert!(html.contains("the range includes protected addresses"));
    assert!(html.contains(r#"name="revision" value="3""#));
    assert!(html.contains("ports 22, 80, 443"));
    assert!(html.contains("Used by 1 Sandbox"));
}
