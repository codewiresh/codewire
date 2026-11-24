//! The Network policies pages' reads and changes (#5114): the organization's
//! stored policies through `NetworkPolicyService`, as the signed-in member,
//! and a destination checked with the engine `cw --cloud policy check` uses.

use std::net::IpAddr;

use axum::http::HeaderValue;
use codewire_egress_policy::check::CheckDestination;
use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy};
use codewire_egress_policy::{BuiltinPolicy, DEFAULT_ALLOW_PORTS};
use codewire_proto::codewire::v1::__buffa::oneof::{network_policy_selector, network_policy_usage};
use codewire_proto::codewire::v1::{
    CreateNetworkPolicyRequest, DeleteNetworkPolicyRequest, GetNetworkPolicyRequest,
    ListNetworkPoliciesRequest, NetworkPolicy, NetworkPolicyRule, NetworkPolicySelector,
    NetworkPolicyServiceClient, NetworkPolicyUsage, UpdateNetworkPolicyRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{organization_connect::past_time, state::AppState, transport::BrowserTransport};

/// The port a check uses when none is given, as `cw policy check` does.
pub(crate) const DEFAULT_CHECK_PORT: u16 = 443;

/// One stored policy at its current revision, as the pages show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) revision: u32,
    pub(crate) digest: String,
    pub(crate) rules: Vec<RuleRow>,
    /// "4 minutes ago".
    pub(crate) saved: String,
    pub(crate) usage: Usage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleRow {
    pub(crate) target: String,
    pub(crate) ports: Vec<u32>,
}

impl RuleRow {
    /// `docs.rs (443)` or `*.crates.io (22, 80, 443)`.
    pub(crate) fn summary(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u32::to_string).collect();
        format!("{} ({})", self.target, ports.join(", "))
    }

    /// `port 443` or `ports 22, 80, 443`.
    pub(crate) fn ports_text(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u32::to_string).collect();
        let noun = if self.ports.len() == 1 {
            "port"
        } else {
            "ports"
        };
        format!("{noun} {}", ports.join(", "))
    }
}

/// How many hosted Sandboxes select one thing, and the first names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub(crate) sandboxes: u32,
    pub(crate) names: Vec<String>,
}

impl Usage {
    /// How many more select it than the names show.
    pub(crate) fn more(&self) -> u32 {
        self.sandboxes
            .saturating_sub(u32::try_from(self.names.len()).unwrap_or(u32::MAX))
    }
}

/// The organization's policies and what its Sandboxes select.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyList {
    pub(crate) policies: Vec<PolicyRow>,
    pub(crate) open: Usage,
    pub(crate) locked: Usage,
    /// Sandboxes that select nothing. The service counts them under `open`
    /// since #3997, so this stays empty until the page is rewired.
    pub(crate) unselected: Usage,
}

/// An allowed destination as the user typed it, before the store judges it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RuleInput {
    pub(crate) target: String,
    /// Empty means 22, 80 and 443.
    pub(crate) ports: Vec<u32>,
}

/// A check's answer in the CLI's words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckAnswer {
    /// `static.crates.io:443`.
    pub(crate) destination: String,
    pub(crate) allowed: bool,
    /// The engine's own words: "when the name answers public addresses" for
    /// an allowed name, or the refusal's reason, such as "name not allowed".
    pub(crate) detail: String,
    /// "Also allowed if the name resolves within …", when that applies.
    pub(crate) within: String,
}

fn client(state: &AppState, cookie: HeaderValue) -> NetworkPolicyServiceClient<BrowserTransport> {
    NetworkPolicyServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone())
            .with_default_timeout(std::time::Duration::from_secs(10)),
    )
}

fn by_name(name: &str) -> NetworkPolicySelector {
    NetworkPolicySelector {
        selector: Some(network_policy_selector::Selector::Name(name.to_owned())),
        ..Default::default()
    }
}

fn proto_rules(rules: &[RuleInput]) -> Vec<NetworkPolicyRule> {
    rules
        .iter()
        .map(|rule| NetworkPolicyRule {
            target: rule.target.clone(),
            ports: if rule.ports.is_empty() {
                DEFAULT_ALLOW_PORTS.map(u32::from).to_vec()
            } else {
                rule.ports.clone()
            },
            ..Default::default()
        })
        .collect()
}

fn policy_row(policy: &NetworkPolicy, usage: Usage) -> PolicyRow {
    PolicyRow {
        id: policy.id.clone(),
        name: policy.name.clone(),
        revision: policy.revision,
        digest: policy.digest.clone(),
        rules: policy
            .rules
            .iter()
            .map(|rule| RuleRow {
                target: rule.target.clone(),
                ports: rule.ports.clone(),
            })
            .collect(),
        saved: policy
            .created_at
            .as_option()
            .map(|at| past_time(at.seconds))
            .unwrap_or_default(),
        usage,
    }
}

fn usage_of(usage: &NetworkPolicyUsage) -> Usage {
    Usage {
        sandboxes: usage.environments,
        names: usage.names.clone(),
    }
}

pub(crate) async fn list(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<PolicyList, ConnectError> {
    let response = client(state, cookie)
        .list_network_policies(ListNetworkPoliciesRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let mut list = PolicyList::default();
    let mut stored = std::collections::HashMap::new();
    for usage in &response.usage {
        match &usage.selection {
            Some(network_policy_usage::Selection::PolicyId(id)) => {
                stored.insert(id.clone(), usage_of(usage));
            }
            Some(network_policy_usage::Selection::Builtin(name)) => {
                match BuiltinPolicy::from_name(name) {
                    Some(BuiltinPolicy::Open) => list.open = usage_of(usage),
                    Some(BuiltinPolicy::Locked) => list.locked = usage_of(usage),
                    // A hosted Sandbox may select `web` (0053), but the page
                    // has no row for it until its text lands (#6226).
                    Some(BuiltinPolicy::Web) | None => {}
                }
            }
            None => {}
        }
    }
    list.policies = response
        .policies
        .iter()
        .map(|policy| policy_row(policy, stored.remove(&policy.id).unwrap_or_default()))
        .collect();
    Ok(list)
}

/// One policy at its current revision, with what selects it.
pub(crate) async fn get(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    name: &str,
) -> Result<PolicyRow, ConnectError> {
    let response = client(state, cookie.clone())
        .get_network_policy(GetNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            policy: Some(by_name(name)).into(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let policy = response.policy.into_option().ok_or_else(|| {
        ConnectError::new(
            connectrpc::ErrorCode::Internal,
            "the network policy store answered with no policy",
        )
    })?;
    // Usage comes with the list; a failed read of it costs only the count.
    let usage = list(state, cookie, org_id)
        .await
        .ok()
        .and_then(|list| list.policies.into_iter().find(|row| row.id == policy.id))
        .map(|row| row.usage)
        .unwrap_or_default();
    Ok(policy_row(&policy, usage))
}

/// A policy at revision 1: the rules of `from` (one of the organization's
/// policies), or none, which is `locked`, plus `allow`.
pub(crate) async fn create(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    name: &str,
    from: Option<&str>,
    allow: &[RuleInput],
) -> Result<(), ConnectError> {
    client(state, cookie)
        .create_network_policy(CreateNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            name: name.to_owned(),
            from: from.map(by_name).into(),
            allow: proto_rules(allow),
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// A new revision of `name` with `allow` added and `remove` dropped, made
/// only if `expected_revision` is still current.
pub(crate) async fn update(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    name: &str,
    allow: &[RuleInput],
    remove: &[String],
    expected_revision: u32,
) -> Result<(), ConnectError> {
    client(state, cookie)
        .update_network_policy(UpdateNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            policy: Some(by_name(name)).into(),
            allow: proto_rules(allow),
            remove: remove.to_vec(),
            expected_revision,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn delete(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    name: &str,
) -> Result<(), ConnectError> {
    client(state, cookie)
        .delete_network_policy(DeleteNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            policy: Some(by_name(name)).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// Why a destination could not be checked, in the user's terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckError {
    /// Not a DNS name or IP address, or a port that is not 1 to 65535.
    Destination,
    /// The revision's rules don't match its digest, or don't compile.
    Policy,
}

/// `destination` (`NAME`, `NAME:PORT`, `ADDRESS`, `[V6]:PORT`) judged
/// against exactly the revision `policy` shows, as `cw policy check` judges it.
pub(crate) fn check(policy: &PolicyRow, destination: &str) -> Result<CheckAnswer, CheckError> {
    let (host, port) = split_destination(destination.trim())?;
    let parsed = CheckDestination::parse(host).map_err(|_| CheckError::Destination)?;
    let rules = policy
        .rules
        .iter()
        .map(|rule| {
            let ports = rule
                .ports
                .iter()
                .map(|port| u16::try_from(*port))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| CheckError::Policy)?;
            let target = AllowTarget::parse(&rule.target).map_err(|_| CheckError::Policy)?;
            AllowRule::new(target, ports).map_err(|_| CheckError::Policy)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let compiled = TypedPolicy::new(rules)
        .map_err(|_| CheckError::Policy)?
        .compile();
    if compiled.digest().to_hex() != policy.digest {
        return Err(CheckError::Policy);
    }
    let answer = compiled
        .check(&parsed, port)
        .map_err(|_| CheckError::Destination)?;
    let named = matches!(parsed, CheckDestination::Name(_));
    let shown = match &parsed {
        CheckDestination::Name(name) => format!("{name}:{port}"),
        CheckDestination::Address(IpAddr::V6(address)) => format!("[{address}]:{port}"),
        CheckDestination::Address(address) => format!("{address}:{port}"),
    };
    let detail = match answer.refusal {
        None if named => "when the name answers public addresses".to_owned(),
        None => String::new(),
        Some(reason) => reason.description().to_owned(),
    };
    let (verb, networks) = if answer.is_allowed() {
        ("refused", &answer.refused_within)
    } else {
        ("allowed", &answer.allowed_within)
    };
    let within = if networks.is_empty() {
        String::new()
    } else {
        format!(
            "Also {verb} if the name resolves within {}",
            networks.join(", ")
        )
    };
    Ok(CheckAnswer {
        destination: shown,
        allowed: answer.is_allowed(),
        detail,
        within,
    })
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`; the port defaults to 443.
fn split_destination(value: &str) -> Result<(&str, u16), CheckError> {
    let port = |text: &str| {
        text.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(CheckError::Destination)
    };
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(CheckError::Destination)?;
        return match tail {
            "" => Ok((host, DEFAULT_CHECK_PORT)),
            _ => Ok((
                host,
                port(tail.strip_prefix(':').ok_or(CheckError::Destination)?)?,
            )),
        };
    }
    match value.rsplit_once(':') {
        // A bare IPv6 address has colons and no port.
        Some(_) if value.parse::<IpAddr>().is_ok() => Ok((value, DEFAULT_CHECK_PORT)),
        Some((host, text)) => Ok((host, port(text)?)),
        None => Ok((value, DEFAULT_CHECK_PORT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy row whose digest is the engine's own for its rules.
    fn compiled(rules: &[(&str, &[u16])]) -> PolicyRow {
        let typed = TypedPolicy::new(
            rules
                .iter()
                .map(|(target, ports)| {
                    AllowRule::new(AllowTarget::parse(target).unwrap(), ports.to_vec()).unwrap()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        PolicyRow {
            id: "id".into(),
            name: "web".into(),
            revision: 2,
            digest: typed.compile().digest().to_hex(),
            rules: rules
                .iter()
                .map(|(target, ports)| RuleRow {
                    target: (*target).into(),
                    ports: ports.iter().copied().map(u32::from).collect(),
                })
                .collect(),
            saved: String::new(),
            usage: Usage::default(),
        }
    }

    #[test]
    fn a_check_answers_as_cw_policy_check_does() {
        let policy = compiled(&[("*.crates.io", &[443]), ("docs.rs", &[22, 80, 443])]);
        let allowed = check(&policy, "static.crates.io").unwrap();
        assert!(allowed.allowed);
        assert_eq!(allowed.destination, "static.crates.io:443");
        assert_eq!(allowed.detail, "when the name answers public addresses");
        let apex = check(&policy, "crates.io:443").unwrap();
        assert!(!apex.allowed);
        assert_eq!(apex.detail, "name not allowed");
        let port = check(&policy, "docs.rs:8443").unwrap();
        assert_eq!(port.detail, "port not allowed");
        let protected = check(&policy, "169.254.169.254:80").unwrap();
        assert_eq!(protected.detail, "protected address");
        assert_eq!(check(&policy, "[::1]").unwrap().destination, "[::1]:443");
    }

    #[test]
    fn a_bad_destination_or_a_revision_that_does_not_match_its_digest_is_not_checked() {
        let policy = compiled(&[("docs.rs", &[443])]);
        assert_eq!(check(&policy, "docs.rs:0"), Err(CheckError::Destination));
        assert_eq!(check(&policy, "not a name"), Err(CheckError::Destination));
        let mut tampered = policy;
        tampered.rules[0].target = "pypi.org".into();
        assert_eq!(check(&tampered, "pypi.org"), Err(CheckError::Policy));
    }

    #[test]
    fn usage_counts_what_the_names_leave_out() {
        let usage = Usage {
            sandboxes: 12,
            names: vec!["a".into(); 10],
        };
        assert_eq!(usage.more(), 2);
        assert_eq!(Usage::default().more(), 0);
    }
}
