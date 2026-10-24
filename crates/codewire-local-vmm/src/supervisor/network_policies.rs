//! The supervisor's network policy RPCs (#2537, protocol 16): the host's
//! policy store behind the owner-only socket. Every request is checked into
//! the typed rule subset before the store sees it, and every refusal names
//! what to change.

use codewire_egress_policy::reference::{PolicyId, PolicyName, PolicyReferenceError};
use codewire_egress_policy::typed::{AllowRule, AllowTarget};
use tonic::Status;

use crate::control::v1;
use crate::network_policy_store::{
    NetworkPolicyStore, NetworkPolicyStoreError, PolicyBase, PolicySelector, StoredPolicy,
};

/// At most this many rules, or targets to remove, in one request.
const MAX_REQUEST_RULES: usize = codewire_egress_policy::typed::MAX_ALLOW_RULES;

pub(super) fn create(
    store: &NetworkPolicyStore,
    request: v1::CreateNetworkPolicyRequest,
) -> Result<v1::NetworkPolicy, Status> {
    let name = policy_name(&request.name)?;
    let base = match request.from {
        None => PolicyBase::Locked,
        Some(selector) => PolicyBase::Policy(selector_from(Some(selector))?),
    };
    let rules = rules_from(&request.allow)?;
    store
        .create(&name, &base, rules)
        .map(|stored| policy_proto(&stored))
        .map_err(status)
}

pub(super) fn list(store: &NetworkPolicyStore) -> Result<v1::ListNetworkPoliciesResponse, Status> {
    Ok(v1::ListNetworkPoliciesResponse {
        policies: store
            .list()
            .map_err(status)?
            .iter()
            .map(policy_proto)
            .collect(),
    })
}

pub(super) fn get(
    store: &NetworkPolicyStore,
    request: v1::GetNetworkPolicyRequest,
) -> Result<v1::NetworkPolicy, Status> {
    let selector = selector_from(request.policy)?;
    let revision = (request.revision != 0).then_some(request.revision);
    store
        .get(&selector, revision)
        .map(|stored| policy_proto(&stored))
        .map_err(status)
}

pub(super) fn update(
    store: &NetworkPolicyStore,
    request: v1::UpdateNetworkPolicyRequest,
) -> Result<v1::NetworkPolicy, Status> {
    let selector = selector_from(request.policy)?;
    let add = rules_from(&request.allow)?;
    if request.remove.len() > MAX_REQUEST_RULES {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_REQUEST_RULES} targets can be removed at once"
        )));
    }
    let remove = request
        .remove
        .iter()
        .map(|target| target_from(target))
        .collect::<Result<Vec<_>, _>>()?;
    if add.is_empty() && remove.is_empty() {
        return Err(Status::invalid_argument(
            "name at least one target to allow or remove",
        ));
    }
    store
        .update(&selector, add, &remove)
        .map(|stored| policy_proto(&stored))
        .map_err(status)
}

/// Delete a policy unless `selected_by` names an environment that selects it.
pub(super) fn delete(
    store: &NetworkPolicyStore,
    selector: v1::NetworkPolicySelector,
    selected_by: impl FnOnce(&PolicyId) -> Vec<String>,
) -> Result<v1::NetworkPolicy, Status> {
    let selector = selector_from(Some(selector))?;
    store
        .delete(&selector, selected_by)
        .map(|stored| policy_proto(&stored))
        .map_err(status)
}

fn policy_name(value: &str) -> Result<PolicyName, Status> {
    PolicyName::parse(value).map_err(|error| match error {
        PolicyReferenceError::ReservedName => Status::invalid_argument(format!(
            "{value} is a built-in policy; choose another name"
        )),
        _ => Status::invalid_argument(
            "a policy name is lowercase letters and digits, with -, _ or . inside, at most 64 bytes",
        ),
    })
}

fn selector_from(selector: Option<v1::NetworkPolicySelector>) -> Result<PolicySelector, Status> {
    match selector.and_then(|selector| selector.selector) {
        Some(v1::network_policy_selector::Selector::Name(name)) => {
            Ok(PolicySelector::Name(policy_name(&name)?))
        }
        Some(v1::network_policy_selector::Selector::Id(id)) => {
            Ok(PolicySelector::Id(PolicyId::parse(&id).map_err(|_| {
                Status::invalid_argument("a policy id is a canonical UUID")
            })?))
        }
        None => Err(Status::invalid_argument("name the network policy")),
    }
}

fn target_from(value: &str) -> Result<AllowTarget, Status> {
    AllowTarget::parse(value).map_err(|error| Status::invalid_argument(error.to_string()))
}

fn rules_from(rules: &[v1::NetworkPolicyRule]) -> Result<Vec<AllowRule>, Status> {
    if rules.len() > MAX_REQUEST_RULES {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_REQUEST_RULES} rules can be added at once"
        )));
    }
    rules
        .iter()
        .map(|rule| {
            let ports = rule
                .ports
                .iter()
                .map(|port| {
                    u16::try_from(*port)
                        .map_err(|_| Status::invalid_argument(format!("{port} is not a TCP port")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            AllowRule::new(target_from(&rule.target)?, ports)
                .map_err(|error| Status::invalid_argument(error.to_string()))
        })
        .collect()
}

pub(super) fn policy_proto(stored: &StoredPolicy) -> v1::NetworkPolicy {
    v1::NetworkPolicy {
        id: stored.id.to_string(),
        name: stored.name.to_string(),
        revision: stored.revision,
        current_revision: stored.current_revision,
        rules: stored
            .policy
            .rules()
            .iter()
            .map(|rule| v1::NetworkPolicyRule {
                target: rule.target().to_string(),
                ports: rule.ports().iter().map(|port| u32::from(*port)).collect(),
            })
            .collect(),
        digest: stored.digest.to_hex(),
        created_unix_ms: stored.created_unix_ms,
    }
}

fn status(error: NetworkPolicyStoreError) -> Status {
    match error {
        NetworkPolicyStoreError::NotFound(_) | NetworkPolicyStoreError::RevisionNotFound { .. } => {
            Status::not_found(error.to_string())
        }
        NetworkPolicyStoreError::AlreadyExists(_) => Status::already_exists(error.to_string()),
        NetworkPolicyStoreError::InUse { .. }
        | NetworkPolicyStoreError::Unchanged(_)
        | NetworkPolicyStoreError::TooManyPolicies
        | NetworkPolicyStoreError::TooManyRevisions(_) => {
            Status::failed_precondition(error.to_string())
        }
        NetworkPolicyStoreError::Rule(_) => Status::invalid_argument(error.to_string()),
        NetworkPolicyStoreError::InvalidDocument
        | NetworkPolicyStoreError::InvalidDatabase
        | NetworkPolicyStoreError::DatabaseIdentityChanged
        | NetworkPolicyStoreError::Path(_)
        | NetworkPolicyStoreError::Database(_) => {
            Status::internal("the local network policy store could not be read")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(target: &str, ports: &[u32]) -> v1::NetworkPolicyRule {
        v1::NetworkPolicyRule {
            target: target.to_owned(),
            ports: ports.to_vec(),
        }
    }

    fn by_name(name: &str) -> Option<v1::NetworkPolicySelector> {
        Some(v1::NetworkPolicySelector {
            selector: Some(v1::network_policy_selector::Selector::Name(name.to_owned())),
        })
    }

    #[test]
    fn requests_are_checked_into_the_typed_subset_with_actionable_errors() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let created = create(
            &store,
            v1::CreateNetworkPolicyRequest {
                name: "work".to_owned(),
                from: None,
                allow: vec![rule("GitHub.com", &[443, 22])],
            },
        )
        .unwrap();
        assert_eq!(created.revision, 1);
        assert_eq!(created.rules, [rule("github.com", &[22, 443])]);
        assert_eq!(created.digest.len(), 64);

        for (request, code, contains) in [
            ("open", tonic::Code::InvalidArgument, "built-in"),
            ("Work", tonic::Code::InvalidArgument, "lowercase"),
            ("work", tonic::Code::AlreadyExists, "already exists"),
        ] {
            let error = create(
                &store,
                v1::CreateNetworkPolicyRequest {
                    name: request.to_owned(),
                    from: None,
                    allow: vec![],
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), code, "{request}");
            assert!(
                error.message().contains(contains),
                "{request}: {}",
                error.message()
            );
        }
        for (target, ports) in [
            ("10.0.0.0/8", vec![443]),
            ("metadata.google.internal", vec![443]),
            ("*", vec![443]),
            ("github.com", vec![]),
            ("github.com", vec![70_000]),
            ("https://github.com/x", vec![443]),
        ] {
            let error = update(
                &store,
                v1::UpdateNetworkPolicyRequest {
                    policy: by_name("work"),
                    allow: vec![rule(target, &ports)],
                    remove: vec![],
                },
            )
            .unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::InvalidArgument,
                "{target} {ports:?}"
            );
        }
        let error = update(
            &store,
            v1::UpdateNetworkPolicyRequest {
                policy: by_name("work"),
                allow: vec![],
                remove: vec!["pypi.org".to_owned()],
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("no rule for pypi.org"));
        assert_eq!(
            get(
                &store,
                v1::GetNetworkPolicyRequest {
                    policy: by_name("work"),
                    revision: 0
                }
            )
            .unwrap()
            .revision,
            1,
            "a refused edit adds no revision"
        );
    }

    #[test]
    fn deletion_names_the_environments_that_select_the_policy() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        create(
            &store,
            v1::CreateNetworkPolicyRequest {
                name: "work".to_owned(),
                from: None,
                allow: vec![],
            },
        )
        .unwrap();
        let selector = by_name("work").unwrap();
        let error = delete(&store, selector.clone(), |_| vec!["team".to_owned()]).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("selected by team"));
        assert_eq!(
            delete(&store, selector, |_| Vec::new()).unwrap().name,
            "work"
        );
        assert!(list(&store).unwrap().policies.is_empty());
    }
}
