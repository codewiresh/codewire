//! Ensuring an environment generation's credential broker with the
//! authority, carrying the boot's secrets from its runner (#3999).

use codewire_local_credentials::EnvironmentBrokerRuntime as AuthorityBrokerRuntime;
use codewire_local_credentials::{AuthorityFeature, LocalCredentialControlClient};

use super::{CredentialBrokerEnsureRequest, SupervisorError, credential_control_error};
use crate::supervisor_config::OUTDATED_CREDENTIAL_SERVICE;

/// Whether an authority at `authority_protocol` may be asked for a broker
/// under this answer (#4926). One from before the rule ignores the answer
/// and serves GitHub, which is only right when the policy allows GitHub.
fn authority_applies_network_policy(authority_protocol: u32, allows_github: bool) -> bool {
    allows_github || AuthorityFeature::NetworkPolicyGithub.served_by(authority_protocol)
}

/// What a user reads when the running credential authority cannot apply a
/// network policy to the GitHub connection (#4926).
fn authority_predates_network_policy_github() -> String {
    format!(
        "this environment's network policy does not allow GitHub, which would be used anyway: {OUTDATED_CREDENTIAL_SERVICE}, or select a network policy that allows github.com and api.github.com"
    )
}

/// What a user reads when the running credential authority would forward an
/// intercepting boot's requests past its network policy (#5555).
fn authority_predates_bound_host_policy() -> String {
    format!(
        "this environment's network policy does not allow every host Codewire intercepts, which would be reached anyway: {OUTDATED_CREDENTIAL_SERVICE}"
    )
}

pub(super) async fn ensure_credential_broker(
    mut request: CredentialBrokerEnsureRequest,
) -> Result<AuthorityBrokerRuntime, SupervisorError> {
    if !request.enabled {
        return Ok(AuthorityBrokerRuntime {
            environment_id: request.environment_id,
            environment_generation: request.environment_generation,
            running: false,
        });
    }
    let (boot_secrets, record) = super::boot_egress::broker_boot_secrets(
        &request.runner_socket,
        &request.environment_id,
        request.environment_generation,
    )
    .await?;
    bind_boot_record(&mut request, record);
    let mut client = LocalCredentialControlClient::connect(&request.authority)
        .await
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?;
    if !authority_applies_network_policy(
        client.info().protocol_version,
        request.network_policy_allows_github,
    ) {
        // An authority from before the rule would ignore the answer and
        // serve GitHub under this policy. It keeps serving the VMs that ran
        // across a cw update, so it cannot be replaced here; this
        // environment gets no credential broker from it instead.
        let _ = client
            .stop_environment_broker(&request.environment_id, None)
            .await;
        return Err(SupervisorError::NetworkPolicySelection(
            authority_predates_network_policy_github(),
        ));
    }
    if !authority_applies_bound_host_policy(
        client.info().protocol_version,
        !boot_secrets.is_empty(),
        &request.network_policy_allowed_hosts,
    ) {
        // The same as above: an older authority's broker would forward an
        // intercepted request past this policy, so it starts none.
        let _ = client
            .stop_environment_broker(&request.environment_id, None)
            .await;
        return Err(SupervisorError::NetworkPolicySelection(
            authority_predates_bound_host_policy(),
        ));
    }
    client
        .ensure_environment_broker(
            &request.environment_id,
            request.environment_generation,
            &request.environment_name,
            &request.runner_socket,
            codewire_local_credentials::EnvironmentBrokerSelection {
                local_profile: request.local_profile,
                projection: request.projection,
                platform: request.platform,
                network_policy_allows_github: request.network_policy_allows_github,
                network_policy_allowed_hosts: request.network_policy_allowed_hosts,
                boot_secrets,
            },
        )
        .await
        .map_err(credential_control_error)
}

/// The boot's record of its bound secrets (#4003), from its runner: what
/// its projection and its broker's leases are checked against, and each of
/// its hosts the policy allows by rule, where a request that carries none of
/// the environment's values is forwarded untouched. A local VM follows its
/// network policy there, as for every intercepted host; it is never refused
/// for carrying none.
fn bind_boot_record(
    request: &mut CredentialBrokerEnsureRequest,
    record: Option<Vec<codewire_access::FirstBindSecret>>,
) {
    let allows = |host: &str| {
        request
            .network_policy
            .allows_by_rule(
                host,
                codewire_egress_front_door_bridge::INTERCEPT_PORT,
                None,
            )
            .unwrap_or(false)
    };
    let allowed: Vec<String> = record
        .iter()
        .flatten()
        .flat_map(|secret| secret.hosts.iter())
        .filter(|host| allows(host))
        .cloned()
        .collect();
    request.network_policy_allowed_hosts.extend(allowed);
    if let Some(projection) = request.projection.as_mut() {
        projection.bound_secrets = record;
    }
}

/// The bound hosts `policy` allows by rule on 443: where a front-door request
/// carrying none of the environment's placeholders may be forwarded untouched
/// (#5555). A host the policy merely doesn't list is not allowed.
pub(super) fn allowed_bound_hosts(
    policy: &codewire_egress_policy::CompiledPolicy,
) -> std::collections::BTreeSet<String> {
    let allows = |host: &str| {
        policy
            .allows_by_rule(
                host,
                codewire_egress_front_door_bridge::INTERCEPT_PORT,
                None,
            )
            .unwrap_or(false)
    };
    let mut allowed: std::collections::BTreeSet<String> =
        codewire_egress_front_door_bridge::RouteTable::bindable_hosts()
            .into_iter()
            .filter(|host| allows(host))
            .collect();
    allowed.extend(
        routed_wildcards()
            .filter(|(_, suffix)| {
                // Routed names can't be listed ahead, so the question is whether a
                // rule covers every name under the suffix. A fresh random label each
                // time means a rule for one name, whichever, never answers yes.
                allows(&format!("{}.{suffix}", random_label()))
            })
            .map(|(wildcard, _)| wildcard),
    );
    allowed
}

/// Each routed suffix's `*.` entry, and the suffix.
fn routed_wildcards() -> impl Iterator<Item = (String, &'static str)> {
    codewire_access::ROUTED_SUFFIXES
        .into_iter()
        .map(|suffix| (format!("*.{suffix}"), suffix))
}

/// A DNS label no policy can name ahead: 32 random hex characters.
fn random_label() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let half = || {
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    };
    format!("cwprobe{:016x}{:016x}", half(), half())
}

/// Whether an authority at `authority_protocol` may start an intercepting
/// boot's broker under these answers (#5555). One from before the feature
/// forwards every front-door request carrying no placeholder, which is only
/// right when the policy allows every host the boot may bind and every name
/// under each routed suffix.
pub(super) fn authority_applies_bound_host_policy(
    authority_protocol: u32,
    intercepting: bool,
    allowed_hosts: &std::collections::BTreeSet<String>,
) -> bool {
    !intercepting
        || AuthorityFeature::NetworkPolicyHosts.served_by(authority_protocol)
        || (codewire_egress_front_door_bridge::RouteTable::bindable_hosts()
            .iter()
            .all(|host| allowed_hosts.contains(host))
            && routed_wildcards().all(|(wildcard, _)| allowed_hosts.contains(&wildcard)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #4926: an authority from before the rule keeps serving across a cw
    /// update and would ignore a "no". It is asked for a broker only when the
    /// policy allows GitHub anyway.
    #[test]
    fn an_authority_from_before_the_rule_is_not_asked_to_refuse_github() {
        let since = AuthorityFeature::NetworkPolicyGithub.since();
        assert!(authority_applies_network_policy(since, false));
        assert!(authority_applies_network_policy(since, true));
        assert!(authority_applies_network_policy(since - 1, true));
        assert!(!authority_applies_network_policy(since - 1, false));
    }

    /// Parity's one difference (#4003): the hosts of the boot's recorded
    /// bound secrets that its network policy allows by rule join the hosts
    /// where a request carrying no Codewire value is forwarded; one the
    /// policy doesn't allow is not. The record reaches the projection the
    /// broker serves, and a boot that recorded nothing stays unrecorded.
    #[test]
    fn a_recorded_bound_host_follows_the_network_policy() {
        use crate::network_policy_store::{PolicyBase, PolicySelection, PolicySelector};
        use codewire_egress_policy::reference::PolicyName;
        use codewire_egress_policy::typed::{AllowRule, AllowTarget};

        let environment = super::super::tests::project_environment_with_access();
        let (_parent, core) = super::super::tests::test_supervisor_core(environment.clone());
        let name = PolicyName::parse("fancy-only").unwrap();
        let rule = AllowRule::new(AllowTarget::parse("api.fancy.com").unwrap(), [443]).unwrap();
        core.network_policies
            .create(&name, &PolicyBase::Locked, vec![rule])
            .unwrap();
        core.network_policies
            .select(
                environment.id,
                Some(&PolicySelection::Stored(PolicySelector::Name(name))),
            )
            .unwrap();
        let record = vec![codewire_access::FirstBindSecret {
            path: "local:user:0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
            key: "FANCY_TOKEN".into(),
            binding_id: "00000000-0000-0000-0000-000000000007".into(),
            binding_generation: 1,
            prefix: None,
            hosts: vec!["api.fancy.com".into(), "api.denied.com".into()],
        }];
        let mut request = core
            .credential_broker_request_for_environment(&environment, 1)
            .unwrap();
        assert!(request.network_policy_allowed_hosts.is_empty());
        bind_boot_record(&mut request, Some(record.clone()));
        assert_eq!(
            request.network_policy_allowed_hosts,
            std::collections::BTreeSet::from(["api.fancy.com".to_owned()])
        );
        let projection = request.projection.as_ref().expect("a local projection");
        assert_eq!(projection.bound_secrets.as_ref(), Some(&record));

        let mut unrecorded = core
            .credential_broker_request_for_environment(&environment, 1)
            .unwrap();
        bind_boot_record(&mut unrecorded, None);
        assert!(unrecorded.network_policy_allowed_hosts.is_empty());
        assert_eq!(
            unrecorded
                .projection
                .map(|projection| projection.bound_secrets),
            Some(None)
        );
    }
}
