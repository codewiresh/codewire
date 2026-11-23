//! A guest-carried daemon's egress self-check, as it records its host key
//! (#5602). In a `standard` Pod the daemon runs in the VM, so the egress
//! stream's lockdown check never sees it. Until an orchestration-side check
//! exists, the daemon's own probes from the workload's network are the floor:
//! each must have found no way out before its Pod's key, and so its
//! `access_ready`, is recorded.

use std::net::SocketAddrV4;

use serde_json::Value;

use codewire_daemon_proto::{POD_RUNTIME_EGRESS_MODE_BROKER, POD_RUNTIME_EGRESS_MODE_ENV};

use super::service::BindError;
use crate::runtime::MemberFacts;
use crate::sandbox::template::RUNTIME_CLASS_STANDARD;

/// The probes a passing check holds, each exactly once.
pub(crate) const PROBES: [&str; 3] = ["direct_dial", "public_dns", "cluster_dns"];
pub(crate) const MAX_PROBES: usize = 8;
pub(crate) const MAX_NAME_BYTES: usize = 32;
pub(crate) const MAX_TARGET_BYTES: usize = 64;

/// One probe as the daemon reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Probe<'a> {
    pub name: &'a str,
    pub target: &'a str,
    pub refused: bool,
}

/// Whether `member` must carry a passing check: a `standard` Pod whose guest
/// carries its own network session. Both come from the Pod's own spec as the
/// API server returned it, never from the request: its runtime class, and its
/// `workspace` container's literal [`POD_RUNTIME_EGRESS_MODE_ENV`]. Only
/// `broker` waives the check, since broker mode's stream is checked by
/// cw-egress's lockdown check (#5800) as on Kata; any other value, none, one
/// from a source, or more than one entry needs it. A Pod read without its spec can't show either, so
/// it is refused rather than taken for one that needs no check.
pub(crate) fn needs_self_check(member: &MemberFacts) -> Result<bool, BindError> {
    if !member.has_spec {
        return Err(BindError::FailedPrecondition);
    }
    if member
        .spec_json
        .get("runtimeClassName")
        .and_then(Value::as_str)
        != Some(RUNTIME_CLASS_STANDARD)
    {
        return Ok(false);
    }
    // A container gets the last of duplicate entries, so only one entry can
    // say which mode runs; admission refuses duplicates, but this does not
    // rest on it.
    let modes: Vec<_> = member
        .containers
        .iter()
        .filter(|container| container.name == "workspace")
        .flat_map(|container| &container.env)
        .filter(|variable| variable.name == POD_RUNTIME_EGRESS_MODE_ENV)
        .collect();
    let broker = matches!(modes.as_slice(), [mode]
        if !mode.from_source && mode.value.as_deref() == Some(POD_RUNTIME_EGRESS_MODE_BROKER));
    Ok(!broker)
}

/// Whether a Pod may record its host key with `check`. A Pod that
/// [`needs_self_check`] needs a passing one: without it, or with any probe
/// that found a way out, its key is refused. Any other Pod's daemon never
/// runs one, so a check from it is refused as malformed. A check out of its
/// bounds is refused before it is read.
pub(crate) fn admit(required: bool, check: Option<&[Probe<'_>]>) -> Result<(), BindError> {
    let Some(probes) = check else {
        return if required {
            Err(BindError::FailedPrecondition)
        } else {
            Ok(())
        };
    };
    if !required {
        return Err(BindError::InvalidArgument);
    }
    if probes.len() > MAX_PROBES
        || probes.iter().any(|probe| {
            probe.name.len() > MAX_NAME_BYTES
                || probe.target.len() > MAX_TARGET_BYTES
                || probe.target.parse::<SocketAddrV4>().is_err()
        })
    {
        return Err(BindError::InvalidArgument);
    }
    let exact = probes.len() == PROBES.len()
        && PROBES
            .iter()
            .all(|name| probes.iter().filter(|probe| probe.name == *name).count() == 1);
    if exact && probes.iter().all(|probe| probe.refused) {
        Ok(())
    } else {
        Err(BindError::FailedPrecondition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> Vec<Probe<'static>> {
        vec![
            Probe {
                name: "direct_dial",
                target: "1.1.1.1:443",
                refused: true,
            },
            Probe {
                name: "public_dns",
                target: "8.8.8.8:53",
                refused: true,
            },
            Probe {
                name: "cluster_dns",
                target: "10.96.0.10:53",
                refused: true,
            },
        ]
    }

    #[test]
    fn a_standard_pod_records_its_key_only_with_a_passing_check() {
        assert_eq!(admit(true, Some(&passing())), Ok(()));
        assert_eq!(admit(true, None), Err(BindError::FailedPrecondition));
        for index in 0..PROBES.len() {
            let mut open = passing();
            open[index].refused = false;
            assert_eq!(
                admit(true, Some(&open)),
                Err(BindError::FailedPrecondition),
                "{index}"
            );
        }
    }

    #[test]
    fn a_check_without_exactly_its_three_probes_is_refused() {
        let mut missing = passing();
        missing.pop();
        let mut repeated = passing();
        repeated[2].name = "public_dns";
        let mut renamed = passing();
        renamed[0].name = "tcp_dial";
        let mut extra = passing();
        extra.push(Probe {
            name: "udp_dial",
            target: "1.1.1.1:443",
            refused: true,
        });
        for (case, probes) in [
            ("missing", missing),
            ("repeated", repeated),
            ("renamed", renamed),
            ("extra", extra),
            ("empty", Vec::new()),
        ] {
            assert_eq!(
                admit(true, Some(&probes)),
                Err(BindError::FailedPrecondition),
                "{case}"
            );
        }
    }

    #[test]
    fn a_check_out_of_its_bounds_is_malformed() {
        let long_name = "n".repeat(MAX_NAME_BYTES + 1);
        let mut named = passing();
        named[0].name = &long_name;
        let mut named_target = passing();
        named_target[1].target = "dns.example:53";
        let mut ipv6 = passing();
        ipv6[1].target = "[2001:db8::1]:53";
        let mut no_port = passing();
        no_port[2].target = "10.96.0.10";
        let many: Vec<_> = (0..=MAX_PROBES).flat_map(|_| passing()).collect();
        for (case, probes) in [
            ("name", named),
            ("a name for a target", named_target),
            ("IPv6", ipv6),
            ("no port", no_port),
            ("too many", many),
        ] {
            assert_eq!(
                admit(true, Some(&probes)),
                Err(BindError::InvalidArgument),
                "{case}"
            );
        }
    }

    #[test]
    fn any_other_pod_records_its_key_without_a_check_and_never_with_one() {
        assert_eq!(admit(false, None), Ok(()));
        assert_eq!(
            admit(false, Some(&passing())),
            Err(BindError::InvalidArgument)
        );
        assert_eq!(admit(false, Some(&[])), Err(BindError::InvalidArgument));
    }

    #[test]
    fn only_a_broker_mode_standard_pod_or_another_class_goes_without_a_check() {
        use k8s_openapi::api::core::v1::{Container, EnvVar, EnvVarSource, Pod, PodSpec};

        let facts = |spec: Option<PodSpec>| {
            crate::runtime::kubernetes::observation::member_facts(&Pod {
                spec,
                ..Default::default()
            })
            .unwrap()
        };
        let pod = |class: Option<&str>, container: &str, mode: Option<EnvVar>| PodSpec {
            runtime_class_name: class.map(Into::into),
            containers: vec![Container {
                name: container.into(),
                env: mode.map(|mode| vec![mode]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mode = |value: &str| {
            Some(EnvVar {
                name: "CODEWIRE_VM_EGRESS_MODE".into(),
                value: Some(value.into()),
                ..Default::default()
            })
        };
        let needs = |spec| needs_self_check(&facts(Some(spec)));
        assert_eq!(
            needs_self_check(&facts(None)),
            Err(BindError::FailedPrecondition)
        );
        for (case, spec, needed) in [
            ("no class", pod(None, "workspace", None), false),
            (
                "commodity",
                pod(Some("commodity"), "workspace", None),
                false,
            ),
            (
                "commodity, broker",
                pod(Some("commodity"), "workspace", mode("broker")),
                false,
            ),
            (
                "standard, broker",
                pod(Some("standard"), "workspace", mode("broker")),
                false,
            ),
            (
                "standard, guest-carried",
                pod(Some("standard"), "workspace", mode("guest-carried")),
                true,
            ),
            (
                "standard, no mode",
                pod(Some("standard"), "workspace", None),
                true,
            ),
            (
                "standard, another mode",
                pod(Some("standard"), "workspace", mode("open")),
                true,
            ),
            (
                "standard, broker on another container",
                pod(Some("standard"), "sidecar", mode("broker")),
                true,
            ),
            (
                "standard, broker from a source",
                pod(
                    Some("standard"),
                    "workspace",
                    Some(EnvVar {
                        name: "CODEWIRE_VM_EGRESS_MODE".into(),
                        value_from: Some(EnvVarSource::default()),
                        ..Default::default()
                    }),
                ),
                true,
            ),
        ] {
            assert_eq!(needs(spec), Ok(needed), "{case}");
        }
        // Duplicates: the container would run the last one, so neither order
        // waives the check, nor do two brokers.
        for values in [
            ["broker", "guest-carried"],
            ["guest-carried", "broker"],
            ["broker", "broker"],
        ] {
            let mut spec = pod(Some("standard"), "workspace", None);
            spec.containers[0].env = Some(
                values
                    .iter()
                    .map(|value| EnvVar {
                        name: "CODEWIRE_VM_EGRESS_MODE".into(),
                        value: Some((*value).into()),
                        ..Default::default()
                    })
                    .collect(),
            );
            assert_eq!(needs(spec), Ok(true), "{values:?}");
        }
    }
}
