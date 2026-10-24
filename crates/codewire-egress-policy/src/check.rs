//! What a policy decides for one destination, without any I/O (#2537
//! `cw policy check`). It runs the same [`CompiledPolicy`] the brokers do and
//! names a refusal with the same [`RefusalReason`] their counters use, so the
//! answer is the same on every placement.
//!
//! A name is judged as the broker judges a guest's lookup and dial: its DNS
//! question first, then a TCP dial on the port to one of its answers. Which
//! addresses a name answers is not known offline, so the dial is decided only
//! by rules that match every address. A rule that also needs the answer
//! inside a network is reported apart, in [`PolicyCheck::allowed_within`] and
//! [`PolicyCheck::refused_within`]; the broker still refuses an answer in a
//! protected range.

use std::net::IpAddr;

use crate::hostname::{canonical_hostname, protected_name};
use crate::lease::RefusalReason;
use crate::{
    CompiledPolicy, DecisionReason, EgressRequest, PolicyAction, PolicyError, RouteClass,
    classify_address,
};

/// One destination to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckDestination {
    Name(String),
    Address(IpAddr),
}

impl CheckDestination {
    /// An IP address, or a DNS name in canonical form.
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(Self::Address(address));
        }
        canonical_hostname(value)
            .map(Self::Name)
            .map_err(|detail| PolicyError::InvalidRequest {
                field: "destination",
                detail,
            })
    }
}

/// The decision for one destination and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCheck {
    /// `None` when allowed; otherwise the refusal's reason.
    pub refusal: Option<RefusalReason>,
    /// The rule that allows it.
    pub rule_id: Option<String>,
    /// For a name: networks that allow the dial when the name answers an
    /// address inside one, though the name alone does not.
    pub allowed_within: Vec<String>,
    /// For an allowed name: networks that refuse the dial when the name
    /// answers an address inside one.
    pub refused_within: Vec<String>,
}

impl PolicyCheck {
    pub fn is_allowed(&self) -> bool {
        self.refusal.is_none()
    }

    fn refused(reason: RefusalReason) -> Self {
        Self {
            refusal: Some(reason),
            rule_id: None,
            allowed_within: Vec::new(),
            refused_within: Vec::new(),
        }
    }

    fn allowed(rule_id: Option<String>) -> Self {
        Self {
            refusal: None,
            rule_id,
            allowed_within: Vec::new(),
            refused_within: Vec::new(),
        }
    }
}

impl CompiledPolicy {
    /// What this policy decides for a dial to `destination` on TCP `port`.
    pub fn check(
        &self,
        destination: &CheckDestination,
        port: u16,
    ) -> Result<PolicyCheck, PolicyError> {
        let route_class = RouteClass::General;
        match destination {
            CheckDestination::Address(address) => {
                if classify_address(*address).is_some() {
                    return Ok(PolicyCheck::refused(RefusalReason::ProtectedAddress));
                }
                let request = EgressRequest::tcp(*address, port, None, route_class)?;
                let decision = self.evaluate(&request);
                if decision.is_allowed() {
                    return Ok(PolicyCheck::allowed(decision.rule_id));
                }
                Ok(PolicyCheck::refused(
                    if self.allows_on_another_port(&request) {
                        RefusalReason::PortNotAllowed
                    } else {
                        RefusalReason::AddressNotAllowed
                    },
                ))
            }
            CheckDestination::Name(name) => {
                if protected_name(name).is_some() {
                    return Ok(PolicyCheck::refused(RefusalReason::ProtectedAnswersOnly));
                }
                let lookup = self.evaluate(&EgressRequest::dns_query(name, route_class)?);
                if !lookup.is_allowed() {
                    return Ok(PolicyCheck::refused(match lookup.reason {
                        DecisionReason::ProtectedName(_) | DecisionReason::ProtectedAddress(_) => {
                            RefusalReason::ProtectedAnswersOnly
                        }
                        _ => RefusalReason::NameNotAllowed,
                    }));
                }
                let dial = self.judge_named_dial(name, port, route_class)?;
                match dial.decided_by {
                    Some((PolicyAction::Allow, rule_id)) => Ok(PolicyCheck {
                        refused_within: dial.refused_within,
                        ..PolicyCheck::allowed(Some(rule_id))
                    }),
                    decided_by => Ok(PolicyCheck {
                        allowed_within: if decided_by.is_some() {
                            Vec::new()
                        } else {
                            dial.allowed_within
                        },
                        ..PolicyCheck::refused(if dial.allowed_on_another_port {
                            RefusalReason::PortNotAllowed
                        } else {
                            RefusalReason::NameNotAllowed
                        })
                    }),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BuiltinPolicy;
    use crate::typed::{AllowRule, AllowTarget, TypedPolicy};

    fn policy(rules: &[(&str, &[u16])]) -> CompiledPolicy {
        TypedPolicy::new(rules.iter().map(|(target, ports)| {
            AllowRule::new(AllowTarget::parse(target).unwrap(), ports.iter().copied()).unwrap()
        }))
        .unwrap()
        .compile()
    }

    fn check(policy: &CompiledPolicy, destination: &str, port: u16) -> Option<RefusalReason> {
        policy
            .check(&CheckDestination::parse(destination).unwrap(), port)
            .unwrap()
            .refusal
    }

    #[test]
    fn a_name_is_judged_by_its_lookup_then_its_dial_port() {
        let work = policy(&[
            ("github.com", &[22, 443]),
            ("*.npmjs.org", &[443]),
            ("185.199.108.0/22", &[443]),
        ]);
        assert_eq!(check(&work, "GitHub.com", 22), None);
        assert_eq!(check(&work, "github.com", 443), None);
        assert_eq!(
            check(&work, "github.com", 80),
            Some(RefusalReason::PortNotAllowed)
        );
        assert_eq!(check(&work, "registry.npmjs.org", 443), None);
        assert_eq!(
            check(&work, "npmjs.org", 443),
            Some(RefusalReason::NameNotAllowed),
            "a descendant pattern excludes the apex"
        );
        assert_eq!(
            check(&work, "example.com", 443),
            Some(RefusalReason::NameNotAllowed)
        );
        assert_eq!(
            check(&work, "metadata.google.internal", 80),
            Some(RefusalReason::ProtectedAnswersOnly)
        );
    }

    #[test]
    fn a_names_dial_is_decided_by_name_rules_and_cidr_rules_are_reported_apart() {
        // 8.0.0.0/8 holds every address a name's dial was once judged for; the
        // broker admits github.com:22 only when github.com answers inside it.
        let work = policy(&[("github.com", &[443]), ("8.0.0.0/8", &[22])]);
        let check = |destination: &str, port| {
            work.check(&CheckDestination::parse(destination).unwrap(), port)
                .unwrap()
        };
        let ssh = check("github.com", 22);
        assert_eq!(ssh.refusal, Some(RefusalReason::PortNotAllowed));
        assert_eq!(ssh.allowed_within, ["8.0.0.0/8"]);
        let https = check("github.com", 443);
        assert!(https.is_allowed());
        assert!(https.allowed_within.is_empty() && https.refused_within.is_empty());
        assert_eq!(
            check("8.8.8.8", 22).refusal,
            None,
            "the address itself is still judged by its CIDR rule"
        );
        let elsewhere = check("example.com", 22);
        assert_eq!(
            elsewhere.refusal,
            Some(RefusalReason::NameNotAllowed),
            "example.com has no lookup rule, so it never resolves"
        );
        assert!(elsewhere.allowed_within.is_empty());
    }

    #[test]
    fn an_address_is_judged_by_cidr_rules_and_the_protected_ranges() {
        let work = policy(&[("185.199.108.0/22", &[443])]);
        assert_eq!(check(&work, "185.199.108.153", 443), None);
        assert_eq!(
            check(&work, "185.199.108.153", 22),
            Some(RefusalReason::PortNotAllowed)
        );
        assert_eq!(
            check(&work, "8.8.8.8", 443),
            Some(RefusalReason::AddressNotAllowed)
        );
        for protected in ["10.0.0.1", "169.254.169.254", "127.0.0.1", "fc00::1"] {
            assert_eq!(
                check(&work, protected, 443),
                Some(RefusalReason::ProtectedAddress),
                "{protected}"
            );
        }
    }

    #[test]
    fn the_built_ins_answer_as_the_brokers_enforce_them() {
        let open = BuiltinPolicy::Open.compile();
        assert_eq!(check(&open, "example.com", 443), None);
        assert_eq!(check(&open, "example.com", 22), None);
        assert_eq!(check(&open, "8.8.8.8", 443), None);
        assert_eq!(
            check(&open, "example.com", 25),
            Some(RefusalReason::PortNotAllowed)
        );
        let locked = BuiltinPolicy::Locked.compile();
        assert_eq!(
            check(&locked, "example.com", 443),
            Some(RefusalReason::NameNotAllowed)
        );
        assert_eq!(
            check(&locked, "8.8.8.8", 443),
            Some(RefusalReason::AddressNotAllowed)
        );
    }
}
