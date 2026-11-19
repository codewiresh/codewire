//! Which hosts a bound Pod's broker hands to its own front door (#4001;
//! `SPEC.md`, cw-egress's front door), read from the Pod's assignment.
//!
//! cw-egress's front door serves only exact names on 443. With interception
//! on, a bound host's requests carry the Sandbox's placeholders, so they are
//! never dialled as ordinary egress (#5159):
//!
//! - every binding exact and servable: the Pod runs a front door, and its
//!   broker hands each bound host's dial to it;
//! - every binding an exact name, but the set unservable (another port, a
//!   name not in canonical form, an environment or generation the front door
//!   cannot be keyed by): no front door, and the broker refuses each binding's
//!   dials, on its own port, as `intercept_unavailable`; other egress carries
//!   on;
//! - a suffix, a host that is not an exact name, a port that is not one, or
//!   more bindings than a set holds: no broker set can match every dial they
//!   name, so the Pod gets no pair at all.

use codewire_egress_front_door_bridge::INTERCEPT_PORT;
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet, MAX_INTERCEPT_BINDINGS};
use codewire_proto::codewire::internal::v1::BoundAssignment;
use uuid::Uuid;

/// What a Pod's front door is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontDoorSpec {
    pub environment_id: Uuid,
    pub generation: u64,
    /// Exact names on 443; never empty.
    pub intercepts: InterceptSet,
}

/// A bound assignment's interception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Interception {
    /// Off, or on with nothing bound: nothing is intercepted.
    Off,
    On(FrontDoorSpec),
    /// On and unservable: no front door, and the broker refuses every dial
    /// to `hosts`, each an exact name on its bound port.
    RefuseHosts {
        hosts: InterceptSet,
        why: InterceptionRefusal,
    },
    /// On, with bindings no broker set can refuse: no pair starts.
    FailClosed(InterceptionRefusal),
}

/// What a started pair intercepts. A [`Interception::FailClosed`] Pod has
/// no pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairIntercepts {
    Off,
    FrontDoor(FrontDoorSpec),
    /// No front door; the broker refuses these hosts' dials.
    Refuse(InterceptSet),
}

impl Interception {
    /// The pair's intercepts, or why the Pod gets no pair.
    pub fn pair(self) -> Result<PairIntercepts, InterceptionRefusal> {
        match self {
            Self::Off => Ok(PairIntercepts::Off),
            Self::On(spec) => Ok(PairIntercepts::FrontDoor(spec)),
            Self::RefuseHosts { hosts, .. } => Ok(PairIntercepts::Refuse(hosts)),
            Self::FailClosed(why) => Err(why),
        }
    }
}

/// Why a set is not served. A fixed code, so it can be logged: never the
/// host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionRefusal {
    /// A suffix binding: no exact set covers its subdomains.
    Suffix,
    /// A host that is not an exact name the policy crate accepts.
    Binding,
    /// More bindings than a set holds.
    TooMany,
    /// A port other than 443: the front door serves only TLS on 443, so the
    /// broker refuses that port. One that is not a port fails the Pod closed.
    Port,
    /// A name not in canonical form.
    Form,
    /// The environment id is not a canonical UUID, or the generation is
    /// negative: the front door's bridge is keyed by both.
    Identity,
}

impl InterceptionRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Suffix => "suffix",
            Self::Binding => "binding",
            Self::TooMany => "too_many",
            Self::Port => "port",
            Self::Form => "form",
            Self::Identity => "identity",
        }
    }
}

/// The interception `bound` asks for.
pub fn interception(bound: &BoundAssignment) -> Interception {
    if !bound.interception {
        return Interception::Off;
    }
    if bound.interception_bindings.len() > MAX_INTERCEPT_BINDINGS {
        return Interception::FailClosed(InterceptionRefusal::TooMany);
    }
    let mut unservable = None;
    let mut hosts = Vec::with_capacity(bound.interception_bindings.len());
    for binding in &bound.interception_bindings {
        if binding.suffix {
            return Interception::FailClosed(InterceptionRefusal::Suffix);
        }
        // Refused on its own port: the broker matches host and port exactly.
        let Some(port) = u16::try_from(binding.port).ok().filter(|port| *port != 0) else {
            return Interception::FailClosed(InterceptionRefusal::Port);
        };
        let Ok(exact) = InterceptBinding::new(&binding.host, port) else {
            return Interception::FailClosed(InterceptionRefusal::Binding);
        };
        // Only the canonical form travels; anything else was not
        // orchestration's, though its canonical name still matches its dials.
        if exact.hostname() != binding.host {
            unservable.get_or_insert(InterceptionRefusal::Form);
        }
        if port != INTERCEPT_PORT {
            unservable.get_or_insert(InterceptionRefusal::Port);
        }
        hosts.push(exact);
    }
    let Ok(hosts) = InterceptSet::new(hosts) else {
        return Interception::FailClosed(InterceptionRefusal::TooMany);
    };
    if hosts.is_empty() {
        return Interception::Off;
    }
    match (unservable, identity(bound)) {
        (None, Ok((environment_id, generation))) => Interception::On(FrontDoorSpec {
            environment_id,
            generation,
            intercepts: hosts,
        }),
        (Some(why), _) | (None, Err(why)) => Interception::RefuseHosts { hosts, why },
    }
}

/// The environment and generation a front door's bridge is keyed by.
fn identity(bound: &BoundAssignment) -> Result<(Uuid, u64), InterceptionRefusal> {
    let environment_id = Uuid::parse_str(&bound.environment_id)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == bound.environment_id)
        .ok_or(InterceptionRefusal::Identity)?;
    let generation =
        u64::try_from(bound.operation_generation).map_err(|_| InterceptionRefusal::Identity)?;
    Ok((environment_id, generation))
}

#[cfg(test)]
mod tests {
    use codewire_proto::codewire::internal::v1::InterceptionBinding;

    use super::*;

    const ENVIRONMENT: &str = "6f1c2a0e-8b4d-4e2a-9c3f-1d2e3f4a5b6c";

    fn binding(host: &str, port: u32, suffix: bool) -> InterceptionBinding {
        InterceptionBinding {
            host: host.into(),
            port,
            suffix,
            ..Default::default()
        }
    }

    fn bound(interception: bool, bindings: Vec<InterceptionBinding>) -> BoundAssignment {
        BoundAssignment {
            environment_id: ENVIRONMENT.into(),
            operation_generation: 3,
            interception,
            interception_bindings: bindings,
            ..Default::default()
        }
    }

    fn exact_hosts() -> Vec<InterceptionBinding> {
        vec![
            binding("api.openai.com", 443, false),
            binding("api.anthropic.com", 443, false),
        ]
    }

    fn hosts(names: &[&str]) -> InterceptSet {
        InterceptSet::new(
            names
                .iter()
                .map(|name| InterceptBinding::new(name, 443).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn interception_off_intercepts_nothing_whatever_is_bound() {
        assert_eq!(
            interception(&bound(false, exact_hosts())),
            Interception::Off
        );
        assert_eq!(
            interception(&bound(false, vec![binding("openai.com", 443, true)])),
            Interception::Off
        );
        // On with nothing bound is the same as off.
        assert_eq!(interception(&bound(true, Vec::new())), Interception::Off);
    }

    #[test]
    fn exact_hosts_on_443_are_the_front_doors_set() {
        let Interception::On(spec) = interception(&bound(true, exact_hosts())) else {
            panic!("a front door");
        };
        assert_eq!(spec.environment_id.to_string(), ENVIRONMENT);
        assert_eq!(spec.generation, 3);
        assert_eq!(
            spec.intercepts,
            hosts(&["api.anthropic.com", "api.openai.com"])
        );
    }

    /// Exact names the front door cannot serve are still refused, every one
    /// of them on 443, never dialled as ordinary egress.
    #[test]
    fn an_unservable_set_of_exact_names_is_refused_whole() {
        let mut bindings = exact_hosts();
        bindings.push(binding("api.example.com", 8443, false));
        let mut refused = vec![InterceptBinding::new("api.example.com", 8443).unwrap()];
        refused.extend(
            hosts(&["api.anthropic.com", "api.openai.com"])
                .bindings()
                .iter()
                .cloned(),
        );
        assert_eq!(
            interception(&bound(true, bindings)),
            Interception::RefuseHosts {
                hosts: InterceptSet::new(refused).unwrap(),
                why: InterceptionRefusal::Port
            }
        );
        let mut bindings = exact_hosts();
        bindings.push(binding("API.example.com", 443, false));
        assert_eq!(
            interception(&bound(true, bindings)),
            Interception::RefuseHosts {
                hosts: hosts(&["api.anthropic.com", "api.example.com", "api.openai.com"]),
                why: InterceptionRefusal::Form
            }
        );
        for (environment_id, generation) in [
            ("env", 3),
            ("6F1C2A0E-8B4D-4E2A-9C3F-1D2E3F4A5B6C", 3),
            ("00000000-0000-0000-0000-000000000000", 3),
            (ENVIRONMENT, -1),
        ] {
            let mut assignment = bound(true, exact_hosts());
            assignment.environment_id = environment_id.into();
            assignment.operation_generation = generation;
            assert_eq!(
                interception(&assignment),
                Interception::RefuseHosts {
                    hosts: hosts(&["api.anthropic.com", "api.openai.com"]),
                    why: InterceptionRefusal::Identity
                },
                "{environment_id} {generation}"
            );
        }
    }

    /// A binding no exact set can match fails the Pod closed: its dials
    /// could not all be refused.
    #[test]
    fn a_binding_no_exact_set_can_refuse_fails_closed() {
        for (refused, why) in [
            (
                binding("openai.com", 443, true),
                InterceptionRefusal::Suffix,
            ),
            (
                binding("*.example.com", 443, false),
                InterceptionRefusal::Binding,
            ),
            (binding("", 443, false), InterceptionRefusal::Binding),
            (
                binding("localhost", 443, false),
                InterceptionRefusal::Binding,
            ),
            (
                binding("api.example.com", 70_000, false),
                InterceptionRefusal::Port,
            ),
            (
                binding("api.example.com", 0, false),
                InterceptionRefusal::Port,
            ),
        ] {
            let mut bindings = exact_hosts();
            bindings.push(refused.clone());
            let assigned = interception(&bound(true, bindings));
            assert_eq!(assigned, Interception::FailClosed(why), "{refused:?}");
            assert_eq!(assigned.pair(), Err(why));
        }
        let many = (0..=MAX_INTERCEPT_BINDINGS)
            .map(|index| binding(&format!("h{index}.example.com"), 443, false))
            .collect();
        assert_eq!(
            interception(&bound(true, many)),
            Interception::FailClosed(InterceptionRefusal::TooMany)
        );
    }
}
