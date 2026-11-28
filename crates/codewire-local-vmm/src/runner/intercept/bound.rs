//! A local VM boot's bound secrets at its runner (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door"): the
//! union of their hosts with the selected credentials', refused by name
//! when it doesn't hold, and the record on the runner's wire.

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::{
    BindingError, BoundHost, FirstBindSecret, MAX_BOUND_HOSTS_PER_ENVIRONMENT, PlatformBootBinding,
    PlatformBootRecord, PlatformBootSecret, ReservedHosts,
};
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};

use super::RunnerError;

/// Why a boot is refused for the bound secrets it recorded (#4003;
/// docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door"), by the
/// codes a hosted first bind uses. Each sentence names the host and the keys,
/// never a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BoundSecretsRefusal {
    /// A local store reserves the hosts a built-in credential names, and no
    /// boot intercepts a name the egress policy protects.
    #[error("{host}, which {key} is sent to, is a name Codewire never sends a secret to")]
    HostReserved { host: String, key: String },
    /// Two values name one host: two bound secrets, or a bound secret and a
    /// selected credential.
    #[error("{host} is named by both {first} and {second}; one host carries only one of them")]
    HostConflict {
        host: String,
        first: String,
        second: String,
    },
    #[error(
        "the bound secrets {} name {count} hosts; an environment carries at most {MAX_BOUND_HOSTS_PER_ENVIRONMENT}",
        .keys.join(", ")
    )]
    TooManyHosts { count: usize, keys: Vec<String> },
    /// The boot would bind a secret's host and can't intercept: it never
    /// falls back to projecting the value.
    #[error(
        "{key} is sent only to its hosts through this VM's front door, which this start can't run ({reason}); remove the egress-intercept file if it says off, or update the local credential service, then start it again"
    )]
    NotInterceptable { key: String, reason: &'static str },
    /// A local source's bound secret in a boot whose credentials come from
    /// the platform: its front door relays every request to the platform,
    /// which holds no grant for a local secret, so it would go unswapped.
    #[error(
        "{key} is a local secret sent only to its hosts, and this VM's credentials come from the platform, whose front door can't send a local secret; set {key} on the platform instead, or start this VM with a local credential profile"
    )]
    LocalOnPlatform { key: String },
}

impl BoundSecretsRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::HostReserved { .. } => "bound_host_reserved",
            Self::HostConflict { .. } => "bound_host_conflict",
            Self::TooManyHosts { .. } => "too_many_bound_hosts",
            Self::NotInterceptable { .. } | Self::LocalOnPlatform { .. } => {
                "bound_secret_not_interceptable"
            }
        }
    }

    /// The code of a create that failed with this refusal.
    pub fn create_code(&self) -> &'static str {
        match self {
            Self::HostReserved { .. } => "create_bound_host_reserved",
            Self::HostConflict { .. } => "create_bound_host_conflict",
            Self::TooManyHosts { .. } => "create_too_many_bound_hosts",
            Self::NotInterceptable { .. } | Self::LocalOnPlatform { .. } => {
                "create_bound_secret_not_interceptable"
            }
        }
    }
}

/// What a selected credential's binding says in a conflict: its hosts are
/// the platform's own, so no credential name is needed.
const SELECTED_CREDENTIAL: &str = "a selected credential";

/// Every host `record`'s secrets bind, once the union with `credentials`,
/// the names the boot's selected credentials bind, holds: no host a built-in
/// credential names or the egress policy protects (a name under `example`,
/// `test` or `invalid`, which a binding allows), no host named twice, and at most
/// [`MAX_BOUND_HOSTS_PER_ENVIRONMENT`] of them.
pub fn bound_hosts(
    record: &[FirstBindSecret],
    credentials: &InterceptSet,
) -> Result<BTreeSet<String>, BoundSecretsRefusal> {
    let mut named: BTreeMap<&str, &str> = BTreeMap::new();
    for secret in record {
        for host in &secret.hosts {
            let interceptable = InterceptBinding::new(host, codewire_access::INTERCEPT_PORT)
                .is_ok_and(|binding| binding.hostname() == host);
            if !interceptable
                || matches!(
                    BoundHost::parse(host, &ReservedHosts::default()),
                    Err(BindingError::ProviderHost(_) | BindingError::DeploymentHost(_))
                )
            {
                return Err(BoundSecretsRefusal::HostReserved {
                    host: host.clone(),
                    key: secret.key.clone(),
                });
            }
            let conflict = |other: &str| BoundSecretsRefusal::HostConflict {
                host: host.clone(),
                first: other.to_owned(),
                second: secret.key.clone(),
            };
            if credentials.binds_name(host) {
                return Err(conflict(SELECTED_CREDENTIAL));
            }
            if let Some(other) = named.insert(host, &secret.key) {
                return Err(conflict(other));
            }
        }
    }
    if named.len() > MAX_BOUND_HOSTS_PER_ENVIRONMENT {
        return Err(BoundSecretsRefusal::TooManyHosts {
            count: named.len(),
            keys: record.iter().map(|secret| secret.key.clone()).collect(),
        });
    }
    Ok(named.into_keys().map(str::to_owned).collect())
}

/// `credentials` with each of `record`'s hosts bound on 443 too, which the
/// front door routes to the bound secrets' route. A record whose union
/// doesn't hold, or a name that isn't a canonical interceptable one, is
/// refused: the supervisor refused it by name before it got here.
pub(super) fn with_bound_hosts(
    credentials: InterceptSet,
    record: &[FirstBindSecret],
) -> Result<InterceptSet, RunnerError> {
    if record.is_empty() {
        return Ok(credentials);
    }
    let hosts = bound_hosts(record, &credentials).map_err(|_| RunnerError::InvalidRequest)?;
    let mut bindings = credentials.bindings().to_vec();
    for host in &hosts {
        let binding = InterceptBinding::new(host, codewire_access::INTERCEPT_PORT)
            .ok()
            .filter(|binding| binding.hostname() == host)
            .ok_or(RunnerError::InvalidRequest)?;
        bindings.push(binding);
    }
    InterceptSet::with_suffixes(bindings, credentials.suffixes().to_vec())
        .map_err(|_| RunnerError::InvalidRequest)
}

/// A recorded bound secret on the runner's wire, as `BootBoundSecret`.
pub(crate) fn record_to_proto(secret: FirstBindSecret) -> crate::control::v1::BootBoundSecret {
    crate::control::v1::BootBoundSecret {
        path: secret.path,
        key: secret.key,
        binding_id: secret.binding_id,
        binding_generation: secret.binding_generation,
        prefix: secret.prefix,
        hosts: secret.hosts,
    }
}

/// A boot's record on the runner's wire, `None` for one that recorded
/// nothing.
pub(crate) fn records_to_proto(
    record: Option<Vec<FirstBindSecret>>,
) -> Option<crate::control::v1::BootBoundSecrets> {
    record.map(|record| crate::control::v1::BootBoundSecrets {
        secrets: record.into_iter().map(record_to_proto).collect(),
    })
}

/// A boot's record read back from the runner's wire. Its hosts are checked
/// where they are bound; its sets where they are leased.
pub(crate) fn records_from_proto(
    record: Option<crate::control::v1::BootBoundSecrets>,
) -> Option<Vec<FirstBindSecret>> {
    record.map(|record| {
        record
            .secrets
            .into_iter()
            .map(|secret| FirstBindSecret {
                path: secret.path,
                key: secret.key,
                binding_id: secret.binding_id,
                binding_generation: secret.binding_generation,
                prefix: secret.prefix,
                hosts: secret.hosts,
            })
            .collect()
    })
}

/// A boot's sealed platform record on the runner's wire, `None` for a boot
/// that has none.
fn platform_record_to_proto(
    record: Option<PlatformBootRecord>,
) -> Option<crate::control::v1::PlatformBootRecord> {
    use crate::control::v1;
    record.map(|record| v1::PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| v1::PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.map(|bound| v1::PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    })
}

/// A boot's sealed platform record read back from the runner's wire. Its
/// hosts are checked where they are bound; its seal by the platform.
fn platform_record_from_proto(
    record: Option<crate::control::v1::PlatformBootRecord>,
) -> Option<PlatformBootRecord> {
    record.map(|record| PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.map(|bound| PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    })
}

/// Every bound secret a boot records: its local sources' and its platform
/// sources', whose hosts it binds together.
fn boot_record_union(
    local: Option<&[FirstBindSecret]>,
    platform: Option<&PlatformBootRecord>,
) -> Vec<FirstBindSecret> {
    let mut union = local.map(<[_]>::to_vec).unwrap_or_default();
    union.extend(platform.map(PlatformBootRecord::bound).unwrap_or_default());
    union
}

/// A boot's records of its bound secrets (#4003): its local sources', and a
/// platform boot's sealed record of its platform sources, which the runner
/// holds unchanged for the boot's brokers and its checkpoints. Each is
/// `None` when the boot has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootRecords {
    pub local: Option<Vec<FirstBindSecret>>,
    pub platform: Option<PlatformBootRecord>,
}

impl BootRecords {
    /// Every bound secret the boot records, whose hosts it binds.
    pub(crate) fn union(&self) -> Vec<FirstBindSecret> {
        boot_record_union(self.local.as_deref(), self.platform.as_ref())
    }

    /// [`boot_record_union`], for a caller outside the runner.
    pub(crate) fn union_of(
        local: Option<&[FirstBindSecret]>,
        platform: Option<&PlatformBootRecord>,
    ) -> Vec<FirstBindSecret> {
        boot_record_union(local, platform)
    }

    /// [`platform_record_to_proto`], for a caller outside the runner.
    pub(crate) fn platform_to_proto(
        record: Option<PlatformBootRecord>,
    ) -> Option<crate::control::v1::PlatformBootRecord> {
        platform_record_to_proto(record)
    }

    /// [`platform_record_from_proto`], for a caller outside the runner.
    pub(crate) fn platform_from_proto(
        record: Option<crate::control::v1::PlatformBootRecord>,
    ) -> Option<PlatformBootRecord> {
        platform_record_from_proto(record)
    }

    /// The records a boot-secrets answer carries, taken from it.
    pub(crate) fn take_from(response: &mut crate::control::v1::GetBootSecretsResponse) -> Self {
        Self {
            local: records_from_proto(response.bound_secrets.take()),
            platform: platform_record_from_proto(response.platform_bound_secrets.take()),
        }
    }
}

#[cfg(test)]
mod tests {
    use codewire_egress_front_door_bridge::RouteTable;

    use super::super::boot_interception;
    use super::*;

    fn secret(key: &str, hosts: &[&str]) -> FirstBindSecret {
        FirstBindSecret {
            path: "local:user:0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
            key: key.into(),
            binding_id: "00000000-0000-0000-0000-000000000007".into(),
            binding_generation: 1,
            prefix: None,
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        }
    }

    fn clients(slots: &[&str]) -> codewire_access::ManagedCredentialClients {
        codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
            .unwrap()
    }

    fn api_key_placeholder() -> crate::control::v1::SeedCredentialPlaceholder {
        crate::control::v1::SeedCredentialPlaceholder {
            slot: 1,
            placeholder: format!("cwp1_{}A", "D".repeat(42)),
        }
    }

    /// The boot binds each recorded host on 443 beside its credentials',
    /// and its front door routes exactly those to the bound secrets' route.
    #[test]
    fn a_boot_binds_its_recorded_hosts_beside_its_credentials() {
        let record = [secret("FANCY_TOKEN", &["api.fancy.com", "up.fancy.com"])];
        let (intercepts, _) = boot_interception(
            true,
            clients(&["anthropic"]),
            vec![api_key_placeholder()],
            &record,
        )
        .unwrap();
        for host in ["api.fancy.com", "up.fancy.com", "api.anthropic.com"] {
            assert!(intercepts.binds(host, 443), "{host}");
        }
        assert!(!intercepts.binds("api.fancy.com", 80));
        let routes = RouteTable::for_intercepts(&intercepts).unwrap();
        assert!(routes.serves_bound_secret("api.fancy.com"));
        assert!(!routes.serves_bound_secret("api.anthropic.com"));

        // With no credential through the front door, the bound hosts alone
        // start one.
        let (alone, placeholders) =
            boot_interception(true, clients(&[]), Vec::new(), &record).unwrap();
        assert!(placeholders.is_empty());
        assert!(alone.binds("api.fancy.com", 443));
        assert!(
            RouteTable::for_intercepts(&alone)
                .unwrap()
                .serves_bound_secret("up.fancy.com")
        );
    }

    /// A platform boot's sealed record binds its bound hosts with the local
    /// record's, and its plain entries bind nothing; the record crosses the
    /// runner's wire unchanged (#4003).
    #[test]
    fn a_boot_binds_its_platform_records_hosts_with_its_local_ones() {
        let local = [secret("LOCAL_TOKEN", &["api.local.com"])];
        let platform = PlatformBootRecord {
            secrets: vec![
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "FANCY_TOKEN".into(),
                    binding_generation: 2,
                    bound: Some(PlatformBootBinding {
                        binding_id: "00000000-0000-0000-0000-000000000009".into(),
                        prefix: Some("ft_".into()),
                        hosts: vec!["api.fancy.com".into()],
                    }),
                },
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "PLAIN_TOKEN".into(),
                    binding_generation: 1,
                    bound: None,
                },
            ],
            seal: "vault:v1:synthetic".into(),
        };
        let union = boot_record_union(Some(&local), Some(&platform));
        assert_eq!(union.len(), 2);
        let (intercepts, _) = boot_interception(
            true,
            clients(&["anthropic"]),
            vec![api_key_placeholder()],
            &union,
        )
        .unwrap();
        let routes = RouteTable::for_intercepts(&intercepts).unwrap();
        for host in ["api.local.com", "api.fancy.com"] {
            assert!(intercepts.binds(host, 443), "{host}");
            assert!(routes.serves_bound_secret(host), "{host}");
        }
        let shared = PlatformBootRecord {
            secrets: vec![PlatformBootSecret {
                bound: Some(PlatformBootBinding {
                    hosts: vec!["api.local.com".into()],
                    ..platform.secrets[0].bound.clone().unwrap()
                }),
                ..platform.secrets[0].clone()
            }],
            ..platform.clone()
        };
        assert!(matches!(
            boot_interception(
                true,
                clients(&[]),
                Vec::new(),
                &boot_record_union(Some(&local), Some(&shared))
            ),
            Err(RunnerError::InvalidRequest)
        ));
        assert_eq!(
            platform_record_from_proto(platform_record_to_proto(Some(platform.clone()))),
            Some(platform)
        );
        assert_eq!(platform_record_from_proto(None), None);
    }

    /// The runner refuses what the supervisor would have refused by name: a
    /// record for a boot that doesn't intercept, or whose union doesn't hold.
    #[test]
    fn a_record_the_boot_cannot_bind_is_refused() {
        let record = [secret("FANCY_TOKEN", &["api.fancy.com"])];
        assert!(matches!(
            boot_interception(false, clients(&[]), Vec::new(), &record),
            Err(RunnerError::InvalidRequest)
        ));
        for refused in [
            vec![
                secret("FANCY_TOKEN", &["api.fancy.com"]),
                secret("OTHER_TOKEN", &["api.fancy.com"]),
            ],
            vec![secret("FANCY_TOKEN", &["api.anthropic.com"])],
            vec![secret("FANCY_TOKEN", &["API.fancy.com"])],
        ] {
            assert!(
                matches!(
                    boot_interception(true, clients(&[]), Vec::new(), &refused),
                    Err(RunnerError::InvalidRequest)
                ),
                "{refused:?}"
            );
        }
    }

    /// The record round-trips the runner's wire, and none stays none.
    #[test]
    fn a_record_round_trips_the_runners_wire() {
        let record = vec![secret("FANCY_TOKEN", &["api.fancy.com"])];
        assert_eq!(
            records_from_proto(records_to_proto(Some(record.clone()))),
            Some(record)
        );
        assert_eq!(records_from_proto(records_to_proto(None)), None);
    }
}
