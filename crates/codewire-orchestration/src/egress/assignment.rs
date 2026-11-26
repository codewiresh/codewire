//! The policy an environment's sandbox enforces through cw-egress (#4000):
//! its selection's current revision, as the canonical document cw-egress
//! compiles and checks against the digest. An environment that selects
//! nothing is on the built-in `open`, the default (#3997), and stores no row.
//! While the platform network policy store is switched off, every
//! environment is on `open`, whatever it selected (#6120).

use codewire_access::{FrontDoorHost, INTERCEPT_PORT, ManagedCredentialClients, front_door_hosts};
use codewire_egress_policy::intercept::{InterceptBinding, MAX_INTERCEPT_BINDINGS};
use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy, PolicyError};
use sqlx::PgPool;
use thiserror::Error;

/// One policy revision, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedPolicy {
    /// `platform:NAME`, or a built-in's name.
    pub name: String,
    /// Zero for a built-in.
    pub revision: u32,
    /// Canonical JSON.
    pub document: Vec<u8>,
    pub digest: [u8; 32],
}

#[derive(Debug, Error)]
pub enum AssignmentError {
    #[error("read the environment's network policy: {0}")]
    Store(#[from] sqlx::Error),
    #[error("the environment does not exist")]
    NoEnvironment,
    #[error("the environment's network policy selection is not valid")]
    CorruptSelection,
    #[error("compile a built-in network policy: {0}")]
    Builtin(#[from] PolicyError),
}

#[derive(sqlx::FromRow)]
struct SelectionRow {
    policy_id: Option<String>,
    builtin: Option<String>,
    policy_name: Option<String>,
    revision: Option<i32>,
    document: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
}

/// One host a bound sandbox's cw-egress hands to its front door: exactly,
/// or with `suffix` every name strictly under it that no exact binding names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Intercept {
    pub binding: InterceptBinding,
    pub suffix: bool,
}

/// What a bound sandbox intercepts when the deployment does (#4001): every
/// host the front door serves for its binding's clients, on its port, the
/// selection a local boot binds too (#4001 step P); nothing when it does
/// not.
pub fn interception_bindings(
    interception: bool,
    clients: ManagedCredentialClients,
) -> anyhow::Result<Vec<Intercept>> {
    if !interception {
        return Ok(Vec::new());
    }
    intercepts(&front_door_hosts(clients))
}

/// Check at startup that the widest selection's bindings validate, so no
/// binding's assignment can fail on them later.
pub fn check_interception_bindings(interception: bool) -> anyhow::Result<()> {
    let widest = ManagedCredentialClients::from_profile_slots([
        "codex",
        "openai",
        "anthropic",
        "gemini",
        "antigravity",
        "ssh",
        "github",
    ])
    .and_then(ManagedCredentialClients::with_anthropic_sign_in)
    .map_err(|_| anyhow::anyhow!("the widest client selection is not valid"))?;
    interception_bindings(interception, widest).map(drop)
}

fn intercepts(hosts: &[FrontDoorHost]) -> anyhow::Result<Vec<Intercept>> {
    anyhow::ensure!(
        hosts.len() <= MAX_INTERCEPT_BINDINGS,
        "the front door's hosts exceed {MAX_INTERCEPT_BINDINGS} interception bindings"
    );
    let mut intercepts = hosts
        .iter()
        .map(|host| {
            let binding = InterceptBinding::new(host.host, INTERCEPT_PORT)
                .map_err(|error| anyhow::anyhow!("front door host {:?}: {error}", host.host))?;
            // A one-label suffix would intercept a whole top-level domain.
            anyhow::ensure!(
                !host.suffix || binding.hostname().contains('.'),
                "front door suffix {:?} has one label",
                host.host
            );
            Ok(Intercept {
                binding,
                suffix: host.suffix,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    intercepts.sort();
    intercepts.dedup();
    Ok(intercepts)
}

/// The current revision of what `environment_id` selects, or `open` while
/// the store is switched off (`store_enabled`, the deployment's
/// `CODEWIRE_PLATFORM_NETWORK_POLICIES_ENABLED`). The stored selections are
/// kept, so switching the store back on restores them unchanged (#6120).
pub async fn environment_policy(
    pool: &PgPool,
    environment_id: &str,
    store_enabled: bool,
) -> Result<AssignedPolicy, AssignmentError> {
    let row: Option<SelectionRow> = sqlx::query_as(
        "SELECT np.policy_id, np.builtin, npp.name AS policy_name,
                npp.current_revision AS revision, npr.document, npr.digest
           FROM environments e
      LEFT JOIN platform_environment_network_policies np ON np.environment_id = e.id
      LEFT JOIN platform_network_policies npp
             ON npp.id = np.policy_id AND npp.org_id = e.org_id
      LEFT JOIN platform_network_policy_revisions npr
             ON npr.policy_id = npp.id AND npr.revision = npp.current_revision
          WHERE e.id = $1",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    selection(row.ok_or(AssignmentError::NoEnvironment)?, store_enabled)
}

fn selection(row: SelectionRow, store_enabled: bool) -> Result<AssignedPolicy, AssignmentError> {
    if !store_enabled {
        return compiled(BuiltinPolicy::Open.name(), &BuiltinPolicy::Open.compile());
    }
    match (row.policy_id, row.builtin.as_deref()) {
        (None, None) => compiled(BuiltinPolicy::Open.name(), &BuiltinPolicy::Open.compile()),
        (None, Some(name)) => {
            let builtin =
                BuiltinPolicy::from_name(name).ok_or(AssignmentError::CorruptSelection)?;
            compiled(builtin.name(), &builtin.compile())
        }
        (Some(_), None) => {
            let (Some(name), Some(revision), Some(document), Some(digest)) =
                (row.policy_name, row.revision, row.document, row.digest)
            else {
                return Err(AssignmentError::CorruptSelection);
            };
            Ok(AssignedPolicy {
                name: format!("platform:{name}"),
                revision: u32::try_from(revision).map_err(|_| AssignmentError::CorruptSelection)?,
                document,
                digest: digest
                    .try_into()
                    .map_err(|_| AssignmentError::CorruptSelection)?,
            })
        }
        (Some(_), Some(_)) => Err(AssignmentError::CorruptSelection),
    }
}

fn compiled(name: &str, policy: &CompiledPolicy) -> Result<AssignedPolicy, AssignmentError> {
    Ok(AssignedPolicy {
        name: name.to_owned(),
        revision: 0,
        document: policy.canonical_json()?,
        digest: *policy.digest().as_bytes(),
    })
}

#[cfg(test)]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> SelectionRow {
        SelectionRow {
            policy_id: None,
            builtin: None,
            policy_name: None,
            revision: None,
            document: None,
            digest: None,
        }
    }

    fn hex(bytes: &[u8; 32]) -> String {
        codewire_egress_policy::PolicyDigest::from_bytes(*bytes).to_hex()
    }

    #[test]
    fn no_selection_is_open_with_its_pinned_digest() {
        let policy = selection(row(), true).unwrap();
        assert_eq!(policy.name, "open");
        assert_eq!(policy.revision, 0);
        assert_eq!(
            hex(&policy.digest),
            "384ad64a6b4de41783c369f74ae4a4265617de1c7da2c97c14f5fb9b4e40090f"
        );
        assert_eq!(
            policy.document,
            BuiltinPolicy::Open.compile().canonical_json().unwrap()
        );
    }

    /// A selection stores a built-in by name, so one of `open` made before
    /// #3997 sends today's `open`, every TCP port, and `web` sends the three
    /// ports `open` had.
    #[test]
    fn a_stored_open_selection_sends_todays_open_and_web_the_old_document() {
        let open = selection(
            SelectionRow {
                builtin: Some("open".to_owned()),
                ..row()
            },
            true,
        )
        .unwrap();
        assert_eq!((open.name.as_str(), open.revision), ("open", 0));
        assert_eq!(hex(&open.digest), BuiltinPolicy::Open.digest_hex());
        let web = selection(
            SelectionRow {
                builtin: Some("web".to_owned()),
                ..row()
            },
            true,
        )
        .unwrap();
        assert_eq!(web.name, "web");
        assert_eq!(
            hex(&web.digest),
            "fab8151c7bffd0d0fe6ca1a9397ae6b60fa1e0ae650a967f9c9445ac3dd4189f"
        );
    }

    #[test]
    fn a_builtin_selection_sends_the_builtin_document() {
        let policy = selection(
            SelectionRow {
                builtin: Some("locked".to_owned()),
                ..row()
            },
            true,
        )
        .unwrap();
        assert_eq!(policy.name, "locked");
        assert_eq!(hex(&policy.digest), BuiltinPolicy::Locked.digest_hex());
        assert_eq!(
            policy.document,
            BuiltinPolicy::Locked.compile().canonical_json().unwrap()
        );
    }

    #[test]
    fn a_stored_selection_sends_its_current_revision() {
        let policy = selection(
            SelectionRow {
                policy_id: Some("id".to_owned()),
                policy_name: Some("team-web".to_owned()),
                revision: Some(3),
                document: Some(b"{}".to_vec()),
                digest: Some(vec![7; 32]),
                ..row()
            },
            true,
        )
        .unwrap();
        assert_eq!(policy.name, "platform:team-web");
        assert_eq!(policy.revision, 3);
        assert_eq!(policy.digest, [7; 32]);
    }

    #[test]
    fn a_selection_that_cannot_be_read_is_refused_not_defaulted() {
        let both = SelectionRow {
            policy_id: Some("id".to_owned()),
            builtin: Some("locked".to_owned()),
            ..row()
        };
        let unknown_builtin = SelectionRow {
            builtin: Some("hosted-default".to_owned()),
            ..row()
        };
        let short_digest = SelectionRow {
            policy_id: Some("id".to_owned()),
            policy_name: Some("team-web".to_owned()),
            revision: Some(1),
            document: Some(b"{}".to_vec()),
            digest: Some(vec![7; 31]),
            ..row()
        };
        for broken in [both, unknown_builtin, short_digest] {
            assert!(matches!(
                selection(broken, true),
                Err(AssignmentError::CorruptSelection)
            ));
        }
    }

    /// With the store switched off every environment is on `open`, whatever
    /// it selected, a wider or a narrower policy alike; switched on, the
    /// stored selection is assigned again (#6120).
    #[test]
    fn with_the_store_off_every_selection_is_assigned_open() {
        let builtin = |name: &str| SelectionRow {
            builtin: Some(name.to_owned()),
            ..row()
        };
        let selections = || {
            [
                (
                    SelectionRow {
                        policy_id: Some("id".to_owned()),
                        policy_name: Some("team-web".to_owned()),
                        revision: Some(3),
                        document: Some(b"{}".to_vec()),
                        digest: Some(vec![7; 32]),
                        ..row()
                    },
                    "platform:team-web",
                ),
                (builtin("locked"), "locked"),
                (builtin("web"), "web"),
                (row(), "open"),
            ]
        };
        for (stored, selected) in selections() {
            let off = selection(stored, false).unwrap();
            assert_eq!(
                (off.name.as_str(), off.revision, hex(&off.digest)),
                ("open", 0, BuiltinPolicy::Open.digest_hex().to_owned()),
                "{selected} with the store off"
            );
        }
        for (stored, selected) in selections() {
            assert_eq!(selection(stored, true).unwrap().name, selected);
        }
    }

    fn host(host: &'static str, suffix: bool) -> FrontDoorHost {
        FrontDoorHost { host, suffix }
    }

    #[test]
    fn interception_binds_each_front_door_host_on_its_port_only_when_on() {
        let clients =
            ManagedCredentialClients::from_profile_slots(["anthropic", "openai", "codex"]).unwrap();
        assert!(interception_bindings(false, clients).unwrap().is_empty());
        // A selection that names no host binds none (#5215).
        assert!(
            interception_bindings(true, ManagedCredentialClients::default())
                .unwrap()
                .is_empty()
        );
        let on = interception_bindings(true, clients).unwrap();
        let mut expected: Vec<(&str, u16, bool)> = codewire_access::FRONT_DOOR_HOSTS
            .iter()
            .map(|host| (host.host, 443, host.suffix))
            .collect();
        expected.sort();
        let sent: Vec<(&str, u16, bool)> = on
            .iter()
            .map(|intercept| {
                (
                    intercept.binding.hostname(),
                    intercept.binding.port(),
                    intercept.suffix,
                )
            })
            .collect();
        assert_eq!(sent, expected);
        check_interception_bindings(true).unwrap();
    }

    /// A hosted sandbox binds exactly the hosts and suffixes a local boot's
    /// front door routes for the same clients, for every selection (#4001
    /// step P, #6195).
    #[test]
    fn the_bindings_are_the_hosts_the_local_front_door_routes() {
        let slots = [
            "codex",
            "openai",
            "anthropic",
            "gemini",
            "antigravity",
            "ssh",
            "github",
        ];
        for bits in 0..(1_u8 << slots.len()) {
            let chosen = (0..slots.len())
                .filter(|bit| bits & (1 << bit) != 0)
                .map(|bit| slots[bit]);
            let base = ManagedCredentialClients::from_profile_slots(chosen).unwrap();
            let forms = [
                Some(base),
                base.with_anthropic_subscription_token().ok(),
                base.with_anthropic_sign_in().ok(),
            ];
            for clients in forms.into_iter().flatten() {
                let bound = interception_bindings(true, clients).unwrap();
                let named = |suffix: bool| -> Vec<String> {
                    bound
                        .iter()
                        .filter(|intercept| intercept.suffix == suffix)
                        .map(|intercept| intercept.binding.hostname().to_owned())
                        .collect()
                };
                let table = codewire_egress_front_door_bridge::RouteTable::for_clients(clients);
                let mut routed: Vec<String> = table
                    .as_ref()
                    .map(|table| table.hosts().into_iter().map(str::to_owned).collect())
                    .unwrap_or_default();
                routed.sort();
                assert_eq!(named(false), routed, "{clients:?}");
                let mut suffixes: Vec<String> = table
                    .as_ref()
                    .map(|table| table.suffixes().into_iter().map(str::to_owned).collect())
                    .unwrap_or_default();
                suffixes.sort();
                assert_eq!(named(true), suffixes, "{clients:?}");
            }
        }
        assert_eq!(
            codewire_egress_front_door_bridge::INTERCEPT_PORT,
            INTERCEPT_PORT
        );
    }

    #[test]
    fn a_suffix_entry_is_carried_as_a_suffix_beside_its_exact_host() {
        let both = intercepts(&[host("chatgpt.com", true), host("chatgpt.com", false)]).unwrap();
        assert_eq!(
            both.iter()
                .map(|intercept| (intercept.binding.hostname(), intercept.suffix))
                .collect::<Vec<_>>(),
            [("chatgpt.com", false), ("chatgpt.com", true)]
        );
        // The same entry twice is one binding.
        assert_eq!(
            intercepts(&[host("chatgpt.com", true), host("chatgpt.com", true)])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_host_list_that_does_not_validate_stops_startup() {
        for bad in [
            host("not a host", false),
            host("*.example.com", false),
            host("", false),
            host("com", true),
        ] {
            assert!(intercepts(&[bad]).is_err(), "{bad:?}");
        }
        let many: Vec<FrontDoorHost> = (0..=MAX_INTERCEPT_BINDINGS)
            .map(|n| host(format!("h{n}.example.com").leak(), false))
            .collect();
        assert!(intercepts(&many).is_err());
        assert!(intercepts(&many[..MAX_INTERCEPT_BINDINGS]).is_ok());
    }
}
