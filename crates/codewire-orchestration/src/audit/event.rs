//! What one audit event says: its kind, its actor and its fields, a closed
//! set per kind (SPEC.md "Sandbox audit log", "What it records"). The field
//! names are the ones the read returns and `cw audit --output json` prints.

use std::net::IpAddr;

use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::Destination;
use serde::{Deserialize, Serialize};

/// The five kinds of event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Access,
    Lifecycle,
    Policy,
    Refused,
    Credentials,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Lifecycle => "lifecycle",
            Self::Policy => "policy",
            Self::Refused => "refused",
            Self::Credentials => "credentials",
        }
    }
}

/// A person's role in the Sandbox's organization when the event happened.
/// `Staff` is a person at Codewire or an operator of the platform acting
/// through a support or admin path ("Staff access").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Member,
    Staff,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Staff => "staff",
        }
    }

    /// An organization role as `org_members` stores it.
    pub fn from_org_role(role: &str) -> Option<Self> {
        match role {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// Who did it, as they were when it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    User {
        id: String,
        email: String,
        role: Role,
    },
    ApiKey {
        id: String,
        name: String,
    },
    /// The platform's own action.
    Platform,
    /// What the Sandbox's workload caused: a refusal or a credential use.
    Sandbox,
}

/// The surface a session was opened on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Terminal,
    Ssh,
    Exec,
    Desktop,
    Preview,
}

impl Surface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Ssh => "ssh",
            Self::Exec => "exec",
            Self::Desktop => "desktop",
            Self::Preview => "preview",
        }
    }

    /// Exec and preview sessions come in bursts and fold per actor, client
    /// IP and hour; the others are one event each.
    pub const fn folds(self) -> bool {
        matches!(self, Self::Exec | Self::Preview)
    }
}

/// Why the platform stopped, restarted or deleted a Sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformReason {
    Idle,
    OutOfCredit,
    Suspended,
    SystemdRefused,
    PodFailed,
    RuntimeReplaced,
    NodeLost,
    ConfigurationChanged,
    SourcesChanged,
    Expired,
}

/// A size as `cw` words it: `2 vCPU · 4 GiB RAM`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub vcpu: u32,
    pub memory_mib: u64,
}

/// What happened to the Sandbox itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Lifecycle {
    Created {
        #[serde(skip_serializing_if = "Option::is_none")]
        preset: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        from_snapshot: Option<String>,
    },
    Started,
    Stopped {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<PlatformReason>,
        /// An idle stop's timeout, in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_stop_seconds: Option<u32>,
    },
    Restarted {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<PlatformReason>,
    },
    Resized {
        from: Size,
        to: Size,
    },
    SnapshotTaken {
        snapshot: String,
    },
    Deleted {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<PlatformReason>,
    },
}

/// A change to the network policy a Sandbox is held to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Policy {
    /// The Sandbox selected another policy.
    Selected { from: String, to: String },
    /// The selected policy got a new revision.
    Edited {
        policy: String,
        from_revision: u32,
        to_revision: u32,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// cw-egress reports it enforces this revision.
    Enforcing { policy: String, revision: u32 },
    /// cw-egress reports it failed closed: no outbound traffic.
    FailedClosed { failure_code: String },
}

/// The transport a refused request used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Dns,
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// What refused a request: the egress broker, or an intercepted host's
/// front door.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalSource {
    Network,
    FrontDoor,
}

/// A refusal reason, stored as its code. Only the policy engine's own
/// reasons exist, so no text the workload chose can be one.
mod reason_code {
    use codewire_egress_policy::lease::RefusalReason;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        reason: &RefusalReason,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(reason.code())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RefusalReason, D::Error> {
        let code = String::deserialize(deserializer)?;
        RefusalReason::ALL
            .into_iter()
            .find(|reason| reason.code() == code)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown refusal reason {code:?}")))
    }
}

/// An egress refusal, with the fields of a `cw --local policy log` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// A checked name or an address; `None` when the name failed the host
    /// check and is withheld.
    pub destination: Option<String>,
    pub withheld: bool,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub protocol: Protocol,
    #[serde(with = "reason_code")]
    pub reason: RefusalReason,
    pub source: RefusalSource,
    pub policy: Option<String>,
    pub revision: Option<u32>,
}

/// A credential or application secret attached, detached or used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Credentials {
    Attached {
        provider: String,
        name: String,
    },
    Detached {
        provider: String,
        name: String,
    },
    /// One credential's use at one host, so two credentials of one provider
    /// stay apart.
    Used {
        provider: String,
        #[serde(default)]
        name: String,
        /// Empty when withheld.
        host: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        withheld: bool,
    },
}

/// An hour's refusals past its 1,000 subjects (SPEC "Bounds"), as the read
/// returns them. The refusal writer keeps the subjects it has counted beside
/// these fields; no reader sees them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalOverflow {
    pub subjects: u64,
    #[serde(default)]
    pub at_least: bool,
}

/// What happened, by kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    Access(Surface),
    Lifecycle(Lifecycle),
    Policy(Policy),
    Refused(Refusal),
    RefusedOverflow(RefusalOverflow),
    Credentials(Credentials),
}

/// One event's stored columns, from its kind and fields.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Columns {
    pub(super) kind: Kind,
    pub(super) action: String,
    /// What a fold is about, or the action for an event that doesn't fold.
    pub(super) subject: String,
    pub(super) folds: bool,
    pub(super) detail: serde_json::Value,
}

impl What {
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Access(_) => Kind::Access,
            Self::Lifecycle(_) => Kind::Lifecycle,
            Self::Policy(_) => Kind::Policy,
            Self::Refused(_) | Self::RefusedOverflow(_) => Kind::Refused,
            Self::Credentials(_) => Kind::Credentials,
        }
    }

    /// The event with every name the workload chose passed through the host
    /// check (SPEC "The host check"): a name that fails is withheld, kept for
    /// its count and never its text, and an address that doesn't parse is
    /// dropped.
    fn checked(&self) -> Self {
        let name = |host: &str| match Destination::checked_name(host) {
            Destination::Name(name) => Some(name),
            Destination::Address(_) | Destination::Withheld => None,
        };
        let address = |text: &str| text.parse::<IpAddr>().ok().map(|ip| ip.to_string());
        match self {
            Self::Refused(refusal) => {
                let destination = refusal
                    .destination
                    .as_deref()
                    .and_then(|host| address(host).or_else(|| name(host)));
                Self::Refused(Refusal {
                    withheld: refusal.withheld
                        || (refusal.destination.is_some() && destination.is_none()),
                    destination,
                    address: refusal.address.as_deref().and_then(address),
                    policy: refusal.policy.as_deref().and_then(name),
                    ..refusal.clone()
                })
            }
            Self::Credentials(Credentials::Used {
                provider,
                name: credential,
                host,
                withheld,
            }) => {
                let checked = name(host);
                Self::Credentials(Credentials::Used {
                    provider: provider.clone(),
                    name: credential.clone(),
                    withheld: *withheld || checked.is_none(),
                    host: checked.unwrap_or_default(),
                })
            }
            other => other.clone(),
        }
    }

    /// The fold's subject for an access event also names the actor and the
    /// client IP, which `actor_key` gives.
    pub(super) fn columns(&self, actor_key: &str) -> Result<Columns, serde_json::Error> {
        let checked = self.checked();
        let kind = checked.kind();
        let (action, folds, subject, detail) = match &checked {
            Self::Access(surface) => (
                surface.as_str().to_owned(),
                surface.folds(),
                format!("{}|{actor_key}", surface.as_str()),
                serde_json::json!({}),
            ),
            Self::Lifecycle(lifecycle) => single(serde_json::to_value(lifecycle)?)?,
            Self::Policy(policy) => single(serde_json::to_value(policy)?)?,
            Self::RefusedOverflow(overflow) => (
                "overflow".to_owned(),
                true,
                "overflow".to_owned(),
                serde_json::to_value(overflow)?,
            ),
            Self::Refused(refusal) => {
                let detail = serde_json::to_value(refusal)?;
                let subject = format!(
                    "{}|{}|{}|{}|{}|{}",
                    refusal.destination.as_deref().unwrap_or("(withheld)"),
                    refusal.protocol.as_str(),
                    refusal
                        .port
                        .map_or_else(String::new, |port| port.to_string()),
                    refusal.reason.code(),
                    refusal.policy.as_deref().unwrap_or(""),
                    refusal
                        .revision
                        .map_or_else(String::new, |revision| revision.to_string()),
                );
                ("refused".to_owned(), true, subject, detail)
            }
            Self::Credentials(
                credentials @ Credentials::Used {
                    provider,
                    name,
                    host,
                    ..
                },
            ) => {
                let (action, _, _, detail) = single(serde_json::to_value(credentials)?)?;
                (action, true, format!("{provider}|{name}|{host}"), detail)
            }
            Self::Credentials(credentials) => single(serde_json::to_value(credentials)?)?,
        };
        Ok(Columns {
            kind,
            action,
            subject,
            folds,
            detail,
        })
    }
}

impl What {
    /// An event as [`Self::columns`] stored it: its kind, its action and its
    /// fields.
    pub fn from_stored(
        kind: &str,
        action: &str,
        detail: &serde_json::Value,
    ) -> Result<Self, serde_json::Error> {
        use serde::de::Error as _;
        let tagged = || {
            let mut fields = detail.clone();
            if let Some(object) = fields.as_object_mut() {
                object.insert("action".into(), action.into());
            }
            fields
        };
        match kind {
            "access" => serde_json::from_value(action.into()).map(Self::Access),
            "lifecycle" => serde_json::from_value(tagged()).map(Self::Lifecycle),
            "policy" => serde_json::from_value(tagged()).map(Self::Policy),
            "refused" if action == "overflow" => {
                serde_json::from_value(detail.clone()).map(Self::RefusedOverflow)
            }
            "refused" => serde_json::from_value(detail.clone()).map(Self::Refused),
            "credentials" => serde_json::from_value(tagged()).map(Self::Credentials),
            other => Err(serde_json::Error::custom(format!("unknown kind {other:?}"))),
        }
    }
}

/// An event that doesn't fold, from a value serialized with
/// `tag = "action"`: its action, which is also its subject, and the rest of
/// its fields.
fn single(
    mut value: serde_json::Value,
) -> Result<(String, bool, String, serde_json::Value), serde_json::Error> {
    use serde::de::Error as _;
    let action = value
        .as_object_mut()
        .and_then(|fields| fields.remove("action"))
        .and_then(|action| action.as_str().map(str::to_owned))
        .ok_or_else(|| serde_json::Error::custom("an event's fields carry its action"))?;
    Ok((action.clone(), false, action, value))
}
