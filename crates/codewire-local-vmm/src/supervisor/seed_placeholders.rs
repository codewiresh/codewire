//! A boot's seed placeholders, when its agent hosts go through the TLS front
//! door (#3999): asked of the credential authority before the boot starts,
//! so the seed carries them beside the front door's CA. A boot whose
//! credentials come from the platform gets them from the platform, through
//! the authority; when it cannot, its start is refused with a named error,
//! never started without interception (#4001, #6270).

use std::time::Duration;

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, GITHUB_HOSTS, ManagedCredentialClient,
    ManagedCredentialClients, front_door_hosts,
};
use codewire_local_credentials::{AuthorityFeature, PlatformCredentialBinding};

use super::boot_egress::BootEgress;
use super::{
    EnvironmentRecord, Supervisor, SupervisorError, access_environment_id,
    credential_control_error, v1,
};
use crate::diagnostic_log::{self, LogField};
use crate::supervisor_config::OUTDATED_CREDENTIAL_SERVICE;

/// The seed's code for each slot that takes a placeholder.
const API_KEY_SLOT: u32 = 1;
const SUBSCRIPTION_TOKEN_SLOT: u32 = 2;
const GITHUB_SLOT: u32 = 3;
/// The supervisor's bound on a platform boot's placeholder call, past the
/// authority's own 10-second deadline for the platform question.
const PLATFORM_PLACEHOLDERS_CALL_BOUND: Duration = Duration::from_secs(15);

impl Supervisor {
    /// The placeholders for an intercepting boot, from the binding it starts
    /// with: what that generation's broker leases carry. None unless the
    /// boot intercepts.
    ///
    /// - The selected Anthropic form's, except the sign-in form, whose login
    ///   carries one. An API key or subscription token without its
    ///   placeholder refuses the start: the guest drops the managed base URL
    ///   whenever it intercepts, so its agents would have no credential at
    ///   all.
    /// - The `github` slot's, when the selection would bind GitHub's hosts
    ///   ([`front_door_hosts`], #4001). Without one the start goes on, and
    ///   the runner binds no GitHub host for it, so Git and `gh` keep their
    ///   loopback route.
    ///
    /// A platform boot asks the platform instead, through an authority that
    /// serves that question, and reads the answer as a local one. A call
    /// that fails, or an authority that predates it, refuses the start with
    /// a [`PlatformPlaceholdersRefusal`].
    pub(super) async fn seed_placeholders(
        &self,
        egress: &BootEgress,
        environment: &EnvironmentRecord,
        generation: u64,
        clients: ManagedCredentialClients,
    ) -> Result<Vec<v1::SeedCredentialPlaceholder>, SupervisorError> {
        let wanted = WantedSlots::for_boot(egress.intercept, clients);
        if wanted.anthropic.is_none() && !wanted.github {
            return Ok(Vec::new());
        }
        if let Some(platform) = egress.platform.clone() {
            let placeholders = self
                .ask_platform_placeholders(platform, environment, generation, &wanted.slots())
                .await
                .map_err(|refusal| {
                    diagnostic_log::record(
                        self.log.as_deref(),
                        "platform_seed_refused",
                        &[
                            ("generation", LogField::Count(generation)),
                            ("reason", LogField::Name(refusal.code())),
                            ("status", LogField::Name(refusal.status_name())),
                        ],
                    );
                    SupervisorError::PlatformPlaceholders(refusal)
                })?;
            return seed_entries(wanted, placeholders);
        }
        let selected = environment
            .access_binding
            .as_ref()
            .ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
        let placeholders = self
            .access_control_client()
            .await?
            .environment_credential_placeholders(selected, generation, &wanted.slots())
            .await
            .map_err(credential_control_error)?;
        seed_entries(wanted, placeholders)
    }

    /// The platform's answer for a platform boot, through the authority.
    async fn ask_platform_placeholders(
        &self,
        platform: PlatformCredentialBinding,
        environment: &EnvironmentRecord,
        generation: u64,
        slots: &[CapabilitySlot],
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, PlatformPlaceholdersRefusal> {
        let unavailable = PlatformPlaceholdersRefusal::Unavailable;
        let environment_id = access_environment_id(environment.id)
            .map_err(|_| unavailable(tonic::Code::InvalidArgument))?;
        let mut client = self
            .access_control_client()
            .await
            .map_err(|_| unavailable(tonic::Code::Unavailable))?;
        if !AuthorityFeature::PlatformCredentialPlaceholders
            .served_by(client.info().protocol_version)
        {
            return Err(PlatformPlaceholdersRefusal::Unsupported);
        }
        tokio::time::timeout(
            PLATFORM_PLACEHOLDERS_CALL_BOUND,
            client.platform_environment_credential_placeholders(
                &environment_id,
                generation,
                platform,
                slots,
            ),
        )
        .await
        .map_err(|_| unavailable(tonic::Code::DeadlineExceeded))?
        .map_err(|status| unavailable(status.code()))
    }
}

/// Why a platform boot's start is refused for its seed placeholders (#4001,
/// #6270). Interception stays on, so the boot never starts without them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformPlaceholdersRefusal {
    /// The running credential authority predates the platform question.
    Unsupported,
    /// The platform question failed with this status.
    Unavailable(tonic::Code),
}

impl PlatformPlaceholdersRefusal {
    /// The named error the start is refused with.
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "platform_placeholders_unsupported",
            Self::Unavailable(_) => "platform_placeholders_unavailable",
        }
    }

    /// The canonical gRPC name of the call's status, or `none`.
    fn status_name(self) -> &'static str {
        let Self::Unavailable(code) = self else {
            return "none";
        };
        match code {
            tonic::Code::Unauthenticated => "UNAUTHENTICATED",
            tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
            tonic::Code::Unavailable => "UNAVAILABLE",
            tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
            tonic::Code::PermissionDenied => "PERMISSION_DENIED",
            tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
            tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
            _ => "OTHER",
        }
    }

    /// What the person does next.
    fn step(self) -> String {
        match self {
            Self::Unsupported => format!("{OUTDATED_CREDENTIAL_SERVICE}, then start this one"),
            Self::Unavailable(tonic::Code::Unauthenticated) => {
                "sign in again with `cw login`, then start it again".to_owned()
            }
            Self::Unavailable(tonic::Code::ResourceExhausted) => {
                "wait a minute, then start it again".to_owned()
            }
            Self::Unavailable(tonic::Code::PermissionDenied) => {
                "the platform refused this VM's credential profile; check the profile, then start it again".to_owned()
            }
            Self::Unavailable(_) => {
                "start it again once the platform is reachable".to_owned()
            }
        }
    }
}

impl std::fmt::Display for PlatformPlaceholdersRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "this VM's credential profile is on the platform, which the running local credential service cannot ask for its placeholders ({}): {}",
                self.code(),
                self.step()
            ),
            Self::Unavailable(_) => write!(
                f,
                "the platform did not give this VM's credential placeholders ({}, status {}): {}",
                self.code(),
                self.status_name(),
                self.step()
            ),
        }
    }
}

/// The slots one boot asks the authority for.
#[derive(Clone, Copy, Debug)]
struct WantedSlots {
    /// The seed code of the selected Anthropic form that takes a placeholder.
    anthropic: Option<u32>,
    /// Whether the selection would bind GitHub's hosts.
    github: bool,
}

impl WantedSlots {
    fn for_boot(intercept: bool, clients: ManagedCredentialClients) -> Self {
        if !intercept {
            return Self {
                anthropic: None,
                github: false,
            };
        }
        let anthropic = (clients.contains(ManagedCredentialClient::Anthropic)
            && !clients.anthropic_sign_in())
        .then(|| {
            if clients.anthropic_subscription_token() {
                SUBSCRIPTION_TOKEN_SLOT
            } else {
                API_KEY_SLOT
            }
        });
        let github = front_door_hosts(clients)
            .iter()
            .any(|host| GITHUB_HOSTS.contains(&host.host));
        Self { anthropic, github }
    }

    fn slots(self) -> Vec<CapabilitySlot> {
        let anthropic = self.anthropic.map(|_| CapabilitySlot::anthropic());
        let github = self.github.then(CapabilitySlot::github);
        anthropic.into_iter().chain(github).collect()
    }
}

/// The seed's entries from what the authority granted: exactly one
/// placeholder for the wanted Anthropic form, or the start is refused; at
/// most one for GitHub, whose absence only leaves GitHub unbound. A slot that
/// was not asked for refuses the start.
fn seed_entries(
    wanted: WantedSlots,
    granted: Vec<(CapabilitySlot, CredentialPlaceholder)>,
) -> Result<Vec<v1::SeedCredentialPlaceholder>, SupervisorError> {
    let mut anthropic = Vec::new();
    let mut github = Vec::new();
    for (slot, placeholder) in granted {
        if slot == CapabilitySlot::anthropic() && wanted.anthropic.is_some() {
            anthropic.push(placeholder);
        } else if slot == CapabilitySlot::github() && wanted.github {
            github.push(placeholder);
        } else {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
    }
    let mut entries = Vec::new();
    if let Some(slot) = wanted.anthropic {
        let Ok([placeholder]) = <[_; 1]>::try_from(anthropic) else {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        };
        entries.push(seed_entry(slot, placeholder));
    }
    match <[_; 1]>::try_from(github) {
        Ok([placeholder]) => entries.push(seed_entry(GITHUB_SLOT, placeholder)),
        Err(none) if none.is_empty() => {}
        Err(_) => return Err(SupervisorError::EnvironmentAccessUnavailable),
    }
    Ok(entries)
}

fn seed_entry(slot: u32, placeholder: CredentialPlaceholder) -> v1::SeedCredentialPlaceholder {
    v1::SeedCredentialPlaceholder {
        slot,
        placeholder: placeholder.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder() -> CredentialPlaceholder {
        CredentialPlaceholder::parse(&format!("cwp1_{}A", "C".repeat(42))).unwrap()
    }

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    fn anthropic_only(slot: u32) -> WantedSlots {
        WantedSlots {
            anthropic: Some(slot),
            github: false,
        }
    }

    /// An intercepting boot whose selected form the authority grants no
    /// placeholder never starts with no credential at all.
    #[test]
    fn a_boot_starts_only_with_exactly_one_placeholder_for_its_form() {
        assert!(matches!(
            seed_entries(anthropic_only(API_KEY_SLOT), Vec::new()),
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
        let two = vec![
            (CapabilitySlot::anthropic(), placeholder()),
            (CapabilitySlot::anthropic(), placeholder()),
        ];
        assert!(seed_entries(anthropic_only(API_KEY_SLOT), two).is_err());
        let entries = seed_entries(
            anthropic_only(SUBSCRIPTION_TOKEN_SLOT),
            vec![(CapabilitySlot::anthropic(), placeholder())],
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slot, SUBSCRIPTION_TOKEN_SLOT);
        assert_eq!(entries[0].placeholder, placeholder().as_str());
    }

    /// GitHub's placeholder is asked for only when the boot would bind its
    /// hosts; a grant without one leaves GitHub out rather than failing the
    /// start, and a slot nobody asked for refuses it (#4001).
    #[test]
    fn the_github_slot_is_asked_for_only_while_its_hosts_would_be_bound() {
        let selected = clients(&["anthropic", "github"]);
        let off = WantedSlots::for_boot(false, selected);
        assert!(off.anthropic.is_none() && !off.github && off.slots().is_empty());
        let on = WantedSlots::for_boot(true, selected);
        assert_eq!(on.anthropic, Some(API_KEY_SLOT));
        assert!(on.github);
        assert!(!WantedSlots::for_boot(true, clients(&["anthropic"])).github);

        let both = WantedSlots {
            anthropic: Some(API_KEY_SLOT),
            github: true,
        };
        assert_eq!(
            both.slots(),
            vec![CapabilitySlot::anthropic(), CapabilitySlot::github()]
        );
        let entries = seed_entries(
            both,
            vec![
                (CapabilitySlot::github(), placeholder()),
                (CapabilitySlot::anthropic(), placeholder()),
            ],
        )
        .unwrap();
        assert_eq!(
            entries.iter().map(|entry| entry.slot).collect::<Vec<_>>(),
            [API_KEY_SLOT, GITHUB_SLOT]
        );
        // None granted for GitHub: the boot goes on without it.
        let entries =
            seed_entries(both, vec![(CapabilitySlot::anthropic(), placeholder())]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slot, API_KEY_SLOT);
        let github_only = WantedSlots {
            anthropic: None,
            github: true,
        };
        assert!(seed_entries(github_only, Vec::new()).unwrap().is_empty());
        let two = vec![
            (CapabilitySlot::github(), placeholder()),
            (CapabilitySlot::github(), placeholder()),
        ];
        assert!(seed_entries(github_only, two).is_err());
        // A GitHub grant nobody asked for refuses the start.
        assert!(
            seed_entries(
                anthropic_only(API_KEY_SLOT),
                vec![
                    (CapabilitySlot::anthropic(), placeholder()),
                    (CapabilitySlot::github(), placeholder()),
                ],
            )
            .is_err()
        );
    }
    /// A platform boot reads the platform's answer as a local one (#4001):
    /// its Anthropic form without a placeholder refuses the start as
    /// locally, and GitHub without one is only unbound.
    #[test]
    fn a_platform_answer_is_read_as_a_local_one() {
        let both = WantedSlots {
            anthropic: Some(API_KEY_SLOT),
            github: true,
        };
        let granted = |slots: &[CapabilitySlot]| {
            slots
                .iter()
                .map(|slot| (slot.clone(), placeholder()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            seed_entries(both, granted(&[CapabilitySlot::anthropic()])).unwrap(),
            vec![seed_entry(API_KEY_SLOT, placeholder())]
        );
        assert!(matches!(
            seed_entries(both, granted(&[CapabilitySlot::github()])),
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
    }

    /// A refused platform boot names its error, the call's status and the
    /// step to take, and never a value (#4001, #6270).
    #[test]
    fn a_platform_refusal_names_its_error_status_and_step() {
        use tonic::Code;
        let unsupported = PlatformPlaceholdersRefusal::Unsupported.to_string();
        assert!(unsupported.contains("platform_placeholders_unsupported"));
        assert!(unsupported.contains(OUTDATED_CREDENTIAL_SERVICE));
        for (status, name, step) in [
            (Code::Unauthenticated, "UNAUTHENTICATED", "`cw login`"),
            (
                Code::ResourceExhausted,
                "RESOURCE_EXHAUSTED",
                "wait a minute",
            ),
            (
                Code::Unavailable,
                "UNAVAILABLE",
                "once the platform is reachable",
            ),
            (
                Code::DeadlineExceeded,
                "DEADLINE_EXCEEDED",
                "once the platform is reachable",
            ),
            (
                Code::PermissionDenied,
                "PERMISSION_DENIED",
                "check the profile",
            ),
        ] {
            let refusal = PlatformPlaceholdersRefusal::Unavailable(status);
            assert_eq!(refusal.code(), "platform_placeholders_unavailable");
            let text = refusal.to_string();
            assert!(text.contains("platform_placeholders_unavailable"), "{text}");
            assert!(text.contains(name), "{text}");
            assert!(text.contains(step), "{text}");
            assert!(!text.contains("cwp1_"), "{text}");
        }
    }
}
