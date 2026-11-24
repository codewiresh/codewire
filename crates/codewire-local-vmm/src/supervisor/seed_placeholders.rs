//! A boot's seed placeholders, when its agent hosts go through the TLS front
//! door (#3999): asked of the credential authority before the boot starts,
//! so the seed carries them beside the front door's CA.

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, GITHUB_HOSTS, ManagedCredentialClient,
    ManagedCredentialClients, front_door_hosts,
};

use super::boot_egress::BootEgress;
use super::{EnvironmentRecord, Supervisor, SupervisorError, credential_control_error, v1};

/// The seed's code for each slot that takes a placeholder.
const API_KEY_SLOT: u32 = 1;
const SUBSCRIPTION_TOKEN_SLOT: u32 = 2;
const GITHUB_SLOT: u32 = 3;

impl Supervisor {
    /// The placeholders for an intercepting boot, from the binding it starts
    /// with: what that generation's broker leases carry. None unless the
    /// boot `intercept`s.
    ///
    /// - The selected Anthropic form's, except the sign-in form, whose login
    ///   carries one. An API key or subscription token without its
    ///   placeholder refuses the start: the guest drops the managed base URL
    ///   whenever it intercepts, so its agents would have no credential at
    ///   all.
    /// - The `github` slot's, when the selection would bind GitHub's hosts
    ///   ([`front_door_hosts`], #4001), and never for a platform profile's
    ///   boot: the local authority refuses a platform binding, and nothing
    ///   forwards the slot to the platform yet. Without one the start goes
    ///   on, and the runner binds no GitHub host for it, so Git and `gh`
    ///   keep their loopback route.
    pub(super) async fn seed_placeholders(
        &self,
        egress: &BootEgress,
        environment: &EnvironmentRecord,
        generation: u64,
        clients: ManagedCredentialClients,
    ) -> Result<Vec<v1::SeedCredentialPlaceholder>, SupervisorError> {
        let wanted = WantedSlots::for_boot(egress.intercept, egress.platform, clients);
        if wanted.anthropic.is_none() && !wanted.github {
            return Ok(Vec::new());
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
    /// `platform`: the boot's credentials come from the platform.
    fn for_boot(intercept: bool, platform: bool, clients: ManagedCredentialClients) -> Self {
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
        let github = !platform
            && front_door_hosts(clients)
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
    let entry = |slot, placeholder: CredentialPlaceholder| v1::SeedCredentialPlaceholder {
        slot,
        placeholder: placeholder.as_str().to_owned(),
    };
    let mut entries = Vec::new();
    if let Some(slot) = wanted.anthropic {
        let Ok([placeholder]) = <[_; 1]>::try_from(anthropic) else {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        };
        entries.push(entry(slot, placeholder));
    }
    match <[_; 1]>::try_from(github) {
        Ok([placeholder]) => entries.push(entry(GITHUB_SLOT, placeholder)),
        Err(none) if none.is_empty() => {}
        Err(_) => return Err(SupervisorError::EnvironmentAccessUnavailable),
    }
    Ok(entries)
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

    /// A platform profile's intercepting boot asks for no `github` slot,
    /// which the local authority would refuse and fail the boot with; its
    /// Anthropic slot is asked for as before (#4001).
    #[test]
    fn a_platform_boot_asks_for_no_github_slot() {
        let platform = WantedSlots::for_boot(true, true, clients(&["anthropic", "github"]));
        assert!(!platform.github);
        assert_eq!(platform.anthropic, Some(API_KEY_SLOT));
        assert_eq!(platform.slots(), vec![CapabilitySlot::anthropic()]);
        let github_only = WantedSlots::for_boot(true, true, clients(&["github"]));
        assert!(github_only.slots().is_empty());
    }

    /// GitHub's placeholder is asked for only when the boot would bind its
    /// hosts; a grant without one leaves GitHub out rather than failing the
    /// start, and a slot nobody asked for refuses it (#4001).
    #[test]
    fn the_github_slot_is_asked_for_only_while_its_hosts_would_be_bound() {
        let selected = clients(&["anthropic", "github"]);
        let off = WantedSlots::for_boot(false, false, selected);
        assert!(off.anthropic.is_none() && !off.github && off.slots().is_empty());
        let on = WantedSlots::for_boot(true, false, selected);
        assert_eq!(on.anthropic, Some(API_KEY_SLOT));
        assert!(on.github);
        assert!(!WantedSlots::for_boot(true, false, clients(&["anthropic"])).github);

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
}
