//! What an ensure does with its generation's running broker: keeps it, has
//! it replaced, or is refused, decided from the running selection and the
//! one asked for.

use codewire_access::HttpProvider;

use super::*;

/// The running broker against an ensure's selection.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SelectionChange {
    /// The same selection: the running broker serves it.
    Same,
    /// A change that may happen within a generation: the running broker is
    /// stopped before its replacement starts, so a replacement that fails
    /// leaves none serving.
    Replace,
    /// Any other change, which waits for the next generation.
    Refused,
}

/// The sources an ensure asks for, beside its process config.
pub(super) struct Sources<'a> {
    pub(super) projection: &'a Option<crate::LocalEnvironmentProjectionBinding>,
    pub(super) platform: &'a Option<crate::PlatformCredentialBinding>,
    pub(super) local_profile: &'a Option<EnvironmentAccessBinding>,
}

/// Two parts of a selection may change while a generation runs: the network
/// policy's answers (#4926, #5555), and the providers, when they grow back to
/// what the pinned profile revision names (#5615). That is a credential that
/// was withheld at start, revoked, expired or needing reconnect, and has been
/// reconnected since. Everything else must be equal.
pub(super) async fn selection_change<S: ProtectedStore + 'static>(
    authority: &Arc<LocalCredentialAuthority<S>>,
    existing: &BrokerProcessEntry,
    config: &LocalBrokerProcessConfig,
    asked: Sources<'_>,
) -> Result<SelectionChange, Status> {
    let under_this_policy = LocalBrokerProcessConfig {
        network_policy_allows_github: config.network_policy_allows_github,
        network_policy_allowed_hosts: config.network_policy_allowed_hosts.clone(),
        http_providers: config.http_providers.clone(),
        ..existing.config.clone()
    };
    if under_this_policy != *config
        || existing.projection != *asked.projection
        || existing.platform != *asked.platform
        || existing.local_profile != *asked.local_profile
    {
        return Ok(SelectionChange::Refused);
    }
    if existing.config == *config {
        return Ok(SelectionChange::Same);
    }
    if existing.config.http_providers == config.http_providers {
        return Ok(SelectionChange::Replace);
    }
    let named = match asked.local_profile.clone() {
        Some(binding) => {
            let authority = Arc::clone(authority);
            run_blocking(move || named_providers(&authority, &binding)).await?
        }
        None => BTreeSet::new(),
    };
    Ok(
        if providers_grew(
            &existing.config.http_providers,
            &config.http_providers,
            &named,
        ) {
            SelectionChange::Replace
        } else {
            SelectionChange::Refused
        },
    )
}

/// The managed clients whose environment keys an ensure's projection
/// reserves: those of the pinned profile revision's slots, whatever their
/// credentials' state, and GitHub while it is granted. That is what the
/// supervisor configures the VM's clients from. From the grants alone, a
/// credential reconnected while the VM runs would change the projection, and
/// the ensure that replaces the broker for it (#5615) would be refused
/// (#6614). Without a local profile, the granted slots.
pub(super) async fn reserving_clients<S: ProtectedStore + 'static>(
    authority: &Arc<LocalCredentialAuthority<S>>,
    request: &BrokerEnsureRequest,
    granted: &BTreeSet<String>,
) -> Result<codewire_access::ManagedCredentialClients, Status> {
    let mut slots = match request.local_profile.clone() {
        Some(binding) => {
            let authority = Arc::clone(authority);
            run_blocking(move || {
                authority
                    .get_profile_revision(&binding.profile_id, binding.profile_revision)
                    .map(|revision| {
                        revision
                            .profile
                            .entries
                            .into_keys()
                            .map(|slot| slot.to_string())
                            .collect::<BTreeSet<_>>()
                    })
            })
            .await?
        }
        None => granted.clone(),
    };
    if granted.contains("github") {
        slots.insert("github".to_owned());
    }
    codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().map(String::as_str))
        .map_err(|_| Status::failed_precondition("invalid managed client selection"))
}

/// Whether `asked` only adds to `running`, and adds only providers the
/// pinned profile revision names (`named`). A set that shrinks or swaps a
/// provider is no growth: a revoked credential is refused at its lease, and
/// the running broker keeps serving the rest.
fn providers_grew(
    running: &BTreeSet<HttpProvider>,
    asked: &BTreeSet<HttpProvider>,
    named: &BTreeSet<HttpProvider>,
) -> bool {
    running.len() < asked.len() && running.is_subset(asked) && asked.is_subset(named)
}

/// Every provider the pinned profile revision names, whatever its
/// credentials' state: its entries' providers, and GitHub for a personal
/// profile. A credential deleted since names none.
fn named_providers<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    binding: &EnvironmentAccessBinding,
) -> Result<BTreeSet<HttpProvider>, LocalCredentialError> {
    let profile = authority
        .get_profile_revision(&binding.profile_id, binding.profile_revision)?
        .profile;
    let mut named = BTreeSet::new();
    for (slot, id) in &profile.entries {
        match authority.get_credential(id) {
            Ok(credential) => {
                named.extend(HttpProvider::for_credential(slot, &credential.metadata))
            }
            Err(LocalCredentialError::CredentialNotFound) => {}
            Err(error) => return Err(error),
        }
    }
    if profile.includes_github() {
        named.insert(HttpProvider::GitHubOAuth);
    }
    Ok(named)
}

#[cfg(test)]
#[path = "broker_selection_tests.rs"]
mod tests;
