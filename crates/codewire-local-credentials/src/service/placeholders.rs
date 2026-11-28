//! The authority's answer to a boot that intercepts its agent hosts: the
//! environment's credential placeholders for its seed (#3999). A boot whose
//! credentials come from the platform is answered by the platform (#4001).

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{CapabilitySlot, EnvironmentAccessBinding, EnvironmentId};
use codewire_protected_store::ProtectedStore;
use tonic::Status;

use super::{
    BrokerProcessManager, environment_id, profile_id, run_blocking, status_for_access_error,
};
use crate::control::v1;

/// The most slots one request names: every slot a profile can select.
const MAX_REQUESTED_SLOTS: usize = 16;
/// The whole platform question, its connection included, so it fits the
/// boot's start budget (#4001).
const PLATFORM_PLACEHOLDERS_DEADLINE: Duration = Duration::from_secs(10);

pub(super) async fn environment_credential_placeholders<S: ProtectedStore + 'static>(
    brokers: Arc<BrokerProcessManager<S>>,
    request: v1::GetEnvironmentCredentialPlaceholdersRequest,
) -> Result<v1::GetEnvironmentCredentialPlaceholdersResponse, Status> {
    let environment_id = environment_id(request.environment_id)?;
    if request.environment_generation == 0 {
        return Err(Status::invalid_argument("invalid environment generation"));
    }
    if request.capability_slots.len() > MAX_REQUESTED_SLOTS {
        return Err(Status::invalid_argument("too many capability slots"));
    }
    let slots = request
        .capability_slots
        .into_iter()
        .map(|slot| CapabilitySlot::parse(slot).map_err(status_for_access_error))
        .collect::<Result<Vec<_>, Status>>()?;
    let generation = request.environment_generation;
    let placeholders = match request.platform {
        Some(platform) => {
            if !request.profile_id.is_empty() || request.profile_revision != 0 {
                return Err(Status::invalid_argument(
                    "a platform binding names no local profile",
                ));
            }
            platform_placeholders(&brokers, environment_id, generation, platform, slots).await?
        }
        None => {
            if request.profile_revision == 0 {
                return Err(Status::invalid_argument("invalid profile revision"));
            }
            let selected = EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile_id(request.profile_id)?,
                profile_revision: request.profile_revision,
            };
            let authority = Arc::clone(&brokers.authority);
            run_blocking(move || {
                authority.environment_slot_placeholders(
                    &environment_id,
                    generation,
                    &selected,
                    &slots,
                )
            })
            .await?
        }
    };
    Ok(v1::GetEnvironmentCredentialPlaceholdersResponse {
        placeholders: placeholders
            .into_iter()
            .map(|(slot, placeholder)| v1::EnvironmentCredentialPlaceholder {
                capability_slot: slot.as_str().to_owned(),
                placeholder: placeholder.as_str().to_owned(),
            })
            .collect(),
    })
}

/// A platform boot's placeholders, asked of the platform as its selection's
/// creator. The environment must be one a platform broker start would
/// admit: it has no local profile binding, as for the GitHub question. One
/// deadline covers the whole question.
async fn platform_placeholders<S: ProtectedStore + 'static>(
    brokers: &BrokerProcessManager<S>,
    environment_id: EnvironmentId,
    generation: u64,
    platform: v1::PlatformCredentialBinding,
    slots: Vec<CapabilitySlot>,
) -> Result<Vec<(CapabilitySlot, codewire_access::CredentialPlaceholder)>, Status> {
    let deadline = tokio::time::Instant::now() + PLATFORM_PLACEHOLDERS_DEADLINE;
    let binding = crate::PlatformCredentialBinding::from_proto(platform)?;
    binding.validate()?;
    let authority = Arc::clone(&brokers.authority);
    let connector = brokers.platform_connector.clone();
    tokio::time::timeout_at(deadline, async move {
        let id = environment_id.clone();
        run_blocking(move || authority.evaluate_selected_environment_grants(&id, generation, None))
            .await?;
        let connector = connector.ok_or_else(|| {
            Status::unavailable("native platform credential connector is unavailable")
        })?;
        connector
            .environment_credential_placeholders(
                binding,
                environment_id.to_string(),
                generation,
                slots,
                deadline,
            )
            .await
    })
    .await
    .map_err(|_| Status::deadline_exceeded("platform credential placeholders timed out"))?
}

/// A platform boot's sealed record of its platform sources' bound secrets
/// (#4003), asked of the platform as its selection's creator for an
/// environment a platform broker start would admit, under the same deadline
/// as its seed placeholders. A platform that keeps no record gives none.
pub(super) async fn platform_boot_bound_secrets<S: ProtectedStore + 'static>(
    brokers: Arc<BrokerProcessManager<S>>,
    request: v1::GetPlatformBootBoundSecretsRequest,
) -> Result<v1::GetPlatformBootBoundSecretsResponse, Status> {
    let environment_id = environment_id(request.environment_id)?;
    let generation = request.environment_generation;
    if generation == 0 {
        return Err(Status::invalid_argument("invalid environment generation"));
    }
    let platform = request
        .platform
        .ok_or_else(|| Status::invalid_argument("a platform boot names its binding"))?;
    let deadline = tokio::time::Instant::now() + PLATFORM_PLACEHOLDERS_DEADLINE;
    let binding = crate::PlatformCredentialBinding::from_proto(platform)?;
    binding.validate()?;
    if binding.boot_record.is_some() {
        return Err(Status::invalid_argument(
            "a boot's record question carries no record",
        ));
    }
    let authority = Arc::clone(&brokers.authority);
    let connector = brokers.platform_connector.clone();
    let record = tokio::time::timeout_at(deadline, async move {
        let id = environment_id.clone();
        run_blocking(move || authority.evaluate_selected_environment_grants(&id, generation, None))
            .await?;
        let connector = connector.ok_or_else(|| {
            Status::unavailable("native platform credential connector is unavailable")
        })?;
        connector
            .environment_bound_secrets(binding, environment_id.to_string(), generation, deadline)
            .await
    })
    .await
    .map_err(|_| Status::deadline_exceeded("platform boot bound secrets timed out"))??;
    Ok(v1::GetPlatformBootBoundSecretsResponse {
        record: record.map(crate::platform::boot_record_to_proto),
    })
}

#[cfg(test)]
mod tests;
