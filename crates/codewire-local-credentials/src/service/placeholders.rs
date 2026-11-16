//! The authority's answer to a boot that intercepts its agent hosts: the
//! environment's credential placeholders for its seed (#3999).

use std::sync::Arc;

use codewire_access::{CapabilitySlot, EnvironmentAccessBinding};
use codewire_protected_store::ProtectedStore;
use tonic::Status;

use super::{environment_id, profile_id, run_blocking, status_for_access_error};
use crate::LocalCredentialAuthority;
use crate::control::v1;

/// The most slots one request names: every slot a profile can select.
const MAX_REQUESTED_SLOTS: usize = 16;

pub(super) async fn environment_credential_placeholders<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    request: v1::GetEnvironmentCredentialPlaceholdersRequest,
) -> Result<v1::GetEnvironmentCredentialPlaceholdersResponse, Status> {
    let environment_id = environment_id(request.environment_id)?;
    if request.environment_generation == 0 || request.profile_revision == 0 {
        return Err(Status::invalid_argument(
            "invalid environment generation or profile revision",
        ));
    }
    if request.capability_slots.len() > MAX_REQUESTED_SLOTS {
        return Err(Status::invalid_argument("too many capability slots"));
    }
    let slots = request
        .capability_slots
        .into_iter()
        .map(|slot| CapabilitySlot::parse(slot).map_err(status_for_access_error))
        .collect::<Result<Vec<_>, Status>>()?;
    let selected = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile_id(request.profile_id)?,
        profile_revision: request.profile_revision,
    };
    let generation = request.environment_generation;
    let placeholders = run_blocking(move || {
        authority.environment_slot_placeholders(&environment_id, generation, &selected, &slots)
    })
    .await?;
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
