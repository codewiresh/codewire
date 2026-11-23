//! The refusals of a create from a snapshot or a VM checkpoint that its
//! request alone decides, checked before it is journaled.

use super::*;

/// Every refusal a restore's request can meet before it is journaled.
pub(super) fn admit_restore_request(
    row: &SnapshotRow,
    manifest: &Manifest,
    request: &v1::CreateEnvironmentRequest,
) -> Result<(), Status> {
    let restore = request
        .snapshot
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("the create names no snapshot"))?;
    let name = &row.name;
    // A fork of a VM checkpoint creates through this path too.
    let (kind, flag) = if manifest.checkpoint.is_some() {
        ("VM checkpoint", "--checkpoint")
    } else {
        ("snapshot", "--snapshot")
    };
    let native = crate::oci::OciArchitecture::native()
        .map(|architecture| architecture.as_str())
        .unwrap_or("unknown");
    if manifest.architecture != native {
        return Err(Status::failed_precondition(format!(
            "{kind} {name} holds {} disks, and this host runs {native}",
            manifest.architecture
        )));
    }
    if !valid_restore_resources(restore.vcpus, restore.memory_mib) {
        return Err(Status::invalid_argument(
            "a restore takes 1 to 32 vCPUs and 128 to 65536 MiB of memory",
        ));
    }
    if manifest.checkpoint.is_some() {
        // A memory image cannot change shape.
        if restore.vcpus != u32::from(manifest.resources.vcpus)
            || restore.memory_mib != manifest.resources.memory_mib
        {
            return Err(Status::invalid_argument(format!(
                "a fork of VM checkpoint {name} has its {} vCPUs and {} MiB of memory",
                manifest.resources.vcpus, manifest.resources.memory_mib
            )));
        }
        // Before anything is journaled, so no fork is made (#5976).
        crate::supervisor::checkpoints::local::require_unlocked(name, "forked")?;
    }
    // The built root accepts only its own project, sources aside.
    manifest
        .root_generation
        .validate_for_project_intent(&request.project_spec_json, &request.project_spec_sha256)
        .map_err(|_| {
            Status::failed_precondition(format!(
                "the create does not name {kind} {name}'s project; create from it with `cw create --local {flag} {name}`"
            ))
        })?;
    let project: codewire_project::ProjectSpec = serde_json::from_slice(&request.project_spec_json)
        .map_err(|_| Status::invalid_argument("the project is not valid JSON"))?;
    validate_request_workspace_plan(request, &project, &manifest.workspace_plan).map_err(|_| {
        Status::failed_precondition(format!(
            "the create does not name {kind} {name}'s workspace inputs exactly"
        ))
    })?;
    if request.docker_disk_bytes != manifest.resources.docker_disk_bytes {
        return Err(Status::failed_precondition(format!(
            "{kind} {name}'s Docker disk is {} bytes; a restore keeps it",
            manifest.resources.docker_disk_bytes
        )));
    }
    let direct = manifest
        .workspace_plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            WorkspaceInput::Direct { source_path, .. } => {
                Some(String::from_utf8_lossy(source_path).into_owned())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !direct.is_empty() && !restore.share_mounts {
        return Err(Status::failed_precondition(format!(
            "{kind} {name}'s source mounts host folders directly ({}); an environment made from it mounts the same folders live, shared with every other one that does. Pass --share-mounts to accept that",
            direct.join(", ")
        )));
    }
    // Signed in to two different platform accounts: the snapshot's and this
    // restore's. With either side signed out, nothing is compared.
    let fresh = PlatformAccount::from_proto(restore.account.as_ref())?;
    if let (Some(recorded), Some(fresh)) = (manifest.platform_account.as_ref(), fresh.as_ref())
        && recorded != fresh
    {
        return Err(Status::permission_denied(format!(
            "{kind} {name} was captured while signed in to {} as user {} in organization {}, and this cw is signed in to {} as user {} in organization {}; sign in as its account (`cw login`) to create from it",
            recorded.server_url,
            recorded.user_id,
            recorded.organization_id,
            fresh.server_url,
            fresh.user_id,
            fresh.organization_id
        )));
    }
    Ok(())
}
