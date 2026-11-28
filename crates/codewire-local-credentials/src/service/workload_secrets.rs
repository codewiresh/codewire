//! Workload secret metadata to and from the wire, and a secret's write with
//! its binding.

use std::collections::BTreeSet;
use std::mem;
use std::sync::Arc;

use codewire_access::{HOST_BOUND_SECRETS, StoredBinding};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use tonic::{Response, Status};
use uuid::Uuid;

use super::run_blocking;
use crate::control::v1;
use crate::{
    BindingWrite, LocalCredentialAuthority, LocalSecretProject, ResolvedWorkloadSecretMetadata,
    WorkloadSecretMetadata, WorkloadSecretSelection, WorkloadSecretSource,
};

/// A write's value and binding, taken out of its request so the request's
/// own buffer is zeroized when it drops. An empty value is none: only a
/// change to a bound secret that needs no value is accepted without one.
fn write_parts(
    value: &mut Vec<u8>,
    binding: Option<String>,
    plain: bool,
) -> Result<(Option<ProtectedValue>, BindingWrite), Status> {
    let binding = match (binding, plain) {
        (Some(_), true) => {
            return Err(Status::invalid_argument(
                "a write binds a secret to hosts or makes it plain, not both",
            ));
        }
        (Some(json), false) => BindingWrite::Bind(
            serde_json::from_str::<StoredBinding>(&json)
                .map_err(|_| Status::invalid_argument("invalid secret binding"))?,
        ),
        (None, true) => BindingWrite::Plain,
        (None, false) => BindingWrite::Keep,
    };
    let value = if value.is_empty() {
        None
    } else {
        Some(
            ProtectedValue::new(mem::take(value))
                .map_err(|_| Status::invalid_argument("invalid workload-secret value"))?,
        )
    };
    Ok((value, binding))
}

pub(super) async fn set_user<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    mut request: v1::SetUserWorkloadSecretRequest,
) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
    let key = mem::take(&mut request.key);
    let (value, binding) = write_parts(&mut request.value, request.binding.take(), request.plain)?;
    let secret = run_blocking(move || {
        authority.write_user_workload_secret(&key, value, binding, HOST_BOUND_SECRETS)
    })
    .await?;
    Ok(Response::new(workload_secret_to_proto(secret)?))
}

pub(super) async fn set_project<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    project_id: Uuid,
    request: &mut v1::SetProjectWorkloadSecretRequest,
) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
    let key = mem::take(&mut request.key);
    let (value, binding) = write_parts(&mut request.value, request.binding.take(), request.plain)?;
    let secret = run_blocking(move || {
        authority.write_project_workload_secret(
            project_id,
            &key,
            value,
            binding,
            HOST_BOUND_SECRETS,
        )
    })
    .await?;
    Ok(Response::new(workload_secret_to_proto(secret)?))
}

pub(super) fn secret_project_to_proto(project: LocalSecretProject) -> v1::LocalSecretProject {
    v1::LocalSecretProject {
        id: project.id.to_string(),
        name: project.name,
        secret_count: project.secret_count,
        created_at_unix_ms: project.created_at_unix_ms,
        updated_at_unix_ms: project.updated_at_unix_ms,
    }
}

pub(super) fn workload_secret_to_proto(
    secret: WorkloadSecretMetadata,
) -> Result<v1::WorkloadSecretMetadata, Status> {
    let binding = secret
        .binding
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| Status::internal("local workload-secret binding is invalid"))?;
    Ok(v1::WorkloadSecretMetadata {
        key: secret.key,
        created_at_unix_ms: secret.created_at_unix_ms,
        updated_at_unix_ms: secret.updated_at_unix_ms,
        protected_store_cleanup_pending: secret.protected_store_cleanup_pending,
        binding,
        binding_generation: secret.binding_generation,
    })
}

fn workload_secret_source_to_proto(source: WorkloadSecretSource) -> v1::WorkloadSecretSource {
    match source {
        WorkloadSecretSource::Organization => v1::WorkloadSecretSource::Organization,
        WorkloadSecretSource::Project => v1::WorkloadSecretSource::Project,
        WorkloadSecretSource::User => v1::WorkloadSecretSource::User,
        WorkloadSecretSource::ExplicitEnvironment => v1::WorkloadSecretSource::ExplicitEnvironment,
    }
}

pub(super) async fn resolve<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    request: v1::ResolveWorkloadSecretMetadataRequest,
) -> Result<Response<v1::ResolveWorkloadSecretMetadataResponse>, Status> {
    let selection = workload_secret_selection_from_proto(
        request
            .selection
            .ok_or_else(|| Status::invalid_argument("workload-secret selection is required"))?,
    )?;
    let secrets =
        run_blocking(move || authority.resolve_workload_secret_metadata(&selection)).await?;
    Ok(Response::new(v1::ResolveWorkloadSecretMetadataResponse {
        secrets: secrets.into_iter().map(resolved_secret_to_proto).collect(),
    }))
}

/// What a local VM's boot records of its bound secrets (#4003), read from
/// exactly the local sources its projection selects. A selection that
/// doesn't read is refused, and the boot with it: recording none in its
/// place would let a secret bound now be projected raw once made plain.
pub(super) async fn record_boot<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    request: v1::RecordBootBoundSecretsRequest,
) -> Result<Response<v1::BootBoundSecrets>, Status> {
    let projection = crate::LocalEnvironmentProjectionBinding::from_proto(
        request
            .projection
            .ok_or_else(|| Status::invalid_argument("a boot's projection is required"))?,
    )?;
    let record =
        run_blocking(move || authority.record_boot_bound_secrets(&projection.selection)).await?;
    Ok(Response::new(v1::BootBoundSecrets {
        secrets: record
            .into_iter()
            .map(crate::broker_channel::record_to_proto)
            .collect(),
    }))
}

fn resolved_secret_to_proto(
    secret: ResolvedWorkloadSecretMetadata,
) -> v1::ResolvedWorkloadSecretMetadata {
    v1::ResolvedWorkloadSecretMetadata {
        key: secret.key,
        source: workload_secret_source_to_proto(secret.source) as i32,
        overridden_sources: secret
            .overridden_sources
            .into_iter()
            .map(|source| workload_secret_source_to_proto(source) as i32)
            .collect(),
    }
}

fn workload_secret_selection_from_proto(
    selection: v1::WorkloadSecretSelection,
) -> Result<WorkloadSecretSelection, Status> {
    let explicit_environment_keys = selection
        .explicit_environment_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if explicit_environment_keys.len() != selection.explicit_environment_keys.len() {
        return Err(Status::invalid_argument(
            "duplicate explicit environment key",
        ));
    }
    Ok(WorkloadSecretSelection {
        organization: selection.organization,
        project: selection.project,
        user: selection.user,
        explicit_environment_keys,
    })
}
