//! Workload secret metadata from the authority, checked as it arrives.

use codewire_workload_secrets::validate_workload_secret_key;
use tonic::Status;
use uuid::Uuid;

use super::data_loss;
use crate::control::v1;
use crate::{
    LocalSecretProject, ResolvedWorkloadSecretMetadata, WorkloadSecretMetadata,
    WorkloadSecretSource,
};

pub(super) fn secret_project_from_proto(
    value: v1::LocalSecretProject,
) -> Result<LocalSecretProject, Status> {
    let id = Uuid::parse_str(&value.id).map_err(data_loss)?;
    if id.is_nil()
        || id.to_string() != value.id
        || !valid_secret_project_name(&value.name)
        || value.updated_at_unix_ms < value.created_at_unix_ms
    {
        return Err(data_loss(()));
    }
    Ok(LocalSecretProject {
        id,
        name: value.name,
        secret_count: value.secret_count,
        created_at_unix_ms: value.created_at_unix_ms,
        updated_at_unix_ms: value.updated_at_unix_ms,
    })
}

pub(super) fn workload_secret_list_from_proto(
    value: v1::ListWorkloadSecretsResponse,
) -> Result<Vec<WorkloadSecretMetadata>, Status> {
    let secrets = value
        .secrets
        .into_iter()
        .map(workload_secret_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    if secrets.windows(2).any(|pair| pair[0].key >= pair[1].key) {
        return Err(data_loss(()));
    }
    Ok(secrets)
}

pub(super) fn workload_secret_from_proto(
    value: v1::WorkloadSecretMetadata,
) -> Result<WorkloadSecretMetadata, Status> {
    if !valid_workload_secret_key(&value.key) || value.updated_at_unix_ms < value.created_at_unix_ms
    {
        return Err(data_loss(()));
    }
    Ok(WorkloadSecretMetadata {
        key: value.key,
        created_at_unix_ms: value.created_at_unix_ms,
        updated_at_unix_ms: value.updated_at_unix_ms,
        protected_store_cleanup_pending: value.protected_store_cleanup_pending,
    })
}

pub(super) fn resolved_workload_secret_from_proto(
    value: v1::ResolvedWorkloadSecretMetadata,
) -> Result<ResolvedWorkloadSecretMetadata, Status> {
    let source = workload_secret_source_from_proto(value.source)?;
    let overridden_sources = value
        .overridden_sources
        .into_iter()
        .map(workload_secret_source_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    if !valid_workload_secret_key(&value.key)
        || overridden_sources
            .iter()
            .any(|overridden| *overridden >= source)
        || !overridden_sources.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(data_loss(()));
    }
    Ok(ResolvedWorkloadSecretMetadata {
        key: value.key,
        source,
        overridden_sources,
    })
}

fn workload_secret_source_from_proto(value: i32) -> Result<WorkloadSecretSource, Status> {
    match v1::WorkloadSecretSource::try_from(value) {
        Ok(v1::WorkloadSecretSource::Organization) => Ok(WorkloadSecretSource::Organization),
        Ok(v1::WorkloadSecretSource::Project) => Ok(WorkloadSecretSource::Project),
        Ok(v1::WorkloadSecretSource::User) => Ok(WorkloadSecretSource::User),
        Ok(v1::WorkloadSecretSource::ExplicitEnvironment) => {
            Ok(WorkloadSecretSource::ExplicitEnvironment)
        }
        Ok(v1::WorkloadSecretSource::Unspecified) | Err(_) => Err(data_loss(())),
    }
}

fn valid_secret_project_name(name: &str) -> bool {
    codewire_workload_secrets::validate_secret_project_name(name).is_ok()
}

pub(super) fn valid_workload_secret_key(key: &str) -> bool {
    validate_workload_secret_key(key).is_ok()
}
