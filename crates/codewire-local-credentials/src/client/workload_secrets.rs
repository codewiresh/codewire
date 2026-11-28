//! Workload secret metadata from the authority, checked as it arrives, and
//! a secret's write with its binding.

use codewire_access::StoredBinding;
use codewire_protected_store::ProtectedValue;
use codewire_workload_secrets::validate_workload_secret_key;
use tonic::Status;
use uuid::Uuid;

use super::{LocalCredentialClient, data_loss};
use crate::control::v1;
use crate::{
    BindingWrite, LocalSecretProject, ResolvedWorkloadSecretMetadata, WorkloadSecretMetadata,
    WorkloadSecretSource,
};

impl LocalCredentialClient {
    /// Set a personal secret's value, or with `None` only change its
    /// binding, and apply `binding`. An authority older than
    /// [`crate::AuthorityFeature::SecretBindings`] ignores the binding and
    /// refuses an empty value, so ask it only of one that serves it.
    pub async fn write_user_workload_secret(
        &mut self,
        key: String,
        value: Option<ProtectedValue>,
        binding: &BindingWrite,
    ) -> Result<WorkloadSecretMetadata, Status> {
        let (binding, plain) = binding_request(binding)?;
        workload_secret_from_proto(
            self.inner
                .set_user_workload_secret(v1::SetUserWorkloadSecretRequest {
                    key,
                    value: value_bytes(value),
                    binding,
                    plain,
                })
                .await?
                .into_inner(),
        )
    }

    /// [`Self::write_user_workload_secret`] for a project's secret.
    pub async fn write_project_workload_secret(
        &mut self,
        project_id: Uuid,
        key: String,
        value: Option<ProtectedValue>,
        binding: &BindingWrite,
    ) -> Result<WorkloadSecretMetadata, Status> {
        let (binding, plain) = binding_request(binding)?;
        workload_secret_from_proto(
            self.inner
                .set_project_workload_secret(v1::SetProjectWorkloadSecretRequest {
                    project_id: project_id.to_string(),
                    key,
                    value: value_bytes(value),
                    binding,
                    plain,
                })
                .await?
                .into_inner(),
        )
    }
}

fn value_bytes(value: Option<ProtectedValue>) -> Vec<u8> {
    value.map_or_else(Vec::new, |value| value.expose_secret().to_vec())
}

/// A write's `binding` and `plain` fields.
fn binding_request(binding: &BindingWrite) -> Result<(Option<String>, bool), Status> {
    match binding {
        BindingWrite::Keep => Ok((None, false)),
        BindingWrite::Plain => Ok((None, true)),
        BindingWrite::Bind(stored) => serde_json::to_string(stored)
            .map(|json| (Some(json), false))
            .map_err(|_| Status::invalid_argument("invalid secret binding")),
    }
}

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
    let binding = value
        .binding
        .as_deref()
        .map(serde_json::from_str::<StoredBinding>)
        .transpose()
        .map_err(data_loss)?;
    Ok(WorkloadSecretMetadata {
        key: value.key,
        created_at_unix_ms: value.created_at_unix_ms,
        updated_at_unix_ms: value.updated_at_unix_ms,
        protected_store_cleanup_pending: value.protected_store_cleanup_pending,
        binding,
        binding_generation: value.binding_generation,
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
