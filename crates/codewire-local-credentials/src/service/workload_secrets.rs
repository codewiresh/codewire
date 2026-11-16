//! Workload secret metadata to and from the wire.

use std::collections::BTreeSet;

use tonic::Status;

use crate::control::v1;
use crate::{
    LocalSecretProject, ResolvedWorkloadSecretMetadata, WorkloadSecretMetadata,
    WorkloadSecretSelection, WorkloadSecretSource,
};

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
) -> v1::WorkloadSecretMetadata {
    v1::WorkloadSecretMetadata {
        key: secret.key,
        created_at_unix_ms: secret.created_at_unix_ms,
        updated_at_unix_ms: secret.updated_at_unix_ms,
        protected_store_cleanup_pending: secret.protected_store_cleanup_pending,
    }
}

fn workload_secret_source_to_proto(source: WorkloadSecretSource) -> v1::WorkloadSecretSource {
    match source {
        WorkloadSecretSource::Organization => v1::WorkloadSecretSource::Organization,
        WorkloadSecretSource::Project => v1::WorkloadSecretSource::Project,
        WorkloadSecretSource::User => v1::WorkloadSecretSource::User,
        WorkloadSecretSource::ExplicitEnvironment => v1::WorkloadSecretSource::ExplicitEnvironment,
    }
}

pub(super) fn resolved_secret_to_proto(
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

pub(super) fn workload_secret_selection_from_proto(
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
