//! Fixed-role, names-only inventory conversion. Framing is not source
//! authorization: each producer still checks its own exact selected scopes.

use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRETS, ProjectionContributor, ProjectionSourceInventory, WorkloadSecretSource,
    validate_workload_secret_key,
};

use crate::codewire::bridge::v1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidProjectionInventory;

pub fn decode_local_inventories(
    values: &[v1::EnvironmentProjectionInventory],
) -> Result<Vec<ProjectionSourceInventory>, InvalidProjectionInventory> {
    decode(values, ProjectionContributor::Local)
}

pub fn decode_platform_inventories(
    values: &[v1::EnvironmentProjectionInventory],
) -> Result<Vec<ProjectionSourceInventory>, InvalidProjectionInventory> {
    decode(values, ProjectionContributor::Platform)
}

pub fn encode_local_inventories(
    values: &[ProjectionSourceInventory],
) -> Result<Vec<v1::EnvironmentProjectionInventory>, InvalidProjectionInventory> {
    encode(values, ProjectionContributor::Local)
}

pub fn encode_platform_inventories(
    values: &[ProjectionSourceInventory],
) -> Result<Vec<v1::EnvironmentProjectionInventory>, InvalidProjectionInventory> {
    encode(values, ProjectionContributor::Platform)
}

fn decode(
    values: &[v1::EnvironmentProjectionInventory],
    contributor: ProjectionContributor,
) -> Result<Vec<ProjectionSourceInventory>, InvalidProjectionInventory> {
    if values.is_empty() || values.len() > 3 {
        return Err(InvalidProjectionInventory);
    }
    let mut previous = None;
    values
        .iter()
        .map(|value| {
            let source = match v1::EnvironmentProjectionSource::try_from(value.source) {
                Ok(v1::EnvironmentProjectionSource::Organization)
                    if contributor == ProjectionContributor::Platform =>
                {
                    WorkloadSecretSource::Organization
                }
                Ok(v1::EnvironmentProjectionSource::Project) => WorkloadSecretSource::Project,
                Ok(v1::EnvironmentProjectionSource::User) => WorkloadSecretSource::User,
                _ => return Err(InvalidProjectionInventory),
            };
            if previous.is_some_and(|previous| previous >= source)
                || value.source_identity.is_empty()
                || value.source_identity.len() > 512
                || value.source_identity.trim() != value.source_identity
                || value.source_identity.chars().any(char::is_control)
                || value.keys.len() > MAX_WORKLOAD_SECRETS
                || value.keys.windows(2).any(|pair| pair[0] >= pair[1])
                || value
                    .keys
                    .iter()
                    .any(|key| validate_workload_secret_key(key).is_err())
            {
                return Err(InvalidProjectionInventory);
            }
            previous = Some(source);
            Ok(ProjectionSourceInventory {
                contributor,
                source,
                source_identity: value.source_identity.clone(),
                keys: value.keys.iter().cloned().collect(),
            })
        })
        .collect()
}

fn encode(
    values: &[ProjectionSourceInventory],
    contributor: ProjectionContributor,
) -> Result<Vec<v1::EnvironmentProjectionInventory>, InvalidProjectionInventory> {
    if values.is_empty() || values.len() > 3 {
        return Err(InvalidProjectionInventory);
    }
    let mut encoded = Vec::with_capacity(values.len());
    for value in values {
        if value.contributor != contributor
            || value.keys.len() > MAX_WORKLOAD_SECRETS
            || value.source_identity.len() > 512
        {
            return Err(InvalidProjectionInventory);
        }
        let source = match value.source {
            WorkloadSecretSource::Organization => v1::EnvironmentProjectionSource::Organization,
            WorkloadSecretSource::Project => v1::EnvironmentProjectionSource::Project,
            WorkloadSecretSource::User => v1::EnvironmentProjectionSource::User,
            WorkloadSecretSource::ExplicitEnvironment => return Err(InvalidProjectionInventory),
        };
        encoded.push(v1::EnvironmentProjectionInventory {
            source: source as i32,
            source_identity: value.source_identity.clone(),
            keys: value.keys.iter().cloned().collect(),
        });
    }
    // Exactly the receiver's canonical validation; never normalize a bad sender.
    decode(&encoded, contributor)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests;
