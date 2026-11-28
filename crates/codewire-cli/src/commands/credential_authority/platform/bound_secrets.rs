//! A platform boot's sealed record of its platform sources' bound secrets
//! (#4003): one unary call, as the selection's creator, with the selection
//! the boot's delegation opens with. The record and seal are carried back
//! unchanged; nothing of them is logged.

use codewire_access::{PlatformBootBinding, PlatformBootRecord, PlatformBootSecret};
use codewire_client::{
    ClientError, CodewireClient, CredentialDelegationOpen, EnvironmentBoundSecretsRequest,
    LocalBootBinding, LocalBootBoundSecret, LocalBootBoundSecrets,
};
use tonic::Status;

use super::client_error;

/// The platform's record, or `None` when it keeps none: one that predates
/// the question, or has no seal key, answers UNIMPLEMENTED.
pub(super) async fn ask(
    client: &CodewireClient,
    selection: CredentialDelegationOpen,
) -> Result<Option<PlatformBootRecord>, Status> {
    let response = match client
        .environment_bound_secrets(EnvironmentBoundSecretsRequest {
            selection: Some(selection).into(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response,
        Err(error) if error.code() == codewire_client::ErrorCode::Unimplemented => {
            return Ok(None);
        }
        Err(error) => return Err(record_error(error)),
    };
    let record = response.record.into_option().ok_or_else(|| {
        Status::internal("the platform answered no record of the boot's bound secrets")
    })?;
    Ok(Some(from_wire(record)))
}

/// The platform's rate limit keeps its code, as the seed's does; every
/// other failure maps as the delegation's does.
fn record_error(error: ClientError) -> Status {
    if error.code() == codewire_client::ErrorCode::ResourceExhausted {
        return Status::resource_exhausted("platform boot bound secrets rate limited");
    }
    client_error(error)
}

fn from_wire(record: LocalBootBoundSecrets) -> PlatformBootRecord {
    PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.into_option().map(|bound| PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    }
}

/// A boot's record as its delegation's Open carries it back.
pub(super) fn to_wire(record: &PlatformBootRecord) -> LocalBootBoundSecrets {
    LocalBootBoundSecrets {
        secrets: record
            .secrets
            .iter()
            .map(|secret| LocalBootBoundSecret {
                path: secret.path.clone(),
                key: secret.key.clone(),
                binding_generation: secret.binding_generation,
                bound: secret
                    .bound
                    .as_ref()
                    .map(|bound| LocalBootBinding {
                        binding_id: bound.binding_id.clone(),
                        prefix: bound.prefix.clone(),
                        hosts: bound.hosts.clone(),
                        ..Default::default()
                    })
                    .into(),
                ..Default::default()
            })
            .collect(),
        seal: record.seal.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_its_wire_form() {
        let record = PlatformBootRecord {
            secrets: vec![
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "FANCY_TOKEN".into(),
                    binding_generation: 2,
                    bound: Some(PlatformBootBinding {
                        binding_id: "00000000-0000-0000-0000-000000000007".into(),
                        prefix: Some("ft_".into()),
                        hosts: vec!["api.fancy.example".into()],
                    }),
                },
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "PLAIN_TOKEN".into(),
                    binding_generation: 1,
                    bound: None,
                },
            ],
            seal: "vault:v1:synthetic".into(),
        };
        assert_eq!(from_wire(to_wire(&record)), record);
    }
}
