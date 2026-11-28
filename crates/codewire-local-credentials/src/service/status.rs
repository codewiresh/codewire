//! What the authority answers, as an RPC status, for each of its errors.

use codewire_access::{AccessError, BindingError};
use tonic::Status;
use tonic::metadata::MetadataValue;

use crate::{LocalCredentialError, STORE_REFUSAL_PROVIDERS_KEY, StoreRefusal};

pub(super) fn status_for_access_error(_error: AccessError) -> Status {
    Status::invalid_argument("invalid local credential request")
}

pub(super) fn status_for_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::StaleCredentialRevision => {
            StoreRefusal::RevisionChanged.attach(Status::failed_precondition(
                "local credential revision changed; inspect before retrying",
            ))
        }
        LocalCredentialError::AlreadyExists => {
            Status::already_exists("local credential record already exists")
        }
        LocalCredentialError::EnvironmentBindingAlreadyExists => {
            Status::already_exists("local environment access binding already exists")
        }
        LocalCredentialError::GitHubAlreadyConnected => StoreRefusal::GithubAlreadyConnected
            .attach(Status::already_exists(
                "a local GitHub connection already exists; reconnect or delete it",
            )),
        LocalCredentialError::CredentialAddInProgress => StoreRefusal::CredentialAddInProgress
            .attach(Status::already_exists(
                "an add of this local credential is still in progress; wait for it to finish",
            )),
        LocalCredentialError::CredentialAddUnfinished => StoreRefusal::CredentialAddUnfinished
            .attach(Status::already_exists(
                "an earlier add of this local credential never finished saving",
            )),
        LocalCredentialError::AmbiguousGitHubConnections => Status::failed_precondition(
            "local credential metadata has more than one active GitHub connection",
        ),
        LocalCredentialError::CredentialNameAmbiguous { providers } => {
            let mut status = StoreRefusal::CredentialNameAmbiguous.attach(
                Status::failed_precondition(
                    "local credential name matches more than one provider's credential",
                ),
            );
            let providers = providers
                .iter()
                .map(|provider| provider.as_str())
                .collect::<Vec<_>>()
                .join(",");
            // Provider ids are ASCII, so this never fails; a list it could not
            // carry is left off rather than guessed.
            if let Ok(value) = MetadataValue::try_from(providers) {
                status
                    .metadata_mut()
                    .insert(STORE_REFUSAL_PROVIDERS_KEY, value);
            }
            status
        }
        LocalCredentialError::CredentialNameReservesProvider => {
            StoreRefusal::CredentialNameReservesProvider.attach(Status::invalid_argument(
                "a new local credential name may not start with anthropic/, openai/, github/, ssh/ or google/",
            ))
        }
        LocalCredentialError::CredentialNotFound
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        | LocalCredentialError::SecretProjectNotFound
        | LocalCredentialError::WorkloadSecretNotFound => {
            Status::not_found("local credential record was not found")
        }
        LocalCredentialError::EnvironmentBindingNotFound => {
            Status::not_found("local environment access binding was not found")
        }
        LocalCredentialError::CredentialRefreshRateLimited { .. } => {
            Status::resource_exhausted("local credential refresh is rate-limited by the provider")
        }
        LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialWithheld(_)
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::WorkloadSecretMaterialMissing
        | LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialRefreshInProgress
        | LocalCredentialError::StaleCredentialRefresh
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProtectedEntryCollision
        | LocalCredentialError::OwnerMismatch
        | LocalCredentialError::ProtectedStoreMismatch
        | LocalCredentialError::UnsupportedSchema
        | LocalCredentialError::InvalidDatabase
        | LocalCredentialError::CorruptMetadata
        | LocalCredentialError::StoreCallInTransaction => {
            Status::failed_precondition("local credential operation cannot be applied")
        }
        // Both are the user's to resolve, so say what holds the record.
        LocalCredentialError::CredentialInUse => Status::failed_precondition(
            "local credential is selected by an access profile or environment; unset it from the profile (cw credentials --local --profile NAME unset PROVIDER) or remove the environment first",
        ),
        LocalCredentialError::ProfileInUse => Status::failed_precondition(
            "local access profile is selected by an environment; remove the environment first",
        ),
        LocalCredentialError::ProfileIsDefault => Status::failed_precondition(
            "local access profile is your default credential profile and cannot be deleted; make another profile the default first: cw credentials --local profiles default NAME",
        ),
        LocalCredentialError::SshCredentialRequiresEnrollment => Status::failed_precondition(
            "SSH credentials require the dedicated enrollment operation",
        ),
        LocalCredentialError::SshEnrollmentClosed => {
            Status::unavailable("local SSH credential enrollment is stopping")
        }
        LocalCredentialError::SshEnrollmentDeadlineElapsed => {
            Status::deadline_exceeded("local SSH credential enrollment timed out")
        }
        // AccessError is deliberately material-free and carries the stable
        // provider/profile diagnostic needed to repair a rejected selection.
        LocalCredentialError::Access(error) => Status::failed_precondition(error.to_string()),
        LocalCredentialError::ProtectedStore(error) => super::store_status::status(error),
        LocalCredentialError::DatabaseUnavailable
        | LocalCredentialError::ProtectedStoreSwitch(_) => {
            Status::unavailable("local credential authority storage is unavailable")
        }
        LocalCredentialError::AlreadyRunning => {
            Status::already_exists("local credential authority is already running")
        }
        LocalCredentialError::UnsupportedPlatform => {
            Status::unimplemented("local credential authority is unsupported")
        }
        LocalCredentialError::OrganizationSecretsUnsupported => {
            Status::unimplemented("organization workload secrets are unsupported locally")
        }
        LocalCredentialError::InvalidWorkloadSecret => {
            Status::invalid_argument("invalid local workload-secret request")
        }
        LocalCredentialError::HostBoundSecretsUnavailable => StoreRefusal::HostBoundSecretsUnavailable
            .attach(Status::failed_precondition(error.to_string())),
        LocalCredentialError::SecretValueRequired(_) => {
            StoreRefusal::SecretValueRequired.attach(Status::invalid_argument(error.to_string()))
        }
        LocalCredentialError::BoundSecretUnprojectable(_)
        | LocalCredentialError::BoundSecretUnrecorded(_) => {
            Status::failed_precondition(error.to_string())
        }
        LocalCredentialError::BoundSecretRename => {
            StoreRefusal::SecretBoundRename.attach(Status::failed_precondition(error.to_string()))
        }
        // A local store has no deployment, so it reserves no name of its own
        // and never refuses `bound_host_reserved`.
        LocalCredentialError::SecretBinding(binding) => match binding {
            BindingError::ProviderHost(_) => StoreRefusal::BoundHostProvider,
            _ => StoreRefusal::SecretBindingInvalid,
        }
        .attach(Status::invalid_argument(binding.to_string())),
        LocalCredentialError::InvalidDatabasePath | LocalCredentialError::InvalidTime => {
            Status::internal("local credential authority state is invalid")
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    /// The error and its status write the prefixes out; both name exactly
    /// the providers a name is unique within.
    #[test]
    fn a_name_reserving_a_provider_is_refused_naming_every_provider() {
        let expected = format!(
            "a new local credential name may not start with {}",
            codewire_access::credential_name_provider_prefixes()
        );
        assert_eq!(
            LocalCredentialError::CredentialNameReservesProvider.to_string(),
            expected
        );
        let status = status_for_error(LocalCredentialError::CredentialNameReservesProvider);
        assert_eq!(status.message(), expected);
    }

    #[test]
    fn a_record_in_use_says_what_holds_it() {
        let credential = status_for_error(LocalCredentialError::CredentialInUse);
        assert_eq!(credential.code(), tonic::Code::FailedPrecondition);
        assert!(
            credential
                .message()
                .contains("selected by an access profile or environment")
        );
        assert!(
            credential
                .message()
                .contains("--profile NAME unset PROVIDER")
        );
        let profile = status_for_error(LocalCredentialError::ProfileInUse);
        assert_eq!(profile.code(), tonic::Code::FailedPrecondition);
        assert!(profile.message().contains("selected by an environment"));
        // Internal states stay undisclosed.
        let corrupt = status_for_error(LocalCredentialError::CorruptMetadata);
        assert_eq!(
            corrupt.message(),
            "local credential operation cannot be applied"
        );
    }

    #[test]
    fn an_ambiguous_name_lists_its_providers_and_no_ids() {
        let providers = ["anthropic", "openai"]
            .map(|provider| codewire_access::ProviderId::parse(provider).unwrap());
        let status = status_for_error(LocalCredentialError::CredentialNameAmbiguous {
            providers: providers.to_vec(),
        });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            crate::store_refusal_reason(&status),
            Some("CREDENTIAL_NAME_AMBIGUOUS")
        );
        assert_eq!(
            crate::store_refusal_providers(&status),
            ["anthropic", "openai"]
        );

        let reserved = status_for_error(LocalCredentialError::CredentialNameReservesProvider);
        assert_eq!(reserved.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            crate::store_refusal_reason(&reserved),
            Some("CREDENTIAL_NAME_RESERVES_PROVIDER")
        );
        assert!(crate::store_refusal_providers(&reserved).is_empty());
    }
}
