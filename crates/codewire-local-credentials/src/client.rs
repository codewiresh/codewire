use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Child;
use std::time::Duration;

use codewire_access::{
    AccessProfile, AccessProfileId, AccessProfileName, AccessProfileReference, AccessProfileScope,
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, CredentialId,
    CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentAccessBinding, EnvironmentId,
    GrantPermission, Owner, OwnerId, Placement, ProviderId,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedStorePersistence, ProtectedValue,
};
use tonic::Status;
use uuid::Uuid;

use crate::broker_channel::MAX_BROKER_LEASE_AUDIT_LIST_LIMIT;
use crate::control::v1::local_credential_authority_service_client::LocalCredentialAuthorityServiceClient;
use crate::control::v1::{self, CredentialAuthenticationKind};
use crate::repository::{MAX_GIT_BUNDLE_BYTES, valid_git_selector, validate_github_https_source};
use crate::service::auth_kind_to_proto;
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRuntimeConfig, AuthorityRuntimeError, connect_owner_only,
};
use crate::{
    AccessProfileRecord, AccessProfileRevisionRecord, BrokerLeaseAuditDecision,
    BrokerLeaseAuditEvent, CredentialRecord, EnvironmentAccessBindingRecord,
    EnvironmentBrokerRuntime, LOCAL_OWNER_ID, NewCredential,
};

const MAX_RPC_MESSAGE_BYTES: usize = MAX_PROTECTED_VALUE_BYTES + 64 * 1024;
const AUTHORITY_START_TIMEOUT: Duration = Duration::from_secs(10);

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityInfo {
    pub protocol_version: u32,
    pub protected_store_persistence: ProtectedStorePersistence,
}

#[derive(Clone)]
pub struct LocalCredentialClient {
    inner: LocalCredentialAuthorityServiceClient<tonic::transport::Channel>,
    info: AuthorityInfo,
}

/// Material-free authority client for lifecycle supervisors.
///
/// This deliberately exposes only exact environment/profile binding controls.
/// The VM supervisor cannot use this type to submit or retrieve provider
/// material, mutate credentials, or edit access profiles.
#[derive(Clone)]
pub struct LocalCredentialControlClient {
    inner: LocalCredentialAuthorityServiceClient<tonic::transport::Channel>,
    info: AuthorityInfo,
}

/// Credential-free output stream from one authority-owned repository
/// executor. The first response metadata is validated before this value is
/// constructed; subsequent items can contain Git bundle bytes only.
pub struct PreparedGitRepository {
    pub branch: String,
    pub commit: String,
    pub bundle_size: u64,
    remaining: u64,
    finished: bool,
    stream: tonic::Streaming<v1::PreparedGitRepositoryChunk>,
}

impl std::fmt::Debug for PreparedGitRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedGitRepository")
            .field("branch", &self.branch)
            .field("commit", &self.commit)
            .field("bundle_size", &self.bundle_size)
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl PreparedGitRepository {
    pub async fn next_bundle_chunk(&mut self) -> Result<Option<Vec<u8>>, Status> {
        if self.finished {
            return Ok(None);
        }
        let message = self.stream.message().await?;
        if self.remaining == 0 {
            self.finished = true;
            return if message.is_none() {
                Ok(None)
            } else {
                Err(Status::data_loss(
                    "local repository authority returned trailing output",
                ))
            };
        }
        let chunk = message.ok_or_else(|| {
            Status::data_loss("local repository authority returned a truncated bundle")
        })?;
        let Some(v1::prepared_git_repository_chunk::Value::Bundle(bytes)) = chunk.value else {
            return Err(Status::data_loss(
                "local repository authority returned invalid chunk ordering",
            ));
        };
        let length = u64::try_from(bytes.len())
            .map_err(|_| Status::data_loss("local repository bundle chunk is invalid"))?;
        if bytes.is_empty() || length > self.remaining {
            return Err(Status::data_loss(
                "local repository authority returned an invalid bundle chunk",
            ));
        }
        self.remaining -= length;
        Ok(Some(bytes))
    }
}

impl std::fmt::Debug for LocalCredentialControlClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCredentialControlClient")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalCredentialClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCredentialClient")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl LocalCredentialClient {
    pub async fn connect_or_start_with<F>(
        config: &AuthorityRuntimeConfig,
        spawn: F,
    ) -> Result<Self, AuthorityRuntimeError>
    where
        F: FnOnce(&AuthorityRuntimeConfig) -> Result<Child, AuthorityRuntimeError>,
    {
        config.prepare_root()?;
        if socket_exists(config)? {
            match Self::connect(config).await {
                Ok(client) => return Ok(client),
                Err(AuthorityRuntimeError::ProtocolMismatch) => {
                    shutdown_incompatible_authority(config).await?;
                }
                Err(AuthorityRuntimeError::Connect) => {}
                Err(error) => return Err(error),
            }
        }

        let mut child = spawn(config)?;
        let mut child_exited = false;
        let deadline = tokio::time::Instant::now() + AUTHORITY_START_TIMEOUT;
        loop {
            if socket_exists(config)? {
                match Self::connect(config).await {
                    Ok(client) => return Ok(client),
                    Err(AuthorityRuntimeError::Connect) => {}
                    Err(error) => {
                        terminate_unadmitted_child(&mut child);
                        return Err(error);
                    }
                }
            }
            if !child_exited {
                child_exited = child
                    .try_wait()
                    .map_err(|_| AuthorityRuntimeError::Spawn)?
                    .is_some();
            }
            if tokio::time::Instant::now() >= deadline {
                if child_exited {
                    return Err(AuthorityRuntimeError::Spawn);
                }
                terminate_unadmitted_child(&mut child);
                return Err(AuthorityRuntimeError::StartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Return newest-first, process-lifetime broker lease decisions. The
    /// bounded local ring contains identifiers and policy metadata only.
    pub async fn list_recent_broker_lease_audit_events(
        &mut self,
        limit: usize,
    ) -> Result<Vec<BrokerLeaseAuditEvent>, Status> {
        if !(1..=MAX_BROKER_LEASE_AUDIT_LIST_LIMIT).contains(&limit) {
            return Err(Status::invalid_argument("invalid broker audit list limit"));
        }
        let response = self
            .inner
            .list_recent_broker_lease_audit_events(v1::ListRecentBrokerLeaseAuditEventsRequest {
                limit: limit as u32,
            })
            .await?
            .into_inner();
        let events = response
            .events
            .into_iter()
            .map(broker_lease_audit_event_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        if events
            .windows(2)
            .any(|pair| pair[0].sequence <= pair[1].sequence)
        {
            return Err(Status::data_loss(
                "local credential authority returned invalid broker audit ordering",
            ));
        }
        Ok(events)
    }

    pub async fn connect(config: &AuthorityRuntimeConfig) -> Result<Self, AuthorityRuntimeError> {
        let channel = connect_owner_only(config).await?;
        let mut inner = LocalCredentialAuthorityServiceClient::new(channel)
            .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES);
        let response = inner
            .get_authority_info(v1::GetAuthorityInfoRequest {})
            .await
            .map_err(|_| AuthorityRuntimeError::Connect)?
            .into_inner();
        if response.protocol_version != AUTHORITY_PROTOCOL_VERSION {
            return Err(AuthorityRuntimeError::ProtocolMismatch);
        }
        let info = AuthorityInfo {
            protocol_version: response.protocol_version,
            protected_store_persistence: persistence_from_proto(
                response.protected_store_persistence,
            )
            .map_err(|_| AuthorityRuntimeError::ProtocolMismatch)?,
        };
        Ok(Self { inner, info })
    }

    pub fn info(&self) -> AuthorityInfo {
        self.info
    }

    pub async fn shutdown(mut self) -> Result<(), Status> {
        self.inner
            .shutdown_authority(v1::ShutdownAuthorityRequest {})
            .await?;
        Ok(())
    }

    pub async fn add_credential(
        &mut self,
        input: NewCredential,
        material: ProtectedValue,
    ) -> Result<CredentialRecord, Status> {
        let request = v1::AddCredentialRequest {
            provider: input.provider.to_string(),
            authentication_kind: auth_kind_to_proto(input.authentication_kind) as i32,
            display_name: input.display_name,
            account_hint: input.account_hint,
            expires_at_unix: input.expires_at_unix,
            material: material.expose_secret().to_vec(),
        };
        self.inner
            .add_credential(request)
            .await
            .and_then(|response| {
                credential_from_proto(response.into_inner()).map(tonic::Response::new)
            })
            .map(tonic::Response::into_inner)
    }

    pub async fn list_credentials(&mut self) -> Result<Vec<CredentialRecord>, Status> {
        self.inner
            .list_credentials(v1::ListCredentialsRequest {})
            .await?
            .into_inner()
            .credentials
            .into_iter()
            .map(credential_from_proto)
            .collect()
    }

    pub async fn get_credential(&mut self, id: &CredentialId) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .get_credential(credential_selector(id))
                .await?
                .into_inner(),
        )
    }

    pub async fn rename_credential(
        &mut self,
        id: &CredentialId,
        display_name: String,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .rename_credential(v1::RenameCredentialRequest {
                    credential_id: id.to_string(),
                    display_name,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn rotate_credential_material(
        &mut self,
        id: &CredentialId,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .rotate_credential_material(v1::RotateCredentialMaterialRequest {
                    credential_id: id.to_string(),
                    material: material.expose_secret().to_vec(),
                    expires_at_unix,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn revoke_credential(
        &mut self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .revoke_credential(credential_selector(id))
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_credential(&mut self, id: &CredentialId) -> Result<(), Status> {
        self.inner
            .delete_credential(credential_selector(id))
            .await?;
        Ok(())
    }

    pub async fn create_profile(
        &mut self,
        name: &AccessProfileName,
        entries: &BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .create_access_profile(v1::CreateAccessProfileRequest {
                    name: name.to_string(),
                    entries: profile_entries_to_proto(entries),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn update_profile(
        &mut self,
        id: &AccessProfileId,
        expected_revision: u64,
        entries: &BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .update_access_profile(v1::UpdateAccessProfileRequest {
                    profile_id: id.to_string(),
                    expected_revision,
                    entries: profile_entries_to_proto(entries),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_profiles(&mut self) -> Result<Vec<AccessProfileRecord>, Status> {
        self.inner
            .list_access_profiles(v1::ListAccessProfilesRequest {})
            .await?
            .into_inner()
            .profiles
            .into_iter()
            .map(profile_record_from_proto)
            .collect()
    }

    pub async fn get_profile(
        &mut self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .get_access_profile(profile_selector(id))
                .await?
                .into_inner(),
        )
    }

    pub async fn get_profile_revision(
        &mut self,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfileRevisionRecord, Status> {
        profile_revision_from_proto(
            self.inner
                .get_access_profile_revision(v1::GetAccessProfileRevisionRequest {
                    profile_id: id.to_string(),
                    revision,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_profile_revisions(
        &mut self,
        id: &AccessProfileId,
    ) -> Result<Vec<AccessProfileRevisionRecord>, Status> {
        self.inner
            .list_access_profile_revisions(v1::ListAccessProfileRevisionsRequest {
                profile_id: id.to_string(),
            })
            .await?
            .into_inner()
            .revisions
            .into_iter()
            .map(profile_revision_from_proto)
            .collect()
    }

    pub async fn resolve_profile(
        &mut self,
        reference: &AccessProfileReference,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .resolve_access_profile(v1::ResolveAccessProfileRequest {
                    reference: reference.to_string(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_profile(&mut self, id: &AccessProfileId) -> Result<(), Status> {
        self.inner
            .delete_access_profile(profile_selector(id))
            .await?;
        Ok(())
    }

    pub async fn create_environment_access_binding(
        &mut self,
        binding: &EnvironmentAccessBinding,
    ) -> Result<EnvironmentAccessBindingRecord, Status> {
        environment_binding_from_proto(
            self.inner
                .create_environment_access_binding(v1::CreateEnvironmentAccessBindingRequest {
                    environment_id: binding.environment_id.to_string(),
                    profile_id: binding.profile_id.to_string(),
                    profile_revision: binding.profile_revision,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn replace_environment_access_binding(
        &mut self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
        profile_id: &AccessProfileId,
        profile_revision: u64,
    ) -> Result<EnvironmentAccessBindingRecord, Status> {
        environment_binding_from_proto(
            self.inner
                .replace_environment_access_binding(v1::ReplaceEnvironmentAccessBindingRequest {
                    environment_id: environment_id.to_string(),
                    expected_profile_id: expected_profile_id.to_string(),
                    expected_profile_revision,
                    profile_id: profile_id.to_string(),
                    profile_revision,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn get_environment_access_binding(
        &mut self,
        environment_id: &EnvironmentId,
    ) -> Result<EnvironmentAccessBindingRecord, Status> {
        environment_binding_from_proto(
            self.inner
                .get_environment_access_binding(v1::EnvironmentAccessBindingSelector {
                    environment_id: environment_id.to_string(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_environment_access_bindings(
        &mut self,
    ) -> Result<Vec<EnvironmentAccessBindingRecord>, Status> {
        self.inner
            .list_environment_access_bindings(v1::ListEnvironmentAccessBindingsRequest {})
            .await?
            .into_inner()
            .bindings
            .into_iter()
            .map(environment_binding_from_proto)
            .collect()
    }

    pub async fn delete_environment_access_binding(
        &mut self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
    ) -> Result<(), Status> {
        self.inner
            .delete_environment_access_binding(v1::DeleteEnvironmentAccessBindingRequest {
                environment_id: environment_id.to_string(),
                expected_profile_id: expected_profile_id.to_string(),
                expected_profile_revision,
            })
            .await?;
        Ok(())
    }

    pub async fn evaluate_environment_grants(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
    ) -> Result<Vec<DerivedGrant>, Status> {
        self.inner
            .evaluate_environment_grants(v1::EvaluateEnvironmentGrantsRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
            })
            .await?
            .into_inner()
            .grants
            .into_iter()
            .map(derived_grant_from_proto)
            .collect()
    }
}

impl LocalCredentialControlClient {
    pub async fn connect(config: &AuthorityRuntimeConfig) -> Result<Self, AuthorityRuntimeError> {
        let client = LocalCredentialClient::connect(config).await?;
        Ok(Self {
            inner: client.inner,
            info: client.info,
        })
    }

    pub fn info(&self) -> AuthorityInfo {
        self.info
    }

    pub async fn prepare_git_repository(
        &mut self,
        request_id: Uuid,
        profile_id: &AccessProfileId,
        profile_revision: u64,
        source: String,
        branch: String,
        revision: String,
    ) -> Result<PreparedGitRepository, Status> {
        if request_id.is_nil()
            || profile_revision == 0
            || validate_github_https_source(&source).is_err()
            || (!branch.is_empty() && !valid_git_selector(&branch))
            || (!revision.is_empty() && !valid_git_selector(&revision))
            || (!branch.is_empty() && !revision.is_empty())
        {
            return Err(Status::invalid_argument(
                "invalid repository preparation request",
            ));
        }
        let mut stream = self
            .inner
            .prepare_git_repository(v1::PrepareGitRepositoryRequest {
                request_id: request_id.to_string(),
                profile_id: profile_id.to_string(),
                profile_revision,
                source,
                branch,
                revision,
            })
            .await?
            .into_inner();
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::data_loss("local repository authority returned no output"))?;
        let Some(v1::prepared_git_repository_chunk::Value::Metadata(metadata)) = first.value else {
            return Err(Status::data_loss(
                "local repository authority returned invalid chunk ordering",
            ));
        };
        if (!metadata.branch.is_empty() && !valid_git_selector(&metadata.branch))
            || !valid_object_id(&metadata.commit)
            || metadata.bundle_size == 0
            || metadata.bundle_size > MAX_GIT_BUNDLE_BYTES
        {
            return Err(Status::data_loss(
                "local repository authority returned invalid metadata",
            ));
        }
        Ok(PreparedGitRepository {
            branch: metadata.branch,
            commit: metadata.commit,
            bundle_size: metadata.bundle_size,
            remaining: metadata.bundle_size,
            finished: false,
            stream,
        })
    }

    pub async fn ensure_environment_access_binding(
        &mut self,
        binding: &EnvironmentAccessBinding,
        reference: &AccessProfileReference,
    ) -> Result<EnvironmentAccessBindingRecord, Status> {
        if reference.scope() != AccessProfileScope::User {
            return Err(Status::failed_precondition(
                "local environment access profile is unavailable",
            ));
        }
        let profile = profile_revision_from_proto(
            self.inner
                .get_access_profile_revision(v1::GetAccessProfileRevisionRequest {
                    profile_id: binding.profile_id.to_string(),
                    revision: binding.profile_revision,
                })
                .await?
                .into_inner(),
        )?;
        if profile.profile.name != *reference.name() {
            return Err(Status::failed_precondition(
                "local environment access profile does not match",
            ));
        }
        match self
            .get_environment_access_binding(&binding.environment_id)
            .await
        {
            Ok(record) if record.binding == *binding => return Ok(record),
            Ok(_) => {
                return Err(Status::failed_precondition(
                    "local environment access binding does not match",
                ));
            }
            Err(status) if status.code() == tonic::Code::NotFound => {}
            Err(status) => return Err(status),
        }

        match self
            .inner
            .create_environment_access_binding(v1::CreateEnvironmentAccessBindingRequest {
                environment_id: binding.environment_id.to_string(),
                profile_id: binding.profile_id.to_string(),
                profile_revision: binding.profile_revision,
            })
            .await
        {
            Ok(response) => environment_binding_from_proto(response.into_inner()),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {
                let record = self
                    .get_environment_access_binding(&binding.environment_id)
                    .await?;
                if record.binding == *binding {
                    Ok(record)
                } else {
                    Err(Status::failed_precondition(
                        "local environment access binding does not match",
                    ))
                }
            }
            Err(status) => Err(status),
        }
    }

    /// Applies one exact, compare-and-swap environment binding transition.
    ///
    /// The operation is safe to replay after either the authority mutation or
    /// the caller's journal checkpoint: observing the exact target is success,
    /// while any binding other than the recorded source or target fails
    /// closed. Profile material is never available through this client.
    pub async fn apply_environment_access_binding(
        &mut self,
        environment_id: &EnvironmentId,
        expected: Option<&EnvironmentAccessBinding>,
        target: Option<(&EnvironmentAccessBinding, &AccessProfileReference)>,
    ) -> Result<Option<EnvironmentAccessBindingRecord>, Status> {
        if expected.is_some_and(|binding| {
            binding.validate().is_err() || binding.environment_id != *environment_id
        }) || target.is_some_and(|(binding, _)| {
            binding.validate().is_err() || binding.environment_id != *environment_id
        }) {
            return Err(Status::invalid_argument(
                "invalid local environment access transition",
            ));
        }

        if let Some((binding, reference)) = target {
            if reference.scope() != AccessProfileScope::User {
                return Err(Status::failed_precondition(
                    "local environment access profile is unavailable",
                ));
            }
            let profile = profile_revision_from_proto(
                self.inner
                    .get_access_profile_revision(v1::GetAccessProfileRevisionRequest {
                        profile_id: binding.profile_id.to_string(),
                        revision: binding.profile_revision,
                    })
                    .await?
                    .into_inner(),
            )?;
            if profile.profile.name != *reference.name() {
                return Err(Status::failed_precondition(
                    "local environment access profile does not match",
                ));
            }
        }

        let current = match self.get_environment_access_binding(environment_id).await {
            Ok(current) => Some(current),
            Err(status) if status.code() == tonic::Code::NotFound => None,
            Err(status) => return Err(status),
        };
        if current.as_ref().map(|record| &record.binding) == target.map(|(binding, _)| binding) {
            return Ok(current);
        }
        if current.as_ref().map(|record| &record.binding) != expected {
            return Err(Status::failed_precondition(
                "local environment access binding does not match",
            ));
        }

        match target {
            Some((binding, _)) => match expected {
                Some(expected) => environment_binding_from_proto(
                    self.inner
                        .replace_environment_access_binding(
                            v1::ReplaceEnvironmentAccessBindingRequest {
                                environment_id: environment_id.to_string(),
                                expected_profile_id: expected.profile_id.to_string(),
                                expected_profile_revision: expected.profile_revision,
                                profile_id: binding.profile_id.to_string(),
                                profile_revision: binding.profile_revision,
                            },
                        )
                        .await?
                        .into_inner(),
                )
                .map(Some),
                None => environment_binding_from_proto(
                    self.inner
                        .create_environment_access_binding(
                            v1::CreateEnvironmentAccessBindingRequest {
                                environment_id: environment_id.to_string(),
                                profile_id: binding.profile_id.to_string(),
                                profile_revision: binding.profile_revision,
                            },
                        )
                        .await?
                        .into_inner(),
                )
                .map(Some),
            },
            None => {
                let expected = expected.ok_or_else(|| {
                    Status::failed_precondition("local environment access binding does not match")
                })?;
                self.inner
                    .delete_environment_access_binding(v1::DeleteEnvironmentAccessBindingRequest {
                        environment_id: environment_id.to_string(),
                        expected_profile_id: expected.profile_id.to_string(),
                        expected_profile_revision: expected.profile_revision,
                    })
                    .await?;
                Ok(None)
            }
        }
    }

    pub async fn get_environment_access_binding(
        &mut self,
        environment_id: &EnvironmentId,
    ) -> Result<EnvironmentAccessBindingRecord, Status> {
        environment_binding_from_proto(
            self.inner
                .get_environment_access_binding(v1::EnvironmentAccessBindingSelector {
                    environment_id: environment_id.to_string(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_environment_access_binding_if_present(
        &mut self,
        environment_id: &EnvironmentId,
    ) -> Result<(), Status> {
        let current = match self.get_environment_access_binding(environment_id).await {
            Ok(current) => current,
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(()),
            Err(status) => return Err(status),
        };
        self.inner
            .delete_environment_access_binding(v1::DeleteEnvironmentAccessBindingRequest {
                environment_id: environment_id.to_string(),
                expected_profile_id: current.binding.profile_id.to_string(),
                expected_profile_revision: current.binding.profile_revision,
            })
            .await?;
        Ok(())
    }

    pub async fn ensure_environment_broker(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        environment_name: &str,
        supervisor_socket: &Path,
    ) -> Result<EnvironmentBrokerRuntime, Status> {
        if environment_generation == 0 {
            return Err(Status::invalid_argument(
                "invalid local credential broker request",
            ));
        }
        let supervisor_socket = broker_supervisor_socket(supervisor_socket)?;
        let response = self
            .inner
            .ensure_environment_broker(v1::EnsureEnvironmentBrokerRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
                environment_name: environment_name.to_owned(),
                supervisor_socket: supervisor_socket.to_owned(),
            })
            .await?
            .into_inner();
        let runtime = EnvironmentBrokerRuntime {
            environment_id: EnvironmentId::parse(response.environment_id).map_err(data_loss)?,
            environment_generation: response.environment_generation,
            running: response.running,
        };
        if runtime.environment_id != *environment_id
            || runtime.environment_generation != environment_generation
        {
            return Err(Status::data_loss(
                "local credential authority returned invalid broker state",
            ));
        }
        Ok(runtime)
    }

    pub async fn stop_environment_broker(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: Option<u64>,
    ) -> Result<(), Status> {
        if environment_generation == Some(0) {
            return Err(Status::invalid_argument("invalid environment generation"));
        }
        self.inner
            .stop_environment_broker(v1::StopEnvironmentBrokerRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
            })
            .await?;
        Ok(())
    }
}

fn broker_supervisor_socket(path: &Path) -> Result<&str, Status> {
    if !path.is_absolute() {
        return Err(Status::invalid_argument(
            "invalid local credential broker request",
        ));
    }
    path.to_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Status::invalid_argument("invalid local credential broker request"))
}

fn broker_lease_audit_event_from_proto(
    event: v1::BrokerLeaseAuditEvent,
) -> Result<BrokerLeaseAuditEvent, Status> {
    let environment_id = EnvironmentId::parse(event.environment_id).map_err(data_loss)?;
    let request_id = uuid::Uuid::parse_str(&event.request_id).map_err(data_loss)?;
    let capability_slot = CapabilitySlot::parse(event.capability_slot).map_err(data_loss)?;
    let operation = BrokerOperationId::parse(event.operation).map_err(data_loss)?;
    let route = BrokerRouteId::parse(event.route).map_err(data_loss)?;
    let decision = match v1::BrokerLeaseAuditDecision::try_from(event.decision) {
        Ok(v1::BrokerLeaseAuditDecision::Admitted) => BrokerLeaseAuditDecision::Admitted,
        Ok(v1::BrokerLeaseAuditDecision::Denied) => BrokerLeaseAuditDecision::Denied,
        Ok(v1::BrokerLeaseAuditDecision::Unavailable) => BrokerLeaseAuditDecision::Unavailable,
        Ok(v1::BrokerLeaseAuditDecision::Unspecified) | Err(_) => return Err(data_loss(())),
    };
    let credential_id = event
        .credential_id
        .map(CredentialId::parse)
        .transpose()
        .map_err(data_loss)?;
    let profile_id = event
        .profile_id
        .map(AccessProfileId::parse)
        .transpose()
        .map_err(data_loss)?;
    let metadata_complete = credential_id.is_some()
        && profile_id.is_some()
        && event.profile_revision.is_some_and(|revision| revision > 0)
        && event
            .credential_revocation_generation
            .is_some_and(|generation| generation > 0);
    let metadata_absent = credential_id.is_none()
        && profile_id.is_none()
        && event.profile_revision.is_none()
        && event.credential_revocation_generation.is_none();
    if event.sequence == 0
        || event.environment_generation == 0
        || request_id.is_nil()
        || match decision {
            BrokerLeaseAuditDecision::Admitted => !metadata_complete,
            BrokerLeaseAuditDecision::Denied | BrokerLeaseAuditDecision::Unavailable => {
                !metadata_absent
            }
        }
    {
        return Err(data_loss(()));
    }
    Ok(BrokerLeaseAuditEvent {
        sequence: event.sequence,
        observed_at_unix_ms: event.observed_at_unix_ms,
        environment_id,
        environment_generation: event.environment_generation,
        request_id,
        capability_slot,
        operation,
        route,
        decision,
        credential_id,
        profile_id,
        profile_revision: event.profile_revision,
        credential_revocation_generation: event.credential_revocation_generation,
    })
}

fn terminate_unadmitted_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

async fn shutdown_incompatible_authority(
    config: &AuthorityRuntimeConfig,
) -> Result<(), AuthorityRuntimeError> {
    let channel = connect_owner_only(config).await?;
    let mut client = LocalCredentialAuthorityServiceClient::new(channel)
        .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES);
    client
        .shutdown_authority(v1::ShutdownAuthorityRequest {})
        .await
        .map_err(|_| AuthorityRuntimeError::ProtocolMismatch)?;
    let deadline = tokio::time::Instant::now() + AUTHORITY_START_TIMEOUT;
    while socket_exists(config)? {
        if tokio::time::Instant::now() >= deadline {
            return Err(AuthorityRuntimeError::StartTimeout);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

fn socket_exists(config: &AuthorityRuntimeConfig) -> Result<bool, AuthorityRuntimeError> {
    match fs::symlink_metadata(config.socket()) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AuthorityRuntimeError::InvalidPrivateSocket),
    }
}

fn credential_selector(id: &CredentialId) -> v1::CredentialSelector {
    v1::CredentialSelector {
        credential_id: id.to_string(),
    }
}

fn profile_selector(id: &AccessProfileId) -> v1::AccessProfileSelector {
    v1::AccessProfileSelector {
        profile_id: id.to_string(),
    }
}

fn profile_entries_to_proto(
    entries: &BTreeMap<CapabilitySlot, CredentialId>,
) -> Vec<v1::AccessProfileEntry> {
    entries
        .iter()
        .map(|(slot, credential)| v1::AccessProfileEntry {
            capability_slot: slot.to_string(),
            credential_id: credential.to_string(),
        })
        .collect()
}

pub(crate) fn credential_from_proto(value: v1::Credential) -> Result<CredentialRecord, Status> {
    let metadata = CredentialMetadata {
        id: CredentialId::parse(value.id).map_err(data_loss)?,
        placement: Placement::Local,
        owner: Owner::User(OwnerId::parse(LOCAL_OWNER_ID).map_err(data_loss)?),
        provider: ProviderId::parse(value.provider).map_err(data_loss)?,
        authentication_kind: auth_kind_from_proto(value.authentication_kind)?,
        display_name: value.display_name,
        account_hint: value.account_hint,
        status: status_from_proto(value.status)?,
        expires_at_unix: value.expires_at_unix,
        revocation_generation: value.revocation_generation,
    };
    metadata.validate().map_err(data_loss)?;
    Ok(CredentialRecord {
        metadata,
        persistence: persistence_from_proto(value.protected_store_persistence)?,
        protected_store_cleanup_pending: value.protected_store_cleanup_pending,
        created_at_unix_ms: value.created_at_unix_ms,
        updated_at_unix_ms: value.updated_at_unix_ms,
    })
}

fn profile_record_from_proto(
    value: v1::AccessProfileRevision,
) -> Result<AccessProfileRecord, Status> {
    let created_at_unix_ms = value.profile_created_at_unix_ms;
    let updated_at_unix_ms = value.revision_created_at_unix_ms;
    Ok(AccessProfileRecord {
        profile: profile_from_proto(value)?,
        created_at_unix_ms,
        updated_at_unix_ms,
    })
}

fn profile_revision_from_proto(
    value: v1::AccessProfileRevision,
) -> Result<AccessProfileRevisionRecord, Status> {
    let profile_created_at_unix_ms = value.profile_created_at_unix_ms;
    let revision_created_at_unix_ms = value.revision_created_at_unix_ms;
    Ok(AccessProfileRevisionRecord {
        profile: profile_from_proto(value)?,
        profile_created_at_unix_ms,
        revision_created_at_unix_ms,
    })
}

fn profile_from_proto(value: v1::AccessProfileRevision) -> Result<AccessProfile, Status> {
    let mut entries = BTreeMap::new();
    for entry in value.entries {
        let slot = CapabilitySlot::parse(entry.capability_slot).map_err(data_loss)?;
        let credential = CredentialId::parse(entry.credential_id).map_err(data_loss)?;
        if entries.insert(slot, credential).is_some() {
            return Err(Status::data_loss(
                "local credential authority returned invalid metadata",
            ));
        }
    }
    let profile = AccessProfile {
        id: AccessProfileId::parse(value.id).map_err(data_loss)?,
        placement: Placement::Local,
        owner: Owner::User(OwnerId::parse(LOCAL_OWNER_ID).map_err(data_loss)?),
        name: AccessProfileName::parse(value.name).map_err(data_loss)?,
        revision: value.revision,
        entries,
    };
    profile.validate().map_err(data_loss)?;
    Ok(profile)
}

fn environment_binding_from_proto(
    value: v1::EnvironmentAccessBinding,
) -> Result<EnvironmentAccessBindingRecord, Status> {
    let binding = EnvironmentAccessBinding {
        environment_id: EnvironmentId::parse(value.environment_id).map_err(data_loss)?,
        profile_id: AccessProfileId::parse(value.profile_id).map_err(data_loss)?,
        profile_revision: value.profile_revision,
    };
    binding.validate().map_err(data_loss)?;
    if value.updated_at_unix_ms < value.created_at_unix_ms {
        return Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        ));
    }
    Ok(EnvironmentAccessBindingRecord {
        binding,
        created_at_unix_ms: value.created_at_unix_ms,
        updated_at_unix_ms: value.updated_at_unix_ms,
    })
}

pub(crate) fn derived_grant_from_proto(value: v1::DerivedGrant) -> Result<DerivedGrant, Status> {
    let mut permissions = BTreeSet::new();
    for permission in value.permissions {
        let permission = GrantPermission {
            operation: BrokerOperationId::parse(permission.operation).map_err(data_loss)?,
            route: BrokerRouteId::parse(permission.route).map_err(data_loss)?,
        };
        if !permissions.insert(permission) {
            return Err(Status::data_loss(
                "local credential authority returned invalid metadata",
            ));
        }
    }
    if value.environment_generation == 0
        || value.profile_revision == 0
        || value.credential_revocation_generation == 0
        || permissions.is_empty()
    {
        return Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        ));
    }
    Ok(DerivedGrant {
        environment_id: EnvironmentId::parse(value.environment_id).map_err(data_loss)?,
        environment_generation: value.environment_generation,
        profile_id: AccessProfileId::parse(value.profile_id).map_err(data_loss)?,
        profile_revision: value.profile_revision,
        capability_slot: CapabilitySlot::parse(value.capability_slot).map_err(data_loss)?,
        credential_id: CredentialId::parse(value.credential_id).map_err(data_loss)?,
        credential_revocation_generation: value.credential_revocation_generation,
        expires_at_unix: value.expires_at_unix,
        permissions,
    })
}

fn auth_kind_from_proto(value: i32) -> Result<CredentialAuthKind, Status> {
    match CredentialAuthenticationKind::try_from(value) {
        Ok(CredentialAuthenticationKind::Oauth) => Ok(CredentialAuthKind::OAuth),
        Ok(CredentialAuthenticationKind::ApiKey) => Ok(CredentialAuthKind::ApiKey),
        Ok(CredentialAuthenticationKind::AccessToken) => Ok(CredentialAuthKind::AccessToken),
        Ok(CredentialAuthenticationKind::GithubApp) => Ok(CredentialAuthKind::GitHubApp),
        Ok(CredentialAuthenticationKind::SshPrivateKey) => Ok(CredentialAuthKind::SshPrivateKey),
        Ok(CredentialAuthenticationKind::SshAgent) => Ok(CredentialAuthKind::SshAgent),
        Ok(CredentialAuthenticationKind::Unspecified) | Err(_) => Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        )),
    }
}

fn status_from_proto(value: i32) -> Result<CredentialStatus, Status> {
    match v1::CredentialStatus::try_from(value) {
        Ok(v1::CredentialStatus::Active) => Ok(CredentialStatus::Active),
        Ok(v1::CredentialStatus::Expired) => Ok(CredentialStatus::Expired),
        Ok(v1::CredentialStatus::RefreshFailed) => Ok(CredentialStatus::RefreshFailed),
        Ok(v1::CredentialStatus::Revoked) => Ok(CredentialStatus::Revoked),
        Ok(v1::CredentialStatus::Unspecified) | Err(_) => Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        )),
    }
}

fn persistence_from_proto(value: i32) -> Result<ProtectedStorePersistence, Status> {
    match v1::ProtectedStorePersistence::try_from(value) {
        Ok(v1::ProtectedStorePersistence::OperatingSystem) => {
            Ok(ProtectedStorePersistence::OperatingSystem)
        }
        Ok(v1::ProtectedStorePersistence::ProcessLifetime) => {
            Ok(ProtectedStorePersistence::ProcessLifetime)
        }
        Ok(v1::ProtectedStorePersistence::Unspecified) | Err(_) => Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        )),
    }
}

fn data_loss<T>(_error: T) -> Status {
    Status::data_loss("local credential authority returned invalid metadata")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn broker_supervisor_socket_never_uses_a_lossy_wire_identity() {
        assert_eq!(
            broker_supervisor_socket(Path::new("/run/user/1000/codewire/supervisor.sock")).unwrap(),
            "/run/user/1000/codewire/supervisor.sock"
        );
        let non_utf8 = PathBuf::from(OsString::from_vec(
            b"/run/user/1000/codewire/supervisor.sock".to_vec(),
        ));
        let mut bytes = non_utf8.into_os_string().into_vec();
        bytes.insert(1, 0xff);
        let non_utf8 = PathBuf::from(OsString::from_vec(bytes));
        assert!(broker_supervisor_socket(&non_utf8).is_err());
        assert!(broker_supervisor_socket(Path::new("relative/supervisor.sock")).is_err());
    }
}
