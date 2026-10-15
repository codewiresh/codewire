use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;

use codewire_access::{
    AccessProfile, AccessProfileId, AccessProfileName, AccessProfileReference, AccessProfileScope,
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, CredentialId,
    CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentAccessBinding, EnvironmentId,
    GrantPermission, GrantProfile, Owner, OwnerId, Placement, ProviderId, SshPublicKeyMetadata,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedStorePersistence, ProtectedValue,
};
use codewire_workload_secrets::validate_workload_secret_key;
use tonic::Status;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::broker_channel::MAX_BROKER_LEASE_AUDIT_LIST_LIMIT;
use crate::control::v1::local_credential_authority_service_client::LocalCredentialAuthorityServiceClient;
use crate::control::v1::{self, CredentialAuthenticationKind};
use crate::repository::{MAX_GIT_BUNDLE_BYTES, valid_git_selector};
use crate::service::REPOSITORY_PREPARATION_TIMEOUT;
use crate::service::auth_kind_to_proto;
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRuntimeConfig, AuthorityRuntimeError, connect_owner_only,
    connect_owner_only_with_timeout, store_error_from_exit_status,
};
use crate::{
    AccessProfileRecord, AccessProfileRevisionRecord, AuthorityProtectedStore,
    BrokerLeaseAuditDecision, BrokerLeaseAuditEvent, CredentialRecord,
    EnvironmentAccessBindingRecord, EnvironmentBrokerRuntime, LOCAL_OWNER_ID, LocalSecretProject,
    NewCredential, ResolvedWorkloadSecretMetadata, WorkloadSecretMetadata, WorkloadSecretSelection,
    WorkloadSecretSource, ensure_private_root,
};

const MAX_RPC_MESSAGE_BYTES: usize = MAX_PROTECTED_VALUE_BYTES + 64 * 1024;
const AUTHORITY_START_TIMEOUT: Duration = Duration::from_secs(10);

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityInfo {
    pub protocol_version: u32,
    pub protected_store_persistence: ProtectedStorePersistence,
    /// `None` from an authority that predates the recorded store; it used
    /// the platform default backend.
    pub protected_store: Option<AuthorityProtectedStore>,
}

/// An authority process the starting client still owns until admission.
pub trait SpawnedAuthority {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>>;
    fn kill(&mut self) -> std::io::Result<()>;
    fn wait(&mut self) -> std::io::Result<ExitStatus>;
}

impl SpawnedAuthority for Child {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }

    fn kill(&mut self) -> std::io::Result<()> {
        Child::kill(self)
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        Child::wait(self)
    }
}

#[derive(Clone)]
pub struct LocalCredentialClient {
    inner: LocalCredentialAuthorityServiceClient<tonic::transport::Channel>,
    info: AuthorityInfo,
}

/// Material-free authority client for lifecycle supervisors.
///
/// This deliberately exposes only material-free lifecycle operations, including
/// exact environment/profile binding controls and workload-secret metadata
/// resolution. The VM supervisor cannot use this type to submit or retrieve
/// provider material, mutate credentials, or edit access profiles.
#[derive(Clone)]
pub struct LocalCredentialControlClient {
    inner: LocalCredentialAuthorityServiceClient<tonic::transport::Channel>,
    info: AuthorityInfo,
    /// Repository preparation reconnects with its own, longer deadline.
    config: AuthorityRuntimeConfig,
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
    /// Admit a currently running authority without starting one when its
    /// endpoint is absent. A socket nothing listens on, left by an authority
    /// that died, counts as absent and is left in place. Any other
    /// unconnectable or incompatible endpoint fails closed without shutdown,
    /// replacement or request replay. The legacy method signature is
    /// retained; its spawner is never invoked.
    pub async fn admit_existing_or_replace_with<F>(
        config: &AuthorityRuntimeConfig,
        _spawn: F,
    ) -> Result<Option<Self>, AuthorityRuntimeError>
    where
        F: FnOnce(&AuthorityRuntimeConfig) -> Result<Child, AuthorityRuntimeError>,
    {
        config.validate()?;
        match fs::symlink_metadata(&config.root) {
            Ok(_) => {
                ensure_private_root(&config.root).map_err(AuthorityRuntimeError::Credential)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AuthorityRuntimeError::InvalidPrivatePath),
        }
        if !socket_exists(config)? {
            return Self::connect_legacy(config).await;
        }
        match Self::connect(config).await {
            Err(AuthorityRuntimeError::Connect) if endpoint_refuses(config) => Ok(None),
            result => result.map(Some),
        }
    }

    /// An authority that a cw from before #2745 started still listens in the
    /// credential root until it exits; use it while it runs. A new authority
    /// starts only once it is gone, and removes its endpoint.
    async fn connect_legacy(
        config: &AuthorityRuntimeConfig,
    ) -> Result<Option<Self>, AuthorityRuntimeError> {
        let legacy = AuthorityRuntimeConfig {
            socket_dir: config.root.clone(),
            ..config.clone()
        };
        // No authority could bind a path over the limit.
        if crate::transport::check_socket_path(&legacy.socket()).is_err()
            || !socket_exists(&legacy)?
        {
            return Ok(None);
        }
        match Self::connect(&legacy).await {
            Err(AuthorityRuntimeError::Connect) if endpoint_refuses(&legacy) => Ok(None),
            result => result.map(Some),
        }
    }

    /// Reuse a compatible authority, or start an owned child when the endpoint
    /// is absent or nothing listens on it. A dead authority's socket is then
    /// replaced only by the new authority after it takes the singleton lock,
    /// which every live authority holds for its whole life, so a live one
    /// keeps its socket. The client itself never unlinks anything, and any
    /// other admission error never grants permission to shut an endpoint
    /// down, unlink it or launch a replacement.
    pub async fn connect_or_start_with<F, C>(
        config: &AuthorityRuntimeConfig,
        spawn: F,
    ) -> Result<Self, AuthorityRuntimeError>
    where
        F: FnOnce(&AuthorityRuntimeConfig) -> Result<C, AuthorityRuntimeError>,
        C: SpawnedAuthority,
    {
        config.prepare_root()?;
        if socket_exists(config)? {
            match Self::connect(config).await {
                Err(AuthorityRuntimeError::Connect) if endpoint_refuses(config) => {}
                result => return result,
            }
        } else if let Some(client) = Self::connect_legacy(config).await? {
            return Ok(client);
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
            if !child_exited
                && let Some(status) = child.try_wait().map_err(|_| AuthorityRuntimeError::Spawn)?
            {
                child_exited = true;
                // A store failure is final for this start: the child held
                // the singleton lock, so no other live authority is coming.
                if let Some(error) = store_error_from_exit_status(status) {
                    return Err(AuthorityRuntimeError::Credential(error));
                }
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
            protected_store: store_from_proto(&response.protected_store_backend)?,
        };
        Ok(Self { inner, info })
    }

    pub fn info(&self) -> AuthorityInfo {
        self.info.clone()
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

    pub async fn generate_ssh_credential(
        &mut self,
        name: String,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .generate_ssh_credential(v1::GenerateSshCredentialRequest {
                    name,
                    expires_at_unix,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn add_ssh_credential(
        &mut self,
        name: String,
        mut private_key: Zeroizing<Vec<u8>>,
        mut passphrase: Option<Zeroizing<Vec<u8>>>,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .add_ssh_credential(v1::AddSshCredentialRequest {
                    name,
                    private_key: std::mem::take(&mut *private_key),
                    passphrase: passphrase
                        .as_mut()
                        .map(|value| std::mem::take(&mut **value)),
                    expires_at_unix,
                })
                .await?
                .into_inner(),
        )
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
        expected_revocation_generation: u64,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
        account_hint: Option<String>,
    ) -> Result<CredentialRecord, Status> {
        credential_from_proto(
            self.inner
                .rotate_credential_material(v1::RotateCredentialMaterialRequest {
                    credential_id: id.to_string(),
                    expected_revocation_generation,
                    material: material.expose_secret().to_vec(),
                    expires_at_unix,
                    account_hint,
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

    pub async fn create_secret_project(
        &mut self,
        name: String,
    ) -> Result<LocalSecretProject, Status> {
        secret_project_from_proto(
            self.inner
                .create_secret_project(v1::CreateLocalSecretProjectRequest { name })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_secret_projects(&mut self) -> Result<Vec<LocalSecretProject>, Status> {
        self.inner
            .list_secret_projects(v1::ListLocalSecretProjectsRequest {})
            .await?
            .into_inner()
            .projects
            .into_iter()
            .map(secret_project_from_proto)
            .collect()
    }

    pub async fn delete_secret_project(&mut self, id: Uuid) -> Result<(), Status> {
        self.inner
            .delete_secret_project(v1::LocalSecretProjectSelector {
                project_id: id.to_string(),
            })
            .await?;
        Ok(())
    }

    pub async fn list_user_workload_secrets(
        &mut self,
    ) -> Result<Vec<WorkloadSecretMetadata>, Status> {
        workload_secret_list_from_proto(
            self.inner
                .list_user_workload_secrets(v1::ListUserWorkloadSecretsRequest {})
                .await?
                .into_inner(),
        )
    }

    pub async fn set_user_workload_secret(
        &mut self,
        key: String,
        value: ProtectedValue,
    ) -> Result<WorkloadSecretMetadata, Status> {
        workload_secret_from_proto(
            self.inner
                .set_user_workload_secret(v1::SetUserWorkloadSecretRequest {
                    key,
                    value: value.expose_secret().to_vec(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_user_workload_secret(&mut self, key: String) -> Result<(), Status> {
        self.inner
            .delete_user_workload_secret(v1::DeleteUserWorkloadSecretRequest { key })
            .await?;
        Ok(())
    }

    pub async fn rename_user_workload_secret(
        &mut self,
        key: String,
        new_key: String,
    ) -> Result<WorkloadSecretMetadata, Status> {
        workload_secret_from_proto(
            self.inner
                .rename_user_workload_secret(v1::RenameUserWorkloadSecretRequest { key, new_key })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_project_workload_secrets(
        &mut self,
        project_id: Uuid,
    ) -> Result<Vec<WorkloadSecretMetadata>, Status> {
        workload_secret_list_from_proto(
            self.inner
                .list_project_workload_secrets(v1::ListProjectWorkloadSecretsRequest {
                    project_id: project_id.to_string(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn set_project_workload_secret(
        &mut self,
        project_id: Uuid,
        key: String,
        value: ProtectedValue,
    ) -> Result<WorkloadSecretMetadata, Status> {
        workload_secret_from_proto(
            self.inner
                .set_project_workload_secret(v1::SetProjectWorkloadSecretRequest {
                    project_id: project_id.to_string(),
                    key,
                    value: value.expose_secret().to_vec(),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_project_workload_secret(
        &mut self,
        project_id: Uuid,
        key: String,
    ) -> Result<(), Status> {
        self.inner
            .delete_project_workload_secret(v1::DeleteProjectWorkloadSecretRequest {
                project_id: project_id.to_string(),
                key,
            })
            .await?;
        Ok(())
    }

    pub async fn rename_project_workload_secret(
        &mut self,
        project_id: Uuid,
        key: String,
        new_key: String,
    ) -> Result<WorkloadSecretMetadata, Status> {
        workload_secret_from_proto(
            self.inner
                .rename_project_workload_secret(v1::RenameProjectWorkloadSecretRequest {
                    project_id: project_id.to_string(),
                    key,
                    new_key,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn resolve_workload_secret_metadata(
        &mut self,
        selection: WorkloadSecretSelection,
    ) -> Result<Vec<ResolvedWorkloadSecretMetadata>, Status> {
        let response = self
            .inner
            .resolve_workload_secret_metadata(v1::ResolveWorkloadSecretMetadataRequest {
                selection: Some(v1::WorkloadSecretSelection {
                    organization: selection.organization,
                    project: selection.project,
                    user: selection.user,
                    explicit_environment_keys: selection
                        .explicit_environment_keys
                        .into_iter()
                        .collect(),
                }),
            })
            .await?
            .into_inner();
        response
            .secrets
            .into_iter()
            .map(resolved_workload_secret_from_proto)
            .collect()
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
            config: config.clone(),
        })
    }

    pub fn info(&self) -> AuthorityInfo {
        self.info.clone()
    }

    /// The capability slots the authority grants this environment generation
    /// now. Grants are material-free; GitHub appears only while the profile
    /// includes it and the store holds an active connection.
    pub async fn environment_grant_slots(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
    ) -> Result<std::collections::BTreeSet<String>, Status> {
        Ok(self
            .inner
            .evaluate_environment_grants(v1::EvaluateEnvironmentGrantsRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
            })
            .await?
            .into_inner()
            .grants
            .into_iter()
            .map(|grant| grant.capability_slot)
            .collect())
    }

    /// Read material-free client-slot metadata from an exact immutable profile
    /// revision. This reuses the authority's existing metadata RPC and exposes
    /// no credential material or profile mutation to lifecycle callers.
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

    pub async fn resolve_workload_secret_metadata(
        &mut self,
        selection: WorkloadSecretSelection,
    ) -> Result<Vec<ResolvedWorkloadSecretMetadata>, Status> {
        let response = self
            .inner
            .resolve_workload_secret_metadata(v1::ResolveWorkloadSecretMetadataRequest {
                selection: Some(v1::WorkloadSecretSelection {
                    organization: selection.organization,
                    project: selection.project,
                    user: selection.user,
                    explicit_environment_keys: selection
                        .explicit_environment_keys
                        .into_iter()
                        .collect(),
                }),
            })
            .await?
            .into_inner();
        response
            .secrets
            .into_iter()
            .map(resolved_workload_secret_from_proto)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_git_repository(
        &mut self,
        request_id: Uuid,
        profile_id: &AccessProfileId,
        profile_revision: u64,
        source: String,
        branch: String,
        revision: String,
        known_hosts: Vec<String>,
        platform: Option<crate::RepositoryPlatformAccess>,
        git: Option<crate::LocalRepositoryGit>,
    ) -> Result<PreparedGitRepository, Status> {
        let authorization = crate::RepositoryCredentialLeaseRequest {
            request_id,
            profile_id: profile_id.clone(),
            profile_revision,
            source: source.clone(),
            branch: branch.clone(),
            revision: revision.clone(),
            known_hosts: known_hosts.clone(),
        };
        if crate::repository::validate_repository_lease_request(&authorization).is_err() {
            return Err(Status::invalid_argument(
                "invalid repository preparation request",
            ));
        }
        if let Some(platform) = &platform {
            platform.validate(&authorization)?;
        }
        if git.as_ref().is_some_and(|git| git.validate().is_err()) {
            return Err(Status::invalid_argument(
                "invalid repository preparation request",
            ));
        }
        // The authority answers only after git has fetched and bundled the
        // repository, which can take minutes; the 30 s control deadline
        // would cut it off. Use one connection with the preparation
        // deadline, checked against the same authority protocol.
        let channel = connect_owner_only_with_timeout(&self.config, REPOSITORY_PREPARATION_TIMEOUT)
            .await
            .map_err(|_| Status::unavailable("local credential authority is unavailable"))?;
        let mut repositories = LocalCredentialAuthorityServiceClient::new(channel)
            .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES);
        let protocol_version = repositories
            .get_authority_info(v1::GetAuthorityInfoRequest {})
            .await?
            .into_inner()
            .protocol_version;
        if protocol_version != self.info.protocol_version {
            return Err(Status::failed_precondition(
                "local credential authority changed during repository preparation",
            ));
        }
        let started = std::time::Instant::now();
        let mut stream = match repositories
            .prepare_git_repository(v1::PrepareGitRepositoryRequest {
                request_id: request_id.to_string(),
                profile_id: profile_id.to_string(),
                profile_revision,
                source,
                branch,
                revision,
                known_hosts,
                platform: platform.map(crate::RepositoryPlatformAccess::into_proto),
                git: git.as_ref().map(crate::LocalRepositoryGit::to_proto),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            // The channel deadline ends the call without a status of its own.
            Err(_) if started.elapsed() >= REPOSITORY_PREPARATION_TIMEOUT => {
                return Err(Status::deadline_exceeded(format!(
                    "repository preparation timed out after {} s",
                    REPOSITORY_PREPARATION_TIMEOUT.as_secs()
                )));
            }
            Err(status) => return Err(status),
        };
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
        runner_socket: &Path,
        selection: crate::EnvironmentBrokerSelection,
    ) -> Result<EnvironmentBrokerRuntime, Status> {
        if environment_generation == 0 {
            return Err(Status::invalid_argument(
                "invalid local credential broker request",
            ));
        }
        let runner_socket = broker_runner_socket(runner_socket)?;
        let crate::EnvironmentBrokerSelection {
            local_profile,
            projection,
            platform,
        } = selection;
        if local_profile.as_ref().is_some_and(|binding| {
            binding.environment_id != *environment_id || binding.profile_revision == 0
        }) {
            return Err(Status::invalid_argument("invalid local provider selection"));
        }
        if let Some(binding) = platform.as_ref() {
            binding.validate()?;
        }
        if let Some(binding) = projection.as_ref() {
            binding
                .validate()
                .map_err(|_| Status::invalid_argument("invalid local projection"))?;
        }
        let response = self
            .inner
            .ensure_environment_broker(v1::EnsureEnvironmentBrokerRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
                environment_name: environment_name.to_owned(),
                runner_socket: runner_socket.to_owned(),
                projection: projection.map(crate::LocalEnvironmentProjectionBinding::into_proto),
                platform: platform.map(crate::PlatformCredentialBinding::into_proto),
                local_profile: local_profile.map(|binding| v1::BrokerLocalProfileSelection {
                    profile_id: binding.profile_id.to_string(),
                    profile_revision: binding.profile_revision,
                }),
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

fn broker_runner_socket(path: &Path) -> Result<&str, Status> {
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

fn store_from_proto(value: &str) -> Result<Option<AuthorityProtectedStore>, AuthorityRuntimeError> {
    if value.is_empty() {
        return Ok(None);
    }
    AuthorityProtectedStore::from_record(value)
        .map(Some)
        .ok_or(AuthorityRuntimeError::ProtocolMismatch)
}

fn terminate_unadmitted_child(child: &mut impl SpawnedAuthority) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Nothing listens on the existing endpoint: the socket of an authority that
/// is no longer running.
fn endpoint_refuses(config: &AuthorityRuntimeConfig) -> bool {
    matches!(
        std::os::unix::net::UnixStream::connect(config.socket()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused
    )
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
        ssh_public_key: value.ssh_public_key.map(|key| SshPublicKeyMetadata {
            openssh: key.openssh,
            fingerprint: key.fingerprint,
        }),
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

fn secret_project_from_proto(value: v1::LocalSecretProject) -> Result<LocalSecretProject, Status> {
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

fn workload_secret_list_from_proto(
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

fn workload_secret_from_proto(
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

fn resolved_workload_secret_from_proto(
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
    let mut bytes = name.bytes();
    !name.is_empty()
        && name.len() <= 64
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_workload_secret_key(key: &str) -> bool {
    validate_workload_secret_key(key).is_ok()
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
        profile: Some(GrantProfile {
            id: AccessProfileId::parse(value.profile_id).map_err(data_loss)?,
            revision: value.profile_revision,
        }),
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
        Ok(CredentialAuthenticationKind::SshKey) => Ok(CredentialAuthKind::SshKey),
        Ok(CredentialAuthenticationKind::ClaudeSignIn) => Ok(CredentialAuthKind::ClaudeSignIn),
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
    fn workload_secret_response_keys_use_the_canonical_workload_grammar() {
        let maximum = format!(
            "A{}",
            "_".repeat(codewire_workload_secrets::MAX_WORKLOAD_SECRET_KEY_BYTES - 1)
        );
        let too_long = format!(
            "A{}",
            "_".repeat(codewire_workload_secrets::MAX_WORKLOAD_SECRET_KEY_BYTES)
        );

        assert!(valid_workload_secret_key(&maximum));
        assert!(!valid_workload_secret_key(&too_long));
        assert!(valid_workload_secret_key("_UNDERSCORE_FIRST"));
        assert!(!valid_workload_secret_key("1DIGIT_FIRST"));
        assert_eq!(
            resolved_workload_secret_from_proto(v1::ResolvedWorkloadSecretMetadata {
                key: "1DIGIT_FIRST".into(),
                source: v1::WorkloadSecretSource::User.into(),
                ..Default::default()
            })
            .unwrap_err()
            .code(),
            tonic::Code::DataLoss
        );
        let decoded = workload_secret_from_proto(v1::WorkloadSecretMetadata {
            key: maximum,
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
            protected_store_cleanup_pending: true,
        })
        .expect("valid workload-secret metadata");
        assert!(decoded.protected_store_cleanup_pending);
        assert_eq!(
            workload_secret_from_proto(v1::WorkloadSecretMetadata {
                key: too_long,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                protected_store_cleanup_pending: false,
            })
            .unwrap_err()
            .code(),
            tonic::Code::DataLoss
        );
    }

    #[test]
    fn broker_runner_socket_never_uses_a_lossy_wire_identity() {
        assert_eq!(
            broker_runner_socket(Path::new("/run/user/1000/codewire/supervisor.sock")).unwrap(),
            "/run/user/1000/codewire/supervisor.sock"
        );
        let non_utf8 = PathBuf::from(OsString::from_vec(
            b"/run/user/1000/codewire/supervisor.sock".to_vec(),
        ));
        let mut bytes = non_utf8.into_os_string().into_vec();
        bytes.insert(1, 0xff);
        let non_utf8 = PathBuf::from(OsString::from_vec(bytes));
        assert!(broker_runner_socket(&non_utf8).is_err());
        assert!(broker_runner_socket(Path::new("relative/supervisor.sock")).is_err());
    }
}
