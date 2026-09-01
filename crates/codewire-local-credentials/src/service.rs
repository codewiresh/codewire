use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::future::Future;
use std::mem;
use std::sync::Arc;

use codewire_access::{
    AccessError, AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot,
    CredentialAuthKind, CredentialId, CredentialStatus, ProviderCatalog, ProviderId,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, OsProtectedStore, ProtectedStore, ProtectedStorePersistence,
    ProtectedValue,
};
use tokio::sync::watch;
use tonic::{Request, Response, Status};

use crate::control::v1::local_credential_authority_service_server::{
    LocalCredentialAuthorityService, LocalCredentialAuthorityServiceServer,
};
use crate::control::v1::{self, CredentialAuthenticationKind};
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRuntimeConfig, AuthorityRuntimeError, bind_owner_only,
    remove_bound_socket,
};
use crate::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, AccessProfileRecord, AccessProfileRevisionRecord,
    CredentialRecord, LocalCredentialAuthority, LocalCredentialError, NewCredential,
};

const MAX_RPC_MESSAGE_BYTES: usize = MAX_PROTECTED_VALUE_BYTES + 64 * 1024;

struct AuthorityRpc<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    shutdown: watch::Sender<bool>,
}

impl<S: ProtectedStore> Clone for AuthorityRpc<S> {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            shutdown: self.shutdown.clone(),
        }
    }
}

pub async fn serve_local_credential_authority<S: ProtectedStore + 'static>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
) -> Result<(), AuthorityRuntimeError> {
    serve_until(config, protected_store, catalog, std::future::pending()).await
}

/// Run the production local authority against the operating-system protected
/// store. Provider adapters populate the catalog in later slices; until then
/// the empty catalog makes every material add fail closed.
pub async fn serve_os_local_credential_authority(
    config: AuthorityRuntimeConfig,
) -> Result<(), AuthorityRuntimeError> {
    verify_production_process_confinement()?;
    serve_local_credential_authority(config, OsProtectedStore, ProviderCatalog::default()).await
}

#[cfg(target_os = "linux")]
fn verify_production_process_confinement() -> Result<(), AuthorityRuntimeError> {
    if !rustix::thread::no_new_privs().map_err(|_| AuthorityRuntimeError::ProcessNotConfined)? {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    let capabilities = rustix::thread::capabilities(None)
        .map_err(|_| AuthorityRuntimeError::ProcessNotConfined)?;
    if !capabilities.effective.is_empty()
        || !capabilities.permitted.is_empty()
        || !capabilities.inheritable.is_empty()
    {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    let pid = rustix::process::getpid();
    if rustix::process::getsid(None).map_err(|_| AuthorityRuntimeError::ProcessNotConfined)? != pid
    {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    for (name, _) in std::env::vars_os() {
        if !AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
            .iter()
            .any(|allowed| name == OsStr::new(allowed))
        {
            return Err(AuthorityRuntimeError::ProcessNotConfined);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_production_process_confinement() -> Result<(), AuthorityRuntimeError> {
    Err(AuthorityRuntimeError::UnsupportedPlatform)
}

pub(crate) async fn serve_until<S, F>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
    shutdown: F,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    config.prepare_root()?;
    let authority = Arc::new(LocalCredentialAuthority::open(
        &config.root,
        protected_store,
        catalog,
    )?);
    // The persistence singleton lock is held before a stale endpoint is ever
    // removed, so a losing process cannot unlink the live authority socket.
    let (incoming, socket_identity) = bind_owner_only(&config)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let service = AuthorityRpc {
        authority,
        shutdown: shutdown_tx,
    };
    let observed_shutdown = async move {
        tokio::select! {
            () = shutdown => {}
            _ = async {
                while shutdown_rx.changed().await.is_ok() {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            } => {}
        }
    };
    let result = tonic::transport::Server::builder()
        .add_service(
            LocalCredentialAuthorityServiceServer::new(service)
                .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, observed_shutdown)
        .await
        .map_err(|_| AuthorityRuntimeError::Serve);
    let cleanup = remove_bound_socket(&config, &socket_identity);
    result.and(cleanup)
}

#[tonic::async_trait]
impl<S: ProtectedStore + 'static> LocalCredentialAuthorityService for AuthorityRpc<S> {
    async fn get_authority_info(
        &self,
        _request: Request<v1::GetAuthorityInfoRequest>,
    ) -> Result<Response<v1::AuthorityInfo>, Status> {
        Ok(Response::new(v1::AuthorityInfo {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            protected_store_persistence: persistence_to_proto(
                self.authority.protected_store_persistence(),
            ) as i32,
        }))
    }

    async fn shutdown_authority(
        &self,
        _request: Request<v1::ShutdownAuthorityRequest>,
    ) -> Result<Response<v1::ShutdownAuthorityResponse>, Status> {
        self.shutdown
            .send(true)
            .map_err(|_| Status::unavailable("local credential authority is stopping"))?;
        Ok(Response::new(v1::ShutdownAuthorityResponse {}))
    }

    async fn add_credential(
        &self,
        request: Request<v1::AddCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let mut request = request.into_inner();
        let input = NewCredential {
            provider: ProviderId::parse(mem::take(&mut request.provider))
                .map_err(status_for_access_error)?,
            authentication_kind: auth_kind_from_proto(request.authentication_kind)?,
            display_name: mem::take(&mut request.display_name),
            account_hint: mem::take(&mut request.account_hint),
            expires_at_unix: request.expires_at_unix,
        };
        let material = ProtectedValue::new(mem::take(&mut request.material))
            .map_err(|_| Status::invalid_argument("invalid credential material"))?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.add_credential(input, material)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn list_credentials(
        &self,
        _request: Request<v1::ListCredentialsRequest>,
    ) -> Result<Response<v1::ListCredentialsResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let credentials = run_blocking(move || authority.list_credentials()).await?;
        Ok(Response::new(v1::ListCredentialsResponse {
            credentials: credentials.into_iter().map(credential_to_proto).collect(),
        }))
    }

    async fn get_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::Credential>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.get_credential(&id)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn rename_credential(
        &self,
        request: Request<v1::RenameCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let request = request.into_inner();
        let id = credential_id(request.credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record =
            run_blocking(move || authority.rename_credential(&id, request.display_name)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn rotate_credential_material(
        &self,
        request: Request<v1::RotateCredentialMaterialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let mut request = request.into_inner();
        let id = credential_id(mem::take(&mut request.credential_id))?;
        let material = ProtectedValue::new(mem::take(&mut request.material))
            .map_err(|_| Status::invalid_argument("invalid credential material"))?;
        let expires_at_unix = request.expires_at_unix;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || {
            authority.rotate_credential_material(&id, material, expires_at_unix)
        })
        .await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn revoke_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::Credential>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.revoke_credential(&id)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn delete_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::DeleteCredentialResponse>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_credential(&id)).await?;
        Ok(Response::new(v1::DeleteCredentialResponse {}))
    }

    async fn create_access_profile(
        &self,
        request: Request<v1::CreateAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let name = AccessProfileName::parse(request.name).map_err(status_for_access_error)?;
        let entries = profile_entries(request.entries)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.create_profile(name, entries)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn update_access_profile(
        &self,
        request: Request<v1::UpdateAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let id = profile_id(request.profile_id)?;
        let entries = profile_entries(request.entries)?;
        let authority = Arc::clone(&self.authority);
        let profile =
            run_blocking(move || authority.update_profile(&id, request.expected_revision, entries))
                .await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn list_access_profiles(
        &self,
        _request: Request<v1::ListAccessProfilesRequest>,
    ) -> Result<Response<v1::ListAccessProfilesResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let profiles = run_blocking(move || authority.list_profiles()).await?;
        Ok(Response::new(v1::ListAccessProfilesResponse {
            profiles: profiles.into_iter().map(profile_record_to_proto).collect(),
        }))
    }

    async fn get_access_profile(
        &self,
        request: Request<v1::AccessProfileSelector>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.get_profile(&id)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn get_access_profile_revision(
        &self,
        request: Request<v1::GetAccessProfileRevisionRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let id = profile_id(request.profile_id)?;
        let authority = Arc::clone(&self.authority);
        let revision =
            run_blocking(move || authority.get_profile_revision(&id, request.revision)).await?;
        Ok(Response::new(profile_revision_to_proto(revision)))
    }

    async fn list_access_profile_revisions(
        &self,
        request: Request<v1::ListAccessProfileRevisionsRequest>,
    ) -> Result<Response<v1::ListAccessProfileRevisionsResponse>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        let revisions = run_blocking(move || authority.list_profile_revisions(&id)).await?;
        Ok(Response::new(v1::ListAccessProfileRevisionsResponse {
            revisions: revisions
                .into_iter()
                .map(profile_revision_to_proto)
                .collect(),
        }))
    }

    async fn resolve_access_profile(
        &self,
        request: Request<v1::ResolveAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let reference = request
            .into_inner()
            .reference
            .parse::<AccessProfileReference>()
            .map_err(status_for_access_error)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.resolve_profile(&reference)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn delete_access_profile(
        &self,
        request: Request<v1::AccessProfileSelector>,
    ) -> Result<Response<v1::DeleteAccessProfileResponse>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_profile(&id)).await?;
        Ok(Response::new(v1::DeleteAccessProfileResponse {}))
    }
}

async fn run_blocking<T, F>(operation: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, LocalCredentialError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| Status::internal("local credential authority worker failed"))?
        .map_err(status_for_error)
}

fn credential_id(value: String) -> Result<CredentialId, Status> {
    CredentialId::parse(value).map_err(status_for_access_error)
}

fn profile_id(value: String) -> Result<AccessProfileId, Status> {
    AccessProfileId::parse(value).map_err(status_for_access_error)
}

fn profile_entries(
    entries: Vec<v1::AccessProfileEntry>,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, Status> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let slot = CapabilitySlot::parse(entry.capability_slot).map_err(status_for_access_error)?;
        let credential =
            CredentialId::parse(entry.credential_id).map_err(status_for_access_error)?;
        if parsed.insert(slot, credential).is_some() {
            return Err(Status::invalid_argument(
                "duplicate access profile capability slot",
            ));
        }
    }
    Ok(parsed)
}

fn auth_kind_from_proto(value: i32) -> Result<CredentialAuthKind, Status> {
    match CredentialAuthenticationKind::try_from(value) {
        Ok(CredentialAuthenticationKind::Oauth) => Ok(CredentialAuthKind::OAuth),
        Ok(CredentialAuthenticationKind::ApiKey) => Ok(CredentialAuthKind::ApiKey),
        Ok(CredentialAuthenticationKind::AccessToken) => Ok(CredentialAuthKind::AccessToken),
        Ok(CredentialAuthenticationKind::GithubApp) => Ok(CredentialAuthKind::GitHubApp),
        Ok(CredentialAuthenticationKind::SshPrivateKey) => Ok(CredentialAuthKind::SshPrivateKey),
        Ok(CredentialAuthenticationKind::SshAgent) => Ok(CredentialAuthKind::SshAgent),
        Ok(CredentialAuthenticationKind::Unspecified) | Err(_) => Err(Status::invalid_argument(
            "invalid credential authentication kind",
        )),
    }
}

pub(crate) fn auth_kind_to_proto(value: CredentialAuthKind) -> CredentialAuthenticationKind {
    match value {
        CredentialAuthKind::OAuth => CredentialAuthenticationKind::Oauth,
        CredentialAuthKind::ApiKey => CredentialAuthenticationKind::ApiKey,
        CredentialAuthKind::AccessToken => CredentialAuthenticationKind::AccessToken,
        CredentialAuthKind::GitHubApp => CredentialAuthenticationKind::GithubApp,
        CredentialAuthKind::SshPrivateKey => CredentialAuthenticationKind::SshPrivateKey,
        CredentialAuthKind::SshAgent => CredentialAuthenticationKind::SshAgent,
    }
}

pub(crate) fn status_to_proto(value: CredentialStatus) -> v1::CredentialStatus {
    match value {
        CredentialStatus::Active => v1::CredentialStatus::Active,
        CredentialStatus::Expired => v1::CredentialStatus::Expired,
        CredentialStatus::RefreshFailed => v1::CredentialStatus::RefreshFailed,
        CredentialStatus::Revoked => v1::CredentialStatus::Revoked,
    }
}

pub(crate) fn persistence_to_proto(
    value: ProtectedStorePersistence,
) -> v1::ProtectedStorePersistence {
    match value {
        ProtectedStorePersistence::OperatingSystem => {
            v1::ProtectedStorePersistence::OperatingSystem
        }
        ProtectedStorePersistence::ProcessLifetime => {
            v1::ProtectedStorePersistence::ProcessLifetime
        }
    }
}

fn credential_to_proto(record: CredentialRecord) -> v1::Credential {
    v1::Credential {
        id: record.metadata.id.to_string(),
        provider: record.metadata.provider.to_string(),
        authentication_kind: auth_kind_to_proto(record.metadata.authentication_kind) as i32,
        display_name: record.metadata.display_name,
        account_hint: record.metadata.account_hint,
        status: status_to_proto(record.metadata.status) as i32,
        expires_at_unix: record.metadata.expires_at_unix,
        revocation_generation: record.metadata.revocation_generation,
        protected_store_persistence: persistence_to_proto(record.persistence) as i32,
        protected_store_cleanup_pending: record.protected_store_cleanup_pending,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
    }
}

fn profile_record_to_proto(record: AccessProfileRecord) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.created_at_unix_ms,
        record.updated_at_unix_ms,
    )
}

fn profile_revision_to_proto(record: AccessProfileRevisionRecord) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.profile_created_at_unix_ms,
        record.revision_created_at_unix_ms,
    )
}

fn profile_to_proto(
    profile: codewire_access::AccessProfile,
    profile_created_at_unix_ms: u64,
    revision_created_at_unix_ms: u64,
) -> v1::AccessProfileRevision {
    v1::AccessProfileRevision {
        id: profile.id.to_string(),
        name: profile.name.to_string(),
        revision: profile.revision,
        entries: profile
            .entries
            .into_iter()
            .map(|(slot, credential)| v1::AccessProfileEntry {
                capability_slot: slot.to_string(),
                credential_id: credential.to_string(),
            })
            .collect(),
        profile_created_at_unix_ms,
        revision_created_at_unix_ms,
    }
}

fn status_for_access_error(_error: AccessError) -> Status {
    Status::invalid_argument("invalid local credential request")
}

fn status_for_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::AlreadyExists => {
            Status::already_exists("local credential record already exists")
        }
        LocalCredentialError::CredentialNotFound
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound => {
            Status::not_found("local credential record was not found")
        }
        LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::CredentialInUse
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::ProtectedEntryCollision
        | LocalCredentialError::OwnerMismatch
        | LocalCredentialError::ProtectedStoreMismatch
        | LocalCredentialError::UnsupportedSchema
        | LocalCredentialError::InvalidDatabase
        | LocalCredentialError::CorruptMetadata
        | LocalCredentialError::Access(_) => {
            Status::failed_precondition("local credential operation cannot be applied")
        }
        LocalCredentialError::DatabaseUnavailable | LocalCredentialError::ProtectedStore(_) => {
            Status::unavailable("local credential authority storage is unavailable")
        }
        LocalCredentialError::AlreadyRunning => {
            Status::already_exists("local credential authority is already running")
        }
        LocalCredentialError::UnsupportedPlatform => {
            Status::unimplemented("local credential authority is unsupported")
        }
        LocalCredentialError::InvalidDatabasePath | LocalCredentialError::InvalidTime => {
            Status::internal("local credential authority state is invalid")
        }
    }
}
