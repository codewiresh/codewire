//! Shared ergonomic Rust client over Codewire's generated Connect-RPC stubs.
//!
//! This crate owns connection configuration, bearer-token provisioning, and
//! typed error decoding. Product consumers use it instead of constructing raw
//! generated clients or formatting platform route strings themselves.

mod auth;
mod config;
mod coordinator;
mod error;
mod mesh;
mod tailnet;

use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::console::v1::{BillingServiceClient, GitHubServiceClient};
use codewire_proto::codewire::v1::{
    ApiKeyServiceClient, EnvironmentServiceClient, EnvironmentSessionServiceClient,
    ExecServiceClient, FileServiceClient, MeshInviteServiceClient, MeshNetworkServiceClient,
    MeshNodeServiceClient, OrganizationServiceClient, PortServiceClient, PresetServiceClient,
    SecretServiceClient,
};
use connectrpc::ConnectError;
use connectrpc::client::{BoxFuture, CallOptions, ClientBody, ClientTransport};
use http::{Request, Response};
use http_body_util::BodyExt as _;

#[cfg(feature = "desktop-keyring")]
pub use auth::KeyringCredentialStore;
pub use auth::{
    AuthClient, AuthClientError, AuthResponse, AuthSession, AuthUser, BearerToken,
    CODEWIRE_CLI_OAUTH_CLIENT_ID, CODEWIRE_CLI_OAUTH_SCOPES, CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
    CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI, CODEWIRE_DESKTOP_OAUTH_SCOPES, CredentialStore,
    FileCredentialStore, OAuthClient, OAuthCredentials, OAuthDeviceAuthorization, OAuthDiscovery,
    OAuthPkceAuthorization, OAuthTokenResponse, OAuthUserInfo, RefreshingTokenProvider,
    StaticTokenProvider, TokenProvider,
};
#[cfg(feature = "desktop-pkce-loopback")]
pub use auth::{DesktopOAuthCancellation, DesktopOAuthLogin};
pub use buffa::EnumValue;
pub use buffa_types::{Duration as ProtoDuration, Empty as ProtoEmpty, Timestamp};
pub use codewire_proto::codewire::console::v1::{
    BillingLimitUsage, BillingLimits, DeleteGitHubTokenRequest, DeleteGitHubTokenResponse,
    GetBillingOverviewRequest, GetBillingOverviewResponse, GetGitHubConfigRequest,
    GetGitHubConfigResponse, GetGitHubStatusRequest, GetGitHubStatusResponse,
    SaveGitHubTokenRequest, SaveGitHubTokenResponse, UsageSummary,
};
pub use codewire_proto::codewire::v1::{
    AccessGrant, AccessPermission, ApiKey, AppPort, AttachSessionOpen, AttachSessionRequest,
    AttachSessionResize, AttachSessionResponse, AttachSessionResponseView, AttachSessionStatus,
    CancelEnvironmentDeletionRequest, CancelEnvironmentDeletionResponse, CreateApiKeyRequest,
    CreateApiKeyResponse, CreateEnvironmentRequest, CreateEnvironmentResponse,
    CreateInvitationRequest, CreateInvitationResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatePortRequest, CreatePortResponse, CreatePresetRequest,
    CreatePresetResponse, DeleteApiKeyRequest, DeleteApiKeyResponse, DeleteEnvironmentRequest,
    DeleteEnvironmentResponse, DeleteOrganizationRequest, DeleteOrganizationResponse,
    DeletePortRequest, DeletePortResponse, DeletePresetRequest, DeletePresetResponse, DesiredState,
    DetectionResult, DownloadFileRequest, DownloadFileResponse, Environment,
    EnvironmentDaemonDiagnostic, EnvironmentDaemonState, EnvironmentDaemonStatus, EnvironmentLog,
    EnvironmentResizeDisruptionPolicy, EnvironmentResizeExecutionMode, EnvironmentResizeFailure,
    EnvironmentResizeOperation, EnvironmentResizeOperationState, EnvironmentResizePlan,
    EnvironmentResources, EnvironmentServiceClient as GeneratedEnvironmentServiceClient,
    EnvironmentSession, EnvironmentSessionOutputChunk, EnvironmentSessionOutputStream,
    EnvironmentSessionServiceClient as GeneratedEnvironmentSessionServiceClient,
    EnvironmentSessionState, EnvironmentState, EnvironmentTrustReport, ExecRequest, ExecResponse,
    ExecServiceClient as GeneratedExecServiceClient, ExtendEnvironmentTtlRequest,
    ExtendEnvironmentTtlResponse, FileEntry, FileServiceClient as GeneratedFileServiceClient,
    GetEnvironmentDaemonStatusRequest, GetEnvironmentDaemonStatusResponse, GetEnvironmentRequest,
    GetEnvironmentResizeOperationRequest, GetEnvironmentResizeOperationResponse,
    GetEnvironmentResponse, GetEnvironmentTrustReportRequest, GetEnvironmentTrustReportResponse,
    GetOrganizationRequest, GetOrganizationResponse, GetSessionRequest, GetSessionResponse,
    GrantEnvironmentAccessRequest, GrantEnvironmentAccessResponse, InvitationStatus, IsolationTier,
    LaunchSessionRequest, LaunchSessionResponse, ListApiKeysRequest, ListApiKeysResponse,
    ListEnvironmentAccessRequest, ListEnvironmentAccessResponse, ListEnvironmentsRequest,
    ListEnvironmentsResponse, ListFilesRequest, ListFilesResponse, ListOrganizationsRequest,
    ListOrganizationsResponse, ListPortsRequest, ListPortsResponse, ListPresetsRequest,
    ListPresetsResponse, ListSessionsRequest, ListSessionsResponse, OrgInvitation, OrgRole,
    Organization, OrganizationDeletionState, OrganizationMembership, PlanEnvironmentResizeRequest,
    PlanEnvironmentResizeResponse, Port, PortAccess, PrepareComplete, Preset, ProjectAgents,
    ProjectCredentialReference, ProjectResources, ProjectSecretBindings, ProjectSkillSelection,
    ProjectSkillSource, ProjectSpec, ProjectWorkspaceMode, ProtectEnvironmentRequest,
    ProtectEnvironmentResponse, ReadSessionOutputRequest, ReadSessionOutputResponse,
    RepairEnvironmentDaemonRequest, RepairEnvironmentDaemonResponse, RepoConfig, RepoEntry,
    ResizeEnvironmentRequest, ResizeEnvironmentResponse, RestartSessionRequest,
    RestartSessionResponse, RevokeEnvironmentAccessRequest, RevokeEnvironmentAccessResponse,
    RunRequest, RunResize, RunResponse, RunResponseView, RunStart, SecretMetadata, SecretProject,
    SetProjectSecretRequest, SetProjectSecretResponse, SetSecretRequest, SetSecretResponse,
    SetUserSecretRequest, SetUserSecretResponse, SetupAgent, StartEnvironmentRequest,
    StartEnvironmentResponse, StopEnvironmentRequest, StopEnvironmentResponse, StopSessionRequest,
    StopSessionResponse, StreamEnvironmentDaemonLogsRequest, StreamEnvironmentDaemonLogsResponse,
    StreamLogsRequest, StreamLogsResponse, UnprotectEnvironmentRequest,
    UnprotectEnvironmentResponse, UpdateApiKeyRequest, UpdateApiKeyResponse, UploadFileHeader,
    UploadFileRequest, UploadFileResponse, WatchEnvironmentCreateRequest,
    WatchEnvironmentCreateResponse,
};
pub use codewire_proto::codewire::v1::{
    CreateMeshInviteRequest, CreateMeshInviteResponse, CreateMeshNetworkRequest,
    CreateMeshNetworkResponse, CreateMeshNodeEnrollmentRequest, CreateMeshNodeEnrollmentResponse,
    JoinMeshNetworkRequest, JoinMeshNetworkResponse, ListMeshNetworksRequest,
    ListMeshNetworksResponse, ListMeshNodesRequest, ListMeshNodesResponse, MeshInvite, MeshNetwork,
    MeshNode, MeshNodeEnrollment, RedeemMeshNodeEnrollmentRequest,
    RedeemMeshNodeEnrollmentResponse, RevokeMeshNodeRequest, RevokeMeshNodeResponse,
};
pub use codewire_proto::codewire::v1::{
    CreateSecretProjectRequest, CreateSecretProjectResponse, DeleteProjectSecretRequest,
    DeleteProjectSecretResponse, DeleteSecretProjectRequest, DeleteSecretProjectResponse,
    DeleteSecretRequest, DeleteSecretResponse, DeleteUserSecretRequest, DeleteUserSecretResponse,
    ListProjectSecretsRequest, ListProjectSecretsResponse, ListSecretProjectsRequest,
    ListSecretProjectsResponse, ListSecretsRequest, ListSecretsResponse, ListUserSecretsRequest,
    ListUserSecretsResponse, RenameProjectSecretRequest, RenameProjectSecretResponse,
    RenameSecretRequest, RenameSecretResponse, RenameUserSecretRequest, RenameUserSecretResponse,
    attach_session_request, attach_session_response, download_file_response, run_request,
    run_response, stream_logs_response, upload_file_request, watch_environment_create_response,
};
pub use config::{
    CODEWIRE_API_URL_ENV, CODEWIRE_URL_ENV, ClientConfig, DEFAULT_CODEWIRE_URL,
    DEFAULT_UNARY_TIMEOUT,
};
pub use connectrpc::ErrorCode;
pub use coordinator::{
    COORDINATOR_SETUP_TIMEOUT, CoordinatorPeerSession, Handlers as CoordinatorHandlers,
    MeshCoordinateIdentity, MeshCoordinatorPeerSession, PrimaryCoordinateIdentity,
};
pub use error::{ClientError, ErrorInfo, ValidationError};
pub use tailnet::{
    EnvironmentTailnetDiagnostic, ExpectedTransport, NativeClientFacade, SshTransportMode,
    TailnetConnection, TailnetDerpMapDiagnostic, TailnetDiagnosticOptions, TailnetDiagnosticStage,
    TailnetPathDiagnostic, TailnetPeerDiagnostic, diagnose_environment_tailnet, parse_duration,
    pipe_shell_stdio,
};
/// The one Rust client core consumed by the CLI and future native bindings.
#[derive(Clone)]
pub struct CodewireClient {
    config: ClientConfig,
    token_provider: Arc<dyn TokenProvider>,
    http: reqwest::Client,
    api_keys: ApiKeyServiceClient<ReqwestConnectTransport>,
    environments: EnvironmentServiceClient<ReqwestConnectTransport>,
    sessions: EnvironmentSessionServiceClient<ReqwestConnectTransport>,
    exec: ExecServiceClient<ReqwestConnectTransport>,
    files: FileServiceClient<ReqwestConnectTransport>,
    organizations: OrganizationServiceClient<ReqwestConnectTransport>,
    presets: PresetServiceClient<ReqwestConnectTransport>,
    ports: PortServiceClient<ReqwestConnectTransport>,
    secrets: SecretServiceClient<ReqwestConnectTransport>,
    billing: BillingServiceClient<ReqwestConnectTransport>,
    github: GitHubServiceClient<ReqwestConnectTransport>,
    mesh_networks: MeshNetworkServiceClient<ReqwestConnectTransport>,
    mesh_nodes: MeshNodeServiceClient<ReqwestConnectTransport>,
    mesh_invites: MeshInviteServiceClient<ReqwestConnectTransport>,
}

/// Unauthenticated public durable-session facade over a caller-owned
/// transport. Local runtimes use this with an owner-verified Unix-socket HTTP/2
/// connection; platform callers continue to use [`CodewireClient`] so bearer
/// refresh and authorization remain platform-owned.
#[derive(Clone)]
pub struct PublicEnvironmentSessionClient<T> {
    sessions: EnvironmentSessionServiceClient<T>,
}

pub struct RunSession {
    input: RunSessionInput,
    output: tokio::sync::mpsc::Receiver<Result<RunResponse, ClientError>>,
    driver: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
pub struct RunSessionInput {
    input: tokio::sync::mpsc::Sender<RunRequest>,
    terminal_error: tokio::sync::watch::Receiver<Option<ClientError>>,
}

/// Managed bidirectional attachment to a durable environment session.
///
/// The attachment is a thin ergonomic layer over the generated Connect stream:
/// it owns the background transport driver, reports terminal errors through
/// both handles, and half-closes cleanly after detach or a terminal status.
pub struct EnvironmentSessionAttachment {
    input: EnvironmentSessionAttachmentInput,
    output: tokio::sync::mpsc::Receiver<Result<AttachSessionResponse, ClientError>>,
    driver: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
pub struct EnvironmentSessionAttachmentInput {
    input: tokio::sync::mpsc::Sender<AttachSessionRequest>,
    terminal_error: tokio::sync::watch::Receiver<Option<ClientError>>,
}

const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(600);

impl<T> PublicEnvironmentSessionClient<T>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    pub fn new(transport: T, config: connectrpc::client::ClientConfig) -> Self {
        Self {
            sessions: EnvironmentSessionServiceClient::new(transport, config),
        }
    }

    pub async fn launch_session(
        &self,
        request: LaunchSessionRequest,
    ) -> Result<LaunchSessionResponse, ClientError> {
        self.sessions
            .launch_session(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_sessions(
        &self,
        request: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, ClientError> {
        self.sessions
            .list_sessions(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_session(
        &self,
        request: GetSessionRequest,
    ) -> Result<GetSessionResponse, ClientError> {
        self.sessions
            .get_session(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn stop_session(
        &self,
        request: StopSessionRequest,
    ) -> Result<StopSessionResponse, ClientError> {
        self.sessions
            .stop_session(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn restart_session(
        &self,
        request: RestartSessionRequest,
    ) -> Result<RestartSessionResponse, ClientError> {
        self.sessions
            .restart_session(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn read_session_output(
        &self,
        request: ReadSessionOutputRequest,
    ) -> Result<ReadSessionOutputResponse, ClientError> {
        self.sessions
            .read_session_output(request)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn attach_session(
        &self,
        open: AttachSessionOpen,
    ) -> Result<EnvironmentSessionAttachment, ClientError> {
        let stream = self
            .sessions
            .attach_session()
            .await
            .map_err(ClientError::from)?;
        start_environment_session_attachment(stream, open).await
    }
}

impl CodewireClient {
    pub fn new(
        config: ClientConfig,
        token_provider: impl TokenProvider + 'static,
    ) -> Result<Self, ClientError> {
        let http = default_http_client(&config)?;
        Self::with_http(config, token_provider, http)
    }

    /// Construct with a caller-supplied HTTP client for tests and custom TLS
    /// policy.
    pub fn with_http(
        config: ClientConfig,
        token_provider: impl TokenProvider + 'static,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        Self::with_http_token_provider(config, Arc::new(token_provider), http)
    }

    /// Construct from a shared token provider. Native consumers use this for
    /// the single refresh-capable OAuth provider across every generated
    /// Connect facade.
    pub fn with_token_provider(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ClientError> {
        let http = default_http_client(&config)?;
        Self::with_http_token_provider(config, token_provider, http)
    }

    /// Construct with a shared provider and caller-supplied HTTP client for
    /// tests and custom TLS policy.
    pub fn with_http_token_provider(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        let api_key_config = config.connect_config()?;
        let environment_config = config.connect_config()?;
        let session_config = config.environment_session_connect_config()?;
        let exec_config = config.connect_config()?;
        let file_config = config.connect_config()?;
        let organization_config = config.connect_config()?;
        let preset_config = config.connect_config()?;
        let port_config = config.connect_config()?;
        let secret_config = config.connect_config()?;
        let billing_config = config.connect_config()?;
        let github_config = config.connect_config()?;
        let mesh_network_config = config.mesh_connect_config()?;
        let mesh_node_config = config.mesh_connect_config()?;
        let mesh_invite_config = config.mesh_connect_config()?;
        Ok(Self {
            config,
            token_provider,
            http: http.clone(),
            api_keys: ApiKeyServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                api_key_config,
            ),
            environments: EnvironmentServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                environment_config,
            ),
            sessions: EnvironmentSessionServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                session_config,
            ),
            exec: ExecServiceClient::new(ReqwestConnectTransport(http.clone()), exec_config),
            files: FileServiceClient::new(ReqwestConnectTransport(http.clone()), file_config),
            organizations: OrganizationServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                organization_config,
            ),
            presets: PresetServiceClient::new(ReqwestConnectTransport(http.clone()), preset_config),
            ports: PortServiceClient::new(ReqwestConnectTransport(http.clone()), port_config),
            secrets: SecretServiceClient::new(ReqwestConnectTransport(http.clone()), secret_config),
            billing: BillingServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                billing_config,
            ),
            github: GitHubServiceClient::new(ReqwestConnectTransport(http.clone()), github_config),
            mesh_networks: MeshNetworkServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                mesh_network_config,
            ),
            mesh_nodes: MeshNodeServiceClient::new(
                ReqwestConnectTransport(http.clone()),
                mesh_node_config,
            ),
            mesh_invites: MeshInviteServiceClient::new(
                ReqwestConnectTransport(http),
                mesh_invite_config,
            ),
        })
    }

    pub fn server_url(&self) -> &url::Url {
        self.config.server_url()
    }

    /// Resolve the current credential for permanent non-Connect transports.
    pub async fn bearer_token(&self) -> Result<BearerToken, ClientError> {
        self.token_provider.token().await
    }

    /// Access the permanent raw-HTTP identity-plane client through the same
    /// configuration, token provider, and HTTP seam as generated Connect RPCs.
    pub fn auth(&self) -> AuthClient {
        AuthClient::authenticated(
            self.config.clone(),
            Arc::clone(&self.token_provider),
            self.http.clone(),
        )
    }

    pub async fn get_billing_overview(
        &self,
        request: GetBillingOverviewRequest,
    ) -> Result<GetBillingOverviewResponse, ClientError> {
        self.billing
            .get_billing_overview_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_github_config(
        &self,
        request: GetGitHubConfigRequest,
    ) -> Result<GetGitHubConfigResponse, ClientError> {
        self.github
            .get_git_hub_config_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_github_status(
        &self,
        request: GetGitHubStatusRequest,
    ) -> Result<GetGitHubStatusResponse, ClientError> {
        self.github
            .get_git_hub_status_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn save_github_token(
        &self,
        request: SaveGitHubTokenRequest,
    ) -> Result<SaveGitHubTokenResponse, ClientError> {
        self.github
            .save_git_hub_token_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_github_token(
        &self,
        request: DeleteGitHubTokenRequest,
    ) -> Result<DeleteGitHubTokenResponse, ClientError> {
        self.github
            .delete_git_hub_token_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_api_keys(
        &self,
        request: ListApiKeysRequest,
    ) -> Result<ListApiKeysResponse, ClientError> {
        self.api_keys
            .list_api_keys_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
    ) -> Result<CreateApiKeyResponse, ClientError> {
        self.api_keys
            .create_api_key_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn update_api_key(
        &self,
        request: UpdateApiKeyRequest,
    ) -> Result<UpdateApiKeyResponse, ClientError> {
        self.api_keys
            .update_api_key_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_api_key(
        &self,
        request: DeleteApiKeyRequest,
    ) -> Result<DeleteApiKeyResponse, ClientError> {
        self.api_keys
            .delete_api_key_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_organizations(
        &self,
        request: ListOrganizationsRequest,
    ) -> Result<ListOrganizationsResponse, ClientError> {
        self.organizations
            .list_organizations_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_organization(
        &self,
        request: CreateOrganizationRequest,
    ) -> Result<CreateOrganizationResponse, ClientError> {
        self.organizations
            .create_organization_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_organization(
        &self,
        request: GetOrganizationRequest,
    ) -> Result<GetOrganizationResponse, ClientError> {
        self.organizations
            .get_organization_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_organization(
        &self,
        request: DeleteOrganizationRequest,
    ) -> Result<DeleteOrganizationResponse, ClientError> {
        self.organizations
            .delete_organization_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_invitation(
        &self,
        request: CreateInvitationRequest,
    ) -> Result<CreateInvitationResponse, ClientError> {
        self.organizations
            .create_invitation_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_presets(
        &self,
        request: ListPresetsRequest,
    ) -> Result<ListPresetsResponse, ClientError> {
        self.presets
            .list_presets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_preset(
        &self,
        request: CreatePresetRequest,
    ) -> Result<CreatePresetResponse, ClientError> {
        self.presets
            .create_preset_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_preset(
        &self,
        request: DeletePresetRequest,
    ) -> Result<DeletePresetResponse, ClientError> {
        self.presets
            .delete_preset_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_ports(
        &self,
        request: ListPortsRequest,
    ) -> Result<ListPortsResponse, ClientError> {
        self.ports
            .list_ports_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_port(
        &self,
        request: CreatePortRequest,
    ) -> Result<CreatePortResponse, ClientError> {
        self.ports
            .create_port_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_port(
        &self,
        request: DeletePortRequest,
    ) -> Result<DeletePortResponse, ClientError> {
        self.ports
            .delete_port_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_secrets(
        &self,
        request: ListSecretsRequest,
    ) -> Result<ListSecretsResponse, ClientError> {
        self.secrets
            .list_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_secret(
        &self,
        request: SetSecretRequest,
    ) -> Result<SetSecretResponse, ClientError> {
        self.secrets
            .set_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_secret(
        &self,
        request: DeleteSecretRequest,
    ) -> Result<DeleteSecretResponse, ClientError> {
        self.secrets
            .delete_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_secret(
        &self,
        request: RenameSecretRequest,
    ) -> Result<RenameSecretResponse, ClientError> {
        self.secrets
            .rename_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_user_secrets(
        &self,
        request: ListUserSecretsRequest,
    ) -> Result<ListUserSecretsResponse, ClientError> {
        self.secrets
            .list_user_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_user_secret(
        &self,
        request: SetUserSecretRequest,
    ) -> Result<SetUserSecretResponse, ClientError> {
        self.secrets
            .set_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_user_secret(
        &self,
        request: DeleteUserSecretRequest,
    ) -> Result<DeleteUserSecretResponse, ClientError> {
        self.secrets
            .delete_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_user_secret(
        &self,
        request: RenameUserSecretRequest,
    ) -> Result<RenameUserSecretResponse, ClientError> {
        self.secrets
            .rename_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_secret_projects(
        &self,
        request: ListSecretProjectsRequest,
    ) -> Result<ListSecretProjectsResponse, ClientError> {
        self.secrets
            .list_secret_projects_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_secret_project(
        &self,
        request: CreateSecretProjectRequest,
    ) -> Result<CreateSecretProjectResponse, ClientError> {
        self.secrets
            .create_secret_project_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_secret_project(
        &self,
        request: DeleteSecretProjectRequest,
    ) -> Result<DeleteSecretProjectResponse, ClientError> {
        self.secrets
            .delete_secret_project_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_project_secrets(
        &self,
        request: ListProjectSecretsRequest,
    ) -> Result<ListProjectSecretsResponse, ClientError> {
        self.secrets
            .list_project_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_project_secret(
        &self,
        request: SetProjectSecretRequest,
    ) -> Result<SetProjectSecretResponse, ClientError> {
        self.secrets
            .set_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_project_secret(
        &self,
        request: DeleteProjectSecretRequest,
    ) -> Result<DeleteProjectSecretResponse, ClientError> {
        self.secrets
            .delete_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_project_secret(
        &self,
        request: RenameProjectSecretRequest,
    ) -> Result<RenameProjectSecretResponse, ClientError> {
        self.secrets
            .rename_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_environments(
        &self,
        request: ListEnvironmentsRequest,
    ) -> Result<ListEnvironmentsResponse, ClientError> {
        self.environments
            .list_environments_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_environment(
        &self,
        request: CreateEnvironmentRequest,
    ) -> Result<CreateEnvironmentResponse, ClientError> {
        self.environments
            .create_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_environment(
        &self,
        request: GetEnvironmentRequest,
    ) -> Result<GetEnvironmentResponse, ClientError> {
        self.environments
            .get_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn resize_environment(
        &self,
        request: ResizeEnvironmentRequest,
    ) -> Result<ResizeEnvironmentResponse, ClientError> {
        self.environments
            .resize_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn plan_environment_resize(
        &self,
        request: PlanEnvironmentResizeRequest,
    ) -> Result<PlanEnvironmentResizeResponse, ClientError> {
        self.environments
            .plan_environment_resize_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_environment_resize_operation(
        &self,
        request: GetEnvironmentResizeOperationRequest,
    ) -> Result<GetEnvironmentResizeOperationResponse, ClientError> {
        self.environments
            .get_environment_resize_operation_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_environment(
        &self,
        request: DeleteEnvironmentRequest,
    ) -> Result<DeleteEnvironmentResponse, ClientError> {
        self.environments
            .delete_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn stop_environment(
        &self,
        request: StopEnvironmentRequest,
    ) -> Result<StopEnvironmentResponse, ClientError> {
        self.environments
            .stop_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn start_environment(
        &self,
        request: StartEnvironmentRequest,
    ) -> Result<StartEnvironmentResponse, ClientError> {
        self.environments
            .start_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn protect_environment(
        &self,
        request: ProtectEnvironmentRequest,
    ) -> Result<ProtectEnvironmentResponse, ClientError> {
        self.environments
            .protect_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn unprotect_environment(
        &self,
        request: UnprotectEnvironmentRequest,
    ) -> Result<UnprotectEnvironmentResponse, ClientError> {
        self.environments
            .unprotect_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn cancel_environment_deletion(
        &self,
        request: CancelEnvironmentDeletionRequest,
    ) -> Result<CancelEnvironmentDeletionResponse, ClientError> {
        self.environments
            .cancel_environment_deletion_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn extend_environment_ttl(
        &self,
        request: ExtendEnvironmentTtlRequest,
    ) -> Result<ExtendEnvironmentTtlResponse, ClientError> {
        self.environments
            .extend_environment_ttl_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_environment_trust_report(
        &self,
        request: GetEnvironmentTrustReportRequest,
    ) -> Result<GetEnvironmentTrustReportResponse, ClientError> {
        self.environments
            .get_environment_trust_report_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_environment_daemon_status(
        &self,
        request: GetEnvironmentDaemonStatusRequest,
    ) -> Result<GetEnvironmentDaemonStatusResponse, ClientError> {
        self.environments
            .get_environment_daemon_status_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn stream_environment_daemon_logs(
        &self,
        request: StreamEnvironmentDaemonLogsRequest,
        mut on_message: impl FnMut(StreamEnvironmentDaemonLogsResponse) -> bool,
    ) -> Result<(), ClientError> {
        let mut stream = self
            .environments
            .stream_environment_daemon_logs_with_options(request, self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        while let Some(message) = stream
            .message::<StreamEnvironmentDaemonLogsResponse>()
            .await
            .map_err(ClientError::from)?
        {
            if !on_message(message.to_owned_message()) {
                break;
            }
        }
        Ok(())
    }

    pub async fn repair_environment_daemon(
        &self,
        request: RepairEnvironmentDaemonRequest,
    ) -> Result<RepairEnvironmentDaemonResponse, ClientError> {
        self.environments
            .repair_environment_daemon_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_environment_access(
        &self,
        request: ListEnvironmentAccessRequest,
    ) -> Result<ListEnvironmentAccessResponse, ClientError> {
        self.environments
            .list_environment_access_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn grant_environment_access(
        &self,
        request: GrantEnvironmentAccessRequest,
    ) -> Result<GrantEnvironmentAccessResponse, ClientError> {
        self.environments
            .grant_environment_access_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn revoke_environment_access(
        &self,
        request: RevokeEnvironmentAccessRequest,
    ) -> Result<RevokeEnvironmentAccessResponse, ClientError> {
        self.environments
            .revoke_environment_access_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn watch_environment_create(
        &self,
        request: WatchEnvironmentCreateRequest,
    ) -> Result<Vec<WatchEnvironmentCreateResponse>, ClientError> {
        let mut stream = self
            .environments
            .watch_environment_create_with_options(request, self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        let mut events = Vec::new();
        while let Some(message) = stream
            .message::<WatchEnvironmentCreateResponse>()
            .await
            .map_err(ClientError::from)?
        {
            events.push(message.to_owned_message());
        }
        Ok(events)
    }

    pub async fn stream_logs(
        &self,
        request: StreamLogsRequest,
        mut on_message: impl FnMut(StreamLogsResponse) -> bool,
    ) -> Result<(), ClientError> {
        let mut stream = self
            .environments
            .stream_logs_with_options(request, self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        while let Some(message) = stream
            .message::<StreamLogsResponse>()
            .await
            .map_err(ClientError::from)?
        {
            if !on_message(message.to_owned_message()) {
                break;
            }
        }
        Ok(())
    }

    pub async fn exec(&self, request: ExecRequest) -> Result<ExecResponse, ClientError> {
        let timeout = request
            .timeout
            .clone()
            .into_option()
            .and_then(|timeout| Duration::try_from(timeout).ok())
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(DEFAULT_EXEC_TIMEOUT);
        self.exec
            .exec_with_options(request, self.auth_options().await?.with_timeout(timeout))
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn run(&self, start: RunStart) -> Result<RunSession, ClientError> {
        let mut stream = self
            .exec
            .run_with_options(self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        stream
            .send(RunRequest {
                input: Some(run_request::Input::Start(Box::new(start))),
                ..Default::default()
            })
            .await
            .map_err(ClientError::from)?;

        let (input_tx, input_rx) = tokio::sync::mpsc::channel(32);
        let (output_tx, output_rx) = tokio::sync::mpsc::channel(32);
        let (terminal_error_tx, terminal_error_rx) = tokio::sync::watch::channel(None);
        let driver = tokio::spawn(run_stream_driver(
            stream,
            input_rx,
            output_tx,
            terminal_error_tx,
        ));
        Ok(RunSession {
            input: RunSessionInput {
                input: input_tx,
                terminal_error: terminal_error_rx,
            },
            output: output_rx,
            driver,
        })
    }

    pub async fn launch_session(
        &self,
        request: LaunchSessionRequest,
    ) -> Result<LaunchSessionResponse, ClientError> {
        self.sessions
            .launch_session_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_sessions(
        &self,
        request: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, ClientError> {
        self.sessions
            .list_sessions_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_session(
        &self,
        request: GetSessionRequest,
    ) -> Result<GetSessionResponse, ClientError> {
        self.sessions
            .get_session_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn stop_session(
        &self,
        request: StopSessionRequest,
    ) -> Result<StopSessionResponse, ClientError> {
        self.sessions
            .stop_session_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn restart_session(
        &self,
        request: RestartSessionRequest,
    ) -> Result<RestartSessionResponse, ClientError> {
        self.sessions
            .restart_session_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn read_session_output(
        &self,
        request: ReadSessionOutputRequest,
    ) -> Result<ReadSessionOutputResponse, ClientError> {
        self.sessions
            .read_session_output_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Open a reconnectable durable-session attachment. The facade sends the
    /// required `open` frame before returning a writable input handle.
    pub async fn attach_session(
        &self,
        open: AttachSessionOpen,
    ) -> Result<EnvironmentSessionAttachment, ClientError> {
        let stream = self
            .sessions
            .attach_session_with_options(self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        start_environment_session_attachment(stream, open).await
    }

    pub async fn list_files(
        &self,
        request: ListFilesRequest,
    ) -> Result<ListFilesResponse, ClientError> {
        self.files
            .list_files_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn download_file(
        &self,
        request: DownloadFileRequest,
    ) -> Result<Vec<DownloadFileResponse>, ClientError> {
        let mut stream = self
            .files
            .download_file_with_options(request, self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        let mut responses = Vec::new();
        while let Some(message) = stream
            .message::<DownloadFileResponse>()
            .await
            .map_err(ClientError::from)?
        {
            responses.push(message.to_owned_message());
        }
        Ok(responses)
    }

    pub async fn upload_file(
        &self,
        requests: impl IntoIterator<Item = UploadFileRequest>,
    ) -> Result<UploadFileResponse, ClientError> {
        self.files
            .upload_file_with_options(requests, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    async fn auth_options(&self) -> Result<CallOptions, ClientError> {
        let token = self.bearer_token().await?;
        CallOptions::default()
            .try_with_header("authorization", token.authorization_header())
            .map_err(ClientError::from)
    }

    async fn session_unary_options(&self) -> Result<CallOptions, ClientError> {
        Ok(self
            .auth_options()
            .await?
            .with_timeout(self.config.unary_timeout()))
    }
}

async fn start_environment_session_attachment<B>(
    mut stream: connectrpc::client::BidiStream<
        B,
        AttachSessionRequest,
        AttachSessionResponseView<'static>,
    >,
    open: AttachSessionOpen,
) -> Result<EnvironmentSessionAttachment, ClientError>
where
    B: connectrpc::http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display,
{
    stream
        .send(AttachSessionRequest {
            input: Some(attach_session_request::Input::Open(Box::new(open))),
            ..Default::default()
        })
        .await
        .map_err(ClientError::from)?;

    let (input_tx, input_rx) = tokio::sync::mpsc::channel(32);
    let (output_tx, output_rx) = tokio::sync::mpsc::channel(32);
    let (terminal_error_tx, terminal_error_rx) = tokio::sync::watch::channel(None);
    let driver = tokio::spawn(attach_session_stream_driver(
        stream,
        input_rx,
        output_tx,
        terminal_error_tx,
    ));
    Ok(EnvironmentSessionAttachment {
        input: EnvironmentSessionAttachmentInput {
            input: input_tx,
            terminal_error: terminal_error_rx,
        },
        output: output_rx,
        driver,
    })
}

impl RunSession {
    pub fn input_handle(&self) -> RunSessionInput {
        self.input.clone()
    }

    pub async fn send(&self, request: RunRequest) -> Result<(), ClientError> {
        self.input.send(request).await
    }

    pub async fn next_output(&mut self) -> Result<Option<RunResponse>, ClientError> {
        match self.output.recv().await {
            Some(Ok(response)) => Ok(Some(response)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
}

impl Drop for RunSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl RunSessionInput {
    pub async fn send(&self, request: RunRequest) -> Result<(), ClientError> {
        if let Some(error) = self.terminal_error.borrow().clone() {
            return Err(error);
        }
        self.input.send(request).await.map_err(|_| {
            self.terminal_error.borrow().clone().unwrap_or_else(|| {
                ClientError::new(
                    ErrorCode::Unavailable,
                    "environment command stream is closed",
                )
            })
        })
    }
}

impl EnvironmentSessionAttachment {
    pub fn input_handle(&self) -> EnvironmentSessionAttachmentInput {
        self.input.clone()
    }

    pub async fn send(&self, request: AttachSessionRequest) -> Result<(), ClientError> {
        self.input.send(request).await
    }

    pub async fn next_output(&mut self) -> Result<Option<AttachSessionResponse>, ClientError> {
        match self.output.recv().await {
            Some(Ok(response)) => Ok(Some(response)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
}

impl Drop for EnvironmentSessionAttachment {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl EnvironmentSessionAttachmentInput {
    pub async fn send(&self, request: AttachSessionRequest) -> Result<(), ClientError> {
        if let Some(error) = self.terminal_error.borrow().clone() {
            return Err(error);
        }
        self.input.send(request).await.map_err(|_| {
            self.terminal_error.borrow().clone().unwrap_or_else(|| {
                ClientError::new(
                    ErrorCode::Unavailable,
                    "environment session attachment is closed",
                )
            })
        })
    }
}

async fn run_stream_driver(
    mut stream: connectrpc::client::BidiStream<reqwest::Body, RunRequest, RunResponseView<'static>>,
    mut input: tokio::sync::mpsc::Receiver<RunRequest>,
    output: tokio::sync::mpsc::Sender<Result<RunResponse, ClientError>>,
    terminal_error: tokio::sync::watch::Sender<Option<ClientError>>,
) {
    loop {
        tokio::select! {
            request = input.recv() => {
                let Some(request) = request else {
                    return;
                };
                if let Err(error) = stream.send(request).await {
                    report_run_stream_error(&output, &terminal_error, error).await;
                    return;
                }
            }
            response = stream.message::<RunResponse>() => {
                match response {
                    Ok(Some(response)) => {
                        let response = response.to_owned_message();
                        let exited = matches!(
                            response.event.as_ref(),
                            Some(run_response::Event::ExitCode(_))
                        );
                        if exited {
                            // A terminal exit is the protocol boundary for this RPC, not
                            // merely an application event.  Half-close the request and
                            // drain the Connect response before exposing it to callers.
                            // Otherwise a caller that returns on ExitCode can abort the
                            // driver while ingress still owns an HTTP/1.1 request body,
                            // leaving a stale connection for its next Run.
                            stream.close_send();
                            match stream.message::<RunResponse>().await {
                                Ok(None) => {}
                                Ok(Some(_)) => {
                                    report_run_stream_error(
                                        &output,
                                        &terminal_error,
                                        ConnectError::internal(
                                            "environment command stream emitted data after exit",
                                        ),
                                    )
                                    .await;
                                    return;
                                }
                                Err(error) => {
                                    report_run_stream_error(&output, &terminal_error, error).await;
                                    return;
                                }
                            }
                        }
                        if output.send(Ok(response)).await.is_err() {
                            return;
                        }
                        if exited {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        report_run_stream_error(&output, &terminal_error, error).await;
                        return;
                    }
                }
            }
        }
    }
}

async fn attach_session_stream_driver<B>(
    mut stream: connectrpc::client::BidiStream<
        B,
        AttachSessionRequest,
        AttachSessionResponseView<'static>,
    >,
    mut input: tokio::sync::mpsc::Receiver<AttachSessionRequest>,
    output: tokio::sync::mpsc::Sender<Result<AttachSessionResponse, ClientError>>,
    terminal_error: tokio::sync::watch::Sender<Option<ClientError>>,
) where
    B: connectrpc::http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display,
{
    let mut input_closed = false;
    loop {
        tokio::select! {
            request = input.recv(), if !input_closed => {
                let Some(request) = request else {
                    stream.close_send();
                    input_closed = true;
                    continue;
                };
                let detach = matches!(
                    request.input.as_ref(),
                    Some(attach_session_request::Input::Detach(_))
                );
                if let Err(error) = stream.send(request).await {
                    report_attachment_stream_error(&output, &terminal_error, error).await;
                    return;
                }
                if detach {
                    stream.close_send();
                    input_closed = true;
                }
            }
            response = stream.message::<AttachSessionResponse>() => {
                match response {
                    Ok(Some(response)) => {
                        let response = response.to_owned_message();
                        let terminal = attachment_response_is_terminal(&response);
                        if terminal {
                            stream.close_send();
                        }
                        if output.send(Ok(response)).await.is_err() {
                            return;
                        }
                        if terminal {
                            match stream.message::<AttachSessionResponse>().await {
                                Ok(None) => return,
                                Ok(Some(_)) => {
                                    report_attachment_stream_error(
                                        &output,
                                        &terminal_error,
                                        ConnectError::internal(
                                            "environment session attachment emitted data after terminal status",
                                        ),
                                    )
                                    .await;
                                    return;
                                }
                                Err(error) => {
                                    report_attachment_stream_error(&output, &terminal_error, error).await;
                                    return;
                                }
                            }
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        report_attachment_stream_error(&output, &terminal_error, error).await;
                        return;
                    }
                }
            }
        }
    }
}

fn attachment_response_is_terminal(response: &AttachSessionResponse) -> bool {
    let Some(attach_session_response::Event::Status(status)) = response.event.as_ref() else {
        return false;
    };
    let Some(session) = status.session.as_option() else {
        return false;
    };
    matches!(
        session.state.as_known(),
        Some(
            EnvironmentSessionState::Stopped
                | EnvironmentSessionState::Exited
                | EnvironmentSessionState::Failed
                | EnvironmentSessionState::Interrupted
        )
    )
}

async fn report_attachment_stream_error(
    output: &tokio::sync::mpsc::Sender<Result<AttachSessionResponse, ClientError>>,
    terminal_error: &tokio::sync::watch::Sender<Option<ClientError>>,
    error: impl Into<ClientError>,
) {
    let error = error.into();
    let _ = terminal_error.send(Some(error.clone()));
    let _ = output.send(Err(error)).await;
}

async fn report_run_stream_error(
    output: &tokio::sync::mpsc::Sender<Result<RunResponse, ClientError>>,
    terminal_error: &tokio::sync::watch::Sender<Option<ClientError>>,
    error: impl Into<ClientError>,
) {
    let error = error.into();
    let _ = terminal_error.send(Some(error.clone()));
    let _ = output.send(Err(error)).await;
}

/// Adapter for connect-rust's transport trait using the repository-standard
/// rustls-backed reqwest client.
#[derive(Clone)]
struct ReqwestConnectTransport(reqwest::Client);

fn default_http_client(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    let builder = if config.server_url().scheme() == "http" {
        // Connect bidi needs HTTP/2 for interleaved input/output. Cleartext
        // direct endpoints therefore use h2c prior knowledge; TLS endpoints
        // negotiate HTTP/2 with ALPN through the ordinary client.
        reqwest::Client::builder().http2_prior_knowledge()
    } else {
        reqwest::Client::builder()
    };
    builder.build().map_err(|error| {
        ClientError::new(
            ErrorCode::Internal,
            format!("build Codewire HTTP client: {error}"),
        )
    })
}

impl ClientTransport for ReqwestConnectTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = reqwest::Body::wrap_stream(body.into_data_stream());
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|error| ConnectError::unavailable(format!("send request: {error}")))?;
            // Use reqwest's lossless HTTP conversion. Rebuilding the response
            // from `bytes_stream()` discards HTTP/2 trailer frames, including
            // the mandatory `grpc-status` used by native gRPC.
            Ok(Response::<reqwest::Body>::from(response))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use buffa::Message as _;
    use codewire_proto::google::rpc::{BadRequest, ErrorInfo as GoogleErrorInfo, RetryInfo};
    use connectrpc::{ConnectError, ErrorDetail};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const LIST_API_KEYS_PATH: &str = "/codewire.v1.ApiKeyService/ListApiKeys";
    const LIST_ENVIRONMENTS_PATH: &str = "/codewire.v1.EnvironmentService/ListEnvironments";
    const LIST_ORGANIZATIONS_PATH: &str = "/codewire.v1.OrganizationService/ListOrganizations";
    const CREATE_ORGANIZATION_PATH: &str = "/codewire.v1.OrganizationService/CreateOrganization";
    const GET_ORGANIZATION_PATH: &str = "/codewire.v1.OrganizationService/GetOrganization";
    const DELETE_ORGANIZATION_PATH: &str = "/codewire.v1.OrganizationService/DeleteOrganization";
    const CREATE_INVITATION_PATH: &str = "/codewire.v1.OrganizationService/CreateInvitation";
    const LIST_PRESETS_PATH: &str = "/codewire.v1.PresetService/ListPresets";
    const CREATE_PRESET_PATH: &str = "/codewire.v1.PresetService/CreatePreset";
    const DELETE_PRESET_PATH: &str = "/codewire.v1.PresetService/DeletePreset";
    const LIST_PORTS_PATH: &str = "/codewire.v1.PortService/ListPorts";
    const CREATE_PORT_PATH: &str = "/codewire.v1.PortService/CreatePort";
    const DELETE_PORT_PATH: &str = "/codewire.v1.PortService/DeletePort";
    const LIST_SECRETS_PATH: &str = "/codewire.v1.SecretService/ListSecrets";
    const SET_SECRET_PATH: &str = "/codewire.v1.SecretService/SetSecret";
    const DELETE_SECRET_PATH: &str = "/codewire.v1.SecretService/DeleteSecret";
    const RENAME_SECRET_PATH: &str = "/codewire.v1.SecretService/RenameSecret";
    const LIST_USER_SECRETS_PATH: &str = "/codewire.v1.SecretService/ListUserSecrets";
    const SET_USER_SECRET_PATH: &str = "/codewire.v1.SecretService/SetUserSecret";
    const DELETE_USER_SECRET_PATH: &str = "/codewire.v1.SecretService/DeleteUserSecret";
    const RENAME_USER_SECRET_PATH: &str = "/codewire.v1.SecretService/RenameUserSecret";
    const LIST_SECRET_PROJECTS_PATH: &str = "/codewire.v1.SecretService/ListSecretProjects";
    const CREATE_SECRET_PROJECT_PATH: &str = "/codewire.v1.SecretService/CreateSecretProject";
    const DELETE_SECRET_PROJECT_PATH: &str = "/codewire.v1.SecretService/DeleteSecretProject";
    const LIST_PROJECT_SECRETS_PATH: &str = "/codewire.v1.SecretService/ListProjectSecrets";
    const SET_PROJECT_SECRET_PATH: &str = "/codewire.v1.SecretService/SetProjectSecret";
    const DELETE_PROJECT_SECRET_PATH: &str = "/codewire.v1.SecretService/DeleteProjectSecret";
    const RENAME_PROJECT_SECRET_PATH: &str = "/codewire.v1.SecretService/RenameProjectSecret";
    const GET_BILLING_OVERVIEW_PATH: &str =
        "/codewire.console.v1.BillingService/GetBillingOverview";
    const GET_GITHUB_CONFIG_PATH: &str = "/codewire.console.v1.GitHubService/GetGitHubConfig";
    const GET_GITHUB_STATUS_PATH: &str = "/codewire.console.v1.GitHubService/GetGitHubStatus";
    const SAVE_GITHUB_TOKEN_PATH: &str = "/codewire.console.v1.GitHubService/SaveGitHubToken";
    const DELETE_GITHUB_TOKEN_PATH: &str = "/codewire.console.v1.GitHubService/DeleteGitHubToken";
    const EXEC_PATH: &str = "/codewire.v1.ExecService/Exec";
    const LAUNCH_SESSION_PATH: &str = "/codewire.v1.EnvironmentSessionService/LaunchSession";
    const LIST_SESSIONS_PATH: &str = "/codewire.v1.EnvironmentSessionService/ListSessions";

    async fn test_client(server: &MockServer) -> CodewireClient {
        let config = ClientConfig::new(server.uri())
            .expect("server URL")
            .with_user_agent("codewire-client-test/1")
            .expect("user-agent");
        CodewireClient::with_http(
            config,
            StaticTokenProvider::new("test-token").expect("token"),
            reqwest::Client::new(),
        )
        .expect("client")
    }

    #[derive(Clone)]
    struct GatedBidiTransport {
        response:
            Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<Response<reqwest::Body>>>>>,
    }

    impl ClientTransport for GatedBidiTransport {
        type ResponseBody = reqwest::Body;
        type Error = ConnectError;

        fn send(
            &self,
            request: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            let response = self
                .response
                .lock()
                .expect("gated response mutex")
                .take()
                .expect("one bidi request");
            Box::pin(async move {
                let result = response.await.map_err(|_| {
                    ConnectError::unavailable("test transport response was cancelled")
                });
                drop(request);
                result
            })
        }
    }

    #[derive(Clone)]
    struct CapturingBidiTransport {
        response:
            Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<Response<reqwest::Body>>>>>,
        request_body: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<ClientBody>>>>,
    }

    impl ClientTransport for CapturingBidiTransport {
        type ResponseBody = reqwest::Body;
        type Error = ConnectError;

        fn send(
            &self,
            request: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            let response = self
                .response
                .lock()
                .expect("captured response mutex")
                .take()
                .expect("one bidi request");
            let request_body = self
                .request_body
                .lock()
                .expect("captured request body mutex")
                .take()
                .expect("one captured request body");
            Box::pin(async move {
                let (_, body) = request.into_parts();
                request_body.send(body).map_err(|_| {
                    ConnectError::unavailable("test request body receiver was cancelled")
                })?;
                response
                    .await
                    .map_err(|_| ConnectError::unavailable("test transport response was cancelled"))
            })
        }
    }

    fn connect_stream_response(message: RunResponse) -> Response<reqwest::Body> {
        let payload = message.encode_to_vec();
        let mut body = Vec::with_capacity(payload.len() + 12);
        body.push(0);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
        body.push(0x02);
        body.extend_from_slice(&(2_u32).to_be_bytes());
        body.extend_from_slice(b"{}");

        Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/connect+proto")
            .body(reqwest::Body::from(body))
            .expect("valid Connect response")
    }

    #[tokio::test]
    async fn run_bidi_initial_receive_cancellation_preserves_full_duplex_input() {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let transport = GatedBidiTransport {
            response: Arc::new(std::sync::Mutex::new(Some(response_rx))),
        };
        let config = connectrpc::client::ClientConfig::new(
            "http://connect-test.invalid"
                .parse()
                .expect("test Connect URL"),
        );
        let client = GeneratedExecServiceClient::new(transport, config);
        let mut stream = client.run().await.expect("start Run stream");
        stream
            .send(RunRequest {
                input: Some(run_request::Input::Start(Box::new(RunStart {
                    org_id: "org_test".into(),
                    environment_id: "env_test".into(),
                    command: vec!["cat".into()],
                    ..Default::default()
                }))),
                ..Default::default()
            })
            .await
            .expect("send Run start");

        let mut first_receive = Box::pin(stream.message::<RunResponse>());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            first_receive.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(first_receive);

        stream
            .send(RunRequest {
                input: Some(run_request::Input::Stdin(b"full-duplex".to_vec())),
                ..Default::default()
            })
            .await
            .expect("input after cancelled receive must remain sendable");
        response_tx
            .send(connect_stream_response(RunResponse {
                event: Some(run_response::Event::Stdout(b"resumed".to_vec())),
                ..Default::default()
            }))
            .expect("cancelled receive must leave response initialization live");

        let response =
            tokio::time::timeout(Duration::from_secs(5), stream.message::<RunResponse>())
                .await
                .expect("resumed receive must finish")
                .expect("resumed receive must decode")
                .expect("resumed receive must yield output")
                .to_owned_message();
        assert_eq!(
            response.event,
            Some(run_response::Event::Stdout(b"resumed".to_vec()))
        );
        assert!(
            stream
                .message::<RunResponse>()
                .await
                .expect("clean Connect end stream")
                .is_none()
        );
    }

    #[tokio::test]
    async fn run_driver_half_closes_before_publishing_terminal_exit() {
        use http_body_util::BodyExt as _;

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let (request_body_tx, request_body_rx) = tokio::sync::oneshot::channel();
        let transport = CapturingBidiTransport {
            response: Arc::new(std::sync::Mutex::new(Some(response_rx))),
            request_body: Arc::new(std::sync::Mutex::new(Some(request_body_tx))),
        };
        let config = connectrpc::client::ClientConfig::new(
            "http://connect-test.invalid"
                .parse()
                .expect("test Connect URL"),
        );
        let client = GeneratedExecServiceClient::new(transport, config);
        let mut stream = client.run().await.expect("start Run stream");
        stream
            .send(RunRequest {
                input: Some(run_request::Input::Start(Box::new(RunStart {
                    org_id: "org_test".into(),
                    environment_id: "env_test".into(),
                    command: vec!["true".into()],
                    ..Default::default()
                }))),
                ..Default::default()
            })
            .await
            .expect("send Run start");

        let mut request_body = tokio::time::timeout(Duration::from_secs(5), request_body_rx)
            .await
            .expect("transport must receive request body")
            .expect("request body sender must remain live");
        let (request_closed_tx, request_closed_rx) = tokio::sync::oneshot::channel();
        let request_reader = tokio::spawn(async move {
            let mut frames = 0;
            while let Some(frame) = request_body.frame().await {
                frame.expect("request body frame must decode");
                frames += 1;
            }
            request_closed_tx
                .send(frames)
                .expect("request closure observer must remain live");
        });

        let (input_tx, input_rx) = tokio::sync::mpsc::channel(1);
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(1);
        // Keep the driver blocked immediately before publishing ExitCode. The
        // request observer must see EOF first; this distinguishes a clean
        // terminal half-close from simply dropping the stream later.
        output_tx
            .send(Ok(RunResponse::default()))
            .await
            .expect("prime output channel");
        let (terminal_error_tx, _terminal_error_rx) = tokio::sync::watch::channel(None);
        let driver = tokio::spawn(run_stream_driver(
            stream,
            input_rx,
            output_tx,
            terminal_error_tx,
        ));
        response_tx
            .send(connect_stream_response(RunResponse {
                event: Some(run_response::Event::ExitCode(29)),
                ..Default::default()
            }))
            .expect("deliver terminal response");

        let frame_count = tokio::time::timeout(Duration::from_secs(5), request_closed_rx)
            .await
            .expect("Run driver must half-close request before publishing exit")
            .expect("request closure observer must report");
        assert!(frame_count >= 1, "Run start frame must reach the transport");
        assert!(matches!(
            output_rx.recv().await,
            Some(Ok(RunResponse { event: None, .. }))
        ));
        assert_eq!(
            output_rx
                .recv()
                .await
                .expect("terminal response")
                .expect("terminal response must be successful")
                .event,
            Some(run_response::Event::ExitCode(29))
        );
        drop(input_tx);
        driver.await.expect("run driver must join");
        request_reader.await.expect("request reader must join");
    }

    #[tokio::test]
    async fn generated_api_key_service_uses_the_provider_and_connection_config() {
        let server = MockServer::start().await;
        let response = ListApiKeysResponse {
            api_keys: vec![ApiKey {
                id: "key_123".into(),
                org_id: "org_123".into(),
                name: "deploy".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(LIST_API_KEYS_PATH))
            .and(header("authorization", "Bearer test-token"))
            .and(header("user-agent", "codewire-client-test/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server).await;
        assert_eq!(client.server_url().as_str(), format!("{}/", server.uri()));
        assert_eq!(
            client.bearer_token().await.expect("token").expose_secret(),
            "test-token"
        );
        let response = client
            .list_api_keys(ListApiKeysRequest {
                org_id: "org_123".into(),
                ..Default::default()
            })
            .await
            .expect("list API keys");
        assert_eq!(response.api_keys[0].id, "key_123");
    }

    #[tokio::test]
    async fn generated_environment_service_uses_the_provider_and_connection_config() {
        let server = MockServer::start().await;
        let response = ListEnvironmentsResponse {
            environments: vec![Environment {
                id: "env_123".into(),
                org_id: "org_123".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(LIST_ENVIRONMENTS_PATH))
            .and(header("authorization", "Bearer test-token"))
            .and(header("user-agent", "codewire-client-test/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = test_client(&server)
            .await
            .list_environments(ListEnvironmentsRequest {
                org_id: "org_123".into(),
                ..Default::default()
            })
            .await
            .expect("list environments");
        assert_eq!(response.environments[0].id, "env_123");
    }

    #[tokio::test]
    async fn generated_environment_session_service_uses_the_shared_provider_and_facade() {
        let server = MockServer::start().await;
        let session = EnvironmentSession {
            session_id: "session_123".into(),
            state: EnvironmentSessionState::Running.into(),
            command: vec!["sleep".into(), "60".into()],
            ..Default::default()
        };
        let launch_response = LaunchSessionResponse {
            session: Some(session.clone()).into(),
            ..Default::default()
        };
        let list_response = ListSessionsResponse {
            sessions: vec![session],
            ..Default::default()
        };
        for (rpc_path, body) in [
            (LAUNCH_SESSION_PATH, launch_response.encode_to_vec()),
            (LIST_SESSIONS_PATH, list_response.encode_to_vec()),
        ] {
            Mock::given(method("POST"))
                .and(path(rpc_path))
                .and(header("authorization", "Bearer test-token"))
                .and(header("user-agent", "codewire-client-test/1"))
                .and(header("connect-timeout-ms", "30000"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = test_client(&server).await;
        let launched = client
            .launch_session(LaunchSessionRequest {
                org_id: "org_123".into(),
                environment_id: "env_123".into(),
                command: vec!["sleep".into(), "60".into()],
                ..Default::default()
            })
            .await
            .expect("launch durable session");
        assert_eq!(
            launched
                .session
                .into_option()
                .expect("launch session")
                .session_id,
            "session_123"
        );
        let listed = client
            .list_sessions(ListSessionsRequest {
                org_id: "org_123".into(),
                environment_id: "env_123".into(),
                ..Default::default()
            })
            .await
            .expect("list durable sessions");
        assert_eq!(listed.sessions[0].session_id, "session_123");
    }

    #[test]
    fn durable_attachment_terminal_detection_requires_a_terminal_status() {
        let mut response = AttachSessionResponse {
            event: Some(attach_session_response::Event::Status(Box::new(
                AttachSessionStatus {
                    session: Some(EnvironmentSession {
                        state: EnvironmentSessionState::Running.into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        assert!(!attachment_response_is_terminal(&response));
        let Some(attach_session_response::Event::Status(status)) = response.event.as_mut() else {
            panic!("status response")
        };
        status.session.get_or_insert_default().state = EnvironmentSessionState::Exited.into();
        assert!(attachment_response_is_terminal(&response));
    }

    #[tokio::test]
    async fn generated_organization_service_uses_the_provider_and_connection_config() {
        let server = MockServer::start().await;
        let organization = Organization {
            id: "org_123".into(),
            name: "Acme".into(),
            slug: "acme".into(),
            ..Default::default()
        };
        let list_response = ListOrganizationsResponse {
            organizations: vec![OrganizationMembership {
                organization: Some(organization.clone()).into(),
                role: OrgRole::Owner.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let create_response = CreateOrganizationResponse {
            organization: Some(organization.clone()).into(),
            ..Default::default()
        };
        let get_response = GetOrganizationResponse {
            organization: Some(organization).into(),
            ..Default::default()
        };
        let delete_response = DeleteOrganizationResponse {
            operation_id: "org-delete-org_123-1".into(),
            state: OrganizationDeletionState::Deleting.into(),
            ..Default::default()
        };
        let invitation_response = CreateInvitationResponse {
            invitation: Some(OrgInvitation {
                id: "invite_123".into(),
                org_id: "org_123".into(),
                email: "member@example.com".into(),
                role: OrgRole::Member.into(),
                status: InvitationStatus::Pending.into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        for (rpc_path, body) in [
            (LIST_ORGANIZATIONS_PATH, list_response.encode_to_vec()),
            (CREATE_ORGANIZATION_PATH, create_response.encode_to_vec()),
            (GET_ORGANIZATION_PATH, get_response.encode_to_vec()),
            (DELETE_ORGANIZATION_PATH, delete_response.encode_to_vec()),
            (CREATE_INVITATION_PATH, invitation_response.encode_to_vec()),
        ] {
            Mock::given(method("POST"))
                .and(path(rpc_path))
                .and(header("authorization", "Bearer test-token"))
                .and(header("user-agent", "codewire-client-test/1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = test_client(&server).await;
        assert_eq!(
            client
                .list_organizations(ListOrganizationsRequest::default())
                .await
                .expect("list organizations")
                .organizations
                .into_iter()
                .next()
                .expect("organization membership")
                .organization
                .into_option()
                .map(|organization| organization.id),
            Some("org_123".to_string())
        );
        assert_eq!(
            client
                .create_organization(CreateOrganizationRequest {
                    name: "Acme".into(),
                    slug: "acme".into(),
                    ..Default::default()
                })
                .await
                .expect("create organization")
                .organization
                .into_option()
                .expect("organization")
                .id,
            "org_123"
        );
        assert_eq!(
            client
                .get_organization(GetOrganizationRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("get organization")
                .organization
                .into_option()
                .expect("organization")
                .slug,
            "acme"
        );
        assert_eq!(
            client
                .delete_organization(DeleteOrganizationRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("delete organization")
                .operation_id,
            "org-delete-org_123-1"
        );
        assert_eq!(
            client
                .create_invitation(CreateInvitationRequest {
                    org_id: "org_123".into(),
                    email: "member@example.com".into(),
                    role: OrgRole::Member.into(),
                    ..Default::default()
                })
                .await
                .expect("create invitation")
                .invitation
                .into_option()
                .expect("invitation")
                .id,
            "invite_123"
        );
    }

    #[tokio::test]
    async fn generated_preset_and_port_services_use_the_provider_and_connection_config() {
        let server = MockServer::start().await;
        let preset = Preset {
            id: "preset_123".into(),
            org_id: Some("org_123".into()),
            name: "Rust".into(),
            slug: Some("rust".into()),
            ..Default::default()
        };
        let port = Port {
            id: "port_123".into(),
            environment_id: "env_123".into(),
            port: 8080,
            label: "web".into(),
            access: PortAccess::Public.into(),
            ..Default::default()
        };
        for (rpc_path, body) in [
            (
                LIST_PRESETS_PATH,
                ListPresetsResponse {
                    presets: vec![preset.clone()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                CREATE_PRESET_PATH,
                CreatePresetResponse {
                    preset: Some(preset).into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                DELETE_PRESET_PATH,
                DeletePresetResponse::default().encode_to_vec(),
            ),
            (
                LIST_PORTS_PATH,
                ListPortsResponse {
                    ports: vec![port.clone()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                CREATE_PORT_PATH,
                CreatePortResponse {
                    port: Some(port).into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                DELETE_PORT_PATH,
                DeletePortResponse::default().encode_to_vec(),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path(rpc_path))
                .and(header("authorization", "Bearer test-token"))
                .and(header("user-agent", "codewire-client-test/1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = test_client(&server).await;
        assert_eq!(
            client
                .list_presets(ListPresetsRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("list presets")
                .presets[0]
                .id,
            "preset_123"
        );
        assert_eq!(
            client
                .create_preset(CreatePresetRequest {
                    org_id: "org_123".into(),
                    name: "Rust".into(),
                    slug: "rust".into(),
                    ..Default::default()
                })
                .await
                .expect("create preset")
                .preset
                .into_option()
                .expect("preset")
                .slug,
            Some("rust".into())
        );
        client
            .delete_preset(DeletePresetRequest {
                org_id: "org_123".into(),
                preset_id: "preset_123".into(),
                ..Default::default()
            })
            .await
            .expect("delete preset");
        assert_eq!(
            client
                .list_ports(ListPortsRequest {
                    org_id: "org_123".into(),
                    environment_id: "env_123".into(),
                    ..Default::default()
                })
                .await
                .expect("list ports")
                .ports[0]
                .port,
            8080
        );
        assert_eq!(
            client
                .create_port(CreatePortRequest {
                    org_id: "org_123".into(),
                    environment_id: "env_123".into(),
                    port: 8080,
                    label: "web".into(),
                    access: PortAccess::Public.into(),
                    ..Default::default()
                })
                .await
                .expect("create port")
                .port
                .into_option()
                .expect("port")
                .id,
            "port_123"
        );
        client
            .delete_port(DeletePortRequest {
                org_id: "org_123".into(),
                environment_id: "env_123".into(),
                port_id: "port_123".into(),
                ..Default::default()
            })
            .await
            .expect("delete port");
    }

    #[tokio::test]
    async fn generated_secret_service_uses_the_provider_and_redacts_write_values() {
        let server = MockServer::start().await;
        let secret = SecretMetadata {
            key: "DATABASE_URL".into(),
            ..Default::default()
        };
        let project = SecretProject {
            id: "sp_123".into(),
            org_id: "org_123".into(),
            name: "production".into(),
            secret_count: 1,
            ..Default::default()
        };
        for (rpc_path, body) in [
            (
                LIST_SECRETS_PATH,
                ListSecretsResponse {
                    secrets: vec![secret.clone()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                SET_SECRET_PATH,
                SetSecretResponse::default().encode_to_vec(),
            ),
            (
                DELETE_SECRET_PATH,
                DeleteSecretResponse::default().encode_to_vec(),
            ),
            (
                RENAME_SECRET_PATH,
                RenameSecretResponse::default().encode_to_vec(),
            ),
            (
                LIST_USER_SECRETS_PATH,
                ListUserSecretsResponse {
                    secrets: vec![secret.clone()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                SET_USER_SECRET_PATH,
                SetUserSecretResponse::default().encode_to_vec(),
            ),
            (
                DELETE_USER_SECRET_PATH,
                DeleteUserSecretResponse::default().encode_to_vec(),
            ),
            (
                RENAME_USER_SECRET_PATH,
                RenameUserSecretResponse::default().encode_to_vec(),
            ),
            (
                LIST_SECRET_PROJECTS_PATH,
                ListSecretProjectsResponse {
                    secret_projects: vec![project.clone()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                CREATE_SECRET_PROJECT_PATH,
                CreateSecretProjectResponse {
                    secret_project: Some(project.clone()).into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                DELETE_SECRET_PROJECT_PATH,
                DeleteSecretProjectResponse::default().encode_to_vec(),
            ),
            (
                LIST_PROJECT_SECRETS_PATH,
                ListProjectSecretsResponse {
                    secrets: vec![secret],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                SET_PROJECT_SECRET_PATH,
                SetProjectSecretResponse::default().encode_to_vec(),
            ),
            (
                DELETE_PROJECT_SECRET_PATH,
                DeleteProjectSecretResponse::default().encode_to_vec(),
            ),
            (
                RENAME_PROJECT_SECRET_PATH,
                RenameProjectSecretResponse::default().encode_to_vec(),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path(rpc_path))
                .and(header("authorization", "Bearer test-token"))
                .and(header("user-agent", "codewire-client-test/1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = test_client(&server).await;
        assert_eq!(
            client
                .list_secrets(ListSecretsRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("list organization secrets")
                .secrets[0]
                .key,
            "DATABASE_URL"
        );
        let marker = "never-log-this-secret-value";
        let set_secret = SetSecretRequest {
            org_id: "org_123".into(),
            key: "DATABASE_URL".into(),
            value: marker.into(),
            ..Default::default()
        };
        assert!(!format!("{set_secret:?}").contains(marker));
        client
            .set_secret(set_secret)
            .await
            .expect("set organization secret");
        client
            .delete_secret(DeleteSecretRequest {
                org_id: "org_123".into(),
                key: "DATABASE_URL".into(),
                ..Default::default()
            })
            .await
            .expect("delete organization secret");
        client
            .rename_secret(RenameSecretRequest {
                org_id: "org_123".into(),
                key: "DATABASE_URL".into(),
                new_key: "DATABASE_URI".into(),
                ..Default::default()
            })
            .await
            .expect("rename organization secret");
        client
            .list_user_secrets(ListUserSecretsRequest::default())
            .await
            .expect("list user secrets");
        client
            .set_user_secret(SetUserSecretRequest {
                key: "GITHUB_TOKEN".into(),
                value: marker.into(),
                ..Default::default()
            })
            .await
            .expect("set user secret");
        client
            .delete_user_secret(DeleteUserSecretRequest {
                key: "GITHUB_TOKEN".into(),
                ..Default::default()
            })
            .await
            .expect("delete user secret");
        client
            .rename_user_secret(RenameUserSecretRequest {
                key: "GITHUB_TOKEN".into(),
                new_key: "GH_TOKEN".into(),
                ..Default::default()
            })
            .await
            .expect("rename user secret");
        assert_eq!(
            client
                .list_secret_projects(ListSecretProjectsRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("list secret projects")
                .secret_projects[0]
                .id,
            "sp_123"
        );
        client
            .create_secret_project(CreateSecretProjectRequest {
                org_id: "org_123".into(),
                name: "production".into(),
                ..Default::default()
            })
            .await
            .expect("create secret project");
        client
            .delete_secret_project(DeleteSecretProjectRequest {
                org_id: "org_123".into(),
                secret_project_id: "sp_123".into(),
                ..Default::default()
            })
            .await
            .expect("delete secret project");
        client
            .list_project_secrets(ListProjectSecretsRequest {
                org_id: "org_123".into(),
                secret_project_id: "sp_123".into(),
                ..Default::default()
            })
            .await
            .expect("list project secrets");
        client
            .set_project_secret(SetProjectSecretRequest {
                org_id: "org_123".into(),
                secret_project_id: "sp_123".into(),
                key: "DATABASE_URL".into(),
                value: marker.into(),
                ..Default::default()
            })
            .await
            .expect("set project secret");
        client
            .delete_project_secret(DeleteProjectSecretRequest {
                org_id: "org_123".into(),
                secret_project_id: "sp_123".into(),
                key: "DATABASE_URL".into(),
                ..Default::default()
            })
            .await
            .expect("delete project secret");
        client
            .rename_project_secret(RenameProjectSecretRequest {
                org_id: "org_123".into(),
                secret_project_id: "sp_123".into(),
                key: "DATABASE_URL".into(),
                new_key: "DATABASE_URI".into(),
                ..Default::default()
            })
            .await
            .expect("rename project secret");
    }

    #[tokio::test]
    async fn generated_console_services_use_the_provider() {
        let server = MockServer::start().await;
        for (rpc_path, body) in [
            (
                GET_BILLING_OVERVIEW_PATH,
                GetBillingOverviewResponse {
                    plan: "team".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                GET_GITHUB_CONFIG_PATH,
                GetGitHubConfigResponse {
                    client_id: "Iv1.example".into(),
                    app_slug: "codewire-dev".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                GET_GITHUB_STATUS_PATH,
                GetGitHubStatusResponse {
                    connected: true,
                    username: "noel".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                SAVE_GITHUB_TOKEN_PATH,
                SaveGitHubTokenResponse::default().encode_to_vec(),
            ),
            (
                DELETE_GITHUB_TOKEN_PATH,
                DeleteGitHubTokenResponse::default().encode_to_vec(),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path(rpc_path))
                .and(header("authorization", "Bearer test-token"))
                .and(header("user-agent", "codewire-client-test/1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = test_client(&server).await;
        assert_eq!(
            client
                .get_billing_overview(GetBillingOverviewRequest {
                    org_id: "org_123".into(),
                    ..Default::default()
                })
                .await
                .expect("get billing overview")
                .plan,
            "team"
        );
        assert_eq!(
            client
                .get_github_config(GetGitHubConfigRequest::default())
                .await
                .expect("get GitHub config")
                .app_slug,
            "codewire-dev"
        );
        assert!(
            client
                .get_github_status(GetGitHubStatusRequest::default())
                .await
                .expect("get GitHub status")
                .connected
        );
        client
            .save_github_token(SaveGitHubTokenRequest {
                access_token: "gho_test".into(),
                ..Default::default()
            })
            .await
            .expect("save GitHub token");
        client
            .delete_github_token(DeleteGitHubTokenRequest::default())
            .await
            .expect("delete GitHub token");
    }

    #[tokio::test]
    async fn api_key_calls_honor_the_configured_unary_deadline() {
        let server = MockServer::start().await;
        let request_accepted = Arc::new(tokio::sync::Notify::new());
        let response_gate = request_accepted.clone();
        Mock::given(method("POST"))
            .and(path(LIST_API_KEYS_PATH))
            .and(header("authorization", "Bearer test-token"))
            .and(header("connect-timeout-ms", "2000"))
            .respond_with(move |_: &wiremock::Request| {
                response_gate.notify_one();
                ResponseTemplate::new(200).set_delay(Duration::from_secs(30))
            })
            .expect(1)
            .mount(&server)
            .await;

        let config = ClientConfig::new(server.uri())
            .expect("server URL")
            .with_unary_timeout(Duration::from_secs(2));
        let client = CodewireClient::with_http(
            config,
            StaticTokenProvider::new("test-token").expect("token"),
            reqwest::Client::new(),
        )
        .expect("client");

        let started = std::time::Instant::now();
        let call = tokio::spawn(async move {
            client
                .list_api_keys(ListApiKeysRequest {
                    org_id: "org_test".into(),
                    ..Default::default()
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), request_accepted.notified())
            .await
            .expect("generated ApiKey request must reach the loopback fixture");
        let error = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("configured client deadline must finish the call")
            .expect("generated ApiKey call task must join")
            .expect_err("withheld unary response must reach its client deadline");

        assert_eq!(error.code(), ErrorCode::DeadlineExceeded);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "hung unary call did not fail finitely: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn exec_uses_the_execution_deadline_instead_of_the_unary_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXEC_PATH))
            .and(header("authorization", "Bearer test-token"))
            .and(header("connect-timeout-ms", "600000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        ExecResponse {
                            exit_code: 0,
                            stdout: b"done".to_vec(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = test_client(&server)
            .await
            .exec(ExecRequest {
                org_id: "org_123".into(),
                environment_id: "env_123".into(),
                command: vec!["true".into()],
                ..Default::default()
            })
            .await
            .expect("exec");
        assert_eq!(response.stdout, b"done");
    }

    enum ExpectedDetail {
        Validation,
        Permission,
        Retry,
    }

    #[tokio::test]
    async fn typed_error_details_decode_from_connect_wire_fixtures() {
        let bad_request = BadRequest {
            field_violations: vec![
                codewire_proto::google::rpc::bad_request::FieldViolation {
                    field: "spec.name".into(),
                    description: "missing required property".into(),
                    ..Default::default()
                },
                codewire_proto::google::rpc::bad_request::FieldViolation {
                    field: "ports[0].target".into(),
                    description: "must be positive".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let permission = GoogleErrorInfo {
            reason: "ORG_MEMBERSHIP_REQUIRED".into(),
            domain: "codewire.sh".into(),
            metadata: [
                ("hint".into(), "ask an organization owner".into()),
                ("request_id".into(), "req_detail".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let retry = RetryInfo {
            retry_delay: Some(buffa_types::google::protobuf::Duration::from_secs_nanos(
                3,
                250_000_000,
            ))
            .into(),
            ..Default::default()
        };
        let cases = [
            (
                ConnectError::invalid_argument("validation failed").with_detail(
                    ErrorDetail::from_message("google.rpc.BadRequest", &bad_request),
                ),
                ExpectedDetail::Validation,
            ),
            (
                ConnectError::permission_denied("organization access denied").with_detail(
                    ErrorDetail::from_message("google.rpc.ErrorInfo", &permission),
                ),
                ExpectedDetail::Permission,
            ),
            (
                ConnectError::resource_exhausted("rate limited")
                    .with_detail(ErrorDetail::from_message("google.rpc.RetryInfo", &retry)),
                ExpectedDetail::Retry,
            ),
        ];

        for (wire_error, expected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(LIST_API_KEYS_PATH))
                .respond_with(
                    ResponseTemplate::new(wire_error.http_status().as_u16())
                        .insert_header("content-type", "application/json")
                        .insert_header("x-request-id", "req_header")
                        .set_body_bytes(wire_error.to_json()),
                )
                .expect(1)
                .mount(&server)
                .await;

            let error = test_client(&server)
                .await
                .list_api_keys(ListApiKeysRequest::default())
                .await
                .expect_err("fixture returns an error");

            match expected {
                ExpectedDetail::Validation => {
                    assert_eq!(error.code(), ErrorCode::InvalidArgument);
                    assert_eq!(error.validation_errors().len(), 2);
                    assert_eq!(error.validation_errors()[0].field(), "spec.name");
                    assert_eq!(error.validation_errors()[1].field(), "ports[0].target");
                    assert_eq!(error.request_id(), Some("req_header"));
                }
                ExpectedDetail::Permission => {
                    assert_eq!(error.code(), ErrorCode::PermissionDenied);
                    assert_eq!(error.reason(), Some("ORG_MEMBERSHIP_REQUIRED"));
                    assert_eq!(error.hint(), Some("ask an organization owner"));
                    assert_eq!(error.request_id(), Some("req_detail"));
                    assert_eq!(
                        error.error_info().map(ErrorInfo::domain),
                        Some("codewire.sh")
                    );
                }
                ExpectedDetail::Retry => {
                    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
                    assert_eq!(error.retry_delay(), Some(Duration::new(3, 250_000_000)));
                    assert_eq!(error.request_id(), Some("req_header"));
                }
            }
        }
    }
}
