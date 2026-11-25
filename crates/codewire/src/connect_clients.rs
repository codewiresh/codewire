//! How a client builds the generated Connect service clients it holds, one
//! per service, over one HTTP client and token provider. Moved from the
//! crate root with no change in behaviour.

use super::*;

impl CodewireClient {
    /// Construct with a shared provider and caller-supplied HTTP client for
    /// tests and custom TLS policy.
    pub fn with_http_token_provider(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        let transport =
            ReqwestConnectTransport::new(http.clone(), Some(Arc::clone(&token_provider)));
        let api_key_config = config.connect_config()?;
        let environment_config = config.connect_config()?;
        let session_config = config.environment_session_connect_config()?;
        let exec_config = config.connect_config()?;
        let file_config = config.file_transfer_connect_config()?;
        let organization_config = config.connect_config()?;
        let preset_config = config.connect_config()?;
        let port_config = config.connect_config()?;
        let secret_config = config.connect_config()?;
        let snapshot_config = config.connect_config()?;
        let access_profile_config = config.connect_config()?;
        let network_policy_config = config.connect_config()?;
        let sandbox_identity_config = config.connect_config()?;
        let audit_config = config.connect_config()?;
        let credential_config = config.connect_config()?;
        let credential_mutation_config = config.connect_config()?;
        let github_repository_config = config.connect_config()?;
        let mesh_network_config = config.mesh_connect_config()?;
        let mesh_node_config = config.mesh_connect_config()?;
        let mesh_invite_config = config.mesh_connect_config()?;
        Ok(Self {
            config,
            token_provider,
            http: http.clone(),
            api_keys: ApiKeyServiceClient::new(transport.clone(), api_key_config),
            environments: EnvironmentServiceClient::new(transport.clone(), environment_config),
            sessions: EnvironmentSessionServiceClient::new(transport.clone(), session_config),
            exec: ExecServiceClient::new(transport.clone(), exec_config),
            files: FileServiceClient::new(transport.clone(), file_config),
            organizations: OrganizationServiceClient::new(transport.clone(), organization_config),
            presets: PresetServiceClient::new(transport.clone(), preset_config),
            ports: PortServiceClient::new(transport.clone(), port_config),
            secrets: SecretServiceClient::new(transport.clone(), secret_config),
            snapshots: SnapshotServiceClient::new(transport.clone(), snapshot_config),
            access_profiles: AccessProfileServiceClient::new(
                transport.clone(),
                access_profile_config,
            ),
            network_policies: NetworkPolicyServiceClient::new(
                transport.clone(),
                network_policy_config,
            ),
            sandbox_identity: SandboxIdentityServiceClient::new(
                transport.clone(),
                sandbox_identity_config,
            ),
            audit: AuditServiceClient::new(transport.clone(), audit_config),
            credentials: CredentialServiceClient::new(transport.clone(), credential_config),
            credential_mutations: CredentialMutationServiceClient::new(
                transport.clone(),
                credential_mutation_config,
            ),
            github_repositories: GithubRepositoryServiceClient::new(
                transport.clone(),
                github_repository_config,
            ),
            mesh_networks: MeshNetworkServiceClient::new(transport.clone(), mesh_network_config),
            mesh_nodes: MeshNodeServiceClient::new(transport.clone(), mesh_node_config),
            mesh_invites: MeshInviteServiceClient::new(transport, mesh_invite_config),
        })
    }

    /// The transport this client's calls go over: its HTTP client, and its
    /// token provider for a unary call whose bearer the auth layer refused.
    #[doc(hidden)]
    pub fn transport(&self) -> ReqwestConnectTransport {
        ReqwestConnectTransport::new(self.http.clone(), Some(Arc::clone(&self.token_provider)))
    }
}
