//! The CLI's and native apps' layer over the Codewire Rust SDK (`codewire`,
//! codewire#3511): sign-in (OAuth device flow, PKCE, credential stores,
//! refresh), billing, setup following, credential delegation, the tailnet and
//! the hosted shell.
//!
//! It re-exports the SDK, so `codewire_client::X` names the SDK's `X` wherever
//! this crate doesn't define its own. [`CodewireClient`] wraps the SDK client,
//! dereferences to it, and adds the console and app-only calls.

mod auth;
mod coordinator;
pub mod create_options;
mod credential_delegation;
pub mod environment_setup;
#[cfg(feature = "tailnet-session")]
pub mod hosted_shell;
#[cfg(target_os = "linux")]
pub mod member_tailnet;
pub mod session_wire;
mod startup_script;
mod tailnet;
#[cfg(feature = "tailnet-session")]
pub mod tailnet_session;

use std::ops::Deref;
use std::sync::Arc;

pub use codewire::*;

use codewire_proto::codewire::console::v1::BillingServiceClient;

#[cfg(feature = "desktop-keyring")]
pub use auth::KeyringCredentialStore;
pub use auth::{
    AuthClient, AuthClientError, AuthResponse, AuthSession, AuthUser, CODEWIRE_CLI_OAUTH_CLIENT_ID,
    CODEWIRE_CLI_OAUTH_SCOPES, CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
    CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI, CODEWIRE_DESKTOP_OAUTH_SCOPES, CredentialStore,
    FileCredentialStore, OAuthClient, OAuthCredentials, OAuthDeviceAuthorization, OAuthDiscovery,
    OAuthPkceAuthorization, OAuthTokenResponse, OAuthUserInfo, RefreshingTokenProvider,
};
#[cfg(feature = "desktop-pkce-loopback")]
pub use auth::{DesktopOAuthCancellation, DesktopOAuthLogin};
pub use codewire_proto::codewire::console::v1::{
    BillingLimitUsage, BillingLimits, GetBillingOverviewRequest, GetBillingOverviewResponse,
    UsageSummary,
};
pub use coordinator::{
    COORDINATOR_SETUP_TIMEOUT, CoordinatorPeerSession, Error as CoordinatorError,
    Handlers as CoordinatorHandlers, MeshCoordinateIdentity, MeshCoordinatorPeerSession,
    PrimaryCoordinateIdentity,
};
pub use credential_delegation::{
    AdmittedCredentialDelegation, CredentialDelegationStream, FRONT_DOOR_EPOCH_BYTES,
    FRONT_DOOR_EPOCH_HEADER, FrontDoorDelegationStream, FrontDoorEpoch,
};
pub use tailnet::{
    EnvironmentTailnetDiagnostic, ExpectedTransport, NativeClientFacade, SshTransportMode,
    StunServer, TailnetConnection, TailnetDerpMapDiagnostic, TailnetDiagnosticOptions,
    TailnetDiagnosticStage, TailnetPathDiagnostic, TailnetPeerDiagnostic, derp_target_for_host,
    derp_target_from_map, diagnose_environment_tailnet, parse_duration, pipe_shell_stdio,
    resolve_stun_servers, stun_servers_from_map,
};

/// The one Rust client core consumed by the CLI and native bindings: the
/// SDK's client plus the console and app-only calls.
#[derive(Clone)]
pub struct CodewireClient {
    sdk: codewire::CodewireClient,
    billing: BillingServiceClient<ReqwestConnectTransport>,
}

impl Deref for CodewireClient {
    type Target = codewire::CodewireClient;

    fn deref(&self) -> &Self::Target {
        &self.sdk
    }
}

impl CodewireClient {
    pub fn new(
        config: ClientConfig,
        token_provider: impl TokenProvider + 'static,
    ) -> Result<Self, ClientError> {
        Self::from_sdk(codewire::CodewireClient::new(config, token_provider)?)
    }

    /// Construct with a caller-supplied HTTP client for tests and custom TLS
    /// policy.
    pub fn with_http(
        config: ClientConfig,
        token_provider: impl TokenProvider + 'static,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        Self::from_sdk(codewire::CodewireClient::with_http(
            config,
            token_provider,
            http,
        )?)
    }

    /// Construct from a shared token provider. Native consumers use this for
    /// the single refresh-capable OAuth provider across every generated
    /// Connect facade.
    pub fn with_token_provider(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ClientError> {
        Self::from_sdk(codewire::CodewireClient::with_token_provider(
            config,
            token_provider,
        )?)
    }

    /// Construct with a shared provider and caller-supplied HTTP client for
    /// tests and custom TLS policy.
    pub fn with_http_token_provider(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        Self::from_sdk(codewire::CodewireClient::with_http_token_provider(
            config,
            token_provider,
            http,
        )?)
    }

    fn from_sdk(sdk: codewire::CodewireClient) -> Result<Self, ClientError> {
        let billing = BillingServiceClient::new(
            ReqwestConnectTransport(sdk.http().clone()),
            sdk.config().connect_config()?,
        );
        Ok(Self { sdk, billing })
    }

    pub fn auth(&self) -> AuthClient {
        AuthClient::authenticated(
            self.config().clone(),
            Arc::clone(self.token_provider()),
            self.http().clone(),
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
}

#[cfg(test)]
mod tests {
    use buffa::Message as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const GET_BILLING_OVERVIEW_PATH: &str =
        "/codewire.console.v1.BillingService/GetBillingOverview";

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

    #[tokio::test]
    async fn generated_billing_service_uses_the_provider() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(GET_BILLING_OVERVIEW_PATH))
            .and(header("authorization", "Bearer test-token"))
            .and(header("user-agent", "codewire-client-test/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        GetBillingOverviewResponse {
                            plan: "team".into(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

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
    }
}
