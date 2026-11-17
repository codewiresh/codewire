//! `cw feedback` (#4061): one public RPC that sends feedback signed in, with
//! the caller's credential, or anonymously, with none.

use std::sync::Arc;

use codewire_proto::codewire::v1::FeedbackServiceClient;
pub use codewire_proto::codewire::v1::{
    FeedbackPlacement, SubmitFeedbackRequest, SubmitFeedbackResponse,
};
use connectrpc::client::CallOptions;

use crate::{
    ClientConfig, ClientError, ReqwestConnectTransport, TokenProvider, default_http_client,
};

/// Sends feedback. A signed-in client attaches its credential, so the
/// feedback records the account; an anonymous one sends no credential at
/// all, so the server records neither account nor organization.
#[derive(Clone)]
pub struct FeedbackClient {
    feedback: FeedbackServiceClient<ReqwestConnectTransport>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl FeedbackClient {
    /// A client that sends with the credential `token_provider` supplies.
    pub fn signed_in(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ClientError> {
        Self::new(config, Some(token_provider))
    }

    /// A client that sends no credential.
    pub fn anonymous(config: ClientConfig) -> Result<Self, ClientError> {
        Self::new(config, None)
    }

    fn new(
        config: ClientConfig,
        token_provider: Option<Arc<dyn TokenProvider>>,
    ) -> Result<Self, ClientError> {
        let http = default_http_client(&config)?;
        Ok(Self {
            feedback: FeedbackServiceClient::new(
                ReqwestConnectTransport(http),
                config.connect_config()?,
            ),
            token_provider,
        })
    }

    /// Whether this client sends a credential.
    pub fn is_signed_in(&self) -> bool {
        self.token_provider.is_some()
    }

    pub async fn submit_feedback(
        &self,
        request: SubmitFeedbackRequest,
    ) -> Result<SubmitFeedbackResponse, ClientError> {
        let options = match &self.token_provider {
            Some(provider) => CallOptions::default()
                .try_with_header(
                    "authorization",
                    provider.token().await?.authorization_header(),
                )
                .map_err(ClientError::from)?,
            None => CallOptions::default(),
        };
        self.feedback
            .submit_feedback_with_options(request, options)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
