//! One original-owner-authenticated stream to the existing platform origin.
//! This facade owns generated RPC construction and shared transport/auth policy;
//! the native runtime owns both stream halves and the actual bridge lifetime.

use std::future::Future;
use std::time::Duration;

use codewire_proto::codewire::bridge::v1 as bridge;
use codewire_proto::codewire::v1::{
    CredentialDelegationServiceClient, DelegateCredentialsResponseView,
};
use connectrpc::client::{BidiStream, CallOptions, ClientTransport};
use tokio::time::Instant;

use crate::{
    ClientError, CodewireClient, CredentialDelegationOpen, DelegateCredentialsRequest,
    DelegateCredentialsResponse, ErrorCode, ReqwestConnectTransport, delegate_credentials_request,
    delegate_credentials_response,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// A credential-free typed message stream. The transport holds the original
/// Codewire OAuth header; it never carries provider credential material. Its
/// owner must close/drop both halves on native authority loss and must never
/// replay an operation across reconnect. Stream closure is not an assertion
/// that the remote broker's retained refresh/sign work has already drained.
/// The initial exact admission echo has already been consumed. The owner must
/// reject any subsequent `Admitted`, missing output or invalid bridge frame;
/// admission cannot be renewed or replaced inside an established stream.
pub type CredentialDelegationStream = connectrpc::client::BidiStream<
    reqwest::Body,
    DelegateCredentialsRequest,
    DelegateCredentialsResponseView<'static>,
>;

impl CodewireClient {
    /// Open an explicit source selection with one current bearer from the
    /// shared token provider. The server authenticates original personal OAuth
    /// and rejects cookie/API-key authority. It binds the selection to the
    /// native operation but does not independently attest that VM.
    ///
    /// Secure public origins use native gRPC; checked-in cleartext test origins
    /// use HTTP/2 Connect, exactly as other bidirectional product streams do.
    /// No background driver, new endpoint URL, credential cache or retry is
    /// created here. One original 15-second deadline covers token resolution,
    /// Open, matching Ready and the exact admitted-selection echo. HTTP200 or a
    /// successful send is not admission. Afterward the caller owns bounded
    /// message conversion, cancellation and both stream halves.
    pub async fn delegate_credentials(
        &self,
        open: CredentialDelegationOpen,
    ) -> Result<CredentialDelegationStream, ClientError> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let client = CredentialDelegationServiceClient::new(
            ReqwestConnectTransport(self.http.clone()),
            self.config.environment_session_connect_config()?,
        );
        setup(client, self.auth_options(), open, deadline).await
    }
}

// Keep the generated call and the entire admission in one cancellable future.
// The pinned BidiStream owns and cancels its pending initialization tasks on
// drop; no second cancellation wrapper or detached driver is needed here.
async fn setup<T: ClientTransport>(
    client: CredentialDelegationServiceClient<T>,
    options: impl Future<Output = Result<CallOptions, ClientError>>,
    open: CredentialDelegationOpen,
    deadline: Instant,
) -> Result<
    BidiStream<
        T::ResponseBody,
        DelegateCredentialsRequest,
        DelegateCredentialsResponseView<'static>,
    >,
    ClientError,
>
where
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    tokio::time::timeout_at(deadline, async {
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let runtime = open.runtime.as_option().ok_or_else(|| {
            ClientError::new(
                ErrorCode::InvalidArgument,
                "credential delegation runtime is missing",
            )
        })?;
        let ready = bridge::CredentialBridgeReady {
            protocol_version: runtime.protocol_version,
            environment_id: runtime.environment_id.clone(),
            environment_generation: runtime.environment_generation,
            ..Default::default()
        };
        let options = options.await?;
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let mut stream = client
            .delegate_credentials_with_options(options)
            .await
            .map_err(ClientError::from)?;
        stream
            .send(DelegateCredentialsRequest {
                input: Some(delegate_credentials_request::Input::Open(Box::new(
                    open.clone(),
                ))),
                ..Default::default()
            })
            .await
            .map_err(ClientError::from)?;
        stream
            .send(DelegateCredentialsRequest {
                input: Some(delegate_credentials_request::Input::Frame(Box::new(
                    bridge::CredentialBridgeGuestMessage {
                        payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                            Box::new(ready),
                        )),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            })
            .await
            .map_err(ClientError::from)?;
        let response = stream
            .message::<DelegateCredentialsResponse>()
            .await
            .map_err(ClientError::from)?
            .ok_or_else(invalid_admission)?
            .to_owned_message();
        match response.output {
            Some(delegate_credentials_response::Output::Admitted(accepted))
                if *accepted == open => {}
            _ => return Err(invalid_admission()),
        }
        // A ready response does not extend or race past the original deadline.
        if Instant::now() >= deadline {
            return Err(expired());
        }
        Ok(stream)
    })
    .await
    .map_err(|_| expired())?
}

fn invalid_admission() -> ClientError {
    ClientError::new(
        ErrorCode::Internal,
        "credential delegation admission is invalid",
    )
}

fn expired() -> ClientError {
    ClientError::new(
        ErrorCode::DeadlineExceeded,
        "credential delegation setup expired",
    )
}

#[cfg(test)]
mod tests;
