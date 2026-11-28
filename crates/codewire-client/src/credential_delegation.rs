//! One original-owner-authenticated stream to the existing platform origin.
//! This facade owns generated RPC construction and shared transport/auth policy;
//! the native runtime owns both stream halves and the actual bridge lifetime.

use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use codewire_proto::codewire::bridge::v1 as bridge;
use codewire_proto::codewire::v1::{
    CredentialDelegationServiceClient, DelegateCredentialsResponseView,
    EnvironmentBoundSecretsRequest, EnvironmentBoundSecretsResponse,
    EnvironmentCredentialPlaceholdersRequest, EnvironmentCredentialPlaceholdersResponse,
    FrontDoorDelegationRequest, FrontDoorDelegationResponse, FrontDoorDelegationResponseView,
    front_door_delegation_response,
};
use connectrpc::client::{BidiStream, CallOptions, ClientTransport};
use tokio::time::Instant;

use crate::{
    ClientError, CodewireClient, CredentialDelegationOpen, DelegateCredentialsRequest,
    DelegateCredentialsResponse, ErrorCode, delegate_credentials_request,
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

/// A local front door's joined stream to its delegation epoch (#4909): its
/// first answer, the admission, has already been read.
pub type FrontDoorDelegationStream = connectrpc::client::BidiStream<
    reqwest::Body,
    FrontDoorDelegationRequest,
    FrontDoorDelegationResponseView<'static>,
>;

/// The request header a front-door join presents its epoch's handle in;
/// the bridge's `CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER`, pinned by a test
/// where both are visible.
pub const FRONT_DOOR_EPOCH_HEADER: &str = "x-codewire-credential-bridge-epoch-bin";

/// A delegation epoch's front-door handle (#4909): exactly 32 bytes, held only
/// by the native authority that admitted the epoch. It grants nothing alone,
/// and its `Debug` never shows it.
#[derive(Clone)]
pub struct FrontDoorEpoch([u8; FRONT_DOOR_EPOCH_BYTES]);

/// A front-door handle's exact length.
pub const FRONT_DOOR_EPOCH_BYTES: usize = 32;

impl std::fmt::Debug for FrontDoorEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FrontDoorEpoch(redacted)")
    }
}

impl FrontDoorEpoch {
    /// The handle an admission answered with: none when empty, refused when
    /// it is any length but exactly [`FRONT_DOOR_EPOCH_BYTES`].
    fn from_admission(bytes: &[u8]) -> Result<Option<Self>, ClientError> {
        match bytes.len() {
            0 => Ok(None),
            FRONT_DOOR_EPOCH_BYTES => Ok(Some(Self(
                bytes.try_into().map_err(|_| invalid_admission())?,
            ))),
            _ => Err(invalid_admission()),
        }
    }
}

/// An admitted stream and what its server said it accepts.
pub struct AdmittedCredentialDelegation {
    pub stream: CredentialDelegationStream,
    /// The server answers request keepalives. Only then may the owner send
    /// one: an older server ends a stream that carries one.
    pub accepts_keepalive: bool,
    /// The epoch's front-door handle, when the server joins a front door to
    /// it. None from a server that predates #4909.
    pub front_door_epoch: Option<FrontDoorEpoch>,
}

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
    ) -> Result<AdmittedCredentialDelegation, ClientError> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let client = CredentialDelegationServiceClient::new(
            self.transport(),
            self.config().environment_session_connect_config()?,
        );
        let (stream, accepts_keepalive, front_door_epoch) =
            setup(client, self.auth_options(), open, deadline).await?;
        Ok(AdmittedCredentialDelegation {
            stream,
            accepts_keepalive,
            front_door_epoch,
        })
    }

    /// Join `epoch`'s front door (#4909) with one current bearer, within the
    /// same 15-second setup bound as admission. `ready` is the epoch's own
    /// Ready, sent first; the platform admits the join only on it. Returns
    /// the stream and the front-door operations its admission names. Any
    /// first answer but an admission is refused.
    pub async fn join_front_door_delegation(
        &self,
        epoch: &FrontDoorEpoch,
        ready: bridge::CredentialBridgeReady,
    ) -> Result<(FrontDoorDelegationStream, Vec<String>), ClientError> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let client = CredentialDelegationServiceClient::new(
                self.transport(),
                self.config().environment_session_connect_config()?,
            );
            let options = self
                .auth_options()
                .await?
                .try_with_header(
                    FRONT_DOOR_EPOCH_HEADER,
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(epoch.0),
                )
                .map_err(|_| invalid_admission())?;
            let mut stream = client
                .front_door_delegation_with_options(options)
                .await
                .map_err(ClientError::from)?;
            stream
                .send(FrontDoorDelegationRequest {
                    frame: Some(bridge::CredentialBridgeGuestMessage {
                        payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                            Box::new(ready),
                        )),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })
                .await
                .map_err(ClientError::from)?;
            let first = stream
                .message::<FrontDoorDelegationResponse>()
                .await
                .map_err(ClientError::from)?
                .ok_or_else(invalid_admission)?
                .to_owned_message();
            let Some(front_door_delegation_response::Output::Admitted(admitted)) = first.output
            else {
                return Err(invalid_admission());
            };
            Ok((stream, admitted.capabilities))
        })
        .await
        .map_err(|_| expired())?
    }
}

impl CodewireClient {
    /// A local VM's seed placeholders on a platform profile (#4001): one
    /// unary call with one current bearer, on the same protocol as the
    /// delegation. The platform admits `request.selection` exactly as its
    /// delegation would before it reads any key. The caller bounds the call.
    pub async fn environment_credential_placeholders(
        &self,
        request: EnvironmentCredentialPlaceholdersRequest,
    ) -> Result<EnvironmentCredentialPlaceholdersResponse, ClientError> {
        CredentialDelegationServiceClient::new(
            self.transport(),
            self.config().environment_session_connect_config()?,
        )
        .environment_credential_placeholders_with_options(request, self.auth_options().await?)
        .await
        .map(|response| response.into_owned())
        .map_err(ClientError::from)
    }

    /// A local VM's sealed record of its platform sources' bound secrets
    /// (#4003): one unary call with one current bearer, admitted as the seed
    /// placeholders are. A platform that keeps no record answers
    /// UNIMPLEMENTED. The caller bounds the call.
    pub async fn environment_bound_secrets(
        &self,
        request: EnvironmentBoundSecretsRequest,
    ) -> Result<EnvironmentBoundSecretsResponse, ClientError> {
        CredentialDelegationServiceClient::new(
            self.transport(),
            self.config().environment_session_connect_config()?,
        )
        .environment_bound_secrets_with_options(request, self.auth_options().await?)
        .await
        .map(|response| response.into_owned())
        .map_err(ClientError::from)
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
    (
        BidiStream<
            T::ResponseBody,
            DelegateCredentialsRequest,
            DelegateCredentialsResponseView<'static>,
        >,
        bool,
        Option<FrontDoorEpoch>,
    ),
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
        let accepts_keepalive = response.accepts_keepalive;
        let front_door_epoch = FrontDoorEpoch::from_admission(&response.front_door_epoch)?;
        match response.output {
            Some(delegate_credentials_response::Output::Admitted(accepted))
                if *accepted == open => {}
            _ => return Err(invalid_admission()),
        }
        // A ready response does not extend or race past the original deadline.
        if Instant::now() >= deadline {
            return Err(expired());
        }
        Ok((stream, accepts_keepalive, front_door_epoch))
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
