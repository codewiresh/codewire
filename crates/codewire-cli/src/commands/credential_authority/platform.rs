//! Explicit saved-owner OAuth connector. The native authority owns admission;
//! this adapter owns no store, background driver, reconnect or replay policy.

use std::future::Future;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use buffa::Message as _;
use codewire_client::{
    ClientConfig, ClientError, CodewireClient, CredentialDelegationOpen,
    CredentialDelegationProfile, CredentialDelegationStream, DelegateCredentialsRequest,
    DelegateCredentialsResponse, FileCredentialStore, OAuthClient, RefreshingTokenProvider,
    StaticTokenProvider, TokenProvider as _, credential_bridge as public_bridge,
    delegate_credentials_request, delegate_credentials_response,
};
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
    codewire::bridge::v1 as bridge,
};
use codewire_local_credentials::{
    PlatformCredentialBinding, PlatformCredentialConnector, PlatformCredentialInput,
    PlatformCredentialOutput,
};
use futures::{StreamExt as _, future::BoxFuture, stream};
use prost::Message as _;
use tokio::time::Instant;
use tonic::Status;

use crate::config;

const MAX_AUTH_FILE_BYTES: u64 = 64 * 1024;
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct NativePlatformCredentialConnector;

impl PlatformCredentialConnector for NativePlatformCredentialConnector {
    fn connect(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialOutput, Status>> {
        Box::pin(async move {
            tokio::time::timeout_at(deadline, async move {
                live(deadline)?;
                binding.validate()?;
                let open = opening(&binding, ready)?;
                let client = authenticated_client(&binding, deadline).await?;
                live(deadline)?;
                let upstream = client
                    .delegate_credentials(open)
                    .await
                    .map_err(client_error)?;
                live(deadline)?;
                Ok(relay(upstream, input))
            })
            .await
            .map_err(|_| expired())?
        })
    }
}

fn opening(
    binding: &PlatformCredentialBinding,
    ready: bridge::CredentialBridgeReady,
) -> Result<CredentialDelegationOpen, Status> {
    let id = uuid::Uuid::parse_str(&ready.environment_id).map_err(|_| denied())?;
    if ready.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        || id.is_nil()
        || id.to_string() != ready.environment_id
        || ready.environment_generation == 0
        || ready.environment_generation > i64::MAX as u64
    {
        return Err(denied());
    }
    Ok(CredentialDelegationOpen {
        runtime: Some(public_bridge::CredentialBridgeOpen {
            protocol_version: ready.protocol_version,
            environment_id: ready.environment_id,
            environment_generation: ready.environment_generation,
            ..Default::default()
        })
        .into(),
        org_id: binding.selection.organization.clone(),
        selection_sha256: binding.selection_sha256.to_vec(),
        project_id: binding.selection.project_id.clone(),
        user_secrets: binding.selection.user_selected,
        organization_secrets: binding.selection.organization_selected,
        profile: binding
            .selection
            .profile
            .as_ref()
            .map(|(id, revision)| CredentialDelegationProfile {
                profile_id: id.clone(),
                profile_revision: *revision,
                ..Default::default()
            })
            .into(),
        ordinary_environment_keys: binding.selection.ordinary_keys.iter().cloned().collect(),
        reserved_environment_keys: binding.selection.reserved_keys.iter().cloned().collect(),
        ..Default::default()
    })
}

async fn authenticated_client(
    binding: &PlatformCredentialBinding,
    deadline: Instant,
) -> Result<CodewireClient, Status> {
    live(deadline)?;
    validate_directory(&binding.config_directory)?;
    validate_file(&binding.config_directory.join("config.json"))?;
    let saved = config::load_platform_config(&binding.config_directory).map_err(|_| denied())?;
    if !config::same_server_url(&saved.server_url, &binding.server_url) {
        return Err(denied());
    }
    // Never derive an origin, directory, API key or organization from ambient
    // environment/defaults. Current default_org does not retarget a pinned VM.
    let path = config::oauth_credentials_path(&binding.config_directory);
    validate_file(&path)?;
    live(deadline)?;
    let http = confined_http(&binding.server_url)?;
    let oauth = OAuthClient::for_server_url_with_http(&binding.server_url, http.clone())
        .map_err(client_error)?;
    // This is the existing normal saved OAuth reader and atomic refresh writer.
    // The explicit canonical owner-only directory is trusted host state, not a
    // guest path. Keep bounded metadata and deadline checks around its small
    // synchronous reads/writes; do not detach them and claim cancellation.
    let provider =
        RefreshingTokenProvider::from_store(oauth.clone(), FileCredentialStore::at(path))
            .map_err(|_| denied())?;
    live(deadline)?;
    let token = provider.token().await.map_err(client_error)?;
    live(deadline)?;
    if token.expose_secret().starts_with("cw_") {
        return Err(denied());
    }
    let user = oauth.userinfo(&token).await.map_err(|_| denied())?;
    live(deadline)?;
    if user.sub != binding.selection.creator {
        return Err(denied());
    }
    // Exactly the bearer used by UserInfo goes to the generated admission RPC.
    // A second refresh/login lookup cannot substitute another original user.
    // The server rechecks membership of Open's exact pinned organization.
    CodewireClient::with_http(
        ClientConfig::new(&binding.server_url).map_err(client_error)?,
        StaticTokenProvider::from_token(token),
        http,
    )
    .map_err(client_error)
}

fn confined_http(server: &str) -> Result<reqwest::Client, Status> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(SEND_TIMEOUT);
    let builder = if url::Url::parse(server).map_err(|_| denied())?.scheme() == "http" {
        builder.http2_prior_knowledge()
    } else {
        builder
    };
    builder.build().map_err(|_| unavailable())
}

fn validate_directory(path: &Path) -> Result<(), Status> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| denied())?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || std::fs::canonicalize(path).map_err(|_| denied())? != path
    {
        return Err(denied());
    }
    Ok(())
}

fn validate_file(path: &Path) -> Result<(), Status> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_AUTH_FILE_BYTES
        || std::fs::canonicalize(path).map_err(|_| denied())? != path
    {
        return Err(denied());
    }
    Ok(())
}

// Private generic seam keeps synthetic relay tests on the real single-owner
// loop; production uses only the existing generated client stream.
trait Upstream: Send + 'static {
    fn send(
        &mut self,
        request: DelegateCredentialsRequest,
    ) -> impl Future<Output = Result<(), Status>> + Send;
    fn receive(
        &mut self,
    ) -> impl Future<Output = Result<Option<DelegateCredentialsResponse>, Status>> + Send;
}

impl Upstream for CredentialDelegationStream {
    async fn send(&mut self, request: DelegateCredentialsRequest) -> Result<(), Status> {
        CredentialDelegationStream::send(self, request)
            .await
            .map_err(|error| client_error(error.into()))
    }

    async fn receive(&mut self) -> Result<Option<DelegateCredentialsResponse>, Status> {
        let response = self
            .message::<DelegateCredentialsResponse>()
            .await
            .map_err(|error| client_error(error.into()))?;
        response
            .map(|message| {
                if message.bytes().len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 8 {
                    return Err(denied());
                }
                Ok(message.to_owned_message())
            })
            .transpose()
    }
}

fn relay(upstream: impl Upstream, input: PlatformCredentialInput) -> PlatformCredentialOutput {
    Box::pin(stream::try_unfold(
        (upstream, input),
        |(mut upstream, mut input)| async move {
            loop {
                tokio::select! {
                    next = upstream.receive() => {
                        let Some(response) = next? else { return Ok(None); };
                        return Ok(Some((decode(response)?, (upstream, input))));
                    }
                    next = input.next() => {
                        let Some(request) = next else { return Ok(None); };
                        let request = encode(request.map_err(|_| unavailable())?)?;
                        tokio::time::timeout(SEND_TIMEOUT, upstream.send(request))
                            .await.map_err(|_| unavailable())??;
                    }
                }
            }
        },
    ))
}

fn encode(
    frame: bridge::CredentialBridgeGuestMessage,
) -> Result<DelegateCredentialsRequest, Status> {
    if frame.payload.is_none()
        || matches!(
            frame.payload,
            Some(bridge::credential_bridge_guest_message::Payload::Ready(_))
        )
        || frame.encoded_len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
    {
        return Err(denied());
    }
    let public =
        public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&frame.encode_to_vec())
            .map_err(|_| denied())?;
    Ok(DelegateCredentialsRequest {
        input: Some(delegate_credentials_request::Input::Frame(Box::new(public))),
        ..Default::default()
    })
}

fn decode(
    response: DelegateCredentialsResponse,
) -> Result<bridge::CredentialBridgeHostMessage, Status> {
    let Some(delegate_credentials_response::Output::Frame(frame)) = response.output else {
        return Err(denied());
    };
    if frame.payload.is_none()
        || matches!(
            frame.payload,
            Some(public_bridge::credential_bridge_host_message::Payload::Open(_))
        )
        || frame.encoded_len() as usize > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
    {
        return Err(denied());
    }
    bridge::CredentialBridgeHostMessage::decode(frame.encode_to_vec().as_slice())
        .map_err(|_| denied())
}

fn live(deadline: Instant) -> Result<(), Status> {
    if Instant::now() >= deadline {
        Err(expired())
    } else {
        Ok(())
    }
}

fn client_error(error: ClientError) -> Status {
    match error.code() {
        codewire_client::ErrorCode::Unauthenticated
        | codewire_client::ErrorCode::PermissionDenied => denied(),
        codewire_client::ErrorCode::DeadlineExceeded => expired(),
        _ => unavailable(),
    }
}

fn denied() -> Status {
    Status::permission_denied("native platform credential authority denied")
}
fn unavailable() -> Status {
    Status::unavailable("native platform credential transport unavailable")
}
fn expired() -> Status {
    Status::deadline_exceeded("native platform credential setup expired")
}

#[cfg(test)]
mod tests;
