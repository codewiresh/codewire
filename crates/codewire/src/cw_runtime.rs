//! Typed platform runtime streaming. This consumer never buffers an entire
//! candidate, retries a mutation, chooses a new UUID or resolves a newer Pod.
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use buffa::Message as _;
use connectrpc::client::ClientTransport;
use futures_util::Stream;
use uuid::Uuid;

use crate::{ClientError, CodewireClient, ErrorCode, ReqwestConnectTransport};
use codewire_proto::codewire::v1::EnvironmentCwRuntimeServiceClient;
pub use codewire_proto::codewire::v1::{
    EnvironmentCwRuntimeAcknowledgement, EnvironmentCwRuntimeExpectation,
    EnvironmentCwRuntimeIdentity, EnvironmentCwRuntimeIncarnation, EnvironmentCwRuntimeOperation,
    EnvironmentCwRuntimeSelection, GetEnvironmentCwRuntimeRequest, GetEnvironmentCwRuntimeResponse,
    ObserveEnvironmentCwRuntimeRequest, ObserveEnvironmentCwRuntimeResponse,
    RollbackEnvironmentCwRuntimeRequest, RollbackEnvironmentCwRuntimeResponse,
    UpdateEnvironmentCwRuntimeHeader, UpdateEnvironmentCwRuntimeRequest,
    UpdateEnvironmentCwRuntimeResponse, environment_cw_runtime_acknowledgement,
    update_environment_cw_runtime_request,
};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MUTATION_TIMEOUT: Duration = Duration::from_secs(960);

#[derive(Debug, thiserror::Error)]
#[error("cw runtime outcome is uncertain; observe the original request {request_id}")]
pub struct CwRuntimeMutationError {
    pub request_id: String,
    /// Boxed so the error stays small beside the response it replaces.
    #[source]
    pub source: Box<ClientError>,
}

fn invalid() -> ClientError {
    ClientError::new(
        ErrorCode::InvalidArgument,
        "cw runtime stream or header is invalid",
    )
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn validate_header(header: &UpdateEnvironmentCwRuntimeHeader) -> Result<u64, ClientError> {
    let identity = header.identity.as_option().ok_or_else(invalid)?;
    let incarnation = header
        .expected_incarnation
        .as_option()
        .ok_or_else(invalid)?;
    let expected = header.expected_selection.as_option().ok_or_else(invalid)?;
    if header.encoded_len() as usize > 32 * 1024
        || !header.__buffa_unknown_fields.is_empty()
        || !uuid(&header.request_id)
        || !uuid(&header.environment_id)
        || header.org_id.is_empty()
        || header.org_id.len() > 128
        || incarnation.environment_id != header.environment_id
        || incarnation.org_id != header.org_id
        || !(64..=MAX_BYTES).contains(&identity.size)
        || identity.target != "x86_64-unknown-linux-musl"
        || (expected.generation == 0) != expected.current_sha256.is_none()
    {
        return Err(invalid());
    }
    Ok(identity.size)
}

struct Frames<S> {
    source: Pin<Box<S>>,
    header: Option<UpdateEnvironmentCwRuntimeHeader>,
    size: u64,
    count: u64,
    chunks: usize,
    finished: bool,
    error: Arc<Mutex<Option<ClientError>>>,
}

impl<S> Frames<S> {
    fn new(header: UpdateEnvironmentCwRuntimeHeader, source: S) -> Result<Self, ClientError> {
        let size = validate_header(&header)?;
        Ok(Self {
            source: Box::pin(source),
            header: Some(header),
            size,
            count: 0,
            chunks: 0,
            finished: false,
            error: Arc::new(Mutex::new(None)),
        })
    }
    fn refuse(&mut self, error: ClientError) -> Poll<Option<UpdateEnvironmentCwRuntimeRequest>> {
        self.finished = true;
        *self.error.lock().expect("runtime stream error lock") = Some(error);
        // Never translate a local read/custody error into a successful EOF.
        // The closed server adapter refuses this frame even if all declared
        // bytes were already emitted. The caller still treats lost ACK as
        // uncertain and observes the original UUID, never replays.
        Poll::Ready(Some(UpdateEnvironmentCwRuntimeRequest::default()))
    }
}

impl<S: Stream<Item = Result<Vec<u8>, ClientError>>> Stream for Frames<S> {
    type Item = UpdateEnvironmentCwRuntimeRequest;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(header) = this.header.take() {
            return Poll::Ready(Some(UpdateEnvironmentCwRuntimeRequest {
                payload: Some(update_environment_cw_runtime_request::Payload::Header(
                    Box::new(header),
                )),
                ..Default::default()
            }));
        }
        if this.finished {
            return Poll::Ready(None);
        }
        match this.source.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) => this.refuse(error),
            Poll::Ready(Some(Ok(bytes))) => {
                this.chunks += 1;
                let Some(next) = this.count.checked_add(bytes.len() as u64) else {
                    return this.refuse(invalid());
                };
                if bytes.is_empty()
                    || bytes.len() > CHUNK_BYTES
                    || next > this.size
                    || this.chunks > 8192
                {
                    return this.refuse(invalid());
                }
                this.count = next;
                Poll::Ready(Some(UpdateEnvironmentCwRuntimeRequest {
                    payload: Some(update_environment_cw_runtime_request::Payload::Chunk(bytes)),
                    ..Default::default()
                }))
            }
            Poll::Ready(None) => {
                if this.count != this.size {
                    return this.refuse(invalid());
                }
                this.finished = true;
                Poll::Ready(None)
            }
        }
    }
}

async fn update<T, S>(
    client: &EnvironmentCwRuntimeServiceClient<T>,
    header: UpdateEnvironmentCwRuntimeHeader,
    source: S,
    options: connectrpc::client::CallOptions,
) -> Result<UpdateEnvironmentCwRuntimeResponse, CwRuntimeMutationError>
where
    T: ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
    S: Stream<Item = Result<Vec<u8>, ClientError>> + Send + 'static,
{
    let id = header.request_id.clone();
    let frames = Frames::new(header, source).map_err(|source| CwRuntimeMutationError {
        request_id: id.clone(),
        source: Box::new(source),
    })?;
    let local_error = frames.error.clone();
    let response = client
        .update_environment_cw_runtime_with_options(frames, options.with_timeout(MUTATION_TIMEOUT))
        .await;
    if let Some(source) = local_error
        .lock()
        .expect("runtime stream error lock")
        .take()
    {
        return Err(CwRuntimeMutationError {
            request_id: id,
            source: Box::new(source),
        });
    }
    let response = response
        .map_err(|e| CwRuntimeMutationError {
            request_id: id.clone(),
            source: Box::new(e.into()),
        })?
        .into_owned();
    if response
        .operation
        .as_option()
        .is_none_or(|op| op.request_id != id)
    {
        return Err(CwRuntimeMutationError {
            request_id: id,
            source: Box::new(ClientError::new(
                ErrorCode::Internal,
                "cw runtime response omitted original request",
            )),
        });
    }
    Ok(response)
}

impl CodewireClient {
    fn cw_runtime_client(
        &self,
    ) -> Result<EnvironmentCwRuntimeServiceClient<ReqwestConnectTransport>, ClientError> {
        let config = self
            .config
            .connect_config()?
            .with_default_max_message_size(CHUNK_BYTES + 1024)
            .with_default_element_memory_limit(256 * 1024);
        Ok(EnvironmentCwRuntimeServiceClient::new(
            ReqwestConnectTransport(self.http.clone()),
            config,
        ))
    }
    pub async fn get_environment_cw_runtime(
        &self,
        request: GetEnvironmentCwRuntimeRequest,
    ) -> Result<GetEnvironmentCwRuntimeResponse, ClientError> {
        self.cw_runtime_client()?
            .get_environment_cw_runtime_with_options(
                request,
                self.auth_options()
                    .await?
                    .with_timeout(Duration::from_secs(180)),
            )
            .await
            .map(|r| r.into_owned())
            .map_err(Into::into)
    }
    pub async fn update_environment_cw_runtime<S>(
        &self,
        header: UpdateEnvironmentCwRuntimeHeader,
        source: S,
    ) -> Result<UpdateEnvironmentCwRuntimeResponse, CwRuntimeMutationError>
    where
        S: Stream<Item = Result<Vec<u8>, ClientError>> + Send + 'static,
    {
        let id = header.request_id.clone();
        let client = self
            .cw_runtime_client()
            .map_err(|source| CwRuntimeMutationError {
                request_id: id.clone(),
                source: Box::new(source),
            })?;
        let options = self
            .auth_options()
            .await
            .map_err(|source| CwRuntimeMutationError {
                request_id: id,
                source: Box::new(source),
            })?;
        update(&client, header, source, options).await
    }
    pub async fn rollback_environment_cw_runtime(
        &self,
        request: RollbackEnvironmentCwRuntimeRequest,
    ) -> Result<RollbackEnvironmentCwRuntimeResponse, CwRuntimeMutationError> {
        let id = request.request_id.clone();
        let client = self
            .cw_runtime_client()
            .map_err(|source| CwRuntimeMutationError {
                request_id: id.clone(),
                source: Box::new(source),
            })?;
        let options = self
            .auth_options()
            .await
            .map_err(|source| CwRuntimeMutationError {
                request_id: id.clone(),
                source: Box::new(source),
            })?
            .with_timeout(MUTATION_TIMEOUT);
        let response = client
            .rollback_environment_cw_runtime_with_options(request, options)
            .await
            .map_err(|e| CwRuntimeMutationError {
                request_id: id.clone(),
                source: Box::new(e.into()),
            })?
            .into_owned();
        if response
            .operation
            .as_option()
            .is_none_or(|op| op.request_id != id)
        {
            return Err(CwRuntimeMutationError {
                request_id: id,
                source: Box::new(ClientError::new(
                    ErrorCode::Internal,
                    "cw runtime response omitted original request",
                )),
            });
        }
        Ok(response)
    }
    pub async fn observe_environment_cw_runtime(
        &self,
        request: ObserveEnvironmentCwRuntimeRequest,
    ) -> Result<ObserveEnvironmentCwRuntimeResponse, ClientError> {
        self.cw_runtime_client()?
            .observe_environment_cw_runtime_with_options(request, self.auth_options().await?)
            .await
            .map(|r| r.into_owned())
            .map_err(Into::into)
    }
}

#[cfg(test)]
#[path = "cw_runtime_tests.rs"]
mod tests;
