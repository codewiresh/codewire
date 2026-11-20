//! The HTTP transport every generated service client here is built on.

use connectrpc::ConnectError;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use http::{Request, Response};
use http_body_util::BodyExt as _;

use crate::{ClientConfig, ClientError, ErrorCode};

/// Adapter for connect-rust's transport trait using the repository-standard
/// rustls-backed reqwest client.
#[doc(hidden)]
#[derive(Clone)]
pub struct ReqwestConnectTransport(pub reqwest::Client);

pub(crate) fn default_http_client(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    // Connect bidi needs HTTP/2: cleartext direct endpoints use h2c prior
    // knowledge, and TLS endpoints negotiate it with ALPN.
    let builder = config.http_client_builder()?;
    let builder = if config.server_url().scheme() == "http" {
        builder.http2_prior_knowledge()
    } else {
        builder
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
                .map_err(crate::transport_error::send_failure)?;
            // Use reqwest's lossless HTTP conversion. Rebuilding the response
            // from `bytes_stream()` discards HTTP/2 trailer frames, including
            // the mandatory `grpc-status` used by native gRPC.
            Ok(Response::<reqwest::Body>::from(response))
        })
    }
}
