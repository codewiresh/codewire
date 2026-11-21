use axum::http::{HeaderMap, HeaderValue, header};
use connectrpc::{
    ConnectError,
    client::{BoxFuture, ClientTransport},
};
use http::{Request, Response};
use http_body_util::BodyExt as _;

#[derive(Clone)]
pub(crate) struct BrowserTransport {
    pub(crate) http: reqwest::Client,
    pub(crate) cookie: Option<HeaderValue>,
    pub(crate) origin: Option<HeaderValue>,
}

impl ClientTransport for BrowserTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<connectrpc::client::ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let client = self.http.clone();
        let cookie = self.cookie.clone();
        let origin = self.origin.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            parts.headers = browser_headers(parts.headers, cookie, origin);
            // Continue this page request's trace in the API (W3C traceparent).
            codewire_server_core::obs::inject_http_headers(&mut parts.headers);
            let body = reqwest::Body::wrap_stream(body.into_data_stream());
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|error| {
                    ConnectError::unavailable(format!("send dashboard request: {error}"))
                })?;
            Ok(Response::<reqwest::Body>::from(response))
        })
    }
}

/// This page request's trace context as request headers (W3C traceparent),
/// so the service called continues its trace, as [`BrowserTransport`] does
/// for a Connect call. Empty unless trace export is on. For the plain HTTP
/// calls to the identity service, and for no address outside the deployment:
/// a trace's ids stay ours (docs/CONFIGURATION.md, "Tracing").
pub(crate) fn trace_context() -> HeaderMap {
    let mut headers = HeaderMap::new();
    codewire_server_core::obs::inject_http_headers(&mut headers);
    headers
}

/// A [`BrowserTransport`] that also passes on the page request's
/// `X-Forwarded-For`, for limits the platform counts per client address
/// (#3840). The platform reads only the hop our edge appended last, so a
/// browser's own entries change nothing.
#[derive(Clone)]
pub(crate) struct ForwardingTransport {
    pub(crate) inner: BrowserTransport,
    pub(crate) forwarded_for: Option<HeaderValue>,
}

impl ClientTransport for ForwardingTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        mut request: Request<connectrpc::client::ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        if let Some(forwarded_for) = &self.forwarded_for {
            request.headers_mut().insert(
                header::HeaderName::from_static("x-forwarded-for"),
                forwarded_for.clone(),
            );
        }
        self.inner.send(request)
    }
}

pub(crate) fn browser_headers(
    mut headers: HeaderMap,
    cookie: Option<HeaderValue>,
    origin: Option<HeaderValue>,
) -> HeaderMap {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
    headers.remove(header::ORIGIN);
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        headers.insert(header::ORIGIN, origin);
    }
    headers
}
