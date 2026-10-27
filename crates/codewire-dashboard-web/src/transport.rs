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
