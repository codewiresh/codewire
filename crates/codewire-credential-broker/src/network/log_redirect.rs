//! The one redirect the broker follows (#5737). GitHub answers an Actions log
//! download with a 302 to a short-lived signed URL on one of its log hosts.
//! That URL is a credential, so it never reaches the guest: the broker
//! fetches it itself, once, and streams the body back.
//!
//! The log host's addresses were looked up at the broker's start and pinned
//! like a provider host's; nothing here looks a name up. See
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Actions reads and the one redirect
//! the broker follows".

use std::sync::atomic::{AtomicU64, Ordering};

use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use super::{
    GITHUB_API_HOST, OPENAI_PORT, ProviderHttpsTransport, REQUEST_TIMEOUT, map_reqwest_error,
    request_failed, validate_response_headers,
};
use crate::{BrokerUpstreamError, BrokerUpstreamResponse};

/// This broker's refused log redirects, carried on each refusal's log line.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Why a log redirect was refused, as its log line names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// The first answer was a 3xx other than 302.
    FirstStatus,
    /// No `Location`, more than one, or one that isn't an absolute URL.
    Location,
    Scheme,
    Port,
    Userinfo,
    Fragment,
    /// A host that is not on the pinned list, or an address literal.
    Unlisted,
    /// A listed host this broker has no address for.
    Dropped,
    /// The log host could not be reached at its pinned address.
    Unanswered,
    /// The log host answered something other than 200, a 3xx among them.
    Status,
}

impl Refused {
    fn as_str(self) -> &'static str {
        match self {
            Self::FirstStatus => "first_status",
            Self::Location => "location",
            Self::Scheme => "scheme",
            Self::Port => "port",
            Self::Userinfo => "userinfo",
            Self::Fragment => "fragment",
            Self::Unlisted => "unlisted",
            Self::Dropped => "dropped",
            Self::Unanswered => "unanswered",
            Self::Status => "status",
        }
    }
}

/// Whether the broker follows this answer to `target`: a 3xx to GET on one of
/// the two log downloads at the API host. Every other answer is returned as
/// the provider gave it, whose `Location` the route never passes on.
pub(super) fn follows(target: &url::Url, method: &Method, status: StatusCode) -> bool {
    status.is_redirection()
        && target.host_str() == Some(GITHUB_API_HOST)
        && crate::github::log_download(method, target.path())
}

/// The signed URL a 302's `Location` names and its listed host, or why it is
/// refused. Nothing is dialled before this passes. The host is the URL
/// parser's, which lowercases it; a trailing dot is not the listed name.
pub(super) fn admit_location(
    headers: &HeaderMap,
) -> Result<(url::Url, &'static str), (Refused, Option<String>)> {
    let mut values = headers.get_all(header::LOCATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err((Refused::Location, None));
    };
    let target = value
        .to_str()
        .ok()
        .and_then(|value| url::Url::parse(value).ok())
        .ok_or((Refused::Location, None))?;
    let host = target.host_str().map(str::to_owned);
    let refused = |reason| Err((reason, host.clone()));
    if target.scheme() != "https" {
        return refused(Refused::Scheme);
    }
    if target.port_or_known_default() != Some(OPENAI_PORT) {
        return refused(Refused::Port);
    }
    if !target.username().is_empty() || target.password().is_some() {
        return refused(Refused::Userinfo);
    }
    if target.fragment().is_some() {
        return refused(Refused::Fragment);
    }
    let listed = match target.host() {
        Some(url::Host::Domain(domain)) => crate::github::log_hosts::log_host(domain),
        _ => None,
    };
    match listed {
        Some(listed) => Ok((target, listed)),
        None => refused(Refused::Unlisted),
    }
}

/// Log a refused redirect by its host, never its URL, and count it. The
/// guest gets `upstream_failed`.
fn refuse(host: Option<&str>, reason: Refused) -> BrokerUpstreamError {
    let refused_total = REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    // A host off the list is GitHub's text: bounded, and only the name.
    let host: String = host.unwrap_or("-").chars().take(253).collect();
    tracing::warn!(
        host = %host,
        reason = reason.as_str(),
        refused_total,
        "github log redirect refused"
    );
    BrokerUpstreamError::Protocol
}

impl ProviderHttpsTransport {
    /// Follow a log download's redirect: one hop, to a listed host this
    /// broker pinned, as a fresh GET with no credential.
    pub(super) async fn follow_log_redirect(
        &self,
        response: reqwest::Response,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if response.status() != StatusCode::FOUND {
            return Err(refuse(None, Refused::FirstStatus));
        }
        let (target, host) = admit_location(response.headers())
            .map_err(|(reason, host)| refuse(host.as_deref(), reason))?;
        // The first answer's body is never read; its connection closes.
        drop(response);
        if !self.log_hosts.contains(host) {
            return Err(refuse(Some(host), Refused::Dropped));
        }
        fetch_log(&self.client, target, host).await
    }
}

/// The second request: GET with only the headers the broker writes, through
/// a client that follows no redirect, and a 200 answer reduced to its body,
/// `Content-Type` and `Content-Length`.
pub(super) async fn fetch_log(
    client: &reqwest::Client,
    target: url::Url,
    host: &'static str,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let response = client
        .get(target)
        .header(
            header::USER_AGENT,
            HeaderValue::from_static("Codewire-Credential-Broker"),
        )
        .header(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        )
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            request_failed(host, false, error);
            refuse(Some(host), Refused::Unanswered)
        })?;
    if response.status() != StatusCode::OK {
        return Err(refuse(Some(host), Refused::Status));
    }
    validate_response_headers(response.headers())?;
    let mut headers = HeaderMap::new();
    for name in [header::CONTENT_TYPE, header::CONTENT_LENGTH] {
        for value in response.headers().get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    let body = response
        .bytes_stream()
        .map(|chunk| chunk.map_err(map_reqwest_error));
    Ok(BrokerUpstreamResponse::new(
        StatusCode::OK,
        headers,
        Box::pin(body),
    ))
}

#[cfg(test)]
#[path = "log_redirect_tests.rs"]
mod tests;
