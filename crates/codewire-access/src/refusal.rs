//! The refusals Codewire answers itself on a managed route, and their one
//! rendering. `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Refusals an agent or a
//! person can read", is the list: a new refusal is added there first.
//!
//! A body names only the provider, the bound host and the kind of fix. It
//! never carries a label, an id or anything from the request or the
//! provider's answer, so nothing here takes one.

use std::borrow::Cow;

mod code;
pub use code::RefusalCode;

/// The response header that carries [`Refusal::reason`].
pub const REFUSAL_HEADER: &str = "codewire-refusal";

/// One refusal Codewire answers in HTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    CredentialRevoked,
    CredentialExpired,
    CredentialNeedsReconnect,
    NoCredentialSelected,
    CredentialUnavailable,
    CredentialConflict,
    PathNotServed,
    WebsocketNotServed,
    RouteNotServed,
    RequestNotForwarded(Unforwarded),
    BodyTooLarge,
    Busy,
    UpstreamFailed(UpstreamFailure),
    NameNotAllowed,
    /// A hosted Sandbox's request that carries none of its placeholders,
    /// refused whatever the network policy (#5555).
    SelectedCredentialOnly,
    /// The sign-in waits out its provider's rate limit on a refresh and the
    /// request's access token has expired (#4975): answered 429 with the
    /// wait left as `Retry-After`, 60 to 600 seconds.
    CredentialRefreshRateLimited {
        retry_after_seconds: u16,
    },
    Unavailable,
    /// An older broker's refusal that carries no reason. It keeps a
    /// denial's 403, so an agent doesn't retry it.
    Denied,
}

/// Why a request isn't forwarded as it is; each keeps the status it had
/// before refusals had reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unforwarded {
    /// 400: a malformed target or header, or a body the client broke off.
    Malformed,
    /// 403: a request the route never carries.
    Refused,
    /// 408: a streamed body the client stopped sending.
    ClientStalled,
    /// 421: a host that isn't this connection's.
    Misdirected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamFailure {
    /// 502: no answer, or one Codewire won't pass on.
    Failed,
    /// 504: no answer in time.
    TimedOut,
}

/// The provider a refusal names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalProvider {
    Anthropic,
    OpenAi,
    GitHub,
}

impl RefusalProvider {
    /// The provider behind a credential bridge capability slot.
    pub fn for_slot(slot: &str) -> Option<Self> {
        match slot {
            "anthropic" => Some(Self::Anthropic),
            "openai" | "codex" => Some(Self::OpenAi),
            "github" => Some(Self::GitHub),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAi => "OpenAI",
            Self::GitHub => "GitHub",
        }
    }

    const fn with_article(self) -> &'static str {
        match self {
            Self::Anthropic => "an Anthropic",
            Self::OpenAi => "an OpenAI",
            Self::GitHub => "a GitHub",
        }
    }
}

const RECONNECT_FIX: &str = "Fix: in a local VM, run `cw credentials --local list` on the computer that runs it; in a hosted Sandbox, run `cw credentials --cloud list` wherever you're signed in to Codewire; then connect it again.";
const PROFILE_FIX: &str = "Fix: run `cw credentials --local profiles list` on the computer that runs the VM, or `cw credentials --cloud profiles list` for a hosted Sandbox.";

impl Refusal {
    /// The `Codewire-Refusal` value: one reason from the spec's list, never
    /// free text.
    pub const fn reason(self) -> &'static str {
        self.code().as_str()
    }

    /// The headers every refusal carries besides its length.
    pub const fn headers(self) -> [(&'static str, &'static str); 3] {
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
            (REFUSAL_HEADER, self.reason()),
        ]
    }

    /// The `Retry-After` seconds a refusal carries beside [`Self::headers`].
    pub const fn retry_after_seconds(self) -> Option<u16> {
        match self {
            Self::CredentialRefreshRateLimited {
                retry_after_seconds,
            } => Some(retry_after_seconds),
            _ => None,
        }
    }

    /// Never 401: an agent answers a 401 with its own token refresh.
    pub const fn status(self) -> u16 {
        match self {
            Self::CredentialRevoked
            | Self::CredentialExpired
            | Self::CredentialNeedsReconnect
            | Self::NoCredentialSelected
            | Self::WebsocketNotServed
            | Self::RouteNotServed
            | Self::RequestNotForwarded(Unforwarded::Refused)
            | Self::NameNotAllowed
            | Self::SelectedCredentialOnly
            | Self::Denied => 403,
            Self::CredentialUnavailable | Self::Busy | Self::Unavailable => 503,
            Self::CredentialConflict | Self::RequestNotForwarded(Unforwarded::Malformed) => 400,
            Self::PathNotServed => 404,
            Self::RequestNotForwarded(Unforwarded::ClientStalled) => 408,
            Self::RequestNotForwarded(Unforwarded::Misdirected) => 421,
            Self::BodyTooLarge => 413,
            Self::CredentialRefreshRateLimited { .. } => 429,
            Self::UpstreamFailed(UpstreamFailure::Failed) => 502,
            Self::UpstreamFailed(UpstreamFailure::TimedOut) => 504,
        }
    }

    /// The plain-text body: the sentence, then a `Fix:` line where there is
    /// one. `host` is the canonical bound name of the host that took the
    /// connection, never the request's Host, SNI or `:authority`; on the
    /// loopback ingress no host was bound and the sentence leaves it out.
    pub fn body(self, provider: Option<RefusalProvider>, host: Option<&str>) -> String {
        let credential = provider.map_or_else(
            || "the credential".to_owned(),
            |provider| format!("the {} credential", provider.name()),
        );
        let to_host = host.map(|host| format!(" to {host}")).unwrap_or_default();
        let (sentence, fix) = match self {
            Self::CredentialRevoked => (
                format!("{credential} this environment uses was revoked."),
                Some(Cow::Borrowed(RECONNECT_FIX)),
            ),
            Self::CredentialExpired => (
                format!("{credential} this environment uses has expired."),
                Some(Cow::Borrowed(RECONNECT_FIX)),
            ),
            Self::CredentialNeedsReconnect => (
                format!("{credential} this environment uses needs reconnecting."),
                Some(Cow::Borrowed(RECONNECT_FIX)),
            ),
            Self::NoCredentialSelected => (
                match provider {
                    Some(provider) => format!(
                        "this environment's profile no longer has {} credential.",
                        provider.with_article()
                    ),
                    None => "this environment's profile no longer has this credential.".to_owned(),
                },
                Some(Cow::Borrowed(PROFILE_FIX)),
            ),
            Self::CredentialUnavailable => {
                (format!("{credential} can't be used right now; try again."), None)
            }
            Self::CredentialRefreshRateLimited {
                retry_after_seconds,
            } => (
                format!(
                    "the provider is rate-limiting the refresh of {credential}; try again in {retry_after_seconds} seconds."
                ),
                None,
            ),
            Self::CredentialConflict => (
                "this request carries the Codewire placeholder and another credential; send only one."
                    .to_owned(),
                None,
            ),
            Self::PathNotServed => (
                match host {
                    Some(host) => format!("this path on {host} isn't one Codewire forwards."),
                    None => "this path isn't one Codewire forwards.".to_owned(),
                },
                None,
            ),
            Self::WebsocketNotServed => (format!("WebSockets{to_host} aren't carried yet."), None),
            Self::RouteNotServed => (
                format!("requests{to_host} can't use this environment's credentials yet."),
                None,
            ),
            Self::RequestNotForwarded(_) => (
                format!("this request{to_host} isn't one Codewire forwards."),
                None,
            ),
            Self::BodyTooLarge => (
                format!("this request's body is over the 4 MiB Codewire forwards{to_host}."),
                None,
            ),
            Self::Busy => (
                "too many requests are in flight; try again.".to_owned(),
                None,
            ),
            Self::UpstreamFailed(_) => (
                match provider {
                    Some(provider) => format!("{} couldn't be reached; try again.", provider.name()),
                    None => "the provider couldn't be reached; try again.".to_owned(),
                },
                None,
            ),
            Self::NameNotAllowed => (
                format!("this environment's network policy doesn't allow this request{to_host}."),
                Some(Cow::Owned(format!(
                    "Fix: to send it, select a network policy with a rule that allows {} on port 443.",
                    allowing_rule(host)
                ))),
            ),
            Self::SelectedCredentialOnly => (
                match host {
                    Some(host) => format!(
                        "in a hosted Sandbox, requests to {host} must carry the Sandbox's Codewire credential."
                    ),
                    None => "in a hosted Sandbox, these requests must carry the Sandbox's Codewire credential."
                        .to_owned(),
                },
                None,
            ),
            Self::Unavailable => (
                format!(
                    "this request{to_host} can't be checked against the network policy right now; try again."
                ),
                None,
            ),
            Self::Denied => ("this request was refused.".to_owned(), None),
        };
        match fix {
            Some(fix) => format!("Codewire: {sentence}\n{fix}\n"),
            None => format!("Codewire: {sentence}\n"),
        }
    }
}

/// The rule a policy needs for an own-key request to `host`: the host itself,
/// or for a routed origin every name under its suffix, since a rule for one
/// routed name doesn't count yet (#4931).
fn allowing_rule(host: Option<&str>) -> String {
    match host {
        Some(host) => match crate::routed_suffix(host) {
            Some(suffix) => format!("*.{suffix}"),
            None => host.to_owned(),
        },
        None => "this host".to_owned(),
    }
}

#[cfg(test)]
mod tests;
