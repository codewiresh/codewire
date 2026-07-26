//! RP-initiated logout — the end-session endpoint (OpenID Connect
//! RP-Initiated Logout 1.0).
//!
//! A relying party sends the user agent to the end-session endpoint to log
//! the end-user out. The provider validates the request (in particular, that
//! any `post_logout_redirect_uri` is registered for the client, exactly —
//! the same anti-open-redirect rule as the authorization endpoint), tells
//! the host which subject to terminate, and either redirects the user agent
//! back to the RP or signals that a default logged-out page should render.
//!
//! Actually tearing down the session is the host's job: this library has no
//! session store. The outcome carries the resolved [`Subject`] (from the
//! `id_token_hint`) so the host can end exactly that user's session.

use crate::Provider;
use crate::error::OAuthError;
use crate::flow::{enc, sep};
use crate::token;
use crate::types::Subject;

/// Raw end-session query parameters, as received off the wire.
#[derive(Debug, Clone, Default)]
pub struct RawEndSessionParams {
    /// `id_token_hint` — an id_token previously issued to the RP. Used to
    /// identify the subject and (via its audience) the client.
    pub id_token_hint: Option<String>,
    /// `client_id` — the RP requesting logout (an alternative to deriving it
    /// from the `id_token_hint`).
    pub client_id: Option<String>,
    /// `post_logout_redirect_uri` — where to send the user agent afterward.
    /// Must be exact-match registered for the resolved client.
    pub post_logout_redirect_uri: Option<String>,
    /// `state` — opaque value round-tripped to the RP on redirect.
    pub state: Option<String>,
}

/// The outcome of [`Provider::end_session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndSessionOutcome {
    /// Terminate the session for `subject` (if known), then redirect the user
    /// agent to this URL (the validated `post_logout_redirect_uri`, with
    /// `state` appended when present).
    Redirect {
        /// Where to send the user agent.
        url: String,
        /// The subject to log out, from the `id_token_hint`, if any.
        subject: Option<Subject>,
    },
    /// Terminate the session for `subject` (if known), then render the
    /// provider's default logged-out page (no `post_logout_redirect_uri` was
    /// supplied).
    LoggedOut {
        /// The subject to log out, from the `id_token_hint`, if any.
        subject: Option<Subject>,
    },
    /// The request was invalid (e.g. an unregistered
    /// `post_logout_redirect_uri`); render this error rather than redirect.
    Fail(OAuthError),
}

impl Provider {
    /// Handle an RP-initiated logout request.
    pub async fn end_session(
        &self,
        params: RawEndSessionParams,
    ) -> Result<EndSessionOutcome, OAuthError> {
        // Resolve subject + client from the id_token_hint, if present. The
        // hint must verify against our published keys (expiry is ignored).
        let mut subject = None;
        let mut hint_client = None;
        if let Some(hint) = params.id_token_hint.as_deref() {
            let keys = self.keys().public_jwks().await?;
            match token::verify_id_token(hint, &keys) {
                Ok(claims) => {
                    subject = Some(Subject(claims.sub));
                    hint_client = claims.azp.or_else(|| claims.aud.into_iter().next());
                }
                Err(e) => return Ok(EndSessionOutcome::Fail(e)),
            }
        }

        // If the client_id parameter is also present, it must agree with the
        // hint's audience (when both are known) — a hint for one client may
        // not drive a logout redirect for another.
        let client_id = match (params.client_id.as_deref(), hint_client.as_deref()) {
            (Some(p), Some(h)) if p != h => {
                return Ok(EndSessionOutcome::Fail(OAuthError::invalid_request(
                    "client_id does not match the id_token_hint audience",
                )));
            }
            (Some(p), _) => Some(p.to_string()),
            (None, h) => h.map(str::to_string),
        };

        let Some(uri) = params.post_logout_redirect_uri.as_deref() else {
            // No redirect requested → host renders the logged-out page.
            return Ok(EndSessionOutcome::LoggedOut { subject });
        };

        // A post-logout redirect must be validated against a known client.
        let Some(client_id) = client_id else {
            return Ok(EndSessionOutcome::Fail(OAuthError::invalid_request(
                "post_logout_redirect_uri requires client_id or id_token_hint",
            )));
        };
        let client = match self.clients().get(&client_id).await? {
            Some(c) if !c.disabled => c,
            _ => {
                return Ok(EndSessionOutcome::Fail(OAuthError::invalid_client(
                    "unknown client",
                )));
            }
        };
        if !client.allows_post_logout_redirect_uri(uri) {
            return Ok(EndSessionOutcome::Fail(OAuthError::invalid_request(
                "post_logout_redirect_uri not registered",
            )));
        }

        let mut url = uri.to_string();
        if let Some(state) = params.state.as_deref() {
            url.push_str(&format!("{}state={}", sep(uri), enc(state)));
        }
        Ok(EndSessionOutcome::Redirect { url, subject })
    }
}
