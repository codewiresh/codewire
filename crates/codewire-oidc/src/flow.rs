//! The authorization-code grant — the provider's core flow.
//!
//! [`Provider::authorize`] validates an `/authorize` request, resolves the
//! end-user through the host's [`UserAuthenticator`], and (on success)
//! issues a single-use authorization code bound to the client, redirect
//! URI, subject, scopes, nonce, and PKCE challenge.
//! [`Provider::exchange_authorization_code`] authenticates the client at the
//! token endpoint, atomically consumes the code, verifies PKCE, and mints an
//! opaque access token, an EdDSA-signed `id_token`, and (when the client
//! allows it) a refresh token.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::Provider;
use crate::error::OAuthError;
use crate::pkce::{self, CodeChallengeMethod};
use crate::token::{self, IdTokenClaims};
use crate::types::{
    AccessGrant, AuthCodeGrant, AuthOutcome, AuthorizationRequest, Client, GrantType, RefreshGrant,
    RequestContext, ResponseType, Scopes, StoredAuthRequest, Subject,
};

/// Raw `/authorize` query parameters, as received off the wire (the HTTP
/// layer URL-decodes and hands them in; the library does all validation).
#[derive(Debug, Clone, Default)]
pub struct RawAuthorizeParams {
    /// `client_id`.
    pub client_id: Option<String>,
    /// `redirect_uri`.
    pub redirect_uri: Option<String>,
    /// `response_type`.
    pub response_type: Option<String>,
    /// `scope` (space-delimited).
    pub scope: Option<String>,
    /// `state`.
    pub state: Option<String>,
    /// `nonce`.
    pub nonce: Option<String>,
    /// `code_challenge`.
    pub code_challenge: Option<String>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// `prompt`.
    pub prompt: Option<String>,
    /// `max_age`.
    pub max_age: Option<u64>,
}

/// The outcome of [`Provider::authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// Redirect the user agent here (success: `?code=…&state=…`, or an OAuth
    /// error redirect: `?error=…&error_description=…&state=…`). The redirect
    /// target is always a validated, client-registered URI.
    Redirect(String),
    /// No live session — send the user agent to the host's login URL.
    RedirectToLogin(String),
    /// The request could not be safely redirected (untrusted/missing
    /// `client_id` or `redirect_uri`); render this error directly instead.
    Fail(OAuthError),
}

/// A successful token-endpoint response (RFC 6749 §5.1 + OIDC `id_token`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The opaque access token.
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// The signed `id_token` (present for `openid` requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token, when the client is allowed one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted scopes (space-delimited).
    pub scope: String,
}

impl Provider {
    /// Validate an authorization request, resolve the end-user, and (on
    /// success) issue an authorization code.
    ///
    /// Validation is staged so errors are only redirected once the
    /// `client_id` and `redirect_uri` are proven trustworthy; before that, a
    /// failure is returned as [`AuthorizeOutcome::Fail`] (threat T1) rather
    /// than reflected to an attacker-supplied URI.
    pub async fn authorize(
        &self,
        ctx: &RequestContext,
        params: RawAuthorizeParams,
    ) -> Result<AuthorizeOutcome, OAuthError> {
        // 1. Client must exist and be enabled.
        let client_id = match &params.client_id {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                return Ok(AuthorizeOutcome::Fail(OAuthError::invalid_request(
                    "missing client_id",
                )));
            }
        };
        let client = match self.clients().get(&client_id).await? {
            Some(c) if !c.disabled => c,
            Some(_) => {
                return Ok(AuthorizeOutcome::Fail(OAuthError::invalid_client(
                    "client disabled",
                )));
            }
            None => {
                return Ok(AuthorizeOutcome::Fail(OAuthError::invalid_client(
                    "unknown client",
                )));
            }
        };

        // 2. redirect_uri must be present and exact-match registered.
        let redirect_uri = match &params.redirect_uri {
            Some(u) if client.allows_redirect_uri(u) => u.clone(),
            _ => {
                return Ok(AuthorizeOutcome::Fail(OAuthError::invalid_request(
                    "redirect_uri not registered",
                )));
            }
        };

        // From here, errors are safe to redirect to the validated URI.
        let state = params.state.clone();
        let err_redirect = |e: OAuthError| {
            AuthorizeOutcome::Redirect(error_redirect(&redirect_uri, &e, state.as_deref()))
        };

        // 3. response_type — code only.
        if params.response_type.as_deref() != Some("code") {
            return Ok(err_redirect(OAuthError::new(
                crate::ErrorCode::UnsupportedResponseType,
                "only response_type=code is supported",
            )));
        }

        // 4. scopes — must request openid and be a subset of the client's.
        let scopes = Scopes::parse(params.scope.as_deref().unwrap_or(""));
        if !scopes.contains("openid") {
            return Ok(err_redirect(OAuthError::new(
                crate::ErrorCode::InvalidScope,
                "the openid scope is required",
            )));
        }
        if let Some(bad) = scopes.0.iter().find(|s| !client.scopes.contains(s)) {
            return Ok(err_redirect(OAuthError::new(
                crate::ErrorCode::InvalidScope,
                format!("scope not allowed for client: {bad}"),
            )));
        }

        // 5. PKCE — required for every client, S256 only (threat T2).
        let code_challenge = match &params.code_challenge {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                return Ok(err_redirect(OAuthError::invalid_request(
                    "code_challenge is required",
                )));
            }
        };
        if CodeChallengeMethod::parse(params.code_challenge_method.as_deref()).is_none() {
            return Ok(err_redirect(OAuthError::invalid_request(
                "code_challenge_method must be S256",
            )));
        }

        // Persist the in-flight request, then resolve the end-user.
        let request = AuthorizationRequest {
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.clone(),
            response_type: ResponseType::Code,
            scopes: scopes.clone(),
            state: state.clone(),
            nonce: params.nonce.clone(),
            code_challenge: Some(code_challenge.clone()),
            code_challenge_method: Some("S256".into()),
            prompt: params.prompt.clone(),
            max_age: params.max_age,
        };
        let id = self
            .auth_requests()
            .create(StoredAuthRequest {
                id: crate::AuthRequestId(String::new()),
                request: request.clone(),
                subject: None,
            })
            .await?;

        // OIDC `prompt=none` means "never show UI": if the user isn't already
        // authenticated we must fail with `login_required` rather than bounce
        // them to a login page (OIDC Core §3.1.2.1).
        let prompt_none = params
            .prompt
            .as_deref()
            .map(|p| p.split_whitespace().any(|v| v == "none"))
            .unwrap_or(false);

        match self
            .authenticator()
            .authenticate(
                ctx,
                &StoredAuthRequest {
                    id: id.clone(),
                    request,
                    subject: None,
                },
            )
            .await?
        {
            AuthOutcome::Authenticated { subject, auth_time } => {
                let code = token::mint_opaque_token();
                self.tokens()
                    .store_code(
                        &code,
                        AuthCodeGrant {
                            client_id: client_id.clone(),
                            redirect_uri: redirect_uri.clone(),
                            subject,
                            scopes,
                            code_challenge: Some(code_challenge),
                            nonce: params.nonce,
                            auth_time,
                        },
                        AUTH_CODE_TTL_SECS,
                    )
                    .await?;
                // The request is consumed; best-effort cleanup.
                let _ = self.auth_requests().delete(&id).await;
                Ok(AuthorizeOutcome::Redirect(success_redirect(
                    &redirect_uri,
                    &code,
                    state.as_deref(),
                )))
            }
            AuthOutcome::NeedsLogin(_) if prompt_none => Ok(err_redirect(OAuthError::new(
                crate::ErrorCode::LoginRequired,
                "prompt=none but the end-user is not authenticated",
            ))),
            AuthOutcome::NeedsLogin(url) => Ok(AuthorizeOutcome::RedirectToLogin(url)),
            AuthOutcome::Denied(reason) => Ok(err_redirect(OAuthError::access_denied(reason))),
        }
    }

    /// Exchange an authorization code for tokens at the token endpoint.
    pub async fn exchange_authorization_code(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        // Authenticate the client.
        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(OAuthError::new(
                crate::ErrorCode::UnauthorizedClient,
                "client may not use the authorization_code grant",
            ));
        }

        // Atomically consume the code (single-use; replay → invalid_grant).
        let grant = self
            .tokens()
            .consume_code(code)
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("invalid or expired code"))?;

        if grant.client_id != client_id {
            return Err(OAuthError::invalid_grant(
                "code was issued to another client",
            ));
        }
        if grant.redirect_uri != redirect_uri {
            return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
        }

        // PKCE — the challenge is always set at issuance; require + verify.
        match (&grant.code_challenge, code_verifier) {
            (Some(challenge), Some(verifier)) if pkce::verify_s256(verifier, challenge) => {}
            _ => return Err(OAuthError::invalid_grant("PKCE verification failed")),
        }

        self.issue_tokens(
            &client,
            grant.subject,
            grant.scopes,
            grant.nonce,
            grant.auth_time,
        )
        .await
    }

    /// Exchange a refresh token for a fresh token set (RFC 6749 §6 +
    /// OIDC §12).
    ///
    /// The presented refresh token is **rotated**: it is atomically consumed
    /// and a new one is issued, so a replayed refresh token fails with
    /// `invalid_grant` (threat T9). An optional `scope` may only *narrow* the
    /// originally granted scopes (RFC 6749 §6); a request for any scope the
    /// original grant lacked is `invalid_scope`.
    pub async fn exchange_refresh_token(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        refresh_token: &str,
        requested_scope: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        if !client.grant_types.contains(&GrantType::RefreshToken) {
            return Err(OAuthError::new(
                crate::ErrorCode::UnauthorizedClient,
                "client may not use the refresh_token grant",
            ));
        }

        // Rotation: consume the presented token atomically.
        let grant = self
            .tokens()
            .consume_refresh(refresh_token)
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("invalid or expired refresh token"))?;
        if grant.client_id != client_id {
            return Err(OAuthError::invalid_grant(
                "refresh token was issued to another client",
            ));
        }

        // Scope may only be narrowed.
        let scopes = match requested_scope {
            Some(s) if !s.trim().is_empty() => {
                let requested = Scopes::parse(s);
                if let Some(bad) = requested.0.iter().find(|sc| !grant.scopes.contains(sc)) {
                    return Err(OAuthError::new(
                        crate::ErrorCode::InvalidScope,
                        format!("scope exceeds the original grant: {bad}"),
                    ));
                }
                requested
            }
            _ => grant.scopes,
        };

        // No nonce on a refresh-issued id_token (OIDC §12.2); auth_time is
        // not re-asserted on refresh.
        self.issue_tokens(&client, grant.subject, scopes, None, None)
            .await
    }

    /// Authenticate a client at the token endpoint per its registered
    /// method: confidential clients present a secret (verified in constant
    /// time by the store); public clients must present none. Shared with the
    /// introspection/revocation endpoints.
    pub(crate) async fn authenticate_client(
        &self,
        client: &Client,
        secret: Option<&str>,
    ) -> Result<(), OAuthError> {
        if client.is_public() {
            // Public client: identity is asserted via PKCE, not a secret.
            if secret.is_some() {
                return Err(OAuthError::invalid_client(
                    "public client must not present a secret",
                ));
            }
            return Ok(());
        }
        let secret = secret.ok_or_else(|| OAuthError::invalid_client("client secret required"))?;
        if self.clients().verify_secret(&client.id, secret).await? {
            Ok(())
        } else {
            Err(OAuthError::invalid_client("invalid client credentials"))
        }
    }

    /// Mint the access token, sign the id_token, and (when allowed) issue a
    /// refresh token. Shared by the code, refresh, and device grants.
    pub(crate) async fn issue_tokens(
        &self,
        client: &Client,
        subject: Subject,
        scopes: Scopes,
        nonce: Option<String>,
        auth_time: Option<i64>,
    ) -> Result<TokenResponse, OAuthError> {
        let now = Utc::now().timestamp();
        // Per-client clock-skew tolerance, applied to the id_token's validity
        // window so RPs with a slightly-off clock still accept a fresh token
        // (matches the reference provider: iat = now − skew, exp = now + skew
        // + lifetime). Defaults to 0.
        let skew = client.clock_skew_secs as i64;

        // Opaque access token.
        let access_token = token::mint_opaque_token();
        self.tokens()
            .store_access(
                &access_token,
                AccessGrant {
                    subject: subject.clone(),
                    client_id: client.id.clone(),
                    scopes: scopes.clone(),
                },
                client.access_token_lifetime_secs,
            )
            .await?;

        // id_token (only for openid requests).
        let id_token = if scopes.contains("openid") {
            let extra = self
                .customizer()
                .extra_claims(&subject, &scopes, client)
                .await?;
            let claims = IdTokenClaims {
                iss: self.config().issuer.as_str().to_string(),
                sub: subject.0.clone(),
                aud: vec![client.id.clone()],
                azp: Some(client.id.clone()),
                exp: now + skew + client.id_token_lifetime_secs as i64,
                iat: now - skew,
                nonce,
                auth_time,
                at_hash: Some(token::at_hash(&access_token)),
                extra,
            };
            let signer = self.keys().active_signer().await?;
            Some(token::sign_id_token(&signer, &claims)?)
        } else {
            None
        };

        // Refresh token — only when the `offline_access` scope was granted
        // (RFC 6749 §1.5 / OIDC §11), the client is allowed the refresh
        // grant, and a lifetime is configured. Gating on the scope (not just
        // client capability) matches the reference provider's
        // `needsRefreshToken`: a client may *support* refresh yet not receive
        // one unless the request asked for offline access.
        let wants_refresh = scopes.contains("offline_access")
            && client.grant_types.contains(&GrantType::RefreshToken);
        let refresh_token = match (wants_refresh, client.refresh_token_lifetime_secs) {
            (true, Some(ttl)) => {
                let rt = token::mint_opaque_token();
                self.tokens()
                    .store_refresh(
                        &rt,
                        RefreshGrant {
                            subject,
                            client_id: client.id.clone(),
                            scopes: scopes.clone(),
                        },
                        ttl,
                    )
                    .await?;
                Some(rt)
            }
            _ => None,
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: client.access_token_lifetime_secs,
            id_token,
            refresh_token,
            scope: scopes.to_space_delimited(),
        })
    }
}

/// Authorization-code lifetime — short, single-use (OAuth 2.1 recommends
/// ≤ 60s; we use 60).
const AUTH_CODE_TTL_SECS: u64 = 60;

/// Build a success redirect: `redirect_uri?code=…[&state=…]`.
fn success_redirect(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut url = format!("{redirect_uri}{}code={}", sep(redirect_uri), enc(code));
    if let Some(s) = state {
        url.push_str(&format!("&state={}", enc(s)));
    }
    url
}

/// Build an OAuth error redirect:
/// `redirect_uri?error=…&error_description=…[&state=…]`.
fn error_redirect(redirect_uri: &str, err: &OAuthError, state: Option<&str>) -> String {
    let mut url = format!(
        "{}{}error={}&error_description={}",
        redirect_uri,
        sep(redirect_uri),
        enc(err.code.as_str()),
        enc(&err.description),
    );
    if let Some(s) = state {
        url.push_str(&format!("&state={}", enc(s)));
    }
    url
}

/// `?` if the URI has no query yet, otherwise `&`.
pub(crate) fn sep(uri: &str) -> char {
    if uri.contains('?') { '&' } else { '?' }
}

/// Percent-encode a query-parameter value (application/x-www-form-urlencoded
/// component rules — encode everything outside the RFC 3986 unreserved set).
pub(crate) fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
