//! GitHub and Google as OAuth providers of `codewire-idp`: their
//! configuration, the fixed endpoints, the code exchange and the identity each
//! one proves. Every call goes through [`OAuthUpstream`], so tests answer them
//! in-process without a network or an injectable base URL.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use zeroize::Zeroizing;

const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
const GITHUB_SCOPES: &str = "read:user user:email";

const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_SCOPES: &str = "openid email profile";
/// The issuers Google's ID tokens carry (its discovery document names the
/// first; tokens may carry either).
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

const MAX_SECRET_BYTES: usize = 16 * 1024;
/// Upper bound on one provider response body. GitHub's email list and
/// Google's token response are a few KiB.
pub(crate) const MAX_UPSTREAM_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_NAME_CHARS: usize = 200;
/// Clock skew tolerated on Google's `exp`.
const EXPIRY_LEEWAY_SECS: i64 = 60;

/// A provider Codewire signs in with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    GitHub,
    Google,
}

impl Provider {
    pub const ALL: [Self; 2] = [Self::GitHub, Self::Google];

    /// The `accounts.provider_id` and URL segment.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }

    /// The name people read.
    pub fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::Google => "Google",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str() == value)
    }
}

/// One provider's OAuth client. The secret is zeroized on drop and never
/// printed.
struct ClientCredentials {
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCredentials")
            .field("client_id_configured", &!self.client_id.is_empty())
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// The configured providers and the transport that reaches them. A provider
/// without both of its client values is off.
#[derive(Clone)]
pub struct OAuthProviders {
    github: Option<Arc<ClientCredentials>>,
    google: Option<Arc<ClientCredentials>>,
    upstream: Arc<dyn OAuthUpstream>,
}

impl fmt::Debug for OAuthProviders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProviders")
            .field("github", &self.github)
            .field("google", &self.google)
            .finish_non_exhaustive()
    }
}

impl OAuthProviders {
    /// Both providers off.
    pub fn disabled() -> Self {
        Self {
            github: None,
            google: None,
            upstream: Arc::new(ReqwestUpstream::new()),
        }
    }

    /// Read `CODEWIRE_OAUTH_{GITHUB,GOOGLE}_CLIENT_{ID,SECRET}`. Each pair is
    /// all or none: none turns the provider off, half a pair is an error so
    /// the IdP does not start with a provider it cannot finish.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    fn from_values(mut value: impl FnMut(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut pair = |provider: Provider| -> anyhow::Result<Option<Arc<ClientCredentials>>> {
            let prefix = match provider {
                Provider::GitHub => "CODEWIRE_OAUTH_GITHUB",
                Provider::Google => "CODEWIRE_OAUTH_GOOGLE",
            };
            let id_name = format!("{prefix}_CLIENT_ID");
            let secret_name = format!("{prefix}_CLIENT_SECRET");
            let id = value(&id_name).map(|id| id.trim().to_owned());
            let secret = value(&secret_name).map(Zeroizing::new);
            let id = id.filter(|id| !id.is_empty());
            let secret = secret.filter(|secret| !secret.trim().is_empty());
            match (id, secret) {
                (None, None) => Ok(None),
                (Some(client_id), Some(client_secret)) => {
                    if client_id.len() > MAX_SECRET_BYTES
                        || client_secret.len() > MAX_SECRET_BYTES
                        || client_id.bytes().any(|byte| byte.is_ascii_control())
                        || client_secret.bytes().any(|byte| byte.is_ascii_control())
                    {
                        anyhow::bail!("{id_name} and {secret_name} must be single-line values");
                    }
                    Ok(Some(Arc::new(ClientCredentials {
                        client_id,
                        client_secret: Zeroizing::new(client_secret.trim().to_owned()),
                    })))
                }
                _ => anyhow::bail!("{id_name} and {secret_name} must both be set or both be unset"),
            }
        };
        Ok(Self {
            github: pair(Provider::GitHub)?,
            google: pair(Provider::Google)?,
            upstream: Arc::new(ReqwestUpstream::new()),
        })
    }

    /// Providers answered by `upstream` instead of the network. Only tests
    /// call this: the endpoints stay the fixed provider URLs.
    pub fn with_upstream(
        github: Option<(&str, &str)>,
        google: Option<(&str, &str)>,
        upstream: Arc<dyn OAuthUpstream>,
    ) -> Self {
        let credentials = |pair: Option<(&str, &str)>| {
            pair.map(|(client_id, client_secret)| {
                Arc::new(ClientCredentials {
                    client_id: client_id.to_owned(),
                    client_secret: Zeroizing::new(client_secret.to_owned()),
                })
            })
        };
        Self {
            github: credentials(github),
            google: credentials(google),
            upstream,
        }
    }

    /// The configured providers, GitHub first.
    pub fn configured(&self) -> Vec<Provider> {
        Provider::ALL
            .into_iter()
            .filter(|provider| self.credentials(*provider).is_some())
            .collect()
    }

    fn credentials(&self, provider: Provider) -> Option<&ClientCredentials> {
        match provider {
            Provider::GitHub => self.github.as_deref(),
            Provider::Google => self.google.as_deref(),
        }
    }

    pub(crate) fn is_configured(&self, provider: Provider) -> bool {
        self.credentials(provider).is_some()
    }

    /// The provider's authorization URL for one round trip.
    pub(crate) fn authorize_url(
        &self,
        provider: Provider,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
        nonce: Option<&str>,
    ) -> Option<String> {
        let credentials = self.credentials(provider)?;
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", &credentials.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        let base = match provider {
            Provider::GitHub => {
                query.append_pair("scope", GITHUB_SCOPES);
                GITHUB_AUTHORIZE_URL
            }
            Provider::Google => {
                query
                    .append_pair("response_type", "code")
                    .append_pair("scope", GOOGLE_SCOPES)
                    .append_pair("nonce", nonce?);
                GOOGLE_AUTHORIZE_URL
            }
        };
        Some(format!("{base}?{}", query.finish()))
    }

    /// Exchange the callback's code server-side with the PKCE verifier and
    /// read the identity it proves. No provider token outlives this call.
    pub(crate) async fn identify(
        &self,
        provider: Provider,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> Result<ProviderIdentity, IdentityError> {
        let credentials = self
            .credentials(provider)
            .ok_or(IdentityError::Unavailable)?;
        match provider {
            Provider::GitHub => {
                github_identity(
                    self.upstream.as_ref(),
                    credentials,
                    code,
                    code_verifier,
                    redirect_uri,
                )
                .await
            }
            Provider::Google => {
                google_identity(
                    self.upstream.as_ref(),
                    credentials,
                    code,
                    code_verifier,
                    redirect_uri,
                    nonce.ok_or(IdentityError::Invalid)?,
                )
                .await
            }
        }
    }
}

/// What a provider proved: its stable subject and a verified email.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProviderIdentity {
    pub(crate) subject: String,
    pub(crate) email: String,
    pub(crate) name: Option<String>,
    /// Google's `hd`: the Google Workspace domain that manages the account.
    /// GitHub has none.
    pub(crate) hosted_domain: Option<String>,
    /// How a person recognizes the provider account: GitHub's login, or the
    /// Google account's email. A link confirmation names it.
    pub(crate) account: String,
}

impl ProviderIdentity {
    /// Whether the provider itself vouches that this person controls the
    /// email address's whole account, so a match may be linked without an
    /// emailed confirmation (owner, 2026-11-11, #4062): only Google, for a
    /// `@gmail.com` address or one whose domain is the `hd` Google manages.
    /// GitHub only says the address was verified once, so it never vouches.
    pub(crate) fn provider_owns_email(&self, provider: Provider) -> bool {
        if provider != Provider::Google {
            return false;
        }
        let Some((_, domain)) = self.email.rsplit_once('@') else {
            return false;
        };
        domain.eq_ignore_ascii_case("gmail.com")
            || self
                .hosted_domain
                .as_deref()
                .is_some_and(|hosted| hosted.eq_ignore_ascii_case(domain))
    }
}

impl fmt::Debug for ProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIdentity")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Why a provider round trip proved no usable identity. None of these carry
/// provider text; the browser sees a fixed message for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityError {
    /// The provider is not configured.
    Unavailable,
    /// The provider did not answer, or answered with an error.
    Upstream,
    /// The answer was malformed, or an ID token failed a check.
    Invalid,
    /// The provider has no verified primary email for the account.
    UnverifiedEmail,
}

/// One request to a provider. Its URL is always one of the fixed endpoints
/// above; values that are secret are zeroized and never printed.
pub struct UpstreamRequest {
    url: &'static str,
    accept: &'static str,
    bearer: Option<Zeroizing<String>>,
    form: Vec<(&'static str, Zeroizing<String>)>,
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamRequest")
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "[REDACTED]"))
            .field(
                "form",
                &self.form.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl UpstreamRequest {
    /// The fixed endpoint.
    pub fn url(&self) -> &str {
        self.url
    }

    /// Whether this is a form POST (the token exchange) rather than a GET.
    pub fn is_post(&self) -> bool {
        !self.form.is_empty()
    }

    /// One form field of the token exchange.
    pub fn form_value(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.as_str())
    }

    /// The bearer token of an API read.
    pub fn bearer(&self) -> Option<&str> {
        self.bearer.as_ref().map(|token| token.as_str())
    }
}

/// A provider's answer: its status and a bounded body.
#[derive(Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The provider could not be reached or its answer exceeded the bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamError;

/// How `codewire-idp` reaches GitHub and Google. Production uses
/// [`ReqwestUpstream`]; tests answer in-process.
#[async_trait]
pub trait OAuthUpstream: Send + Sync {
    async fn execute(&self, request: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError>;
}

/// The network transport: a 10 s bound, no redirects, a bounded body.
pub struct ReqwestUpstream {
    http: reqwest::Client,
}

impl ReqwestUpstream {
    fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("codewire-idp")
                .build()
                .expect("static OAuth provider HTTP client configuration"),
        }
    }
}

#[async_trait]
impl OAuthUpstream for ReqwestUpstream {
    async fn execute(&self, request: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let mut builder = if request.is_post() {
            let form: Vec<(&str, &str)> = request
                .form
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            self.http.post(request.url).form(&form)
        } else {
            self.http.get(request.url)
        };
        builder = builder.header(reqwest::header::ACCEPT, request.accept);
        if let Some(token) = request.bearer.as_ref() {
            builder = builder.bearer_auth(token.as_str());
        }
        if request.url.starts_with("https://api.github.com/") {
            builder = builder.header("X-GitHub-Api-Version", "2022-11-28");
        }
        let mut response = builder.send().await.map_err(|_| UpstreamError)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_UPSTREAM_RESPONSE_BYTES as u64)
        {
            return Err(UpstreamError);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| UpstreamError)? {
            if body.len() + chunk.len() > MAX_UPSTREAM_RESPONSE_BYTES {
                return Err(UpstreamError);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse { status, body })
    }
}

fn token_request(
    url: &'static str,
    credentials: &ClientCredentials,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> UpstreamRequest {
    UpstreamRequest {
        url,
        accept: "application/json",
        bearer: None,
        form: vec![
            (
                "grant_type",
                Zeroizing::new("authorization_code".to_owned()),
            ),
            ("client_id", Zeroizing::new(credentials.client_id.clone())),
            (
                "client_secret",
                Zeroizing::new(credentials.client_secret.as_str().to_owned()),
            ),
            ("code", Zeroizing::new(code.to_owned())),
            ("code_verifier", Zeroizing::new(code_verifier.to_owned())),
            ("redirect_uri", Zeroizing::new(redirect_uri.to_owned())),
        ],
    }
}

async fn json_call<T: serde::de::DeserializeOwned>(
    upstream: &dyn OAuthUpstream,
    request: UpstreamRequest,
) -> Result<T, IdentityError> {
    let response = upstream
        .execute(request)
        .await
        .map_err(|_| IdentityError::Upstream)?;
    if !(200..300).contains(&response.status) {
        return Err(IdentityError::Upstream);
    }
    if response.body.len() > MAX_UPSTREAM_RESPONSE_BYTES {
        return Err(IdentityError::Upstream);
    }
    serde_json::from_slice(&response.body).map_err(|_| IdentityError::Invalid)
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<Zeroizing<String>>,
    #[serde(default)]
    id_token: Option<Zeroizing<String>>,
    /// GitHub answers a refused exchange with 200 and an `error` field.
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

async fn github_identity(
    upstream: &dyn OAuthUpstream,
    credentials: &ClientCredentials,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<ProviderIdentity, IdentityError> {
    let token: TokenResponse = json_call(
        upstream,
        token_request(
            GITHUB_TOKEN_URL,
            credentials,
            code,
            code_verifier,
            redirect_uri,
        ),
    )
    .await?;
    if token.error.is_some() {
        return Err(IdentityError::Upstream);
    }
    let access_token = token.access_token.ok_or(IdentityError::Invalid)?;
    let api = |url: &'static str| UpstreamRequest {
        url,
        accept: "application/vnd.github+json",
        bearer: Some(access_token.clone()),
        form: Vec::new(),
    };
    let user: GitHubUser = json_call(upstream, api(GITHUB_USER_URL)).await?;
    let emails: Vec<GitHubEmail> = json_call(upstream, api(GITHUB_EMAILS_URL)).await?;
    if user.id == 0 {
        return Err(IdentityError::Invalid);
    }
    // Only the primary address, and only when GitHub verified it.
    let primary = emails
        .into_iter()
        .find(|email| email.primary)
        .ok_or(IdentityError::UnverifiedEmail)?;
    if !primary.verified {
        return Err(IdentityError::UnverifiedEmail);
    }
    let email = valid_email(primary.email)?;
    // GitHub logins are 1-39 ASCII letters, digits and hyphens; anything else
    // is not shown as one.
    let login = user.login.filter(|login| {
        (1..=39).contains(&login.len())
            && login
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    let account = login.clone().unwrap_or_else(|| email.clone());
    let name = user
        .name
        .filter(|name| !name.trim().is_empty())
        .or(login)
        .and_then(display_name);
    Ok(ProviderIdentity {
        subject: user.id.to_string(),
        email,
        name,
        hosted_domain: None,
        account,
    })
}

/// The claims Codewire reads from a Google ID token.
#[derive(Deserialize)]
struct GoogleClaims {
    iss: String,
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<BoolOrString>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    hd: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BoolOrString {
    Bool(bool),
    String(String),
}

impl BoolOrString {
    fn is_true(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::String(value) => value == "true",
        }
    }
}

async fn google_identity(
    upstream: &dyn OAuthUpstream,
    credentials: &ClientCredentials,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    nonce: &str,
) -> Result<ProviderIdentity, IdentityError> {
    let token: TokenResponse = json_call(
        upstream,
        token_request(
            GOOGLE_TOKEN_URL,
            credentials,
            code,
            code_verifier,
            redirect_uri,
        ),
    )
    .await?;
    if token.error.is_some() {
        return Err(IdentityError::Upstream);
    }
    let id_token = token.id_token.ok_or(IdentityError::Invalid)?;
    let claims = google_claims(&id_token)?;
    check_google_claims(
        &claims,
        &credentials.client_id,
        nonce,
        chrono::Utc::now().timestamp(),
    )?;
    let email = valid_email(claims.email.ok_or(IdentityError::UnverifiedEmail)?)?;
    let subject = claims.sub;
    if subject.is_empty() || subject.len() > MAX_SUBJECT_BYTES {
        return Err(IdentityError::Invalid);
    }
    Ok(ProviderIdentity {
        subject,
        account: email.clone(),
        email,
        name: claims.name.and_then(display_name),
        hosted_domain: claims
            .hd
            .filter(|hd| !hd.is_empty() && hd.len() <= MAX_EMAIL_BYTES),
    })
}

/// Decode the payload of an ID token received straight from Google's token
/// endpoint. That TLS response authenticates the issuer, so OpenID Connect
/// Core's ID token validation rules let the client skip the signature (the
/// authorization code flow, step 6); every claim below is still checked.
fn google_claims(id_token: &str) -> Result<GoogleClaims, IdentityError> {
    let mut parts = id_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IdentityError::Invalid);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| IdentityError::Invalid)?;
    serde_json::from_slice(&bytes).map_err(|_| IdentityError::Invalid)
}

fn check_google_claims(
    claims: &GoogleClaims,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<(), IdentityError> {
    if !GOOGLE_ISSUERS.contains(&claims.iss.as_str()) {
        return Err(IdentityError::Invalid);
    }
    let audience_ok = match &claims.aud {
        Audience::One(audience) => audience == client_id,
        Audience::Many(audiences) => {
            audiences.iter().any(|audience| audience == client_id)
                && claims.azp.as_deref() == Some(client_id)
        }
    };
    if !audience_ok {
        return Err(IdentityError::Invalid);
    }
    if claims.exp + EXPIRY_LEEWAY_SECS <= now {
        return Err(IdentityError::Invalid);
    }
    let nonce_ok = claims
        .nonce
        .as_deref()
        .is_some_and(|claimed| crate::oauth::same_secret(claimed.as_bytes(), nonce.as_bytes()));
    if !nonce_ok {
        return Err(IdentityError::Invalid);
    }
    if !claims
        .email_verified
        .as_ref()
        .is_some_and(BoolOrString::is_true)
    {
        return Err(IdentityError::UnverifiedEmail);
    }
    Ok(())
}

fn valid_email(email: String) -> Result<String, IdentityError> {
    let email = email.trim().to_owned();
    let well_formed = email.len() <= MAX_EMAIL_BYTES
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
        && !email
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    if well_formed {
        Ok(email)
    } else {
        Err(IdentityError::Invalid)
    }
}

fn display_name(name: String) -> Option<String> {
    let name: String = name
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(values: &[(&str, &str)]) -> impl FnMut(&str) -> Option<String> {
        let values: Vec<(String, String)> = values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            values
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn providers_are_off_when_unset_and_on_with_both_values() {
        let none = OAuthProviders::from_values(lookup(&[])).unwrap();
        assert!(none.configured().is_empty());

        let blank = OAuthProviders::from_values(lookup(&[
            ("CODEWIRE_OAUTH_GITHUB_CLIENT_ID", " "),
            ("CODEWIRE_OAUTH_GITHUB_CLIENT_SECRET", ""),
        ]))
        .unwrap();
        assert!(blank.configured().is_empty());

        let both = OAuthProviders::from_values(lookup(&[
            ("CODEWIRE_OAUTH_GITHUB_CLIENT_ID", "github-client"),
            (
                "CODEWIRE_OAUTH_GITHUB_CLIENT_SECRET",
                "github-secret-marker",
            ),
            ("CODEWIRE_OAUTH_GOOGLE_CLIENT_ID", "google-client"),
            (
                "CODEWIRE_OAUTH_GOOGLE_CLIENT_SECRET",
                "google-secret-marker",
            ),
        ]))
        .unwrap();
        assert_eq!(both.configured(), [Provider::GitHub, Provider::Google]);

        let google_only = OAuthProviders::from_values(lookup(&[
            ("CODEWIRE_OAUTH_GOOGLE_CLIENT_ID", "google-client"),
            (
                "CODEWIRE_OAUTH_GOOGLE_CLIENT_SECRET",
                "google-secret-marker",
            ),
        ]))
        .unwrap();
        assert_eq!(google_only.configured(), [Provider::Google]);
    }

    #[test]
    fn half_a_pair_stops_configuration_without_printing_values() {
        for values in [
            [("CODEWIRE_OAUTH_GITHUB_CLIENT_ID", "github-client-marker")],
            [(
                "CODEWIRE_OAUTH_GOOGLE_CLIENT_SECRET",
                "google-secret-marker",
            )],
        ] {
            let error = OAuthProviders::from_values(lookup(&values)).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("must both be set or both be unset"));
            assert!(!message.contains("marker"));
        }
    }

    #[test]
    fn debug_never_prints_client_secrets() {
        let providers = OAuthProviders::from_values(lookup(&[
            ("CODEWIRE_OAUTH_GITHUB_CLIENT_ID", "github-client"),
            (
                "CODEWIRE_OAUTH_GITHUB_CLIENT_SECRET",
                "github-secret-marker",
            ),
        ]))
        .unwrap();
        let debug = format!("{providers:?}");
        assert!(!debug.contains("github-secret-marker"));
        assert!(debug.contains("[REDACTED]"));

        let request = token_request(
            GITHUB_TOKEN_URL,
            providers.credentials(Provider::GitHub).unwrap(),
            "code-marker",
            "verifier-marker",
            "https://app.example/cb",
        );
        let debug = format!("{request:?}");
        for marker in ["github-secret-marker", "code-marker", "verifier-marker"] {
            assert!(!debug.contains(marker));
        }
    }

    #[test]
    fn authorize_urls_carry_state_pkce_and_the_agreed_scopes() {
        let providers = OAuthProviders::with_upstream(
            Some(("github-client", "s")),
            Some(("google-client", "s")),
            Arc::new(ReqwestUpstream::new()),
        );
        let github = providers
            .authorize_url(
                Provider::GitHub,
                "https://app.example/api/auth/oauth/github/callback",
                "state-value",
                "challenge-value",
                None,
            )
            .unwrap();
        let github = reqwest::Url::parse(&github).unwrap();
        assert_eq!(github.host_str(), Some("github.com"));
        let pairs: Vec<(String, String)> = github.query_pairs().into_owned().collect();
        for (name, value) in [
            ("client_id", "github-client"),
            ("state", "state-value"),
            ("code_challenge", "challenge-value"),
            ("code_challenge_method", "S256"),
            ("scope", "read:user user:email"),
            (
                "redirect_uri",
                "https://app.example/api/auth/oauth/github/callback",
            ),
        ] {
            assert!(
                pairs.contains(&(name.to_owned(), value.to_owned())),
                "{name}"
            );
        }

        let google = providers
            .authorize_url(
                Provider::Google,
                "https://app.example/api/auth/oauth/google/callback",
                "state-value",
                "challenge-value",
                Some("nonce-value"),
            )
            .unwrap();
        let google = reqwest::Url::parse(&google).unwrap();
        assert_eq!(google.host_str(), Some("accounts.google.com"));
        let pairs: Vec<(String, String)> = google.query_pairs().into_owned().collect();
        for (name, value) in [
            ("response_type", "code"),
            ("scope", "openid email profile"),
            ("nonce", "nonce-value"),
            ("code_challenge_method", "S256"),
        ] {
            assert!(
                pairs.contains(&(name.to_owned(), value.to_owned())),
                "{name}"
            );
        }
        // Google needs its nonce.
        assert!(
            providers
                .authorize_url(Provider::Google, "https://x/cb", "s", "c", None)
                .is_none()
        );
    }

    fn claims(json: serde_json::Value) -> GoogleClaims {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn google_claims_check_issuer_audience_expiry_nonce_and_verified_email() {
        let now = 1_800_000_000;
        let good = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "google-client",
            "exp": now + 300,
            "nonce": "expected-nonce",
            "sub": "1234",
            "email": "person@example.test",
            "email_verified": true,
        });
        assert!(
            check_google_claims(
                &claims(good.clone()),
                "google-client",
                "expected-nonce",
                now
            )
            .is_ok()
        );

        let with = |field: &str, value: serde_json::Value| {
            let mut changed = good.clone();
            changed[field] = value;
            claims(changed)
        };
        for (field, value, expected) in [
            (
                "iss",
                serde_json::json!("https://evil.example"),
                IdentityError::Invalid,
            ),
            (
                "aud",
                serde_json::json!("other-client"),
                IdentityError::Invalid,
            ),
            ("exp", serde_json::json!(now - 120), IdentityError::Invalid),
            (
                "nonce",
                serde_json::json!("other-nonce"),
                IdentityError::Invalid,
            ),
            (
                "email_verified",
                serde_json::json!(false),
                IdentityError::UnverifiedEmail,
            ),
        ] {
            assert_eq!(
                check_google_claims(&with(field, value), "google-client", "expected-nonce", now),
                Err(expected),
                "{field}"
            );
        }
        // A token without a nonce is refused.
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("nonce");
        assert_eq!(
            check_google_claims(&claims(missing), "google-client", "expected-nonce", now),
            Err(IdentityError::Invalid)
        );
        // Several audiences need this client as the authorized party.
        let many = with("aud", serde_json::json!(["google-client", "other"]));
        assert_eq!(
            check_google_claims(&many, "google-client", "expected-nonce", now),
            Err(IdentityError::Invalid)
        );
    }

    #[test]
    fn only_google_vouches_for_gmail_and_its_hosted_domains() {
        let identity = |email: &str, hd: Option<&str>| ProviderIdentity {
            subject: "1".into(),
            email: email.into(),
            name: None,
            hosted_domain: hd.map(str::to_owned),
            account: email.into(),
        };
        assert!(identity("ada@gmail.com", None).provider_owns_email(Provider::Google));
        assert!(identity("ada@GMail.com", None).provider_owns_email(Provider::Google));
        assert!(
            identity("ada@corp.example", Some("corp.example"))
                .provider_owns_email(Provider::Google)
        );
        assert!(
            identity("ada@Corp.Example", Some("corp.example"))
                .provider_owns_email(Provider::Google)
        );
        for (email, hd) in [
            ("ada@corp.example", None),
            ("ada@corp.example", Some("other.example")),
            ("ada@sub.corp.example", Some("corp.example")),
            ("ada@googlemail.com", None),
            ("ada@gmail.com.evil.example", None),
        ] {
            assert!(
                !identity(email, hd).provider_owns_email(Provider::Google),
                "{email} {hd:?}"
            );
        }
        assert!(!identity("ada@gmail.com", None).provider_owns_email(Provider::GitHub));
    }

    #[test]
    fn id_token_payloads_decode_only_from_three_parts() {
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "accounts.google.com", "aud": "c", "exp": 1, "sub": "s"
            })
            .to_string(),
        );
        assert!(google_claims(&format!("h.{payload}.s")).is_ok());
        assert!(google_claims(&format!("h.{payload}")).is_err());
        assert!(google_claims(&format!("h.{payload}.s.x")).is_err());
        assert!(google_claims("h.not base64.s").is_err());
    }
}
