//! Real generated Connect mount, restricted LOGIN, and a synthetic in-process
//! provider for the native device logins.

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use async_trait::async_trait;
use base64::Engine as _;
use codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig;
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};
use codewire_server_core::auth::{
    AuthState, SESSION_COOKIE_NAME, hash_api_key, hash_oauth_token, hash_session_token,
};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router_with_auth};
use reqwest::{Client, Response, StatusCode};
use tokio::task::JoinHandle;

pub const ALICE: &str = "mutation-alice";
pub const BOB: &str = "mutation-bob";
pub const CLIENT: &str = "mutation-client";
pub const ACCESS: &str = "private-mutation-access-canary";
pub const REFRESH: &str = "private-mutation-refresh-canary";
pub const SESSION: &str = "private-mutation-session-canary";
pub const API_KEY_MATERIAL: &str = "private-api-key-material-canary";
pub const GITHUB_TOKEN: &str = "ghu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const USER_CODE: &str = "ABCD-EFGH";
/// The one code the synthetic Claude token endpoint redeems.
pub const CLAUDE_CODE: &str = "synthetic-claude-code";
const GITHUB_APP_SLUG: &str = "codewire-synthetic";
const SERVICE: &str = "codewire.v1.CredentialMutationService";

/// The provider side of both device logins. A test holds the first request,
/// approves the code, and gives each login distinct tokens; nothing runs
/// outside this process.
#[derive(Default)]
pub struct DeviceProvider {
    hold: AtomicBool,
    released: tokio::sync::Notify,
    approved: AtomicBool,
    started: AtomicUsize,
    suffix: Mutex<String>,
    claude_exchanges: AtomicUsize,
}

impl DeviceProvider {
    /// Device logins started (user or device code requested).
    pub fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    /// Claude code exchanges received.
    pub fn claude_exchanges(&self) -> usize {
        self.claude_exchanges.load(Ordering::SeqCst)
    }

    fn answer(&self, target: &str, body: &[u8]) -> Option<(http::StatusCode, Value)> {
        let suffix = self.suffix.lock().unwrap().clone();
        let approved = self.approved.load(Ordering::SeqCst);
        Some(match target {
            "https://auth.openai.com/api/accounts/deviceauth/usercode" => (
                http::StatusCode::OK,
                json!({"device_auth_id":"synthetic-device-auth","user_code":USER_CODE,"interval":"1"}),
            ),
            "https://auth.openai.com/api/accounts/deviceauth/token" if approved => (
                http::StatusCode::OK,
                json!({"authorization_code":"synthetic-code","code_challenge":"synthetic-challenge",
                    "code_verifier":"synthetic-verifier"}),
            ),
            "https://auth.openai.com/api/accounts/deviceauth/token" => {
                (http::StatusCode::FORBIDDEN, json!({}))
            }
            "https://auth.openai.com/oauth/token" => {
                let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&json!({"email":"person@example.test",
                        "https://api.openai.com/auth":{"chatgpt_account_id":"synthetic-account"}}))
                    .ok()?,
                );
                (
                    http::StatusCode::OK,
                    json!({"id_token":format!("e30.{id_payload}.c2ln"),
                        "access_token":format!("{ACCESS}{suffix}"),
                        "refresh_token":format!("{REFRESH}{suffix}")}),
                )
            }
            "https://github.com/login/device/code" => (
                http::StatusCode::OK,
                json!({"device_code":"synthetic-device-code","user_code":USER_CODE,
                    "verification_uri":"https://github.com/login/device","expires_in":900,"interval":1}),
            ),
            "https://github.com/login/oauth/access_token" if approved => (
                http::StatusCode::OK,
                json!({"access_token":GITHUB_TOKEN,"token_type":"bearer"}),
            ),
            "https://github.com/login/oauth/access_token" => (
                http::StatusCode::OK,
                json!({"error":"authorization_pending"}),
            ),
            "https://api.github.com/user" => (
                http::StatusCode::OK,
                json!({"id":7,"login":"synthetic-user"}),
            ),
            "https://api.github.com/user/installations?per_page=100&page=1" => (
                http::StatusCode::OK,
                json!({"installations":[{"id":41,"app_slug":GITHUB_APP_SLUG}]}),
            ),
            // Claude redeems only its synthetic code, with a verifier, for
            // Claude Code's client and manual redirect.
            "https://platform.claude.com/v1/oauth/token" => {
                let request: Value = serde_json::from_slice(body).ok()?;
                if request["grant_type"] == "authorization_code"
                    && request["code"] == CLAUDE_CODE
                    && request["client_id"] == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
                    && request["redirect_uri"] == "https://platform.claude.com/oauth/code/callback"
                    && request["code_verifier"].as_str().is_some_and(|v| v.len() == 43)
                    && request["state"].as_str().is_some_and(|v| v.len() == 43)
                {
                    (
                        http::StatusCode::OK,
                        json!({"token_type":"Bearer",
                            "access_token":format!("{ACCESS}{suffix}"),
                            "refresh_token":format!("{REFRESH}{suffix}"),
                            "expires_in":28_800,
                            "scope":"user:profile user:inference user:sessions:claude_code"}),
                    )
                } else {
                    (
                        http::StatusCode::BAD_REQUEST,
                        json!({"error":"invalid_grant"}),
                    )
                }
            }
            "https://api.anthropic.com/api/oauth/profile" => (
                http::StatusCode::OK,
                json!({"account":{"uuid":"synthetic-account","email":"person@example.test"},
                    "organization":{"uuid":"synthetic-organization",
                        "organization_type":"claude_max",
                        "rate_limit_tier":"default_claude_max_20x"}}),
            ),
            _ => return None,
        })
        .filter(|_| body.len() <= 64 * 1024)
    }
}

#[async_trait]
impl BrokerUpstreamTransport for DeviceProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_method, target, _headers, body) = request.into_parts();
        if target.as_str() == "https://platform.claude.com/v1/oauth/token" {
            self.claude_exchanges.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(
            target.as_str(),
            "https://auth.openai.com/api/accounts/deviceauth/usercode"
                | "https://github.com/login/device/code"
        ) {
            self.started.fetch_add(1, Ordering::SeqCst);
            while self.hold.load(Ordering::SeqCst) {
                let released = self.released.notified();
                if !self.hold.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
        }
        let (status, value) = self
            .answer(target.as_str(), &body)
            .ok_or(BrokerUpstreamError::Protocol)?;
        let body = serde_json::to_vec(&value).map_err(|_| BrokerUpstreamError::Protocol)?;
        Ok(BrokerUpstreamResponse::new(
            status,
            http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move { Ok(body.into()) })),
        ))
    }
}

pub fn oauth(user: &str) -> String {
    format!("private-mutation-oauth-{user}")
}

pub fn api_key() -> String {
    format!("cw_{}", "0123456789abcdef".repeat(4))
}

#[derive(Clone, Copy)]
pub enum Auth {
    Alice,
    Bob,
    Cookie,
    CookieWrongOrigin,
    ApiKey,
    Missing,
}

impl Auth {
    pub fn denial_code(self) -> &'static str {
        if matches!(self, Self::CookieWrongOrigin) {
            "permission_denied"
        } else {
            "unauthenticated"
        }
    }
}

fn authenticate(request: reqwest::RequestBuilder, auth: Auth) -> reqwest::RequestBuilder {
    match auth {
        Auth::Alice => request.bearer_auth(oauth(ALICE)),
        Auth::Bob => request.bearer_auth(oauth(BOB)),
        Auth::Cookie => request
            .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
            .header("origin", "https://codewire.example"),
        Auth::CookieWrongOrigin => request
            .header("cookie", format!("{SESSION_COOKIE_NAME}={SESSION}"))
            .header("origin", "https://attacker.example"),
        Auth::ApiKey => request.bearer_auth(api_key()),
        Auth::Missing => request,
    }
}

pub fn blind(value: &Value) -> Result<()> {
    let bytes = value.to_string();
    for canary in [
        ACCESS,
        REFRESH,
        SESSION,
        API_KEY_MATERIAL,
        GITHUB_TOKEN,
        &oauth(ALICE),
        &oauth(BOB),
        &api_key(),
        "synthetic stderr",
        "synthetic private log",
        "synthetic-platform-broker-test-only",
    ] {
        ensure!(
            !bytes.contains(canary),
            "private fixture input entered public wire output"
        );
    }
    Ok(())
}

pub struct ConnectStream {
    response: Response,
    buffer: Vec<u8>,
    terminal: bool,
}

impl ConnectStream {
    pub async fn next(&mut self) -> Result<Option<Value>> {
        if self.terminal {
            return Ok(None);
        }
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if self.buffer.len() >= 5 {
                let flags = self.buffer[0];
                ensure!(
                    flags == 0 || flags == 2,
                    "unsupported Connect envelope flags"
                );
                let size = u32::from_be_bytes(self.buffer[1..5].try_into()?) as usize;
                ensure!(size <= 64 * 1024, "unbounded Connect envelope");
                if self.buffer.len() >= size + 5 {
                    let payload: Value = serde_json::from_slice(&self.buffer[5..size + 5])?;
                    self.buffer.drain(..size + 5);
                    blind(&payload)?;
                    if flags == 2 {
                        self.terminal = true;
                    }
                    return Ok(Some(payload));
                }
            }
            let chunk = tokio::time::timeout_at(deadline, self.response.chunk())
                .await
                .context("bounded generated Connect response")??;
            match chunk {
                Some(chunk) => {
                    ensure!(
                        self.buffer.len() + chunk.len() <= 128 * 1024,
                        "unbounded Connect buffer"
                    );
                    self.buffer.extend_from_slice(&chunk);
                }
                None => anyhow::bail!("Connect stream ended without its terminal envelope"),
            }
        }
    }

    pub async fn challenge(&mut self) -> Result<Value> {
        let value = self.next().await?.context("missing challenge")?;
        ensure!(value["challenge"]["verificationUrl"] == "https://auth.openai.com/codex/device");
        ensure!(value["challenge"]["userCode"] == "ABCD-EFGH");
        ensure!(value.get("credential").is_none());
        Ok(value["challenge"].clone())
    }

    pub async fn committed(&mut self) -> Result<Value> {
        let value = self.next().await?.context("missing committed metadata")?;
        let credential = value
            .get("credential")
            .context("missing committed credential")?
            .clone();
        ensure!(
            self.next().await? == Some(json!({})),
            "unsuccessful terminal envelope"
        );
        ensure!(self.next().await?.is_none());
        Ok(credential)
    }

    pub async fn error(&mut self, code: &str) -> Result<()> {
        let value = self.next().await?.context("missing terminal error")?;
        ensure!(
            value["error"]["code"] == code,
            "unexpected closed Connect error: {value}"
        );
        ensure!(self.terminal && self.next().await?.is_none());
        Ok(())
    }
}

#[derive(Clone)]
pub struct Rpc {
    client: Client,
    url: String,
}

impl Rpc {
    pub async fn update(
        &self,
        method: &str,
        auth: Auth,
        body: Value,
    ) -> Result<(StatusCode, Value)> {
        let request = self
            .client
            .post(format!("{}/{SERVICE}/{method}", self.url))
            .header("connect-protocol-version", "1")
            .json(&body);
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        Ok((status, value))
    }

    pub async fn ssh(&self, method: &str, auth: Auth, body: Value) -> Result<(StatusCode, Value)> {
        let request = self
            .client
            .post(format!("{}/{SERVICE}/{method}", self.url))
            .header("connect-protocol-version", "1")
            .json(&body);
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        Ok((status, value))
    }

    async fn enrollment_response(&self, auth: Auth, request: Value) -> Result<Response> {
        self.enrollment_response_for("EnrollCodex", auth, request)
            .await
    }

    async fn enrollment_response_for(
        &self,
        method: &str,
        auth: Auth,
        request: Value,
    ) -> Result<Response> {
        let body = serde_json::to_vec(&request)?;
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        frame.extend_from_slice(&body);
        let request = self
            .client
            .post(format!("{}/{SERVICE}/{method}", self.url))
            .header("connect-protocol-version", "1")
            .header("content-type", "application/connect+json")
            .body(frame);
        Ok(tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??)
    }

    pub async fn enroll(&self, auth: Auth, name: &str) -> Result<ConnectStream> {
        self.enroll_request(auth, json!({"name": name})).await
    }

    pub async fn enroll_request(&self, auth: Auth, request: Value) -> Result<ConnectStream> {
        let response = self.enrollment_response(auth, request).await?;
        self.enrollment_stream(response)
    }

    pub async fn enroll_github_request(&self, auth: Auth, request: Value) -> Result<ConnectStream> {
        let response = self
            .enrollment_response_for("EnrollGithub", auth, request)
            .await?;
        self.enrollment_stream(response)
    }

    fn enrollment_stream(&self, response: Response) -> Result<ConnectStream> {
        ensure!(
            response.status() == StatusCode::OK,
            "enrollment headers denied"
        );
        ensure!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|value| value.starts_with("application/connect+json"))
        );
        Ok(ConnectStream {
            response,
            buffer: Vec::new(),
            terminal: false,
        })
    }

    pub async fn add_api_key(
        &self,
        auth: Auth,
        provider: &str,
        name: &str,
        material: &[u8],
        expiry: Option<u64>,
    ) -> Result<(StatusCode, Value)> {
        let mut body = json!({"provider":provider,"name":name,
            "value":base64::engine::general_purpose::STANDARD.encode(material)});
        if let Some(expiry) = expiry {
            body["expiresAtUnix"] = json!(expiry.to_string());
        }
        let request = self
            .client
            .post(format!("{}/{SERVICE}/AddApiKeyCredential", self.url))
            .header("connect-protocol-version", "1")
            .json(&body);
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        Ok((status, value))
    }

    /// The JSON Connect form of AddClaudeSubscriptionTokenCredential. `body`
    /// carries every field except the base64 token.
    pub async fn add_claude_subscription_token(
        &self,
        auth: Auth,
        mut body: Value,
        token: &[u8],
    ) -> Result<(StatusCode, Value)> {
        body["token"] = json!(base64::engine::general_purpose::STANDARD.encode(token));
        let request = self
            .client
            .post(format!(
                "{}/{SERVICE}/AddClaudeSubscriptionTokenCredential",
                self.url
            ))
            .header("connect-protocol-version", "1")
            .json(&body);
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        let rendered = value.to_string();
        ensure!(
            token.is_empty()
                || !rendered
                    .as_bytes()
                    .windows(token.len())
                    .any(|window| window == token),
            "response echoed the subscription token"
        );
        Ok((status, value))
    }

    /// StartClaudeSignIn: the authorize URL's state and the opaque handle.
    pub async fn start_claude_sign_in(&self, auth: Auth) -> Result<(StatusCode, Value)> {
        let request = self
            .client
            .post(format!("{}/{SERVICE}/StartClaudeSignIn", self.url))
            .header("connect-protocol-version", "1")
            .json(&json!({}));
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        Ok((status, value))
    }

    /// CompleteClaudeSignIn. `body` carries every field except the base64
    /// pasted code.
    pub async fn complete_claude_sign_in(
        &self,
        auth: Auth,
        mut body: Value,
        pasted: &str,
    ) -> Result<(StatusCode, Value)> {
        body["authorizationCode"] =
            json!(base64::engine::general_purpose::STANDARD.encode(pasted.as_bytes()));
        let request = self
            .client
            .post(format!("{}/{SERVICE}/CompleteClaudeSignIn", self.url))
            .header("connect-protocol-version", "1")
            .json(&body);
        let response = tokio::time::timeout(TIMEOUT, authenticate(request, auth).send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        ensure!(
            !value.to_string().contains(CLAUDE_CODE),
            "response echoed the Claude code"
        );
        Ok((status, value))
    }

    pub async fn denied_enrollment(&self, auth: Auth) -> Result<()> {
        // Connect streaming errors retain HTTP 200 and reject in the first
        // END_STREAM envelope. A Challenge before this error must fail.
        self.enroll(auth, "must-not-start")
            .await?
            .error(auth.denial_code())
            .await
    }

    pub async fn lifecycle(
        &self,
        method: &str,
        auth: Auth,
        id: &str,
        revision: u64,
    ) -> Result<(StatusCode, Value)> {
        let response = tokio::time::timeout(TIMEOUT, authenticate(self.client
            .post(format!("{}/{SERVICE}/{method}", self.url))
            .header("connect-protocol-version", "1")
            .json(&json!({"credentialId":id,"expectedRevocationGeneration":revision.to_string()})),auth)
            .send()).await??;
        let status = response.status();
        let value: Value = response.json().await?;
        blind(&value)?;
        Ok((status, value))
    }

    pub async fn lifecycle_error(
        &self,
        method: &str,
        auth: Auth,
        id: &str,
        revision: u64,
        code: &str,
    ) -> Result<()> {
        let (status, value) = self.lifecycle(method, auth, id, revision).await?;
        ensure!(
            !status.is_success() && value["code"] == code,
            "unexpected lifecycle response: {value}"
        );
        Ok(())
    }
}

pub struct Harness {
    pub db: TestDatabase,
    pub pool: PgPool,
    pub role: String,
    pub provider: Arc<SyntheticKek>,
    pub store: Arc<PlatformCredentialStore>,
    pub owner: Arc<CredentialMutationOwner>,
    pub rpc: Rpc,
    pub device: Arc<DeviceProvider>,
    server: Option<(oneshot::Sender<()>, JoinHandle<std::io::Result<()>>)>,
}

impl Harness {
    pub async fn new() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        Self::build(Some(listener), address).await
    }

    /// The runtime tests mount this same owner in the real dual-listener
    /// runtime. Do not also start the mutation-only fixture server there.
    pub async fn unserved(address: SocketAddr) -> Result<Self> {
        Self::build(None, address).await
    }

    async fn build(listener: Option<tokio::net::TcpListener>, address: SocketAddr) -> Result<Self> {
        let db = TestDatabase::create().await?;
        let setup = async {
            seed(&db.pool).await?;
            let (pool,role) = db.broker_pool().await?;
            for grant in [
                "SELECT (id,is_admin,enabled) ON public.users",
                "SELECT (token_hash,user_id,client_id,scopes,expires_at) ON public.oidc_access_tokens",
                "SELECT (id,disabled) ON public.oidc_clients",
                "EXECUTE ON FUNCTION public.codewire_lock_oauth_bearer_authority(text,text,text,timestamptz)",
                "EXECUTE ON FUNCTION public.codewire_authenticate_credential_session(text)",
                "EXECUTE ON FUNCTION public.codewire_lock_credential_session_authority(text,text,text,timestamptz)",
            ] {
                sqlx::query(&format!("GRANT {grant} TO {}", quote_ident(&role))).execute(&db.pool).await?;
            }
            let device = Arc::new(DeviceProvider::default());
            let codex_login = CodexDeviceLogin::new(device.clone());
            let claude_sign_in = ClaudeSignIn::new(device.clone());
            let github_login = GitHubDeviceLogin::new(
                GitHubDeviceLoginConfig::new("Iv1.synthetic".into(), GITHUB_APP_SLUG.into())
                    .map_err(|_| anyhow::anyhow!("synthetic GitHub App configuration"))?,
                device.clone(),
            );
            let provider = Arc::new(SyntheticKek::default());
            let store = Arc::new(PlatformCredentialStore::new(pool.clone(),provider.clone(),builtin_provider_catalog()));
            let owner = Arc::new(CredentialMutationOwner::new(pool.clone(),store.clone(),codex_login,claude_sign_in,Some(github_login),None));
            let rpc = Rpc {client:Client::builder().no_proxy().timeout(TIMEOUT).build()?,url:format!("http://{address}")};
            let server = listener.map(|listener| {
                let app = connect_router_with_auth(owner.router(),ConnectAuthLayer::credential_mutation(AuthState{pool:pool.clone()},http::HeaderValue::from_static("https://codewire.example")));
                let (stop,stopped) = oneshot::channel();
                let server = tokio::spawn(async move {
                    axum::serve(listener,app).with_graceful_shutdown(async {let _=stopped.await;}).await
                });
                (stop,server)
            });
            Ok::<_,anyhow::Error>((pool,role,provider,store,owner,device,server,rpc))
        }.await;
        match setup {
            Ok((pool, role, provider, store, owner, device, server, rpc)) => Ok(Self {
                db,
                pool,
                role,
                provider,
                store,
                owner,
                rpc,
                device,
                server,
            }),
            Err(error) => {
                db.finish(Err(error)).await?;
                unreachable!("fixture setup failed")
            }
        }
    }

    /// Approve the device code: the next poll completes the login.
    pub fn release(&self) -> Result<()> {
        self.device.approved.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Hold every device login at its first provider request.
    pub fn hold_challenge(&self) -> Result<()> {
        self.device.hold.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn wait_started(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, async {
            while self.device.started() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("no device login reached the provider")?;
        Ok(())
    }

    pub async fn drained(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, async {
            while !self.owner.workers.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("mutation owner did not drain")?;
        Ok(())
    }

    pub async fn reset_login(&self) -> Result<()> {
        self.drained().await?;
        self.device.hold.store(false, Ordering::SeqCst);
        self.device.released.notify_waiters();
        self.device.approved.store(false, Ordering::SeqCst);
        self.device.started.store(0, Ordering::SeqCst);
        // Distinct device logins mint distinct synthetic credentials, including
        // a rejected duplicate-name enrollment. They must not alias the first
        // successful login whose protected bytes remain stored.
        *self.device.suffix.lock().unwrap() = format!("-{}", uuid::Uuid::new_v4().simple());
        Ok(())
    }

    pub async fn count(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM public.platform_credentials")
                .fetch_one(&self.db.pool)
                .await?,
        )
    }

    /// Test the retained real owner directly, after its listener has gone.
    /// Authentication is still the shared SQL-backed OAuth implementation.
    pub async fn assert_admission_closed(&self) -> Result<()> {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", oauth(ALICE)).parse()?);
        let auth = authenticate_headers_with_context(
            &AuthState {
                pool: self.pool.clone(),
            },
            &headers,
        )
        .await?;
        let authority = CredentialMutationAuthority::from(
            auth.oauth_bearer_authority()
                .context("synthetic OAuth authority")?
                .clone(),
        );
        ensure!(matches!(
            self.owner
                .enroll(authority, "closed-runtime".into(), None, None),
            Err(Error::Unavailable)
        ));
        Ok(())
    }

    pub async fn wait_shutdown_started(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, self.owner.stop.cancelled()).await?;
        Ok(())
    }

    pub async fn finish(self, result: Result<()>) -> Result<()> {
        self.provider.generate_gate.release();
        self.provider.unwrap_gate.release();
        let drain = match tokio::time::timeout(TIMEOUT, self.owner.shutdown()).await {
            Ok(result) => {
                result.map_err(|error| anyhow::anyhow!("closed mutation shutdown: {error:?}"))
            }
            Err(_) => Err(anyhow::anyhow!("bounded mutation shutdown elapsed")),
        };
        let stopped = if let Some((stop, mut server)) = self.server {
            let _ = stop.send(());
            match tokio::time::timeout(TIMEOUT, &mut server).await {
                Ok(result) => result
                    .context("Connect fixture join")
                    .and_then(|result| result.context("Connect fixture listener")),
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    Err(anyhow::anyhow!("Connect fixture shutdown deadline"))
                }
            }
        } else {
            Ok(())
        };
        self.pool.close().await;
        self.db.finish(result.and(drain).and(stopped)).await
    }
}

async fn seed(pool: &PgPool) -> Result<()> {
    for user in [ALICE, BOB] {
        sqlx::query("INSERT INTO users(id,email,is_admin) VALUES ($1,$2,true)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(pool)
            .await?;
    }
    sqlx::query(
        "INSERT INTO oidc_clients(id,name,application_type,auth_method,redirect_uris) \
        VALUES ($1,'Synthetic mutation client','native','none','{}')",
    )
    .bind(CLIENT)
    .execute(pool)
    .await?;
    for user in [ALICE, BOB] {
        sqlx::query(
            "INSERT INTO oidc_access_tokens(token_hash,client_id,user_id,scopes,expires_at) \
            VALUES ($1,$2,$3,ARRAY['codewire.api'],now()+interval '1 hour')",
        )
        .bind(hash_oauth_token(&oauth(user)))
        .bind(CLIENT)
        .bind(user)
        .execute(pool)
        .await?;
    }
    sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES ('mutation-session',$1,$2,now()+interval '1 hour')")
        .bind(ALICE).bind(hash_session_token(SESSION)).execute(pool).await?;
    sqlx::query("INSERT INTO organizations(id,name,slug,created_by) VALUES ('mutation-org','Synthetic','mutation-org',$1)")
        .bind(ALICE).execute(pool).await?;
    sqlx::query(
        "INSERT INTO api_keys(id,user_id,org_id,name,key_hash,key_prefix,scopes) \
        VALUES ('mutation-api-key',$1,'mutation-org','Synthetic',$2,$3,ARRAY['*'])",
    )
    .bind(ALICE)
    .bind(hash_api_key(&api_key()))
    .bind(&api_key()[3..11])
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn denied(pool: &PgPool, statement: &str) -> Result<()> {
    let result = sqlx::query(statement).execute(pool).await;
    let error = result
        .err()
        .context("restricted login unexpectedly gained authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501")
    );
    Ok(())
}

pub async fn blocked_by(pool: &PgPool, blocker: i32) -> Result<i32> {
    tokio::time::timeout(TIMEOUT,async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_catalog.pg_stat_activity \
                WHERE datname=current_database() AND $1=ANY(pg_catalog.pg_blocking_pids(pid)) LIMIT 1")
                .bind(blocker).fetch_optional(pool).await?;
            if let Some(pid)=pid {return Ok::<_,anyhow::Error>(pid);}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("publication did not reach exact SQL blocker")?
}
