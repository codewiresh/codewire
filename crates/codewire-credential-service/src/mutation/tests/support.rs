//! Real generated Connect mount, restricted LOGIN, and synthetic local login.

use super::*;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use base64::Engine as _;
use codewire_credential_broker::codex_enrollment::{CodexEnrollmentConfig, CodexEnrollmentOwner};
use codewire_credential_broker::github_enrollment::{
    GitHubEnrollmentConfig, GitHubEnrollmentOwner,
};
use codewire_server_core::auth::{
    AuthState, SESSION_COOKIE_NAME, hash_api_key, hash_oauth_token, hash_session_token,
};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router_with_auth};
use reqwest::{Client, Response, StatusCode};
use tempfile::TempDir;
use tokio::task::JoinHandle;

pub const ALICE: &str = "mutation-alice";
pub const BOB: &str = "mutation-bob";
pub const CLIENT: &str = "mutation-client";
pub const ACCESS: &str = "private-mutation-access-canary";
pub const REFRESH: &str = "private-mutation-refresh-canary";
pub const SESSION: &str = "private-mutation-session-canary";
pub const API_KEY_MATERIAL: &str = "private-api-key-material-canary";
pub const GITHUB_TOKEN: &str = "gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SERVICE: &str = "codewire.v1.CredentialMutationService";
const SHELL: &str = include_str!(
    "../../../../codewire-credential-broker/src/codex_enrollment/tests/synthetic-codex.sh"
);
const GITHUB_SHELL: &str = include_str!(
    "../../../../codewire-credential-broker/src/github_enrollment/tests/synthetic-gh.sh"
);

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
    root: TempDir,
    _executable: TempDir,
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
            let root = tempfile::Builder::new().prefix("cw-mutation-synthetic-").tempdir_in("/dev/shm")?;
            std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(0o700))?;
            let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
                "email":"person@example.test", "https://api.openai.com/auth":{"chatgpt_account_id":"synthetic-account"}
            }))?);
            let auth = serde_json::to_vec(&json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,
                "tokens":{"id_token":format!("e30.{id_payload}.c2ln"),"access_token":ACCESS,
                "refresh_token":REFRESH,"account_id":"synthetic-account"}}))?;
            std::fs::write(root.path().join("synthetic-auth.fixture.json"),auth)?;
            // Executable TMPDIR is a documented local fixture input. Secret
            // staging itself must be owned tmpfs; there is no persistent fallback.
            let executable = tempfile::Builder::new().prefix("cw-mutation-executable-").tempdir()?;
            let script = executable.path().join("codex");
            let gate = "#!/bin/sh\nset -eu\nfixture_root=${CODEX_HOME%/*}\nif [ \"${1-}\" = login ]; then\n  printf '%s\\n' \"$$\" > \"$fixture_root/before-challenge.pid\"\n  while [ -f \"$fixture_root/hold-before-challenge\" ]; do sleep 0.02; done\nfi\n";
            std::fs::write(&script,format!("{gate}{}",SHELL.strip_prefix("#!/bin/sh\n").context("pinned shell fixture header")?))?;
            std::fs::set_permissions(&script,std::fs::Permissions::from_mode(0o700))?;
            let enrollment = CodexEnrollmentOwner::new(CodexEnrollmentConfig::new(script,root.path().to_owned(),OsString::from("/usr/bin:/bin"))
                .map_err(|_|anyhow::anyhow!("synthetic enrollment configuration"))?);
            let github_script = executable.path().join("gh");
            std::fs::write(&github_script, GITHUB_SHELL)?;
            std::fs::set_permissions(&github_script,std::fs::Permissions::from_mode(0o700))?;
            let github_token = GITHUB_TOKEN;
            std::fs::write(root.path().join("hosts.fixture.yml"), format!("github.com:\n    users:\n        synthetic-user:\n            oauth_token: {github_token}\n    git_protocol: https\n    oauth_token: {github_token}\n    user: synthetic-user\n"))?;
            let github = GitHubEnrollmentOwner::new(GitHubEnrollmentConfig::new(github_script,root.path().to_owned(),OsString::from("/usr/bin:/bin"))
                .map_err(|_|anyhow::anyhow!("synthetic GitHub enrollment configuration"))?);
            let provider = Arc::new(SyntheticKek::default());
            let store = Arc::new(PlatformCredentialStore::new(pool.clone(),provider.clone(),builtin_provider_catalog()));
            let owner = Arc::new(CredentialMutationOwner::new(pool.clone(),store.clone(),enrollment,github));
            let rpc = Rpc {client:Client::builder().no_proxy().timeout(TIMEOUT).build()?,url:format!("http://{address}")};
            let server = listener.map(|listener| {
                let app = connect_router_with_auth(owner.router(),ConnectAuthLayer::credential_mutation(AuthState{pool:pool.clone()},http::HeaderValue::from_static("https://codewire.example")));
                let (stop,stopped) = oneshot::channel();
                let server = tokio::spawn(async move {
                    axum::serve(listener,app).with_graceful_shutdown(async {let _=stopped.await;}).await
                });
                (stop,server)
            });
            Ok::<_,anyhow::Error>((pool,role,provider,store,owner,root,executable,server,rpc))
        }.await;
        match setup {
            Ok((pool, role, provider, store, owner, root, executable, server, rpc)) => Ok(Self {
                db,
                pool,
                role,
                provider,
                store,
                owner,
                rpc,
                root,
                _executable: executable,
                server,
            }),
            Err(error) => {
                db.finish(Err(error)).await?;
                unreachable!("fixture setup failed")
            }
        }
    }

    pub fn control(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
    pub fn release(&self) -> Result<()> {
        Ok(std::fs::write(
            self.control("release"),
            b"synthetic release",
        )?)
    }
    pub fn hold_challenge(&self) -> Result<()> {
        Ok(std::fs::write(
            self.control("hold-before-challenge"),
            b"synthetic gate",
        )?)
    }
    pub fn logged_out(&self) -> bool {
        self.control("logout.called").exists()
    }

    pub async fn wait_file(&self, name: &str) -> Result<()> {
        tokio::time::timeout(TIMEOUT, async {
            while !self.control(name).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("synthetic Codex did not reach its file barrier")?;
        Ok(())
    }

    pub async fn drained(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let homes =
                    std::fs::read_dir(self.root.path())?.collect::<std::io::Result<Vec<_>>>()?;
                if self.owner.workers.is_empty()
                    && !homes.iter().any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".codewire-provider-login-")
                    })
                {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("mutation/provider owner did not drain")??;
        Ok(())
    }

    pub async fn reset_login(&self) -> Result<()> {
        self.drained().await?;
        for name in [
            "release",
            "logout.called",
            "wrapper.pid",
            "native.pid",
            "native.finished",
            "before-challenge.pid",
            "hold-before-challenge",
        ] {
            match std::fs::remove_file(self.control(name)) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        // Distinct device logins mint distinct synthetic credentials, including
        // a rejected duplicate-name enrollment. They must not alias the first
        // successful login whose protected bytes remain stored.
        let path = self.control("synthetic-auth.fixture.json");
        let mut auth: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        auth["tokens"]["access_token"] = json!(format!("{ACCESS}-{suffix}"));
        auth["tokens"]["refresh_token"] = json!(format!("{REFRESH}-{suffix}"));
        std::fs::write(path, serde_json::to_vec(&auth)?)?;
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
