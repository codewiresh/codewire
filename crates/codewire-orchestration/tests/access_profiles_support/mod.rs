//! Exact disposable databases, restricted logins and the real generated service.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use codewire_server_core::auth::{
    AuthState, SESSION_COOKIE_NAME, hash_api_key, hash_oauth_token, hash_session_token,
};
use codewire_server_core::connect::{ConnectAuthLayer, connect_unary_router_with_auth};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{sync::oneshot, task::JoinHandle};

/// Bounds a wait that ends on its event, and replaces the service's
/// five-second response bound and statement ceiling on `Harness::rpc`. It
/// only turns a hang into a failure; a stalled CI slot spent the 5 s bounds
/// (#3310).
pub const HANG: Duration = Duration::from_secs(60);
pub const ALICE: &str = "synthetic-alice";
pub const BOB: &str = "synthetic-bob";
pub const ORG: &str = "synthetic-org";
pub const ENV: &str = "synthetic-environment";
pub const CREDENTIAL: &str = "synthetic-alice-codex";
pub const OTHER_CREDENTIAL: &str = "synthetic-bob-codex";
const PASSWORD: &str = "synthetic-profile-login-test-only";
const SERVICE: &str = "codewire.v1.AccessProfileService";

pub struct Harness {
    pub db: PgPool,
    pub service_pool: PgPool,
    pub role: String,
    admin: PgPool,
    name: String,
    stop: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<std::io::Result<()>>>,
    /// The service with [`HANG`] in place of its five-second bounds.
    pub rpc: Rpc,
    /// The production-mounted service, for tests whose subject is its bounds.
    pub production_rpc: Rpc,
}

#[derive(Clone)]
pub struct Rpc {
    client: reqwest::Client,
    url: String,
}

#[derive(Clone, Copy)]
pub enum Auth {
    Alice,
    Bob,
    Cookie,
    ApiKey,
    Missing,
    Expired,
}

/// Direct transaction-helper proof, not an HTTP route or a runtime-delivery
/// fixture. Only stopped changes may commit without workflow dispatch.
pub async fn admit_sources(
    pool: &PgPool,
    user: &codewire_server_core::auth::AuthUser,
    environment: &str,
    body: &codewire_orchestration::api::environment_sources::UpdateEnvironmentSourcesBody,
) -> Result<
    codewire_orchestration::api::environment_sources::EnvironmentSourcesUpdate,
    codewire_server_core::AppError,
> {
    use codewire_orchestration::api::environment_sources::{
        EnvironmentSourcesUpdateOutcome, replace_environment_sources_in,
    };
    let profiles = codewire_platform_credentials::PlatformAccessProfileStore::new(
        pool.clone(),
        codewire_access::builtin_provider_catalog(),
    );
    let mut tx = profiles.begin_transaction().await.map_err(|_| {
        codewire_server_core::AppError::ServiceUnavailable(
            "source fixture transaction unavailable".into(),
        )
    })?;
    let result =
        replace_environment_sources_in(&mut tx, &profiles, user, ORG, environment, body).await?;
    if result.outcome == EnvironmentSourcesUpdateOutcome::RestartRequired {
        return Err(codewire_server_core::AppError::Precondition(
            "source fixture does not dispatch runtime changes".into(),
        ));
    }
    tx.commit().await?;
    Ok(result)
}

pub fn source_actor(user: &str) -> codewire_server_core::auth::AuthUser {
    codewire_server_core::auth::AuthUser {
        user_id: user.into(),
        org_id: None,
        is_admin: true,
        via_api_key: false,
    }
}

pub fn source_binding(
    profile: &Value,
) -> codewire_orchestration::api::environment_sources::EnvironmentSourceSelection {
    codewire_orchestration::api::environment_sources::EnvironmentSourceSelection {
        credentials: Some(codewire_project::CredentialBinding {
            profile: format!(
                "platform:id:{}",
                profile["id"].as_str().expect("profile ID")
            ),
        }),
        profile_revision: Some(
            profile["revision"]
                .as_str()
                .expect("revision")
                .parse()
                .expect("integer revision"),
        ),
        ..Default::default()
    }
}

pub fn source_replacement(
    expected: codewire_orchestration::api::environment_sources::EnvironmentSourceSelection,
    replacement: codewire_orchestration::api::environment_sources::EnvironmentSourceSelection,
) -> codewire_orchestration::api::environment_sources::UpdateEnvironmentSourcesBody {
    codewire_orchestration::api::environment_sources::UpdateEnvironmentSourcesBody {
        expected_operation_generation: 7,
        expected,
        replacement,
        allow_restart: false,
        confirm_personal_credentials: true,
        confirm_personal_secrets: false,
    }
}

fn oauth(user: &str) -> String {
    format!("synthetic-opaque-profile-oauth-{user}")
}

fn api_key() -> String {
    format!("cw_{}", "0123456789abcdef".repeat(4))
}

impl Rpc {
    pub async fn call(&self, method: &str, auth: Auth, body: Value) -> Result<(StatusCode, Value)> {
        let mut request = self
            .client
            .post(format!("{}/{SERVICE}/{method}", self.url))
            .header("connect-protocol-version", "1")
            .json(&body);
        request = match auth {
            Auth::Alice => request.bearer_auth(oauth(ALICE)),
            Auth::Bob => request.bearer_auth(oauth(BOB)),
            Auth::Cookie => request.header(
                "cookie",
                format!("{SESSION_COOKIE_NAME}=synthetic-profile-session"),
            ),
            Auth::ApiKey => request.bearer_auth(api_key()),
            Auth::Expired => request.bearer_auth("synthetic-profile-expired-oauth"),
            Auth::Missing => request,
        };
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        ensure!(bytes.len() <= 128 * 1024, "unbounded profile response");
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    pub async fn ok(&self, method: &str, auth: Auth, body: Value) -> Result<Value> {
        let (status, response) = self.call(method, auth, body).await?;
        ensure!(status == StatusCode::OK, "{method}: {status}: {response}");
        Ok(response)
    }

    pub async fn error(&self, method: &str, auth: Auth, body: Value, code: &str) -> Result<()> {
        let (status, response) = self.call(method, auth, body).await?;
        ensure!(!status.is_success(), "{method} unexpectedly succeeded");
        ensure!(response["code"] == code, "{method}: {status}: {response}");
        for canary in ["synthetic-opaque", "synthetic-profile-session", PASSWORD] {
            ensure!(!response.to_string().contains(canary));
        }
        Ok(())
    }

    pub async fn create(&self, name: &str, credential: &str) -> Result<Value> {
        let response = self
            .ok(
                "CreateAccessProfile",
                Auth::Alice,
                json!({
                    "name": name, "entries": entries(credential)
                }),
            )
            .await?;
        Ok(response["accessProfile"].clone())
    }

    pub async fn absent_route(&self, path: &str) -> Result<()> {
        let response = self
            .client
            .post(format!("{}{path}", self.url))
            .bearer_auth(oauth(ALICE))
            .json(&json!({}))
            .send()
            .await?;
        ensure!(response.status() == StatusCode::NOT_FOUND);
        Ok(())
    }
}

pub fn entries(credential: &str) -> Value {
    json!([{ "capabilitySlot": "codex", "credentialId": credential }])
}

pub fn binding(profile: &Value) -> Value {
    json!({ "environmentId": ENV, "accessProfileId": profile["id"],
        "accessProfileRevision": profile["revision"] })
}

pub fn id(profile: &Value) -> Result<&str> {
    profile["id"].as_str().context("profile has no identifier")
}

impl Harness {
    pub async fn create() -> Result<Self> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for isolated public-profile proof")?;
        ensure!(!admin_url.is_empty());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("cw_public_profiles_{suffix}");
        let role = format!("cw_profile_service_{suffix}");
        let mut url = url::Url::parse(&admin_url)?;
        url.set_path(&name);
        sqlx::query(&format!("CREATE DATABASE {}", quote(&name)))
            .execute(&admin)
            .await?;
        let prepared = async {
            codewire_server_core::migrate::ensure_schema(url.as_str()).await?;
            let db = PgPoolOptions::new().max_connections(8).connect(url.as_str()).await?;
            seed(&db).await?;
            sqlx::query(&format!("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                NOINHERIT NOBYPASSRLS PASSWORD '{PASSWORD}'", quote(&role)))
                .execute(&admin).await?;
            for grant in [
                format!("CONNECT ON DATABASE {}", quote(&name)),
                "USAGE ON SCHEMA public".into(),
                "SELECT,INSERT,UPDATE,DELETE ON public.platform_access_profiles, public.platform_access_profile_revisions, public.platform_access_profile_entries, public.platform_environment_access_bindings".into(),
                "SELECT ON public.platform_credentials".into(),
                "SELECT (id,is_admin,enabled) ON public.users".into(),
                "SELECT (id,deletion_state) ON public.organizations".into(),
                "SELECT (id,org_id,created_by,type,state,desired_state,deletion_requested_at,environment_operation_generation) ON public.environments".into(),
                // PostgreSQL row locks need UPDATE privilege on at least one
                // column. Neither grant authorizes lifecycle/membership edits.
                "UPDATE (state_changed_at) ON public.environments".into(),
                "SELECT (id,user_id,org_id) ON public.org_members".into(),
                "UPDATE (updated_at) ON public.org_members".into(),
                "SELECT (token_hash,user_id,client_id,scopes,expires_at) ON public.oidc_access_tokens".into(),
                "SELECT (id,disabled) ON public.oidc_clients".into(),
                "SELECT (token_hash,user_id,expires_at) ON public.sessions".into(),
                "UPDATE (expires_at,updated_at) ON public.sessions".into(),
                "SELECT (id,user_id,org_id,key_prefix,key_hash,expires_at,disabled_at,scopes,last_used_at) ON public.api_keys".into(),
                "UPDATE (last_used_at) ON public.api_keys".into(),
                "EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text)".into(),
                "EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text)".into(),
                "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)".into(),
                "EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text)".into(),
            ] {
                sqlx::query(&format!("GRANT {grant} TO {}", quote(&role))).execute(&db).await?;
            }
            url.set_username(&role).map_err(|_| anyhow::anyhow!("set synthetic login"))?;
            url.set_password(Some(PASSWORD)).map_err(|_| anyhow::anyhow!("set synthetic password"))?;
            let service_pool = PgPoolOptions::new().max_connections(4).connect(url.as_str()).await?;
            let auth = || ConnectAuthLayer::authenticated(AuthState { pool: service_pool.clone() });
            let production = connect_unary_router_with_auth(
                codewire_orchestration::connect::access_profiles::router(service_pool.clone()),
                auth(),
            );
            let app = connect_unary_router_with_auth(
                codewire_orchestration::connect::access_profiles::router_with_bounds(
                    service_pool.clone(),
                    Some(HANG),
                ),
                auth(),
            )
            .nest("/production", production);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let client = reqwest::Client::builder().no_proxy().timeout(HANG).build()?;
            let (stop, stopped) = oneshot::channel();
            let server = tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async { let _ = stopped.await; }).await
            });
            let production_rpc = Rpc { client: client.clone(), url: format!("http://{address}/production") };
            Ok::<_, anyhow::Error>((db, service_pool, stop, server,
                Rpc { client, url: format!("http://{address}") }, production_rpc))
        }.await;
        match prepared {
            Ok((db, service_pool, stop, server, rpc, production_rpc)) => Ok(Self {
                db,
                service_pool,
                admin,
                name,
                role,
                stop: Some(stop),
                server: Some(server),
                rpc,
                production_rpc,
            }),
            Err(error) => {
                cleanup(&admin, &name, &role).await?;
                admin.close().await;
                Err(error)
            }
        }
    }

    pub async fn finish(mut self, result: Result<()>) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let stopped = if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(HANG, &mut server).await {
                Ok(joined) => joined
                    .context("join generated profile listener")
                    .and_then(|result| result.context("serve generated profile listener")),
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    Err(anyhow::anyhow!("profile listener did not stop"))
                }
            }
        } else {
            Ok(())
        };
        self.service_pool.close().await;
        self.db.close().await;
        let cleaned = cleanup(&self.admin, &self.name, &self.role).await;
        self.admin.close().await;
        cleaned.context("clean exact public-profile database and role")?;
        stopped?;
        result
    }

    pub async fn member(&self) -> Result<()> {
        sqlx::query("INSERT INTO org_members(id,user_id,org_id,role) VALUES ('alice-membership',$1,$2,'member')")
            .bind(ALICE).bind(ORG).execute(&self.db).await?;
        Ok(())
    }
}

async fn cleanup(admin: &PgPool, name: &str, role: &str) -> Result<()> {
    sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", quote(name)))
        .execute(admin)
        .await?;
    sqlx::query(&format!("DROP ROLE IF EXISTS {}", quote(role)))
        .execute(admin)
        .await?;
    Ok(())
}

pub fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

async fn seed(db: &PgPool) -> Result<()> {
    for user in [ALICE, BOB] {
        sqlx::query("INSERT INTO users(id,email,is_admin) VALUES ($1,$2,true)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(db)
            .await?;
    }
    sqlx::query("INSERT INTO organizations(id,name,slug,created_by) VALUES ($1,$1,$1,$2)")
        .bind(ORG)
        .bind(ALICE)
        .execute(db)
        .await?;
    for (user, member) in [(ALICE, "alice-membership"), (BOB, "bob-membership")] {
        sqlx::query("INSERT INTO org_members(id,user_id,org_id,role) VALUES ($1,$2,$3,'member')")
            .bind(member)
            .bind(user)
            .bind(ORG)
            .execute(db)
            .await?;
    }
    sqlx::query(
        "INSERT INTO oidc_clients(id,name,application_type,auth_method,redirect_uris) \
        VALUES ('profile-client','Synthetic profile client','native','none','{}')",
    )
    .execute(db)
    .await?;
    for (raw, user, seconds) in [
        (oauth(ALICE), ALICE, 3600_i32),
        (oauth(BOB), BOB, 3600),
        ("synthetic-profile-expired-oauth".into(), ALICE, -60),
    ] {
        sqlx::query(
            "INSERT INTO oidc_access_tokens(token_hash,client_id,user_id,scopes,expires_at) \
            VALUES ($1,'profile-client',$2,ARRAY['codewire.api'],now()+$3*interval '1 second')",
        )
        .bind(hash_oauth_token(&raw))
        .bind(user)
        .bind(seconds)
        .execute(db)
        .await?;
    }
    sqlx::query(
        "INSERT INTO sessions(id,user_id,token_hash,expires_at) \
        VALUES ('profile-session',$1,$2,now()+interval '1 hour')",
    )
    .bind(ALICE)
    .bind(hash_session_token("synthetic-profile-session"))
    .execute(db)
    .await?;
    sqlx::query(
        "INSERT INTO api_keys(id,user_id,org_id,name,key_hash,key_prefix,scopes) \
        VALUES ('profile-key',$1,$2,'Synthetic profile API key',$3,$4,ARRAY['*'])",
    )
    .bind(ALICE)
    .bind(ORG)
    .bind(hash_api_key(&api_key()))
    .bind(&api_key()[3..11])
    .execute(db)
    .await?;
    for (credential, owner) in [(CREDENTIAL, ALICE), (OTHER_CREDENTIAL, BOB)] {
        // Metadata only, deliberately no material row or KEK provider. Profile
        // selection is not enrollment or material-use admission.
        sqlx::query("INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
            VALUES ($1,$2,'openai','oauth',$1,'active',1,1)")
            .bind(credential).bind(owner).execute(db).await?;
    }
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
        VALUES ('profile-preset',$1,'Synthetic profile preset','profile-preset', \
        '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(ORG)
    .execute(db)
    .await?;
    sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
        VALUES ($1,$2,$3,'sandbox','profile-preset','running','started',7, \
        '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
        .bind(ENV).bind(ORG).bind(ALICE).execute(db).await?;
    Ok(())
}

pub async fn denied(pool: &PgPool, sql: &str) -> Result<()> {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .err()
        .context("restricted profile login unexpectedly gained authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501"),
        "expected insufficient_privilege, not a fixture/syntax failure"
    );
    Ok(())
}

/// Observe a real PostgreSQL wait edge, never infer locking from a sleep.
pub async fn blocked_service(
    db: &PgPool,
    role: &str,
    holder: i32,
    count: usize,
) -> Result<Vec<i32>> {
    tokio::time::timeout(HANG, async {
        loop {
            // A second row-lock waiter can queue behind the first waiter,
            // rather than directly behind the transaction holding the row.
            let waiting: Vec<i32> = sqlx::query_scalar(
                "WITH RECURSIVE blocked(pid) AS ( \
                SELECT pid FROM pg_catalog.pg_stat_activity \
                WHERE usename=$1 AND $2=ANY(pg_catalog.pg_blocking_pids(pid)) UNION \
                SELECT a.pid FROM pg_catalog.pg_stat_activity a JOIN blocked b \
                ON b.pid=ANY(pg_catalog.pg_blocking_pids(a.pid)) WHERE a.usename=$1) \
                SELECT pid FROM blocked ORDER BY pid",
            )
            .bind(role)
            .bind(holder)
            .fetch_all(db)
            .await?;
            if waiting.len() == count {
                return Ok::<_, anyhow::Error>(waiting);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("profile request did not reach exact row-lock barrier")?
}

pub async fn blocked_pid(db: &PgPool, waiter: i32, holder: i32) -> Result<()> {
    tokio::time::timeout(HANG, async {
        loop {
            let blocked: bool =
                sqlx::query_scalar("SELECT $2=ANY(pg_catalog.pg_blocking_pids($1))")
                    .bind(waiter)
                    .bind(holder)
                    .fetch_one(db)
                    .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("membership removal did not reach exact binding lock")?
}

/// A failed intermediate assertion must not detach a pending HTTP/SQL task.
pub struct TestTask<T> {
    task: Option<JoinHandle<Result<T>>>,
}

impl<T> Drop for TestTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub fn spawn<T: Send + 'static>(
    future: impl Future<Output = Result<T>> + Send + 'static,
) -> TestTask<T> {
    TestTask {
        task: Some(tokio::spawn(future)),
    }
}

/// Abort and drain a failed waiter as well as bounding successful joins.
pub async fn joined<T>(mut owner: TestTask<T>) -> Result<T> {
    let mut task = owner.task.take().context("missing profile fixture task")?;
    match tokio::time::timeout(HANG, &mut task).await {
        Ok(result) => result.context("join profile fixture operation")?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(anyhow::anyhow!("profile fixture operation timed out"))
        }
    }
}
