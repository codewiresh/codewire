//! Synthetic metadata-only role and the real generated CredentialService.

use anyhow::{Context, Result, ensure};
use codewire_server_core::auth::{AuthState, hash_api_key, hash_oauth_token, hash_session_token};
use codewire_server_core::connect::{ConnectAuthLayer, connect_unary_router_with_auth};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

pub const ALICE: &str = "metadata-alice";
pub const BOB: &str = "metadata-bob";
pub const ALICE_CREDENTIAL: &str = "credential-a";
pub const BOB_CREDENTIAL: &str = "credential-bob";
pub const ORG_CREDENTIAL: &str = "credential-org";
const PASSWORD: &str = "synthetic-metadata-reader-only";
const TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE: &str = "codewire.v1.CredentialService";

#[derive(Clone, Copy)]
pub enum Auth {
    Alice,
    Bob,
    Cookie,
    ApiKey,
    Missing,
    Expired,
    WrongScope,
}

pub struct Harness {
    pub db: PgPool,
    pub reader: PgPool,
    pub role: String,
    admin: PgPool,
    name: String,
    client: reqwest::Client,
    address: String,
    stop: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<std::io::Result<()>>>,
}

fn raw(user: &str) -> String {
    format!("synthetic-metadata-oauth-{user}")
}
fn key() -> String {
    format!("cw_{}", "0123456789abcdef".repeat(4))
}
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

impl Harness {
    pub async fn create() -> Result<Self> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL required for isolated credential metadata proof")?;
        ensure!(!admin_url.is_empty());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("cw_metadata_{suffix}");
        let role = format!("cw_metadata_reader_{suffix}");
        let mut url = url::Url::parse(&admin_url)?;
        url.set_path(&name);
        sqlx::query(&format!("CREATE DATABASE {}", quote(&name)))
            .execute(&admin)
            .await?;
        let prepared = async {
            codewire_server_core::migrate::ensure_schema(url.as_str()).await?;
            let db = PgPoolOptions::new().max_connections(4).connect(url.as_str()).await?;
            seed(&db).await?;
            sqlx::query(&format!("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{PASSWORD}'", quote(&role))).execute(&admin).await?;
            for grant in [
                format!("CONNECT ON DATABASE {}", quote(&name)),
                "USAGE ON SCHEMA public".into(),
                "SELECT ON public.platform_credentials".into(),
                "SELECT (id,is_admin) ON public.users".into(),
                "SELECT (id,deletion_state) ON public.organizations".into(),
                "SELECT (token_hash,user_id,client_id,scopes,expires_at) ON public.oidc_access_tokens".into(),
                "SELECT (id,disabled) ON public.oidc_clients".into(),
                // Ordinary account auth retains its existing session sliding
                // expiry and API-key usage paths; these are not metadata writes.
                "SELECT (token_hash,user_id,expires_at) ON public.sessions".into(),
                "UPDATE (expires_at,updated_at) ON public.sessions".into(),
                "SELECT (id,user_id,org_id,key_prefix,key_hash,expires_at,disabled_at,scopes,last_used_at) ON public.api_keys".into(),
                "UPDATE (last_used_at) ON public.api_keys".into(),
            ] {
                sqlx::query(&format!("GRANT {grant} TO {}", quote(&role))).execute(&db).await?;
            }
            url.set_username(&role).map_err(|_| anyhow::anyhow!("set synthetic metadata role"))?;
            url.set_password(Some(PASSWORD)).map_err(|_| anyhow::anyhow!("set synthetic metadata password"))?;
            let reader = PgPoolOptions::new().max_connections(2).connect(url.as_str()).await?;
            let app = connect_unary_router_with_auth(
                codewire_orchestration::connect::credentials::router(reader.clone()),
                ConnectAuthLayer::authenticated(AuthState { pool: reader.clone() }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = format!("http://{}", listener.local_addr()?);
            let client = reqwest::Client::builder().no_proxy().timeout(TIMEOUT).build()?;
            let (stop, stopped) = oneshot::channel();
            let server = tokio::spawn(async move { axum::serve(listener, app)
                .with_graceful_shutdown(async { let _ = stopped.await; }).await });
            Ok::<_, anyhow::Error>((db, reader, address, client, stop, server))
        }.await;
        match prepared {
            Ok((db, reader, address, client, stop, server)) => Ok(Self {
                db,
                reader,
                role,
                admin,
                name,
                client,
                address,
                stop: Some(stop),
                server: Some(server),
            }),
            Err(error) => {
                cleanup(&admin, &name, &role).await?;
                admin.close().await;
                Err(error)
            }
        }
    }

    pub async fn call(&self, method: &str, auth: Auth, body: Value) -> Result<(StatusCode, Value)> {
        let mut request = self
            .client
            .post(format!("{}/{SERVICE}/{method}", self.address))
            .header("connect-protocol-version", "1")
            .json(&body);
        request = match auth {
            Auth::Alice => request.bearer_auth(raw(ALICE)),
            Auth::Bob => request.bearer_auth(raw(BOB)),
            Auth::Cookie => request.header(
                "cookie",
                "codewire.session_token=synthetic-metadata-session",
            ),
            Auth::ApiKey => request.bearer_auth(key()),
            Auth::Missing => request,
            Auth::Expired => request.bearer_auth("synthetic-metadata-expired"),
            Auth::WrongScope => request.bearer_auth("synthetic-metadata-identity-only"),
        };
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        ensure!(bytes.len() <= 128 * 1024);
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    pub async fn ok(&self, method: &str, auth: Auth, body: Value) -> Result<Value> {
        let (status, body) = self.call(method, auth, body).await?;
        ensure!(status == StatusCode::OK, "{method}: {status}: {body}");
        Ok(body)
    }

    pub async fn error(&self, method: &str, auth: Auth, body: Value, code: &str) -> Result<()> {
        let (status, body) = self.call(method, auth, body).await?;
        ensure!(
            !status.is_success() && body["code"] == code,
            "{method}: {status}: {body}"
        );
        for canary in [
            "synthetic-metadata",
            PASSWORD,
            "platform_credentials",
            "SELECT ",
        ] {
            ensure!(!body.to_string().contains(canary));
        }
        Ok(())
    }

    pub async fn absent_mutation_routes(&self) -> Result<()> {
        for method in ["EnrollCodex", "RevokeCredential", "DeleteCredential"] {
            let response = self
                .client
                .post(format!(
                    "{}/codewire.v1.CredentialMutationService/{method}",
                    self.address
                ))
                .bearer_auth(raw(ALICE))
                .json(&json!({}))
                .send()
                .await?;
            ensure!(response.status() == StatusCode::NOT_FOUND);
        }
        Ok(())
    }

    pub async fn finish(mut self, result: Result<()>) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let stopped = if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(TIMEOUT, &mut server).await {
                Ok(result) => result
                    .context("join metadata listener")
                    .and_then(|result| result.context("metadata listener")),
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    Err(anyhow::anyhow!("metadata listener did not stop"))
                }
            }
        } else {
            Ok(())
        };
        self.reader.close().await;
        self.db.close().await;
        let cleaned = cleanup(&self.admin, &self.name, &self.role).await;
        self.admin.close().await;
        cleaned?;
        stopped?;
        result
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

async fn seed(db: &PgPool) -> Result<()> {
    for user in [ALICE, BOB] {
        sqlx::query("INSERT INTO users(id,email,is_admin) VALUES ($1,$2,true)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(db)
            .await?;
    }
    // Deliberately identical organization/user text IDs are separate owners.
    sqlx::query("INSERT INTO organizations(id,name,slug,created_by) VALUES ($1,'Metadata org','metadata-org',$1)")
        .bind(ALICE).execute(db).await?;
    sqlx::query("INSERT INTO oidc_clients(id,name,application_type,auth_method,redirect_uris) VALUES ('metadata-client','Metadata fixture','native','none','{}')")
        .execute(db).await?;
    for (token, user, scope, lifetime) in [
        (raw(ALICE), ALICE, "codewire.api", 3600_i32),
        (raw(BOB), BOB, "codewire.api", 3600),
        (
            "synthetic-metadata-expired".into(),
            ALICE,
            "codewire.api",
            -60,
        ),
        (
            "synthetic-metadata-identity-only".into(),
            ALICE,
            "openid",
            3600,
        ),
    ] {
        sqlx::query("INSERT INTO oidc_access_tokens(token_hash,client_id,user_id,scopes,expires_at) VALUES ($1,'metadata-client',$2,ARRAY[$3::text],now()+$4*interval '1 second')")
            .bind(hash_oauth_token(&token)).bind(user).bind(scope).bind(lifetime).execute(db).await?;
    }
    sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES ('metadata-session',$1,$2,now()+interval '1 hour')")
        .bind(ALICE).bind(hash_session_token("synthetic-metadata-session")).execute(db).await?;
    sqlx::query("INSERT INTO api_keys(id,user_id,org_id,name,key_hash,key_prefix,scopes) VALUES ('metadata-api-key',$1,$1,'Metadata API key',$2,$3,ARRAY['*'])")
        .bind(ALICE).bind(hash_api_key(&key())).bind(&key()[3..11]).execute(db).await?;
    for (id, owner, name, kind, status, hint, expiry, generation) in [
        (
            ALICE_CREDENTIAL,
            ALICE,
            "Work Codex",
            "oauth",
            "active",
            None,
            None,
            9_007_199_254_740_993_i64,
        ),
        (
            "credential-c",
            ALICE,
            "Revoked",
            "api_key",
            "revoked",
            Some("Synthetic account"),
            Some(i64::MAX),
            2,
        ),
        (
            "credential-d",
            ALICE,
            "Expired",
            "oauth",
            "expired",
            None,
            Some(1),
            1,
        ),
        (
            "credential-e",
            ALICE,
            "Refresh Failed",
            "oauth",
            "refresh_failed",
            None,
            None,
            1,
        ),
        (
            BOB_CREDENTIAL,
            BOB,
            "Work Codex",
            "oauth",
            "active",
            None,
            None,
            1,
        ),
    ] {
        // No provider or material fixture is created: all data is metadata.
        sqlx::query("INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status,account_hint,expires_at_unix,revocation_generation,material_generation) VALUES ($1,$2,'openai',$3,$4,$5,$6,$7,$8,1)")
            .bind(id).bind(owner).bind(kind).bind(name).bind(status).bind(hint).bind(expiry).bind(generation).execute(db).await?;
    }
    sqlx::query("INSERT INTO platform_credentials(id,organization_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) VALUES ($1,$2,'openai','oauth','Work Codex','active',1,1)")
        .bind(ORG_CREDENTIAL).bind(ALICE).execute(db).await?;
    Ok(())
}

pub async fn denied(pool: &PgPool, sql: &str) -> Result<()> {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .err()
        .context("metadata login gained forbidden authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501")
    );
    Ok(())
}
