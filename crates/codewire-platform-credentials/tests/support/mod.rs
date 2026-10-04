//! Synthetic, exact-database fixtures. No live OpenBao or product credentials.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use codewire_access::{CredentialAuthKind, Owner, OwnerId, ProviderId, builtin_provider_catalog};
use codewire_platform_credentials::{CredentialRegistration, PlatformCredentialStore};
use codewire_protected_store::ProtectedValue;
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, GeneratedDek, KekProvider, KekProviderKind, SecretEnvelopeError,
    TestKekProvider, WrappedDek,
};
use codewire_server_core::auth::AuthUser;
use sqlx::PgPool;
use sqlx::postgres::{PgPoolOptions, PgSslMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use zeroize::Zeroizing;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const OLD_VALUE: &[u8] = b"synthetic-platform-credential-old-never-public";
pub const NEW_VALUE: &[u8] = b"synthetic-platform-credential-new-never-public";

pub struct TestDatabase {
    pub pool: PgPool,
    admin: PgPool,
    url: String,
    name: String,
    roles: Mutex<Vec<String>>,
}

impl TestDatabase {
    pub async fn create() -> Result<Self> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for platform credential storage tests")?;
        ensure!(!admin_url.is_empty(), "TEST_DATABASE_URL must not be empty");
        let name = format!("cw_credential_test_{}", uuid::Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let mut url = url::Url::parse(&admin_url)?;
        url.set_path(&name);
        sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
            .execute(&admin)
            .await?;
        let setup = async {
            codewire_server_core::migrate::ensure_schema(url.as_str()).await?;
            let pool = PgPoolOptions::new().max_connections(8).connect(url.as_str()).await?;
            sqlx::query("INSERT INTO users (id,email) VALUES ('fixture-admin','fixture-admin@example.test')")
                .execute(&pool).await?;
            Ok::<_, anyhow::Error>(pool)
        }.await;
        match setup {
            Ok(pool) => Ok(Self {
                pool,
                admin,
                url: url.to_string(),
                name,
                roles: Mutex::new(Vec::new()),
            }),
            Err(error) => {
                sqlx::query(&format!(
                    "DROP DATABASE {} WITH (FORCE)",
                    quote_ident(&name)
                ))
                .execute(&admin)
                .await?;
                admin.close().await;
                Err(error)
            }
        }
    }

    /// Every test returns its assertions as Result so cleanup also runs on a
    /// failed assertion. FORCE is scoped only to this generated test database.
    pub async fn finish(self, result: Result<()>) -> Result<()> {
        self.pool.close().await;
        let cleanup = async {
            sqlx::query(&format!(
                "DROP DATABASE {} WITH (FORCE)",
                quote_ident(&self.name)
            ))
            .execute(&self.admin)
            .await?;
            let roles = self.roles.lock().expect("test role registry").clone();
            for role in roles {
                sqlx::query(&format!("DROP ROLE {}", quote_ident(&role)))
                    .execute(&self.admin)
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        self.admin.close().await;
        cleanup.context("clean exact platform credential test database and roles")?;
        result
    }

    pub async fn user(&self, id: &str) -> Result<Owner> {
        sqlx::query("INSERT INTO users (id,email) VALUES ($1,$2)")
            .bind(id)
            .bind(format!("{id}@example.test"))
            .execute(&self.pool)
            .await?;
        Ok(Owner::User(OwnerId::parse(id)?))
    }

    pub async fn organization(&self, id: &str) -> Result<Owner> {
        sqlx::query(
            "INSERT INTO organizations (id,name,slug,created_by) VALUES ($1,$1,$2,'fixture-admin')",
        )
        .bind(id)
        .bind(format!("fixture-{}", uuid::Uuid::new_v4().simple()))
        .execute(&self.pool)
        .await?;
        sqlx::query("INSERT INTO org_members (id,org_id,user_id,role) VALUES ($1,$2,'fixture-admin','owner')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(id).execute(&self.pool).await?;
        Ok(Owner::Organization(OwnerId::parse(id)?))
    }

    pub fn store(&self, provider: Arc<dyn KekProvider>) -> Arc<PlatformCredentialStore> {
        Arc::new(PlatformCredentialStore::new(
            self.pool.clone(),
            provider,
            builtin_provider_catalog(),
        ))
    }

    pub async fn metadata_pool(&self) -> Result<(PgPool, String)> {
        // Public, fixed synthetic-only password for this generated disposable
        // role. Authenticate as the reader itself: an admin session with SET
        // ROLE could regain material privileges through RESET ROLE.
        const SYNTHETIC_PASSWORD: &str = "synthetic-platform-reader-test-only";
        let role = format!("cw_credential_reader_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{SYNTHETIC_PASSWORD}'",
            quote_ident(&role)
        ))
        .execute(&self.admin)
        .await?;
        self.roles
            .lock()
            .expect("test role registry")
            .push(role.clone());
        for statement in [
            format!(
                "GRANT CONNECT ON DATABASE {} TO {}",
                quote_ident(&self.name),
                quote_ident(&role)
            ),
            format!("GRANT USAGE ON SCHEMA public TO {}", quote_ident(&role)),
            format!(
                "GRANT SELECT ON platform_credentials TO {}",
                quote_ident(&role)
            ),
            format!("GRANT SELECT (id) ON users TO {}", quote_ident(&role)),
            format!(
                "GRANT SELECT (id,deletion_state) ON organizations TO {}",
                quote_ident(&role)
            ),
        ] {
            sqlx::query(&statement).execute(&self.pool).await?;
        }
        let mut reader_url = url::Url::parse(&self.url)?;
        reader_url
            .set_username(&role)
            .map_err(|_| anyhow::anyhow!("set synthetic reader username"))?;
        reader_url
            .set_password(Some(SYNTHETIC_PASSWORD))
            .map_err(|_| anyhow::anyhow!("set synthetic reader password"))?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(reader_url.as_str())
            .await?;
        Ok((pool, role))
    }

    /// Authenticate as a real restricted enrollment/broker login. Only the
    /// disposable fixture administrator provisions it; production role and
    /// credential reconciliation is not performed by the placement library.
    #[allow(dead_code)] // Shared fixtures are also compiled by the storage-only target.
    pub async fn broker_pool(&self) -> Result<(PgPool, String)> {
        const SYNTHETIC_PASSWORD: &str = "synthetic-platform-broker-test-only";
        let role = format!("cw_credential_broker_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{SYNTHETIC_PASSWORD}'",
            quote_ident(&role)
        ))
        .execute(&self.admin)
        .await?;
        self.roles
            .lock()
            .expect("test role registry")
            .push(role.clone());
        let role_ident = quote_ident(&role);
        sqlx::query(&format!(
            "GRANT CONNECT ON DATABASE {} TO {role_ident}",
            quote_ident(&self.name)
        ))
        .execute(&self.pool)
        .await?;
        for grant in [
            "USAGE ON SCHEMA public",
            "SELECT (id) ON public.users",
            "SELECT (id,deletion_state) ON public.organizations",
            "SELECT (id,created_by,org_id,environment_operation_generation,desired_state,state) ON public.environments",
            "SELECT (id,user_id,organization_id,name,current_revision) ON public.platform_access_profiles",
            "SELECT (profile_id,revision) ON public.platform_access_profile_revisions",
            "SELECT ON public.platform_access_profile_entries",
            "SELECT (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) ON public.platform_environment_access_bindings",
            "SELECT,INSERT,DELETE ON public.platform_credentials",
            "UPDATE (status,expires_at_unix,revocation_generation,material_generation,updated_at,account_hint,display_name) ON public.platform_credentials",
            "SELECT,INSERT,DELETE ON public.platform_credential_material",
            "SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_attempts",
            "SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_material",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_authority_stamp(text[],text[])",
        ] {
            sqlx::query(&format!("GRANT {grant} TO {role_ident}"))
                .execute(&self.pool)
                .await?;
        }
        let mut broker_url = url::Url::parse(&self.url)?;
        broker_url
            .set_username(&role)
            .map_err(|_| anyhow::anyhow!("set synthetic broker username"))?;
        broker_url
            .set_password(Some(SYNTHETIC_PASSWORD))
            .map_err(|_| anyhow::anyhow!("set synthetic broker password"))?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(broker_url.as_str())
            .await?;
        Ok((pool, role))
    }
}

pub fn admin_user() -> AuthUser {
    AuthUser {
        user_id: "fixture-admin".into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

pub fn registration(name: &str, kind: CredentialAuthKind) -> CredentialRegistration {
    CredentialRegistration {
        provider: ProviderId::parse("openai").expect("built-in provider"),
        authentication_kind: kind,
        display_name: name.into(),
        account_hint: Some("synthetic-account".into()),
        expires_at_unix: None,
    }
}

pub fn value(bytes: &[u8]) -> ProtectedValue {
    ProtectedValue::from_slice(bytes).expect("nonempty bounded synthetic material")
}

pub fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// One-shot barriers establish the exact provider boundary without sleeps.
#[derive(Default)]
pub struct Gate {
    armed: AtomicBool,
    entered: Notify,
    released: Notify,
}

impl Gate {
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    async fn pass(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.released.notified().await;
        }
    }
    pub async fn wait(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, self.entered.notified())
            .await
            .context("synthetic provider did not reach its barrier")?;
        Ok(())
    }
    pub fn release(&self) {
        self.released.notify_one();
    }
}

/// TestKekProvider is intentionally not OpenBao: it exercises the same local
/// authenticated envelope while deterministic barriers/failures exercise SQL
/// publication. No claim about Transit authentication follows from this fake.
#[derive(Default)]
pub struct SyntheticKek {
    pub generate_gate: Gate,
    pub unwrap_gate: Gate,
    pub generate_calls: AtomicUsize,
    pub unwrap_calls: AtomicUsize,
    pub fail_generate: AtomicBool,
}

#[async_trait]
impl KekProvider for SyntheticKek {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }

    async fn generate(&self, context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError> {
        self.generate_calls.fetch_add(1, Ordering::SeqCst);
        self.generate_gate.pass().await;
        if self.fail_generate.swap(false, Ordering::SeqCst) {
            let mut invalid = TestKekProvider.generate(context).await?.wrapped;
            invalid.ciphertext = b"synthetic-provider-error-input-never-public".to_vec();
            return match TestKekProvider.unwrap(context, &invalid).await {
                Err(error) => Err(error),
                Ok(_) => unreachable!("invalid synthetic wrapped DEK must fail"),
            };
        }
        TestKekProvider.generate(context).await
    }

    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        self.unwrap_gate.pass().await;
        TestKekProvider.unwrap(context, wrapped).await
    }

    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        TestKekProvider.rewrap(context, wrapped).await
    }

    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError> {
        TestKekProvider.authority_id().await
    }
}

pub async fn material_count(pool: &PgPool, id: &str) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM platform_credential_material WHERE credential_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

pub async fn envelope_bytes(pool: &PgPool, id: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    Ok(sqlx::query_as(
        "SELECT wrapped_dek,ciphertext,nonce FROM platform_credential_material WHERE credential_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

pub async fn wait_for_advisory_waiter(pool: &PgPool, key: i32) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' \
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) \
                 AND classid=0 AND objid=$1::oid AND NOT granted)",
            )
            .bind(key)
            .fetch_one(pool)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("publication did not reach the SQL barrier")??;
    Ok(())
}

/// Counts the statements a pool sends to PostgreSQL, at the wire. SQLx waits
/// for each statement's ReadyForQuery before it sends the next one, so every
/// simple Query ('Q') and every extended-protocol Execute ('E') is exactly one
/// sequential round trip. Statement preparation (Parse/Describe/Sync) and the
/// pool's connection pings (Sync alone) execute nothing and are not counted.
/// The text of every statement prepared or sent is kept for `ensure_cheap_plans`.
#[allow(dead_code)] // Only the round-trip tests use it.
pub struct StatementCounter {
    statements: Arc<AtomicUsize>,
    texts: Arc<Mutex<BTreeSet<String>>>,
    accept: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)]
impl StatementCounter {
    /// A pool with `pool`'s exact login and database whose connections all
    /// pass through this counter. Plaintext keeps the protocol readable; the
    /// disposable synthetic database never carries a real credential.
    pub async fn pool(pool: &PgPool, max_connections: u32) -> Result<(Self, PgPool)> {
        let options = pool.connect_options().as_ref().clone();
        let upstream = format!("{}:{}", options.get_host(), options.get_port());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let statements = Arc::new(AtomicUsize::new(0));
        let texts = Arc::new(Mutex::new(BTreeSet::new()));
        let (counted, seen) = (statements.clone(), texts.clone());
        let accept = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let (counted, seen) = (counted.clone(), seen.clone());
                tokio::spawn(async move {
                    if let Ok(server) = TcpStream::connect(&upstream).await {
                        let _ = relay_counting_statements(client, server, counted, seen).await;
                    }
                });
            }
        });
        let counter = Self {
            statements,
            texts,
            accept,
        };
        let counted_pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(
                options
                    .host("127.0.0.1")
                    .port(port)
                    .ssl_mode(PgSslMode::Disable),
            )
            .await?;
        Ok((counter, counted_pool))
    }

    /// The statements `work` sent, and its output.
    pub async fn count<T>(&self, work: impl Future<Output = T>) -> (T, usize) {
        self.statements.store(0, Ordering::SeqCst);
        let output = work.await;
        (output, self.statements.swap(0, Ordering::SeqCst))
    }

    /// Every statement text prepared or sent through this counter so far.
    pub fn texts(&self) -> Vec<String> {
        self.texts
            .lock()
            .expect("statement text registry")
            .iter()
            .cloned()
            .collect()
    }
}

/// The largest estimated cost any statement on a runtime authority path may
/// have. Each lock helper is a table function that PostgreSQL estimates at
/// 1000 rows; nested calls multiply that, and above `jit_above_cost` (100000
/// by default) every execution is JIT-compiled, which costs far more than the
/// round trips a merged statement saves. The current statements stay below 100.
#[allow(dead_code)]
pub const MAX_PLANNED_COST: f64 = 1000.0;

/// Plan every query in `texts` generically as `admin` and require each total
/// cost to stay at or below `MAX_PLANNED_COST`. Returns the largest cost.
#[allow(dead_code)]
pub async fn ensure_cheap_plans(admin: &PgPool, texts: &[String]) -> Result<f64> {
    let mut largest: f64 = 0.0;
    for text in texts {
        let keyword = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if !matches!(keyword.as_str(), "SELECT" | "WITH") {
            continue;
        }
        // The simple protocol: a generic plan keeps `$n` unbound.
        let explain = format!("EXPLAIN (GENERIC_PLAN, FORMAT JSON) {text}");
        let plan: serde_json::Value = sqlx::raw_sql(&explain)
            .fetch_one(admin)
            .await
            .and_then(|row| sqlx::Row::try_get(&row, 0))
            .with_context(|| format!("plan {text}"))?;
        let cost = plan[0]["Plan"]["Total Cost"]
            .as_f64()
            .context("plan total cost")?;
        ensure!(
            cost <= MAX_PLANNED_COST,
            "statement planned at cost {cost}, above {MAX_PLANNED_COST}: {text}"
        );
        largest = largest.max(cost);
    }
    Ok(largest)
}

impl Drop for StatementCounter {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn relay_counting_statements(
    client: TcpStream,
    server: TcpStream,
    statements: Arc<AtomicUsize>,
    texts: Arc<Mutex<BTreeSet<String>>>,
) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let downstream =
        tokio::spawn(async move { tokio::io::copy(&mut server_read, &mut client_write).await });
    // The StartupMessage is the only untyped frontend message without TLS.
    let mut length = [0_u8; 4];
    client_read.read_exact(&mut length).await?;
    let mut startup = vec![0_u8; (u32::from_be_bytes(length) as usize).saturating_sub(4)];
    client_read.read_exact(&mut startup).await?;
    server_write.write_all(&length).await?;
    server_write.write_all(&startup).await?;
    let mut header = [0_u8; 5];
    while client_read.read_exact(&mut header).await.is_ok() {
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut message = header.to_vec();
        message.resize(1 + length.max(4), 0);
        client_read.read_exact(&mut message[5..]).await?;
        // Counted before it is forwarded, so its reply cannot precede it.
        if matches!(header[0], b'Q' | b'E') {
            statements.fetch_add(1, Ordering::SeqCst);
        }
        // Parse carries a statement name, then its text; Query only its text.
        let body = &message[5..];
        let text = match header[0] {
            b'P' => body
                .iter()
                .position(|byte| *byte == 0)
                .map(|end| &body[end + 1..]),
            b'Q' => Some(body),
            _ => None,
        };
        if let Some(text) = text.and_then(|text| text.split(|byte| *byte == 0).next()) {
            texts
                .lock()
                .expect("statement text registry")
                .insert(String::from_utf8_lossy(text).into_owned());
        }
        server_write.write_all(&message).await?;
    }
    downstream.abort();
    Ok(())
}
