//! Synthetic, exact-database fixtures. No live OpenBao or product credentials.

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
use sqlx::postgres::PgPoolOptions;
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
            "UPDATE (status,expires_at_unix,revocation_generation,material_generation,updated_at) ON public.platform_credentials",
            "SELECT,INSERT,DELETE ON public.platform_credential_material",
            "SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_attempts",
            "SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_material",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)",
            "EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text)",
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
