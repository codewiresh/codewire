//! Exact non-promotable fixture inputs; never shared service defaults.

use std::path::PathBuf;

use codewire_credential_broker::platform::keepalive::OAuthKeepAliveConfig;
use codewire_tls::ServerTlsFiles;
use sqlx::PgPool;
use zeroize::Zeroizing;

use super::super::{Listeners, RuntimeError};

pub(super) const NAMESPACE: &str = "codewire-e2e";
const DATABASE_URL: &str = "postgres://codewire_credential_broker:kind-credential-broker-synthetic-only@postgres.codewire-e2e.svc.cluster.local:5432/codewire?sslmode=disable";
const ROLE: &str = "codewire_credential_broker";

pub(super) struct Config {
    pub(super) database_url: Zeroizing<String>,
    pub(super) listeners: Listeners,
    pub(super) runtime_directory: PathBuf,
    pub(super) oauth_keepalive: Option<OAuthKeepAliveConfig>,
}

impl Config {
    pub(super) fn from_env() -> Result<Self, RuntimeError> {
        // Check fixed names only, not an environment dump containing unrelated
        // values. SQLx must not discover pgpass, client keys or a second host.
        for name in [
            "PGPORT",
            "PGHOSTADDR",
            "PGHOST",
            "PGUSER",
            "PGDATABASE",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGSSLROOTCERT",
            "PGSSLCERT",
            "PGSSLKEY",
            "PGSSLMODE",
            "PGAPPNAME",
            "PGOPTIONS",
            "PGSERVICE",
            "PGSERVICEFILE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            if std::env::var_os(name).is_some() {
                return Err(RuntimeError::Configuration("ambient Kind fixture override"));
            }
        }
        if required("CODEWIRE_KIND_CREDENTIAL_FIXTURE")? != "1"
            || required("POD_NAMESPACE")? != NAMESPACE
        {
            return Err(RuntimeError::Configuration(
                "managed Kind fixture selection",
            ));
        }
        let database_url = Zeroizing::new(required("CREDENTIAL_DATABASE_URL")?);
        if database_url.as_str() != DATABASE_URL {
            return Err(RuntimeError::Configuration(
                "synthetic restricted Kind database",
            ));
        }
        // Preserve the shipped ports; the fixture owns no auxiliary listener.
        if required("CREDENTIAL_HTTP_LISTEN_ADDR")? != "0.0.0.0:8086"
            || required("CREDENTIAL_BROKER_TLS_LISTEN_ADDR")? != "0.0.0.0:9443"
        {
            return Err(RuntimeError::Configuration(
                "Kind credential listener addresses",
            ));
        }
        let tls = ServerTlsFiles::new(
            path("CREDENTIAL_BROKER_TLS_CERT_FILE")?,
            path("CREDENTIAL_BROKER_TLS_KEY_FILE")?,
        )
        .map_err(|_| RuntimeError::Tls)?;
        let public_origin = parse_kind_public_origin(&required("CREDENTIAL_PUBLIC_ORIGIN")?)?;
        Ok(Self {
            database_url,
            listeners: Listeners {
                public: ([0, 0, 0, 0], 8086).into(),
                public_origin,
                private: ([0, 0, 0, 0], 9443).into(),
                tls,
            },
            runtime_directory: path("CREDENTIAL_RUNTIME_DIR")?,
            oauth_keepalive: super::super::config::oauth_keepalive_config(&|name| {
                std::env::var_os(name)
            })?,
        })
    }
}

fn parse_kind_public_origin(value: &str) -> Result<http::HeaderValue, RuntimeError> {
    // Saved profiles vary only the host ingress port. Do not normalize URLs:
    // other hosts, aliases, userinfo and trailing components are not admitted.
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(RuntimeError::Configuration(
            "managed Kind credential public origin",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return Err(RuntimeError::Configuration(
            "managed Kind credential public origin",
        ));
    }
    http::HeaderValue::from_str(value)
        .map_err(|_| RuntimeError::Configuration("managed Kind credential public origin"))
}

fn required(name: &'static str) -> Result<String, RuntimeError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
        .ok_or(RuntimeError::Configuration(name))
}

fn path(name: &'static str) -> Result<PathBuf, RuntimeError> {
    let path = PathBuf::from(required(name)?);
    if !path.is_absolute() {
        return Err(RuntimeError::Configuration(name));
    }
    Ok(path)
}

/// Check the same forbidden authority/material surfaces as the restricted
/// mutation, profile and runtime-identity fixtures. Effective ACL checks include
/// PUBLIC grants and column-only grants; NOINHERIT alone does not prevent SET
/// ROLE. Named missing relations fail closed. This issues no mutation probes.
pub(super) async fn assert_restricted_login(pool: &PgPool) -> Result<(), RuntimeError> {
    assert_restricted_role(pool, ROLE).await
}

async fn assert_restricted_role(pool: &PgPool, expected_role: &str) -> Result<(), RuntimeError> {
    let restricted: bool = tokio::time::timeout(
        super::super::DATABASE_TIMEOUT,
        sqlx::query_scalar(
            "SELECT current_user::text=$1 AND session_user::text=$1 \
         AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole \
         AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit \
         AND NOT pg_catalog.pg_has_role(current_user,d.datdba,'MEMBER') \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) \
         AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE') \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
             WHERE c.relnamespace='public'::regnamespace AND c.relowner=r.oid) \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p \
             WHERE p.pronamespace='public'::regnamespace AND p.proowner=r.oid) \
         AND NOT EXISTS ( \
             SELECT 1 FROM unnest(ARRAY[ \
                 'users','organizations','org_members','environments','environment_presets', \
                 'sandbox_environment_backend','oidc_access_tokens','oidc_clients', \
                 'platform_access_profiles','platform_access_profile_revisions', \
                 'platform_access_profile_entries','platform_environment_access_bindings', \
                 'tenant_secrets','tenant_secret_deks','secret_projects' \
             ]::text[]) AS authority(name) \
             WHERE pg_catalog.has_table_privilege(current_user,'public.'||authority.name, \
                 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') \
                OR pg_catalog.has_any_column_privilege(current_user,'public.'||authority.name, \
                 'INSERT,UPDATE,REFERENCES') \
         ) \
         AND NOT EXISTS ( \
             SELECT 1 FROM unnest(ARRAY[ \
                 'tenant_secret_kek_canary', \
                 'confidential_storage_keys','sessions','api_keys','oidc_refresh_tokens','jwks' \
             ]::text[]) AS material(name) \
             WHERE pg_catalog.has_any_column_privilege(current_user,'public.'||material.name,'SELECT') \
         ) \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.tenant_secrets','SELECT') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.tenant_secret_deks','SELECT') \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a \
             WHERE a.attrelid='public.tenant_secrets'::regclass AND a.attnum>0 AND NOT a.attisdropped \
             AND a.attname<>ALL(ARRAY['path','key','scope','scope_id','dek_id','ciphertext','nonce','format','storage_contract_version']) \
             AND pg_catalog.has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')) \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a \
             WHERE a.attrelid='public.tenant_secret_deks'::regclass AND a.attnum>0 AND NOT a.attisdropped \
             AND a.attname<>ALL(ARRAY['dek_id','scope','scope_id','provider','key_name','key_version','wrapped_dek','format','revision']) \
             AND pg_catalog.has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')) \
         AND NOT pg_catalog.has_column_privilege(current_user,'public.environments','project_spec','SELECT') \
         AND NOT pg_catalog.has_column_privilege(current_user,'public.oidc_clients','secret','SELECT') \
         AND NOT pg_catalog.has_column_privilege(current_user,'public.users','email','SELECT') \
         FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_database d \
         WHERE r.rolname=current_user AND d.datname=current_database()",
        )
        .bind(expected_role)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| RuntimeError::Database)?
    .map_err(|_| RuntimeError::Database)?;
    if !restricted {
        return Err(RuntimeError::Configuration(
            "restricted Kind database login",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn kind_public_origin_accepts_saved_ports_and_rejects_unmanaged_origins() {
        for port in [1, 8090, 32767, 65535] {
            let origin = format!("http://127.0.0.1:{port}");
            assert_eq!(
                super::parse_kind_public_origin(&origin)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                origin
            );
        }
        for origin in [
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:08090",
            "http://127.0.0.1:+8090",
            "http://127.0.0.1:8090/",
            "http://127.0.0.1:8090/path",
            "http://127.0.0.1:8090?x=1",
            "http://127.0.0.1:8090#fragment",
            "http://user@127.0.0.1:8090",
            "http://localhost:8090",
            "http://127.1:8090",
            "http://[::1]:8090",
            "http://0.0.0.0:8090",
            "https://127.0.0.1:8090",
            "http://127.0.0.1",
            " http://127.0.0.1:8090",
            "http://127.0.0.1:8090\n",
        ] {
            assert!(
                super::parse_kind_public_origin(origin).is_err(),
                "accepted {origin:?}"
            );
        }
    }

    use anyhow::{Context, Result, ensure};

    use super::*;
    use crate::platform_test_support::{TIMEOUT, TestDatabase, quote_ident};

    async fn execute(pool: &PgPool, statement: &str) -> Result<()> {
        tokio::time::timeout(TIMEOUT, sqlx::query(statement).execute(pool))
            .await
            .context("synthetic ACL change timed out")??;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires isolated TEST_DATABASE_URL"]
    async fn effective_acl_guard_rejects_direct_column_and_membership_authority() -> Result<()> {
        let database = TestDatabase::create().await?;
        let result = async {
            // Authenticate as the real restricted login, never SET ROLE from
            // the fixture administrator. Both generated roles are registered
            // with TestDatabase for cleanup, including failed assertions.
            let (pool, role) = database.broker_pool().await?;
            let result = async {
                assert_restricted_role(&pool, &role).await?;
                ensure!(
                    matches!(
                        assert_restricted_login(&pool).await,
                        Err(RuntimeError::Configuration(
                            "restricted Kind database login"
                        ))
                    ),
                    "Kind entrypoint must still require its fixed login"
                );
                let role_ident = quote_ident(&role);
                for privilege in [
                    "UPDATE ON public.environments",
                    "UPDATE (is_admin) ON public.users",
                    "SELECT (created_at) ON public.tenant_secrets",
                    "SELECT ON public.tenant_secrets",
                    "SELECT (created_at) ON public.tenant_secret_deks",
                    "SELECT (project_spec) ON public.environments",
                    "UPDATE (ciphertext) ON public.tenant_secrets",
                    "SELECT (email) ON public.users",
                    "SELECT (secret) ON public.oidc_clients",
                ] {
                    execute(
                        &database.pool,
                        &format!("GRANT {privilege} TO {role_ident}"),
                    )
                    .await?;
                    let observed = assert_restricted_role(&pool, &role).await;
                    // Restore even when the guard unexpectedly accepts the
                    // grant or returns a database error instead of rejection.
                    execute(
                        &database.pool,
                        &format!("REVOKE {privilege} FROM {role_ident}"),
                    )
                    .await?;
                    ensure!(
                        matches!(
                            observed,
                            Err(RuntimeError::Configuration(
                                "restricted Kind database login"
                            ))
                        ),
                        "effective ACL guard did not reject synthetic privilege: {privilege}"
                    );
                    assert_restricted_role(&pool, &role).await?;
                }

                // Another restricted broker is not the database owner. Its
                // membership must fail independently of the owner/NOINHERIT
                // checks, because NOINHERIT still permits SET ROLE.
                let (other_pool, other_role) = database.broker_pool().await?;
                other_pool.close().await;
                let other_ident = quote_ident(&other_role);
                execute(
                    &database.pool,
                    &format!("GRANT {other_ident} TO {role_ident}"),
                )
                .await?;
                let observed = assert_restricted_role(&pool, &role).await;
                execute(
                    &database.pool,
                    &format!("REVOKE {other_ident} FROM {role_ident}"),
                )
                .await?;
                ensure!(
                    matches!(
                        observed,
                        Err(RuntimeError::Configuration(
                            "restricted Kind database login"
                        ))
                    ),
                    "effective ACL guard accepted non-owner role membership"
                );
                assert_restricted_role(&pool, &role).await?;
                Ok(())
            }
            .await;
            pool.close().await;
            result
        }
        .await;
        database.finish(result).await
    }
}
