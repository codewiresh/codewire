//! What a mint reads and writes: the Sandbox, its organization, its groups
//! and kill switches, the organization's registration of the audience, and
//! the mint log. The records' own store and APIs belong to the records
//! slice (#4663); minting only reads them, on a pool of its own so tenant
//! traffic here can't exhaust orchestration's.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

const MINT_POOL_CONNECTIONS: u32 = 4;
const MINT_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the sandbox identity store is unavailable")]
pub(crate) struct MintStoreUnavailable;

/// Whether the organization may mint at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrgStanding {
    Active,
    Suspended,
    /// Being deleted, or a deletion that failed.
    Deleting,
}

/// The Sandbox as one mint reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MintSubject {
    pub(crate) org_id: String,
    pub(crate) org: OrgStanding,
    pub(crate) running: bool,
    /// The Sandbox's access is suspended: its creator's account is.
    pub(crate) access_suspended: bool,
    /// A kill switch is on for the Sandbox or its organization.
    pub(crate) stopped: bool,
    /// The creator's stable user ID.
    pub(crate) created_by: String,
    pub(crate) name: Option<String>,
    pub(crate) groups: Vec<String>,
    /// 0 while the Sandbox has never had groups; a stored version is never 0.
    pub(crate) groups_version: i64,
}

/// An organization's registration of one audience.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct Registration {
    /// `None` sees every group.
    pub(crate) visible_groups: Option<Vec<String>>,
    pub(crate) lifetime_seconds: i32,
    pub(crate) claim_created_by: bool,
    pub(crate) claim_environment_name: bool,
    pub(crate) version: i64,
}

/// One signature's row in `identity_mints`. It never holds the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MintRecord {
    pub(crate) jti: String,
    pub(crate) environment_id: String,
    pub(crate) org_id: String,
    pub(crate) audience: String,
    pub(crate) kid: String,
    pub(crate) groups_version: i64,
    pub(crate) audience_version: i64,
    pub(crate) minted_at: DateTime<Utc>,
}

#[async_trait]
pub(crate) trait MintStore: Send + Sync {
    async fn subject(
        &self,
        environment_id: &str,
    ) -> Result<Option<MintSubject>, MintStoreUnavailable>;

    async fn registration(
        &self,
        org_id: &str,
        audience: &str,
    ) -> Result<Option<Registration>, MintStoreUnavailable>;

    async fn record(&self, record: &MintRecord) -> Result<(), MintStoreUnavailable>;
}

pub(crate) struct PgMintStore {
    pool: PgPool,
}

impl PgMintStore {
    pub(crate) fn connect_lazy(database_url: &str) -> anyhow::Result<Self> {
        let pool = codewire_server_core::db::checked_pool_options()
            .max_connections(MINT_POOL_CONNECTIONS)
            .min_connections(0)
            .acquire_timeout(MINT_POOL_ACQUIRE_TIMEOUT)
            .idle_timeout(Some(Duration::from_secs(5 * 60)))
            .max_lifetime(Some(Duration::from_secs(30 * 60)))
            .connect_lazy(database_url)?;
        Ok(Self { pool })
    }

    #[cfg(test)]
    pub(crate) fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct SubjectRow {
    org_id: String,
    org_active: bool,
    org_suspended: bool,
    running: bool,
    access_suspended: bool,
    stopped: bool,
    created_by: String,
    name: Option<String>,
    groups: Option<Vec<String>>,
    groups_version: Option<i64>,
}

fn unavailable(what: &'static str) -> impl FnOnce(sqlx::Error) -> MintStoreUnavailable {
    move |error| {
        tracing::warn!(error = %error, "sandbox identity {what} failed");
        MintStoreUnavailable
    }
}

#[async_trait]
impl MintStore for PgMintStore {
    async fn subject(
        &self,
        environment_id: &str,
    ) -> Result<Option<MintSubject>, MintStoreUnavailable> {
        let row: Option<SubjectRow> = sqlx::query_as(
            r#"SELECT e.org_id,
                      o.deletion_state = 'active' AS org_active,
                      o.suspended_at IS NOT NULL AS org_suspended,
                      e.state = 'running' AS running,
                      COALESCE(u.suspended_at IS NOT NULL, false) AS access_suspended,
                      EXISTS (SELECT 1 FROM identity_minting_stops s
                               WHERE s.org_id = e.org_id
                                 AND (s.environment_id IS NULL OR s.environment_id = e.id))
                          AS stopped,
                      e.created_by,
                      e.name,
                      g.groups,
                      g.version AS groups_version
                 FROM environments e
                 JOIN organizations o ON o.id = e.org_id
            LEFT JOIN users u ON u.id = e.created_by
            LEFT JOIN environment_identity_groups g ON g.environment_id = e.id
                WHERE e.id = $1"#,
        )
        .bind(environment_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable("subject lookup"))?;
        Ok(row.map(|row| MintSubject {
            org_id: row.org_id,
            org: match (row.org_active, row.org_suspended) {
                (false, _) => OrgStanding::Deleting,
                (true, true) => OrgStanding::Suspended,
                (true, false) => OrgStanding::Active,
            },
            running: row.running,
            access_suspended: row.access_suspended,
            stopped: row.stopped,
            created_by: row.created_by,
            name: row.name,
            groups: row.groups.unwrap_or_default(),
            groups_version: row.groups_version.unwrap_or(0),
        }))
    }

    async fn registration(
        &self,
        org_id: &str,
        audience: &str,
    ) -> Result<Option<Registration>, MintStoreUnavailable> {
        sqlx::query_as(
            "SELECT visible_groups, lifetime_seconds, claim_created_by, \
                    claim_environment_name, version \
               FROM identity_audiences WHERE org_id = $1 AND audience = $2",
        )
        .bind(org_id)
        .bind(audience)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable("registration lookup"))
    }

    async fn record(&self, record: &MintRecord) -> Result<(), MintStoreUnavailable> {
        sqlx::query(
            "INSERT INTO identity_mints \
                 (jti, environment_id, org_id, audience, kid, groups_version, \
                  audience_version, minted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&record.jti)
        .bind(&record.environment_id)
        .bind(&record.org_id)
        .bind(&record.audience)
        .bind(&record.kid)
        .bind(record.groups_version)
        .bind(record.audience_version)
        .bind(record.minted_at)
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(unavailable("mint log write"))
    }
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod database_tests;
