//! Value-blind operator workflow for tenant-secret import and KEK maintenance.
//!
//! The import transition takes the exclusive side of the same durable control
//! row lock held by product writes. Once it reaches `importing`, Infisical is
//! mutation-fenced and can be copied into encrypted Postgres without a dual-
//! write window. Activation remains a separate explicit operation.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use zeroize::Zeroizing;

use super::postgres_secrets::{PostgresSecretStore, RewrapSummary, ValidationSummary};
use super::secret_envelope::DekContext;
use super::secrets::{InfisicalClient, InfisicalSecret};

const SOURCE_REVISION_ENV: &str = "TENANT_SECRET_IMPORT_SOURCE_REVISION";

fn operator_error(class: &'static str) -> anyhow::Error {
    anyhow::anyhow!("tenant-secret-operator failure_class={class}")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TenantSecretOperatorCommand {
    InitCanary,
    ImportInfisical,
    Validate,
    ActivatePostgres,
    Rewrap,
}

impl TenantSecretOperatorCommand {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "init-canary" => Ok(Self::InitCanary),
            "import-infisical" => Ok(Self::ImportInfisical),
            "validate" => Ok(Self::Validate),
            "activate-postgres" => Ok(Self::ActivatePostgres),
            "rewrap" => Ok(Self::Rewrap),
            _ => Err(operator_error("unknown-command")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::InitCanary => "init-canary",
            Self::ImportInfisical => "import-infisical",
            Self::Validate => "validate",
            Self::ActivatePostgres => "activate-postgres",
            Self::Rewrap => "rewrap",
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct TenantSecretOperatorSummary {
    operation: &'static str,
    paths: usize,
    secrets: usize,
    scopes: usize,
    rewrapped: usize,
    canary_created: bool,
    canary_rewrapped: bool,
}

impl TenantSecretOperatorSummary {
    fn for_command(command: TenantSecretOperatorCommand) -> Self {
        Self {
            operation: command.name(),
            ..Self::default()
        }
    }
}

#[derive(sqlx::FromRow)]
struct ControlRow {
    state: String,
    source_revision: Option<String>,
    verified_at: Option<DateTime<Utc>>,
}

#[async_trait]
trait TenantSecretImportSource: Send + Sync {
    async fn list_folders(&self, parent_path: &str) -> anyhow::Result<Vec<String>>;
    async fn read_path(&self, secret_path: &str) -> anyhow::Result<Vec<InfisicalSecret>>;
}

#[async_trait]
impl TenantSecretImportSource for InfisicalClient {
    async fn list_folders(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        self.list_folders_at_path(parent_path)
            .await
            .map_err(|_| operator_error("source-enumeration-failed"))
    }

    async fn read_path(&self, secret_path: &str) -> anyhow::Result<Vec<InfisicalSecret>> {
        self.get_secrets_raw_at_path(secret_path)
            .await
            .map_err(|_| operator_error("source-read-failed"))
    }
}

type SecretValues = BTreeMap<String, Zeroizing<String>>;

pub async fn run_tenant_secret_operator(
    command: TenantSecretOperatorCommand,
    pool: PgPool,
) -> anyhow::Result<TenantSecretOperatorSummary> {
    let destination = PostgresSecretStore::from_env(pool.clone())?;
    let mut summary = TenantSecretOperatorSummary::for_command(command);
    match command {
        TenantSecretOperatorCommand::InitCanary => {
            summary.canary_created = destination.initialize_canary().await?;
            destination.verify_canary().await?;
        }
        TenantSecretOperatorCommand::ImportInfisical => {
            let revision = source_revision_from_env()?;
            destination.verify_canary().await?;
            begin_import(&pool, &revision).await?;
            let source = InfisicalClient::from_env_for_import(pool.clone());
            let copied = reconcile_import(&source, &destination).await?;
            finish_import(&pool, &revision).await?;
            summary.paths = copied.paths;
            summary.secrets = copied.secrets;
        }
        TenantSecretOperatorCommand::Validate => {
            let revision = source_revision_from_env()?;
            require_control(&pool, "postgres-readonly", Some(&revision), false).await?;
            let source = InfisicalClient::from_env_for_import(pool.clone());
            let compared = compare_source_and_destination(&source, &destination).await?;
            let validated = destination.validate_all().await?;
            if compared.secrets != validated.secrets {
                return Err(operator_error("validation-count-mismatch"));
            }
            mark_verified(&pool, "postgres-readonly", &revision).await?;
            summary.paths = compared.paths;
            summary.secrets = compared.secrets;
            summary.scopes = validated.scopes;
        }
        TenantSecretOperatorCommand::ActivatePostgres => {
            let revision = source_revision_from_env()?;
            destination.verify_canary().await?;
            activate_postgres(&pool, &revision).await?;
        }
        TenantSecretOperatorCommand::Rewrap => {
            let control = require_rewrap_state(&pool).await?;
            let rewrapped = destination.rewrap_all().await?;
            let validated = destination.validate_all().await?;
            mark_canary_verified(&pool, &control.state, control.source_revision.as_deref()).await?;
            apply_rewrap_summary(&mut summary, rewrapped, validated);
        }
    }
    Ok(summary)
}

fn source_revision_from_env() -> anyhow::Result<Zeroizing<String>> {
    let revision = Zeroizing::new(
        std::env::var(SOURCE_REVISION_ENV)
            .map_err(|_| operator_error("missing-source-revision"))?,
    );
    if revision.is_empty()
        || revision.len() > 1024
        || revision.trim() != revision.as_str()
        || revision.chars().any(char::is_control)
    {
        return Err(operator_error("invalid-source-revision"));
    }
    Ok(revision)
}

async fn begin_import(pool: &PgPool, revision: &str) -> anyhow::Result<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| operator_error("control-transaction-start-failed"))?;
    let row: ControlRow = sqlx::query_as(
        "SELECT state, source_revision, verified_at FROM tenant_secret_control \
         WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| operator_error("control-lock-failed"))?;
    match row.state.as_str() {
        "infisical" => {
            sqlx::query(
                "UPDATE tenant_secret_control SET state = 'importing', \
                        generation = generation + 1, source_revision = $1, \
                        transition_started_at = now(), verified_at = NULL, updated_at = now() \
                 WHERE singleton = true",
            )
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(|_| operator_error("control-transition-failed"))?;
        }
        "importing" if row.source_revision.as_deref() == Some(revision) => {}
        _ => return Err(operator_error("import-state-mismatch")),
    }
    tx.commit()
        .await
        .map_err(|_| operator_error("control-transaction-commit-failed"))
}

async fn finish_import(pool: &PgPool, revision: &str) -> anyhow::Result<()> {
    let updated = sqlx::query(
        "UPDATE tenant_secret_control SET state = 'postgres-readonly', \
                verified_at = NULL, updated_at = now() \
         WHERE singleton = true AND state = 'importing' AND source_revision = $1",
    )
    .bind(revision)
    .execute(pool)
    .await
    .map_err(|_| operator_error("control-transition-failed"))?;
    if updated.rows_affected() != 1 {
        return Err(operator_error("import-state-mismatch"));
    }
    Ok(())
}

async fn require_control(
    pool: &PgPool,
    expected_state: &str,
    expected_revision: Option<&str>,
    require_verified: bool,
) -> anyhow::Result<ControlRow> {
    let row: ControlRow = sqlx::query_as(
        "SELECT state, source_revision, verified_at FROM tenant_secret_control \
         WHERE singleton = true",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| operator_error("control-query-failed"))?;
    if row.state != expected_state
        || expected_revision.is_some() && row.source_revision.as_deref() != expected_revision
        || require_verified && row.verified_at.is_none()
    {
        return Err(operator_error("control-state-mismatch"));
    }
    Ok(row)
}

async fn require_rewrap_state(pool: &PgPool) -> anyhow::Result<ControlRow> {
    let row: ControlRow = sqlx::query_as(
        "SELECT state, source_revision, verified_at FROM tenant_secret_control \
         WHERE singleton = true",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| operator_error("control-query-failed"))?;
    if !matches!(row.state.as_str(), "postgres-readonly" | "postgres") {
        return Err(operator_error("rewrap-state-mismatch"));
    }
    Ok(row)
}

async fn mark_verified(pool: &PgPool, state: &str, revision: &str) -> anyhow::Result<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| operator_error("control-transaction-start-failed"))?;
    let updated = sqlx::query(
        "UPDATE tenant_secret_control SET verified_at = now(), updated_at = now() \
         WHERE singleton = true AND state = $1 AND source_revision = $2",
    )
    .bind(state)
    .bind(revision)
    .execute(&mut *tx)
    .await
    .map_err(|_| operator_error("verification-record-failed"))?;
    if updated.rows_affected() != 1 {
        return Err(operator_error("control-state-mismatch"));
    }
    sqlx::query(
        "UPDATE tenant_secret_kek_canary SET verified_at = now(), updated_at = now() \
         WHERE singleton = true",
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| operator_error("verification-record-failed"))?;
    tx.commit()
        .await
        .map_err(|_| operator_error("control-transaction-commit-failed"))
}

async fn mark_canary_verified(
    pool: &PgPool,
    state: &str,
    revision: Option<&str>,
) -> anyhow::Result<()> {
    let revision = revision.ok_or_else(|| operator_error("control-state-mismatch"))?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| operator_error("control-transaction-start-failed"))?;
    let matches: bool = sqlx::query_scalar(
        "SELECT state = $1 AND source_revision = $2 FROM tenant_secret_control \
         WHERE singleton = true FOR SHARE",
    )
    .bind(state)
    .bind(revision)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| operator_error("control-query-failed"))?;
    if !matches {
        return Err(operator_error("control-state-mismatch"));
    }
    let updated = sqlx::query(
        "UPDATE tenant_secret_kek_canary SET verified_at = now(), updated_at = now() \
         WHERE singleton = true",
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| operator_error("verification-record-failed"))?;
    if updated.rows_affected() != 1 {
        return Err(operator_error("verification-record-failed"));
    }
    tx.commit()
        .await
        .map_err(|_| operator_error("control-transaction-commit-failed"))
}

async fn activate_postgres(pool: &PgPool, revision: &str) -> anyhow::Result<()> {
    require_control(pool, "postgres-readonly", Some(revision), true).await?;
    let updated = sqlx::query(
        "UPDATE tenant_secret_control SET state = 'postgres', updated_at = now() \
         WHERE singleton = true AND state = 'postgres-readonly' \
           AND source_revision = $1 AND verified_at IS NOT NULL",
    )
    .bind(revision)
    .execute(pool)
    .await
    .map_err(|_| operator_error("control-transition-failed"))?;
    if updated.rows_affected() != 1 {
        return Err(operator_error("control-state-mismatch"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct CopySummary {
    paths: usize,
    secrets: usize,
}

async fn reconcile_import<S: TenantSecretImportSource>(
    source: &S,
    destination: &PostgresSecretStore,
) -> anyhow::Result<CopySummary> {
    let paths = enumerate_source_paths(source).await?;
    let source_path_set: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    for extra_path in destination.imported_paths().await? {
        if source_path_set.contains(extra_path.as_str()) {
            continue;
        }
        for secret in destination
            .get_imported_secrets_at_path(&extra_path)
            .await?
        {
            destination
                .delete_imported_secret_at_path(&extra_path, &secret.key)
                .await?;
        }
    }

    let mut populated_paths = BTreeSet::new();
    let mut secret_count = 0_usize;
    for path in &paths {
        let source_values = secret_values(source.read_path(path).await?)?;
        let destination_values =
            secret_values(destination.get_imported_secrets_at_path(path).await?)?;
        for destination_key in destination_values.keys() {
            if !source_values.contains_key(destination_key) {
                destination
                    .delete_imported_secret_at_path(path, destination_key)
                    .await?;
            }
        }
        for (key, value) in &source_values {
            destination.import_secret_at_path(path, key, value).await?;
        }
        let imported = secret_values(destination.get_imported_secrets_at_path(path).await?)?;
        if !secret_values_equal(&source_values, &imported) {
            return Err(operator_error("import-equality-failed"));
        }
        if !source_values.is_empty() {
            populated_paths.insert(path.as_str());
        }
        secret_count = secret_count.saturating_add(source_values.len());
    }
    let imported_paths: BTreeSet<String> =
        destination.imported_paths().await?.into_iter().collect();
    if imported_paths.len() != populated_paths.len()
        || !imported_paths
            .iter()
            .all(|path| populated_paths.contains(path.as_str()))
    {
        return Err(operator_error("import-path-equality-failed"));
    }
    Ok(CopySummary {
        paths: paths.len(),
        secrets: secret_count,
    })
}

async fn compare_source_and_destination<S: TenantSecretImportSource>(
    source: &S,
    destination: &PostgresSecretStore,
) -> anyhow::Result<CopySummary> {
    let paths = enumerate_source_paths(source).await?;
    let mut populated_paths = BTreeSet::new();
    let mut secret_count = 0_usize;
    for path in &paths {
        let source_values = secret_values(source.read_path(path).await?)?;
        let imported = secret_values(destination.get_imported_secrets_at_path(path).await?)?;
        if !secret_values_equal(&source_values, &imported) {
            return Err(operator_error("validation-equality-failed"));
        }
        if !source_values.is_empty() {
            populated_paths.insert(path.as_str());
        }
        secret_count = secret_count.saturating_add(source_values.len());
    }
    let imported_paths: BTreeSet<String> =
        destination.imported_paths().await?.into_iter().collect();
    if imported_paths.len() != populated_paths.len()
        || !imported_paths
            .iter()
            .all(|path| populated_paths.contains(path.as_str()))
    {
        return Err(operator_error("validation-path-equality-failed"));
    }
    Ok(CopySummary {
        paths: paths.len(),
        secrets: secret_count,
    })
}

async fn enumerate_source_paths<S: TenantSecretImportSource>(
    source: &S,
) -> anyhow::Result<Vec<String>> {
    let mut paths = BTreeSet::new();
    for name in source.list_folders("/org-secrets").await? {
        let path = format!("/org-secrets/{name}");
        validate_source_path(&path)?;
        paths.insert(path);
    }
    for name in source.list_folders("/users").await? {
        let path = format!("/users/{name}");
        validate_source_path(&path)?;
        paths.insert(path);
    }
    for organization in source.list_folders("/projects").await? {
        if !valid_path_segment(&organization) {
            return Err(operator_error("invalid-source-layout"));
        }
        let parent = format!("/projects/{organization}");
        for project in source.list_folders(&parent).await? {
            let path = format!("{parent}/{project}");
            validate_source_path(&path)?;
            paths.insert(path);
        }
    }
    Ok(paths.into_iter().collect())
}

fn validate_source_path(path: &str) -> anyhow::Result<()> {
    DekContext::from_secret_path(path)
        .map(|_| ())
        .map_err(|_| operator_error("invalid-source-layout"))
}

fn valid_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn secret_values(secrets: Vec<InfisicalSecret>) -> anyhow::Result<SecretValues> {
    let mut values = BTreeMap::new();
    for secret in secrets {
        if values
            .insert(secret.key, Zeroizing::new(secret.value))
            .is_some()
        {
            return Err(operator_error("duplicate-secret-key"));
        }
    }
    Ok(values)
}

fn secret_values_equal(left: &SecretValues, right: &SecretValues) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|((left_key, left_value), (right_key, right_value))| {
                left_key == right_key && left_value.as_bytes() == right_value.as_bytes()
            })
}

fn apply_rewrap_summary(
    output: &mut TenantSecretOperatorSummary,
    rewrapped: RewrapSummary,
    validated: ValidationSummary,
) {
    output.scopes = validated.scopes;
    output.secrets = validated.secrets;
    output.rewrapped = rewrapped.rewrapped;
    output.canary_rewrapped = rewrapped.canary_rewrapped;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct FakeSource {
        folders: HashMap<String, Vec<String>>,
    }

    #[async_trait]
    impl TenantSecretImportSource for FakeSource {
        async fn list_folders(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.folders.get(parent_path).cloned().unwrap_or_default())
        }

        async fn read_path(&self, _secret_path: &str) -> anyhow::Result<Vec<InfisicalSecret>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn enumeration_is_complete_sorted_and_deduplicated() {
        let source = FakeSource {
            folders: HashMap::from([
                (
                    "/org-secrets".into(),
                    vec!["org_b".into(), "org_a".into(), "org_a".into()],
                ),
                ("/users".into(), vec!["user_b".into(), "user_a".into()]),
                ("/projects".into(), vec!["org_b".into(), "org_a".into()]),
                (
                    "/projects/org_a".into(),
                    vec!["project_b".into(), "project_a".into()],
                ),
                ("/projects/org_b".into(), vec!["project_c".into()]),
            ]),
        };
        let paths = enumerate_source_paths(&source).await.unwrap();
        assert_eq!(
            paths,
            vec![
                "/org-secrets/org_a",
                "/org-secrets/org_b",
                "/projects/org_a/project_a",
                "/projects/org_a/project_b",
                "/projects/org_b/project_c",
                "/users/user_a",
                "/users/user_b",
            ]
        );
    }

    #[test]
    fn equality_is_exact_and_debug_output_is_value_blind() {
        let values = secret_values(vec![InfisicalSecret {
            key: "PRIVATE_KEY".into(),
            value: "tenant-secret-value-must-never-render".into(),
            ..Default::default()
        }])
        .unwrap();
        let same = secret_values(vec![InfisicalSecret {
            key: "PRIVATE_KEY".into(),
            value: "tenant-secret-value-must-never-render".into(),
            ..Default::default()
        }])
        .unwrap();
        let different = secret_values(vec![InfisicalSecret {
            key: "PRIVATE_KEY".into(),
            value: "different-private-value".into(),
            ..Default::default()
        }])
        .unwrap();
        assert!(secret_values_equal(&values, &same));
        assert!(!secret_values_equal(&values, &different));
        let rendered = format!(
            "{:?}",
            TenantSecretOperatorSummary {
                operation: "validate",
                paths: 1,
                secrets: 1,
                ..Default::default()
            }
        );
        assert!(!rendered.contains("PRIVATE_KEY"));
        assert!(!rendered.contains("tenant-secret-value-must-never-render"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn control_transition_is_forward_only_and_requires_verification() -> anyhow::Result<()> {
        const TEST_LOCK: i64 = 0x4357_5453_4f50_5431;
        let database_url = std::env::var("TEST_DATABASE_URL")?;
        codewire_server_core::migrate::ensure_schema(&database_url).await?;
        let pool = PgPool::connect(&database_url).await?;
        let mut isolation = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(TEST_LOCK)
            .fetch_one(&mut *isolation)
            .await?;
        sqlx::query(
            "UPDATE tenant_secret_control SET state = 'infisical', source_revision = NULL, \
                    transition_started_at = NULL, verified_at = NULL, updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;

        let revision = "operator-transition-test";
        begin_import(&pool, revision).await?;
        begin_import(&pool, revision).await?;
        assert!(
            begin_import(&pool, "different-transition-test")
                .await
                .is_err()
        );
        finish_import(&pool, revision).await?;
        assert!(activate_postgres(&pool, revision).await.is_err());
        mark_verified(&pool, "postgres-readonly", revision).await?;
        activate_postgres(&pool, revision).await?;
        let row = require_control(&pool, "postgres", Some(revision), true).await?;
        assert_eq!(row.state, "postgres");

        sqlx::query(
            "UPDATE tenant_secret_control SET state = 'infisical', source_revision = NULL, \
                    transition_started_at = NULL, verified_at = NULL, updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;
        isolation.rollback().await?;
        pool.close().await;
        Ok(())
    }
}
