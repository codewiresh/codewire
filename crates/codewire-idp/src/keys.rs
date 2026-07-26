//! [`KeyStore`] over the `jwks` table.
//!
//! Signing-capable rows contain a versioned AES-GCM envelope. Retired rows are
//! public-only; the final schema has no raw private-JWK column.

use async_trait::async_trait;
use codewire_oidc::{KeyStore, PublicJwk, SigningKey, StoreError, StoreResult};
use codewire_server_core::migrate::application_migrator;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use sqlx::migrate::Migrate;
use sqlx::{FromRow, PgConnection, PgPool, Postgres, Transaction};

use crate::jwk;
use crate::jwk_envelope::{JwkEnvelope, SigningKekKeyring};

// "cwidpsig". This is distinct from the long-lived orchestration and billing
// leader locks; it serializes only the empty-registry create-or-adopt
// transaction so every IDP replica starts with the same active signer.
const ACTIVE_SIGNER_ADVISORY_LOCK_ID: i64 = 0x6377_6964_7073_6967;

/// Value-blind result of one transactional signing-envelope rewrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKekRewrapReport {
    pub active_kek_id: String,
    pub total: usize,
    pub signing: usize,
    pub rewrapped: usize,
    pub already_active: usize,
    pub public_only: usize,
}

#[derive(FromRow)]
struct JwkRow {
    id: String,
    public_key: String,
    private_key_ciphertext: Option<Vec<u8>>,
    private_key_nonce: Option<Vec<u8>>,
    private_key_kek_id: Option<String>,
    private_key_format: Option<i16>,
}

enum EnvelopeState {
    Complete(JwkEnvelope),
    Partial,
    PublicOnly,
}

impl JwkRow {
    fn envelope_state(&self) -> EnvelopeState {
        match (
            &self.private_key_ciphertext,
            &self.private_key_nonce,
            &self.private_key_kek_id,
            self.private_key_format,
        ) {
            (Some(ciphertext), Some(nonce), Some(kek_id), Some(format)) => {
                EnvelopeState::Complete(JwkEnvelope {
                    ciphertext: ciphertext.clone(),
                    nonce: nonce.clone(),
                    kek_id: kek_id.clone(),
                    format,
                })
            }
            (None, None, None, None) => EnvelopeState::PublicOnly,
            _ => EnvelopeState::Partial,
        }
    }
}

/// `KeyStore` backed by the `jwks` Postgres table.
#[derive(Clone)]
pub struct PgKeyStore {
    pool: PgPool,
    keyring: SigningKekKeyring,
}

impl PgKeyStore {
    /// Wrap a connection pool and the idp-only signing KEK keyring.
    pub fn new(pool: PgPool, keyring: SigningKekKeyring) -> Self {
        Self { pool, keyring }
    }

    /// Authenticate and atomically rewrap every signing-capable JWK row under
    /// the configured active KEK.
    ///
    /// The operator path is deliberately migration-free. It locks both the
    /// existing SQLx ledger and JWK table, requires the accepted final schema
    /// and immutable migration history, and rolls back every update when any
    /// row is partial, corrupt, or references an unavailable KEK.
    pub async fn rewrap_signing_envelopes(&self) -> StoreResult<SigningKekRewrapReport> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| rewrap_failure("transaction-begin"))?;

        let required_tables: bool = sqlx::query_scalar(
            "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL \
                    AND to_regclass('public.jwks') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| rewrap_failure("schema-probe"))?;
        if !required_tables {
            return Err(rewrap_failure("required-schema-absent"));
        }

        // SHARE blocks migration ledger writers. SHARE ROW EXCLUSIVE blocks
        // INSERT/UPDATE/DELETE on jwks for the complete read-transform-write
        // transaction while still allowing ordinary public reads.
        sqlx::query("LOCK TABLE _sqlx_migrations IN SHARE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|_| rewrap_failure("migration-ledger-lock"))?;
        sqlx::query("LOCK TABLE jwks IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|_| rewrap_failure("jwk-table-lock"))?;

        validate_current_migration_ledger(&mut transaction).await?;
        let final_schema = has_final_jwk_schema(&mut transaction).await?;
        if !final_schema {
            return Err(rewrap_failure("final-jwk-schema-required"));
        }

        let rows = sqlx::query_as::<_, JwkRow>(
            "SELECT id, public_key, private_key_ciphertext, \
                    private_key_nonce, private_key_kek_id, private_key_format \
             FROM jwks ORDER BY created_at, id",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| rewrap_failure("row-read"))?;

        let mut report = SigningKekRewrapReport {
            active_kek_id: self.keyring.active_id().to_owned(),
            total: rows.len(),
            signing: 0,
            rewrapped: 0,
            already_active: 0,
            public_only: 0,
        };

        for row in rows {
            let envelope = match row.envelope_state() {
                EnvelopeState::PublicOnly => {
                    report.public_only += 1;
                    continue;
                }
                EnvelopeState::Partial => return Err(rewrap_failure("partial-envelope")),
                EnvelopeState::Complete(envelope) => envelope,
            };
            report.signing += 1;

            let public = jwk::parse_public_key(&row.id, &row.public_key)
                .map(|key| key.public_key)
                .map_err(|_| rewrap_failure("public-jwk-invalid"))?;
            let seed = self
                .keyring
                .decrypt(&row.id, &public, &envelope)
                .map_err(|_| rewrap_failure("envelope-invalid"))?;

            if envelope.kek_id == self.keyring.active_id() {
                report.already_active += 1;
                continue;
            }

            let replacement = self
                .keyring
                .encrypt(&row.id, &public, &seed)
                .map_err(|_| rewrap_failure("envelope-encryption"))?;
            let updated = sqlx::query(
                "UPDATE jwks \
                    SET private_key_ciphertext = $1, private_key_nonce = $2, \
                        private_key_kek_id = $3, private_key_format = $4 \
                  WHERE id = $5",
            )
            .bind(&replacement.ciphertext)
            .bind(&replacement.nonce)
            .bind(&replacement.kek_id)
            .bind(replacement.format)
            .bind(&row.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| rewrap_failure("row-update"))?;
            if updated.rows_affected() != 1 {
                return Err(rewrap_failure("row-update-count"));
            }
            report.rewrapped += 1;
        }

        let non_active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM jwks \
              WHERE num_nonnulls( \
                        private_key_ciphertext, private_key_nonce, \
                        private_key_kek_id, private_key_format \
                    ) = 4 \
                AND private_key_kek_id IS DISTINCT FROM $1",
        )
        .bind(self.keyring.active_id())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| rewrap_failure("active-kek-assertion"))?;
        if non_active != 0 {
            return Err(rewrap_failure("non-active-envelope-remains"));
        }

        transaction
            .commit()
            .await
            .map_err(|_| rewrap_failure("transaction-commit"))?;
        Ok(report)
    }

    /// Authenticate every signing-capable row before the replica becomes
    /// ready. Public-only history is left untouched and remains publishable
    /// without a KEK read.
    pub async fn validate_envelopes(&self) -> StoreResult<usize> {
        let rows = sqlx::query_as::<_, JwkRow>(
            "SELECT id, public_key, private_key_ciphertext, \
                    private_key_nonce, private_key_kek_id, private_key_format \
             FROM jwks ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::new)?;

        let mut validated = 0;
        for row in rows {
            match row.envelope_state() {
                EnvelopeState::PublicOnly => continue,
                EnvelopeState::Partial => {
                    return Err(row_failure("partial-envelope", &row.id, None, None));
                }
                EnvelopeState::Complete(envelope) => {
                    self.decrypt_row(&row, &envelope)?;
                    validated += 1;
                }
            }
        }
        Ok(validated)
    }

    /// Generate a fresh Ed25519 key, persist only its public JWK and encrypted
    /// seed, and return it. The caller holds the active-signer transaction
    /// lock; the conflict adoption remains a fail-closed boundary for an
    /// externally inserted winner.
    async fn generate_and_store(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> StoreResult<SigningKey> {
        use rand::RngCore;

        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signer = Ed25519SigningKey::from_bytes(&seed);
        let secret = signer.to_bytes().to_vec();
        let public = signer.verifying_key().to_bytes().to_vec();
        let kid = format!("codewire-{}", chrono::Utc::now().timestamp());
        let public_json = jwk::encode_public_key(&kid, &public)
            .map_err(|_| row_failure("jwk-encoding", &kid, None, None))?;
        let envelope = self
            .keyring
            .encrypt(&kid, &public, &secret)
            .map_err(StoreError::new)?;

        let inserted = sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, \
                 private_key_nonce, private_key_kek_id, private_key_format, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&kid)
        .bind(&public_json)
        .bind(&envelope.ciphertext)
        .bind(&envelope.nonce)
        .bind(&envelope.kek_id)
        .bind(envelope.format)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::new)?;

        if inserted.rows_affected() > 0 {
            return Ok(SigningKey {
                kid,
                secret_key: secret,
                public_key: public,
            });
        }

        // The winner's exact id is authoritative. A non-envelope winner is a
        // terminal compatibility violation; never replace it silently.
        let row = self
            .row_by_id(transaction, &kid)
            .await?
            .ok_or_else(|| row_failure("insert-winner-missing", &kid, None, None))?;
        self.signer_from_row(row)
    }

    async fn row_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        kid: &str,
    ) -> StoreResult<Option<JwkRow>> {
        sqlx::query_as::<_, JwkRow>(
            "SELECT id, public_key, private_key_ciphertext, \
                    private_key_nonce, private_key_kek_id, private_key_format \
             FROM jwks WHERE id = $1",
        )
        .bind(kid)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::new)
    }

    fn signer_from_row(&self, row: JwkRow) -> StoreResult<SigningKey> {
        match row.envelope_state() {
            EnvelopeState::Complete(envelope) => self.decrypt_row(&row, &envelope),
            EnvelopeState::Partial => Err(row_failure("partial-envelope", &row.id, None, None)),
            EnvelopeState::PublicOnly => {
                Err(row_failure("public-only-active-row", &row.id, None, None))
            }
        }
    }

    fn public_bytes(&self, row: &JwkRow) -> StoreResult<Vec<u8>> {
        jwk::parse_public_key(&row.id, &row.public_key)
            .map(|key| key.public_key)
            .map_err(|_| row_failure("public-jwk-invalid", &row.id, None, None))
    }

    fn decrypt_row(&self, row: &JwkRow, envelope: &JwkEnvelope) -> StoreResult<SigningKey> {
        let public = self.public_bytes(row)?;
        let seed = self
            .keyring
            .decrypt(&row.id, &public, envelope)
            .map_err(StoreError::new)?;
        Ok(SigningKey {
            kid: row.id.clone(),
            secret_key: seed.to_vec(),
            public_key: public,
        })
    }
}

#[async_trait]
impl KeyStore for PgKeyStore {
    async fn active_signer(&self) -> StoreResult<SigningKey> {
        // The usual issuance path is a single read and must not serialize
        // every token mint behind first-key initialization.
        let row = sqlx::query_as::<_, JwkRow>(
            "SELECT id, public_key, private_key_ciphertext, \
                    private_key_nonce, private_key_kek_id, private_key_format \
             FROM jwks \
             WHERE private_key_ciphertext IS NOT NULL \
                OR private_key_nonce IS NOT NULL \
                OR private_key_kek_id IS NOT NULL \
                OR private_key_format IS NOT NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;
        if let Some(row) = row {
            return self.signer_from_row(row);
        }

        // A first signer needs a single durable winner. Re-check under the
        // transaction-scoped lock because another replica may have completed
        // initialization after the lock-free read above.
        let mut transaction = self.pool.begin().await.map_err(StoreError::new)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ACTIVE_SIGNER_ADVISORY_LOCK_ID)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::new)?;
        let row = sqlx::query_as::<_, JwkRow>(
            "SELECT id, public_key, private_key_ciphertext, \
                    private_key_nonce, private_key_kek_id, private_key_format \
             FROM jwks \
             WHERE private_key_ciphertext IS NOT NULL \
                OR private_key_nonce IS NOT NULL \
                OR private_key_kek_id IS NOT NULL \
                OR private_key_format IS NOT NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(StoreError::new)?;
        let signer = match row {
            Some(row) => self.signer_from_row(row),
            None => {
                let registry_nonempty: bool =
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM jwks)")
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(StoreError::new)?;
                if registry_nonempty {
                    // The transaction lock means an existing registry with
                    // no signing envelope is conclusively public-only. Never
                    // manufacture a replacement key for that state.
                    Err(row_failure("no-signing-capable-row", "<none>", None, None))
                } else {
                    self.generate_and_store(&mut transaction).await
                }
            }
        }?;
        transaction.commit().await.map_err(StoreError::new)?;
        Ok(signer)
    }

    async fn public_jwks(&self) -> StoreResult<Vec<PublicJwk>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, public_key FROM jwks ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(StoreError::new)?;
        // Preserve the existing publication posture: a malformed historical
        // public row is skipped, and private/envelope columns are never read.
        Ok(rows
            .iter()
            .filter_map(|(kid, value)| jwk::parse_public_key(kid, value).ok())
            .collect())
    }
}

fn row_failure(
    class: &'static str,
    kid: &str,
    kek_id: Option<&str>,
    format: Option<i16>,
) -> StoreError {
    let mut message = format!("jwk-envelope failure_class={class} kid={kid:?}");
    if let Some(kek_id) = kek_id {
        message.push_str(&format!(" kek_id={kek_id:?}"));
    }
    if let Some(format) = format {
        message.push_str(&format!(" format={format}"));
    }
    StoreError::new(message)
}

fn rewrap_failure(class: &'static str) -> StoreError {
    StoreError::new(format!("jwk-rewrap failure_class={class}"))
}

async fn validate_current_migration_ledger(conn: &mut PgConnection) -> StoreResult<()> {
    if Migrate::dirty_version(&mut *conn)
        .await
        .map_err(|_| rewrap_failure("migration-ledger-invalid"))?
        .is_some()
    {
        return Err(rewrap_failure("migration-ledger-invalid"));
    }
    let applied = Migrate::list_applied_migrations(&mut *conn)
        .await
        .map_err(|_| rewrap_failure("migration-ledger-invalid"))?;
    let migrator = application_migrator();
    let embedded_max = migrator
        .iter()
        .map(|migration| migration.version)
        .max()
        .ok_or_else(|| rewrap_failure("embedded-migrations-absent"))?;

    if applied.iter().any(|migration| {
        migration.version <= embedded_max && !migrator.version_exists(migration.version)
    }) {
        return Err(rewrap_failure("migration-ledger-invalid"));
    }
    for migration in migrator
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
    {
        let Some(applied_migration) = applied
            .iter()
            .find(|applied| applied.version == migration.version)
        else {
            return Err(rewrap_failure("migration-ledger-invalid"));
        };
        if migration.checksum != applied_migration.checksum {
            return Err(rewrap_failure("migration-ledger-invalid"));
        }
    }
    Ok(())
}

async fn has_final_jwk_schema(conn: &mut PgConnection) -> StoreResult<bool> {
    sqlx::query_scalar(
        r#"
        SELECT
            to_regclass('public.jwks') IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema = 'public'
                   AND table_name = 'jwks'
                   AND column_name = 'private_key'
            )
            AND EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema = 'public'
                   AND table_name = 'jwks'
                   AND column_name = 'private_key_ciphertext'
                   AND data_type = 'bytea'
                   AND is_nullable = 'YES'
            )
            AND EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema = 'public'
                   AND table_name = 'jwks'
                   AND column_name = 'private_key_nonce'
                   AND data_type = 'bytea'
                   AND is_nullable = 'YES'
            )
            AND EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema = 'public'
                   AND table_name = 'jwks'
                   AND column_name = 'private_key_kek_id'
                   AND data_type = 'text'
                   AND is_nullable = 'YES'
            )
            AND EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema = 'public'
                   AND table_name = 'jwks'
                   AND column_name = 'private_key_format'
                   AND data_type = 'smallint'
                   AND is_nullable = 'YES'
            )
            AND EXISTS (
                SELECT 1
                  FROM pg_constraint AS constraint_row
                  JOIN pg_class AS table_row
                    ON table_row.oid = constraint_row.conrelid
                  JOIN pg_namespace AS namespace_row
                    ON namespace_row.oid = table_row.relnamespace
                 WHERE namespace_row.nspname = 'public'
                   AND table_row.relname = 'jwks'
                   AND constraint_row.conname = 'jwks_private_key_envelope_shape_check'
                   AND constraint_row.contype = 'c'
                   AND constraint_row.convalidated
                   AND NOT constraint_row.condeferrable
                   AND NOT constraint_row.condeferred
                   AND NOT constraint_row.connoinherit
                   AND pg_get_constraintdef(constraint_row.oid, true) =
                       'CHECK (num_nonnulls(private_key_ciphertext, private_key_nonce, private_key_kek_id, private_key_format) = ANY (ARRAY[0, 4]))'
            )
        "#,
    )
    .fetch_one(conn)
    .await
    .map_err(|_| rewrap_failure("schema-validation"))
}
