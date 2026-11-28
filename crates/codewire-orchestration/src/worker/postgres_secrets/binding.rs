//! Writing a secret together with its binding (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound application secrets").
//! One transaction locks the row, checks the new binding and the value
//! against it, enforces the re-entry rule, and moves the binding's
//! generation and the value's version.

use codewire_access::{
    BindingError, HostBinding, ReservedHosts, StoredBinding, change_moves_generation,
    change_needs_value,
};
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, SecretCoordinates, encrypt_secret,
};
use codewire_workload_secrets::validate_workload_secret_value;
use sqlx::types::Json;
use thiserror::Error;
use uuid::Uuid;

use super::{PostgresSecretStore, envelope_error, store_error};
use crate::worker::secrets::is_valid_secret_key;

/// What a write does to a secret's binding.
#[derive(Clone, Debug)]
pub enum BindingWrite {
    /// Leave it as it is: a new value never unbinds a secret.
    Keep,
    /// Bind the secret, or change its binding.
    Bind(StoredBinding),
    /// Remove every host.
    Plain,
}

/// Why a write was refused. Each message is the one a person reads.
#[derive(Debug, Error)]
pub enum SecretWriteError {
    #[error("{0} needs the secret's value again")]
    ValueRequired(&'static str),
    /// No value, and no change to a bound secret that would need none: what
    /// an empty value has always been refused as.
    #[error("a secret's value can't be empty")]
    EmptyValue,
    #[error(transparent)]
    Binding(#[from] BindingError),
    /// Binding is switched off in this deployment: nothing would send the
    /// value only to its hosts yet.
    #[error("sending a secret only to its hosts isn't available yet")]
    Unavailable,
    /// The set the secret is stored in has an ID that isn't its kind's one
    /// spelling, so it has no slot and no placeholder (#4003;
    /// docs/dev/SECRETS-AND-CREDENTIALS.md, "The placeholder").
    #[error("secrets stored here can't be sent only to their hosts")]
    NoSlot,
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

#[derive(sqlx::FromRow)]
struct BindingRow {
    binding: Option<Json<StoredBinding>>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
    value_version: i64,
}

/// The binding columns a write leaves the row with.
struct Written {
    binding: Option<Json<StoredBinding>>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
}

/// A new value for one key, and the version it becomes.
struct ValueWrite<'a> {
    secret_path: &'a str,
    key: &'a str,
    value: &'a str,
    value_version: i64,
}

/// A rename of a bound secret: it would change the secret's slot, and a
/// rename carries no value (docs/dev/SECRETS-AND-CREDENTIALS.md,
/// "Re-entering the value").
#[derive(Debug, Error)]
#[error("a bound secret can't be renamed; set the new key with its value, then delete the old one")]
pub struct BoundSecretRename;

/// The change, in the words of [`SecretWriteError::ValueRequired`].
fn change_words(before: Option<&HostBinding>, after: Option<&HostBinding>) -> &'static str {
    match (before, after) {
        (None, Some(_)) => "binding a secret to hosts",
        (Some(_), None) => "making a secret plain",
        (Some(before), Some(after)) if before.presentation() != after.presentation() => {
            "changing how a secret is sent"
        }
        _ => "adding a host",
    }
}

fn read_binding(row: Option<&BindingRow>) -> Result<Option<HostBinding>, SecretWriteError> {
    // Read back under no deployment names: a name the deployment reserves
    // after a secret was bound refuses it at the next bind, not here.
    row.and_then(|row| row.binding.as_ref())
        .map(|Json(stored)| stored.parse(&ReservedHosts::default()))
        .transpose()
        .map_err(|_| SecretWriteError::Store(store_error("invalid-persisted-secret-binding")))
}

impl PostgresSecretStore {
    /// Set `key` at `secret_path` with `value`, or with no value for a change
    /// to a bound secret that needs none, and apply `binding`.
    pub async fn write_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: Option<&str>,
        binding: BindingWrite,
        reserved: &ReservedHosts,
    ) -> Result<(), SecretWriteError> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if !is_valid_secret_key(key) {
            return Err(store_error("invalid-secret-key").into());
        }
        if let Some(value) = value {
            validate_workload_secret_value(value.as_bytes())
                .map_err(|_| store_error("invalid-secret-value"))?;
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_scope(&mut tx, &context).await?;
        let row: Option<BindingRow> = sqlx::query_as(
            "SELECT binding, binding_id, binding_generation, value_version \
             FROM tenant_secrets WHERE path = $1 AND key = $2 FOR UPDATE",
        )
        .bind(secret_path)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| store_error("secret-binding-query-failed"))?;

        let before = read_binding(row.as_ref())?;
        let (after, preset) = match &binding {
            BindingWrite::Keep => (before.clone(), None),
            BindingWrite::Bind(stored) => (Some(stored.parse(reserved)?), stored.preset.clone()),
            BindingWrite::Plain => (None, None),
        };
        match value {
            Some(value) => {
                if let Some(after) = &after {
                    after.validate_value(value.as_bytes())?;
                }
            }
            None => {
                if before.is_none() && after.is_none() {
                    return Err(SecretWriteError::EmptyValue);
                }
                if before.is_none() || change_needs_value(before.as_ref(), after.as_ref()) {
                    return Err(SecretWriteError::ValueRequired(change_words(
                        before.as_ref(),
                        after.as_ref(),
                    )));
                }
            }
        }

        let generation = row.as_ref().map_or(0, |row| row.binding_generation);
        let written = Written {
            binding_id: match (&after, row.as_ref().and_then(|row| row.binding_id)) {
                (Some(_), None) => Some(Uuid::new_v4()),
                (_, kept) => kept,
            },
            binding_generation: if change_moves_generation(before.as_ref(), after.as_ref()) {
                generation + 1
            } else {
                generation
            },
            binding: after.as_ref().map(|after| {
                let mut stored = StoredBinding::from(after);
                stored.preset = match &binding {
                    BindingWrite::Keep => row
                        .as_ref()
                        .and_then(|row| row.binding.as_ref())
                        .and_then(|Json(kept)| kept.preset.clone()),
                    _ => preset.clone(),
                };
                Json(stored)
            }),
        };

        let mut generated_dek = None;
        match value {
            Some(value) => {
                let write = ValueWrite {
                    secret_path,
                    key,
                    value,
                    value_version: row.as_ref().map_or(1, |row| row.value_version + 1),
                };
                generated_dek = self
                    .upsert_value(&mut tx, &context, &write, &written)
                    .await?;
            }
            None => {
                sqlx::query(
                    "UPDATE tenant_secrets SET binding = $3, binding_id = $4, \
                     binding_generation = $5, updated_at = now() \
                     WHERE path = $1 AND key = $2",
                )
                .bind(secret_path)
                .bind(key)
                .bind(&written.binding)
                .bind(written.binding_id)
                .bind(written.binding_generation)
                .execute(&mut *tx)
                .await
                .map_err(|_| store_error("secret-binding-update-failed"))?;
            }
        }
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        // Cached only once the row that holds it is committed.
        if let Some((dek_id, dek)) = generated_dek {
            self.cache.lock().await.insert(dek_id, dek);
        }
        Ok(())
    }

    /// Encrypt and store the value, returning a newly generated DEK for the
    /// caller to cache after commit.
    async fn upsert_value(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        context: &DekContext,
        write: &ValueWrite<'_>,
        written: &Written,
    ) -> anyhow::Result<Option<(String, zeroize::Zeroizing<[u8; DEK_BYTES]>)>> {
        let ValueWrite {
            secret_path,
            key,
            value,
            value_version,
        } = *write;
        let existing = Self::fetch_dek_locked(tx, context).await?;
        let (dek_id, dek, generated) = if let Some(row) = existing {
            let dek = self.unwrap_dek(context, &row).await?;
            (row.dek_id, dek, false)
        } else {
            let generated = self
                .provider
                .generate(context)
                .await
                .map_err(envelope_error)?;
            let dek_id = Self::insert_generated_dek(tx, context, &generated).await?;
            (dek_id, generated.plaintext, true)
        };
        let coordinates = SecretCoordinates {
            context,
            path: secret_path,
            key,
        };
        let encrypted =
            encrypt_secret(&dek, &coordinates, value.as_bytes()).map_err(envelope_error)?;
        sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, storage_contract_version, \
              binding, binding_id, binding_generation, value_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $11, $12) \
             ON CONFLICT (path, key) DO UPDATE SET \
               dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, scope_id = EXCLUDED.scope_id, \
               ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce, \
               format = EXCLUDED.format, binding = EXCLUDED.binding, \
               binding_id = EXCLUDED.binding_id, \
               binding_generation = EXCLUDED.binding_generation, \
               value_version = EXCLUDED.value_version, updated_at = now()",
        )
        .bind(secret_path)
        .bind(key)
        .bind(&dek_id)
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .bind(encrypted.ciphertext)
        .bind(encrypted.nonce)
        .bind(encrypted.format)
        .bind(&written.binding)
        .bind(written.binding_id)
        .bind(written.binding_generation)
        .bind(value_version)
        .execute(&mut **tx)
        .await
        .map_err(|_| store_error("secret-upsert-failed"))?;
        Ok(generated.then_some((dek_id, dek)))
    }
}

#[cfg(test)]
mod database_tests;
