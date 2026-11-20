//! One hosted environment's placeholder key (#4001): the key its credential
//! placeholders are derived under (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Per-environment placeholders").
//!
//! The key is sealed in `platform_placeholder_keys` like credential material:
//! a DEK from the credential-material KEK, scoped to the environment's
//! organization, and AES-GCM ciphertext whose associated data names the
//! environment. It is created once and never changes, and the environment's
//! deletion removes it. Nothing here caches it: each call reads and opens it,
//! and the caller drops it once it has derived what it needs.

use codewire_access::{EnvironmentId, PLACEHOLDER_KEY_BYTES, PlaceholderKey};
use codewire_protected_store::secret_envelope::{
    DekContext, SECRET_FORMAT_V1, SecretCoordinates, TenantSecretScope, decrypt_secret,
    encrypt_secret,
};
use rand::RngCore as _;
use zeroize::Zeroizing;

use super::{
    MaterialRow, PlatformCredentialStore, database_error, provider_call, validate_wrapper,
};
use crate::PlatformCredentialError as Error;

/// The envelope's key coordinate; the path names the environment.
const KEY: &str = "placeholder-key/v1";

fn path(environment_id: &EnvironmentId) -> String {
    format!("/platform-placeholder-keys/v1/{}", environment_id.as_str())
}

impl PlatformCredentialStore {
    /// `environment_id`'s placeholder key, created on its first use.
    ///
    /// Two first uses may race: each inserts with `ON CONFLICT DO NOTHING`
    /// and then opens the row that is stored, never the key it generated, so
    /// both derive under the one key that won.
    pub async fn environment_placeholder_key(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<PlaceholderKey, Error> {
        let organization: String =
            sqlx::query_scalar("SELECT org_id FROM environments WHERE id=$1")
                .bind(environment_id.as_str())
                .fetch_optional(&self.reader.pool)
                .await
                .map_err(database_error)?
                .ok_or(Error::NotFound)?;
        let context = DekContext {
            scope: TenantSecretScope::Organization,
            scope_id: organization,
        };
        let row = match self.placeholder_key_row(environment_id).await? {
            Some(row) => row,
            None => {
                self.insert_placeholder_key(environment_id, &context)
                    .await?;
                self.placeholder_key_row(environment_id)
                    .await?
                    .ok_or(Error::NotFound)?
            }
        };
        let prepared = row.prepared(self.provider.kind())?;
        let dek = provider_call(self.provider.unwrap(&context, &prepared.wrapped)).await?;
        let path = path(environment_id);
        let key = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: KEY,
            },
            &prepared.envelope,
        )
        .map_err(|_| Error::CorruptRecord)?;
        PlaceholderKey::from_slice(&key).map_err(|_| Error::CorruptRecord)
    }

    async fn placeholder_key_row(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Option<MaterialRow>, Error> {
        sqlx::query_as(
            "SELECT kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
             ciphertext, nonce, format FROM platform_placeholder_keys WHERE environment_id=$1",
        )
        .bind(environment_id.as_str())
        .fetch_optional(&self.reader.pool)
        .await
        .map_err(database_error)
    }

    /// Seal a new key and insert it unless the environment already has one.
    async fn insert_placeholder_key(
        &self,
        environment_id: &EnvironmentId,
        context: &DekContext,
    ) -> Result<(), Error> {
        let mut key = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| Error::ProviderUnavailable)?;
        let generated = provider_call(self.provider.generate(context)).await?;
        validate_wrapper(&generated.wrapped, self.provider.kind())?;
        let path = path(environment_id);
        let envelope = encrypt_secret(
            &generated.plaintext,
            &SecretCoordinates {
                context,
                path: &path,
                key: KEY,
            },
            &*key,
        )
        .map_err(|_| Error::CorruptRecord)?;
        sqlx::query(
            "INSERT INTO platform_placeholder_keys \
             (environment_id, kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
              ciphertext, nonce, format) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (environment_id) DO NOTHING",
        )
        .bind(environment_id.as_str())
        .bind(generated.wrapped.provider.as_str())
        .bind(generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(generated.wrapped.ciphertext)
        .bind(generated.wrapped.format)
        .bind(envelope.ciphertext)
        .bind(envelope.nonce)
        .bind(SECRET_FORMAT_V1)
        .execute(&self.reader.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }
}
