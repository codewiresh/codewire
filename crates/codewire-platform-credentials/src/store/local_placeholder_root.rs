//! One owner's local placeholder root (#6191): the key from which the
//! placeholder key of each local VM that owner runs on a platform profile is
//! derived (#4909; docs/dev/SECRETS-AND-CREDENTIALS.md, "Per-environment
//! placeholders"). Such a VM has no row in `environments`, so the hosted
//! per-environment keys (`placeholder_key`) cannot serve it.
//!
//! The root is sealed in `platform_local_placeholder_roots` like credential
//! material: a DEK from the credential-material KEK, scoped to the user, and
//! AES-GCM ciphertext whose associated data names the user and this purpose.
//! It is created once and never changes; there is no rotation path. The
//! user's deletion removes it. Nothing here caches the root or a derived key:
//! each call reads and opens the root, derives the one environment's key, and
//! drops the root.

use codewire_access::{EnvironmentId, OwnerId, PLACEHOLDER_KEY_BYTES, PlaceholderKey};
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

/// The envelope's key coordinate, which names this purpose; the path names
/// the user. Both are in the associated data.
const KEY: &str = "platform_local_placeholder_root/v1";

fn path(user: &OwnerId) -> String {
    format!("/platform-local-placeholder-roots/v1/{}", user.as_str())
}

fn context(user: &OwnerId) -> DekContext {
    DekContext {
        scope: TenantSecretScope::User,
        scope_id: user.as_str().to_owned(),
    }
}

impl PlatformCredentialStore {
    /// The placeholder key of `environment_id`, a local VM of `user`'s on a
    /// platform profile: derived from `user`'s local placeholder root, which
    /// is created on its first use (#6191). Both come from the delegation's
    /// admitted session, never from a frame.
    ///
    /// Two first uses may race: each inserts with `ON CONFLICT DO NOTHING`
    /// and then opens the row that is stored, never the root it generated,
    /// so both derive under the one root that won.
    pub async fn owner_local_placeholder_key(
        &self,
        user: &OwnerId,
        environment_id: &EnvironmentId,
    ) -> Result<PlaceholderKey, Error> {
        let context = context(user);
        let row = match self.local_placeholder_root_row(user).await? {
            Some(row) => row,
            None => {
                self.insert_local_placeholder_root(user, &context).await?;
                self.local_placeholder_root_row(user)
                    .await?
                    .ok_or(Error::NotFound)?
            }
        };
        let prepared = row.prepared(self.provider.kind())?;
        let dek = provider_call(self.provider.unwrap(&context, &prepared.wrapped)).await?;
        let path = path(user);
        let root = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: KEY,
            },
            &prepared.envelope,
        )
        .map_err(|_| Error::CorruptRecord)?;
        let root = PlaceholderKey::from_slice(&root).map_err(|_| Error::CorruptRecord)?;
        Ok(PlaceholderKey::owner_local(&root, environment_id))
    }

    async fn local_placeholder_root_row(
        &self,
        user: &OwnerId,
    ) -> Result<Option<MaterialRow>, Error> {
        sqlx::query_as(
            "SELECT kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
             ciphertext, nonce, format FROM platform_local_placeholder_roots WHERE user_id=$1",
        )
        .bind(user.as_str())
        .fetch_optional(&self.reader.pool)
        .await
        .map_err(database_error)
    }

    /// Seal a new root and insert it unless the user already has one. A user
    /// that does not exist has no row to refer to, and the insert fails.
    async fn insert_local_placeholder_root(
        &self,
        user: &OwnerId,
        context: &DekContext,
    ) -> Result<(), Error> {
        let mut root = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *root)
            .map_err(|_| Error::ProviderUnavailable)?;
        let generated = provider_call(self.provider.generate(context)).await?;
        validate_wrapper(&generated.wrapped, self.provider.kind())?;
        let path = path(user);
        let envelope = encrypt_secret(
            &generated.plaintext,
            &SecretCoordinates {
                context,
                path: &path,
                key: KEY,
            },
            &*root,
        )
        .map_err(|_| Error::CorruptRecord)?;
        sqlx::query(
            "INSERT INTO platform_local_placeholder_roots \
             (user_id, kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
              ciphertext, nonce, format) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user.as_str())
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
