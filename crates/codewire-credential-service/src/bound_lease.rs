//! A host-bound secret's grants and leases, inside the credential service
//! (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap" steps 1 and 2).
//!
//! The grants are the Pod's first-bind record, or a local VM's verified boot
//! record, read under the projection's authority: the same scope and
//! selection the epoch was admitted with, its creator, organization and
//! digest, each record kept only for a source the selection holds and a key
//! the environment doesn't set itself. Nothing a frame sends chooses one.
//!
//! A lease rereads the secret's row by its set's path and key, in the
//! tenant-secret access the projection already has, and checks its
//! `binding_id`, `binding_generation` and hosts against the record. Its
//! value is decrypted only for a lease that passed: the row's ciphertext is
//! selected only then, and only for a row that is bound.

use codewire_access::{FirstBindSecret, HostBinding, ReservedHosts, StoredBinding};
use codewire_credential_broker::bound_secret::{BoundSecretLeaseError, BoundSecretRow};
use codewire_credential_broker::platform::{PlatformRuntimeAuthority as _, PlatformRuntimeError};
use codewire_project::PlatformProjectionSelection;
use codewire_protected_store::secret_envelope::KekProvider;
use codewire_protected_store::secret_envelope::{
    DekContext, EncryptedTenantSecret, KekProviderKind, SecretCoordinates, WrappedDek,
    decrypt_secret,
};
use sqlx::{PgPool, Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::authority::{KubernetesPlatformRuntimeAuthority, SCOPE_QUERY, Scope};
use crate::projection::{FIRST_BIND_QUERY, METADATA_QUERY, ProjectionMetadata, paths};

/// The largest ciphertext a bound value has: 8 KiB and its tag.
const MAX_BOUND_CIPHERTEXT_BYTES: i32 = 8 * 1024 + 16;

/// One secret's row as a lease reads it. The ciphertext is selected only
/// when the lease asks for the value and the row is bound.
#[derive(sqlx::FromRow)]
struct BoundRow {
    dek_id: String,
    scope: String,
    scope_id: String,
    ciphertext: Option<Vec<u8>>,
    nonce: Vec<u8>,
    format: i16,
    storage_contract_version: i16,
    binding: Option<String>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
    value_version: i64,
}

const BOUND_ROW_QUERY: &str = "SELECT dek_id,scope,scope_id, \
     CASE WHEN $3 AND binding IS NOT NULL AND octet_length(ciphertext) BETWEEN 17 AND $4 \
     THEN ciphertext END AS ciphertext,nonce,format,storage_contract_version, \
     binding::text AS binding,binding_id,binding_generation,value_version \
     FROM public.tenant_secrets WHERE path=$1 AND key=$2";

#[derive(sqlx::FromRow)]
struct DekRow {
    key_name: String,
    key_version: i64,
    wrapped_dek: String,
    format: i16,
    provider: String,
    revision: i64,
}

const DEK_QUERY: &str = "SELECT key_name,key_version,wrapped_dek,format,provider,revision \
     FROM public.tenant_secret_deks WHERE dek_id=$1 AND scope=$2 AND scope_id=$3";

fn runtime_error(error: PlatformRuntimeError) -> BoundSecretLeaseError {
    match error {
        PlatformRuntimeError::Denied
        | PlatformRuntimeError::CreatorDeparted
        | PlatformRuntimeError::CreatorDisabled => BoundSecretLeaseError::Denied,
        PlatformRuntimeError::Unavailable => BoundSecretLeaseError::Unavailable,
    }
}

/// `row` checked against `secret`'s record for a request to `host`: a
/// deleted secret, one plain now or of another binding, and a host the
/// binding or the record no longer names are each refused by name; a row
/// that doesn't read back is a broken store and denied.
fn checked(
    row: Option<&BoundRow>,
    secret: &FirstBindSecret,
    host: &str,
) -> Result<(HostBinding, u64), BoundSecretLeaseError> {
    let row = row.ok_or(BoundSecretLeaseError::Deleted)?;
    let context =
        DekContext::from_secret_path(&secret.path).map_err(|_| BoundSecretLeaseError::Denied)?;
    if row.scope != context.scope.as_str()
        || row.scope_id != context.scope_id
        || row.storage_contract_version != 1
        || row.format != 1
        || row.nonce.len() != 12
    {
        return Err(BoundSecretLeaseError::Denied);
    }
    let (Some(binding), Some(binding_id)) = (&row.binding, row.binding_id) else {
        return Err(BoundSecretLeaseError::BindingChanged);
    };
    if binding_id.to_string() != secret.binding_id
        || u64::try_from(row.binding_generation).ok() != Some(secret.binding_generation)
    {
        return Err(BoundSecretLeaseError::BindingChanged);
    }
    let stored: StoredBinding =
        serde_json::from_str(binding).map_err(|_| BoundSecretLeaseError::Denied)?;
    // The credential service holds no deployment's names: the bind checked
    // them for this Pod, and its record is what is served.
    let binding = stored
        .parse(&ReservedHosts::default())
        .map_err(|_| BoundSecretLeaseError::Denied)?;
    if !binding.names(host) || !secret.names(host) {
        return Err(BoundSecretLeaseError::NotBoundToHost);
    }
    let value_version =
        u64::try_from(row.value_version).map_err(|_| BoundSecretLeaseError::Denied)?;
    Ok((binding, value_version))
}

/// The records an epoch grants: each one for a source `selection` holds and
/// a key the environment doesn't set itself.
pub(crate) fn selected_grants(
    recorded: impl IntoIterator<Item = FirstBindSecret>,
    selection: &PlatformProjectionSelection,
) -> Vec<FirstBindSecret> {
    let sources = paths(selection);
    recorded
        .into_iter()
        .filter(|secret| {
            sources.contains(&secret.path)
                && !selection.ordinary_keys.contains(&secret.key)
                && !selection.reserved_keys.contains(&secret.key)
        })
        .collect()
}

impl KubernetesPlatformRuntimeAuthority {
    /// The epoch's bound-secret grants: the Pod's first-bind record, under
    /// the scope and selection the epoch was admitted with. A Pod whose
    /// first bind recorded nothing has none.
    pub(crate) async fn bound_secret_grants(
        &self,
    ) -> Result<Vec<FirstBindSecret>, PlatformRuntimeError> {
        self.current_session().await?;
        let recorded = self
            .identities
            .bounded(async {
                let mut tx = self
                    .authority
                    .pool
                    .begin()
                    .await
                    .map_err(|_| PlatformRuntimeError::Unavailable)?;
                self.same_scope(&mut tx)
                    .await
                    .map_err(|_| PlatformRuntimeError::Denied)?;
                let recorded: Option<Option<String>> = sqlx::query_scalar(FIRST_BIND_QUERY)
                    .bind(&self.initial.scope.pod_uid)
                    .bind(&self.initial.scope.environment_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| PlatformRuntimeError::Unavailable)?;
                tx.commit()
                    .await
                    .map_err(|_| PlatformRuntimeError::Unavailable)?;
                recorded.ok_or(PlatformRuntimeError::Denied)
            })
            .await?;
        let Some(recorded) = recorded else {
            return Ok(Vec::new());
        };
        let recorded: Vec<FirstBindSecret> =
            serde_json::from_str(&recorded).map_err(|_| PlatformRuntimeError::Denied)?;
        Ok(selected_grants(recorded, &self.initial.selection))
    }

    /// The scope and the selection's metadata now, exactly as the epoch
    /// was admitted with them; anything else is denied.
    async fn same_scope(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), ()> {
        let scope: Option<Scope> = sqlx::query_as(SCOPE_QUERY)
            .bind(&self.initial.scope.environment_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(drop)?;
        let metadata: Option<ProjectionMetadata> = sqlx::query_as(METADATA_QUERY)
            .bind(&self.initial.scope.environment_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(drop)?;
        if scope.as_ref() == Some(&self.initial.scope)
            && metadata.as_ref() == Some(&self.initial.metadata)
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// What bounds each read of a lease: the caller's authority, live and
/// within its own deadline.
pub(crate) trait LeaseBounds {
    fn ensure_live(&self) -> Result<(), PlatformRuntimeError>;
    /// When the next read must have finished.
    fn read_deadline(&self) -> Result<tokio::time::Instant, PlatformRuntimeError>;
}

/// Where a lease reads a secret's row and decrypts its value: the selection
/// its epoch was admitted with, and the bounds its authority sets. A hosted
/// Pod and a local VM's delegation each have one.
pub(crate) struct LeaseSource<'a> {
    pub(crate) pool: &'a PgPool,
    pub(crate) provider: &'a dyn KekProvider,
    pub(crate) selection: &'a PlatformProjectionSelection,
    pub(crate) bounds: &'a (dyn LeaseBounds + Sync),
}

impl LeaseSource<'_> {
    async fn bounded<T>(
        &self,
        work: impl Future<Output = Result<T, PlatformRuntimeError>>,
    ) -> Result<T, PlatformRuntimeError> {
        self.bounds.ensure_live()?;
        let result = tokio::time::timeout_at(self.bounds.read_deadline()?, work).await;
        self.bounds.ensure_live()?;
        result.map_err(|_| PlatformRuntimeError::Unavailable)?
    }
}

/// One read of `secret`'s row, the ciphertext only with `value`, once
/// `secret` is one of the selection's sources.
async fn bound_row(
    source: &LeaseSource<'_>,
    secret: &FirstBindSecret,
    value: bool,
) -> Result<Option<BoundRow>, BoundSecretLeaseError> {
    if !paths(source.selection).contains(&secret.path) {
        return Err(BoundSecretLeaseError::Denied);
    }
    source
        .bounded(async {
            sqlx::query_as(BOUND_ROW_QUERY)
                .bind(&secret.path)
                .bind(&secret.key)
                .bind(value)
                .bind(MAX_BOUND_CIPHERTEXT_BYTES)
                .fetch_optional(source.pool)
                .await
                .map_err(|_| PlatformRuntimeError::Unavailable)
        })
        .await
        .map_err(runtime_error)
}

/// `secret`'s row now, checked against its record for `host`.
pub(crate) async fn lease_row(
    source: &LeaseSource<'_>,
    secret: &FirstBindSecret,
    host: &str,
) -> Result<BoundSecretRow, BoundSecretLeaseError> {
    let row = bound_row(source, secret, false).await?;
    let (binding, value_version) = checked(row.as_ref(), secret, host)?;
    Ok(BoundSecretRow {
        binding,
        value_version,
    })
}

/// The row's value, decrypted for a lease whose row passes every check
/// again, and its version.
pub(crate) async fn lease_value(
    source: &LeaseSource<'_>,
    secret: &FirstBindSecret,
    host: &str,
) -> Result<(u64, Zeroizing<Vec<u8>>), BoundSecretLeaseError> {
    let row = bound_row(source, secret, true).await?;
    let (_, value_version) = checked(row.as_ref(), secret, host)?;
    let row = row.ok_or(BoundSecretLeaseError::Deleted)?;
    let ciphertext = row
        .ciphertext
        .clone()
        .ok_or(BoundSecretLeaseError::Denied)?;
    let context =
        DekContext::from_secret_path(&secret.path).map_err(|_| BoundSecretLeaseError::Denied)?;
    let dek: DekRow = source
        .bounded(async {
            sqlx::query_as(DEK_QUERY)
                .bind(&row.dek_id)
                .bind(&row.scope)
                .bind(&row.scope_id)
                .fetch_optional(source.pool)
                .await
                .map_err(|_| PlatformRuntimeError::Unavailable)?
                .ok_or(PlatformRuntimeError::Denied)
        })
        .await
        .map_err(runtime_error)?;
    if dek.provider != "openbao-transit"
        || dek.key_name != "tenant-dek"
        || dek.revision <= 0
        || dek.format != 1
        || dek.wrapped_dek.len() > 4096
    {
        return Err(BoundSecretLeaseError::Denied);
    }
    let wrapped = WrappedDek {
        provider: KekProviderKind::OpenBaoTransit,
        key_name: dek.key_name,
        key_version: u32::try_from(dek.key_version)
            .ok()
            .filter(|version| *version > 0)
            .ok_or(BoundSecretLeaseError::Denied)?,
        ciphertext: dek.wrapped_dek.into_bytes(),
        nonce: None,
        format: dek.format,
    };
    let unwrapped = source
        .bounded(async {
            source
                .provider
                .unwrap(&context, &wrapped)
                .await
                .map_err(|_| PlatformRuntimeError::Unavailable)
        })
        .await
        .map_err(runtime_error)?;
    let value = decrypt_secret(
        &unwrapped,
        &SecretCoordinates {
            context: &context,
            path: &secret.path,
            key: &secret.key,
        },
        &EncryptedTenantSecret {
            ciphertext,
            nonce: row.nonce.clone(),
            format: row.format,
        },
    )
    .map_err(|_| BoundSecretLeaseError::Denied)?;
    source.bounds.ensure_live().map_err(runtime_error)?;
    Ok((value_version, value))
}

impl KubernetesPlatformRuntimeAuthority {
    /// Where this Pod's leases read.
    pub(crate) fn lease_source(&self) -> LeaseSource<'_> {
        LeaseSource {
            pool: &self.authority.pool,
            provider: self.authority.provider.as_ref(),
            selection: &self.initial.selection,
            bounds: &self.identities,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
    const BINDING: &str = r#"{"hosts":["api.fancy.com","uploads.fancy.com"],"presentation":{"kind":"header","headers":["Authorization"],"scheme":"Bearer"}}"#;

    fn secret() -> FirstBindSecret {
        FirstBindSecret {
            path: format!("/org-secrets/{ORG}"),
            key: "FANCY_TOKEN".into(),
            binding_id: Uuid::from_u128(7).to_string(),
            binding_generation: 2,
            prefix: None,
            hosts: vec!["api.fancy.com".into(), "uploads.fancy.com".into()],
        }
    }

    fn row() -> BoundRow {
        BoundRow {
            dek_id: "dek".into(),
            scope: "org".into(),
            scope_id: ORG.into(),
            ciphertext: None,
            nonce: vec![0; 12],
            format: 1,
            storage_contract_version: 1,
            binding: Some(BINDING.into()),
            binding_id: Some(Uuid::from_u128(7)),
            binding_generation: 2,
            value_version: 5,
        }
    }

    /// Each refusal the spec names, from the row against the record.
    #[test]
    fn a_row_is_checked_against_its_record() {
        let host = "api.fancy.com";
        assert_eq!(
            checked(Some(&row()), &secret(), host).map(|(_, version)| version),
            Ok(5)
        );
        assert_eq!(
            checked(None, &secret(), host).map(drop),
            Err(BoundSecretLeaseError::Deleted)
        );
        let plain = BoundRow {
            binding: None,
            ..row()
        };
        let rebound = BoundRow {
            binding_id: Some(Uuid::from_u128(8)),
            ..row()
        };
        let regenerated = BoundRow {
            binding_generation: 3,
            ..row()
        };
        for changed in [plain, rebound, regenerated] {
            assert_eq!(
                checked(Some(&changed), &secret(), host).map(drop),
                Err(BoundSecretLeaseError::BindingChanged)
            );
        }
        // A host removed from the binding, and one the record never named.
        let removed = BoundRow {
            binding: Some(BINDING.replace(",\"uploads.fancy.com\"", "")),
            ..row()
        };
        assert_eq!(
            checked(Some(&removed), &secret(), "uploads.fancy.com").map(drop),
            Err(BoundSecretLeaseError::NotBoundToHost)
        );
        let added = BoundRow {
            binding: Some(BINDING.replace(
                "\"uploads.fancy.com\"",
                "\"uploads.fancy.com\",\"new.fancy.com\"",
            )),
            ..row()
        };
        assert_eq!(
            checked(Some(&added), &secret(), "new.fancy.com").map(drop),
            Err(BoundSecretLeaseError::NotBoundToHost)
        );
        let elsewhere = BoundRow {
            scope_id: "1".repeat(32),
            ..row()
        };
        assert_eq!(
            checked(Some(&elsewhere), &secret(), host).map(drop),
            Err(BoundSecretLeaseError::Denied)
        );
    }
}
