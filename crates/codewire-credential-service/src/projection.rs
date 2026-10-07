//! One-launch application values, inside the isolated credential process.
//! Only the authenticated runtime's immutable source selection is readable.
//! Capture and final comparison share the writers' tenant advisory locks;
//! OpenBao/decryption happen outside SQL locks. Only recipient ciphertext leaves.

use std::collections::{BTreeMap, BTreeSet};

use codewire_credential_broker::platform::{
    PlatformRuntimeAuthority, PlatformRuntimeError as Error,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_project::PlatformProjectionSelection;
use codewire_protected_store::secret_envelope::{
    DekContext, EncryptedTenantSecret, KekProvider, KekProviderKind, SecretCoordinates, WrappedDek,
    decrypt_secret,
};
use codewire_workload_secrets::{
    EnvironmentProjection, MAX_ENVIRONMENT_PROJECTION_BYTES, MAX_WORKLOAD_SECRET_VALUE_BYTES,
    MAX_WORKLOAD_SECRETS, ProjectionContext, WorkloadSecretSource,
    resolve_workload_secret_metadata, seal_environment_projection, validate_projection_recipient,
    validate_workload_secret_key,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::authority::{KubernetesPlatformRuntimeAuthority, SCOPE_QUERY, Scope};

#[cfg(feature = "enrollment")]
pub(crate) mod composition;

#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ProjectionMetadata {
    pub(crate) organization_selected: bool,
    pub(crate) user_placement: Option<String>,
    pub(crate) project_reference: Option<String>,
    pub(crate) credential_reference: Option<String>,
    pub(crate) ordinary_keys: Vec<String>,
    pub(crate) selection_valid: bool,
}

impl ProjectionMetadata {
    pub(crate) fn selection(
        &self,
        scope: &Scope,
        reserved_keys: BTreeSet<String>,
    ) -> Result<PlatformProjectionSelection, Error> {
        if !self.selection_valid
            || self
                .user_placement
                .as_deref()
                .is_some_and(|placement| placement != "platform")
            || self.ordinary_keys.len() > MAX_WORKLOAD_SECRETS
        {
            return Err(Error::Denied);
        }
        let profile = match (
            &self.credential_reference,
            &scope.profile_id,
            scope.profile_revision,
        ) {
            (None, None, None) => None,
            (Some(reference), Some(id), Some(revision)) if revision > 0 => {
                if exact_id(reference)? != *id {
                    return Err(Error::Denied);
                }
                Some((id.clone(), revision as u64))
            }
            _ => return Err(Error::Denied),
        };
        let selection = PlatformProjectionSelection {
            creator: scope.creator.clone(),
            organization: scope.organization.clone(),
            organization_selected: self.organization_selected,
            project_id: self
                .project_reference
                .as_deref()
                .map(exact_id)
                .transpose()?,
            user_selected: self.user_placement.is_some(),
            profile,
            ordinary_keys: self.ordinary_keys.iter().cloned().collect(),
            reserved_keys,
        };
        if selection.ordinary_keys.len() != self.ordinary_keys.len() {
            return Err(Error::Denied);
        }
        selection.validate().map_err(|_| Error::Denied)?;
        Ok(selection)
    }
}

fn exact_id(reference: &str) -> Result<String, Error> {
    let raw = reference
        .strip_prefix("platform:id:")
        .ok_or(Error::Denied)?;
    let id = Uuid::parse_str(raw).map_err(|_| Error::Denied)?;
    if id.is_nil() || id.to_string() != raw {
        return Err(Error::Denied);
    }
    Ok(raw.to_owned())
}

pub(crate) const METADATA_QUERY: &str =
    "SELECT * FROM public.codewire_platform_projection_metadata($1)";

#[derive(PartialEq, Eq, sqlx::FromRow)]
struct KeyRow {
    key: String,
    scope: String,
    scope_id: String,
}

#[derive(PartialEq, Eq, sqlx::FromRow)]
struct EnvelopeRow {
    dek_id: String,
    scope: String,
    scope_id: String,
    // SQL bounds allocation even if a corrupt/old writer stored a huge value.
    ciphertext: Option<Vec<u8>>,
    nonce: Vec<u8>,
    format: i16,
    storage_contract_version: i16,
}

#[derive(PartialEq, Eq, sqlx::FromRow)]
struct DekRow {
    dek_id: String,
    scope: String,
    scope_id: String,
    provider: String,
    key_name: String,
    key_version: i64,
    wrapped_dek: String,
    format: i16,
    revision: i64,
}

#[derive(PartialEq, Eq)]
struct Winner {
    path: String,
    envelope: EnvelopeRow,
}

#[derive(PartialEq, Eq)]
pub(crate) struct Capture {
    inventories: Vec<(String, Vec<KeyRow>)>,
    winners: BTreeMap<String, Winner>,
    deks: BTreeMap<String, DekRow>,
}

fn selected_winners(
    inventories: &[(String, Vec<KeyRow>)],
    selection: &PlatformProjectionSelection,
) -> Result<BTreeMap<String, String>, Error> {
    let mut source_paths = BTreeMap::new();
    let mut names = Vec::new();
    for (path, keys) in inventories {
        let source = source_for_path(path)?;
        if source_paths.insert(source, path).is_some() {
            return Err(Error::Denied);
        }
        for key in keys {
            if selection.reserved_keys.contains(&key.key) {
                return Err(Error::Denied);
            }
            names.push((source, key.key.as_str()));
        }
    }
    names.extend(
        selection
            .ordinary_keys
            .iter()
            .map(|key| (WorkloadSecretSource::ExplicitEnvironment, key.as_str())),
    );
    // Use the shared union bound INCLUDING ordinary configured keys, not a
    // separate 256-key allowance for each source/configuration collection.
    resolve_workload_secret_metadata(names)
        .map_err(|_| Error::Denied)?
        .into_iter()
        .filter(|entry| entry.source != WorkloadSecretSource::ExplicitEnvironment)
        .map(|entry| {
            Ok((
                entry.key,
                (*source_paths.get(&entry.source).ok_or(Error::Denied)?).clone(),
            ))
        })
        .collect()
}

fn source_for_path(path: &str) -> Result<WorkloadSecretSource, Error> {
    if path.starts_with("/org-secrets/") {
        Ok(WorkloadSecretSource::Organization)
    } else if path.starts_with("/projects/") {
        Ok(WorkloadSecretSource::Project)
    } else if path.starts_with("/users/") {
        Ok(WorkloadSecretSource::User)
    } else {
        Err(Error::Denied)
    }
}

fn paths(selection: &PlatformProjectionSelection) -> Vec<String> {
    selection
        .source_identities()
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

// This is the existing PostgresSecretStore::lock_scope encoding, not another
// lock namespace. Tests bind the exact domain/length-prefix/BE-u64 recipe.
pub(crate) fn scope_lock_key(context: &DekContext) -> i64 {
    let mut hash = Sha256::new();
    hash.update(b"codewire/tenant-secret-scope-lock/v1\0");
    for field in [context.scope.as_str(), &context.scope_id] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    i64::from_be_bytes(hash.finalize()[..8].try_into().expect("SHA256 width"))
}

async fn capture<'a>(
    pool: &'a PgPool,
    scope: &Scope,
    expected_metadata: &ProjectionMetadata,
    selection: &PlatformProjectionSelection,
) -> Result<(Transaction<'a, Postgres>, Capture), Error> {
    let mut tx = pool.begin().await.map_err(|_| Error::Unavailable)?;
    let locked: bool = sqlx::query_scalar(
        "SELECT public.codewire_platform_lock_projection_authority($1,$2,$3,$4)",
    )
    .bind(&scope.environment_id)
    .bind(&scope.creator)
    .bind(&scope.organization)
    .bind(&selection.project_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable)?;
    if !locked {
        return Err(Error::Denied);
    }
    let current_scope: Scope = sqlx::query_as(SCOPE_QUERY)
        .bind(&scope.environment_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Denied)?;
    let current_metadata: ProjectionMetadata = sqlx::query_as(METADATA_QUERY)
        .bind(&scope.environment_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Denied)?;
    if current_scope != *scope || current_metadata != *expected_metadata {
        return Err(Error::Denied);
    }
    let captured = capture_in(&mut tx, selection).await?;
    Ok((tx, captured))
}

/// Capture the exact selected tenant-secret metadata while the caller retains
/// its own authority transaction. The caller must establish and retain its
/// identity/owner/source locks before this function; these advisory locks then
/// serialize the same tenant-secret scopes as their writers.
pub(crate) async fn capture_in(
    tx: &mut Transaction<'_, Postgres>,
    selection: &PlatformProjectionSelection,
) -> Result<Capture, Error> {
    let inventories = capture_inventories_in(tx, selection).await?;
    let winner_paths = selected_winners(&inventories, selection)?;
    capture_winners_in(tx, inventories, winner_paths).await
}

async fn capture_inventories_in(
    tx: &mut Transaction<'_, Postgres>,
    selection: &PlatformProjectionSelection,
) -> Result<Vec<(String, Vec<KeyRow>)>, Error> {
    let paths = paths(selection);
    let mut locks = BTreeSet::new();
    for path in &paths {
        let context = DekContext::from_secret_path(path).map_err(|_| Error::Denied)?;
        locks.insert(scope_lock_key(&context));
    }
    for key in locks {
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **tx)
            .await
            .map_err(|_| Error::Unavailable)?;
    }
    let mut inventories = Vec::new();
    for path in paths {
        let context = DekContext::from_secret_path(&path).map_err(|_| Error::Denied)?;
        let keys: Vec<KeyRow> = sqlx::query_as(
            "SELECT key,scope,scope_id FROM public.tenant_secrets WHERE path=$1 ORDER BY key LIMIT $2",
        ).bind(&path).bind((MAX_WORKLOAD_SECRETS + 1) as i64).fetch_all(&mut **tx).await
            .map_err(|_| Error::Unavailable)?;
        if keys.len() > MAX_WORKLOAD_SECRETS {
            return Err(Error::Denied);
        }
        for key in &keys {
            validate_workload_secret_key(&key.key).map_err(|_| Error::Denied)?;
            if key.scope != context.scope.as_str() || key.scope_id != context.scope_id {
                return Err(Error::Denied);
            }
        }
        inventories.push((path, keys));
    }
    Ok(inventories)
}

async fn capture_winners_in(
    tx: &mut Transaction<'_, Postgres>,
    inventories: Vec<(String, Vec<KeyRow>)>,
    winner_paths: BTreeMap<String, String>,
) -> Result<Capture, Error> {
    let mut captured = Capture {
        inventories,
        winners: BTreeMap::new(),
        deks: BTreeMap::new(),
    };
    let mut encoded_len = 4_usize;
    for (key, path) in winner_paths {
        let context = DekContext::from_secret_path(&path).map_err(|_| Error::Denied)?;
        let envelope: EnvelopeRow = sqlx::query_as(
            "SELECT dek_id,scope,scope_id,CASE WHEN octet_length(ciphertext) BETWEEN 17 AND $3 \
             THEN ciphertext END AS ciphertext,nonce,format,storage_contract_version \
             FROM public.tenant_secrets WHERE path=$1 AND key=$2",
        )
        .bind(&path)
        .bind(&key)
        .bind((MAX_WORKLOAD_SECRET_VALUE_BYTES + 16) as i32)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Denied)?;
        let ciphertext = envelope.ciphertext.as_ref().ok_or(Error::Denied)?;
        if envelope.scope != context.scope.as_str()
            || envelope.scope_id != context.scope_id
            || envelope.storage_contract_version != 1
            || envelope.format != 1
            || envelope.nonce.len() != 12
        {
            return Err(Error::Denied);
        }
        encoded_len = encoded_len
            .checked_add(8 + key.len() + ciphertext.len() - 16)
            .ok_or(Error::Denied)?;
        if encoded_len > MAX_ENVIRONMENT_PROJECTION_BYTES {
            return Err(Error::Denied);
        }
        if !captured.deks.contains_key(&envelope.dek_id) {
            let dek: DekRow = sqlx::query_as(
                "SELECT dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format,revision \
                 FROM public.tenant_secret_deks WHERE dek_id=$1 AND scope=$2 AND scope_id=$3",
            ).bind(&envelope.dek_id).bind(&envelope.scope).bind(&envelope.scope_id)
                .fetch_optional(&mut **tx).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Denied)?;
            if dek.provider != "openbao-transit"
                || dek.key_name != "tenant-dek"
                || dek.revision <= 0
                || dek.format != 1
                || dek.wrapped_dek.len() > 4096
            {
                return Err(Error::Denied);
            }
            captured.deks.insert(dek.dek_id.clone(), dek);
        }
        captured.winners.insert(key, Winner { path, envelope });
    }
    Ok(captured)
}

impl Capture {
    pub(crate) async fn decrypt(
        &self,
        provider: &dyn KekProvider,
        context: &ProjectionContext,
    ) -> Result<EnvironmentProjection, Error> {
        let mut deks = BTreeMap::new();
        for (id, row) in &self.deks {
            ensure_deadline(context)?;
            let winner = self
                .winners
                .values()
                .find(|winner| &winner.envelope.dek_id == id)
                .ok_or(Error::Denied)?;
            let dek_context =
                DekContext::from_secret_path(&winner.path).map_err(|_| Error::Denied)?;
            let wrapped = WrappedDek {
                provider: KekProviderKind::OpenBaoTransit,
                key_name: row.key_name.clone(),
                key_version: u32::try_from(row.key_version)
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or(Error::Denied)?,
                ciphertext: row.wrapped_dek.as_bytes().to_vec(),
                nonce: None,
                format: row.format,
            };
            let dek = provider
                .unwrap(&dek_context, &wrapped)
                .await
                .map_err(|_| Error::Unavailable)?;
            ensure_deadline(context)?;
            deks.insert(id.clone(), dek);
        }
        let mut entries = Vec::with_capacity(self.winners.len());
        for (key, winner) in &self.winners {
            ensure_deadline(context)?;
            let dek_context =
                DekContext::from_secret_path(&winner.path).map_err(|_| Error::Denied)?;
            let coordinates = SecretCoordinates {
                context: &dek_context,
                path: &winner.path,
                key,
            };
            let envelope = EncryptedTenantSecret {
                ciphertext: winner
                    .envelope
                    .ciphertext
                    .as_ref()
                    .ok_or(Error::Denied)?
                    .clone(),
                nonce: winner.envelope.nonce.clone(),
                format: winner.envelope.format,
            };
            let dek = deks.get(&winner.envelope.dek_id).ok_or(Error::Denied)?;
            let value = decrypt_secret(dek, &coordinates, &envelope).map_err(|_| Error::Denied)?;
            entries.push((key.clone(), value));
        }
        EnvironmentProjection::from_entries(entries).map_err(|_| Error::Denied)
    }
}

impl KubernetesPlatformRuntimeAuthority {
    pub(crate) async fn project(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, Error> {
        if !request.local_inventories.is_empty() {
            return Err(Error::Denied);
        }
        let request_id = Uuid::parse_str(&request.request_id).map_err(|_| Error::Denied)?;
        if request_id.is_nil() || request_id.to_string() != request.request_id {
            return Err(Error::Denied);
        }
        let recipient: [u8; 32] = request
            .recipient_public_key
            .try_into()
            .map_err(|_| Error::Denied)?;
        validate_projection_recipient(recipient).map_err(|_| Error::Denied)?;
        let selection_sha256 = self.initial.selection.sha256().map_err(|_| Error::Denied)?;
        if request.selection_sha256.as_slice() != selection_sha256 {
            return Err(Error::Denied);
        }
        let environment =
            Uuid::parse_str(&self.initial.scope.environment_id).map_err(|_| Error::Denied)?;
        let context = ProjectionContext {
            environment_id: *environment.as_bytes(),
            operation_generation: self.initial.scope.generation as u64,
            selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        ensure_deadline(&context)?;
        // Original verified identity and monotonic request deadlines both bound
        // every awaited phase. Dropping the bridge task drops this owner/SQL tx.
        let remaining = context
            .deadline_unix_ms
            .checked_sub(unix_millis()?)
            .ok_or(Error::Denied)?;
        tokio::time::timeout(
            std::time::Duration::from_millis(remaining),
            self.identities.bounded(async {
                self.current_session().await?;
                let (tx, captured) = capture(
                    &self.authority.pool,
                    &self.initial.scope,
                    &self.initial.metadata,
                    &self.initial.selection,
                )
                .await?;
                ensure_deadline(&context)?;
                tx.commit().await.map_err(|_| Error::Unavailable)?;
                let values = captured
                    .decrypt(self.authority.provider.as_ref(), &context)
                    .await?;
                // Token rotation never extends this channel; both live Pod/controller
                // identity and canonical provider/source selection are checked again.
                self.current_session().await?;
                let (tx, current) = capture(
                    &self.authority.pool,
                    &self.initial.scope,
                    &self.initial.metadata,
                    &self.initial.selection,
                )
                .await?;
                if captured != current {
                    return Err(Error::Denied);
                }
                self.identities.ensure_live()?;
                ensure_deadline(&context)?;
                let sealed =
                    seal_environment_projection(values, &context, recipient, unix_millis()?)
                        .map_err(|_| Error::Denied)?;
                tx.commit().await.map_err(|_| Error::Unavailable)?;
                self.identities.ensure_live()?;
                ensure_deadline(&context)?;
                Ok(sealed)
            }),
        )
        .await
        .map_err(|_| Error::Denied)?
    }
}

fn ensure_deadline(context: &ProjectionContext) -> Result<(), Error> {
    context
        .validate_at(unix_millis()?)
        .map_err(|_| Error::Denied)
}

fn unix_millis() -> Result<u64, Error> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests;
