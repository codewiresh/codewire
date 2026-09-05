//! Durable provider-operation coordination, not exactly-once OAuth delivery.
//!
//! Only an unstarted reservation can expire into a new attempt. Once start
//! commits, losing the caller or its acknowledgement never permits replay.
//! An unknown provider outcome is terminal until explicit owner replacement.
//! Protected result staging survives a lost promotion acknowledgement; neither
//! a stage nor a publication receipt admits a guest operation.

use std::fmt;

use codewire_access::{
    CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS, CredentialId, CredentialStatus, Owner,
};
use codewire_protected_store::ProtectedValue;
use codewire_protected_store::secret_envelope::{
    GeneratedDek, SECRET_FORMAT_V1, SecretCoordinates, decrypt_secret, encrypt_secret,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::store::{
    MaterialRow, PreparedMaterial, check_owner, compare_version, database_error, delete_material,
    generation, insert_material, load_record, provider_call, require_oauth_refresh,
    validate_wrapper,
};
use crate::{
    CredentialRecord, CredentialVersion, PlatformCredentialError as Error, PlatformCredentialStore,
};

/// Authority-private durable state. `Committed` is only an exact-attempt
/// receipt, retained until a superseding attempt or owner mutation removes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRefreshState {
    Reserved,
    Started,
    Staged,
    Committed,
    Unknown,
    Cancelled,
}

/// Material-free discovery for a trusted placement authority on any replica.
/// Neither an attempt ID nor a live deadline reconstructs a provider-send
/// permit. Live flags describe only the corresponding Reserved/Started phase
/// at the database-clock admission point; callers must use the mutation APIs
/// to recheck them. A committed attempt remains only a publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthRefreshAttemptInfo {
    pub attempt_id: Uuid,
    pub expected: CredentialVersion,
    pub state: OAuthRefreshState,
    pub reservation_live: bool,
    pub execution_live: bool,
}

impl OAuthRefreshState {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "started" => Ok(Self::Started),
            "staged" => Ok(Self::Staged),
            "committed" => Ok(Self::Committed),
            "unknown" => Ok(Self::Unknown),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Error::CorruptRecord),
        }
    }
}

#[derive(Clone)]
struct Identity {
    owner: Owner,
    credential_id: CredentialId,
    expected: CredentialVersion,
    attempt_id: Uuid,
}

impl Identity {
    fn new(
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<Self, Error> {
        expected.replaced()?;
        if attempt_id.is_nil() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            owner: owner.clone(),
            credential_id: id.clone(),
            expected,
            attempt_id,
        })
    }
}

/// A non-cloneable, process-local prepared DEK. This is not permission to send
/// a provider request. Dropping the permit zeroizes its plaintext DEK.
pub struct PreparedOAuthRefresh {
    identity: Identity,
    next: CredentialRecord,
    generated: GeneratedDek,
}

/// One successful durable reserved-to-started transition. Only this permit
/// authorizes starting the provider exchange; it must never be reconstructed
/// from a `Started` state query after an ambiguous acknowledgement.
pub struct StartedOAuthRefresh(PreparedOAuthRefresh);

/// One immutable encrypted provider result. Reuse this exact object when a
/// stage acknowledgement is ambiguous; do not reissue the provider request.
pub struct PreparedOAuthRefreshResult {
    identity: Identity,
    material: PreparedMaterial,
}

impl fmt::Debug for PreparedOAuthRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedOAuthRefresh([REDACTED])")
    }
}

impl fmt::Debug for StartedOAuthRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StartedOAuthRefresh([REDACTED])")
    }
}

impl fmt::Debug for PreparedOAuthRefreshResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedOAuthRefreshResult([REDACTED])")
    }
}

impl StartedOAuthRefresh {
    /// The broker must validate the provider's canonical bundle and identity
    /// before this call. No provider request, database access, or OpenBao call
    /// occurs here; the DEK was prepared before request start.
    pub fn prepare_result(
        &self,
        value: &ProtectedValue,
    ) -> Result<PreparedOAuthRefreshResult, Error> {
        let context = self.0.next.context();
        let envelope = encrypt_secret(
            &self.0.generated.plaintext,
            &SecretCoordinates {
                context: &context,
                path: &self.0.next.path(),
                key: &self.0.next.key(),
            },
            value.expose_secret(),
        )
        .map_err(|_| Error::CorruptRecord)?;
        Ok(PreparedOAuthRefreshResult {
            identity: self.0.identity.clone(),
            material: PreparedMaterial {
                envelope,
                wrapped: self.0.generated.wrapped.clone(),
            },
        })
    }
}

impl PlatformCredentialStore {
    /// Reserve one exact credential version for at most 60 database-clock
    /// seconds before start. Duplicate attempt IDs do not yield another permit.
    /// All OpenBao work completes before reservation locks or provider start.
    pub async fn begin_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<PreparedOAuthRefresh, Error> {
        let identity = Identity::new(owner, id, expected, attempt_id)?;
        let mut next = self.record(owner, id).await?;
        compare_version(&next, expected)?;
        require_oauth_refresh(&next)?;
        next.version = expected.replaced()?;
        next.metadata.revocation_generation = next.version.revocation_generation;
        let generated = provider_call(self.provider().generate(&next.context())).await?;
        validate_wrapper(&generated.wrapped, self.provider().kind())?;

        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let current = lock_record(self, &mut tx, &identity).await?;
        compare_version(&current, expected)?;
        require_oauth_refresh(&current)?;
        if current.metadata.provider != next.metadata.provider
            || current.metadata.authentication_kind != next.metadata.authentication_kind
        {
            return Err(Error::CorruptRecord);
        }
        if let Some(previous) = load_attempt(&mut tx, id).await? {
            if previous.attempt_id == attempt_id {
                return Err(Error::StaleRefresh);
            }
            match previous.state()? {
                OAuthRefreshState::Reserved if !previous.reservation_live => {}
                OAuthRefreshState::Committed | OAuthRefreshState::Cancelled => {}
                OAuthRefreshState::Unknown => return Err(Error::RefreshOutcomeUnknown),
                _ => return Err(Error::RefreshInProgress),
            }
            delete_refresh_attempt(&mut tx, id).await?;
        }
        sqlx::query("INSERT INTO platform_credential_refresh_attempts \
            (credential_id,attempt_id,expected_revocation_generation,expected_material_generation,state,reserved_until) \
            VALUES ($1,$2,$3,$4,'reserved',clock_timestamp()+interval '60 seconds')")
            .bind(id.as_str()).bind(attempt_id)
            .bind(generation(expected.revocation_generation)?).bind(generation(expected.material_generation)?)
            .execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("INSERT INTO platform_credential_refresh_material \
            (attempt_id,kek_provider,key_name,key_version,wrapped_dek,wrapped_format) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(attempt_id).bind(generated.wrapped.provider.as_str()).bind(&generated.wrapped.key_name)
            .bind(i64::from(generated.wrapped.key_version)).bind(&generated.wrapped.ciphertext)
            .bind(generated.wrapped.format).execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(PreparedOAuthRefresh {
            identity,
            next,
            generated,
        })
    }

    /// Consume the only prepared permit. An ambiguous database commit destroys
    /// this in-memory permit and leaves a possibly-started attempt, never a
    /// second permission to send. A caller must not retry the external exchange.
    pub async fn start_oauth_refresh(
        &self,
        prepared: PreparedOAuthRefresh,
    ) -> Result<StartedOAuthRefresh, Error> {
        let identity = &prepared.identity;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let current = lock_record(self, &mut tx, identity).await?;
        compare_version(&current, identity.expected)?;
        require_oauth_refresh(&current)?;
        let attempt = exact_attempt(&mut tx, identity).await?;
        if attempt.state()? != OAuthRefreshState::Reserved || !attempt.reservation_live {
            return Err(Error::StaleRefresh);
        }
        let changed = sqlx::query("WITH admission_time AS (SELECT clock_timestamp() AS admitted_at) \
            UPDATE platform_credential_refresh_attempts SET state='started',started_at=admission_time.admitted_at, \
            started_until=admission_time.admitted_at+($2::bigint * interval '1 second'),updated_at=admission_time.admitted_at FROM admission_time \
            WHERE credential_id=$1 AND state='reserved' AND reserved_until>admission_time.admitted_at")
            .bind(identity.credential_id.as_str())
            .bind(i64::try_from(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS).map_err(|_| Error::InvalidInput)?)
            .execute(&mut *tx).await.map_err(database_error)?.rows_affected();
        if changed != 1 {
            return Err(Error::StaleRefresh);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(StartedOAuthRefresh(prepared))
    }

    /// Durably retain an exact encrypted result. Same-result retries are
    /// harmless; another envelope for the same attempt cannot replace it.
    /// Initial staging rechecks the durable execution deadline at its final
    /// state-transition fence. Already staged results remain recoverable after
    /// that horizon.
    pub async fn stage_oauth_refresh(
        &self,
        result: &PreparedOAuthRefreshResult,
    ) -> Result<(), Error> {
        let identity = &result.identity;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let current = lock_record(self, &mut tx, identity).await?;
        let attempt = exact_attempt(&mut tx, identity).await?;
        if attempt.state()? == OAuthRefreshState::Committed {
            return Err(Error::StaleRefresh);
        }
        compare_version(&current, identity.expected)?;
        require_oauth_refresh(&current)?;
        match attempt.state()? {
            OAuthRefreshState::Staged => {
                let existing = load_staged(self, &mut tx, identity.attempt_id).await?;
                if existing.wrapped != result.material.wrapped
                    || existing.envelope != result.material.envelope
                {
                    return Err(Error::StaleRefresh);
                }
            }
            OAuthRefreshState::Started => {
                if !attempt.execution_live {
                    return Err(Error::StaleRefresh);
                }
                let wrapped = &result.material.wrapped;
                let changed = sqlx::query("UPDATE platform_credential_refresh_material SET ciphertext=$2,nonce=$3,format=$4 \
                    WHERE attempt_id=$1 AND ciphertext IS NULL AND nonce IS NULL AND format IS NULL \
                    AND kek_provider=$5 AND key_name=$6 AND key_version=$7 AND wrapped_dek=$8 AND wrapped_format=$9")
                    .bind(identity.attempt_id).bind(&result.material.envelope.ciphertext)
                    .bind(&result.material.envelope.nonce).bind(SECRET_FORMAT_V1)
                    .bind(wrapped.provider.as_str()).bind(&wrapped.key_name).bind(i64::from(wrapped.key_version))
                    .bind(&wrapped.ciphertext).bind(wrapped.format)
                    .execute(&mut *tx).await.map_err(database_error)?.rows_affected();
                if changed != 1 {
                    return Err(Error::CorruptRecord);
                }
                let changed = sqlx::query("UPDATE platform_credential_refresh_attempts SET state='staged',updated_at=clock_timestamp() \
                    WHERE credential_id=$1 AND state='started' AND started_until>clock_timestamp()")
                    .bind(identity.credential_id.as_str()).execute(&mut *tx).await.map_err(database_error)?.rows_affected();
                if changed != 1 {
                    return Err(Error::StaleRefresh);
                }
            }
            OAuthRefreshState::Unknown => return Err(Error::RefreshOutcomeUnknown),
            _ => return Err(Error::StaleRefresh),
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    /// Promote the already staged envelope without repeating the OAuth provider
    /// exchange. A KEK unwrap authenticates durable staging outside DB locks;
    /// an outage leaves that result available for a later recovery attempt.
    /// A repeated committed receipt reports that attempt's version, not current
    /// authorization or permission to use material.
    pub async fn promote_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<CredentialVersion, Error> {
        let identity = Identity::new(owner, id, expected, attempt_id)?;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let mut current = lock_record(self, &mut tx, &identity).await?;
        let attempt = exact_attempt(&mut tx, &identity).await?;
        if attempt.state()? == OAuthRefreshState::Committed {
            tx.commit().await.map_err(database_error)?;
            return expected.replaced();
        }
        compare_version(&current, expected)?;
        require_oauth_refresh(&current)?;
        if attempt.state()? != OAuthRefreshState::Staged {
            return Err(if attempt.state()? == OAuthRefreshState::Unknown {
                Error::RefreshOutcomeUnknown
            } else {
                Error::StaleRefresh
            });
        }
        let authenticated = load_staged(self, &mut tx, attempt_id).await?;
        tx.commit().await.map_err(database_error)?;
        current.version = expected.replaced()?;
        current.metadata.revocation_generation = current.version.revocation_generation;
        let context = current.context();
        let dek = provider_call(self.provider().unwrap(&context, &authenticated.wrapped)).await?;
        let plaintext = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &current.path(),
                key: &current.key(),
            },
            &authenticated.envelope,
        )
        .map_err(|_| Error::CorruptRecord)?;
        drop(plaintext);
        drop(dek);

        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let latest = lock_record(self, &mut tx, &identity).await?;
        let attempt = exact_attempt(&mut tx, &identity).await?;
        if attempt.state()? == OAuthRefreshState::Committed {
            tx.commit().await.map_err(database_error)?;
            return expected.replaced();
        }
        compare_version(&latest, expected)?;
        require_oauth_refresh(&latest)?;
        if attempt.state()? != OAuthRefreshState::Staged {
            return Err(Error::StaleRefresh);
        }
        if latest.metadata.provider != current.metadata.provider
            || latest.metadata.authentication_kind != current.metadata.authentication_kind
        {
            return Err(Error::CorruptRecord);
        }
        let material = load_staged(self, &mut tx, attempt_id).await?;
        if material.wrapped != authenticated.wrapped || material.envelope != authenticated.envelope
        {
            return Err(Error::CorruptRecord);
        }
        delete_material(&mut tx, id).await?;
        sqlx::query("UPDATE platform_credentials SET revocation_generation=$2,material_generation=$3,updated_at=clock_timestamp() WHERE id=$1")
            .bind(id.as_str()).bind(generation(current.version.revocation_generation)?)
            .bind(generation(current.version.material_generation)?).execute(&mut *tx).await.map_err(database_error)?;
        insert_material(&mut tx, &current, material).await?;
        delete_attempt_material(&mut tx, attempt_id).await?;
        sqlx::query("UPDATE platform_credential_refresh_attempts SET state='committed',updated_at=clock_timestamp() WHERE credential_id=$1")
            .bind(id.as_str()).execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(current.version)
    }

    /// Discover the current durable attempt without a caller-supplied UUID or
    /// any material/KEK access. The owner and credential fences match mutation
    /// lock order. This is not a general metadata-reader or send capability;
    /// terminal and hard-expired records remain discoverable for recovery.
    pub async fn current_oauth_refresh_attempt(
        &self,
        owner: &Owner,
        id: &CredentialId,
    ) -> Result<Option<OAuthRefreshAttemptInfo>, Error> {
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        check_owner(&mut *tx, owner, true).await?;
        load_record(&mut *tx, owner, id, true, self.catalog()).await?;
        let info = load_attempt(&mut tx, id)
            .await?
            .map(|attempt| attempt.info())
            .transpose()?;
        tx.commit().await.map_err(database_error)?;
        Ok(info)
    }

    /// Read material-free attempt state through the trusted authority. This
    /// query does not reconstruct a send permit or reopen a failed attempt.
    pub async fn oauth_refresh_state(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<OAuthRefreshState, Error> {
        let identity = Identity::new(owner, id, expected, attempt_id)?;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        lock_record(self, &mut tx, &identity).await?;
        let state = exact_attempt(&mut tx, &identity).await?.state()?;
        tx.commit().await.map_err(database_error)?;
        Ok(state)
    }

    /// Cancel only a reservation which never crossed request-start admission.
    /// Late aborts cannot delete a started, staged, or published provider result.
    pub async fn cancel_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<(), Error> {
        let identity = Identity::new(owner, id, expected, attempt_id)?;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let current = lock_record(self, &mut tx, &identity).await?;
        let attempt = exact_attempt(&mut tx, &identity).await?;
        compare_version(&current, expected)?;
        match attempt.state()? {
            OAuthRefreshState::Cancelled => {}
            OAuthRefreshState::Reserved => {
                delete_attempt_material(&mut tx, attempt_id).await?;
                sqlx::query("UPDATE platform_credential_refresh_attempts SET state='cancelled',updated_at=clock_timestamp() WHERE credential_id=$1")
                    .bind(id.as_str()).execute(&mut *tx).await.map_err(database_error)?;
            }
            OAuthRefreshState::Started | OAuthRefreshState::Unknown => {
                return Err(Error::RefreshOutcomeUnknown);
            }
            _ => return Err(Error::StaleRefresh),
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    /// Consume the exact process-local send-owner permit after an unsuccessful
    /// or ambiguous exchange with no durable result. Unlike another replica,
    /// this caller need not wait for the execution deadline. A lost database
    /// acknowledgement never reconstructs the permit: discover the attempt and
    /// use deadline-gated abandonment if it is still Started.
    pub async fn fail_oauth_refresh(&self, started: StartedOAuthRefresh) -> Result<(), Error> {
        self.fail_oauth_refresh_identity(&started.0.identity, false)
            .await
    }

    /// Fail closed on a Started attempt only after its durable database-clock
    /// execution deadline. Expiry is an abandonment fence, not proof of process
    /// death or permission to repeat the provider request. A concurrent stage
    /// wins permanently once durable; it must be promoted, never discarded.
    /// Exact Unknown acknowledgements are idempotent. Hard credential expiry
    /// does not prevent closing an unknown outcome; explicit owner replacement
    /// is required before further brokerage.
    pub async fn fail_abandoned_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        attempt_id: Uuid,
    ) -> Result<(), Error> {
        let identity = Identity::new(owner, id, expected, attempt_id)?;
        self.fail_oauth_refresh_identity(&identity, true).await
    }

    async fn fail_oauth_refresh_identity(
        &self,
        identity: &Identity,
        require_expired: bool,
    ) -> Result<(), Error> {
        let id = &identity.credential_id;
        let expected = identity.expected;
        let attempt_id = identity.attempt_id;
        let mut tx = self.pool().begin().await.map_err(database_error)?;
        let current = lock_record(self, &mut tx, identity).await?;
        let attempt = exact_attempt(&mut tx, identity).await?;
        if attempt.state()? == OAuthRefreshState::Unknown {
            if current.version != expected.revoked()?
                || current.metadata.status != CredentialStatus::RefreshFailed
            {
                return Err(Error::StaleVersion);
            }
        } else {
            compare_version(&current, expected)?;
            if attempt.state()? != OAuthRefreshState::Started
                || current.metadata.status != CredentialStatus::Active
            {
                return Err(Error::StaleRefresh);
            }
            if require_expired && attempt.execution_live {
                return Err(Error::RefreshInProgress);
            }
            let changed = sqlx::query("UPDATE platform_credential_refresh_attempts SET state='unknown',updated_at=clock_timestamp() \
                WHERE credential_id=$1 AND state='started' AND (NOT $2::boolean OR started_until<=clock_timestamp())")
                .bind(id.as_str()).bind(require_expired)
                .execute(&mut *tx).await.map_err(database_error)?.rows_affected();
            if changed != 1 {
                return Err(Error::RefreshInProgress);
            }
            delete_material(&mut tx, id).await?;
            delete_attempt_material(&mut tx, attempt_id).await?;
            sqlx::query("UPDATE platform_credentials SET status='refresh_failed',revocation_generation=$2,updated_at=clock_timestamp() WHERE id=$1")
                .bind(id.as_str()).bind(generation(expected.revoked()?.revocation_generation)?)
                .execute(&mut *tx).await.map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct AttemptRow {
    attempt_id: Uuid,
    expected_revocation_generation: i64,
    expected_material_generation: i64,
    state: String,
    reservation_live: bool,
    execution_live: bool,
}

impl AttemptRow {
    fn state(&self) -> Result<OAuthRefreshState, Error> {
        OAuthRefreshState::parse(&self.state)
    }

    fn info(&self) -> Result<OAuthRefreshAttemptInfo, Error> {
        let expected = CredentialVersion {
            revocation_generation: self
                .expected_revocation_generation
                .try_into()
                .map_err(|_| Error::CorruptRecord)?,
            material_generation: self
                .expected_material_generation
                .try_into()
                .map_err(|_| Error::CorruptRecord)?,
        };
        expected.replaced().map_err(|_| Error::CorruptRecord)?;
        if self.attempt_id.is_nil() {
            return Err(Error::CorruptRecord);
        }
        Ok(OAuthRefreshAttemptInfo {
            attempt_id: self.attempt_id,
            expected,
            state: self.state()?,
            reservation_live: self.reservation_live,
            execution_live: self.execution_live,
        })
    }
}

async fn lock_record(
    store: &PlatformCredentialStore,
    tx: &mut Transaction<'_, Postgres>,
    identity: &Identity,
) -> Result<CredentialRecord, Error> {
    check_owner(&mut **tx, &identity.owner, true).await?;
    load_record(
        &mut **tx,
        &identity.owner,
        &identity.credential_id,
        true,
        store.catalog(),
    )
    .await
}

async fn load_attempt(
    tx: &mut Transaction<'_, Postgres>,
    id: &CredentialId,
) -> Result<Option<AttemptRow>, Error> {
    sqlx::query_as(
        "SELECT attempt_id,expected_revocation_generation,expected_material_generation,state, \
        state='reserved' AND reserved_until>clock_timestamp() AS reservation_live, \
        state='started' AND COALESCE(started_until>clock_timestamp(),false) AS execution_live \
        FROM platform_credential_refresh_attempts WHERE credential_id=$1 FOR UPDATE",
    )
    .bind(id.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)
}

async fn exact_attempt(
    tx: &mut Transaction<'_, Postgres>,
    identity: &Identity,
) -> Result<AttemptRow, Error> {
    let attempt = load_attempt(tx, &identity.credential_id)
        .await?
        .ok_or(Error::StaleRefresh)?;
    if attempt.attempt_id != identity.attempt_id
        || attempt.expected_revocation_generation
            != generation(identity.expected.revocation_generation)?
        || attempt.expected_material_generation
            != generation(identity.expected.material_generation)?
    {
        return Err(Error::StaleRefresh);
    }
    Ok(attempt)
}

async fn load_staged(
    store: &PlatformCredentialStore,
    tx: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
) -> Result<PreparedMaterial, Error> {
    let row: MaterialRow = sqlx::query_as("SELECT kek_provider,key_name,key_version,wrapped_dek,wrapped_format,ciphertext,nonce,format \
        FROM platform_credential_refresh_material WHERE attempt_id=$1 AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND format IS NOT NULL FOR UPDATE")
        .bind(attempt_id).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(Error::CorruptRecord)?;
    row.prepared(store.provider().kind())
}

async fn delete_attempt_material(
    tx: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
) -> Result<(), Error> {
    sqlx::query("DELETE FROM platform_credential_refresh_material WHERE attempt_id=$1")
        .bind(attempt_id)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

pub(crate) async fn delete_refresh_attempt(
    tx: &mut Transaction<'_, Postgres>,
    id: &CredentialId,
) -> Result<(), Error> {
    sqlx::query("DELETE FROM platform_credential_refresh_attempts WHERE credential_id=$1")
        .bind(id.as_str())
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

/// Caller holds owner SHARE then credential UPDATE. An expired, never-started
/// reservation can be superseded; a started operation cannot be stolen.
pub(crate) async fn fence_refresh_mutation(
    tx: &mut Transaction<'_, Postgres>,
    id: &CredentialId,
) -> Result<(), Error> {
    if let Some(attempt) = load_attempt(tx, id).await? {
        match attempt.state()? {
            OAuthRefreshState::Reserved if !attempt.reservation_live => {}
            OAuthRefreshState::Committed
            | OAuthRefreshState::Cancelled
            | OAuthRefreshState::Unknown => {}
            _ => return Err(Error::RefreshInProgress),
        }
        delete_refresh_attempt(tx, id).await?;
    }
    Ok(())
}
