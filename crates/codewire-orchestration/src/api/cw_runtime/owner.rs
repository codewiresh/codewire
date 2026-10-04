//! Durable metadata ownership. No method here dispatches a daemon command,
//! uploads bytes, changes a Pod or resolves a latest credential/channel.
//!
//! A fresh successful Issued commit returns a nonserializable permit. Loading
//! a request, retrying admission, losing a COMMIT response, or observing a
//! matching Store digest never recreates one. The later adapter must keep its
//! captured channel and perform at most the closed effect named by that permit.

use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    EnvironmentRuntimeLeaseSettlement, acquire_environment_runtime_mutation_lease_in,
    bound_environment_runtime_transaction, settle_environment_runtime_mutation_lease_in,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::CapturedPlatformCwRuntime;
use super::model::{
    CapturedBindingFacts, CheckpointAcknowledgement, EffectReceipt, MAX_CHECKPOINTS,
    MAX_JSON_BYTES, RuntimeAction, RuntimeEffect, RuntimeMutation, RuntimePhase, bounded_json,
    conflict, fingerprint, invalid_request, unavailable,
};
use crate::api::environments::lock_cw_runtime_operator_in;
use crate::confidential_storage::FeatureFlags;
use crate::worker::workspace_binding::live_cw_runtime_binding;

#[cfg(test)]
#[path = "database_tests.rs"]
mod database_tests;

const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct RuntimeJournal {
    pool: PgPool,
    flags: FeatureFlags,
}

/// Value-blind, nonsecret observation. Ownership and future dispatch permits
/// are deliberately absent from the serializable form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequest {
    pub mutation: RuntimeMutation,
    pub binding: CapturedBindingFacts,
    pub actor_user_id: String,
    pub phase: RuntimePhase,
    pub checkpoint: i32,
    pub effect: Option<RuntimeEffect>,
    pub acknowledgements: Vec<CheckpointAcknowledgement>,
    pub error_code: Option<String>,
    pub admitted_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub terminal_at: Option<DateTime<Utc>>,
}

pub enum Admission {
    Owned {
        request: Box<RuntimeRequest>,
        owner: RequestOwner,
    },
    Existing(Box<RuntimeRequest>),
}

/// Only fresh, known-committed admission creates this capability. It has no
/// deserializer, public constructor or clone, and holds no provider material.
pub struct RequestOwner {
    request_id: Uuid,
    owner_id: Uuid,
    fingerprint: String,
    organization_id: String,
    environment_id: String,
}

/// Authorizes exactly one later effect, only after its durable Issued commit.
/// There is no retry or recovery constructor. This component proves the
/// journal boundary, not execution of that future command.
pub struct IssuedEffect {
    owner: RequestOwner,
    checkpoint: i32,
    effect: RuntimeEffect,
}

impl IssuedEffect {
    pub fn request_id(&self) -> Uuid {
        self.owner.request_id
    }
    pub fn checkpoint(&self) -> i32 {
        self.checkpoint
    }
    pub fn effect(&self) -> RuntimeEffect {
        self.effect
    }
}

#[derive(Clone, Copy)]
pub enum KnownFailure {
    CancelledBeforeDispatch,
    CommandRefused,
}

impl KnownFailure {
    fn code(self) -> &'static str {
        match self {
            Self::CancelledBeforeDispatch => "cw_runtime_cancelled_before_dispatch",
            Self::CommandRefused => "cw_runtime_command_refused",
        }
    }
}

#[derive(sqlx::FromRow)]
struct SavedRequest {
    request_id: Uuid,
    organization_id: String,
    environment_id: String,
    actor_user_id: String,
    via_api_key: bool,
    delegated_organization_id: Option<String>,
    pod_uid: Uuid,
    fingerprint: String,
    request_json: serde_json::Value,
    binding_json: serde_json::Value,
    expected_store_generation: String,
    owner_id: Uuid,
    mutation_lease_id: String,
    phase: String,
    checkpoint: i32,
    effect: Option<String>,
    acknowledgements: serde_json::Value,
    error_code: Option<String>,
    admitted_at: DateTime<Utc>,
    issued_at: Option<DateTime<Utc>>,
    terminal_at: Option<DateTime<Utc>>,
}

impl SavedRequest {
    fn decode(&self) -> AppResult<RuntimeRequest> {
        // The SQL constraints also bound these. Revalidate typed facts and the
        // fingerprint so malformed durable metadata never becomes authority.
        for value in [
            &self.request_json,
            &self.binding_json,
            &self.acknowledgements,
        ] {
            if value.to_string().len() > MAX_JSON_BYTES {
                return Err(unavailable());
            }
        }
        let mutation: RuntimeMutation =
            serde_json::from_value(self.request_json.clone()).map_err(|_| unavailable())?;
        let binding: CapturedBindingFacts =
            serde_json::from_value(self.binding_json.clone()).map_err(|_| unavailable())?;
        mutation.validate().map_err(|_| unavailable())?;
        binding.validate().map_err(|_| unavailable())?;
        if mutation.request_id != self.request_id
            || mutation.expected_store_generation.to_string() != self.expected_store_generation
            || binding.organization_id != self.organization_id
            || binding.environment_id != self.environment_id
            || binding.pod_uid != self.pod_uid.to_string()
            || self.via_api_key != self.delegated_organization_id.is_some()
            || self
                .delegated_organization_id
                .as_deref()
                .is_some_and(|o| o != self.organization_id)
            || fingerprint(
                &self.actor_user_id,
                self.via_api_key,
                self.delegated_organization_id.as_deref(),
                &mutation,
                &binding,
            )? != self.fingerprint
            || self.owner_id.is_nil()
        {
            return Err(unavailable());
        }
        let phase = parse_enum(&self.phase)?;
        let effect = self.effect.as_deref().map(parse_enum).transpose()?;
        let acknowledgements: Vec<CheckpointAcknowledgement> =
            serde_json::from_value(self.acknowledgements.clone()).map_err(|_| unavailable())?;
        let request = RuntimeRequest {
            mutation,
            binding,
            actor_user_id: self.actor_user_id.clone(),
            phase,
            checkpoint: self.checkpoint,
            effect,
            acknowledgements,
            error_code: self.error_code.clone(),
            admitted_at: self.admitted_at,
            issued_at: self.issued_at,
            terminal_at: self.terminal_at,
        };
        validate_history(&request).map_err(|_| unavailable())?;
        Ok(request)
    }

    fn require_owner(&self, owner: &RequestOwner) -> AppResult<()> {
        if self.request_id != owner.request_id
            || self.owner_id != owner.owner_id
            || self.fingerprint != owner.fingerprint
            || self.organization_id != owner.organization_id
            || self.environment_id != owner.environment_id
        {
            return Err(conflict());
        }
        Ok(())
    }

    fn owner(&self) -> RequestOwner {
        RequestOwner {
            request_id: self.request_id,
            owner_id: self.owner_id,
            fingerprint: self.fingerprint.clone(),
            organization_id: self.organization_id.clone(),
            environment_id: self.environment_id.clone(),
        }
    }
}

impl RuntimeJournal {
    pub fn new(pool: PgPool, flags: FeatureFlags) -> Self {
        Self { pool, flags }
    }

    /// Use only the row already admitted with an actual Pod probe and captured
    /// Pod channel. The transaction rechecks that entire row under its locks.
    pub async fn admit(
        &self,
        captured: &CapturedPlatformCwRuntime,
        user: &AuthUser,
        mutation: RuntimeMutation,
    ) -> AppResult<Admission> {
        self.admit_facts(
            CapturedBindingFacts::from(&captured.row),
            user.clone(),
            mutation,
        )
        .await
    }

    async fn admit_facts(
        &self,
        binding: CapturedBindingFacts,
        user: AuthUser,
        mutation: RuntimeMutation,
    ) -> AppResult<Admission> {
        mutation.validate()?;
        binding.validate()?;
        validate_principal(&user, &binding.organization_id)?;
        let journal = self.clone();
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            let result = journal.admit_in(&mut tx, &binding, &user, &mutation).await;
            match result {
                Ok(admission) => {
                    // On an ambiguous commit, return no ownership capability.
                    // An exact UUID retry observes any saved row, never reissues.
                    tx.commit().await.map_err(|_| unavailable())?;
                    Ok(admission)
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    Err(error)
                }
            }
        })
        .await
    }

    async fn admit_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        binding: &CapturedBindingFacts,
        user: &AuthUser,
        mutation: &RuntimeMutation,
    ) -> AppResult<Admission> {
        let (org, env) = (&binding.organization_id, &binding.environment_id);
        lock_cw_runtime_operator_in(tx, user, org, env, self.flags).await?;
        let delegated = user.via_api_key.then_some(user.org_id.as_deref()).flatten();
        let expected = fingerprint(
            &user.user_id,
            user.via_api_key,
            delegated,
            mutation,
            binding,
        )?;
        if let Some(saved) = load_in(tx, mutation.request_id, true).await? {
            if saved.organization_id != *org
                || saved.environment_id != *env
                || saved.fingerprint != expected
            {
                return Err(conflict());
            }
            return Ok(Admission::Existing(Box::new(saved.decode()?)));
        }
        lock_binding_in(tx, binding).await?;
        let unresolved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM environment_cw_runtime_requests WHERE environment_id=$1 \
             AND phase IN ('admitted','issued','acknowledged','unknown'))",
        )
        .bind(env)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        if unresolved {
            return Err(conflict());
        }
        let lease = acquire_environment_runtime_mutation_lease_in(tx, org, env).await?;
        let request_json = serde_json::from_slice::<serde_json::Value>(&bounded_json(mutation)?)
            .map_err(|_| invalid_request())?;
        let binding_json = serde_json::from_slice::<serde_json::Value>(&bounded_json(binding)?)
            .map_err(|_| invalid_request())?;
        let saved: SavedRequest = sqlx::query_as(
            "INSERT INTO environment_cw_runtime_requests \
             (request_id,organization_id,environment_id,actor_user_id,via_api_key,delegated_organization_id,\
              pod_uid,fingerprint,request_json,binding_json,expected_store_generation,owner_id,mutation_lease_id) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *",
        ).bind(mutation.request_id).bind(org).bind(env).bind(&user.user_id).bind(user.via_api_key)
            .bind(delegated).bind(Uuid::parse_str(&binding.pod_uid).map_err(|_| invalid_request())?)
            .bind(expected).bind(request_json).bind(binding_json)
            .bind(mutation.expected_store_generation.to_string()).bind(Uuid::new_v4()).bind(lease.id)
            .fetch_one(&mut **tx).await.map_err(|_| conflict())?;
        Ok(Admission::Owned {
            request: Box::new(saved.decode()?),
            owner: saved.owner(),
        })
    }

    /// A read returns saved evidence and no owner or effect permission. Current
    /// operator checks still apply, but it never substitutes a replacement Pod.
    pub async fn observe(
        &self,
        user: &AuthUser,
        org: &str,
        env: &str,
        request_id: Uuid,
    ) -> AppResult<RuntimeRequest> {
        let (journal, user, org, env) =
            (self.clone(), user.clone(), org.to_owned(), env.to_owned());
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            lock_cw_runtime_operator_in(&mut tx, &user, &org, &env, journal.flags).await?;
            let saved = load_in(&mut tx, request_id, false)
                .await?
                .ok_or_else(conflict)?;
            if saved.organization_id != org || saved.environment_id != env {
                return Err(conflict());
            }
            let request = saved.decode()?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(request)
        })
        .await
    }

    /// Commit Issued before returning the one effect permit. Permission and the
    /// exact original binding are rechecked for every new effect, including
    /// bootstrap/staging/cleanup. A revoked operator cannot use an old capture.
    pub async fn issue(
        &self,
        owner: &RequestOwner,
        user: &AuthUser,
        expected_checkpoint: i32,
        effect: RuntimeEffect,
    ) -> AppResult<IssuedEffect> {
        let (journal, owner, user) = (self.clone(), copy_owner(owner), user.clone());
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            lock_cw_runtime_operator_in(
                &mut tx,
                &user,
                &owner.organization_id,
                &owner.environment_id,
                journal.flags,
            )
            .await?;
            let saved = load_in(&mut tx, owner.request_id, false)
                .await?
                .ok_or_else(conflict)?;
            saved.require_owner(&owner)?;
            let request = saved.decode()?;
            require_principal(&saved, &user)?;
            lock_binding_in(&mut tx, &request.binding).await?;
            let saved = load_in(&mut tx, owner.request_id, true)
                .await?
                .ok_or_else(conflict)?;
            saved.require_owner(&owner)?;
            let request = saved.decode()?;
            if request.checkpoint != expected_checkpoint || next_effect(&request)? != effect {
                return Err(conflict());
            }
            let next_checkpoint = expected_checkpoint
                .checked_add(1)
                .filter(|n| *n <= MAX_CHECKPOINTS)
                .ok_or_else(conflict)?;
            sqlx::query(
                "UPDATE environment_cw_runtime_requests SET phase='issued',checkpoint=$2,effect=$3,\
                 issued_at=clock_timestamp(),updated_at=clock_timestamp() WHERE request_id=$1",
            )
            .bind(owner.request_id)
            .bind(next_checkpoint)
            .bind(effect.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(IssuedEffect {
                owner,
                checkpoint: next_checkpoint,
                effect,
            })
        })
        .await
    }

    /// A saved successful closed command result. This does not inspect Store
    /// state or attribute a matching digest to a missing acknowledgement.
    pub async fn acknowledge(
        &self,
        issued: &IssuedEffect,
        receipt: EffectReceipt,
    ) -> AppResult<RuntimeRequest> {
        let (journal, owner, checkpoint, effect) = (
            self.clone(),
            copy_owner(&issued.owner),
            issued.checkpoint,
            issued.effect,
        );
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            bound_environment_runtime_transaction(&mut tx).await?;
            let saved = load_in(&mut tx, owner.request_id, true).await?.ok_or_else(conflict)?;
            saved.require_owner(&owner)?;
            let mut request = saved.decode()?;
            require_issued(&request, checkpoint, effect)?;
            validate_receipt(&request, effect, &receipt)?;
            request.acknowledgements.push(CheckpointAcknowledgement { checkpoint, effect, receipt });
            let json = serde_json::from_slice::<serde_json::Value>(&bounded_json(&request.acknowledgements)?)
                .map_err(|_| invalid_request())?;
            let saved: SavedRequest = sqlx::query_as(
                "UPDATE environment_cw_runtime_requests SET phase='acknowledged',acknowledgements=$2,\
                 updated_at=clock_timestamp() WHERE request_id=$1 RETURNING *",
            ).bind(owner.request_id).bind(json).fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
            let result = saved.decode()?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(result)
        }).await
    }

    /// After the final cleanup acknowledgement, atomically close the journal
    /// and release its original lease. Revocation does not block recording an
    /// already issued outcome, and this method cannot dispatch another effect.
    pub async fn succeed(&self, owner: &RequestOwner) -> AppResult<RuntimeRequest> {
        self.settle(copy_owner(owner), Settlement::Succeeded).await
    }

    /// A known failure before the next effect (admitted/acknowledged only).
    /// In particular this is not an escape hatch from an Issued uncertainty.
    pub async fn cancel(&self, owner: &RequestOwner) -> AppResult<RuntimeRequest> {
        self.settle(copy_owner(owner), Settlement::Cancelled).await
    }

    /// Record only an explicit closed command refusal or non-dispatch outcome.
    /// A timeout/disconnect/cancel after sending must instead remain Unknown.
    pub async fn fail_known(
        &self,
        issued: &IssuedEffect,
        failure: KnownFailure,
    ) -> AppResult<RuntimeRequest> {
        self.settle(
            copy_owner(&issued.owner),
            Settlement::Refused {
                checkpoint: issued.checkpoint,
                effect: issued.effect,
                failure,
            },
        )
        .await
    }

    pub async fn mark_unknown(&self, issued: &IssuedEffect) -> AppResult<RuntimeRequest> {
        self.settle(
            copy_owner(&issued.owner),
            Settlement::Unknown {
                checkpoint: issued.checkpoint,
                effect: issued.effect,
            },
        )
        .await
    }

    async fn settle(
        &self,
        owner: RequestOwner,
        settlement: Settlement,
    ) -> AppResult<RuntimeRequest> {
        let journal = self.clone();
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            bound_environment_runtime_transaction(&mut tx).await?;
            let saved = load_in(&mut tx, owner.request_id, true).await?.ok_or_else(conflict)?;
            saved.require_owner(&owner)?;
            let request = saved.decode()?;
            let (phase, code, lease_settlement) = match settlement {
                Settlement::Succeeded => {
                    if request.phase != RuntimePhase::Acknowledged || request.effect != Some(RuntimeEffect::Cleanup) {
                        return Err(conflict());
                    }
                    ("succeeded", None, EnvironmentRuntimeLeaseSettlement::Known)
                }
                Settlement::Cancelled => {
                    if !matches!(request.phase, RuntimePhase::Admitted | RuntimePhase::Acknowledged) {
                        return Err(conflict());
                    }
                    ("failed", Some(KnownFailure::CancelledBeforeDispatch.code()), EnvironmentRuntimeLeaseSettlement::Known)
                }
                Settlement::Refused { checkpoint, effect, failure } => {
                    require_issued(&request, checkpoint, effect)?;
                    ("failed", Some(failure.code()), EnvironmentRuntimeLeaseSettlement::Known)
                }
                Settlement::Unknown { checkpoint, effect } => {
                    require_issued(&request, checkpoint, effect)?;
                    ("unknown", Some("cw_runtime_dispatch_unknown"), EnvironmentRuntimeLeaseSettlement::Unknown)
                }
            };
            let saved: SavedRequest = sqlx::query_as(
                "UPDATE environment_cw_runtime_requests SET phase=$2,error_code=$3,\
                 terminal_at=clock_timestamp(),updated_at=clock_timestamp() WHERE request_id=$1 RETURNING *",
            ).bind(owner.request_id).bind(phase).bind(code).fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
            settle_environment_runtime_mutation_lease_in(&mut tx, &saved.mutation_lease_id,
                &saved.organization_id, &saved.environment_id, lease_settlement).await?;
            let result = saved.decode()?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(result)
        }).await
    }
}

enum Settlement {
    Succeeded,
    Cancelled,
    Refused {
        checkpoint: i32,
        effect: RuntimeEffect,
        failure: KnownFailure,
    },
    Unknown {
        checkpoint: i32,
        effect: RuntimeEffect,
    },
}

fn copy_owner(owner: &RequestOwner) -> RequestOwner {
    RequestOwner {
        request_id: owner.request_id,
        owner_id: owner.owner_id,
        fingerprint: owner.fingerprint.clone(),
        organization_id: owner.organization_id.clone(),
        environment_id: owner.environment_id.clone(),
    }
}

async fn owned<T, F>(future: F) -> AppResult<T>
where
    T: Send + 'static,
    F: Future<Output = AppResult<T>> + Send + 'static,
{
    // Spawn before admission/Issued/settlement. Dropping an HTTP waiter does
    // not cancel the database owner between a commit and result delivery.
    tokio::spawn(async move {
        tokio::time::timeout(TRANSACTION_TIMEOUT, future)
            .await
            .map_err(|_| unavailable())?
    })
    .await
    .map_err(|_| unavailable())?
}

async fn load_in(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    lock: bool,
) -> AppResult<Option<SavedRequest>> {
    let sql = if lock {
        "SELECT * FROM environment_cw_runtime_requests WHERE request_id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM environment_cw_runtime_requests WHERE request_id=$1"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())
}

async fn lock_binding_in(
    tx: &mut Transaction<'_, Postgres>,
    expected: &CapturedBindingFacts,
) -> AppResult<()> {
    // Organization/environment/membership/grant locks are held by the caller.
    // Lock setup/backend before the immutable original binding, matching the
    // writer's row ownership. Never look up a latest binding credential.
    let backend: Option<String> = sqlx::query_scalar(
        "SELECT environment_id FROM sandbox_environment_backend WHERE environment_id=$1 FOR UPDATE",
    )
    .bind(&expected.environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if backend.is_none() {
        return Err(conflict());
    }
    let binding: Option<String> = sqlx::query_scalar(
        "SELECT pod_uid FROM sandbox_workspace_bindings WHERE environment_id=$1 AND pod_uid=$2 \
         AND released_at IS NULL FOR SHARE",
    )
    .bind(&expected.environment_id)
    .bind(&expected.pod_uid)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if binding.is_none() {
        return Err(conflict());
    }
    let current = live_cw_runtime_binding(
        &mut **tx,
        &expected.organization_id,
        &expected.environment_id,
    )
    .await
    .map_err(|_| unavailable())?
    .ok_or_else(conflict)?;
    if CapturedBindingFacts::from(&current) != *expected {
        return Err(conflict());
    }
    expected.validate()
}

fn validate_principal(user: &AuthUser, org: &str) -> AppResult<()> {
    if user.user_id.is_empty()
        || user.user_id.len() > 128
        || !user.permits_organization(org)
        || (user.via_api_key && user.org_id.as_deref() != Some(org))
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn require_principal(saved: &SavedRequest, user: &AuthUser) -> AppResult<()> {
    validate_principal(user, &saved.organization_id)?;
    if saved.actor_user_id != user.user_id
        || saved.via_api_key != user.via_api_key
        || saved.delegated_organization_id.as_deref()
            != user.via_api_key.then_some(user.org_id.as_deref()).flatten()
    {
        return Err(conflict());
    }
    Ok(())
}

fn parse_enum<T: serde::de::DeserializeOwned>(value: &str) -> AppResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(|_| unavailable())
}

fn effect_sequence(mutation: &RuntimeMutation) -> Vec<RuntimeEffect> {
    match mutation.action {
        RuntimeAction::Update if mutation.expected_store_generation == 0 => vec![
            RuntimeEffect::Bootstrap,
            RuntimeEffect::Staging,
            RuntimeEffect::Update,
            RuntimeEffect::Cleanup,
        ],
        RuntimeAction::Update => vec![
            RuntimeEffect::Staging,
            RuntimeEffect::Update,
            RuntimeEffect::Cleanup,
        ],
        RuntimeAction::Rollback => vec![RuntimeEffect::Rollback, RuntimeEffect::Cleanup],
    }
}

fn next_effect(request: &RuntimeRequest) -> AppResult<RuntimeEffect> {
    if !matches!(
        request.phase,
        RuntimePhase::Admitted | RuntimePhase::Acknowledged
    ) {
        return Err(conflict());
    }
    effect_sequence(&request.mutation)
        .get(request.acknowledgements.len())
        .copied()
        .ok_or_else(conflict)
}

fn require_issued(
    request: &RuntimeRequest,
    checkpoint: i32,
    effect: RuntimeEffect,
) -> AppResult<()> {
    if request.phase != RuntimePhase::Issued
        || request.checkpoint != checkpoint
        || request.effect != Some(effect)
    {
        return Err(conflict());
    }
    Ok(())
}

fn prior_selection(request: &RuntimeRequest) -> (u64, Option<&str>, Option<&str>) {
    request
        .acknowledgements
        .iter()
        .rev()
        .find_map(|a| {
            if let EffectReceipt::Selected {
                sha256,
                generation,
                previous_sha256,
                ..
            } = &a.receipt
            {
                Some((
                    *generation,
                    Some(sha256.as_str()),
                    previous_sha256.as_deref(),
                ))
            } else {
                None
            }
        })
        .unwrap_or((
            request.mutation.expected_store_generation,
            request.mutation.expected_current_sha256.as_deref(),
            request.mutation.expected_previous_sha256.as_deref(),
        ))
}

fn validate_receipt(
    request: &RuntimeRequest,
    effect: RuntimeEffect,
    receipt: &EffectReceipt,
) -> AppResult<()> {
    match (effect, receipt) {
        (RuntimeEffect::Staging, EffectReceipt::Staged { sha256, size })
            if *sha256 == request.mutation.target_identity.sha256
                && *size == request.mutation.target_identity.size =>
        {
            Ok(())
        }
        (
            RuntimeEffect::Bootstrap | RuntimeEffect::Update | RuntimeEffect::Rollback,
            EffectReceipt::Selected {
                sha256,
                generation,
                previous_sha256,
                changed,
            },
        ) => {
            let target = if effect == RuntimeEffect::Bootstrap {
                &request
                    .mutation
                    .bootstrap_identity
                    .as_ref()
                    .ok_or_else(conflict)?
                    .sha256
            } else {
                &request.mutation.target_identity.sha256
            };
            let (prior_generation, prior_sha, prior_previous) = prior_selection(request);
            let expected_changed = prior_sha != Some(target.as_str());
            let expected_generation = prior_generation
                .checked_add(u64::from(expected_changed))
                .ok_or_else(conflict)?;
            let expected_previous = if expected_changed {
                prior_sha
            } else {
                prior_previous
            };
            if sha256 != target
                || *generation != expected_generation
                || *changed != expected_changed
                || previous_sha256.as_deref() != expected_previous
            {
                return Err(conflict());
            }
            Ok(())
        }
        (RuntimeEffect::Cleanup, EffectReceipt::Cleaned) => Ok(()),
        _ => Err(conflict()),
    }
}

fn validate_history(request: &RuntimeRequest) -> AppResult<()> {
    let sequence = effect_sequence(&request.mutation);
    let count = request.acknowledgements.len();
    if request.checkpoint < 0
        || request.checkpoint > MAX_CHECKPOINTS
        || count > sequence.len()
        || count > request.checkpoint as usize
    {
        return Err(conflict());
    }
    let mut prefix = request.clone();
    prefix.acknowledgements.clear();
    for (index, ack) in request.acknowledgements.iter().enumerate() {
        if ack.checkpoint != index as i32 + 1 || ack.effect != sequence[index] {
            return Err(conflict());
        }
        validate_receipt(&prefix, ack.effect, &ack.receipt)?;
        prefix.acknowledgements.push(ack.clone());
    }
    let metadata_valid = match request.phase {
        RuntimePhase::Admitted => {
            request.checkpoint == 0
                && count == 0
                && request.effect.is_none()
                && request.issued_at.is_none()
                && request.terminal_at.is_none()
                && request.error_code.is_none()
        }
        RuntimePhase::Issued | RuntimePhase::Unknown => {
            request.checkpoint as usize == count + 1
                && request.effect == sequence.get(count).copied()
                && request.issued_at.is_some()
                && ((request.phase == RuntimePhase::Issued
                    && request.terminal_at.is_none()
                    && request.error_code.is_none())
                    || (request.phase == RuntimePhase::Unknown
                        && request.terminal_at.is_some()
                        && request.error_code.as_deref() == Some("cw_runtime_dispatch_unknown")))
        }
        RuntimePhase::Acknowledged | RuntimePhase::Succeeded => {
            request.checkpoint as usize == count
                && count > 0
                && request.effect == sequence.get(count - 1).copied()
                && request.issued_at.is_some()
                && request.error_code.is_none()
                && ((request.phase == RuntimePhase::Acknowledged && request.terminal_at.is_none())
                    || (request.phase == RuntimePhase::Succeeded
                        && count == sequence.len()
                        && request.terminal_at.is_some()))
        }
        RuntimePhase::Failed => {
            request.terminal_at.is_some()
                && matches!(
                    request.error_code.as_deref(),
                    Some("cw_runtime_cancelled_before_dispatch" | "cw_runtime_command_refused")
                )
                && ((request.checkpoint == 0
                    && count == 0
                    && request.effect.is_none()
                    && request.issued_at.is_none())
                    || (request.checkpoint > 0
                        && request.issued_at.is_some()
                        && ((request.checkpoint as usize == count + 1
                            && request.effect == sequence.get(count).copied())
                            || (request.checkpoint as usize == count
                                && count > 0
                                && request.effect == sequence.get(count - 1).copied()))))
        }
    };
    if !metadata_valid {
        return Err(conflict());
    }
    Ok(())
}
