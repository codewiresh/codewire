//! Durable original-conversation ownership, never a daemon dispatcher.
//!
//! A fresh known COMMIT is the only source of an Issued capability. RPC loss,
//! recovery and duplicate admission can observe evidence but cannot recreate
//! that capability. Database tasks retain their ownership after caller drop.

use super::model::*;
use crate::api::cw_runtime::model::CapturedBindingFacts;
use crate::api::cw_runtime::owner::lock_binding_in;
use crate::api::environments::lock_cw_runtime_operator_in;
use crate::confidential_storage::FeatureFlags;
use chrono::{DateTime, Utc};
use codewire_server_core::org_deletion::{
    EnvironmentRuntimeLeaseSettlement, acquire_environment_runtime_mutation_lease_in,
    bound_environment_runtime_transaction, settle_environment_runtime_mutation_lease_in,
};
use codewire_server_core::{AppResult, auth::AuthUser};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use std::{future::Future, time::Duration};
use uuid::Uuid;

#[cfg(test)]
#[path = "database_tests.rs"]
mod database_tests;

#[derive(Clone)]
pub struct ManagedJournal {
    pool: PgPool,
    flags: FeatureFlags,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRequest {
    pub mutation: ManagedMutation,
    pub binding: CapturedBindingFacts,
    pub actor_user_id: String,
    pub fingerprint: String,
    pub phase: ManagedPhase,
    pub receipt: Option<ManagedReceipt>,
    pub cleanup_of: Option<Uuid>,
    pub reason_code: String,
    pub admitted_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub terminal_at: Option<DateTime<Utc>>,
}
pub enum Admission {
    Owned {
        request: Box<ManagedRequest>,
        owner: RequestOwner,
    },
    Existing(Box<ManagedRequest>),
}
pub struct RequestOwner {
    request_id: Uuid,
    owner_id: Uuid,
    fingerprint: String,
    organization_id: String,
    environment_id: String,
}
pub struct IssuedOperation {
    owner: RequestOwner,
    request: ManagedRequest,
    cleanup_original: Option<ManagedRequest>,
}
impl RequestOwner {
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
}
impl IssuedOperation {
    pub fn request_id(&self) -> Uuid {
        self.owner.request_id
    }
    pub fn request(&self) -> &ManagedRequest {
        &self.request
    }
}
#[derive(sqlx::FromRow)]
struct Saved {
    request_id: Uuid,
    organization_id: String,
    environment_id: String,
    actor_user_id: String,
    via_api_key: bool,
    delegated_organization_id: Option<String>,
    pod_uid: Uuid,
    fingerprint: String,
    mutation_json: serde_json::Value,
    binding_json: serde_json::Value,
    owner_id: Uuid,
    mutation_lease_id: String,
    cleanup_of: Option<Uuid>,
    phase: String,
    receipt_json: Option<serde_json::Value>,
    reason_code: String,
    admitted_at: DateTime<Utc>,
    issued_at: Option<DateTime<Utc>>,
    terminal_at: Option<DateTime<Utc>>,
}
impl Saved {
    fn decode(&self) -> AppResult<ManagedRequest> {
        bounded_json(&self.mutation_json).map_err(|_| unavailable())?;
        bounded_json(&self.binding_json).map_err(|_| unavailable())?;
        let m: ManagedMutation =
            serde_json::from_value(self.mutation_json.clone()).map_err(|_| unavailable())?;
        let b: CapturedBindingFacts =
            serde_json::from_value(self.binding_json.clone()).map_err(|_| unavailable())?;
        m.validate_binding(&b).map_err(|_| unavailable())?;
        let phase: ManagedPhase =
            serde_json::from_value(serde_json::Value::String(self.phase.clone()))
                .map_err(|_| unavailable())?;
        let receipt: Option<ManagedReceipt> = self
            .receipt_json
            .as_ref()
            .map(|v| {
                bounded_json(v).map_err(|_| unavailable())?;
                let r: ManagedReceipt =
                    serde_json::from_value(v.clone()).map_err(|_| unavailable())?;
                r.validate_for(&m, &b).map_err(|_| unavailable())?;
                Ok::<_, codewire_server_core::AppError>(r)
            })
            .transpose()?;
        if m.request_id != self.request_id
            || b.organization_id != self.organization_id
            || b.environment_id != self.environment_id
            || b.pod_uid != self.pod_uid.to_string()
            || self.owner_id.is_nil()
            || fingerprint(
                &self.actor_user_id,
                self.via_api_key,
                self.delegated_organization_id.as_deref(),
                &m,
                &b,
            )? != self.fingerprint
            || !valid_reason(&self.reason_code)
            || self.cleanup_of != m.cleanup_of_request_id
            || (self.cleanup_of.is_some()
                && (m.action != ManagedAction::Stop || self.cleanup_of == Some(m.request_id)))
            || (phase == ManagedPhase::Admitted
                && (self.issued_at.is_some() || self.terminal_at.is_some() || receipt.is_some()))
            || (phase == ManagedPhase::Issued
                && (self.issued_at.is_none() || self.terminal_at.is_some() || receipt.is_some()))
            || (matches!(
                phase,
                ManagedPhase::Completed | ManagedPhase::Rejected | ManagedPhase::Unknown
            ) && self.terminal_at.is_none())
            || (matches!(phase, ManagedPhase::Completed | ManagedPhase::Unknown)
                && self.issued_at.is_none())
            || (phase == ManagedPhase::Rejected
                && if self.issued_at.is_some() {
                    receipt
                        .as_ref()
                        .is_none_or(|r| r.phase != ManagedPhase::Rejected)
                        || self.reason_code != "platform-agent-command-refused"
                } else {
                    receipt.is_some()
                        || !matches!(
                            self.reason_code.as_str(),
                            "platform-agent-preissue-refused"
                                | "platform-agent-cancelled-before-dispatch"
                        )
                })
            || (phase == ManagedPhase::Completed
                && receipt
                    .as_ref()
                    .is_none_or(|r| r.phase != ManagedPhase::Completed))
        {
            return Err(unavailable());
        }
        Ok(ManagedRequest {
            mutation: m,
            binding: b,
            actor_user_id: self.actor_user_id.clone(),
            fingerprint: self.fingerprint.clone(),
            phase,
            receipt,
            cleanup_of: self.cleanup_of,
            reason_code: self.reason_code.clone(),
            admitted_at: self.admitted_at,
            issued_at: self.issued_at,
            terminal_at: self.terminal_at,
        })
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
    fn require(&self, o: &RequestOwner) -> AppResult<()> {
        if self.request_id != o.request_id
            || self.owner_id != o.owner_id
            || self.fingerprint != o.fingerprint
            || self.organization_id != o.organization_id
            || self.environment_id != o.environment_id
        {
            return Err(conflict());
        }
        Ok(())
    }
}
#[derive(sqlx::FromRow)]
struct Conversation {
    driver_id: Uuid,
    binding_json: serde_json::Value,
    support_image_sha256: String,
    support_image_size: i64,
    launch_generation: String,
    active_request_id: Option<Uuid>,
    cleanup_request_id: Option<Uuid>,
    known_clean: bool,
}
impl Conversation {
    fn require(&self, b: &CapturedBindingFacts, m: &ManagedMutation) -> AppResult<()> {
        self.require_scope(b, m)?;
        if self.launch_generation != m.expected_launch_generation.to_string() {
            return Err(conflict());
        }
        Ok(())
    }
    fn require_scope(&self, b: &CapturedBindingFacts, m: &ManagedMutation) -> AppResult<()> {
        if self.driver_id != m.driver_id
            || self.binding_json != json(b)?
            || self.support_image_sha256 != m.support_image_sha256
            || u64::try_from(self.support_image_size).ok() != Some(m.support_image_size)
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn require_cleanup(
        &self,
        b: &CapturedBindingFacts,
        m: &ManagedMutation,
        original: &ManagedRequest,
    ) -> AppResult<()> {
        self.require_scope(b, m)?;
        require_cleanup_original(b, m, original)?;
        if self.active_request_id != Some(original.mutation.request_id)
            || self.launch_generation != original.mutation.expected_launch_generation.to_string()
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn owns(&self, r: &ManagedRequest) -> bool {
        if r.cleanup_of.is_some() {
            self.active_request_id == r.cleanup_of
                && self.cleanup_request_id == Some(r.mutation.request_id)
        } else {
            self.active_request_id == Some(r.mutation.request_id)
                && self.cleanup_request_id.is_none()
        }
    }
}

impl ManagedJournal {
    pub fn new(pool: PgPool, flags: FeatureFlags) -> Self {
        Self { pool, flags }
    }
    pub async fn admit(
        &self,
        binding: CapturedBindingFacts,
        user: &AuthUser,
        mutation: ManagedMutation,
    ) -> AppResult<Admission> {
        self.admit_with(binding, user, mutation, None).await
    }
    /// Admit a Resume whose predecessor was proven absent in Kubernetes as
    /// `checked`. The admission reads the predecessor again and refuses unless
    /// it is exactly the Pod that was checked (#2705).
    pub async fn admit_resume(
        &self,
        binding: CapturedBindingFacts,
        user: &AuthUser,
        mutation: ManagedMutation,
        checked: ResumePredecessor,
    ) -> AppResult<Admission> {
        if mutation.action != ManagedAction::Resume {
            return Err(invalid());
        }
        self.admit_with(binding, user, mutation, Some(checked))
            .await
    }
    /// The repeat of a Resume already admitted under the same request ID: it
    /// is answered from that admission, exactly as any repeated request is,
    /// and never admits anything new (#2705).
    pub async fn repeat_resume(
        &self,
        binding: CapturedBindingFacts,
        user: &AuthUser,
        mutation: ManagedMutation,
    ) -> AppResult<ManagedRequest> {
        if mutation.action != ManagedAction::Resume {
            return Err(invalid());
        }
        match self.admit_with(binding, user, mutation, None).await? {
            Admission::Existing(saved) => Ok(*saved),
            Admission::Owned { .. } => Err(conflict()),
        }
    }
    /// The saved Resume with this request ID in this environment, whose
    /// control-plane fields a repeat must carry to match its fingerprint.
    /// `None` when the ID is new; any other saved request conflicts.
    pub async fn saved_resume(
        &self,
        binding: &CapturedBindingFacts,
        user: &AuthUser,
        request_id: Uuid,
    ) -> AppResult<Option<ManagedMutation>> {
        let (j, b, u) = (self.clone(), binding.clone(), user.clone());
        owned(async move {
            let mut tx = j.pool.begin().await.map_err(|_| unavailable())?;
            lock_cw_runtime_operator_in(
                &mut tx,
                &u,
                &b.organization_id,
                &b.environment_id,
                j.flags,
            )
            .await?;
            let saved = load(&mut tx, request_id, false).await?;
            tx.commit().await.map_err(|_| unavailable())?;
            let Some(saved) = saved else {
                return Ok(None);
            };
            if saved.organization_id != b.organization_id
                || saved.environment_id != b.environment_id
            {
                return Err(conflict());
            }
            let request = saved.decode()?;
            if request.mutation.action != ManagedAction::Resume {
                return Err(conflict());
            }
            Ok(Some(request.mutation))
        })
        .await
    }
    async fn admit_with(
        &self,
        binding: CapturedBindingFacts,
        user: &AuthUser,
        mutation: ManagedMutation,
        checked: Option<ResumePredecessor>,
    ) -> AppResult<Admission> {
        // A new Resume needs its checked predecessor; without one, admission
        // only answers a repeat (`admit_in` refuses to admit anything).
        if mutation.action != ManagedAction::Resume && checked.is_some() {
            return Err(invalid());
        }
        mutation.validate_binding(&binding)?;
        fingerprint(
            &user.user_id,
            user.via_api_key,
            delegation(user),
            &mutation,
            &binding,
        )?;
        let (journal, user) = (self.clone(), user.clone());
        owned(async move {
            let mut tx = journal.pool.begin().await.map_err(|_| unavailable())?;
            let admission = journal
                .admit_in(&mut tx, &binding, &user, &mutation, checked.as_ref())
                .await?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(admission)
        })
        .await
    }
    async fn admit_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        b: &CapturedBindingFacts,
        u: &AuthUser,
        m: &ManagedMutation,
        checked: Option<&ResumePredecessor>,
    ) -> AppResult<Admission> {
        lock_cw_runtime_operator_in(tx, u, &b.organization_id, &b.environment_id, self.flags)
            .await?;
        let f = fingerprint(&u.user_id, u.via_api_key, delegation(u), m, b)?;
        if let Some(saved) = load(tx, m.request_id, true).await? {
            if saved.fingerprint != f
                || saved.organization_id != b.organization_id
                || saved.environment_id != b.environment_id
            {
                return Err(conflict());
            }
            return Ok(Admission::Existing(Box::new(saved.decode()?)));
        }
        lock_binding_in(tx, b).await?;
        let mut cleanup_of = None;
        if m.action == ManagedAction::Resume {
            // Read the predecessor again under the conversation locks: it
            // must be exactly the Pod that was proven absent, at the same
            // generation and agent, before this Pod's row takes the Resume.
            let checked = checked.ok_or_else(invalid)?;
            let again = resume_predecessor_in(tx, b, &m.session_id, m.driver_id).await?;
            if again != *checked
                || m.predecessor_pod_uid.as_deref() != Some(again.pod_uid.as_str())
                || m.expected_launch_generation != again.generation
                || m.agent != Some(again.agent)
            {
                return Err(conflict());
            }
            match conversation(tx, b, m).await? {
                None => {
                    let agent = match again.agent {
                        ManagedAgent::Codex => "codex",
                        ManagedAgent::Claude => "claude",
                    };
                    // The new Pod's row starts at the predecessor's generation
                    // and advances once when the Resume completes, as Restart.
                    sqlx::query("INSERT INTO environment_platform_agent_conversations(environment_id,pod_uid,session_id,driver_id,\
                        binding_json,support_image_sha256,support_image_size,agent,launch_generation,active_request_id) \
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                        .bind(&b.environment_id).bind(uuid(&b.pod_uid)?).bind(&m.session_id).bind(m.driver_id).bind(json(b)?)
                        .bind(&m.support_image_sha256).bind(i64::try_from(m.support_image_size).map_err(|_|invalid())?).bind(agent)
                        .bind(again.generation.to_string()).bind(m.request_id).execute(&mut **tx).await.map_err(|_|conflict())?;
                }
                // A Rejected Resume left this Pod's row at the predecessor's
                // generation with nothing active; a later Resume reuses it.
                Some(c) => {
                    c.require(b, m)?;
                    if c.active_request_id.is_some() || c.cleanup_request_id.is_some() {
                        return Err(resume_refused(RESUME_IN_PROGRESS));
                    }
                    sqlx::query("UPDATE environment_platform_agent_conversations SET active_request_id=$4,updated_at=clock_timestamp() \
                        WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3")
                        .bind(&b.environment_id).bind(uuid(&b.pod_uid)?).bind(&m.session_id).bind(m.request_id)
                        .execute(&mut **tx).await.map_err(|_|unavailable())?;
                }
            }
        } else if m.action == ManagedAction::Launch {
            if let Some(parent) = m.parent_session_id.as_ref() {
                let parent_driver = uuid(parent.strip_prefix("session-").ok_or_else(invalid)?)?;
                let mut pm = m.clone();
                pm.session_id = parent.clone();
                pm.driver_id = parent_driver;
                pm.expected_launch_generation = m.expected_parent_launch_generation;
                let p = conversation(tx, b, &pm).await?.ok_or_else(conflict)?;
                p.require(b, &pm)?;
                if p.active_request_id.is_some() || p.cleanup_request_id.is_some() || p.known_clean
                {
                    return Err(conflict());
                }
            }
            let agent = match m.agent.ok_or_else(invalid)? {
                ManagedAgent::Codex => "codex",
                ManagedAgent::Claude => "claude",
            };
            sqlx::query("INSERT INTO environment_platform_agent_conversations(environment_id,pod_uid,session_id,driver_id,\
                binding_json,support_image_sha256,support_image_size,agent,launch_generation,active_request_id) \
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,'1',$9)")
                .bind(&b.environment_id).bind(uuid(&b.pod_uid)?).bind(&m.session_id).bind(m.driver_id).bind(json(b)?)
                .bind(&m.support_image_sha256).bind(i64::try_from(m.support_image_size).map_err(|_|invalid())?).bind(agent)
                .bind(m.request_id).execute(&mut **tx).await.map_err(|_|conflict())?;
        } else {
            let c = conversation(tx, b, m).await?.ok_or_else(conflict)?;
            if let Some(id) = c.active_request_id {
                let original = load(tx, id, true).await?.ok_or_else(conflict)?.decode()?;
                c.require_cleanup(b, m, &original)?;
                if let Some(previous_id) = c.cleanup_request_id {
                    let previous = load(tx, previous_id, true)
                        .await?
                        .ok_or_else(conflict)?
                        .decode()?;
                    if !matches!(previous.phase, ManagedPhase::Issued | ManagedPhase::Unknown) {
                        return Err(conflict());
                    }
                    require_cleanup_original(b, &previous.mutation, &original)?;
                }
                let linked: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM environment_platform_agent_requests WHERE cleanup_of=$1 AND phase IN ('issued','unknown')"
                ).bind(id).fetch_one(&mut **tx).await.map_err(|_| unavailable())?;
                if linked >= 16 {
                    return Err(conflict());
                }
                cleanup_of = Some(id);
            } else {
                c.require(b, m)?;
                if m.cleanup_of_request_id.is_some() || c.cleanup_request_id.is_some() {
                    return Err(conflict());
                }
                if m.action == ManagedAction::Restart {
                    m.expected_launch_generation
                        .checked_add(1)
                        .ok_or_else(conflict)?;
                } else if c.known_clean && m.action != ManagedAction::Stop {
                    return Err(conflict());
                }
            }
            sqlx::query(if cleanup_of.is_some() {
                "UPDATE environment_platform_agent_conversations SET cleanup_request_id=$4,updated_at=clock_timestamp() \
                 WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3"
            }else{
                "UPDATE environment_platform_agent_conversations SET active_request_id=$4,updated_at=clock_timestamp() \
                 WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3"
            }).bind(&b.environment_id).bind(uuid(&b.pod_uid)?).bind(&m.session_id).bind(m.request_id)
                .execute(&mut **tx).await.map_err(|_|unavailable())?;
        }
        let lease = acquire_environment_runtime_mutation_lease_in(
            tx,
            &b.organization_id,
            &b.environment_id,
        )
        .await?;
        let saved:Saved=sqlx::query_as("INSERT INTO environment_platform_agent_requests(request_id,organization_id,environment_id,\
            actor_user_id,via_api_key,delegated_organization_id,pod_uid,fingerprint,mutation_json,binding_json,owner_id,mutation_lease_id,cleanup_of) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *")
            .bind(m.request_id).bind(&b.organization_id).bind(&b.environment_id).bind(&u.user_id).bind(u.via_api_key)
            .bind(delegation(u)).bind(uuid(&b.pod_uid)?).bind(f).bind(json(m)?).bind(json(b)?).bind(Uuid::new_v4())
            .bind(lease.id).bind(cleanup_of).fetch_one(&mut **tx).await.map_err(|_|conflict())?;
        Ok(Admission::Owned {
            request: Box::new(saved.decode()?),
            owner: saved.owner(),
        })
    }
    pub async fn issue(&self, owner: &RequestOwner, user: &AuthUser) -> AppResult<IssuedOperation> {
        let (j, o, u) = (self.clone(), copy_owner(owner), user.clone());
        owned(async move {
            let mut tx=j.pool.begin().await.map_err(|_|unavailable())?;
            lock_cw_runtime_operator_in(&mut tx,&u,&o.organization_id,&o.environment_id,j.flags).await?;
            let r=load(&mut tx,o.request_id,false).await?.ok_or_else(conflict)?;r.require(&o)?;
            if r.actor_user_id!=u.user_id || r.via_api_key!=u.via_api_key || r.delegated_organization_id.as_deref()!=delegation(&u) {return Err(conflict());}
            let request=r.decode()?;lock_binding_in(&mut tx,&request.binding).await?;
            let c=conversation(&mut tx,&request.binding,&request.mutation).await?.ok_or_else(conflict)?;
            let cleanup_original=require_owned_conversation(&mut tx,&c,&request).await?;if !c.owns(&request){return Err(conflict());}
            let r=load(&mut tx,o.request_id,true).await?.ok_or_else(conflict)?;r.require(&o)?;
            if r.phase!="admitted" {return Err(conflict());}
            sqlx::query("UPDATE environment_platform_agent_requests SET phase='issued',issued_at=clock_timestamp(),updated_at=clock_timestamp() WHERE request_id=$1")
                .bind(o.request_id).execute(&mut *tx).await.map_err(|_|unavailable())?;
            let request=load(&mut tx,o.request_id,false).await?.ok_or_else(conflict)?.decode()?;
            tx.commit().await.map_err(|_|unavailable())?;Ok(IssuedOperation {owner:o,request,cleanup_original})
        }).await
    }
    pub async fn observe(
        &self,
        user: &AuthUser,
        org: &str,
        env: &str,
        id: Uuid,
    ) -> AppResult<ManagedRequest> {
        let (j, u, org, env) = (self.clone(), user.clone(), org.to_owned(), env.to_owned());
        owned(async move {
            let mut tx = j.pool.begin().await.map_err(|_| unavailable())?;
            lock_cw_runtime_operator_in(&mut tx, &u, &org, &env, j.flags).await?;
            let r = load(&mut tx, id, false).await?.ok_or_else(conflict)?;
            if r.organization_id != org || r.environment_id != env {
                return Err(conflict());
            }
            let request = r.decode()?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(request)
        })
        .await
    }
    pub async fn settle(
        &self,
        issued: IssuedOperation,
        receipt: ManagedReceipt,
    ) -> AppResult<ManagedRequest> {
        if receipt
            .validate_for(&issued.request.mutation, &issued.request.binding)
            .is_err()
            || (receipt.phase == ManagedPhase::Completed
                && issued.cleanup_original.as_ref().is_some_and(|original| {
                    require_cleanup_proof(&issued.request, original, &receipt).is_err()
                }))
        {
            return self
                .mark_unknown(issued, "platform-agent-dispatch-unknown")
                .await;
        }
        let phase = match receipt.phase {
            ManagedPhase::Completed => ManagedPhase::Completed,
            ManagedPhase::Rejected => ManagedPhase::Rejected,
            _ => ManagedPhase::Unknown,
        };
        let reason = match phase {
            ManagedPhase::Completed => "",
            ManagedPhase::Rejected => "platform-agent-command-refused",
            _ => "platform-agent-dispatch-unknown",
        };
        self.finish(issued.owner, Some(receipt), phase, reason, true)
            .await
    }
    pub async fn mark_unknown(
        &self,
        issued: IssuedOperation,
        reason: &'static str,
    ) -> AppResult<ManagedRequest> {
        if reason != "platform-agent-dispatch-unknown" {
            return Err(invalid());
        }
        self.finish(issued.owner, None, ManagedPhase::Unknown, reason, true)
            .await
    }
    pub async fn reject_before_issue(
        &self,
        owner: RequestOwner,
        reason: &'static str,
    ) -> AppResult<ManagedRequest> {
        if !matches!(
            reason,
            "platform-agent-preissue-refused" | "platform-agent-cancelled-before-dispatch"
        ) {
            return Err(invalid());
        }
        self.finish(owner, None, ManagedPhase::Rejected, reason, false)
            .await
    }
    async fn finish(
        &self,
        o: RequestOwner,
        receipt: Option<ManagedReceipt>,
        phase: ManagedPhase,
        reason: &'static str,
        issued: bool,
    ) -> AppResult<ManagedRequest> {
        let j = self.clone();
        owned(async move {
            let mut tx=j.pool.begin().await.map_err(|_|unavailable())?;bound_environment_runtime_transaction(&mut tx).await?;
            let saved=load(&mut tx,o.request_id,false).await?.ok_or_else(conflict)?;saved.require(&o)?;
            let r=saved.decode()?;
            let c=conversation(&mut tx,&r.binding,&r.mutation).await?.ok_or_else(conflict)?;
            let _ = require_owned_conversation(&mut tx,&c,&r).await?;
            if !c.owns(&r){return Err(conflict());}
            let saved=load(&mut tx,o.request_id,true).await?.ok_or_else(conflict)?;saved.require(&o)?;
            if saved.phase!=if issued{"issued"}else{"admitted"} {return Err(conflict());}
            if let Some(receipt)=receipt.as_ref(){receipt.validate_for(&r.mutation,&r.binding)?;}
            let clearing=phase!=ManagedPhase::Unknown;
            // A target Rejected result carries no delivery/ACK or cleanup ambiguity.
            if phase==ManagedPhase::Rejected && receipt.as_ref().is_some_and(|p|p.cleanup_unknown || p.pipe_acknowledged || p.native_acknowledged) {return Err(invalid());}
            if r.cleanup_of.is_some() && phase==ManagedPhase::Completed {
                let proof=receipt.as_ref().filter(|p|p.known_clean()).ok_or_else(invalid)?;
                resolve_original(&mut tx,&r,proof).await?;
            }
            sqlx::query("UPDATE environment_platform_agent_requests SET phase=$2,receipt_json=$3,reason_code=$4,\
                terminal_at=clock_timestamp(),updated_at=clock_timestamp() WHERE request_id=$1")
                .bind(o.request_id).bind(phase.as_str()).bind(receipt.as_ref().map(json).transpose()?).bind(reason)
                .execute(&mut *tx).await.map_err(|_|unavailable())?;
            if clearing {
                if r.cleanup_of.is_some() {
                    let completed = phase == ManagedPhase::Completed;
                    let generation = if completed {
                        r.mutation.expected_launch_generation.to_string()
                    } else {
                        c.launch_generation.clone()
                    };
                    sqlx::query("UPDATE environment_platform_agent_conversations \
                        SET active_request_id=CASE WHEN $4 THEN NULL ELSE active_request_id END, \
                        cleanup_request_id=NULL,known_clean=CASE WHEN $4 THEN true ELSE known_clean END, \
                        launch_generation=$5,updated_at=clock_timestamp() \
                        WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3")
                        .bind(&r.binding.environment_id).bind(uuid(&r.binding.pod_uid)?).bind(&r.mutation.session_id)
                        .bind(completed).bind(generation)
                        .execute(&mut *tx).await.map_err(|_|unavailable())?;
                }else{
                    let generation=if phase==ManagedPhase::Completed {receipt.as_ref().ok_or_else(invalid)?.launch_generation}else{r.mutation.expected_launch_generation};
                    let clean=if phase==ManagedPhase::Completed {receipt.as_ref().is_some_and(ManagedReceipt::known_clean)}
                        else {c.known_clean || r.mutation.action==ManagedAction::Launch};
                    sqlx::query("UPDATE environment_platform_agent_conversations SET active_request_id=NULL,launch_generation=$4,known_clean=$5,\
                        updated_at=clock_timestamp() WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3")
                        .bind(&r.binding.environment_id).bind(uuid(&r.binding.pod_uid)?).bind(&r.mutation.session_id)
                        .bind(generation.to_string()).bind(clean).execute(&mut *tx).await.map_err(|_|unavailable())?;
                }
            }
            settle_environment_runtime_mutation_lease_in(&mut tx,&saved.mutation_lease_id,&o.organization_id,&o.environment_id,
                if phase==ManagedPhase::Unknown {EnvironmentRuntimeLeaseSettlement::Unknown}else{EnvironmentRuntimeLeaseSettlement::Known}).await?;
            let request=load(&mut tx,o.request_id,false).await?.ok_or_else(conflict)?.decode()?;
            tx.commit().await.map_err(|_|unavailable())?;Ok(request)
        }).await
    }
}

// This is the only generation exception. It is tied to an explicit unresolved
// original request, and it never grants another Restart or a latest-generation
// lookup. Target proof is independently required before any lease can resolve.
fn require_cleanup_original(
    binding: &CapturedBindingFacts,
    stop: &ManagedMutation,
    original: &ManagedRequest,
) -> AppResult<()> {
    let old = &original.mutation;
    if stop.action != ManagedAction::Stop
        || stop.cleanup_of_request_id != Some(old.request_id)
        || !matches!(original.phase, ManagedPhase::Issued | ManagedPhase::Unknown)
        || original.binding != *binding
        || old.driver_id != stop.driver_id
        || old.session_id != stop.session_id
        || old.support_image_sha256 != stop.support_image_sha256
        || old.support_image_size != stop.support_image_size
    {
        return Err(conflict());
    }
    if stop.expected_launch_generation != old.expected_launch_generation
        && !(original.phase == ManagedPhase::Unknown
            && old.action == ManagedAction::Restart
            && old.expected_launch_generation.checked_add(1)
                == Some(stop.expected_launch_generation))
    {
        return Err(conflict());
    }
    Ok(())
}
async fn require_owned_conversation(
    tx: &mut Transaction<'_, Postgres>,
    c: &Conversation,
    request: &ManagedRequest,
) -> AppResult<Option<ManagedRequest>> {
    if let Some(id) = request.cleanup_of {
        let original = load(tx, id, true).await?.ok_or_else(conflict)?.decode()?;
        c.require_cleanup(&request.binding, &request.mutation, &original)?;
        Ok(Some(original))
    } else {
        c.require(&request.binding, &request.mutation)?;
        Ok(None)
    }
}
fn require_cleanup_proof(
    stop: &ManagedRequest,
    original: &ManagedRequest,
    proof: &ManagedReceipt,
) -> AppResult<()> {
    require_cleanup_original(&stop.binding, &stop.mutation, original)?;
    if proof.phase != ManagedPhase::Completed
        || !proof.known_clean()
        || proof.cleanup_of_request_id != Some(original.mutation.request_id)
        || proof.cleanup_previous_generation != original.mutation.expected_launch_generation
        || !proof.cleanup_previous_cleanup_known
    {
        return Err(conflict());
    }
    Ok(())
}

async fn resolve_original(
    tx: &mut Transaction<'_, Postgres>,
    stop: &ManagedRequest,
    proof: &ManagedReceipt,
) -> AppResult<()> {
    if stop.mutation.action != ManagedAction::Stop
        || proof.phase != ManagedPhase::Completed
        || !proof.known_clean()
    {
        return Err(conflict());
    }
    let original = load(tx, stop.cleanup_of.ok_or_else(conflict)?, true)
        .await?
        .ok_or_else(conflict)?;
    let r = original.decode()?;
    require_cleanup_proof(stop, &r, proof)?;
    // Class-specific recovery in this same transaction. Every previous linked
    // cleanup retains its original Issued/Unknown outcome; only its lease can
    // resolve from this new, known-clean exact-generation guardian evidence.
    let linked: Vec<Saved> = sqlx::query_as(
        "SELECT * FROM environment_platform_agent_requests WHERE cleanup_of=$1 \
        AND phase IN ('issued','unknown') ORDER BY admitted_at,request_id LIMIT 17 FOR UPDATE",
    )
    .bind(r.mutation.request_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if linked.len() > 16 {
        return Err(conflict());
    }
    for prior in linked
        .iter()
        .filter(|p| p.request_id != stop.mutation.request_id)
        .chain(std::iter::once(&original))
    {
        let row = prior.decode()?;
        if prior.request_id != original.request_id {
            require_cleanup_original(&stop.binding, &row.mutation, &r)?;
        }
        let changed=sqlx::query("UPDATE organization_mutation_leases SET state=CASE WHEN state='active' THEN 'released' ELSE 'resolved' END,\
            released_at=CASE WHEN state='active' THEN NOW() ELSE released_at END,\
            resolved_at=CASE WHEN state='resolution_required' THEN NOW() ELSE resolved_at END,updated_at=NOW() \
            WHERE id=$1 AND organization_id=$2 AND environment_id=$3 AND mutation_class='environment_runtime_dispatch' \
            AND ((state='active' AND $4='issued' AND recovery_code IS NULL) OR \
                 (state='resolution_required' AND $4='unknown' AND recovery_code='cw_runtime_dispatch_unknown'))")
            .bind(&prior.mutation_lease_id).bind(&stop.binding.organization_id).bind(&stop.binding.environment_id)
            .bind(&prior.phase).execute(&mut **tx).await.map_err(|_|unavailable())?;
        if changed.rows_affected() != 1 {
            return Err(conflict());
        }
    }
    Ok(())
}

impl ManagedJournal {
    /// The earlier Pod a Resume of `session_id` continues from, or the plain
    /// reason it cannot be resumed. Read-only; the admission reads it again.
    pub async fn resume_predecessor(
        &self,
        binding: &CapturedBindingFacts,
        session_id: &str,
        driver_id: Uuid,
    ) -> AppResult<ResumePredecessor> {
        let (pool, binding, session_id) =
            (self.pool.clone(), binding.clone(), session_id.to_owned());
        owned(async move {
            let mut tx = pool.begin().await.map_err(|_| unavailable())?;
            let predecessor =
                resume_predecessor_in(&mut tx, &binding, &session_id, driver_id).await;
            let _ = tx.rollback().await;
            predecessor
        })
        .await
    }
}

const RESUME_IN_PROGRESS: &str =
    "this conversation is already resuming in this environment; try again shortly";

/// The predecessor is the Pod of the session's latest Completed Launch,
/// Restart or Resume: the last Pod where a driver for it started. Every
/// earlier such Pod was proven absent by the Resume that left it, and absence
/// is final, so only this one needs proving (#2705).
async fn resume_predecessor_in(
    tx: &mut Transaction<'_, Postgres>,
    b: &CapturedBindingFacts,
    session_id: &str,
    driver_id: Uuid,
) -> AppResult<ResumePredecessor> {
    // Organization first, so the (organization_id, environment_id,
    // request_id) index serves these reads.
    const STARTS: &str = "FROM environment_platform_agent_requests \
        WHERE organization_id=$1 AND environment_id=$2 AND mutation_json->>'session_id'=$3 \
          AND mutation_json->>'action' IN ('launch','restart','resume')";
    // A start issued in this Pod is still in progress: a racing Resume waits
    // for it. Any other start whose outcome is open or unknown may have run a
    // driver or moved the generation anywhere, and its Pod is gone; the
    // conversation ends rather than guess.
    let (in_progress, open, child): (bool, bool, bool) = sqlx::query_as(&format!(
        "SELECT EXISTS(SELECT 1 {STARTS} AND phase='issued' AND pod_uid=$4), \
                EXISTS(SELECT 1 {STARTS} AND phase IN ('issued','unknown') \
                       AND NOT (phase='issued' AND pod_uid=$4)), \
                EXISTS(SELECT 1 {STARTS} AND mutation_json->>'action'='launch' \
                       AND mutation_json->>'parent_session_id' IS NOT NULL)"
    ))
    .bind(&b.organization_id)
    .bind(&b.environment_id)
    .bind(session_id)
    .bind(uuid(&b.pod_uid)?)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if open {
        return Err(resume_refused(
            "this conversation's last start, restart or resume has an unknown outcome; \
             it has ended. Start a new conversation",
        ));
    }
    if in_progress {
        return Err(resume_refused(RESUME_IN_PROGRESS));
    }
    if child {
        return Err(resume_refused(
            "a child conversation ends with its environment; resume its parent or \
             start a new conversation",
        ));
    }
    let latest: Option<(Uuid,)> = sqlx::query_as(&format!(
        "SELECT pod_uid {STARTS} AND phase='completed' \
          ORDER BY terminal_at DESC, admitted_at DESC, request_id DESC LIMIT 1"
    ))
    .bind(&b.organization_id)
    .bind(&b.environment_id)
    .bind(session_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    let pod = latest
        .map(|(pod,)| pod)
        .ok_or_else(|| resume_refused("this conversation never started; start a new one"))?;
    if pod.to_string() == b.pod_uid {
        // Still this Pod's conversation: Restart is the operation for it.
        return Err(conflict());
    }
    let row: Option<(Uuid, serde_json::Value, String, String)> = sqlx::query_as(
        "SELECT driver_id, binding_json, launch_generation, agent \
           FROM environment_platform_agent_conversations \
          WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3 FOR UPDATE",
    )
    .bind(&b.environment_id)
    .bind(pod)
    .bind(session_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    let (row_driver, binding_json, generation, agent) = row.ok_or_else(unavailable)?;
    bounded_json(&binding_json).map_err(|_| unavailable())?;
    let previous: CapturedBindingFacts =
        serde_json::from_value(binding_json).map_err(|_| unavailable())?;
    if row_driver != driver_id
        || previous.pod_uid != pod.to_string()
        || previous.environment_id != b.environment_id
        || previous.organization_id != b.organization_id
    {
        return Err(conflict());
    }
    // The selection digest pins the profile revision, which pins each slot's
    // credential: an equal digest keeps the agent's credential identity.
    if previous.projection_selection_sha256 != b.projection_selection_sha256 {
        return Err(resume_refused(
            "the environment's selected credentials or secret sources changed since \
             this conversation started; start a new conversation",
        ));
    }
    let released: Option<(Option<chrono::DateTime<Utc>>,)> = sqlx::query_as(
        "SELECT released_at FROM sandbox_workspace_bindings WHERE environment_id=$1 AND pod_uid=$2",
    )
    .bind(&b.environment_id)
    .bind(&previous.pod_uid)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if !matches!(released, Some((Some(_),))) {
        return Err(resume_refused(
            "the environment's previous Pod is still stopping; try again shortly",
        ));
    }
    Ok(ResumePredecessor {
        pod_uid: previous.pod_uid,
        namespace: previous.namespace,
        pod_name: previous.pod_name,
        generation: generation.parse().map_err(|_| unavailable())?,
        agent: match agent.as_str() {
            "codex" => ManagedAgent::Codex,
            "claude" => ManagedAgent::Claude,
            _ => return Err(unavailable()),
        },
    })
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    lock: bool,
) -> AppResult<Option<Saved>> {
    sqlx::query_as(if lock {
        "SELECT * FROM environment_platform_agent_requests WHERE request_id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM environment_platform_agent_requests WHERE request_id=$1"
    })
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())
}
async fn conversation(
    tx: &mut Transaction<'_, Postgres>,
    b: &CapturedBindingFacts,
    m: &ManagedMutation,
) -> AppResult<Option<Conversation>> {
    sqlx::query_as("SELECT * FROM environment_platform_agent_conversations WHERE environment_id=$1 AND pod_uid=$2 AND session_id=$3 FOR UPDATE")
        .bind(&b.environment_id).bind(uuid(&b.pod_uid)?).bind(&m.session_id).fetch_optional(&mut **tx).await.map_err(|_|unavailable())
}
fn copy_owner(o: &RequestOwner) -> RequestOwner {
    RequestOwner {
        request_id: o.request_id,
        owner_id: o.owner_id,
        fingerprint: o.fingerprint.clone(),
        organization_id: o.organization_id.clone(),
        environment_id: o.environment_id.clone(),
    }
}
fn delegation(u: &AuthUser) -> Option<&str> {
    u.via_api_key.then_some(u.org_id.as_deref()).flatten()
}
fn json(v: &impl Serialize) -> AppResult<serde_json::Value> {
    serde_json::from_slice(&bounded_json(v)?).map_err(|_| invalid())
}
async fn owned<T: Send + 'static, F: Future<Output = AppResult<T>> + Send + 'static>(
    future: F,
) -> AppResult<T> {
    tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(20), future)
            .await
            .map_err(|_| unavailable())?
    })
    .await
    .map_err(|_| unavailable())?
}
