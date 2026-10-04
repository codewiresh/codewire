//! Genuine PostgreSQL journal/authorization/concurrency proof. Each case
//! creates and drops only its named disposable database through the existing
//! TEST_DATABASE_URL fixture. No Pod, daemon or incoming binary is executed.

use std::borrow::Cow;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use codewire_cw_release::identity::CwPayloadIdentity;
use codewire_server_core::migrate::application_migrator;
use sha2::{Digest, Sha384};
use sqlx::migrate::Migrator;

use super::*;
use crate::test_database_support::TestDatabase;

const ORG: &str = "runtime-journal-org";
const ACTOR: &str = "runtime-journal-operator";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const NEXT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const CLAIM: &str = "c0ffee00-e29b-41d4-a716-446655440000";
const SANDBOX: &str = "5a4db0c5-e29b-41d4-a716-446655440000";
const PVC: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
// Accepted canonical fec3adae21 + a164, independently saved before migration35
// in platform-prior-migrations-176.json. These are not derived from this branch.
const HISTORY34: &str = "2513689128f703bffca25e18a45a238a0f2cb774a394be9e45f44001f6008b0ce3d39f5b9c394d2e8826b1c8501e7a5a";
const MIGRATION34: &str = "8cca018f2f40699d2a852d6bf8e0301e0732bb651fad0c86ef04dfc21945aa4db2b892098d7fb2b93b0fbe0a2b51d2e6";
const SCHEMA34: &str = "218a3ea293e6023d9023b3b133534bfeba823dd68e17818196d609032ccca1b5";
const DATABASE_TIMEOUT: Duration = Duration::from_secs(15);

struct Fixture {
    pool: PgPool,
    journal: RuntimeJournal,
    user: AuthUser,
    facts: CapturedBindingFacts,
}

impl Fixture {
    async fn seed(pool: &PgPool) -> Result<Self> {
        sqlx::query("INSERT INTO users(id,email) VALUES($1,'runtime-operator@example.test')")
            .bind(ACTOR)
            .execute(pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations(id,name,slug,created_by) VALUES($1,$1,$1,'fixture-admin')",
        )
        .bind(ORG)
        .execute(pool)
        .await?;
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES($1,$2,$3,'member')")
            .bind(Uuid::new_v4().to_string())
            .bind(ORG)
            .bind(ACTOR)
            .execute(pool)
            .await?;
        sqlx::query("INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
            VALUES('runtime-preset',$1,'Runtime','runtime','{\"schema_version\":1,\"working_directory\":\"/workspace\"}')")
            .bind(ORG).execute(pool).await?;
        sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,\
            environment_operation_generation,project_spec) VALUES($1,$2,$3,'sandbox','runtime-preset','running','started',9,\
            '{\"schema_version\":1,\"working_directory\":\"/workspace\"}')")
            .bind(ENV).bind(ORG).bind(ACTOR).execute(pool).await?;
        sqlx::query("INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,\
            claim_uid,sandbox_uid,workspace_pvc_uid,operation_generation,projection_selection_sha256,\
            managed_credential_clients,credential_scope,bound_at) \
            VALUES($1,$2,'runtime-sandboxes',$3,$4,$5,$6,3,$7,$8,'pod','2026-10-01T12:00:00Z')")
            .bind(POD).bind(ENV).bind(format!("sandbox-{ENV}")).bind(CLAIM).bind(SANDBOX).bind(PVC)
            .bind("a".repeat(64)).bind(codewire_access::ManagedCredentialClients::default().encode())
            .execute(pool).await?;
        sqlx::query(
            "INSERT INTO sandbox_environment_backend(environment_id,namespace,pod_name,pod_ip,\
            sandbox_claim_uid,setup_complete,pod_uid,bound_at,workspace_pvc_uid) \
            VALUES($1,'runtime-sandboxes',$2,'10.12.3.4',$3,true,$4,'2026-10-01T12:00:00Z',$5)",
        )
        .bind(ENV)
        .bind(format!("sandbox-{ENV}"))
        .bind(CLAIM)
        .bind(POD)
        .bind(PVC)
        .execute(pool)
        .await?;
        let facts = read_facts(pool).await?;
        facts.validate()?;
        Ok(Self {
            pool: pool.clone(),
            journal: RuntimeJournal::new(pool.clone(), flags()),
            user: AuthUser {
                user_id: ACTOR.into(),
                org_id: None,
                is_admin: false,
                via_api_key: false,
            },
            facts,
        })
    }

    async fn admit(&self, mutation: RuntimeMutation) -> Result<(RuntimeRequest, RequestOwner)> {
        owned_admission(
            self.journal
                .admit_facts(self.facts.clone(), self.user.clone(), mutation)
                .await?,
        )
    }

    async fn observe(&self, id: Uuid) -> Result<RuntimeRequest> {
        Ok(self.journal.observe(&self.user, ORG, ENV, id).await?)
    }

    async fn counts(&self) -> Result<(i64, i64)> {
        Ok(sqlx::query_as(
            "SELECT (SELECT count(*) FROM environment_cw_runtime_requests),\
            (SELECT count(*) FROM organization_mutation_leases)",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn grant_operator(&self) -> Result<()> {
        sqlx::query("UPDATE environments SET created_by='fixture-admin' WHERE id=$1")
            .bind(ENV)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO environment_access(environment_id,user_id,permission,granted_by) \
            VALUES($1,$2,'operator','fixture-admin')",
        )
        .bind(ENV)
        .bind(ACTOR)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn flags() -> FeatureFlags {
    FeatureFlags {
        enabled: true,
        admin_only: true,
    }
}

fn identity(sha: char) -> CwPayloadIdentity {
    CwPayloadIdentity {
        schema_version: 2,
        protocol_version: 1,
        record_version: 1,
        package_version: "0.1.0".into(),
        target: "x86_64-unknown-linux-musl".into(),
        source_revision: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        rustc: "rustc 1.93.0 (254b59607 2026-01-19)".into(),
        sha256: sha.to_string().repeat(64),
        size: 64,
    }
}

fn mutation() -> RuntimeMutation {
    RuntimeMutation {
        request_id: Uuid::new_v4(),
        action: RuntimeAction::Update,
        expected_store_generation: 1,
        expected_current_sha256: Some("a".repeat(64)),
        expected_previous_sha256: None,
        bootstrap_identity: None,
        target_identity: identity('b'),
    }
}

fn owned_admission(admission: Admission) -> Result<(RuntimeRequest, RequestOwner)> {
    match admission {
        Admission::Owned { request, owner } => Ok((*request, owner)),
        Admission::Existing(_) => anyhow::bail!("expected fresh ownership"),
    }
}

async fn read_facts(pool: &PgPool) -> Result<CapturedBindingFacts> {
    let row = live_cw_runtime_binding(pool, ORG, ENV)
        .await?
        .context("original live binding")?;
    Ok(CapturedBindingFacts::from(&row))
}

async fn backend_pid(tx: &mut Transaction<'_, Postgres>) -> Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await?)
}

async fn wait_blocked(pool: &PgPool, waiter: i32, blocker: i32) -> Result<()> {
    tokio::time::timeout(DATABASE_TIMEOUT, async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
                .bind(waiter)
                .bind(blocker)
                .fetch_one(pool)
                .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("specific backend did not reach lock barrier")??;
    Ok(())
}

async fn wait_blocked_query(pool: &PgPool, query_prefix: &str, blocker: i32) -> Result<i32> {
    tokio::time::timeout(DATABASE_TIMEOUT, async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity \
                WHERE datname=current_database() AND starts_with(query,$1) AND $2=ANY(pg_blocking_pids(pid))")
                .bind(query_prefix).bind(blocker).fetch_optional(pool).await?;
            if let Some(pid) = pid { return Ok::<_, anyhow::Error>(pid); }
            tokio::task::yield_now().await;
        }
    }).await.context("own query did not reach PostgreSQL lock barrier")?
}

macro_rules! database_case {
    ($name:ident, $fixture:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let database = TestDatabase::create().await?;
            let result = async {
                let $fixture = Fixture::seed(&database.pool).await?;
                $body
                Ok(())
            }.await;
            database.finish(result).await
        }
    };
}

database_case!(
    db_admission_keeps_the_complete_original_tuple_and_atomic_lease,
    f,
    {
        let (request, owner) = f.admit(mutation()).await?;
        ensure!(
            request.binding == f.facts
                && request.binding.environment_generation == 9
                && request.binding.binding_generation == 3
                && request.phase == RuntimePhase::Admitted
        );
        ensure!(f.counts().await? == (1, 1));
        let lease: (String, String, String, String) = sqlx::query_as("SELECT l.organization_id,l.environment_id,\
        l.mutation_class,l.state FROM organization_mutation_leases l JOIN environment_cw_runtime_requests r \
        ON r.mutation_lease_id=l.id WHERE r.request_id=$1")
        .bind(owner.request_id).fetch_one(&f.pool).await?;
        ensure!(
            lease
                == (
                    ORG.into(),
                    ENV.into(),
                    "environment_runtime_dispatch".into(),
                    "active".into()
                )
        );
    }
);

database_case!(
    db_exact_retry_observes_without_ownership_or_second_lease,
    f,
    {
        let intent = mutation();
        let (request, _) = f.admit(intent.clone()).await?;
        let admission = f
            .journal
            .admit_facts(f.facts.clone(), f.user.clone(), intent)
            .await?;
        ensure!(matches!(admission, Admission::Existing(ref saved) if **saved == request));
        ensure!(f.counts().await? == (1, 1));
    }
);

database_case!(
    db_same_uuid_different_body_or_principal_is_not_a_retry,
    f,
    {
        let intent = mutation();
        f.admit(intent.clone()).await?;
        let mut different = intent.clone();
        different.action = RuntimeAction::Rollback;
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), different)
                .await
                .is_err()
        );
        let mut different = intent.clone();
        different.target_identity = identity('c');
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), different)
                .await
                .is_err()
        );
        let key = AuthUser {
            org_id: Some(ORG.into()),
            via_api_key: true,
            ..f.user.clone()
        };
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), key, intent)
                .await
                .is_err()
        );
        ensure!(f.counts().await? == (1, 1));
    }
);

database_case!(
    db_concurrent_update_and_rollback_have_one_environment_owner,
    f,
    {
        let update = mutation();
        let rollback = RuntimeMutation {
            action: RuntimeAction::Rollback,
            ..mutation()
        };
        let (a, b) = tokio::join!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), update),
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), rollback)
        );
        ensure!(a.is_ok() != b.is_ok());
        ensure!(f.counts().await? == (1, 1));
    }
);

database_case!(
    db_creator_and_cached_global_admin_still_need_membership,
    f,
    {
        sqlx::query("DELETE FROM org_members WHERE org_id=$1 AND user_id=$2")
            .bind(ORG)
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        let stale = AuthUser {
            is_admin: true,
            ..f.user.clone()
        };
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), stale, mutation())
                .await
                .is_err()
        );
        ensure!(f.counts().await? == (0, 0));
    }
);

database_case!(db_current_operator_grant_and_tenant_are_required, f, {
    sqlx::query("UPDATE environments SET created_by='fixture-admin' WHERE id=$1")
        .bind(ENV)
        .execute(&f.pool)
        .await?;
    ensure!(
        f.journal
            .admit_facts(f.facts.clone(), f.user.clone(), mutation())
            .await
            .is_err()
    );
    sqlx::query(
        "INSERT INTO environment_access(environment_id,user_id,permission,granted_by) \
        VALUES($1,$2,'viewer','fixture-admin')",
    )
    .bind(ENV)
    .bind(ACTOR)
    .execute(&f.pool)
    .await?;
    ensure!(
        f.journal
            .admit_facts(f.facts.clone(), f.user.clone(), mutation())
            .await
            .is_err()
    );
    sqlx::query("UPDATE environment_access SET permission='operator' WHERE environment_id=$1")
        .bind(ENV)
        .execute(&f.pool)
        .await?;
    let wrong_key = AuthUser {
        org_id: Some("different-tenant".into()),
        via_api_key: true,
        ..f.user.clone()
    };
    ensure!(
        f.journal
            .admit_facts(f.facts.clone(), wrong_key, mutation())
            .await
            .is_err()
    );
    f.admit(mutation()).await?;
    ensure!(f.counts().await? == (1, 1));
});

database_case!(
    db_disabled_account_refuses_stale_authenticated_principal,
    f,
    {
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), mutation())
                .await
                .is_err()
        );
        ensure!(f.counts().await? == (0, 0));
    }
);

database_case!(
    db_confidential_policy_uses_current_admin_and_not_api_key_admin,
    f,
    {
        sqlx::query("UPDATE environments SET isolation_tier='confidential' WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        let facts = read_facts(&f.pool).await?;
        let stale = AuthUser {
            is_admin: true,
            ..f.user.clone()
        };
        ensure!(
            f.journal
                .admit_facts(facts.clone(), stale, mutation())
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET is_admin=true WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        let key = AuthUser {
            org_id: Some(ORG.into()),
            is_admin: true,
            via_api_key: true,
            ..f.user.clone()
        };
        ensure!(
            f.journal
                .admit_facts(facts.clone(), key, mutation())
                .await
                .is_err()
        );
        let disabled = RuntimeJournal::new(
            f.pool.clone(),
            FeatureFlags {
                enabled: false,
                admin_only: true,
            },
        );
        ensure!(
            disabled
                .admit_facts(facts.clone(), f.user.clone(), mutation())
                .await
                .is_err()
        );
        owned_admission(
            f.journal
                .admit_facts(facts, f.user.clone(), mutation())
                .await?,
        )?;
    }
);

async fn finish_update(f: &Fixture, owner: &RequestOwner) -> Result<()> {
    let stage = f
        .journal
        .issue(owner, &f.user, 0, RuntimeEffect::Staging)
        .await?;
    f.journal
        .acknowledge(
            &stage,
            EffectReceipt::Staged {
                sha256: "b".repeat(64),
                size: 64,
            },
        )
        .await?;
    let update = f
        .journal
        .issue(owner, &f.user, 1, RuntimeEffect::Update)
        .await?;
    ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Issued);
    f.journal
        .acknowledge(
            &update,
            EffectReceipt::Selected {
                sha256: "b".repeat(64),
                generation: 2,
                previous_sha256: Some("a".repeat(64)),
                changed: true,
            },
        )
        .await?;
    let cleanup = f
        .journal
        .issue(owner, &f.user, 2, RuntimeEffect::Cleanup)
        .await?;
    f.journal
        .acknowledge(&cleanup, EffectReceipt::Cleaned)
        .await?;
    f.journal.succeed(owner).await?;
    Ok(())
}

database_case!(
    db_update_closed_sequence_cas_receipts_and_atomic_success,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        ensure!(
            f.journal
                .issue(&owner, &f.user, 0, RuntimeEffect::Update)
                .await
                .is_err()
        );
        ensure!(f.journal.succeed(&owner).await.is_err());
        finish_update(&f, &owner).await?;
        let saved = f.observe(owner.request_id).await?;
        ensure!(saved.phase == RuntimePhase::Succeeded && saved.acknowledgements.len() == 3);
        let state: String = sqlx::query_scalar("SELECT state FROM organization_mutation_leases")
            .fetch_one(&f.pool)
            .await?;
        ensure!(state == "released");
        f.admit(mutation()).await?;
    }
);

database_case!(
    db_rollback_preserves_lossless_maximum_u64_noop_generation,
    f,
    {
        let intent = RuntimeMutation {
            action: RuntimeAction::Rollback,
            expected_store_generation: u64::MAX,
            expected_current_sha256: Some("b".repeat(64)),
            expected_previous_sha256: Some("a".repeat(64)),
            ..mutation()
        };
        let (_, owner) = f.admit(intent).await?;
        let issued = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Rollback)
            .await?;
        ensure!(
            f.journal
                .acknowledge(
                    &issued,
                    EffectReceipt::Selected {
                        sha256: "b".repeat(64),
                        generation: u64::MAX - 1,
                        previous_sha256: Some("a".repeat(64)),
                        changed: false
                    }
                )
                .await
                .is_err()
        );
        // A no-op retains Store::Selected.previous; it does not replace it
        // with the current version. Refuse the earlier incorrect contract.
        ensure!(
            f.journal
                .acknowledge(
                    &issued,
                    EffectReceipt::Selected {
                        sha256: "b".repeat(64),
                        generation: u64::MAX,
                        previous_sha256: Some("b".repeat(64)),
                        changed: false,
                    }
                )
                .await
                .is_err()
        );
        let selected = codewire_cw_release::store::Selected {
            generation: u64::MAX,
            current: "b".repeat(64),
            previous: Some("a".repeat(64)),
            changed: false,
        };
        f.journal
            .acknowledge(
                &issued,
                EffectReceipt::Selected {
                    sha256: selected.current,
                    generation: selected.generation,
                    previous_sha256: selected.previous,
                    changed: selected.changed,
                },
            )
            .await?;
        let cleanup = f
            .journal
            .issue(&owner, &f.user, 1, RuntimeEffect::Cleanup)
            .await?;
        f.journal
            .acknowledge(&cleanup, EffectReceipt::Cleaned)
            .await?;
        f.journal.succeed(&owner).await?;
        let saved: String = sqlx::query_scalar(
            "SELECT expected_store_generation FROM environment_cw_runtime_requests",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(saved == u64::MAX.to_string());
    }
);

database_case!(
    db_changed_rollback_retains_the_precommand_current_as_previous,
    f,
    {
        let intent = RuntimeMutation {
            action: RuntimeAction::Rollback,
            expected_store_generation: 2,
            expected_current_sha256: Some("b".repeat(64)),
            expected_previous_sha256: Some("a".repeat(64)),
            target_identity: identity('a'),
            ..mutation()
        };
        let (_, owner) = f.admit(intent).await?;
        let issued = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Rollback)
            .await?;
        ensure!(
            f.journal
                .acknowledge(
                    &issued,
                    EffectReceipt::Selected {
                        sha256: "a".repeat(64),
                        generation: 3,
                        previous_sha256: Some("a".repeat(64)),
                        changed: true,
                    }
                )
                .await
                .is_err()
        );
        let selected = codewire_cw_release::store::Selected {
            generation: 3,
            current: "a".repeat(64),
            previous: Some("b".repeat(64)),
            changed: true,
        };
        f.journal
            .acknowledge(
                &issued,
                EffectReceipt::Selected {
                    sha256: selected.current,
                    generation: selected.generation,
                    previous_sha256: selected.previous,
                    changed: selected.changed,
                },
            )
            .await?;
        let cleanup = f
            .journal
            .issue(&owner, &f.user, 1, RuntimeEffect::Cleanup)
            .await?;
        f.journal
            .acknowledge(&cleanup, EffectReceipt::Cleaned)
            .await?;
        let completed = f.journal.succeed(&owner).await?;
        ensure!(completed.phase == RuntimePhase::Succeeded);
        ensure!(f.observe(owner.request_id).await? == completed);
    }
);

database_case!(
    db_bootstrap_is_separately_issued_before_staging_and_selection,
    f,
    {
        let intent = RuntimeMutation {
            expected_store_generation: 0,
            expected_current_sha256: None,
            bootstrap_identity: Some(identity('a')),
            ..mutation()
        };
        let (_, owner) = f.admit(intent).await?;
        ensure!(
            f.journal
                .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
                .await
                .is_err()
        );
        let bootstrap = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Bootstrap)
            .await?;
        f.journal
            .acknowledge(
                &bootstrap,
                EffectReceipt::Selected {
                    sha256: "a".repeat(64),
                    generation: 1,
                    previous_sha256: None,
                    changed: true,
                },
            )
            .await?;
        let stage = f
            .journal
            .issue(&owner, &f.user, 1, RuntimeEffect::Staging)
            .await?;
        f.journal
            .acknowledge(
                &stage,
                EffectReceipt::Staged {
                    sha256: "b".repeat(64),
                    size: 64,
                },
            )
            .await?;
        let update = f
            .journal
            .issue(&owner, &f.user, 2, RuntimeEffect::Update)
            .await?;
        f.journal
            .acknowledge(
                &update,
                EffectReceipt::Selected {
                    sha256: "b".repeat(64),
                    generation: 2,
                    previous_sha256: Some("a".repeat(64)),
                    changed: true,
                },
            )
            .await?;
        let cleanup = f
            .journal
            .issue(&owner, &f.user, 3, RuntimeEffect::Cleanup)
            .await?;
        f.journal
            .acknowledge(&cleanup, EffectReceipt::Cleaned)
            .await?;
        ensure!(f.journal.succeed(&owner).await?.checkpoint == 4);
    }
);

database_case!(db_duplicate_checkpoint_and_wrong_owner_never_issue, f, {
    let (_, owner) = f.admit(mutation()).await?;
    let mut foreign = copy_owner(&owner);
    foreign.owner_id = Uuid::new_v4();
    ensure!(
        f.journal
            .issue(&foreign, &f.user, 0, RuntimeEffect::Staging)
            .await
            .is_err()
    );
    foreign.owner_id = owner.owner_id;
    foreign.fingerprint = "c".repeat(64);
    ensure!(
        f.journal
            .issue(&foreign, &f.user, 0, RuntimeEffect::Staging)
            .await
            .is_err()
    );
    let issued = f
        .journal
        .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
        .await?;
    ensure!(
        f.journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await
            .is_err()
    );
    ensure!(
        f.journal
            .issue(&owner, &f.user, 1, RuntimeEffect::Update)
            .await
            .is_err()
    );
    ensure!(
        f.journal
            .acknowledge(
                &issued,
                EffectReceipt::Staged {
                    sha256: "c".repeat(64),
                    size: 64
                }
            )
            .await
            .is_err()
    );
    ensure!(
        f.journal
            .acknowledge(
                &issued,
                EffectReceipt::Staged {
                    sha256: "b".repeat(64),
                    size: 65
                }
            )
            .await
            .is_err()
    );
    ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Issued);
});

database_case!(
    db_current_setup_and_lifecycle_are_rechecked_before_issue,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        for statement in [
            "UPDATE sandbox_environment_backend SET setup_complete=false WHERE environment_id=$1",
            "UPDATE sandbox_environment_backend SET setup_complete=true,pod_ip='10.12.3.5' WHERE environment_id=$1",
            "UPDATE environments SET desired_state='stopped' WHERE id=$1",
        ] {
            sqlx::query(statement).bind(ENV).execute(&f.pool).await?;
            ensure!(
                f.journal
                    .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
                    .await
                    .is_err()
            );
            ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Admitted);
        }
    }
);

database_case!(db_replacement_pod_cannot_retarget_the_saved_owner, f, {
    let (_, owner) = f.admit(mutation()).await?;
    let mut tx = f.pool.begin().await?;
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at=clock_timestamp() WHERE pod_uid=$1",
    )
    .bind(POD)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO sandbox_workspace_bindings \
        SELECT $2,environment_id,namespace,pod_name,claim_uid,sandbox_uid,workspace_pvc_uid,operation_generation,\
        projection_selection_sha256,managed_credential_clients,credential_scope,clock_timestamp(),NULL \
        FROM sandbox_workspace_bindings WHERE pod_uid=$1")
        .bind(POD).bind(NEXT_POD).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend b SET pod_uid=$2,bound_at=w.bound_at \
        FROM sandbox_workspace_bindings w WHERE b.environment_id=$1 AND w.pod_uid=$2",
    )
    .bind(ENV)
    .bind(NEXT_POD)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(
        f.journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await
            .is_err()
    );
    let saved = f.observe(owner.request_id).await?;
    ensure!(saved.binding.pod_uid == POD && saved.phase == RuntimePhase::Admitted);
    let next = read_facts(&f.pool).await?;
    ensure!(
        f.journal
            .admit_facts(next, f.user.clone(), mutation())
            .await
            .is_err()
    );
});

database_case!(
    db_full_tuple_admission_refuses_stale_ip_generation_and_pointer,
    f,
    {
        for statement in [
            "UPDATE sandbox_environment_backend SET pod_ip='10.12.3.5' WHERE environment_id=$1",
            "UPDATE environments SET environment_operation_generation=10 WHERE id=$1",
            "UPDATE sandbox_environment_backend SET workspace_pvc_uid=NULL WHERE environment_id=$1",
        ] {
            sqlx::query(statement).bind(ENV).execute(&f.pool).await?;
            ensure!(
                f.journal
                    .admit_facts(f.facts.clone(), f.user.clone(), mutation())
                    .await
                    .is_err()
            );
            ensure!(f.counts().await? == (0, 0));
        }
    }
);

database_case!(
    db_known_outcome_settles_after_revocation_and_environment_removal,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        let issued = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await?;
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        sqlx::query("DELETE FROM environments WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        let outcome = f
            .journal
            .fail_known(&issued, KnownFailure::CommandRefused)
            .await?;
        ensure!(outcome.phase == RuntimePhase::Failed && outcome.binding.pod_uid == POD);
        ensure!(f.counts().await? == (1, 1));
        let state: String = sqlx::query_scalar("SELECT state FROM organization_mutation_leases")
            .fetch_one(&f.pool)
            .await?;
        ensure!(state == "released");
    }
);

database_case!(
    db_lost_ack_is_unknown_and_expired_lease_never_resolves_it,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        let issued = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await?;
        f.journal.mark_unknown(&issued).await?;
        sqlx::query(
            "UPDATE organization_mutation_leases SET admitted_at=now()-interval '2 minutes',\
        deadline_at=now()-interval '1 minute'",
        )
        .execute(&f.pool)
        .await?;
        ensure!(
            f.journal
                .acknowledge(
                    &issued,
                    EffectReceipt::Staged {
                        sha256: "b".repeat(64),
                        size: 64
                    }
                )
                .await
                .is_err()
        );
        ensure!(
            f.journal
                .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
                .await
                .is_err()
        );
        ensure!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), mutation())
                .await
                .is_err()
        );
        let state: (String, String) =
            sqlx::query_as("SELECT state,recovery_code FROM organization_mutation_leases")
                .fetch_one(&f.pool)
                .await?;
        ensure!(
            state
                == (
                    "resolution_required".into(),
                    "cw_runtime_dispatch_unknown".into()
                )
        );
        ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Unknown);
    }
);

database_case!(
    db_crash_after_issued_commit_has_no_recovery_dispatch_permit,
    f,
    {
        let intent = mutation();
        let (_, owner) = f.admit(intent.clone()).await?;
        let issued = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await?;
        drop(issued); // The future sender died before any effect/ACK fixture call.
        let recovered = RuntimeJournal::new(f.pool.clone(), flags());
        let retry = recovered
            .admit_facts(f.facts.clone(), f.user.clone(), intent)
            .await?;
        ensure!(matches!(retry, Admission::Existing(ref r) if r.phase == RuntimePhase::Issued));
        ensure!(
            recovered
                .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
                .await
                .is_err()
        );
        let observed = recovered
            .observe(&f.user, ORG, ENV, owner.request_id)
            .await?;
        let json = bounded_json(&observed)?;
        ensure!(!String::from_utf8(json)?.contains(&owner.owner_id.to_string()));
        ensure!(f.counts().await? == (1, 1));
    }
);

database_case!(db_cancel_cannot_terminalize_an_issued_unknown_outcome, f, {
    let (_, owner) = f.admit(mutation()).await?;
    f.journal.cancel(&owner).await?;
    let (_, second) = f.admit(mutation()).await?;
    let issued = f
        .journal
        .issue(&second, &f.user, 0, RuntimeEffect::Staging)
        .await?;
    ensure!(f.journal.cancel(&second).await.is_err());
    f.journal.mark_unknown(&issued).await?;
    ensure!(f.journal.cancel(&second).await.is_err());
});

database_case!(
    db_atomic_admission_rollback_removes_both_request_and_lease,
    f,
    {
        let mut tx = f.pool.begin().await?;
        let admitted = f
            .journal
            .admit_in(&mut tx, &f.facts, &f.user, &mutation())
            .await?;
        ensure!(matches!(admitted, Admission::Owned { .. }));
        tx.rollback().await?;
        ensure!(f.counts().await? == (0, 0));
    }
);

database_case!(
    db_settlement_failure_rolls_back_terminal_and_lease_together,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        let stage = f
            .journal
            .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
            .await?;
        sqlx::raw_sql(
            "CREATE FUNCTION fixture_refuse_lease() RETURNS trigger LANGUAGE plpgsql AS $$ \
        BEGIN RAISE EXCEPTION 'synthetic lease update refusal'; END $$; \
        CREATE TRIGGER fixture_refuse_lease BEFORE UPDATE ON organization_mutation_leases \
        FOR EACH ROW EXECUTE FUNCTION fixture_refuse_lease()",
        )
        .execute(&f.pool)
        .await?;
        ensure!(f.journal.mark_unknown(&stage).await.is_err());
        ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Issued);
        let state: String = sqlx::query_scalar("SELECT state FROM organization_mutation_leases")
            .fetch_one(&f.pool)
            .await?;
        ensure!(state == "active");
    }
);

database_case!(
    db_transaction_bounds_do_not_lengthen_a_shorter_caller_bound,
    f,
    {
        let mut tx = f.pool.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout','17ms',true)")
            .execute(&mut *tx)
            .await?;
        bound_environment_runtime_transaction(&mut tx).await?;
        let settings: Vec<(String, String)> = sqlx::query_as("SELECT name,setting FROM pg_settings \
        WHERE name IN ('lock_timeout','statement_timeout','idle_in_transaction_session_timeout') ORDER BY name")
        .fetch_all(&mut *tx).await?;
        ensure!(
            settings
                == vec![
                    ("idle_in_transaction_session_timeout".into(), "5000".into()),
                    ("lock_timeout".into(), "17".into()),
                    ("statement_timeout".into(), "5000".into())
                ]
        );
        tx.rollback().await?;
    }
);

database_case!(
    db_constraint_rejects_missing_coordinates_and_nondecimal_generation,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        let row: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(r) FROM environment_cw_runtime_requests r")
                .fetch_one(&f.pool)
                .await?;
        for (change, constraint) in [
            (
                serde_json::json!({"binding_json": {}}),
                "environment_cw_runtime_request_coordinates",
            ),
            (
                serde_json::json!({"binding_json": {"organization_id":ORG,"environment_id":ENV,"pod_uid":null}}),
                "environment_cw_runtime_request_coordinates",
            ),
            (
                serde_json::json!({"expected_store_generation":"18446744073709551616"}),
                "environment_cw_runtime_requests_expected_store_generation_check",
            ),
            (
                serde_json::json!({"expected_store_generation":"01"}),
                "environment_cw_runtime_requests_expected_store_generation_check",
            ),
            (
                serde_json::json!({"via_api_key":true,"delegated_organization_id":null}),
                "environment_cw_runtime_request_delegation",
            ),
        ] {
            let mut candidate = row.clone();
            candidate["request_id"] = serde_json::json!(Uuid::new_v4());
            candidate["environment_id"] = serde_json::json!(Uuid::new_v4().to_string());
            candidate["binding_json"]["environment_id"] = candidate["environment_id"].clone();
            candidate["mutation_lease_id"] =
                serde_json::json!(format!("fixture/{}", Uuid::new_v4()));
            for (key, value) in change.as_object().unwrap() {
                candidate[key] = value.clone();
            }
            candidate["request_json"]["expected_store_generation"] =
                candidate["expected_store_generation"].clone();
            let error = sqlx::query(
                "INSERT INTO environment_cw_runtime_requests \
            SELECT (jsonb_populate_record(NULL::environment_cw_runtime_requests,$1)).*",
            )
            .bind(candidate)
            .execute(&f.pool)
            .await
            .expect_err("invalid metadata must be refused");
            ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"));
            ensure!(error.as_database_error().and_then(|e| e.constraint()) == Some(constraint));
        }
        ensure!(f.observe(owner.request_id).await?.phase == RuntimePhase::Admitted);
    }
);

database_case!(
    db_identity_and_terminal_evidence_are_immutable_and_not_deleted,
    f,
    {
        let (_, owner) = f.admit(mutation()).await?;
        for statement in [
            "DELETE FROM environment_cw_runtime_requests WHERE request_id=$1",
            "UPDATE environment_cw_runtime_requests SET actor_user_id='fixture-admin' WHERE request_id=$1",
            "UPDATE environment_cw_runtime_requests SET owner_id=gen_random_uuid() WHERE request_id=$1",
            "UPDATE environment_cw_runtime_requests SET fingerprint=repeat('c',64) WHERE request_id=$1",
        ] {
            ensure!(
                sqlx::query(statement)
                    .bind(owner.request_id)
                    .execute(&f.pool)
                    .await
                    .is_err()
            );
        }
        f.journal.cancel(&owner).await?;
        ensure!(sqlx::query("UPDATE environment_cw_runtime_requests SET updated_at=clock_timestamp() WHERE request_id=$1")
        .bind(owner.request_id).execute(&f.pool).await.is_err());
        ensure!(f.counts().await? == (1, 1));
    }
);

database_case!(
    db_membership_revocation_wins_a_real_admission_lock_barrier,
    f,
    {
        let mut revocation = f.pool.begin().await?;
        let blocker = backend_pid(&mut revocation).await?;
        sqlx::query("DELETE FROM org_members WHERE org_id=$1 AND user_id=$2")
            .bind(ORG)
            .bind(ACTOR)
            .execute(&mut *revocation)
            .await?;
        let mut admission = f.pool.begin().await?;
        let waiter = backend_pid(&mut admission).await?;
        let (journal, user, facts) = (f.journal.clone(), f.user.clone(), f.facts.clone());
        let task = tokio::spawn(async move {
            let result = journal
                .admit_in(&mut admission, &facts, &user, &mutation())
                .await;
            admission.rollback().await?;
            Ok::<_, anyhow::Error>(result.is_err())
        });
        wait_blocked(&f.pool, waiter, blocker).await?;
        revocation.commit().await?;
        ensure!(task.await??);
        ensure!(f.counts().await? == (0, 0));
    }
);

database_case!(
    db_admission_wins_then_revocation_blocks_the_next_issued_effect,
    f,
    {
        let mut admission = f.pool.begin().await?;
        let blocker = backend_pid(&mut admission).await?;
        let (_, owner) = owned_admission(
            f.journal
                .admit_in(&mut admission, &f.facts, &f.user, &mutation())
                .await?,
        )?;
        let mut revocation = f.pool.begin().await?;
        let waiter = backend_pid(&mut revocation).await?;
        let task = tokio::spawn(async move {
            sqlx::query("DELETE FROM org_members WHERE org_id=$1 AND user_id=$2")
                .bind(ORG)
                .bind(ACTOR)
                .execute(&mut *revocation)
                .await?;
            revocation.commit().await?;
            Ok::<_, anyhow::Error>(())
        });
        wait_blocked(&f.pool, waiter, blocker).await?;
        admission.commit().await?;
        task.await??;
        ensure!(
            f.journal
                .issue(&owner, &f.user, 0, RuntimeEffect::Staging)
                .await
                .is_err()
        );
        let saved: String = sqlx::query_scalar("SELECT phase FROM environment_cw_runtime_requests")
            .fetch_one(&f.pool)
            .await?;
        ensure!(saved == "admitted");
        f.journal.cancel(&owner).await?;
    }
);

database_case!(db_disable_wins_the_enabled_user_lock_before_admission, f, {
    let mut disable = f.pool.begin().await?;
    let blocker = backend_pid(&mut disable).await?;
    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(ACTOR)
        .execute(&mut *disable)
        .await?;
    let mut admission = f.pool.begin().await?;
    let waiter = backend_pid(&mut admission).await?;
    let (journal, facts, user) = (f.journal.clone(), f.facts.clone(), f.user.clone());
    let task = tokio::spawn(async move {
        let denied = journal
            .admit_in(&mut admission, &facts, &user, &mutation())
            .await
            .is_err();
        admission.rollback().await?;
        Ok::<_, anyhow::Error>(denied)
    });
    wait_blocked(&f.pool, waiter, blocker).await?;
    disable.commit().await?;
    ensure!(task.await??);
    ensure!(f.counts().await? == (0, 0));
});

database_case!(db_grant_revocation_wins_before_next_issued_commit, f, {
    f.grant_operator().await?;
    let (_, owner) = f.admit(mutation()).await?;
    let mut revocation = f.pool.begin().await?;
    let blocker = backend_pid(&mut revocation).await?;
    sqlx::query(
        "UPDATE environment_access SET permission='viewer' WHERE environment_id=$1 AND user_id=$2",
    )
    .bind(ENV)
    .bind(ACTOR)
    .execute(&mut *revocation)
    .await?;
    let (journal, user) = (f.journal.clone(), f.user.clone());
    let task = tokio::spawn(async move {
        journal
            .issue(&owner, &user, 0, RuntimeEffect::Staging)
            .await
    });
    wait_blocked_query(
        &f.pool,
        "SELECT permission FROM environment_access",
        blocker,
    )
    .await?;
    revocation.commit().await?;
    ensure!(task.await?.is_err());
    let phase: String = sqlx::query_scalar("SELECT phase FROM environment_cw_runtime_requests")
        .fetch_one(&f.pool)
        .await?;
    ensure!(phase == "admitted");
});

database_case!(db_setup_writer_wins_before_next_issued_commit, f, {
    let (_, owner) = f.admit(mutation()).await?;
    let mut setup = f.pool.begin().await?;
    let blocker = backend_pid(&mut setup).await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET setup_complete=false WHERE environment_id=$1",
    )
    .bind(ENV)
    .execute(&mut *setup)
    .await?;
    let (journal, user) = (f.journal.clone(), f.user.clone());
    let task = tokio::spawn(async move {
        journal
            .issue(&owner, &user, 0, RuntimeEffect::Staging)
            .await
    });
    wait_blocked_query(
        &f.pool,
        "SELECT environment_id FROM sandbox_environment_backend",
        blocker,
    )
    .await?;
    setup.commit().await?;
    ensure!(task.await?.is_err());
    let phase: String = sqlx::query_scalar("SELECT phase FROM environment_cw_runtime_requests")
        .fetch_one(&f.pool)
        .await?;
    ensure!(phase == "admitted");
});

database_case!(
    db_dropped_admission_waiter_does_not_cancel_the_database_owner,
    f,
    {
        let intent = mutation();
        let mut fence = f.pool.begin().await?;
        let blocker = backend_pid(&mut fence).await?;
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE")
            .bind(ENV)
            .execute(&mut *fence)
            .await?;
        let (journal, facts, user, request) = (
            f.journal.clone(),
            f.facts.clone(),
            f.user.clone(),
            intent.clone(),
        );
        let caller = tokio::spawn(async move { journal.admit_facts(facts, user, request).await });
        wait_blocked_query(
            &f.pool,
            "SELECT org_id,created_by,isolation_tier FROM environments",
            blocker,
        )
        .await?;
        caller.abort();
        ensure!(matches!(caller.await, Err(ref error) if error.is_cancelled()));
        fence.commit().await?;
        tokio::time::timeout(DATABASE_TIMEOUT, async {
            loop {
                if f.counts().await? == (1, 1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        ensure!(matches!(
            f.journal
                .admit_facts(f.facts.clone(), f.user.clone(), intent)
                .await?,
            Admission::Existing(_)
        ));
    }
);

fn accepted_prior34() -> Result<()> {
    let migrations: Vec<_> = application_migrator()
        .iter()
        .filter(|m| m.version <= 34)
        .collect();
    ensure!(migrations.len() == 34);
    let mut hash = Sha384::new();
    for (i, m) in migrations.iter().enumerate() {
        ensure!(m.version == i as i64 + 1);
        hash.update(Sha384::digest(m.sql.as_bytes()));
    }
    ensure!(format!("{:x}", hash.finalize()) == HISTORY34);
    ensure!(format!("{:x}", Sha384::digest(migrations[33].sql.as_bytes())) == MIGRATION34);
    Ok(())
}

async fn fingerprint_schema(pool: &PgPool) -> Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../../codewire-server-core/tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn install_prior34(pool: &PgPool) -> Result<()> {
    accepted_prior34()?;
    // This pool belongs to the newly generated exact fixture database only.
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await?;
    let prior = Migrator {
        migrations: Cow::Owned(
            application_migrator()
                .iter()
                .filter(|m| m.version <= 34)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    prior.run(pool).await?;
    ensure!(fingerprint_schema(pool).await? == SCHEMA34);
    Ok(())
}

async fn existing_rows_and_helpers(pool: &PgPool) -> Result<(Vec<String>, Vec<String>)> {
    let names: Vec<String> = sqlx::query_scalar("SELECT tablename FROM pg_tables WHERE schemaname='public' \
        AND tablename NOT IN ('environment_cw_runtime_requests','_sqlx_migrations') ORDER BY tablename")
        .fetch_all(pool).await?;
    let mut rows = Vec::new();
    for name in names {
        ensure!(
            name.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        );
        let sql = format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM public.\"{name}\" t"
        );
        rows.push(sqlx::query_scalar(&sql).fetch_one(pool).await?);
    }
    let helpers = sqlx::query_scalar("SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace \
        WHERE n.nspname='public' AND p.proname<>'codewire_cw_runtime_request_immutable' \
        ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)").fetch_all(pool).await?;
    Ok((rows, helpers))
}

#[tokio::test]
#[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
async fn db_migration_upgrade_preserves_accepted34_rows_helpers_and_ledger() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        install_prior34(&db.pool).await?;
        sqlx::query(
            "INSERT INTO users(id,email) VALUES('fixture-admin','fixture-admin@example.test')",
        )
        .execute(&db.pool)
        .await?;
        Fixture::seed(&db.pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA unrelated_fixture; CREATE TABLE unrelated_fixture.sentinel(value text); \
            INSERT INTO unrelated_fixture.sentinel VALUES('retained')",
        )
        .execute(&db.pool)
        .await?;
        let before = existing_rows_and_helpers(&db.pool).await?;
        let history: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&db.pool)
                .await?;
        application_migrator().run(&db.pool).await?;
        ensure!(existing_rows_and_helpers(&db.pool).await? == before);
        let after: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&db.pool)
                .await?;
        ensure!(after.len() == 35 && after[..34] == history);
        ensure!(after[34].0 == 35);
        let measured = fingerprint_schema(&db.pool).await?;
        ensure!(measured != SCHEMA34);
        println!("CW_RUNTIME_SCHEMA35_FINGERPRINT={measured}");
        let sentinel: String = sqlx::query_scalar("SELECT value FROM unrelated_fixture.sentinel")
            .fetch_one(&db.pool)
            .await?;
        ensure!(sentinel == "retained");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
async fn db_migration_fresh_matches_upgrade_and_reapplication_is_idempotent() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        accepted_prior34()?;
        let fresh = fingerprint_schema(&db.pool).await?;
        application_migrator().run(&db.pool).await?;
        ensure!(fingerprint_schema(&db.pool).await? == fresh);
        install_prior34(&db.pool).await?;
        application_migrator().run(&db.pool).await?;
        ensure!(fingerprint_schema(&db.pool).await? == fresh);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
async fn db_migration_failed_forward_rolls_back_all_new_objects() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        install_prior34(&db.pool).await?;
        let before = fingerprint_schema(&db.pool).await?;
        let sql = application_migrator()
            .iter()
            .find(|m| m.version == 35)
            .context("migration35")?
            .sql
            .as_ref();
        let mut tx = db.pool.begin().await?;
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        ensure!(sqlx::query("SELECT 1/0").execute(&mut *tx).await.is_err());
        tx.rollback().await?;
        ensure!(fingerprint_schema(&db.pool).await? == before);
        let exists: bool = sqlx::query_scalar(
            "SELECT to_regclass('environment_cw_runtime_requests') IS NOT NULL \
            OR to_regprocedure('codewire_cw_runtime_request_immutable()') IS NOT NULL",
        )
        .fetch_one(&db.pool)
        .await?;
        ensure!(!exists);
        application_migrator().run(&db.pool).await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

const EMPTY_ROLLBACK: &str = "DO $$ BEGIN \
    LOCK TABLE environment_cw_runtime_requests IN ACCESS EXCLUSIVE MODE; \
    IF EXISTS(SELECT 1 FROM environment_cw_runtime_requests) THEN \
        RAISE EXCEPTION 'cw runtime journal evidence must be retained'; END IF; \
    END $$; \
    DROP TABLE environment_cw_runtime_requests; \
    DROP FUNCTION codewire_cw_runtime_request_immutable(); \
    DELETE FROM _sqlx_migrations WHERE version=35";

#[tokio::test]
#[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
async fn db_migration_empty_rollback_restores34_and_nonempty_rollback_refuses() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let f = Fixture::seed(&db.pool).await?;
        let (_, owner) = f.admit(mutation()).await?;
        f.journal.cancel(&owner).await?;
        let schema = fingerprint_schema(&db.pool).await?;
        let mut tx = db.pool.begin().await?;
        ensure!(
            sqlx::raw_sql(EMPTY_ROLLBACK)
                .execute(&mut *tx)
                .await
                .is_err()
        );
        tx.rollback().await?;
        ensure!(fingerprint_schema(&db.pool).await? == schema && f.counts().await? == (1, 1));
        // No production rollback is promised. This exact fixture proves the
        // additive source-revert and an empty-only operator SQL reversal;
        // retained requests (even known terminal ones) forbid schema removal.
        install_prior34(&db.pool).await?;
        application_migrator().run(&db.pool).await?;
        let mut tx = db.pool.begin().await?;
        sqlx::raw_sql(EMPTY_ROLLBACK).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(fingerprint_schema(&db.pool).await? == SCHEMA34);
        application_migrator().run(&db.pool).await?;
        ensure!(fingerprint_schema(&db.pool).await? == schema);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[test]
fn model_decimal_generation_and_intent_bounds_are_closed() -> Result<()> {
    let mut intent = mutation();
    intent.expected_store_generation = u64::MAX;
    ensure!(intent.validate().is_err());
    intent.expected_current_sha256 = Some(intent.target_identity.sha256.clone());
    intent.expected_previous_sha256 = Some("a".repeat(64));
    intent.validate()?;
    let value = serde_json::to_value(&intent)?;
    ensure!(value["expected_store_generation"] == u64::MAX.to_string());
    for generation in [
        serde_json::json!(true),
        serde_json::json!(1),
        serde_json::json!("01"),
        serde_json::json!("18446744073709551616"),
    ] {
        let mut invalid = value.clone();
        invalid["expected_store_generation"] = generation;
        ensure!(serde_json::from_value::<RuntimeMutation>(invalid).is_err());
    }
    let mut invalid = intent.clone();
    invalid.expected_previous_sha256 = Some("not-a-digest".into());
    ensure!(invalid.validate().is_err());
    invalid = RuntimeMutation {
        expected_store_generation: 0,
        expected_current_sha256: None,
        expected_previous_sha256: Some("a".repeat(64)),
        bootstrap_identity: Some(identity('a')),
        ..mutation()
    };
    ensure!(invalid.validate().is_err());
    let start = Instant::now();
    let prior = application_migrator()
        .iter()
        .filter(|m| m.version <= 34)
        .count();
    accepted_prior34()?;
    ensure!(prior == 34 && start.elapsed() < DATABASE_TIMEOUT);
    Ok(())
}
