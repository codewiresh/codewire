//! #6251: a Sandbox left with another activity's `claimed` post-start setup
//! owner is refused runtime admission (`GetEnvironmentCwRuntime` answers
//! `failed_precondition`) until the running path releases that owner, and is
//! admitted after. Each case runs in its own disposable database from
//! `TEST_DATABASE_URL`. No Pod or daemon exists: the probe reports the bound
//! Pod as the runtime would, and nothing connects.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::activity_authority::ActivityAuthority;
use crate::worker::setup_lease::{
    PhaseAcquire, PhasePreparation, SetupActivityIdentity, SetupPhaseAuthority,
};

const ORG: &str = "setup-owner-org";
const ENV: &str = "6251e29b-41d4-4716-a446-655440000000";
const POD: &str = "6251f6b2-0bd2-4f11-8b16-9c239851eb52";
const POD_IP: &str = "10.12.3.4";
const CLAIM: &str = "6251ee00-e29b-41d4-a716-446655440000";
const SANDBOX: &str = "6251b0c5-e29b-41d4-a716-446655440000";
const PVC: &str = "62517b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const RUN: &str = "run-a";

/// A running, set-up Sandbox bound to [`POD`], its generation claimed by
/// [`RUN`]. Returns that generation.
async fn seed(pool: &PgPool) -> Result<i64> {
    sqlx::query(
        "INSERT INTO organizations(id,name,slug,created_by) VALUES($1,$1,$1,'fixture-admin')",
    )
    .bind(ORG)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES('setup-owner-preset',$1,'Setup owner','setup-owner',\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}')",
    )
    .bind(ORG)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,\
         project_spec) VALUES($1,$2,'fixture-admin','sandbox','setup-owner-preset','running',\
         'started','{\"schema_version\":1,\"working_directory\":\"/workspace\"}')",
    )
    .bind(ENV)
    .bind(ORG)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,\
         claim_uid,sandbox_uid,workspace_pvc_uid,operation_generation,projection_selection_sha256,\
         managed_credential_clients,credential_scope,bound_at) \
         VALUES($1,$2,'runtime-sandboxes',$3,$4,$5,$6,1,$7,$8,'pod','2026-11-24T03:28:34Z')",
    )
    .bind(POD)
    .bind(ENV)
    .bind(format!("sandbox-{ENV}"))
    .bind(CLAIM)
    .bind(SANDBOX)
    .bind(PVC)
    .bind("a".repeat(64))
    .bind(codewire_access::ManagedCredentialClients::default().encode())
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend(environment_id,namespace,pod_name,pod_ip,\
         sandbox_claim_uid,setup_complete,pod_uid,bound_at,workspace_pvc_uid) \
         VALUES($1,'runtime-sandboxes',$2,$3,$4,true,$5,'2026-11-24T03:28:34Z',$6)",
    )
    .bind(ENV)
    .bind(format!("sandbox-{ENV}"))
    .bind(POD_IP)
    .bind(CLAIM)
    .bind(POD)
    .bind(PVC)
    .execute(pool)
    .await?;
    ActivityAuthority::claim(pool, ENV, RUN, 10).await
}

async fn activity(
    pool: &PgPool,
    generation: i64,
    activity_id: &str,
    attempt: u32,
) -> Result<SetupPhaseAuthority> {
    SetupPhaseAuthority::new(
        ActivityAuthority::capture_for_run(pool, ENV, generation, RUN).await?,
        SetupActivityIdentity::new(generation, activity_id.into(), attempt)?,
    )
}

/// The capture backend `GetEnvironmentCwRuntime` uses, reading the binding
/// from the database, with the bound Pod running and every caller authorised.
struct DatabaseBackend(PgPool);

#[async_trait]
impl CaptureBackend for DatabaseBackend {
    type Client = ();

    async fn authorize(&self, _org: &str, env: &str) -> AppResult<SandboxTarget> {
        Ok(SandboxTarget {
            environment_id: env.into(),
            namespace: "runtime-sandboxes".into(),
            pod_name: format!("sandbox-{env}"),
        })
    }

    async fn binding(&self, org: &str, env: &str) -> AppResult<Option<CwRuntimeLiveBinding>> {
        live_cw_runtime_binding(&self.0, org, env)
            .await
            .map_err(|_| binding_unavailable())
    }

    async fn probe(&self, _namespace: &str, env: &str) -> AppResult<RuntimeProbe> {
        Ok(RuntimeProbe {
            claim_exists: true,
            claim_ready: true,
            replicas: 1,
            pod_exists: true,
            pod_phase: "Running".into(),
            pod_name: format!("sandbox-{env}"),
            pod_uid: POD.into(),
            pod_ip: POD_IP.into(),
            ..Default::default()
        })
    }

    async fn confidential_access(&self, _org: &str, _tier: &str) -> AppResult<()> {
        Ok(())
    }

    fn endpoint(&self, _namespace: &str, _env: &str) -> String {
        String::new()
    }

    async fn connect(&self, _endpoint: String, _credential: String) -> AppResult<()> {
        Err(binding_unavailable())
    }
}

/// `admit_row` on the current binding, then the whole admission
/// `GetEnvironmentCwRuntime` runs before it connects.
async fn admission(backend: &DatabaseBackend) -> Result<(AppResult<()>, AppResult<()>)> {
    let row = backend
        .binding(ORG, ENV)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the seeded binding is live"))?;
    let expected = model::CapturedBindingFacts::from(&row).incarnation();
    let target = backend.authorize(ORG, ENV).await?;
    let row_admission = admit_row(backend, &expected, &target, &row).await;
    let admission = admitted_row(backend, &expected).await.map(drop);
    Ok((row_admission, admission))
}

fn not_ready(result: &AppResult<()>) -> bool {
    matches!(result, Err(AppError::Precondition(message))
        if message == "environment runtime or setup is not ready")
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_runtime_admission_follows_the_release_of_a_left_claimed_owner() -> Result<()> {
    let database = TestDatabase::create().await?;
    let result = async {
        let pool = &database.pool;
        let generation = seed(pool).await?;
        let backend = DatabaseBackend(pool.clone());
        let (row, whole) = admission(&backend).await?;
        ensure!(
            row.is_ok() && whole.is_ok(),
            "the seeded Sandbox is admitted: {row:?} {whole:?}"
        );

        let left = activity(pool, generation, "118", 1).await?;
        ensure!(
            left.prepare_post_start_mutation(0).await?
                == PhasePreparation::Ready(PhaseAcquire::Acquired)
        );
        let (row, whole) = admission(&backend).await?;
        ensure!(
            not_ready(&row) && not_ready(&whole),
            "a claimed owner is refused: {row:?} {whole:?}"
        );

        let retry = activity(pool, generation, "118", 2).await?;
        ensure!(retry.release_stale_claimed_owner().await?.is_some());
        let (row, whole) = admission(&backend).await?;
        ensure!(
            row.is_ok() && whole.is_ok(),
            "the released Sandbox is admitted: {row:?} {whole:?}"
        );
        Ok(())
    }
    .await;
    database.finish(result).await
}
