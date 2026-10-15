//! Real disposable PostgreSQL proof; synthetic identities and no daemon calls.
use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::workspace_binding::live_cw_runtime_binding;
use anyhow::{Result, ensure};
use codewire_daemon_proto::daemon::v1 as private;
use codewire_server_core::AppError;
use codewire_server_core::migrate::application_migrator;
use sha2::{Digest, Sha384};
const ORG: &str = "runtime-journal-org";
const ACTOR: &str = "runtime-journal-operator";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const CLAIM: &str = "c0ffee00-e29b-41d4-a716-446655440000";
const SANDBOX: &str = "5a4db0c5-e29b-41d4-a716-446655440000";
const PVC: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
// Canonical1..37 plus byte-identical CW38; the schema pin is measured
// independently before qualifying the additive managed39 upgrade/rollback.
const SCHEMA38: &str = "8ba1bff35a4a9ba8d1ad41aebab3c2bbbecea13a7efed58b3b3e220e9a950252";
const SCHEMA39: &str = "9c5febb69fa7d930c3b4528cda06cf84521162cc51ed7c912959159a28be78fc";
const HISTORY38: &str = "68604f8738c2fdf1058494e572f7fb16b690847b820cb19afd2227e1583013ce9c8f6d5bc38f9fda9539131cf0e8a9a2";
struct Fixture {
    pool: PgPool,
    journal: ManagedJournal,
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
            journal: ManagedJournal::new(pool.clone(), flags()),
            user: AuthUser {
                user_id: ACTOR.into(),
                org_id: None,
                is_admin: false,
                via_api_key: false,
            },
            facts,
        })
    }

    async fn admit(&self, m: ManagedMutation) -> Result<(ManagedRequest, RequestOwner)> {
        own(self
            .journal
            .admit(self.facts.clone(), &self.user, m)
            .await?)
    }
    async fn issue(&self, m: ManagedMutation) -> Result<IssuedOperation> {
        let (_, o) = self.admit(m).await?;
        Ok(self.journal.issue(&o, &self.user).await?)
    }
    async fn observe(&self, id: Uuid) -> Result<ManagedRequest> {
        Ok(self.journal.observe(&self.user, ORG, ENV, id).await?)
    }
    async fn counts(&self) -> Result<(i64, i64, i64)> {
        Ok(sqlx::query_as("SELECT (SELECT count(*) FROM environment_platform_agent_requests), (SELECT count(*) FROM environment_platform_agent_conversations), (SELECT count(*) FROM organization_mutation_leases)").fetch_one(&self.pool).await?)
    }
    async fn launch(&self) -> Result<ManagedMutation> {
        let m = launch(Uuid::new_v4());
        let i = self.issue(m.clone()).await?;
        self.journal
            .settle(i, receipt(&m, &self.facts, ManagedLifecycle::Running))
            .await?;
        Ok(m)
    }
}
const POD2: &str = "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b";
impl Fixture {
    /// The environment's Pod after a Stop/Start (#2705): the first binding
    /// is released and a second one, with the same selection, is live.
    async fn next_pod(&self) -> Result<CapturedBindingFacts> {
        self.next_pod_as(POD, POD2, 4, &"a".repeat(64)).await
    }
    /// Release `previous` and bind `pod` at `generation` with `selection`.
    async fn next_pod_as(
        &self,
        previous: &str,
        pod: &str,
        generation: i64,
        selection: &str,
    ) -> Result<CapturedBindingFacts> {
        sqlx::query(
            "UPDATE sandbox_workspace_bindings SET released_at=bound_at+interval '30 minutes' WHERE pod_uid=$1",
        )
        .bind(previous)
        .execute(&self.pool)
        .await?;
        let bound_at = format!("2026-10-01T{:02}:00:00Z", 9 + generation);
        sqlx::query("INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,\
            claim_uid,sandbox_uid,workspace_pvc_uid,operation_generation,projection_selection_sha256,\
            managed_credential_clients,credential_scope,bound_at) \
            VALUES($1,$2,'runtime-sandboxes',$3,$4,$5,$6,$7,$8,$9,'pod',$10::timestamptz)")
            .bind(pod).bind(ENV).bind(format!("sandbox-{ENV}")).bind(CLAIM).bind(SANDBOX).bind(PVC)
            .bind(generation).bind(selection)
            .bind(codewire_access::ManagedCredentialClients::default().encode())
            .bind(&bound_at)
            .execute(&self.pool).await?;
        sqlx::query(
            "UPDATE sandbox_environment_backend SET pod_uid=$2,bound_at=$3::timestamptz \
             WHERE environment_id=$1",
        )
        .bind(ENV)
        .bind(pod)
        .bind(&bound_at)
        .execute(&self.pool)
        .await?;
        let facts = read_facts(&self.pool).await?;
        facts.validate()?;
        ensure!(facts.pod_uid == pod && facts.binding_generation == generation);
        Ok(facts)
    }
}
fn scope2() -> private::PlatformManagedScope {
    private::PlatformManagedScope {
        pod_uid: POD2.into(),
        binding_generation: 4,
        ..scope()
    }
}
fn resume(m: &ManagedMutation, predecessor: &str, generation: u64) -> ManagedMutation {
    ManagedMutation::from_private(&private::PlatformManagedMutationRequest {
        request_id: Uuid::new_v4().to_string(),
        scope: Some(scope2()),
        operation: Some(
            private::platform_managed_mutation_request::Operation::Control(
                private::PlatformManagedControl {
                    action: private::PlatformManagedAction::Resume as i32,
                    session_id: m.session_id.clone(),
                    driver_id: m.driver_id.to_string(),
                    expected_launch_generation: generation,
                    predecessor_pod_uid: predecessor.into(),
                    agent: private::PlatformManagedAgent::Codex as i32,
                    expected_provider_sha256: vec![0xcc; 32],
                    expected_provider_size: 4,
                    expected_provider_version: "0.160.0".into(),
                    ..Default::default()
                },
            ),
        ),
    })
    .expect("closed synthetic resume")
}
fn flags() -> FeatureFlags {
    FeatureFlags {
        enabled: true,
        admin_only: true,
    }
}
async fn read_facts(pool: &PgPool) -> Result<CapturedBindingFacts> {
    Ok(CapturedBindingFacts::from(
        &live_cw_runtime_binding(pool, ORG, ENV)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing synthetic binding"))?,
    ))
}
fn own(a: Admission) -> Result<(ManagedRequest, RequestOwner)> {
    match a {
        Admission::Owned { request, owner } => Ok((*request, owner)),
        _ => anyhow::bail!("expected fresh admission"),
    }
}
fn scope() -> private::PlatformManagedScope {
    private::PlatformManagedScope {
        environment_id: ENV.into(),
        org_id: ORG.into(),
        pod_uid: POD.into(),
        binding_generation: 3,
        projection_selection_sha256: vec![0xaa; 32],
        support_image_sha256: vec![0xbb; 32],
        support_image_size: 4,
    }
}
fn launch(id: Uuid) -> ManagedMutation {
    ManagedMutation::from_private(&private::PlatformManagedMutationRequest {
        request_id: id.to_string(),
        scope: Some(scope()),
        operation: Some(
            private::platform_managed_mutation_request::Operation::Launch(
                private::PlatformManagedLaunch {
                    agent: private::PlatformManagedAgent::Codex as i32,
                    model: "synthetic-model".into(),
                    name: "Synthetic".into(),
                    expected_provider_sha256: vec![0xcc; 32],
                    expected_provider_size: 4,
                    expected_provider_version: "0.160.0".into(),
                    ..Default::default()
                },
            ),
        ),
    })
    .expect("closed synthetic launch")
}
fn control(m: &ManagedMutation, a: ManagedAction) -> ManagedMutation {
    control_linked(m, a, None)
}
fn cleanup(original: &ManagedMutation, generation: u64) -> ManagedMutation {
    let mut context = original.clone();
    context.expected_launch_generation = generation;
    control_linked(&context, ManagedAction::Stop, Some(original.request_id))
}
fn control_linked(
    m: &ManagedMutation,
    a: ManagedAction,
    cleanup_of: Option<Uuid>,
) -> ManagedMutation {
    control_with_id(m, a, cleanup_of, Uuid::new_v4())
}
fn control_with_id(
    m: &ManagedMutation,
    a: ManagedAction,
    cleanup_of: Option<Uuid>,
    request_id: Uuid,
) -> ManagedMutation {
    let action = match a {
        ManagedAction::Message => private::PlatformManagedAction::Message,
        ManagedAction::Steer => private::PlatformManagedAction::Steer,
        ManagedAction::Interrupt => private::PlatformManagedAction::Interrupt,
        ManagedAction::Stop => private::PlatformManagedAction::Stop,
        ManagedAction::Restart => private::PlatformManagedAction::Restart,
        ManagedAction::Launch | ManagedAction::Resume => panic!("plain control action"),
    };
    ManagedMutation::from_private(&private::PlatformManagedMutationRequest {
        request_id: request_id.to_string(),
        scope: Some(scope()),
        operation: Some(
            private::platform_managed_mutation_request::Operation::Control(
                private::PlatformManagedControl {
                    action: action as i32,
                    session_id: m.session_id.clone(),
                    driver_id: m.driver_id.to_string(),
                    expected_launch_generation: m.expected_launch_generation,
                    cleanup_of_request_id: cleanup_of.map(|id| id.to_string()),
                    text: if matches!(a, ManagedAction::Message | ManagedAction::Steer) {
                        "synthetic text that must not be stored".into()
                    } else {
                        String::new()
                    },
                    expected_turn_id: (a == ManagedAction::Steer).then(|| "synthetic-turn".into()),
                    expected_active_message_id: matches!(
                        a,
                        ManagedAction::Steer | ManagedAction::Interrupt
                    )
                    .then(|| Uuid::new_v4().to_string()),
                    ..Default::default()
                },
            ),
        ),
    })
    .expect("closed synthetic control")
}
fn receipt(m: &ManagedMutation, b: &CapturedBindingFacts, l: ManagedLifecycle) -> ManagedReceipt {
    ManagedReceipt {
        request_id: m.request_id,
        organization_id: b.organization_id.clone(),
        environment_id: b.environment_id.clone(),
        pod_uid: b.pod_uid.clone(),
        binding_generation: b.binding_generation as u64,
        projection_selection_sha256: b.projection_selection_sha256.clone().unwrap(),
        support_image_sha256: m.support_image_sha256.clone(),
        support_image_size: m.support_image_size,
        private_fingerprint: m.private_fingerprint.clone(),
        phase: ManagedPhase::Completed,
        session_id: m.session_id.clone(),
        driver_id: m.driver_id,
        message_id: m.message_id,
        launch_generation: if matches!(m.action, ManagedAction::Restart | ManagedAction::Resume) {
            m.expected_launch_generation.checked_add(1).unwrap()
        } else {
            m.expected_launch_generation
        },
        lifecycle: l,
        exit_code: (l == ManagedLifecycle::Exited).then_some(0),
        cleanup_unknown: false,
        pipe_acknowledged: matches!(
            m.action,
            ManagedAction::Message | ManagedAction::Steer | ManagedAction::Interrupt
        ),
        native_acknowledged: m.action == ManagedAction::Interrupt,
        cleanup_of_request_id: m.cleanup_of_request_id,
        cleanup_previous_generation: if m.cleanup_of_request_id.is_some() {
            m.expected_launch_generation
        } else {
            0
        },
        cleanup_previous_cleanup_known: m.cleanup_of_request_id.is_some()
            && matches!(l, ManagedLifecycle::Stopped | ManagedLifecycle::Exited),
        reason_code: "settled".into(),
    }
}
async fn schema(pool: &PgPool) -> Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../../codewire-server-core/tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}
macro_rules! database_case {($name:ident,$f:ident,$body:block)=>{
    #[tokio::test]
    #[ignore="requires checked-in disposable TEST_DATABASE_URL"]
    async fn $name()->Result<()> {
        let db=TestDatabase::create().await?;
        let result=async {let $f=Fixture::seed(&db.pool).await?;$body Ok::<(),anyhow::Error>(())}.await;
        db.finish(result).await
    }
};}

database_case!(
    db_admission_full_scope_lease_and_material_free_metadata,
    f,
    {
        let m = launch(Uuid::new_v4());
        let (r, _) = f.admit(m).await?;
        ensure!(
            r.binding == f.facts
                && r.binding.environment_generation == 9
                && r.binding.binding_generation == 3
                && r.phase == ManagedPhase::Admitted
                && f.counts().await? == (1, 1, 1)
        );
        let raw:String=sqlx::query_scalar("SELECT mutation_json::text||binding_json::text FROM environment_platform_agent_requests")
        .fetch_one(&f.pool).await?;
        for forbidden in [
            "synthetic-model",
            "synthetic text",
            "prompt",
            "working_dir",
            "provider_sha256",
            "token",
        ] {
            ensure!(
                !raw.contains(forbidden),
                "durable material boundary {forbidden}"
            );
        }
        let lease:(String,String,String,String)=sqlx::query_as("SELECT organization_id,environment_id,mutation_class,state FROM organization_mutation_leases")
        .fetch_one(&f.pool).await?;
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
    db_duplicate_observe_only_changed_digest_and_actor_conflict,
    f,
    {
        let m = launch(Uuid::new_v4());
        let (r, _) = f.admit(m.clone()).await?;
        ensure!(matches!(
            f.journal.admit(f.facts.clone(), &f.user, m.clone()).await?,
            Admission::Existing(_)
        ));
        let mut changed = m.clone();
        changed.private_fingerprint = "d".repeat(64);
        ensure!(
            f.journal
                .admit(f.facts.clone(), &f.user, changed)
                .await
                .is_err()
        );
        let mut api = f.user.clone();
        api.via_api_key = true;
        api.org_id = Some(ORG.into());
        ensure!(f.journal.admit(f.facts.clone(), &api, m).await.is_err());
        ensure!(f.counts().await? == (1, 1, 1) && f.observe(r.mutation.request_id).await? == r);
    }
);
database_case!(db_concurrent_duplicate_has_one_owner_and_lease, f, {
    let m = launch(Uuid::new_v4());
    let (a, b) = tokio::join!(
        f.journal.admit(f.facts.clone(), &f.user, m.clone()),
        f.journal.admit(f.facts.clone(), &f.user, m)
    );
    ensure!(matches!(
        (&a, &b),
        (Ok(Admission::Owned { .. }), Ok(Admission::Existing(_)))
            | (Ok(Admission::Existing(_)), Ok(Admission::Owned { .. }))
    ));
    ensure!(f.counts().await? == (1, 1, 1));
});
database_case!(db_issue_is_one_use_and_observation_has_no_permit, f, {
    let m = launch(Uuid::new_v4());
    let (_, o) = f.admit(m.clone()).await?;
    let i = f.journal.issue(&o, &f.user).await?;
    ensure!(
        i.request().phase == ManagedPhase::Issued && f.journal.issue(&o, &f.user).await.is_err()
    );
    ensure!(matches!(
        f.journal.admit(f.facts.clone(), &f.user, m.clone()).await?,
        Admission::Existing(_)
    ));
    ensure!(
        f.observe(m.request_id).await?.phase == ManagedPhase::Issued
            && f.counts().await? == (1, 1, 1)
    );
});
database_case!(db_revocation_before_issue_and_observe_refuses, f, {
    let m = launch(Uuid::new_v4());
    let (_, o) = f.admit(m.clone()).await?;
    for query in [
        "UPDATE users SET enabled=false WHERE id='runtime-journal-operator'",
        "DELETE FROM org_members WHERE org_id='runtime-journal-org' AND user_id='runtime-journal-operator'",
        "UPDATE organizations SET deletion_state='deleting', deletion_generation=1, deletion_operation_id='runtime-journal-delete-operation', deletion_workflow_id='runtime-journal-delete-workflow', deletion_requested_by='runtime-journal-operator', deletion_requested_at=NOW(), deletion_phase='revoking' WHERE id='runtime-journal-org'",
    ] {
        let mut tx = f.pool.begin().await?;
        sqlx::query(query).execute(&mut *tx).await?;
        // Commit the revocation; callbacks must read fresh committed authority.
        tx.commit().await?;
        ensure!(
            f.journal.issue(&o, &f.user).await.is_err() && f.observe(m.request_id).await.is_err()
        );
        sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        sqlx::query("UPDATE organizations SET deletion_state='active', deletion_generation=0, deletion_operation_id=NULL, deletion_workflow_id=NULL, deletion_requested_by=NULL, deletion_requested_at=NULL, deletion_phase=NULL WHERE id=$1")
            .bind(ORG)
            .execute(&f.pool)
            .await?;
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES($1,$2,$3,'member') ON CONFLICT(org_id,user_id) DO NOTHING")
            .bind(Uuid::new_v4().to_string()).bind(ORG).bind(ACTOR).execute(&f.pool).await?;
    }
    ensure!(f.observe(m.request_id).await?.phase == ManagedPhase::Admitted);
});
database_case!(
    db_binding_generation_projection_and_private_scope_refuse,
    f,
    {
        let mut foreign = launch(Uuid::new_v4());
        foreign.pod_uid = Uuid::new_v4().to_string();
        ensure!(
            f.journal
                .admit(f.facts.clone(), &f.user, foreign)
                .await
                .is_err()
        );
        let m = launch(Uuid::new_v4());
        let (_, o) = f.admit(m.clone()).await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=10 WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        ensure!(f.journal.issue(&o, &f.user).await.is_err());
        sqlx::query("UPDATE environments SET environment_operation_generation=9 WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        // Immutable original binding cannot be silently replaced by a projection.
        let mut facts = f.facts.clone();
        facts.projection_selection_sha256 = Some("d".repeat(64));
        let mut changed = launch(Uuid::new_v4());
        changed.projection_selection_sha256 = "d".repeat(64);
        ensure!(f.journal.admit(facts, &f.user, changed).await.is_err());
        ensure!(f.counts().await? == (1, 1, 1));
    }
);
database_case!(
    db_distinct_conversations_do_not_share_generation_or_barrier,
    f,
    {
        let a = launch(Uuid::new_v4());
        let b = launch(Uuid::new_v4());
        let _a = f.issue(a.clone()).await?;
        let i = f.issue(b.clone()).await?;
        f.journal
            .settle(i, receipt(&b, &f.facts, ManagedLifecycle::Running))
            .await?;
        ensure!(
            f.observe(a.request_id).await?.phase == ManagedPhase::Issued
                && f.observe(b.request_id).await?.phase == ManagedPhase::Completed
        );
        ensure!(f.counts().await? == (2, 2, 2));
    }
);
database_case!(
    db_unknown_retains_barrier_no_replay_and_original_scope,
    f,
    {
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        let unknown = f
            .journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        ensure!(unknown.phase == ManagedPhase::Unknown);
        for a in [
            ManagedAction::Message,
            ManagedAction::Steer,
            ManagedAction::Interrupt,
            ManagedAction::Restart,
        ] {
            ensure!(f.admit(control(&m, a)).await.is_err());
        }
        ensure!(matches!(
            f.journal.admit(f.facts.clone(), &f.user, m.clone()).await?,
            Admission::Existing(_)
        ));
        ensure!(f.observe(m.request_id).await? == unknown && f.counts().await? == (1, 1, 1));
    }
);
database_case!(
    db_original_generation_stop_resolves_only_unknown_lease,
    f,
    {
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        let old = f
            .journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        let stop = cleanup(&m, m.expected_launch_generation);
        let i = f.issue(stop.clone()).await?;
        ensure!(i.request().cleanup_of == Some(m.request_id));
        let stopped = f
            .journal
            .settle(i, receipt(&stop, &f.facts, ManagedLifecycle::Stopped))
            .await?;
        ensure!(stopped.phase == ManagedPhase::Completed && f.observe(m.request_id).await? == old);
        let states:Vec<String>=sqlx::query_scalar("SELECT l.state FROM organization_mutation_leases l JOIN environment_platform_agent_requests r ON r.mutation_lease_id=l.id ORDER BY r.admitted_at")
        .fetch_all(&f.pool).await?;
        ensure!(states == ["resolved", "released"]);
        let restart = control(&m, ManagedAction::Restart);
        let i = f.issue(restart.clone()).await?;
        let result = f
            .journal
            .settle(i, receipt(&restart, &f.facts, ManagedLifecycle::Running))
            .await?;
        ensure!(result.receipt.unwrap().launch_generation == 2);
    }
);
database_case!(
    db_unknown_cleanup_can_be_followed_by_fresh_known_clean_stop,
    f,
    {
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        let original = f
            .journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        let first = cleanup(&m, m.expected_launch_generation);
        let i = f.issue(first.clone()).await?;
        let first_unknown = f
            .journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        let second = cleanup(&m, m.expected_launch_generation);
        let i = f.issue(second.clone()).await?;
        f.journal
            .settle(i, receipt(&second, &f.facts, ManagedLifecycle::Exited))
            .await?;
        ensure!(
            f.observe(m.request_id).await? == original
                && f.observe(first.request_id).await? == first_unknown
        );
        let states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM organization_mutation_leases ORDER BY admitted_at,id",
        )
        .fetch_all(&f.pool)
        .await?;
        ensure!(
            states.iter().filter(|s| s.as_str() == "resolved").count() == 2
                && states.iter().filter(|s| s.as_str() == "released").count() == 1
        );
    }
);
database_case!(db_crashed_issued_cleanup_preserves_issued_evidence, f, {
    let m = launch(Uuid::new_v4());
    let i = f.issue(m.clone()).await?;
    drop(i);
    let original = f.observe(m.request_id).await?;
    let stop = cleanup(&m, m.expected_launch_generation);
    let i = f.issue(stop.clone()).await?;
    f.journal
        .settle(i, receipt(&stop, &f.facts, ManagedLifecycle::Stopped))
        .await?;
    ensure!(f.observe(m.request_id).await? == original && original.phase == ManagedPhase::Issued);
    ensure!(f.admit(control(&m, ManagedAction::Restart)).await.is_ok());
});
database_case!(
    db_cleanup_mismatched_scope_and_generation_have_no_lease,
    f,
    {
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        f.journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        let mut stop = cleanup(&m, m.expected_launch_generation);
        stop.expected_launch_generation = 2;
        ensure!(f.admit(stop).await.is_err());
        let mut stop = cleanup(&m, m.expected_launch_generation);
        stop.support_image_sha256 = "d".repeat(64);
        ensure!(f.admit(stop).await.is_err());
        ensure!(f.counts().await? == (1, 1, 1));
    }
);
database_case!(db_unclean_exited_nonzero_stop_does_not_clear_unknown, f, {
    let m = launch(Uuid::new_v4());
    let i = f.issue(m.clone()).await?;
    let old = f
        .journal
        .mark_unknown(i, "platform-agent-dispatch-unknown")
        .await?;
    let stop = cleanup(&m, m.expected_launch_generation);
    let i = f.issue(stop.clone()).await?;
    let mut bad = receipt(&stop, &f.facts, ManagedLifecycle::Exited);
    bad.exit_code = Some(1);
    ensure!(f.journal.settle(i, bad).await?.phase == ManagedPhase::Unknown);
    ensure!(
        f.observe(m.request_id).await? == old
            && f.admit(control(&m, ManagedAction::Restart)).await.is_err()
    );
});
database_case!(db_restart_generation_cas_and_stale_controls_refuse, f, {
    let m = f.launch().await?;
    let restart = control(&m, ManagedAction::Restart);
    let i = f.issue(restart.clone()).await?;
    let result = f
        .journal
        .settle(i, receipt(&restart, &f.facts, ManagedLifecycle::Running))
        .await?;
    ensure!(result.receipt.unwrap().launch_generation == 2);
    for a in [
        ManagedAction::Message,
        ManagedAction::Stop,
        ManagedAction::Restart,
    ] {
        ensure!(f.admit(control(&m, a)).await.is_err());
    }
    let mut next = m;
    next.expected_launch_generation = 2;
    let _ = f.admit(control(&next, ManagedAction::Message)).await?;
});
database_case!(
    db_linked_stop_after_unknown_restart_advances_only_cleanup_generation,
    f,
    {
        let m = f.launch().await?;
        let restart = control(&m, ManagedAction::Restart);
        let issued = f.issue(restart.clone()).await?;
        let original = f
            .journal
            .mark_unknown(issued, "platform-agent-dispatch-unknown")
            .await?;
        let stop = cleanup(&restart, 2);
        let issued = f.issue(stop.clone()).await?;
        let mut proof = receipt(&stop, &f.facts, ManagedLifecycle::Stopped);
        proof.cleanup_previous_generation = 1;
        let completed = f.journal.settle(issued, proof).await?;
        ensure!(
            completed.phase == ManagedPhase::Completed
                && completed.cleanup_of == Some(restart.request_id)
                && f.observe(restart.request_id).await? == original
        );
        let conversation: (String, bool, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT launch_generation,known_clean,active_request_id,cleanup_request_id \
             FROM environment_platform_agent_conversations WHERE driver_id=$1",
        )
        .bind(m.driver_id)
        .fetch_one(&f.pool)
        .await?;
        ensure!(conversation == ("2".into(), true, None, None));
        ensure!(matches!(
            f.journal
                .admit(f.facts.clone(), &f.user, stop.clone())
                .await?,
            Admission::Existing(r) if *r == completed
        ));
        for altered in 0..3 {
            let mut changed = stop.clone();
            match altered {
                0 => changed.cleanup_of_request_id = Some(Uuid::new_v4()),
                1 => changed.private_fingerprint = "d".repeat(64),
                2 => changed.expected_launch_generation = 1,
                _ => unreachable!(),
            }
            ensure!(f.admit(changed).await.is_err());
        }
        let delegated = AuthUser {
            via_api_key: true,
            org_id: Some(ORG.into()),
            ..f.user.clone()
        };
        ensure!(
            f.journal
                .admit(f.facts.clone(), &delegated, stop)
                .await
                .is_err()
        );
        let states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM organization_mutation_leases ORDER BY admitted_at,id",
        )
        .fetch_all(&f.pool)
        .await?;
        ensure!(
            states.iter().filter(|s| s.as_str() == "resolved").count() == 1
                && states.iter().filter(|s| s.as_str() == "released").count() == 2
        );
        ensure!(f.admit(control(&m, ManagedAction::Restart)).await.is_err());
        let mut current = m;
        current.expected_launch_generation = 2;
        ensure!(
            f.admit(control(&current, ManagedAction::Message))
                .await
                .is_err()
        );
        let restart = control(&current, ManagedAction::Restart);
        let issued = f.issue(restart.clone()).await?;
        let completed = f
            .journal
            .settle(
                issued,
                receipt(&restart, &f.facts, ManagedLifecycle::Running),
            )
            .await?;
        ensure!(completed.receipt.unwrap().launch_generation == 3);
    }
);
database_case!(
    db_cleanup_requires_explicit_original_unknown_restart_for_plus_one,
    f,
    {
        for phase in [ManagedPhase::Issued, ManagedPhase::Unknown] {
            for action in [
                ManagedAction::Launch,
                ManagedAction::Message,
                ManagedAction::Restart,
            ] {
                let launch = if action == ManagedAction::Launch {
                    launch(Uuid::new_v4())
                } else {
                    f.launch().await?
                };
                let original = if action == ManagedAction::Launch {
                    launch.clone()
                } else {
                    control(&launch, action)
                };
                let issued = f.issue(original.clone()).await?;
                if phase == ManagedPhase::Unknown {
                    f.journal
                        .mark_unknown(issued, "platform-agent-dispatch-unknown")
                        .await?;
                } else {
                    drop(issued);
                }
                let before = f.counts().await?;
                for bad in 0..6 {
                    let mut stop = cleanup(&original, 2);
                    match bad {
                        0 => stop.cleanup_of_request_id = None,
                        1 => stop.cleanup_of_request_id = Some(Uuid::new_v4()),
                        2 => stop.driver_id = Uuid::new_v4(),
                        3 => stop.support_image_sha256 = "e".repeat(64),
                        4 => stop.support_image_size += 1,
                        5 => stop.expected_launch_generation = 3,
                        _ => unreachable!(),
                    }
                    if bad == 2 {
                        stop.session_id = format!("session-{}", stop.driver_id);
                    }
                    ensure!(f.admit(stop).await.is_err());
                }
                if phase != ManagedPhase::Unknown || action != ManagedAction::Restart {
                    ensure!(f.admit(cleanup(&original, 2)).await.is_err());
                }
                let mut wrong_binding = f.facts.clone();
                wrong_binding.environment_generation += 1;
                ensure!(
                    f.journal
                        .admit(wrong_binding, &f.user, cleanup(&original, 1))
                        .await
                        .is_err()
                );
                ensure!(f.counts().await? == before);
                let same_generation = cleanup(&original, 1);
                let (_, owner) = f.admit(same_generation.clone()).await?;
                ensure!(matches!(
                    f.journal
                        .admit(f.facts.clone(), &f.user, same_generation)
                        .await?,
                    Admission::Existing(_)
                ));
                f.journal
                    .reject_before_issue(owner, "platform-agent-preissue-refused")
                    .await?;
                ensure!(f.observe(original.request_id).await?.phase == phase);
            }
        }
    }
);
database_case!(
    db_cleanup_lineage_receipts_refuse_generic_current_generation_evidence,
    f,
    {
        let launch = f.launch().await?;
        let restart = control(&launch, ManagedAction::Restart);
        let issued = f.issue(restart.clone()).await?;
        let original = f
            .journal
            .mark_unknown(issued, "platform-agent-dispatch-unknown")
            .await?;
        let mut rejected = Vec::new();
        for case in 0..10 {
            let stop = cleanup(&restart, 2);
            let issued = f.issue(stop.clone()).await?;
            let mut bad = receipt(&stop, &f.facts, ManagedLifecycle::Stopped);
            bad.cleanup_previous_generation = 1;
            match case {
                0 => bad.cleanup_previous_generation = 2,
                1 => bad.cleanup_previous_generation = 0,
                2 => bad.cleanup_of_request_id = None,
                3 => bad.cleanup_of_request_id = Some(Uuid::new_v4()),
                4 => bad.cleanup_previous_cleanup_known = false,
                5 => bad.cleanup_unknown = true,
                6 => bad.lifecycle = ManagedLifecycle::Running,
                7 => bad.private_fingerprint = "e".repeat(64),
                8 => bad.launch_generation = 3,
                9 => bad.exit_code = Some(0), // Stopped must carry no exit code.
                _ => unreachable!(),
            }
            let result = f.journal.settle(issued, bad).await?;
            ensure!(result.phase == ManagedPhase::Unknown && result.receipt.is_none());
            rejected.push(result);
            ensure!(
                f.observe(restart.request_id).await? == original
                    && f.admit(control(&launch, ManagedAction::Restart))
                        .await
                        .is_err()
            );
        }
        let stop = cleanup(&restart, 2);
        let issued = f.issue(stop.clone()).await?;
        let mut proof = receipt(&stop, &f.facts, ManagedLifecycle::Exited);
        proof.cleanup_previous_generation = 1;
        ensure!(f.journal.settle(issued, proof).await?.phase == ManagedPhase::Completed);
        ensure!(f.observe(restart.request_id).await? == original);
        for saved in rejected {
            ensure!(f.observe(saved.mutation.request_id).await? == saved);
        }
        let unresolved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_mutation_leases WHERE state='resolution_required'",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(unresolved == 0);
    }
);
database_case!(
    db_private_receipt_codec_refuses_malformed_cleanup_tuple_before_intake,
    f,
    {
        let launch = launch(Uuid::new_v4());
        let restart = control(&launch, ManagedAction::Restart);
        let stop = cleanup(&restart, 2);
        let valid = private::PlatformManagedReceipt {
            request_id: stop.request_id.to_string(),
            scope: Some(scope()),
            fingerprint_sha256: stop.private_fingerprint.clone(),
            phase: private::PlatformManagedRequestPhase::Completed as i32,
            session_id: stop.session_id.clone(),
            driver_id: stop.driver_id.to_string(),
            launch_generation: 2,
            session_state: private::SessionLifecycleState::Stopped as i32,
            cleanup_of_request_id: Some(restart.request_id.to_string()),
            cleanup_previous_generation: 1,
            cleanup_previous_cleanup_known: true,
            reason: "settled".into(),
            ..Default::default()
        };
        ManagedReceipt::from_private(&valid)?.validate_for(&stop, &f.facts)?;
        for case in 0..8 {
            let mut bad = valid.clone();
            match case {
                0 => bad.cleanup_of_request_id = Some(String::new()),
                1 => bad.cleanup_of_request_id = Some(stop.request_id.to_string()),
                2 => bad.cleanup_previous_generation = 0,
                3 => bad.cleanup_previous_generation = 3,
                4 => bad.cleanup_previous_cleanup_known = false,
                5 => bad.exit_code = Some(0),
                6 => {
                    bad.phase = private::PlatformManagedRequestPhase::Unknown as i32;
                    bad.cleanup_previous_cleanup_known = false;
                    bad.reason = "issued-outcome-unknown".into();
                    bad.pipe_acknowledged = true;
                }
                7 => bad.reason = "untrusted dynamic diagnostic".into(),
                _ => unreachable!(),
            }
            ensure!(ManagedReceipt::from_private(&bad).is_err());
        }
        ensure!(f.counts().await? == (0, 0, 0));
    }
);
database_case!(
    db_cleanup_lease_resolution_is_exact_class_scope_state_and_recovery_code,
    f,
    {
        for case in 0..5 {
            let original = launch(Uuid::new_v4());
            let issued = f.issue(original.clone()).await?;
            let unknown = f
                .journal
                .mark_unknown(issued, "platform-agent-dispatch-unknown")
                .await?;
            let lease: String = sqlx::query_scalar(
                "SELECT mutation_lease_id FROM environment_platform_agent_requests WHERE request_id=$1",
            )
            .bind(original.request_id)
            .fetch_one(&f.pool)
            .await?;
            let update = match case {
                0 => {
                    "UPDATE organization_mutation_leases SET organization_id='foreign-org' WHERE id=$1"
                }
                1 => {
                    "UPDATE organization_mutation_leases SET environment_id='foreign-env' WHERE id=$1"
                }
                2 => {
                    "UPDATE organization_mutation_leases SET environment_id=NULL,mutation_class='billing_provider' WHERE id=$1"
                }
                3 => {
                    "UPDATE organization_mutation_leases SET recovery_code='foreign_recovery' WHERE id=$1"
                }
                4 => {
                    "UPDATE organization_mutation_leases SET state='active',resolution_required_at=NULL,recovery_code=NULL WHERE id=$1"
                }
                _ => unreachable!(),
            };
            sqlx::query(update).bind(&lease).execute(&f.pool).await?;
            let before: serde_json::Value = sqlx::query_scalar(
                "SELECT to_jsonb(l) FROM organization_mutation_leases l WHERE id=$1",
            )
            .bind(&lease)
            .fetch_one(&f.pool)
            .await?;
            let stop = cleanup(&original, 1);
            let issued = f.issue(stop.clone()).await?;
            ensure!(
                f.journal
                    .settle(issued, receipt(&stop, &f.facts, ManagedLifecycle::Stopped))
                    .await
                    .is_err()
            );
            let after: serde_json::Value = sqlx::query_scalar(
                "SELECT to_jsonb(l) FROM organization_mutation_leases l WHERE id=$1",
            )
            .bind(&lease)
            .fetch_one(&f.pool)
            .await?;
            ensure!(
                after == before
                    && f.observe(original.request_id).await? == unknown
                    && f.observe(stop.request_id).await?.phase == ManagedPhase::Issued
                    && f.admit(control(&original, ManagedAction::Restart))
                        .await
                        .is_err()
            );
        }
    }
);
database_case!(
    db_cleanup_issue_rechecks_current_actor_and_full_binding,
    f,
    {
        let launch = f.launch().await?;
        let restart = control(&launch, ManagedAction::Restart);
        let issued = f.issue(restart.clone()).await?;
        let original = f
            .journal
            .mark_unknown(issued, "platform-agent-dispatch-unknown")
            .await?;
        let stop = cleanup(&restart, 2);
        let (_, owner) = f.admit(stop.clone()).await?;
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        ensure!(f.journal.issue(&owner, &f.user).await.is_err());
        sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=10 WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        ensure!(f.journal.issue(&owner, &f.user).await.is_err());
        sqlx::query("UPDATE environments SET environment_operation_generation=9 WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        ensure!(f.observe(stop.request_id).await?.phase == ManagedPhase::Admitted);
        let issued = f.journal.issue(&owner, &f.user).await?;
        let mut proof = receipt(&stop, &f.facts, ManagedLifecycle::Stopped);
        proof.cleanup_previous_generation = 1;
        ensure!(f.journal.settle(issued, proof).await?.phase == ManagedPhase::Completed);
        ensure!(f.observe(restart.request_id).await? == original);
    }
);
database_case!(
    db_malformed_target_receipt_becomes_unknown_never_releases,
    f,
    {
        let m = f.launch().await?;
        let message = control(&m, ManagedAction::Message);
        let i = f.issue(message.clone()).await?;
        let mut bad = receipt(&message, &f.facts, ManagedLifecycle::Running);
        bad.message_id = Some(Uuid::new_v4());
        ensure!(f.journal.settle(i, bad).await?.phase == ManagedPhase::Unknown);
        ensure!(f.admit(control(&m, ManagedAction::Message)).await.is_err());
        let leases: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_mutation_leases WHERE state='resolution_required'",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(leases == 1);
    }
);
database_case!(
    db_action_receipts_require_original_scope_generation_and_ack,
    f,
    {
        for case in 0..11 {
            let launch = f.launch().await?;
            let action = match case {
                0 => ManagedAction::Restart,
                1 => ManagedAction::Stop,
                2 => ManagedAction::Interrupt,
                _ => ManagedAction::Message,
            };
            let m = control(&launch, action);
            let issued = f.issue(m.clone()).await?;
            let mut bad = receipt(&m, &f.facts, ManagedLifecycle::Running);
            match case {
                0 => bad.launch_generation = m.expected_launch_generation,
                1 => {} // A live monitor does not attest known-clean Stop.
                2 => bad.native_acknowledged = false,
                3 => bad.pipe_acknowledged = false,
                4 => bad.private_fingerprint = "e".repeat(64),
                5 => bad.request_id = Uuid::new_v4(),
                6 => bad.pod_uid = Uuid::new_v4().to_string(),
                7 => bad.binding_generation += 1,
                8 => bad.projection_selection_sha256 = "d".repeat(64),
                9 | 10 => {
                    bad.phase = ManagedPhase::Rejected;
                    bad.reason_code = "refused-before-issue".into();
                    bad.pipe_acknowledged = case == 10;
                    bad.cleanup_unknown = case == 9;
                }
                _ => unreachable!(),
            }
            let saved = f.journal.settle(issued, bad).await?;
            ensure!(
                saved.phase == ManagedPhase::Unknown && saved.receipt.is_none(),
                "invalid receipt case {case} was settled"
            );
            ensure!(
                f.admit(control(&launch, ManagedAction::Restart))
                    .await
                    .is_err()
            );
            ensure!(f.observe(m.request_id).await? == saved);
        }
    }
);
database_case!(db_lifecycle_receipts_cannot_claim_message_control_ack, f, {
    for action in [
        ManagedAction::Launch,
        ManagedAction::Stop,
        ManagedAction::Restart,
    ] {
        for native in [false, true] {
            let mutation = if action == ManagedAction::Launch {
                launch(Uuid::new_v4())
            } else {
                control(&f.launch().await?, action)
            };
            let issued = f.issue(mutation.clone()).await?;
            let lifecycle = if action == ManagedAction::Stop {
                ManagedLifecycle::Stopped
            } else {
                ManagedLifecycle::Running
            };
            let mut bad = receipt(&mutation, &f.facts, lifecycle);
            bad.pipe_acknowledged = true;
            bad.native_acknowledged = native;
            let saved = f.journal.settle(issued, bad).await?;
            ensure!(saved.phase == ManagedPhase::Unknown && saved.receipt.is_none());
        }
    }
});
database_case!(
    db_operator_grant_revocation_prevents_issued_permission,
    f,
    {
        sqlx::query("UPDATE environments SET created_by='fixture-admin' WHERE id=$1")
            .bind(ENV)
            .execute(&f.pool)
            .await?;
        sqlx::query("INSERT INTO environment_access(environment_id,user_id,permission,granted_by) VALUES($1,$2,'operator','fixture-admin')")
        .bind(ENV).bind(ACTOR).execute(&f.pool).await?;
        let m = launch(Uuid::new_v4());
        let (_, owner) = f.admit(m.clone()).await?;
        sqlx::query("DELETE FROM environment_access WHERE environment_id=$1 AND user_id=$2")
            .bind(ENV)
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        ensure!(f.journal.issue(&owner, &f.user).await.is_err());
        let phase: String = sqlx::query_scalar(
            "SELECT phase FROM environment_platform_agent_requests WHERE request_id=$1",
        )
        .bind(m.request_id)
        .fetch_one(&f.pool)
        .await?;
        ensure!(phase == "admitted" && f.counts().await? == (1, 1, 1));
        ensure!(f.observe(m.request_id).await.is_err());
    }
);
database_case!(db_known_preissue_refusal_releases_only_its_lease, f, {
    let m = launch(Uuid::new_v4());
    let (_, o) = f.admit(m.clone()).await?;
    let r = f
        .journal
        .reject_before_issue(o, "platform-agent-preissue-refused")
        .await?;
    ensure!(r.phase == ManagedPhase::Rejected && r.issued_at.is_none());
    let state: String = sqlx::query_scalar("SELECT state FROM organization_mutation_leases")
        .fetch_one(&f.pool)
        .await?;
    ensure!(state == "released");
    ensure!(matches!(
        f.journal.admit(f.facts.clone(), &f.user, m).await?,
        Admission::Existing(_)
    ));
});
database_case!(
    db_atomic_rollback_removes_request_conversation_and_lease,
    f,
    {
        let mut tx = f.pool.begin().await?;
        let m = launch(Uuid::new_v4());
        let _ = f
            .journal
            .admit_in(&mut tx, &f.facts, &f.user, &m, None)
            .await?;
        tx.rollback().await?;
        ensure!(f.counts().await? == (0, 0, 0));
    }
);
database_case!(db_parent_requires_original_known_generation_and_scope, f, {
    let parent = f.launch().await?;
    let mut child = launch(Uuid::new_v4());
    child.parent_session_id = Some(parent.session_id.clone());
    child.expected_parent_launch_generation = 1;
    let _ = f.admit(child.clone()).await?;
    child.request_id = Uuid::new_v4();
    child.driver_id = child.request_id;
    child.session_id = format!("session-{}", child.driver_id);
    child.expected_parent_launch_generation = 2;
    ensure!(f.admit(child).await.is_err());
});
database_case!(
    db_lossless_u64_generation_and_checked_restart_overflow,
    f,
    {
        let mut m = f.launch().await?;
        // Model a legitimately old retained generation without u64-many restarts.
        // Only this disposable fixture changes its generator; production triggers
        // remain mandatory on every journal operation tested below.
        sqlx::query("ALTER TABLE environment_platform_agent_conversations DISABLE TRIGGER environment_platform_agent_conversation_immutable").execute(&f.pool).await?;
        sqlx::query("UPDATE environment_platform_agent_conversations SET launch_generation=$1")
            .bind(u64::MAX.to_string())
            .execute(&f.pool)
            .await?;
        sqlx::query("ALTER TABLE environment_platform_agent_conversations ENABLE TRIGGER environment_platform_agent_conversation_immutable").execute(&f.pool).await?;
        m.expected_launch_generation = u64::MAX;
        let message = control(&m, ManagedAction::Message);
        let i = f.issue(message.clone()).await?;
        let result = f
            .journal
            .settle(i, receipt(&message, &f.facts, ManagedLifecycle::Running))
            .await?;
        ensure!(result.receipt.unwrap().launch_generation == u64::MAX);
        ensure!(f.admit(control(&m, ManagedAction::Restart)).await.is_err());
        for value in ["0", "01", "18446744073709551616"] {
            ensure!(
                sqlx::query(
                    "UPDATE environment_platform_agent_conversations SET launch_generation=$1"
                )
                .bind(value)
                .execute(&f.pool)
                .await
                .is_err()
            );
        }
    }
);
database_case!(
    db_terminal_rows_and_original_identity_cannot_delete_or_replay,
    f,
    {
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        let old = f
            .journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        for query in [
            "UPDATE environment_platform_agent_requests SET phase='admitted'",
            "UPDATE environment_platform_agent_requests SET fingerprint=repeat('d',64)",
            "DELETE FROM environment_platform_agent_requests",
            "DELETE FROM environment_platform_agent_conversations",
        ] {
            ensure!(sqlx::query(query).execute(&f.pool).await.is_err());
        }
        ensure!(f.observe(m.request_id).await? == old);
    }
);

#[tokio::test]
#[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
async fn db_migration39_fresh_upgrade_rollback_and_retained_evidence_refusal() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        // The fixture database carries every embedded migration. Return it to
        // version 39 and prove only this boundary, so a later migration can
        // neither enter this proof nor be undone by it.
        application_migrator().undo(&db.pool, 39).await?;
        let migrator = boundary39_migrator();
        let fresh = schema(&db.pool).await?;
        ensure!(fresh == SCHEMA39);
        println!("MEASURED_PLATFORM_MANAGED_SCHEMA39={fresh}");
        migrator.undo(&db.pool, 38).await?;
        ensure!(schema(&db.pool).await? == SCHEMA38);
        let mut h = Sha384::new();
        for m in migrator
            .iter()
            .filter(|m| m.version <= 38 && m.migration_type.is_up_migration())
        {
            h.update(Sha384::digest(m.sql.as_bytes()));
        }
        ensure!(format!("{:x}", h.finalize()) == HISTORY38);
        let f = Fixture::seed(&db.pool).await?;
        let before: Vec<String> =
            sqlx::query_scalar("SELECT row_to_json(e)::text FROM environments e ORDER BY id")
                .fetch_all(&db.pool)
                .await?;
        migrator.run(&db.pool).await?;
        ensure!(schema(&db.pool).await? == fresh);
        let after: Vec<String> =
            sqlx::query_scalar("SELECT row_to_json(e)::text FROM environments e ORDER BY id")
                .fetch_all(&db.pool)
                .await?;
        ensure!(after == before);
        let m = launch(Uuid::new_v4());
        let i = f.issue(m.clone()).await?;
        f.journal
            .mark_unknown(i, "platform-agent-dispatch-unknown")
            .await?;
        ensure!(migrator.undo(&db.pool, 38).await.is_err());
        ensure!(
            f.observe(m.request_id).await?.phase == ManagedPhase::Unknown
                && schema(&db.pool).await? == fresh
        );
        let latest: i64 =
            sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
                .fetch_one(&db.pool)
                .await?;
        ensure!(latest == 39);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Embedded migrations 1..=39, up and down: the managed-agent boundary.
fn boundary39_migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            application_migrator()
                .iter()
                .filter(|m| m.version <= 39)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

async fn wait_blocker(pool: &PgPool, pid: i32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(pool)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}
database_case!(
    db_caller_drop_does_not_cancel_owned_commit_or_reacquire_owner,
    f,
    {
        let mut blocker = f.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(ACTOR)
            .execute(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let j = f.journal.clone();
        let b = f.facts.clone();
        let u = f.user.clone();
        let m = launch(Uuid::new_v4());
        let intent = m.clone();
        let caller = tokio::spawn(async move { j.admit(b, &u, intent).await });
        wait_blocker(&f.pool, pid).await?;
        caller.abort();
        let _ = caller.await;
        blocker.commit().await?;
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if f.observe(m.request_id).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        ensure!(
            matches!(
                f.journal.admit(f.facts.clone(), &f.user, m).await?,
                Admission::Existing(_)
            ) && f.counts().await? == (1, 1, 1)
        );
    }
);
database_case!(
    db_issue_waits_for_authority_lock_and_sees_committed_revocation,
    f,
    {
        let m = launch(Uuid::new_v4());
        let (_, owner) = f.admit(m.clone()).await?;
        let mut blocker = f.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(ACTOR)
            .execute(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let j = f.journal.clone();
        let user = f.user.clone();
        let worker = tokio::spawn(async move { j.issue(&owner, &user).await });
        wait_blocker(&f.pool, pid).await?;
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(ACTOR)
            .execute(&mut *blocker)
            .await?;
        blocker.commit().await?;
        ensure!(worker.await?.is_err());
        sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
            .bind(ACTOR)
            .execute(&f.pool)
            .await?;
        ensure!(f.observe(m.request_id).await?.phase == ManagedPhase::Admitted);
    }
);

#[tokio::test]
#[ignore = "invoked only by the owned abrupt-exit parent fixture"]
async fn crash_after_journal_helper() -> Result<()> {
    let phase = std::env::var("CW_PLATFORM_JOURNAL_CRASH_PHASE")?;
    let id = uuid(&std::env::var("CW_PLATFORM_JOURNAL_CRASH_ID")?)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("TEST_DATABASE_URL")?)
        .await?;
    let facts = read_facts(&pool).await?;
    let j = ManagedJournal::new(pool.clone(), flags());
    let u = AuthUser {
        user_id: ACTOR.into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    let mutation = if phase == "linked-effect" {
        let original_id = uuid(&std::env::var("CW_PLATFORM_JOURNAL_ORIGINAL_ID")?)?;
        let original = j.observe(&u, ORG, ENV, original_id).await?;
        ensure!(
            original.phase == ManagedPhase::Unknown
                && original.mutation.action == ManagedAction::Restart
        );
        let mut advanced = original.mutation;
        advanced.expected_launch_generation = advanced
            .expected_launch_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("synthetic cleanup generation overflow"))?;
        control_with_id(&advanced, ManagedAction::Stop, Some(original_id), id)
    } else {
        launch(id)
    };
    let (_, o) = own(j.admit(facts, &u, mutation).await?)?;
    if phase == "admitted" {
        std::process::exit(77);
    }
    let _issued = j.issue(&o, &u).await?;
    if matches!(phase.as_str(), "effect" | "linked-effect") {
        sqlx::query("INSERT INTO synthetic_platform_journal_effects(request_id) VALUES($1)")
            .bind(id)
            .execute(&pool)
            .await?;
    }
    ensure!(matches!(
        phase.as_str(),
        "issued" | "effect" | "linked-effect"
    ));
    std::process::exit(77);
}
database_case!(
    db_actual_crash_boundaries_preserve_tombstones_without_effect_replay,
    f,
    {
        sqlx::query("CREATE TABLE synthetic_platform_journal_effects(request_id uuid PRIMARY KEY)")
            .execute(&f.pool)
            .await?;
        let dbname: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&f.pool)
            .await?;
        let mut url = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        url.set_path(&dbname);
        for phase in ["admitted", "issued", "effect"] {
            let id = Uuid::new_v4();
            let mut child = tokio::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "api::platform_agents::journal::database_tests::crash_after_journal_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("TEST_DATABASE_URL", url.as_str())
                .env("CW_PLATFORM_JOURNAL_CRASH_ID", id.to_string())
                .env("CW_PLATFORM_JOURNAL_CRASH_PHASE", phase)
                .kill_on_drop(true)
                .spawn()?;
            let result = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
                Ok(status) => status?,
                Err(error) => {
                    child.kill().await?;
                    child.wait().await?;
                    return Err(error.into());
                }
            };
            ensure!(
                result.code() == Some(77),
                "owned abrupt child did not reach {phase}"
            );
            let observed = f.observe(id).await?;
            ensure!(
                observed.phase
                    == if phase == "admitted" {
                        ManagedPhase::Admitted
                    } else {
                        ManagedPhase::Issued
                    }
            );
            ensure!(matches!(
                f.journal
                    .admit(f.facts.clone(), &f.user, launch(id))
                    .await?,
                Admission::Existing(_)
            ));
            let effects: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM synthetic_platform_journal_effects WHERE request_id=$1",
            )
            .bind(id)
            .fetch_one(&f.pool)
            .await?;
            ensure!(effects == i64::from(phase == "effect"));
        }
        ensure!(f.counts().await? == (3, 3, 3));
    }
);
database_case!(
    db_actual_linked_cleanup_crash_remains_observe_only_until_fresh_clean_stop,
    f,
    {
        sqlx::query("CREATE TABLE synthetic_platform_journal_effects(request_id uuid PRIMARY KEY)")
            .execute(&f.pool)
            .await?;
        let launch = f.launch().await?;
        let restart = control(&launch, ManagedAction::Restart);
        let issued = f.issue(restart.clone()).await?;
        let original = f
            .journal
            .mark_unknown(issued, "platform-agent-dispatch-unknown")
            .await?;
        let dbname: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&f.pool)
            .await?;
        let mut url = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        url.set_path(&dbname);
        let id = Uuid::new_v4();
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "api::platform_agents::journal::database_tests::crash_after_journal_helper",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TEST_DATABASE_URL", url.as_str())
            .env("CW_PLATFORM_JOURNAL_CRASH_ID", id.to_string())
            .env("CW_PLATFORM_JOURNAL_CRASH_PHASE", "linked-effect")
            .env(
                "CW_PLATFORM_JOURNAL_ORIGINAL_ID",
                restart.request_id.to_string(),
            )
            .kill_on_drop(true)
            .spawn()?;
        let status = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
            Ok(status) => status?,
            Err(error) => {
                child.kill().await?;
                child.wait().await?;
                return Err(error.into());
            }
        };
        ensure!(status.code() == Some(77));
        let crashed = f.observe(id).await?;
        ensure!(
            crashed.phase == ManagedPhase::Issued && crashed.cleanup_of == Some(restart.request_id)
        );
        ensure!(matches!(
            f.journal
                .admit(f.facts.clone(), &f.user, crashed.mutation.clone())
                .await?,
            Admission::Existing(r) if *r == crashed
        ));
        let stop = cleanup(&restart, 2);
        let issued = f.issue(stop.clone()).await?;
        let mut proof = receipt(&stop, &f.facts, ManagedLifecycle::Stopped);
        proof.cleanup_previous_generation = 1;
        ensure!(f.journal.settle(issued, proof).await?.phase == ManagedPhase::Completed);
        ensure!(
            f.observe(restart.request_id).await? == original && f.observe(id).await? == crashed
        );
        let effects: i64 =
            sqlx::query_scalar("SELECT count(*) FROM synthetic_platform_journal_effects")
                .fetch_one(&f.pool)
                .await?;
        let unresolved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_mutation_leases WHERE state IN ('active','resolution_required')",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(effects == 1 && unresolved == 0);
    }
);
database_case!(
    db_launch_denied_before_run_is_refused_and_releases_its_lease,
    f,
    {
        // #2705: the daemon refused an issued launch's projection before its
        // agent ran and confirmed cleanup. That is a definite refusal: the
        // conversation has no active request and the deletion lease is
        // released, not left resolution_required.
        let m = launch(Uuid::new_v4());
        let issued = f.issue(m.clone()).await?;
        let mut denied = receipt(&m, &f.facts, ManagedLifecycle::Failed);
        denied.phase = ManagedPhase::Rejected;
        denied.reason_code = "denied-before-run".into();
        denied.exit_code = None;
        let saved = f.journal.settle(issued, denied).await?;
        ensure!(saved.phase == ManagedPhase::Rejected);
        ensure!(f.observe(m.request_id).await? == saved);
        let (active, clean): (Option<Uuid>, bool) = sqlx::query_as(
            "SELECT active_request_id,known_clean FROM environment_platform_agent_conversations WHERE session_id=$1",
        )
        .bind(&m.session_id)
        .fetch_one(&f.pool)
        .await?;
        ensure!(active.is_none() && clean);
        let reason: String = sqlx::query_scalar(
            "SELECT reason_code FROM environment_platform_agent_requests WHERE request_id=$1",
        )
        .bind(m.request_id)
        .fetch_one(&f.pool)
        .await?;
        ensure!(reason == "platform-agent-command-refused");
        let unresolved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_mutation_leases WHERE state='resolution_required'",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(unresolved == 0);
        // Only a launch may be denied before it ran, and only as Failed with
        // confirmed cleanup; anything else stays unknown.
        for case in 0..3 {
            let launched = f.launch().await?;
            let (mutation, lifecycle) = match case {
                0 => (
                    control(&launched, ManagedAction::Stop),
                    ManagedLifecycle::Failed,
                ),
                _ => (launch(Uuid::new_v4()), ManagedLifecycle::Interrupted),
            };
            let issued = f.issue(mutation.clone()).await?;
            let mut bad = receipt(&mutation, &f.facts, lifecycle);
            bad.phase = ManagedPhase::Rejected;
            bad.reason_code = "denied-before-run".into();
            bad.exit_code = None;
            bad.pipe_acknowledged = false;
            bad.native_acknowledged = false;
            bad.cleanup_unknown = case == 2;
            if case == 2 {
                bad.lifecycle = ManagedLifecycle::Failed;
            }
            ensure!(
                f.journal.settle(issued, bad).await?.phase == ManagedPhase::Unknown,
                "invalid denial case {case} was settled"
            );
        }
    }
);
database_case!(
    db_resume_continues_a_conversation_of_the_released_pod_once,
    f,
    {
        // #2705: after a Stop/Start the conversation continues in the new Pod
        // from the last Pod a driver ran in, at its generation, once.
        let m = f.launch().await?;
        let refused = |result: AppResult<ResumePredecessor>, needle: &str| -> Result<()> {
            match result {
                Err(AppError::Coded { detail, .. }) if detail.contains(needle) => Ok(()),
                other => anyhow::bail!("expected a refusal naming {needle:?}, got {other:?}"),
            }
        };
        // Still this Pod's conversation: Restart is the operation for it.
        ensure!(
            f.journal
                .resume_predecessor(&f.facts, &m.session_id, m.driver_id)
                .await
                .is_err()
        );
        let facts2 = f.next_pod().await?;
        let predecessor = f
            .journal
            .resume_predecessor(&facts2, &m.session_id, m.driver_id)
            .await?;
        ensure!(
            predecessor
                == ResumePredecessor {
                    pod_uid: POD.into(),
                    namespace: "runtime-sandboxes".into(),
                    pod_name: format!("sandbox-{ENV}"),
                    generation: 1,
                    agent: ManagedAgent::Codex,
                }
        );
        // A Resume naming anything other than the checked predecessor, its
        // generation or its agent conflicts at admission.
        for (pod, generation) in [(SANDBOX, 1), (POD, 2)] {
            ensure!(
                f.journal
                    .admit_resume(
                        facts2.clone(),
                        &f.user,
                        resume(&m, pod, generation),
                        predecessor.clone()
                    )
                    .await
                    .is_err()
            );
        }
        // A Rejected Resume leaves the new Pod's row at the predecessor's
        // generation; the next Resume reuses it.
        let rejected = resume(&m, POD, 1);
        let (_, owner) = own(f
            .journal
            .admit_resume(
                facts2.clone(),
                &f.user,
                rejected.clone(),
                predecessor.clone(),
            )
            .await?)?;
        let issued = f.journal.issue(&owner, &f.user).await?;
        let mut refusal = receipt(&rejected, &facts2, ManagedLifecycle::Stopped);
        refusal.phase = ManagedPhase::Rejected;
        refusal.reason_code = "refused-before-issue".into();
        // A refusal advances nothing: the daemon reports the predecessor's
        // generation, not the one a completed Resume would reach.
        refusal.launch_generation = rejected.expected_launch_generation;
        ensure!(f.journal.settle(issued, refusal).await?.phase == ManagedPhase::Rejected);
        // The predecessor is still the last Pod a driver ran in.
        ensure!(
            f.journal
                .resume_predecessor(&facts2, &m.session_id, m.driver_id)
                .await?
                == predecessor
        );
        let r = resume(&m, POD, 1);
        let (_, owner) = own(f
            .journal
            .admit_resume(facts2.clone(), &f.user, r.clone(), predecessor.clone())
            .await?)?;
        let issued = f.journal.issue(&owner, &f.user).await?;
        let saved = f
            .journal
            .settle(issued, receipt(&r, &facts2, ManagedLifecycle::Running))
            .await?;
        ensure!(saved.phase == ManagedPhase::Completed);
        let rows: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
            "SELECT pod_uid,launch_generation,active_request_id FROM environment_platform_agent_conversations \
             WHERE session_id=$1 ORDER BY pod_uid=$2",
        )
        .bind(&m.session_id)
        .bind(Uuid::parse_str(POD2)?)
        .fetch_all(&f.pool)
        .await?;
        ensure!(
            rows.len() == 2
                && rows[0].0.to_string() == POD
                && rows[0].1 == "1"
                && rows[1].0.to_string() == POD2
                && rows[1].1 == "2"
                && rows[1].2.is_none(),
            "{rows:?}"
        );
        // Now this Pod's conversation: it is Restart's, and a second Resume
        // has no earlier Pod to continue from.
        ensure!(
            f.journal
                .resume_predecessor(&facts2, &m.session_id, m.driver_id)
                .await
                .is_err()
        );
        // A conversation whose last start has an unknown outcome has ended,
        // wherever that start was.
        let restart = ManagedMutation::from_private(&private::PlatformManagedMutationRequest {
            request_id: Uuid::new_v4().to_string(),
            scope: Some(scope2()),
            operation: Some(
                private::platform_managed_mutation_request::Operation::Control(
                    private::PlatformManagedControl {
                        action: private::PlatformManagedAction::Restart as i32,
                        session_id: m.session_id.clone(),
                        driver_id: m.driver_id.to_string(),
                        expected_launch_generation: 2,
                        ..Default::default()
                    },
                ),
            ),
        })?;
        let (_, owner) = own(f.journal.admit(facts2.clone(), &f.user, restart).await?)?;
        let issued = f.journal.issue(&owner, &f.user).await?;
        ensure!(
            f.journal
                .mark_unknown(issued, "platform-agent-dispatch-unknown")
                .await?
                .phase
                == ManagedPhase::Unknown
        );
        refused(
            f.journal
                .resume_predecessor(&facts2, &m.session_id, m.driver_id)
                .await,
            "unknown outcome",
        )?;
    }
);
fn resume_refusal(result: AppResult<ResumePredecessor>, needle: &str) -> Result<()> {
    match result {
        Err(AppError::Coded { code, detail, .. })
            if code == "platform_agent_resume_refused" && detail.contains(needle) =>
        {
            Ok(())
        }
        other => anyhow::bail!("expected a refusal naming {needle:?}, got {other:?}"),
    }
}
const POD3: &str = "6b2d3c4e-5f60-4a71-8b92-0a1b2c3d4e5f";
const POD4: &str = "8c3e4d5f-6071-4b82-9ca3-1b2c3d4e5f60";
database_case!(
    db_resume_refusals_name_why_and_an_unknown_resume_ends_the_conversation,
    f,
    {
        // #2705: each refusal says why. A Resume in progress in this Pod asks
        // the user to wait; an Unknown Resume at the predecessor's generation
        // ends the conversation wherever it ran.
        let m = f.launch().await?;
        let other = f.launch().await?;
        let mut child = launch(Uuid::new_v4());
        child.parent_session_id = Some(other.session_id.clone());
        child.expected_parent_launch_generation = 1;
        let issued = f.issue(child.clone()).await?;
        f.journal
            .settle(issued, receipt(&child, &f.facts, ManagedLifecycle::Running))
            .await?;
        let facts2 = f.next_pod().await?;
        let predecessor = f
            .journal
            .resume_predecessor(&facts2, &m.session_id, m.driver_id)
            .await?;
        let first = resume(&m, POD, 1);
        let (_, owner) = own(f
            .journal
            .admit_resume(facts2.clone(), &f.user, first.clone(), predecessor.clone())
            .await?)?;
        // A second Resume while the first is admitted in this Pod.
        match f
            .journal
            .admit_resume(
                facts2.clone(),
                &f.user,
                resume(&m, POD, 1),
                predecessor.clone(),
            )
            .await
        {
            Err(AppError::Coded { code, detail, .. })
                if code == "platform_agent_resume_refused"
                    && detail.contains("already resuming") => {}
            other => anyhow::bail!("expected the in-progress refusal, got {:?}", other.err()),
        }
        // ... and while it is issued here.
        let issued = f.journal.issue(&owner, &f.user).await?;
        resume_refusal(
            f.journal
                .resume_predecessor(&facts2, &m.session_id, m.driver_id)
                .await,
            "already resuming",
        )?;
        // Its outcome becomes unknown: the conversation has ended, here and
        // in every later Pod.
        ensure!(
            f.journal
                .mark_unknown(issued, "platform-agent-dispatch-unknown")
                .await?
                .phase
                == ManagedPhase::Unknown
        );
        resume_refusal(
            f.journal
                .resume_predecessor(&facts2, &m.session_id, m.driver_id)
                .await,
            "unknown outcome",
        )?;
        let facts3 = f.next_pod_as(POD2, POD3, 5, &"a".repeat(64)).await?;
        resume_refusal(
            f.journal
                .resume_predecessor(&facts3, &m.session_id, m.driver_id)
                .await,
            "unknown outcome",
        )?;
        // A child conversation ends with its environment.
        resume_refusal(
            f.journal
                .resume_predecessor(&facts3, &child.session_id, child.driver_id)
                .await,
            "child conversation",
        )?;
        // Unchanged selection: the other conversation still resumes.
        f.journal
            .resume_predecessor(&facts3, &other.session_id, other.driver_id)
            .await?;
        // A changed selection: credentials or secret sources.
        let facts4 = f.next_pod_as(POD3, POD4, 6, &"b".repeat(64)).await?;
        resume_refusal(
            f.journal
                .resume_predecessor(&facts4, &other.session_id, other.driver_id)
                .await,
            "selected credentials or secret sources changed",
        )?;
    }
);
database_case!(
    db_resume_admission_rereads_the_exact_checked_predecessor,
    f,
    {
        // #2705: the admission reads the predecessor again under its locks
        // and refuses unless it is exactly the one proven absent.
        let m = f.launch().await?;
        let facts2 = f.next_pod().await?;
        let predecessor = f
            .journal
            .resume_predecessor(&facts2, &m.session_id, m.driver_id)
            .await?;
        for checked in [
            ResumePredecessor {
                pod_name: "sandbox-another".into(),
                ..predecessor.clone()
            },
            ResumePredecessor {
                namespace: "another-namespace".into(),
                ..predecessor.clone()
            },
            ResumePredecessor {
                pod_uid: POD3.into(),
                ..predecessor.clone()
            },
            ResumePredecessor {
                generation: 2,
                ..predecessor.clone()
            },
            ResumePredecessor {
                agent: ManagedAgent::Claude,
                ..predecessor.clone()
            },
        ] {
            ensure!(
                f.journal
                    .admit_resume(facts2.clone(), &f.user, resume(&m, POD, 1), checked.clone())
                    .await
                    .is_err(),
                "{checked:?}"
            );
        }
        // Nothing was admitted for any of them.
        let rows: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM environment_platform_agent_requests \
                     WHERE mutation_json->>'action'='resume') \
                  + (SELECT count(*) FROM environment_platform_agent_conversations WHERE pod_uid=$1)",
        )
        .bind(Uuid::parse_str(POD2)?)
        .fetch_one(&f.pool)
        .await?;
        ensure!(rows == 0, "{rows}");
        own(f
            .journal
            .admit_resume(facts2, &f.user, resume(&m, POD, 1), predecessor)
            .await?)?;
    }
);
database_case!(db_resume_repeat_is_answered_from_its_first_admission, f, {
    // #2705: a repeated Resume request ID is answered from its first
    // admission in every phase, never re-derived or refused as in progress.
    let m = f.launch().await?;
    // A plain Resume reason on any other action is not a refusal.
    let l = launch(Uuid::new_v4());
    let issued = f.issue(l.clone()).await?;
    let mut wrong = receipt(&l, &f.facts, ManagedLifecycle::Unspecified);
    wrong.phase = ManagedPhase::Rejected;
    wrong.reason_code = "resume-driver-alive".into();
    ensure!(f.journal.settle(issued, wrong).await?.phase == ManagedPhase::Unknown);
    let facts2 = f.next_pod().await?;
    let predecessor = f
        .journal
        .resume_predecessor(&facts2, &m.session_id, m.driver_id)
        .await?;
    let r = resume(&m, POD, 1);
    ensure!(
        f.journal
            .saved_resume(&facts2, &f.user, r.request_id)
            .await?
            .is_none()
    );
    // A repeat admits nothing new.
    ensure!(
        f.journal
            .repeat_resume(facts2.clone(), &f.user, r.clone())
            .await
            .is_err()
    );
    let (_, owner) = own(f
        .journal
        .admit_resume(facts2.clone(), &f.user, r.clone(), predecessor.clone())
        .await?)?;
    ensure!(
        f.journal
            .saved_resume(&facts2, &f.user, r.request_id)
            .await?
            == Some(r.clone())
    );
    let repeat = |phase: ManagedPhase| {
        let (journal, facts, user, r) = (&f.journal, facts2.clone(), &f.user, r.clone());
        async move {
            let saved = journal.repeat_resume(facts, user, r).await?;
            ensure!(saved.phase == phase, "{:?}", saved.phase);
            Ok::<_, anyhow::Error>(saved)
        }
    };
    repeat(ManagedPhase::Admitted).await?;
    let issued = f.journal.issue(&owner, &f.user).await?;
    repeat(ManagedPhase::Issued).await?;
    // A different request under the same ID conflicts, and another action's
    // ID is never answered as a Resume.
    let mut changed = r.clone();
    changed.driver_id = Uuid::new_v4();
    changed.session_id = format!("session-{}", changed.driver_id);
    ensure!(
        f.journal
            .repeat_resume(facts2.clone(), &f.user, changed)
            .await
            .is_err()
    );
    ensure!(
        f.journal
            .saved_resume(&facts2, &f.user, m.request_id)
            .await
            .is_err()
    );
    // The target refused it for a plain reason: Rejected with that reason,
    // answered with its text on every repeat, and the row stays at the
    // predecessor's generation for the next Resume.
    let mut refusal = receipt(&r, &facts2, ManagedLifecycle::Unspecified);
    refusal.phase = ManagedPhase::Rejected;
    refusal.reason_code = "resume-driver-alive".into();
    refusal.launch_generation = r.expected_launch_generation;
    let saved = f.journal.settle(issued, refusal).await?;
    ensure!(saved.phase == ManagedPhase::Rejected);
    let text = crate::api::platform_agents::resume_rejection(&saved);
    ensure!(
        text.is_some_and(|t| t.contains("still running")),
        "{text:?}"
    );
    let again = repeat(ManagedPhase::Rejected).await?;
    ensure!(crate::api::platform_agents::resume_rejection(&again) == text);
    let generation: String = sqlx::query_scalar(
        "SELECT launch_generation FROM environment_platform_agent_conversations WHERE pod_uid=$1",
    )
    .bind(Uuid::parse_str(POD2)?)
    .fetch_one(&f.pool)
    .await?;
    ensure!(generation == "1");
    own(f
        .journal
        .admit_resume(facts2.clone(), &f.user, resume(&m, POD, 1), predecessor)
        .await?)?;
});
