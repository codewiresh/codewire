use super::*;

use crate::platform_test_support as support;
use support::{StatementCounter, TestDatabase, ensure_cheap_plans, quote_ident};

mod projection;

struct Fixture {
    db: TestDatabase,
    pool: sqlx::PgPool,
    role: String,
    scope: Scope,
    profile: AccessProfile,
    context: GrantContext,
    owner: Owner,
    kube: KubeFixture,
}

impl Fixture {
    async fn create() -> Result<Self> {
        let db = TestDatabase::create().await?;
        let setup=async {
            let mut selected=scope();
            let owner=db.user(&selected.creator).await?;
            db.organization(&selected.organization).await?;
            sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES ($1,$2,$3,'member')")
                .bind(&selected.member_id).bind(&selected.organization).bind(&selected.creator).execute(&db.pool).await?;
            sqlx::query("INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
                VALUES ('synthetic-preset',$1,'Synthetic','synthetic','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
                .bind(&selected.organization).execute(&db.pool).await?;
            sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
                VALUES ($1,$2,$3,'sandbox','synthetic-preset','running','started',7,'{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
                .bind(&selected.environment_id).bind(&selected.organization).bind(&selected.creator).execute(&db.pool).await?;
            // No setup-owner Pod UID: that completed-setup field is not durable.
            sqlx::query("INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_name,setup_complete) \
                VALUES ($1,$2,$3,$4,$5,true)")
                .bind(&selected.environment_id).bind(&selected.namespace).bind(&selected.claim_name)
                .bind(&selected.claim_uid).bind(&selected.pod_name).execute(&db.pool).await?;
            // Orchestration's claim-time binding of the reviewed workspace Pod.
            sqlx::query("INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid,operation_generation,managed_credential_clients,credential_scope) \
                VALUES ($1,$2,$3,$4,$5,$6,7,$7,$8)")
                .bind(&selected.pod_uid).bind(&selected.environment_id).bind(&selected.namespace)
                .bind(&selected.pod_name).bind(&selected.binding_claim_uid).bind(&selected.binding_sandbox_uid)
                .bind(&selected.managed_credential_clients).bind(&selected.credential_scope)
                .execute(&db.pool).await?;
            sqlx::query("UPDATE sandbox_environment_backend SET pod_uid=$2,bound_at=now() WHERE environment_id=$1")
                .bind(&selected.environment_id).bind(&selected.pod_uid).execute(&db.pool).await?;
            let credential=CredentialId::parse(Uuid::new_v4().to_string())?;
            // Only synthetic metadata is necessary. There is intentionally no
            // envelope, KEK, credential material or OAuth attempt in this DB.
            sqlx::query("INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
                VALUES ($1,$2,'openai','oauth','Synthetic','active',1,1)")
                .bind(credential.as_str()).bind(&selected.creator).execute(&db.pool).await?;
            let context=GrantContext {
                environment_id:EnvironmentId::parse(&selected.environment_id)?,
                environment_generation:7,placement:GrantPlacement::Platform,
                user_id:OwnerId::parse(&selected.creator)?,
                organization_id:Some(OwnerId::parse(&selected.organization)?),
                allow_personal_credentials:true,authorized_credentials:[credential.clone()].into_iter().collect(),
            };
            let manager=PlatformAccessProfileStore::new(db.pool.clone(),builtin_provider_catalog());
            // The creator's first profile is their default, whose owner never
            // changes; the bound profile is an ordinary one, so the authority
            // cases below can move it to another owner.
            manager.create(&owner,AccessProfileName::parse("default")?,BTreeMap::new()).await?;
            let profile=manager.create(&owner,AccessProfileName::parse("synthetic")?,
                BTreeMap::from([(CapabilitySlot::codex(),credential)])).await?;
            manager.create_binding(&context,EnvironmentAccessBinding {
                environment_id:context.environment_id.clone(),profile_id:profile.id.clone(),profile_revision:profile.revision,
            },Some(&context.user_id)).await?;
            selected.profile_id=Some(profile.id.to_string());
            sqlx::query("UPDATE environments SET project_spec=jsonb_set(project_spec,'{credentials}',$2) WHERE id=$1")
                .bind(&selected.environment_id)
                .bind(json!({"profile":format!("platform:id:{}",profile.id)})).execute(&db.pool).await?;
            let (pool,role)=db.metadata_pool().await?;
            let role_ident=quote_ident(&role);
            sqlx::query(&format!("REVOKE SELECT ON public.platform_credentials FROM {role_ident}")).execute(&db.pool).await?;
            for grant in [
                "SELECT (id,user_id,organization_id,provider,authentication_kind,status,expires_at_unix) ON public.platform_credentials",
                "SELECT (id,created_by,org_id,type,state,desired_state,deletion_requested_at,environment_operation_generation) ON public.environments",
                "SELECT (id,org_id,user_id,role) ON public.org_members",
                "SELECT (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_name,pod_uid,bound_at) ON public.sandbox_environment_backend",
                "SELECT (environment_id,pod_uid,claim_uid,sandbox_uid,managed_credential_clients,credential_scope,released_at) ON public.sandbox_workspace_bindings",
                "SELECT (id,user_id,organization_id) ON public.platform_access_profiles",
                "SELECT (profile_id,revision) ON public.platform_access_profile_revisions",
                "SELECT (profile_id,revision,capability_slot,credential_id) ON public.platform_access_profile_entries",
                "SELECT (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) ON public.platform_environment_access_bindings",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_projection_metadata(text)",
            ] {
                sqlx::query(&format!("GRANT {grant} TO {role_ident}")).execute(&db.pool).await?;
            }
            Ok::<_,anyhow::Error>((pool,role,selected,profile,context,owner))
        }.await;
        match setup {
            Ok((pool, role, scope, profile, context, owner)) => Ok(Self {
                db,
                pool,
                role,
                scope,
                profile,
                context,
                owner,
                kube: KubeFixture::new(),
            }),
            Err(error) => {
                db.finish(Err(error)).await?;
                unreachable!("setup failed")
            }
        }
    }
    fn authenticator(&self) -> KubernetesPlatformBridgeAuthenticator {
        KubernetesPlatformBridgeAuthenticator::new(
            self.kube.client(),
            self.pool.clone(),
            Arc::new(TestKekProvider),
            RELAY_NAMESPACE.to_owned(),
        )
    }
    async fn admitted(&self) -> Result<Arc<crate::KubernetesPlatformRuntimeAuthority>> {
        Ok(self
            .authenticator()
            .authenticate(&headers(unix_now()? + 600))
            .await?)
    }
    async fn rebind(&self) -> Result<()> {
        let manager =
            PlatformAccessProfileStore::new(self.db.pool.clone(), builtin_provider_catalog());
        let profile = manager
            .create(
                &self.owner,
                AccessProfileName::parse("other-exact-binding")?,
                self.profile.entries.clone(),
            )
            .await?;
        let mut tx = manager.begin_transaction().await?;
        manager
            .replace_binding_in(
                &mut tx,
                &self.context,
                &EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: self.profile.id.clone(),
                    profile_revision: self.profile.revision,
                },
                EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: profile.id.clone(),
                    profile_revision: profile.revision,
                },
                Some(&self.context.user_id),
            )
            .await?;
        sqlx::query("UPDATE environments SET project_spec=jsonb_set(project_spec,'{credentials}',$2) WHERE id=$1")
            .bind(&self.scope.environment_id)
            .bind(json!({"profile":format!("platform:id:{}",profile.id)}))
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Point the workspace Pod's binding at another Sandbox. Only a test can:
    /// the binding's immutability trigger is suspended for this one update,
    /// inside its transaction.
    async fn bind_sandbox(&self, sandbox_uid: &str) -> Result<()> {
        let mut tx = self.db.pool.begin().await?;
        sqlx::query(
            "ALTER TABLE public.sandbox_workspace_bindings \
             DISABLE TRIGGER codewire_workspace_binding_immutable",
        )
        .execute(&mut *tx)
        .await?;
        let updated = sqlx::query(
            "UPDATE public.sandbox_workspace_bindings SET sandbox_uid=$1 WHERE pod_uid=$2",
        )
        .bind(sandbox_uid)
        .bind(&self.scope.pod_uid)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        ensure!(updated == 1, "the workspace Pod's binding was not updated");
        sqlx::query(
            "ALTER TABLE public.sandbox_workspace_bindings \
             ENABLE TRIGGER codewire_workspace_binding_immutable",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn restore_membership(&self) -> Result<()> {
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES ($1,$2,$3,'member')")
            .bind(&self.scope.member_id)
            .bind(&self.scope.organization)
            .bind(&self.scope.creator)
            .execute(&self.db.pool)
            .await?;
        Ok(())
    }
    async fn finish(self, result: Result<()>) -> Result<()> {
        self.kube.gate.release();
        self.pool.close().await;
        self.db.finish(result).await
    }
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn restricted_metadata_login_admits_personal_scope_and_pins_exact_binding() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let identities: (String, String) =
            sqlx::query_as("SELECT current_user::text,session_user::text")
                .fetch_one(&fixture.pool)
                .await?;
        ensure!(identities == (fixture.role.clone(), fixture.role.clone()));
        let (authority, admission) = timing::measure(fixture.admitted()).await;
        let authority = authority?;
        ensure!(admission.token_review.count == 2 && admission.resolve.count == 1);
        let (session, timings) = timing::measure(authority.current_session()).await;
        session?;
        // One resolve, split into its Kubernetes reads and its SQL.
        ensure!(timings.resolve.count == 1);
        ensure!(timings.resolve_kubernetes > std::time::Duration::ZERO);
        ensure!(timings.resolve_sql() > std::time::Duration::ZERO);
        ensure!(timings.token_review.count == 0);
        // A later resolve issues every Kubernetes read at once: delaying each
        // costs it one delay, where reading the Claim, then its Sandbox cost
        // two. The time recorded is that wall time.
        const DELAY: Duration = Duration::from_millis(300);
        let delayed: BTreeMap<String, Duration> = fixture
            .kube
            .objects
            .lock()
            .unwrap()
            .keys()
            .map(|path| (path.clone(), DELAY))
            .collect();
        ensure!(delayed.len() == 3, "the three lineage objects");
        *fixture.kube.delays.lock().unwrap() = delayed;
        let (session, timings) = timing::measure(authority.current_session()).await;
        fixture.kube.delays.lock().unwrap().clear();
        session?;
        eprintln!(
            "later resolve: Kubernetes {:?} of {:?} total, each read delayed {DELAY:?}",
            timings.resolve_kubernetes, timings.resolve.elapsed
        );
        ensure!(
            timings.resolve_kubernetes >= DELAY && timings.resolve_kubernetes < DELAY * 2,
            "a later resolve's Kubernetes reads took {:?}, not one round trip",
            timings.resolve_kubernetes
        );
        ensure!(timings.resolve_kubernetes <= timings.resolve.elapsed);
        for sql in [
            "UPDATE public.environments SET state=state",
            "UPDATE public.org_members SET role=role",
            "UPDATE public.platform_access_profiles SET name=name",
            "SELECT id FROM public.users FOR SHARE",
            "SELECT setup_owner_pod_uid FROM public.sandbox_environment_backend",
            "SELECT workspace_pvc_uid FROM public.sandbox_environment_backend",
            "SELECT operation_generation FROM public.sandbox_workspace_bindings",
            "SELECT workspace_pvc_uid FROM public.sandbox_workspace_bindings",
            "UPDATE public.sandbox_workspace_bindings SET released_at=released_at",
            "UPDATE public.sandbox_environment_backend SET pod_uid=pod_uid",
            "SELECT display_name FROM public.platform_credentials",
            "SELECT * FROM public.platform_credential_material",
            "SELECT * FROM public.platform_credential_refresh_attempts",
            "SELECT * FROM public.tenant_secrets",
        ] {
            let error = sqlx::query(sql).execute(&fixture.pool).await.unwrap_err();
            ensure!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref()
                    == Some("42501")
            );
        }
        let reviews = fixture.kube.reviews.load(Ordering::SeqCst);
        fixture.rebind().await?; // same credential IDs and same explicit confirmer
        ensure!(matches!(
            authority.current_session().await,
            Err(PlatformRuntimeError::Denied)
        ));
        ensure!(
            fixture.kube.reviews.load(Ordering::SeqCst) == reviews,
            "connected tokens were re-reviewed/substituted"
        );
        fixture.admitted().await?.current_session().await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn live_revalidation_denies_membership_consent_backend_lifecycle_and_pod_changes()
-> Result<()> {
    let fixture = Fixture::create().await?;
    let result=async {
        let authority=fixture.admitted().await?;
        for (change,restore) in [
            ("DELETE FROM org_members WHERE id='synthetic-membership'",
             "INSERT INTO org_members(id,org_id,user_id,role) VALUES ('synthetic-membership','synthetic-org','synthetic-creator','member')"),
            ("UPDATE environments SET desired_state='stopped'","UPDATE environments SET desired_state='started'"),
            ("UPDATE environments SET environment_operation_generation=8","UPDATE environments SET environment_operation_generation=7"),
            ("UPDATE sandbox_environment_backend SET sandbox_claim_uid='fcb6ac9e-65c3-4d61-9bac-11d55dfd70dc'",
             "UPDATE sandbox_environment_backend SET sandbox_claim_uid='e78d4729-6710-4ad9-8b05-ecad87013e33'"),
            // An unbound runtime never scopes: the pointer is cleared, as it is
            // before orchestration records a binding.
            ("UPDATE sandbox_environment_backend SET pod_uid=NULL,bound_at=NULL",
             "UPDATE sandbox_environment_backend SET pod_uid='5334599b-3b66-4363-92b3-bd1cb230d95e',bound_at=now()"),
            ("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=NULL",
             "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by='synthetic-creator'"),
            ("UPDATE organizations SET deletion_state='deleting',deletion_generation=1,deletion_operation_id='synthetic-delete',deletion_workflow_id='synthetic-delete',deletion_requested_at=now(),deletion_phase='queued' WHERE id='synthetic-org'",
             "UPDATE organizations SET deletion_state='active',deletion_operation_id=NULL,deletion_workflow_id=NULL,deletion_requested_at=NULL,deletion_phase=NULL WHERE id='synthetic-org'"),
            ("UPDATE platform_access_profiles SET user_id=NULL,organization_id='synthetic-org' WHERE name='synthetic'",
             "UPDATE platform_access_profiles SET user_id='synthetic-creator',organization_id=NULL WHERE name='synthetic'"),
        ] {
            sqlx::query(change).execute(&fixture.db.pool).await?;
            ensure!(matches!(authority.current_session().await,Err(PlatformRuntimeError::Denied)));
            sqlx::query(restore).execute(&fixture.db.pool).await?;
            authority.current_session().await?;
        }
        let original=fixture.kube.objects.lock().unwrap().clone();
        for fault in 0..5 {
            {
                let mut values=fixture.kube.objects.lock().unwrap();
                let pod=values.get_mut(&pod_path(WORKSPACE)).unwrap();
                match fault {
                    0 => pod["metadata"]["uid"]=json!(Uuid::new_v4().to_string()),
                    1 => pod["metadata"]["deletionTimestamp"]=json!("2026-01-01T00:00:00Z"),
                    2 => pod["status"]["conditions"][0]["status"]=json!("False"),
                    3 => pod["metadata"]["labels"]["codewire.sh/environment-operation-generation"]=json!("6"),
                    _ => pod["metadata"]["ownerReferences"][0]["uid"]=json!(Uuid::new_v4().to_string()),
                }
            }
            ensure!(matches!(authority.current_session().await,Err(PlatformRuntimeError::Denied)));
            *fixture.kube.objects.lock().unwrap()=original.clone();
            authority.current_session().await?;
        }
        // A released binding never scopes again (a release is final), and a
        // pointer moved to the next Pod's binding does not admit this Pod.
        sqlx::query("UPDATE sandbox_workspace_bindings SET released_at=now() WHERE pod_uid=$1")
            .bind(WORKSPACE_UID).execute(&fixture.db.pool).await?;
        ensure!(matches!(authority.current_session().await,Err(PlatformRuntimeError::Denied)));
        ensure!(matches!(fixture.authenticator().authenticate(&headers(unix_now()?+600)).await,
            Err(PlatformBridgeAuthenticationError::Denied)));
        let next=Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid,operation_generation,managed_credential_clients,credential_scope) \
            SELECT $1,environment_id,namespace,pod_name,claim_uid,sandbox_uid,operation_generation,managed_credential_clients,credential_scope \
            FROM sandbox_workspace_bindings WHERE pod_uid=$2")
            .bind(&next).bind(WORKSPACE_UID).execute(&fixture.db.pool).await?;
        sqlx::query("UPDATE sandbox_environment_backend SET pod_uid=$1,bound_at=now()")
            .bind(&next).execute(&fixture.db.pool).await?;
        ensure!(matches!(authority.current_session().await,Err(PlatformRuntimeError::Denied)));
        ensure!(matches!(fixture.authenticator().authenticate(&headers(unix_now()?+600)).await,
            Err(PlatformBridgeAuthenticationError::Denied)));
        Ok(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn final_scope_reread_and_original_expiry_fence_pending_kubernetes() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let authority = fixture.admitted().await?;
        for change in ["membership", "binding"] {
            fixture.kube.gate.arm(pod_path(WORKSPACE));
            let authority = authority.clone();
            let task = tokio::spawn(async move { authority.current_session().await });
            fixture.kube.gate.wait().await?;
            if change == "membership" {
                sqlx::query("DELETE FROM org_members WHERE id='synthetic-membership'")
                    .execute(&fixture.db.pool)
                    .await?;
            } else {
                fixture.rebind().await?;
            }
            fixture.kube.gate.release();
            ensure!(matches!(
                tokio::time::timeout(TIMEOUT, task).await??,
                Err(PlatformRuntimeError::Denied)
            ));
            if change == "membership" {
                fixture.restore_membership().await?;
            }
        }
        let authority = fixture
            .authenticator()
            .authenticate(&headers(unix_now()? + 60))
            .await?;
        let reviews = fixture.kube.reviews.load(Ordering::SeqCst);
        fixture.kube.gate.arm(pod_path(WORKSPACE));
        let task = tokio::spawn(async move { authority.current_session().await });
        fixture.kube.gate.wait().await?;
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        tokio::time::resume();
        fixture.kube.gate.release();
        ensure!(matches!(task.await?, Err(PlatformRuntimeError::Denied)));
        ensure!(fixture.kube.reviews.load(Ordering::SeqCst) == reviews);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

/// The read order's backstop. Kubernetes names are immutable and UIDs unique,
/// so whatever a later resolve finds under a name other than its admission's
/// is another object, and the epoch's lineage equality denies the request even
/// when that successor is fully valid: a newly admitted epoch over the same
/// objects is admitted.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn later_resolves_deny_a_valid_successor_sandbox() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let authority = fixture.admitted().await?;
        let admitted = authority.current_session().await?;
        let original = fixture.kube.objects.lock().unwrap().clone();
        let sandbox_path = |name: &str| {
            format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/{name}")
        };
        let claim_path = format!(
            "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxclaims/{}",
            fixture.scope.claim_name
        );

        // The Claim and the binding name a successor Sandbox, which owns the
        // workspace Pod. A binding is insert-only (baseline schema), so its
        // trigger is suspended for this one update: the state cannot arise in
        // production, and is built here only so that every check but lineage
        // equality admits it. Here the scope's binding Sandbox differs too.
        let successor_sandbox = Uuid::new_v4().to_string();
        {
            let mut objects = fixture.kube.objects.lock().unwrap();
            let mut sandbox = objects[&sandbox_path("synthetic-sandbox")].clone();
            sandbox["metadata"]["name"] = json!("synthetic-sandbox-2");
            sandbox["metadata"]["uid"] = json!(successor_sandbox);
            objects.insert(sandbox_path("synthetic-sandbox-2"), sandbox);
            objects.get_mut(&claim_path).unwrap()["status"]["sandbox"]["name"] =
                json!("synthetic-sandbox-2");
            let owner = &mut objects.get_mut(&pod_path(WORKSPACE)).unwrap()["metadata"]
                ["ownerReferences"][0];
            owner["name"] = json!("synthetic-sandbox-2");
            owner["uid"] = json!(successor_sandbox);
        }
        fixture.bind_sandbox(&successor_sandbox).await?;
        ensure!(
            matches!(
                authority.current_session().await,
                Err(PlatformRuntimeError::Denied)
            ),
            "the epoch admitted a successor Sandbox"
        );
        fixture.admitted().await?.current_session().await?;

        // Restored, the first epoch's lineage is its own again.
        fixture.bind_sandbox(&fixture.scope.binding_sandbox_uid).await?;
        *fixture.kube.objects.lock().unwrap() = original;
        ensure!(authority.current_session().await? == admitted);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

/// Statement round trips of one runtime authority resolve, counted at the wire
/// after the admission resolve has prepared every statement on the one pooled
/// connection. Each count is exact: a change must update it deliberately.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn each_runtime_authority_resolve_takes_a_fixed_number_of_statement_round_trips() -> Result<()>
{
    let fixture = Fixture::create().await?;
    let result = async {
        let (counter, pool) = StatementCounter::pool(&fixture.pool, 1).await?;
        let authenticator = KubernetesPlatformBridgeAuthenticator::new(
            fixture.kube.client(),
            pool.clone(),
            Arc::new(TestKekProvider),
            RELAY_NAMESPACE.to_owned(),
        );
        let mut observed = Vec::new();
        // Scope and metadata; BEGIN, timeouts, owner and environment locks,
        // binding and revision, COMMIT; GitHub and ownership; the final scope
        // and metadata. With one statement per read these were 24 and 4.
        for (case, expected) in [("personal profile", 8), ("no profile", 2)] {
            if case == "no profile" {
                sqlx::query("DELETE FROM platform_environment_access_bindings")
                    .execute(&fixture.db.pool)
                    .await?;
                sqlx::query("UPDATE environments SET project_spec=project_spec-'credentials'")
                    .execute(&fixture.db.pool)
                    .await?;
            }
            let authority = authenticator
                .authenticate(&headers(unix_now()? + 600))
                .await?;
            let (session, statements) = counter.count(authority.current_session()).await;
            session?;
            observed.push((case, statements, expected));
        }
        ensure!(
            observed
                .iter()
                .all(|(_, counted, expected)| counted == expected),
            "statement round trips per resolve (case, observed, expected): {observed:?}"
        );
        // No statement on the path is planned large enough to be JIT-compiled.
        ensure_cheap_plans(&fixture.db.pool, &counter.texts()).await?;
        pool.close().await;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

/// The one-statement scope and metadata read and the one-statement GitHub and
/// ownership read: each condition they decide changes the runtime session on
/// its own, as the separate statements did, including in the final reread.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn merged_resolve_reads_decide_each_condition_alone() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        let authority = fixture.admitted().await?;
        let admitted = authority.current_session().await?;
        fixture.db.user("synthetic-other").await?;
        let credential = fixture
            .profile
            .entries
            .values()
            .next()
            .context("synthetic profile entry")?
            .to_string();
        let selected = format!(
            "UPDATE environments SET project_spec=jsonb_set(project_spec,'{{credentials}}',\
             '{{\"profile\":\"platform:id:{}\"}}')",
            fixture.profile.id
        );
        for (case, change, restore) in [
            // The scope half.
            (
                "membership",
                "DELETE FROM org_members WHERE id='synthetic-membership'".to_string(),
                "INSERT INTO org_members(id,org_id,user_id,role) \
                 VALUES ('synthetic-membership','synthetic-org','synthetic-creator','member')"
                    .to_string(),
            ),
            // The metadata half.
            (
                "profile reference",
                format!(
                    "UPDATE environments SET project_spec=jsonb_set(project_spec,'{{credentials}}',\
                     '{{\"profile\":\"platform:id:{}\"}}')",
                    Uuid::new_v4()
                ),
                selected.clone(),
            ),
            (
                "secret source",
                "UPDATE environments SET project_spec=\
                 jsonb_set(project_spec,'{secrets}','{\"user\":\"local\"}')"
                    .to_string(),
                "UPDATE environments SET project_spec=project_spec-'secrets'".to_string(),
            ),
            // The ownership half of the GitHub and ownership read.
            (
                "credential owner",
                format!("UPDATE platform_credentials SET user_id='synthetic-other' WHERE id='{credential}'"),
                format!("UPDATE platform_credentials SET user_id='synthetic-creator' WHERE id='{credential}'"),
            ),
        ] {
            sqlx::query(&change).execute(&fixture.db.pool).await?;
            ensure!(
                matches!(authority.current_session().await, Err(PlatformRuntimeError::Denied)),
                "{case}"
            );
            sqlx::query(&restore).execute(&fixture.db.pool).await?;
            ensure!(authority.current_session().await? == admitted, "{case} restored");
        }
        // The GitHub half: the creator's connection is authorized while it can
        // be used now, and omitted, not denied, when it cannot.
        let github = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,\
             status,revocation_generation,material_generation) \
             VALUES ($1,'synthetic-creator','github','oauth','GitHub','active',1,1)",
        )
        .bind(&github)
        .execute(&fixture.db.pool)
        .await?;
        let connected = authority.current_session().await?;
        ensure!(connected != admitted && format!("{connected:?}").contains(&github));
        for (change, restore) in [
            ("expires_at_unix=1", "expires_at_unix=NULL"),
            ("status='revoked'", "status='active'"),
        ] {
            sqlx::query(&format!("UPDATE platform_credentials SET {change} WHERE id=$1"))
                .bind(&github)
                .execute(&fixture.db.pool)
                .await?;
            ensure!(authority.current_session().await? == admitted, "{change}");
            sqlx::query(&format!("UPDATE platform_credentials SET {restore} WHERE id=$1"))
                .bind(&github)
                .execute(&fixture.db.pool)
                .await?;
            ensure!(authority.current_session().await? == connected, "{restore}");
        }
        // The final reread's metadata half: a valid selection change while
        // Kubernetes is pending denies, as a scope change does.
        fixture.kube.gate.arm(pod_path(WORKSPACE));
        let pending = authority.clone();
        let task = tokio::spawn(async move { pending.current_session().await });
        fixture.kube.gate.wait().await?;
        sqlx::query(
            "UPDATE environments SET project_spec=\
             jsonb_set(project_spec,'{secrets}','{\"organization\":true}')",
        )
        .execute(&fixture.db.pool)
        .await?;
        fixture.kube.gate.release();
        ensure!(matches!(
            tokio::time::timeout(TIMEOUT, task).await??,
            Err(PlatformRuntimeError::Denied)
        ));
        sqlx::query("UPDATE environments SET project_spec=project_spec-'secrets'")
            .execute(&fixture.db.pool)
            .await?;
        ensure!(authority.current_session().await? == connected);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
