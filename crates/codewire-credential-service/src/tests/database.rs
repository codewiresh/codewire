use super::*;

use crate::platform_test_support as support;
use support::{TestDatabase, quote_ident};

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
            let credential=CredentialId::parse(Uuid::new_v4().to_string())?;
            // Only synthetic metadata is necessary. There is intentionally no
            // envelope, KEK, credential material or OAuth attempt in this DB.
            sqlx::query("INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
                VALUES ($1,$2,'openai','oauth','Synthetic','active',1,1)")
                .bind(credential.as_str()).bind(&selected.creator).execute(&db.pool).await?;
            let context=GrantContext {
                environment_id:EnvironmentId::parse(&selected.environment_id)?,
                environment_generation:7,placement:Placement::Platform,
                user_id:OwnerId::parse(&selected.creator)?,
                organization_id:Some(OwnerId::parse(&selected.organization)?),
                allow_personal_credentials:true,authorized_credentials:[credential.clone()].into_iter().collect(),
            };
            let manager=PlatformAccessProfileStore::new(db.pool.clone(),builtin_provider_catalog());
            let profile=manager.create(&owner,AccessProfileName::parse("synthetic")?,
                BTreeMap::from([(CapabilitySlot::codex(),credential)])).await?;
            manager.create_binding(&context,EnvironmentAccessBinding {
                environment_id:context.environment_id.clone(),profile_id:profile.id.clone(),profile_revision:profile.revision,
            },Some(&context.user_id)).await?;
            selected.profile_id=profile.id.to_string();
            let (pool,role)=db.metadata_pool().await?;
            let role_ident=quote_ident(&role);
            sqlx::query(&format!("REVOKE SELECT ON public.platform_credentials FROM {role_ident}")).execute(&db.pool).await?;
            for grant in [
                "SELECT (id,user_id,organization_id) ON public.platform_credentials",
                "SELECT (id,created_by,org_id,type,state,desired_state,deletion_requested_at,environment_operation_generation) ON public.environments",
                "SELECT (id,org_id,user_id,role) ON public.org_members",
                "SELECT (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_name) ON public.sandbox_environment_backend",
                "SELECT (id,user_id,organization_id) ON public.platform_access_profiles",
                "SELECT (profile_id,revision) ON public.platform_access_profile_revisions",
                "SELECT (profile_id,revision,capability_slot,credential_id) ON public.platform_access_profile_entries",
                "SELECT (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) ON public.platform_environment_access_bindings",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)",
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
        KubernetesPlatformBridgeAuthenticator::new(self.kube.client(), self.pool.clone())
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
        manager
            .replace_binding(
                &self.context,
                &EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: self.profile.id.clone(),
                    profile_revision: self.profile.revision,
                },
                EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: profile.id,
                    profile_revision: profile.revision,
                },
                Some(&self.context.user_id),
            )
            .await?;
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
        let authority = fixture.admitted().await?;
        authority.current_session().await?;
        for sql in [
            "UPDATE public.environments SET state=state",
            "UPDATE public.org_members SET role=role",
            "UPDATE public.platform_access_profiles SET name=name",
            "SELECT id FROM public.users FOR SHARE",
            "SELECT setup_owner_pod_uid FROM public.sandbox_environment_backend",
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
            ("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=NULL",
             "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by='synthetic-creator'"),
            ("UPDATE organizations SET deletion_state='deleting',deletion_generation=1,deletion_operation_id='synthetic-delete',deletion_workflow_id='synthetic-delete',deletion_requested_at=now(),deletion_phase='queued' WHERE id='synthetic-org'",
             "UPDATE organizations SET deletion_state='active',deletion_operation_id=NULL,deletion_workflow_id=NULL,deletion_requested_at=NULL,deletion_phase=NULL WHERE id='synthetic-org'"),
            ("UPDATE platform_access_profiles SET user_id=NULL,organization_id='synthetic-org'",
             "UPDATE platform_access_profiles SET user_id='synthetic-creator',organization_id=NULL"),
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
