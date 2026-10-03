//! Real restricted PostgreSQL login + synthetic TokenReviews, Pods and KEK.
//! These tests do not claim Pod launcher, Dev or live OpenBao delivery.

use super::*;

use async_trait::async_trait;
use codewire_credential_broker::{
    BrokerCredentialLease, BrokerLeaseError, BrokerLeaseProvider,
    platform::PlatformBrokerLeaseProvider,
};
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_platform_credentials::PlatformCredentialStore;
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, GeneratedDek, KekProvider, KekProviderKind, SecretCoordinates,
    SecretEnvelopeError, WrappedDek, encrypt_secret,
};
use codewire_workload_secrets::{ProjectionContext, ProjectionRecipient};
use zeroize::Zeroizing;

#[derive(Default)]
struct ObservedProvider {
    calls: AtomicUsize,
    gate: Gate,
}

#[async_trait]
impl KekProvider for ObservedProvider {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }
    async fn generate(
        &self,
        context: &DekContext,
    ) -> std::result::Result<GeneratedDek, SecretEnvelopeError> {
        TestKekProvider.generate(context).await
    }
    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> std::result::Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.gate.pass("unwrap").await;
        TestKekProvider.unwrap(context, wrapped).await
    }
    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> std::result::Result<WrappedDek, SecretEnvelopeError> {
        TestKekProvider.rewrap(context, wrapped).await
    }
    async fn authority_id(&self) -> std::result::Result<Option<String>, SecretEnvelopeError> {
        Ok(None)
    }
}

async fn grant_projection(f: &Fixture) -> Result<()> {
    let role = quote_ident(&f.role);
    for grant in [
        "EXECUTE ON FUNCTION public.codewire_platform_lock_projection_authority(text,text,text,text)",
        "SELECT (path,key,scope,scope_id,dek_id,ciphertext,nonce,format,storage_contract_version) ON public.tenant_secrets",
        "SELECT (dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format,revision) ON public.tenant_secret_deks",
    ] {
        sqlx::query(&format!("GRANT {grant} TO {role}"))
            .execute(&f.db.pool)
            .await?;
    }
    Ok(())
}

async fn sources(f: &Fixture, secrets: Value, ordinary: Value, profile: bool) -> Result<()> {
    let mut addition = json!({"secrets":secrets,"environment":ordinary});
    if profile {
        addition["credentials"] = json!({"profile":format!("platform:id:{}",f.profile.id)});
    } else {
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(&f.scope.environment_id)
            .execute(&f.db.pool)
            .await?;
    }
    sqlx::query("UPDATE environments SET project_spec=(project_spec-'secrets'-'environment'-'credentials') || $2 WHERE id=$1")
        .bind(&f.scope.environment_id).bind(addition).execute(&f.db.pool).await?;
    Ok(())
}

async fn admitted(
    f: &Fixture,
    provider: Arc<ObservedProvider>,
) -> Result<Arc<crate::KubernetesPlatformRuntimeAuthority>> {
    let authorities =
        crate::authority::RuntimeKekAuthorities::new(Arc::new(TestKekProvider), provider);
    Ok(authorities
        .kubernetes_authenticator(f.kube.client(), f.pool.clone())
        .authenticate(&headers(unix_now()? + 600))
        .await?)
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn request(
    authority: &crate::KubernetesPlatformRuntimeAuthority,
) -> Result<(
    v1::EnvironmentProjectionRequest,
    ProjectionRecipient,
    ProjectionContext,
)> {
    let recipient = ProjectionRecipient::new();
    let context = ProjectionContext {
        environment_id: *Uuid::parse_str(&authority.initial.scope.environment_id)?.as_bytes(),
        operation_generation: authority.initial.scope.generation as u64,
        selection_sha256: authority.initial.selection.sha256()?,
        deadline_unix_ms: now_ms() + 15_000,
    };
    Ok((
        v1::EnvironmentProjectionRequest {
            request_id: Uuid::new_v4().to_string(),
            recipient_public_key: recipient.public_key().to_vec(),
            selection_sha256: context.selection_sha256.to_vec(),
            deadline_unix_ms: context.deadline_unix_ms,
            local_inventories: Vec::new(),
        },
        recipient,
        context,
    ))
}

// Synthetic writer follows the actual store's scope lock and crypto/AAD format.
async fn put(f: &Fixture, path: &str, key: &str, value: &[u8]) -> Result<()> {
    let context = DekContext::from_secret_path(path)?;
    let mut tx = f.db.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(crate::projection::scope_lock_key(&context))
        .execute(&mut *tx)
        .await?;
    let existing: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT dek_id,wrapped_dek,key_version FROM tenant_secret_deks WHERE scope=$1 AND scope_id=$2",
    ).bind(context.scope.as_str()).bind(&context.scope_id).fetch_optional(&mut *tx).await?;
    let (id, dek) = match existing {
        Some((id, ciphertext, version)) => {
            let wrapped = WrappedDek {
                provider: KekProviderKind::OpenBaoTransit,
                key_name: "tenant-dek".into(),
                key_version: version.try_into()?,
                ciphertext: ciphertext.into_bytes(),
                nonce: None,
                format: 1,
            };
            (id, TestKekProvider.unwrap(&context, &wrapped).await?)
        }
        None => {
            let generated = TestKekProvider.generate(&context).await?;
            let id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO tenant_secret_deks(dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format) VALUES($1,$2,$3,'openbao-transit','tenant-dek',1,$4,1)")
                .bind(&id).bind(context.scope.as_str()).bind(&context.scope_id)
                .bind(std::str::from_utf8(&generated.wrapped.ciphertext)?).execute(&mut *tx).await?;
            (id, generated.plaintext)
        }
    };
    let encrypted = encrypt_secret(
        &dek,
        &SecretCoordinates {
            context: &context,
            path,
            key,
        },
        value,
    )?;
    sqlx::query("INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
        VALUES($1,$2,$3,$4,$5,$6,$7,1,1) ON CONFLICT(path,key) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,nonce=EXCLUDED.nonce")
        .bind(path).bind(key).bind(id).bind(context.scope.as_str()).bind(context.scope_id)
        .bind(encrypted.ciphertext).bind(encrypted.nonce).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn app_only_projection_uses_exact_precedence_and_never_reads_suppressed_material()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        let project = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'development')")
            .bind(&project).bind(&f.scope.organization).execute(&f.db.pool).await?;
        sources(&f,json!({"organization":true,"project":format!("platform:id:{project}"),"user":"platform"}),json!({"CONFIGURED":"ordinary-value"}),false).await?;
        let org = format!("/org-secrets/{}", f.scope.organization);
        let project_path = format!("/projects/{}/{project}", f.scope.organization);
        let user = format!("/users/{}", f.scope.creator);
        put(&f,&org,"SHARED",b"organization").await?;
        put(&f,&org,"ORG_ONLY",b"org-value").await?;
        put(&f,&project_path,"SHARED",b"project").await?;
        put(&f,&project_path,"PROJECT_ONLY",b"project-value").await?;
        put(&f,&user,"SHARED",b"personal").await?;
        put(&f,&user,"CONFIGURED",b"must-not-read").await?;
        // Authenticated ciphertext intentionally broken only for losing keys.
        sqlx::query("UPDATE tenant_secrets SET ciphertext=decode(repeat('00',16),'hex') WHERE key='CONFIGURED' OR (key='SHARED' AND path<>$1)")
            .bind(&user).execute(&f.db.pool).await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f,provider.clone()).await?;
        let (message,recipient,context) = request(&authority)?;
        let mut mixed = message.clone();
        mixed.local_inventories = vec![v1::EnvironmentProjectionInventory {
            source: v1::EnvironmentProjectionSource::Project as i32,
            source_identity: "/projects/local-owner/project".into(),
            keys: vec!["LOCAL".into()],
        }];
        ensure!(authority.project_environment(mixed).await.is_err());
        ensure!(provider.calls.load(Ordering::SeqCst)==0, "workload authority must reject mixed inventories before material");
        let sealed = authority.project_environment(message).await?;
        let values = recipient.open(&sealed,&context,now_ms())?;
        ensure!(values.entries().collect::<BTreeMap<_,_>>() == BTreeMap::from([
            ("ORG_ONLY","org-value"),("PROJECT_ONLY","project-value"),("SHARED","personal"),
        ]));
        ensure!(provider.calls.load(Ordering::SeqCst)==2, "one unwrap per winning scope only");
        let broker = PlatformBrokerLeaseProvider::connect(authority,
            Arc::new(PlatformCredentialStore::new(f.pool.clone(),provider,builtin_provider_catalog())),
            PlatformAccessProfileStore::new(f.pool.clone(),builtin_provider_catalog())).await?;
        ensure!(broker.lease_operation(Uuid::new_v4(), CapabilitySlot::codex(),
            codewire_access::BrokerOperationId::parse("responses")?,codewire_access::BrokerRouteId::parse("responses")?).await.is_err());
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn provider_only_projection_is_authenticated_empty_and_performs_no_app_reads() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        // Deliberately do NOT grant tenant encrypted reads: an empty source set
        // must still seal after exact provider/runtime admission without them.
        sqlx::query(&format!("GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_projection_authority(text,text,text,text) TO {}",quote_ident(&f.role)))
            .execute(&f.db.pool).await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f,provider.clone()).await?;
        let (message,recipient,context) = request(&authority)?;
        let sealed = authority.project_environment(message).await?;
        ensure!(recipient.open(&sealed,&context,now_ms())?.entries().len()==0);
        ensure!(provider.calls.load(Ordering::SeqCst)==0);
        // Revoking the profile's credential withholds only its capability; the
        // launch projection is not a credential fence and still seals.
        sqlx::query("UPDATE platform_credentials SET status='revoked'").execute(&f.db.pool).await?;
        let (message,recipient,context) = request(&authority)?;
        let sealed = authority.project_environment(message).await?;
        ensure!(recipient.open(&sealed,&context,now_ms())?.entries().len()==0);
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn organization_profile_does_not_change_the_personal_application_source_owner() -> Result<()>
{
    let f = Fixture::create().await?;
    let result=async {
        grant_projection(&f).await?;
        sqlx::query("UPDATE platform_access_profiles SET user_id=NULL,organization_id=$1")
            .bind(&f.scope.organization).execute(&f.db.pool).await?;
        // Organizations hold API keys, never an OAuth login.
        sqlx::query("UPDATE platform_credentials SET user_id=NULL,organization_id=$1,authentication_kind='api_key'")
            .bind(&f.scope.organization).execute(&f.db.pool).await?;
        sqlx::query("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=NULL")
            .execute(&f.db.pool).await?;
        sources(&f,json!({"user":"platform"}),json!({}),true).await?;
        put(&f,&format!("/users/{}",f.scope.creator),"APP_VALUE",b"creator-owned").await?;
        let provider=Arc::new(ObservedProvider::default());
        let authority=admitted(&f,provider.clone()).await?;
        let (message,recipient,context)=request(&authority)?;
        let sealed=authority.project_environment(message).await?;
        ensure!(recipient.open(&sealed,&context,now_ms())?.entries().collect::<Vec<_>>()==[("APP_VALUE","creator-owned")]);
        // Personal confirmation is not silently carried onto an organization pin.
        sqlx::query("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by='synthetic-creator'")
            .execute(&f.db.pool).await?;
        ensure!(admitted(&f,provider).await.is_err());
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn malformed_recipient_selection_deadline_and_reserved_collision_fail_before_unwrap()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(&f, json!({"user":"platform"}), json!({}), true).await?;
        let path = format!("/users/{}", f.scope.creator);
        put(&f, &path, "APP_VALUE", b"synthetic").await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f, provider.clone()).await?;
        for fault in 0..5 {
            let (mut message, _, _) = request(&authority)?;
            match fault {
                0 => message.recipient_public_key = vec![0; 32],
                1 => message.selection_sha256 = vec![0; 32],
                2 => message.deadline_unix_ms = now_ms(),
                3 => message.deadline_unix_ms = u64::MAX,
                _ => message.request_id = Uuid::nil().to_string(),
            }
            ensure!(authority.project_environment(message).await.is_err());
        }
        put(&f, &path, "CODEX_HOME", b"must-not-read").await?;
        let (message, _, _) = request(&authority)?;
        ensure!(authority.project_environment(message).await.is_err());
        ensure!(provider.calls.load(Ordering::SeqCst) == 0);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_revalidates_ciphertext_inventory_sources_membership_and_pods_after_unwrap()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(&f,json!({"user":"platform"}),json!({}),false).await?;
        let path = format!("/users/{}",f.scope.creator);
        put(&f,&path,"APP_VALUE",b"before").await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f,provider.clone()).await?;
        for fault in 0..8 {
            provider.gate.arm("unwrap".into());
            let (message,_,_) = request(&authority)?;
            let runtime = authority.clone();
            let task = tokio::spawn(async move { runtime.project_environment(message).await });
            provider.gate.wait().await?;
            // These writes completing before gate release prove no authority or
            // tenant locks are held across the protected-provider await.
            tokio::time::timeout(TIMEOUT, async {
                match fault {
                    0 => put(&f,&path,"APP_VALUE",b"rotated").await?,
                    1 => put(&f,&path,"NEW_KEY",b"new").await?,
                    2 => { sqlx::query("UPDATE environments SET project_spec=jsonb_set(project_spec,'{environment}','{\"APP_VALUE\":\"ordinary\"}')").execute(&f.db.pool).await?; }
                    3 => { sqlx::query("DELETE FROM org_members WHERE id='synthetic-membership'").execute(&f.db.pool).await?; }
                    4 => { sqlx::query("UPDATE environments SET state='stopping'").execute(&f.db.pool).await?; }
                    5 => { f.kube.objects.lock().unwrap().get_mut(&pod_path(WORKSPACE)).unwrap()["metadata"]["uid"]=json!(Uuid::new_v4().to_string()); }
                    6 => { sqlx::query("UPDATE tenant_secret_deks SET revision=revision+1").execute(&f.db.pool).await?; }
                    _ => { sqlx::query("UPDATE environments SET environment_operation_generation=8").execute(&f.db.pool).await?; }
                }
                Ok::<_,anyhow::Error>(())
            }).await.context("mutation blocked behind OpenBao")??;
            provider.gate.release();
            ensure!(task.await?.is_err(),"race {fault} released a projection");
            match fault {
                1 => { sqlx::query("DELETE FROM tenant_secrets WHERE key='NEW_KEY'").execute(&f.db.pool).await?; }
                2 => sources(&f,json!({"user":"platform"}),json!({}),false).await?,
                3 => f.restore_membership().await?,
                4 => { sqlx::query("UPDATE environments SET state='running'").execute(&f.db.pool).await?; }
                5 => { f.kube.objects.lock().unwrap().get_mut(&pod_path(WORKSPACE)).unwrap()["metadata"]["uid"]=json!(WORKSPACE_UID); }
                7 => { sqlx::query("UPDATE environments SET environment_operation_generation=7").execute(&f.db.pool).await?; }
                _ => {}
            }
        }
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_restricted_reader_cannot_read_configuration_or_mutate_authority_or_material()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(
            &f,
            json!({"user":"platform"}),
            json!({"KEY":"synthetic-ordinary-never-returned"}),
            true,
        )
        .await?;
        let metadata: Value = sqlx::query_scalar(
            "SELECT to_jsonb(p) FROM public.codewire_platform_projection_metadata($1) p",
        )
        .bind(&f.scope.environment_id)
        .fetch_one(&f.pool)
        .await?;
        ensure!(
            !metadata
                .to_string()
                .contains("synthetic-ordinary-never-returned")
        );
        ensure!(metadata["ordinary_keys"] == json!(["KEY"]));
        for statement in [
            "SELECT project_spec FROM environments",
            "SELECT * FROM tenant_secrets",
            "SELECT * FROM tenant_secret_deks",
            "SELECT * FROM tenant_secret_kek_canary",
            "UPDATE tenant_secrets SET key=key",
            "UPDATE tenant_secret_deks SET revision=revision",
            "DELETE FROM tenant_secrets",
            "UPDATE environments SET state=state",
            "UPDATE org_members SET role=role",
            "SELECT * FROM secret_projects",
            "CREATE TABLE forbidden(id integer)",
        ] {
            let error = sqlx::query(statement).execute(&f.pool).await.unwrap_err();
            ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
                "{statement}"
            );
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_bounds_inventory_and_values_before_unwrap_and_never_falls_back() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(&f,json!({"organization":true,"user":"platform"}),json!({}),false).await?;
        let user = format!("/users/{}",f.scope.creator);
        let org = format!("/org-secrets/{}",f.scope.organization);
        put(&f,&org,"APP_VALUE",b"must-not-be-fallback").await?;
        put(&f,&user,"APP_VALUE",b"personal").await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f,provider.clone()).await?;
        sqlx::query("INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
            SELECT s.path,'KEY_'||n,s.dek_id,s.scope,s.scope_id,s.ciphertext,s.nonce,1,1 FROM tenant_secrets s \
            CROSS JOIN generate_series(1,256) n WHERE s.path=$1 AND s.key='APP_VALUE'")
            .bind(&user).execute(&f.db.pool).await?;
        let (message,_,_) = request(&authority)?;
        ensure!(authority.project_environment(message).await.is_err());
        sqlx::query("DELETE FROM tenant_secrets WHERE key LIKE 'KEY_%'").execute(&f.db.pool).await?;
        put(&f,&user,"APP_VALUE",&vec![b'x';65_537]).await?;
        let (message,_,_) = request(&authority)?;
        ensure!(authority.project_environment(message).await.is_err());
        ensure!(provider.calls.load(Ordering::SeqCst)==0);
        // Correct size but unauthenticated winning material fails the entire
        // projection; the valid lower source is not substituted.
        sqlx::query("UPDATE tenant_secrets SET ciphertext=decode(repeat('00',32),'hex') WHERE path=$1")
            .bind(&user).execute(&f.db.pool).await?;
        let (message,_,_) = request(&authority)?;
        ensure!(authority.project_environment(message).await.is_err());
        ensure!(provider.calls.load(Ordering::SeqCst)==1);
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_cancellation_and_original_request_deadline_release_no_late_values() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(&f, json!({"user":"platform"}), json!({}), false).await?;
        let path = format!("/users/{}", f.scope.creator);
        put(&f, &path, "APP_VALUE", b"synthetic").await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f, provider.clone()).await?;
        provider.gate.arm("unwrap".into());
        let (message, _, _) = request(&authority)?;
        let runtime = authority.clone();
        let task = tokio::spawn(async move { runtime.project_environment(message).await });
        provider.gate.wait().await?;
        task.abort();
        ensure!(task.await.unwrap_err().is_cancelled());
        // No detached unwrap task survives the owner cancellation.
        put(&f, &path, "APP_VALUE", b"after-cancel").await?;
        let (message, recipient, context) = request(&authority)?;
        let sealed = authority.project_environment(message).await?;
        ensure!(
            recipient
                .open(&sealed, &context, now_ms())?
                .entries()
                .collect::<Vec<_>>()
                == [("APP_VALUE", "after-cancel")]
        );
        provider.gate.arm("unwrap".into());
        let (mut message, _, _) = request(&authority)?;
        message.deadline_unix_ms = now_ms() + 500;
        let runtime = authority.clone();
        let task = tokio::spawn(async move { runtime.project_environment(message).await });
        provider.gate.wait().await?;
        ensure!(
            tokio::time::timeout(std::time::Duration::from_secs(2), task)
                .await??
                .is_err()
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_metadata_rejects_foreign_projects_and_retired_or_local_selectors() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        let other = "another-synthetic-org";
        f.db.organization(other).await?;
        let project = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'foreign')")
            .bind(&project)
            .bind(other)
            .execute(&f.db.pool)
            .await?;
        let provider = Arc::new(ObservedProvider::default());
        for selection in [
            json!({"project":format!("platform:id:{project}")}),
            json!({"project":format!("local:id:{project}")}),
            json!({"project":"development"}),
            json!({"user":"local"}),
            json!({"user":true}),
            json!({"exposed":true}),
        ] {
            sources(&f, selection, json!({}), false).await?;
            ensure!(admitted(&f, provider.clone()).await.is_err());
        }
        ensure!(provider.calls.load(Ordering::SeqCst) == 0);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn projection_share_helper_fences_each_exact_authority_row_without_dml_grants() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        let project = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'locked-project')")
            .bind(&project)
            .bind(&f.scope.organization)
            .execute(&f.db.pool)
            .await?;
        sources(
            &f,
            json!({"project":format!("platform:id:{project}")}),
            json!({}),
            true,
        )
        .await?;
        for statement in [
            "UPDATE users SET is_admin=is_admin WHERE id='synthetic-creator'",
            "UPDATE organizations SET deletion_state=deletion_state WHERE id='synthetic-org'",
            "UPDATE org_members SET role=role WHERE id='synthetic-membership'",
            "UPDATE environments SET state=state",
            "UPDATE sandbox_environment_backend SET pod_name=pod_name",
            "UPDATE platform_environment_access_bindings SET profile_revision=profile_revision",
            "UPDATE platform_access_profiles SET current_revision=current_revision",
            "UPDATE secret_projects SET name=name",
        ] {
            let mut tx = f.pool.begin().await?;
            let locked: bool = sqlx::query_scalar(
                "SELECT public.codewire_platform_lock_projection_authority($1,$2,$3,$4)",
            )
            .bind(&f.scope.environment_id)
            .bind(&f.scope.creator)
            .bind(&f.scope.organization)
            .bind(&project)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(locked);
            let writer = f.db.pool.clone();
            let mut task =
                tokio::spawn(async move { sqlx::query(statement).execute(&writer).await });
            let blocked = tokio::time::timeout(std::time::Duration::from_millis(100), &mut task)
                .await
                .is_err();
            tx.rollback().await?;
            if blocked {
                tokio::time::timeout(TIMEOUT, task).await???;
            }
            ensure!(
                blocked,
                "authority mutation did not wait for SHARE fence: {statement}"
            );
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

async fn bind_two_capabilities(
    f: &Fixture,
    kek: Arc<support::SyntheticKek>,
) -> Result<(CredentialId, CredentialId)> {
    use codewire_access::{CredentialAuthKind, ProviderId};
    use codewire_platform_credentials::CredentialRegistration;
    let store = PlatformCredentialStore::new(f.db.pool.clone(), kek, builtin_provider_catalog());
    let registration = |provider: &str, kind, name: &str| CredentialRegistration {
        provider: ProviderId::parse(provider).unwrap(),
        authentication_kind: kind,
        display_name: name.into(),
        account_hint: None,
        expires_at_unix: None,
    };
    let codex = store
        .create(
            &f.owner,
            registration("openai", CredentialAuthKind::OAuth, "Synthetic Codex"),
            &support::value(b"synthetic-codex-bundle-never-projected"),
        )
        .await?
        .metadata
        .id;
    let anthropic = store
        .create(
            &f.owner,
            registration(
                "anthropic",
                CredentialAuthKind::ApiKey,
                "Synthetic Anthropic",
            ),
            &support::value(b"synthetic-anthropic-key-never-projected"),
        )
        .await?
        .metadata
        .id;
    let manager = PlatformAccessProfileStore::new(f.db.pool.clone(), builtin_provider_catalog());
    let revised = manager
        .update(
            &f.owner,
            &f.profile.id,
            f.profile.revision,
            BTreeMap::from([
                (CapabilitySlot::codex(), codex.clone()),
                (CapabilitySlot::anthropic(), anthropic.clone()),
            ]),
        )
        .await?;
    let mut context = f.context.clone();
    context.authorized_credentials = [codex.clone(), anthropic.clone()].into_iter().collect();
    manager
        .replace_binding(
            &context,
            &EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: f.profile.id.clone(),
                profile_revision: f.profile.revision,
            },
            EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: revised.id.clone(),
                profile_revision: revised.revision,
            },
            Some(&context.user_id),
        )
        .await?;
    Ok((codex, anthropic))
}

#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn credential_needing_reconnect_withholds_only_its_capability_and_launches_still_project()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        sources(&f, json!({"user":"platform"}), json!({}), true).await?;
        put(&f, &format!("/users/{}", f.scope.creator), "APP_VALUE", b"launch-value").await?;
        let kek = Arc::new(support::SyntheticKek::default());
        let (codex, _) = bind_two_capabilities(&f, kek.clone()).await?;
        let (broker_pool, _) = f.db.broker_pool().await?;
        let admin = PlatformCredentialStore::new(f.db.pool.clone(), kek.clone(), builtin_provider_catalog());
        let lease = async |authority: Arc<crate::KubernetesPlatformRuntimeAuthority>, slot: CapabilitySlot, operation: &str, route: &str| {
            let broker = PlatformBrokerLeaseProvider::connect(
                authority,
                Arc::new(PlatformCredentialStore::new(broker_pool.clone(), kek.clone(), builtin_provider_catalog())),
                PlatformAccessProfileStore::new(broker_pool.clone(), builtin_provider_catalog()),
            ).await?;
            anyhow::Ok(broker.lease_operation(
                Uuid::new_v4(), slot,
                codewire_access::BrokerOperationId::parse(operation)?,
                codewire_access::BrokerRouteId::parse(route)?,
            ).await)
        };
        let codex_lease = |authority| lease(authority, CapabilitySlot::codex(), "responses", "openai-api");
        let anthropic_lease = |authority| lease(authority, CapabilitySlot::anthropic(), "messages", "anthropic-api");

        // The refresh failure path: status refresh_failed at a new revocation generation.
        sqlx::query("UPDATE platform_credentials SET status='refresh_failed',revocation_generation=revocation_generation+1 WHERE id=$1")
            .bind(codex.as_str()).execute(&f.db.pool).await?;
        for state in ["refresh_failed", "revoked", "expired", "past-deadline"] {
            match state {
                "revoked" => {
                    let current = admin.record(&f.owner, &codex).await?;
                    admin.revoke(&f.owner, &codex, current.version).await?;
                }
                "expired" => { sqlx::query("UPDATE platform_credentials SET status='expired' WHERE id=$1").bind(codex.as_str()).execute(&f.db.pool).await?; }
                "past-deadline" => { sqlx::query("UPDATE platform_credentials SET status='active',expires_at_unix=1 WHERE id=$1").bind(codex.as_str()).execute(&f.db.pool).await?; }
                _ => {}
            }
            // A new gateway/workspace bridge is still admitted, and every launch
            // still receives its environment projection.
            let authority = admitted(&f, Arc::new(ObservedProvider::default())).await
                .with_context(|| format!("{state}: bridge admission was refused"))?;
            let (message, recipient, context) = request(&authority)?;
            let sealed = authority.project_environment(message).await
                .with_context(|| format!("{state}: launch projection was refused"))?;
            ensure!(recipient.open(&sealed, &context, now_ms())?.entries().collect::<Vec<_>>() == [("APP_VALUE", "launch-value")]);
            // The other capability keeps working with its own material.
            let unwraps = kek.unwrap_calls.load(Ordering::SeqCst);
            let anthropic = anthropic_lease(authority.clone()).await?
                .map_err(|error| anyhow::anyhow!("{state}: healthy capability withheld: {error}"))?;
            ensure!(anthropic.with_material(|material| material == b"synthetic-anthropic-key-never-projected"));
            ensure!(kek.unwrap_calls.load(Ordering::SeqCst) == unwraps + 1);
            // The withheld capability names its Reconnect and reads no material.
            // (Its HTTP route turns this into the fixed 403 explanation; see the
            // broker's runtime HTTP tests.)
            ensure!(
                matches!(codex_lease(authority.clone()).await?, Err(BrokerLeaseError::ReconnectRequired)),
                "{state}: withheld capability did not report Reconnect"
            );
            ensure!(kek.unwrap_calls.load(Ordering::SeqCst) == unwraps + 1, "{state}: withheld capability read material");
        }

        // Reconnect republishes the same identity: the capability returns on
        // the very next admission, with no new Sandbox, binding or bridge.
        let authority = admitted(&f, Arc::new(ObservedProvider::default())).await?;
        let current = admin.record(&f.owner, &codex).await?;
        admin.replace(&f.owner, &codex, current.version, &support::value(b"synthetic-codex-reconnected"), None).await?;
        let reconnected = codex_lease(authority.clone()).await?
            .map_err(|error| anyhow::anyhow!("reconnected capability withheld: {error}"))?;
        ensure!(reconnected.with_material(|material| material == b"synthetic-codex-reconnected"));

        // A selected credential that no longer exists is integrity damage the
        // product cannot create (bound credentials cannot be deleted): it still
        // refuses the whole runtime, as before.
        sqlx::query("DELETE FROM platform_credentials WHERE id=$1").bind(codex.as_str()).execute(&f.db.pool).await?;
        ensure!(authority.current_session().await.is_err());
        ensure!(admitted(&f, Arc::new(ObservedProvider::default())).await.is_err());
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// The hosted authority maps `environments.created_by` to the session's user
/// and admits a personal profile only when its `personal_owner_confirmed_by`
/// is that creator; the broker's Codex login predicate relies on both.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn codex_login_follows_only_the_creators_own_confirmed_profile() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let kek = Arc::new(support::SyntheticKek::default());
        let (codex, _) = bind_two_capabilities(&f, kek.clone()).await?;
        let (broker_pool, _) = f.db.broker_pool().await?;
        let connect = async |authority: Arc<crate::KubernetesPlatformRuntimeAuthority>| {
            anyhow::Ok(
                PlatformBrokerLeaseProvider::connect(
                    authority,
                    Arc::new(PlatformCredentialStore::new(
                        broker_pool.clone(),
                        kek.clone(),
                        builtin_provider_catalog(),
                    )),
                    PlatformAccessProfileStore::new(
                        broker_pool.clone(),
                        builtin_provider_catalog(),
                    ),
                )
                .await?,
            )
        };
        let authority = admitted(&f, Arc::new(ObservedProvider::default())).await?;
        let broker = connect(authority.clone()).await?;
        let login = broker.lease_codex_login(Uuid::new_v4()).await?;
        ensure!(login.credential_metadata().id == codex);
        ensure!(login.credential_metadata().owner == f.owner);
        ensure!(login.permission() == &codewire_access::codex_login_permission());
        ensure!(
            login.with_material(|material| material == b"synthetic-codex-bundle-never-projected")
        );

        // Consent recorded by anyone but the creator, or by nobody: the
        // connected broker's next login is denied and no new session forms.
        f.db.user("synthetic-other-user").await?;
        for confirmed in [Some("synthetic-other-user"), None] {
            sqlx::query(
                "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=$1",
            )
            .bind(confirmed)
            .execute(&f.db.pool)
            .await?;
            ensure!(
                matches!(
                    broker.lease_codex_login(Uuid::new_v4()).await,
                    Err(BrokerLeaseError::Denied)
                ),
                "{confirmed:?}: a login followed another user's consent"
            );
            ensure!(
                admitted(&f, Arc::new(ObservedProvider::default()))
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}
