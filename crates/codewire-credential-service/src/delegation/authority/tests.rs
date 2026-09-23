use super::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, Owner, OwnerId, ProviderId,
    builtin_provider_catalog,
};
use codewire_gateway_proto::projection::{decode_local_inventories, decode_platform_inventories};
use codewire_platform_credentials::{CredentialRegistration, PlatformAccessProfileStore};
use codewire_protected_store::ProtectedValue;
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, GeneratedDek, KekProvider, KekProviderKind, SecretCoordinates,
    SecretEnvelopeError, TestKekProvider, WrappedDek, encrypt_secret,
};
use codewire_server_core::auth::{AuthState, authenticate_product_credential, hash_oauth_token};
use codewire_workload_secrets::{
    EnvironmentProjection, MAX_PROJECTION_LIFETIME_MS, ProjectionCompositionPlan,
    ProjectionContributor, ProjectionRecipient, compose_environment_projection,
    seal_environment_projection_fragment,
};
use zeroize::Zeroizing;

use crate::mutation::tests::support::{ALICE, CLIENT, Harness, oauth};
use crate::platform_test_support::quote_ident;

const ORGANIZATION: &str = "mutation-org";

/// Test-only provider whose envelope bytes are intentionally incompatible with
/// the credential-store fixture provider. The tag models distinct Transit
/// authorities without claiming a live OpenBao integration.
struct TaggedApplicationKek {
    unwrap_calls: AtomicUsize,
}

impl TaggedApplicationKek {
    const PREFIX: &'static [u8] = b"vault:v1:";
    const MASK: &'static [u8] = b"application-authority";

    fn mask(bytes: &mut [u8]) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte ^= Self::MASK[index % Self::MASK.len()];
        }
    }

    fn new() -> Self {
        Self {
            unwrap_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl KekProvider for TaggedApplicationKek {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }

    async fn generate(
        &self,
        context: &DekContext,
    ) -> std::result::Result<GeneratedDek, SecretEnvelopeError> {
        let mut generated = TestKekProvider.generate(context).await?;
        let payload = generated
            .wrapped
            .ciphertext
            .strip_prefix(Self::PREFIX)
            .expect("test provider ciphertext prefix");
        let mut wrapped = STANDARD
            .decode(payload)
            .expect("test provider base64 ciphertext");
        Self::mask(&mut wrapped);
        generated.wrapped.ciphertext = format!("vault:v1:{}", STANDARD.encode(wrapped)).into();
        Ok(generated)
    }

    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> std::result::Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        let mut untagged = wrapped.clone();
        if let Some(ciphertext) = wrapped.ciphertext.strip_prefix(Self::PREFIX)
            && let Ok(mut decoded) = STANDARD.decode(ciphertext)
        {
            Self::mask(&mut decoded);
            untagged.ciphertext = format!("vault:v1:{}", STANDARD.encode(decoded)).into();
        } else {
            untagged.ciphertext = b"wrong-synthetic-application-authority".to_vec();
        }
        TestKekProvider.unwrap(context, &untagged).await
    }

    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> std::result::Result<WrappedDek, SecretEnvelopeError> {
        self.unwrap(context, wrapped).await?;
        Ok(wrapped.clone())
    }

    async fn authority_id(&self) -> std::result::Result<Option<String>, SecretEnvelopeError> {
        Ok(None)
    }
}

mod public_wire;

fn platform_selection() -> PlatformProjectionSelection {
    // A local VM captured while GitHub was connected reserves its keys.
    let mut reserved_keys = platform_projection_reserved_keys(["github"]).unwrap();
    reserved_keys.insert(NATIVE_CODEX_HOME_KEY.into());
    PlatformProjectionSelection {
        creator: "owner-user".into(),
        organization: "owner-org".into(),
        organization_selected: true,
        project_id: Some(Uuid::new_v4().to_string()),
        user_selected: true,
        profile: None,
        ordinary_keys: ["ORDINARY".into()].into_iter().collect(),
        reserved_keys,
    }
}

#[test]
fn owner_local_selection_binds_distinct_native_digest_and_exact_operation() {
    let platform = platform_selection();
    let platform_digest = platform.sha256().unwrap();
    let native_digest = [9; 32];
    assert_ne!(native_digest, platform_digest);
    let environment = Uuid::new_v4();
    let selected = OwnerLocalSelection::new(environment, 7, platform.clone(), native_digest)
        .expect("valid owner-local selection");
    assert_eq!(selected.local_environment_id, environment);
    assert_eq!(selected.local_environment_generation, 7);
    assert_eq!(selected.platform, platform);
    assert_eq!(selected.selection_sha256, native_digest);
}

#[test]
fn owner_local_selection_rejects_unbound_runtime_shape() {
    let platform = platform_selection();
    for (environment, generation, digest) in [
        (Uuid::nil(), 1, [1; 32]),
        (Uuid::new_v4(), 0, [1; 32]),
        (Uuid::new_v4(), i64::MAX as u64 + 1, [1; 32]),
        (Uuid::new_v4(), 1, [0; 32]),
    ] {
        assert!(
            OwnerLocalSelection::new(environment, generation, platform.clone(), digest).is_err()
        );
    }

    let mut overlapping = platform;
    overlapping
        .ordinary_keys
        .insert("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS".into());
    assert!(
        OwnerLocalSelection::new(Uuid::new_v4(), 1, overlapping, [1; 32]).is_err(),
        "runtime-owned names cannot be asserted as ordinary environment names"
    );
}

#[test]
fn owner_local_reservations_allow_extra_native_names_but_require_selected_platform_slots() {
    let mut platform = platform_selection();
    platform.reserved_keys.insert("ANTHROPIC_BASE_URL".into());
    OwnerLocalSelection::new(Uuid::new_v4(), 1, platform.clone(), [1; 32])
        .expect("a native-profile reservation may conservatively deny a platform source");

    platform.profile = Some((Uuid::new_v4().to_string(), 1));
    validate_reserved_keys(&platform, [])
        .expect("a pinned empty platform profile needs no invented provider reservation");
    assert!(validate_reserved_keys(&platform, ["ssh"]).is_err());
    platform.reserved_keys.insert("SSH_AUTH_SOCK".into());
    validate_reserved_keys(&platform, ["ssh"]).expect("selected platform slot is reserved");

    platform.reserved_keys.remove(NATIVE_CODEX_HOME_KEY);
    assert!(validate_reserved_keys(&platform, ["ssh"]).is_err());
}

async fn setup_owner_sources(h: &Harness) -> Result<(OwnerLocalSelection, String)> {
    setup_owner_sources_with_entries(h, BTreeMap::new()).await
}

async fn setup_owner_sources_with_entries(
    h: &Harness,
    entries: BTreeMap<CapabilitySlot, codewire_access::CredentialId>,
) -> Result<(OwnerLocalSelection, String)> {
    let project = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES ($1,$2,$3,'member')")
        .bind(Uuid::new_v4().to_string())
        .bind(ORGANIZATION)
        .bind(ALICE)
        .execute(&h.db.pool)
        .await?;
    sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'delegated')")
        .bind(&project)
        .bind(ORGANIZATION)
        .execute(&h.db.pool)
        .await?;

    let profiles = PlatformAccessProfileStore::new(h.db.pool.clone(), builtin_provider_catalog());
    let profile = profiles
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            AccessProfileName::parse("empty-owner-local")?,
            entries,
        )
        .await?;
    let role = quote_ident(&h.role);
    for grant in [
        "EXECUTE ON FUNCTION public.codewire_platform_lock_owner_source_authority(text,text,text)",
        "SELECT (path,key,scope,scope_id,dek_id,ciphertext,nonce,format,storage_contract_version) ON public.tenant_secrets",
        "SELECT (dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format,revision) ON public.tenant_secret_deks",
    ] {
        sqlx::query(&format!("GRANT {grant} TO {role}"))
            .execute(&h.db.pool)
            .await?;
    }

    let mut reserved = platform_projection_reserved_keys(["github"])?;
    reserved.extend([NATIVE_CODEX_HOME_KEY.into(), "SSH_AUTH_SOCK".into()]);
    let platform = PlatformProjectionSelection {
        creator: ALICE.into(),
        organization: ORGANIZATION.into(),
        organization_selected: true,
        project_id: Some(project.clone()),
        user_selected: true,
        profile: Some((profile.id.to_string(), profile.revision)),
        ordinary_keys: ["SUPPRESSED".into()].into_iter().collect(),
        reserved_keys: reserved,
    };
    Ok((
        OwnerLocalSelection::new(Uuid::new_v4(), 7, platform, [0x5a; 32])?,
        project,
    ))
}

async fn admitted(
    h: &Harness,
    selection: OwnerLocalSelection,
) -> Result<Arc<OwnerLocalRuntimeAuthority>> {
    admitted_with_provider(h, selection, h.provider.clone()).await
}

async fn admitted_with_provider(
    h: &Harness,
    selection: OwnerLocalSelection,
    provider: Arc<dyn KekProvider>,
) -> Result<Arc<OwnerLocalRuntimeAuthority>> {
    let bearer = oauth(ALICE);
    let authentication = authenticate_product_credential(
        &AuthState {
            pool: h.pool.clone(),
        },
        None,
        Some(&bearer),
    )
    .await?;
    let oauth = authentication
        .oauth_bearer_authority()
        .context("real synthetic OAuth bearer authority")?
        .clone();
    Ok(OwnerLocalRuntimeAuthority::new(
        h.pool.clone(),
        provider,
        PlatformAccessProfileStore::new(h.pool.clone(), builtin_provider_catalog()),
        oauth,
        selection,
        unix_seconds()?.checked_add(600).context("fixture expiry")?,
    )
    .await?)
}

fn projection_request(
    selection: &OwnerLocalSelection,
    deadline_unix_ms: u64,
) -> (
    v1::EnvironmentProjectionRequest,
    ProjectionRecipient,
    ProjectionContext,
) {
    let recipient = ProjectionRecipient::new();
    let context = ProjectionContext {
        environment_id: *selection.local_environment_id.as_bytes(),
        operation_generation: selection.local_environment_generation,
        selection_sha256: selection.selection_sha256,
        deadline_unix_ms,
    };
    (
        v1::EnvironmentProjectionRequest {
            request_id: Uuid::new_v4().to_string(),
            recipient_public_key: recipient.public_key().to_vec(),
            selection_sha256: selection.selection_sha256.to_vec(),
            deadline_unix_ms,
            local_inventories: Vec::new(),
        },
        recipient,
        context,
    )
}

async fn put(path: &str, key: &str, value: &[u8], pool: &PgPool) -> Result<()> {
    put_with_provider(path, key, value, pool, &TestKekProvider).await
}

async fn put_with_provider(
    path: &str,
    key: &str,
    value: &[u8],
    pool: &PgPool,
    provider: &dyn KekProvider,
) -> Result<()> {
    let context = DekContext::from_secret_path(path)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(crate::projection::scope_lock_key(&context))
        .execute(&mut *tx)
        .await?;
    let existing: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT dek_id,wrapped_dek,key_version FROM tenant_secret_deks \
         WHERE scope=$1 AND scope_id=$2",
    )
    .bind(context.scope.as_str())
    .bind(&context.scope_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (dek_id, dek): (String, Zeroizing<[u8; DEK_BYTES]>) = match existing {
        Some((id, ciphertext, version)) => {
            let wrapped = WrappedDek {
                provider: KekProviderKind::OpenBaoTransit,
                key_name: "tenant-dek".into(),
                key_version: version.try_into()?,
                ciphertext: ciphertext.into_bytes(),
                nonce: None,
                format: 1,
            };
            (id, provider.unwrap(&context, &wrapped).await?)
        }
        None => {
            let generated = provider.generate(&context).await?;
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO tenant_secret_deks \
                 (dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format) \
                 VALUES($1,$2,$3,'openbao-transit','tenant-dek',1,$4,1)",
            )
            .bind(&id)
            .bind(context.scope.as_str())
            .bind(&context.scope_id)
            .bind(std::str::from_utf8(&generated.wrapped.ciphertext)?)
            .execute(&mut *tx)
            .await?;
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
    sqlx::query(
        "INSERT INTO tenant_secrets \
         (path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
         VALUES($1,$2,$3,$4,$5,$6,$7,1,1) \
         ON CONFLICT(path,key) DO UPDATE SET \
         ciphertext=EXCLUDED.ciphertext,nonce=EXCLUDED.nonce",
    )
    .bind(path)
    .bind(key)
    .bind(dek_id)
    .bind(context.scope.as_str())
    .bind(&context.scope_id)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn application_and_credential_authorities_are_incompatible_across_full_and_mixed_projection()
-> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let credential_value =
            ProtectedValue::from_slice(b"synthetic-credential-authority-material-never-public")?;
        let application = Arc::new(TaggedApplicationKek::new());
        let authorities =
            crate::authority::RuntimeKekAuthorities::new(h.provider.clone(), application.clone());
        let credential_store = authorities.credential_store(h.pool.clone());
        let credential = credential_store
            .create(
                &owner,
                CredentialRegistration {
                    provider: ProviderId::parse("openai")?,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "separate credential authority".into(),
                    account_hint: Some("synthetic-account".into()),
                    expires_at_unix: None,
                },
                &credential_value,
            )
            .await?;
        let (mut selection, _) = setup_owner_sources_with_entries(
            &h,
            BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await?;
        selection.platform.project_id = None;

        let path = format!("/users/{ALICE}");
        put_with_provider(
            &path,
            "PLATFORM_ONLY",
            b"application-value",
            &h.db.pool,
            application.as_ref(),
        )
        .await?;

        let authority =
            admitted_with_provider(&h, selection.clone(), authorities.delegation_provider())
                .await?;
        let session = authority.current_session().await?;
        let grants = authority.owner_local_grants(&session).await?;
        ensure!(
            grants.len() == 1 && grants[0].credential_id == credential.metadata.id,
            "profile admission changed the application projection authority"
        );
        ensure!(
            credential_store
                .read_for_broker(&owner, &credential.metadata.id, credential.version)
                .await?
                .expose_secret()
                == credential_value.expose_secret(),
            "credential material did not remain under the credential authority"
        );

        let (request, recipient, context) = projection_request(&selection, unix_millis()? + 15_000);
        let sealed = authority.project_environment(request).await?;
        ensure!(
            recipient
                .open(&sealed, &context, unix_millis()?)?
                .entries()
                .collect::<Vec<_>>()
                == [("PLATFORM_ONLY", "application-value")]
        );

        let (mut request, recipient, context) =
            projection_request(&selection, unix_millis()? + 15_000);
        request.local_inventories = vec![v1::EnvironmentProjectionInventory {
            source: v1::EnvironmentProjectionSource::Project as i32,
            source_identity: "/projects/local-owner/local-project".into(),
            keys: vec!["LOCAL_ONLY".into()],
        }];
        let response = authority
            .project_environment_fragment(request.clone())
            .await?;
        let mut inventories = decode_local_inventories(&request.local_inventories)
            .map_err(|_| anyhow::anyhow!("local fixture inventory"))?;
        inventories.extend(
            decode_platform_inventories(&response.platform_inventories)
                .map_err(|_| anyhow::anyhow!("platform fixture inventory"))?,
        );
        inventories.sort_by_key(|inventory| inventory.source);
        let plan = ProjectionCompositionPlan::new(
            &context,
            *Uuid::parse_str(&request.request_id)?.as_bytes(),
            recipient.public_key(),
            &inventories,
            &selection.platform.ordinary_keys,
            &selection.platform.reserved_keys,
            unix_millis()?,
        )?;
        let local = seal_environment_projection_fragment(
            EnvironmentProjection::from_entries([(
                "LOCAL_ONLY".into(),
                Zeroizing::new(b"local-value".to_vec()),
            )])?,
            &context,
            recipient.public_key(),
            ProjectionContributor::Local,
            &plan,
            unix_millis()?,
        )?;
        let composed = compose_environment_projection(&local, &response.sealed_platform_fragment)?;
        ensure!(
            recipient
                .open(&composed, &context, unix_millis()?)?
                .entries()
                .collect::<BTreeMap<_, _>>()
                == BTreeMap::from([
                    ("LOCAL_ONLY", "local-value"),
                    ("PLATFORM_ONLY", "application-value"),
                ])
        );

        let wrong_application = admitted(&h, selection.clone()).await?;
        let (request, _, _) = projection_request(&selection, unix_millis()? + 15_000);
        ensure!(
            wrong_application
                .project_environment(request)
                .await
                .is_err(),
            "credential authority decrypted application material"
        );
        let reversed =
            crate::authority::RuntimeKekAuthorities::new(application.clone(), h.provider.clone());
        let wrong_store = reversed.credential_store(h.db.pool.clone());
        ensure!(
            wrong_store
                .read_for_broker(&owner, &credential.metadata.id, credential.version)
                .await
                .is_err(),
            "application authority decrypted credential material"
        );
        ensure!(
            application.unwrap_calls.load(Ordering::SeqCst) == 3,
            "application authority did not own both projections and the wrong-store denial"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_is_granted_only_when_the_local_capture_selected_it_and_it_is_connected()
-> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (captured, _) = setup_owner_sources(&h).await?;
        let mut platform = captured.platform.clone();
        for key in HttpProvider::GitHubOAuth.reserved_environment_keys() {
            platform.reserved_keys.remove(*key);
        }
        let uncaptured = OwnerLocalSelection::new(
            captured.local_environment_id,
            captured.local_environment_generation,
            platform,
            captured.selection_sha256,
        )?;
        let grants = |selection: OwnerLocalSelection| {
            let h = &h;
            async move {
                let authority = admitted(h, selection).await?;
                let session = authority.current_session().await?;
                anyhow::Ok(authority.owner_local_grants(&session).await?)
            }
        };

        // Without a connection both captures admit and no GitHub is fabricated.
        ensure!(grants(captured.clone()).await?.is_empty());
        ensure!(grants(uncaptured.clone()).await?.is_empty());

        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let github = h
            .store
            .create(
                &owner,
                CredentialRegistration {
                    provider: ProviderId::parse("github")?,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "GitHub".into(),
                    account_hint: Some("synthetic-account".into()),
                    expires_at_unix: None,
                },
                &ProtectedValue::from_slice(b"synthetic-github-material-never-public")?,
            )
            .await?;

        // A capture that selected GitHub is granted the account's connection.
        let connected = grants(captured).await?;
        ensure!(
            connected.len() == 1
                && connected[0].credential_id == github.metadata.id
                && connected[0].capability_slot == CapabilitySlot::github(),
            "captured GitHub was not granted the active connection"
        );
        // A capture made without GitHub never fails and never gains it later;
        // reselecting the profile captures it again.
        ensure!(grants(uncaptured).await?.is_empty());
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn empty_profile_admits_without_platform_environment_and_seals_exact_winners() -> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, _) = setup_owner_sources(&h).await?;
        let environment_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM environments WHERE id=$1")
                .bind(selection.local_environment_id.to_string())
                .fetch_one(&h.db.pool)
                .await?;
        ensure!(
            environment_rows == 0,
            "owner-local admission forged an environment row"
        );

        let organization = format!("/org-secrets/{ORGANIZATION}");
        let project = format!(
            "/projects/{ORGANIZATION}/{}",
            selection
                .platform
                .project_id
                .as_deref()
                .context("project")?
        );
        let user = format!("/users/{ALICE}");
        put(&organization, "SHARED", b"losing-organization", &h.db.pool).await?;
        put(&project, "SHARED", b"losing-project", &h.db.pool).await?;
        put(&user, "SHARED", b"winning-user", &h.db.pool).await?;
        put(&user, "EXACT", b"original-value", &h.db.pool).await?;
        put(&user, "SUPPRESSED", b"must-not-read", &h.db.pool).await?;
        sqlx::query(
            "UPDATE tenant_secrets SET ciphertext=decode(repeat('00',16),'hex') \
             WHERE key='SUPPRESSED' OR (key='SHARED' AND path<>$1)",
        )
        .bind(&user)
        .execute(&h.db.pool)
        .await?;

        let authority = admitted(&h, selection.clone()).await?;
        let session = authority.current_session().await?;
        ensure!(authority.owner_local_grants(&session).await?.is_empty());

        let now = unix_millis()?;
        let (mut stale_hash, _, _) = projection_request(&selection, now + 15_000);
        stale_hash.selection_sha256[0] ^= 1;
        ensure!(authority.project_environment(stale_hash).await.is_err());
        let (mut bad_recipient, _, _) = projection_request(&selection, now + 15_000);
        bad_recipient.recipient_public_key = vec![0; 32];
        ensure!(authority.project_environment(bad_recipient).await.is_err());
        let (expired, _, _) = projection_request(&selection, now.saturating_sub(1));
        ensure!(authority.project_environment(expired).await.is_err());
        let (too_long, _, _) =
            projection_request(&selection, unix_millis()? + 2 * MAX_PROJECTION_LIFETIME_MS);
        ensure!(authority.project_environment(too_long).await.is_err());

        let mut stale_generation = selection.clone();
        stale_generation.local_environment_generation += 1;
        let stale_authority = admitted(&h, stale_generation).await?;
        let stale_session = stale_authority.current_session().await?;
        ensure!(authority.owner_local_grants(&stale_session).await.is_err());

        let (request, recipient, context) = projection_request(&selection, unix_millis()? + 15_000);
        let sealed = authority.project_environment(request).await?;
        let values = recipient.open(&sealed, &context, unix_millis()?)?;
        ensure!(
            values.entries().collect::<BTreeMap<_, _>>()
                == BTreeMap::from([("EXACT", "original-value"), ("SHARED", "winning-user")])
        );
        ensure!(
            h.provider
                .unwrap_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                == 1
        );

        h.provider.unwrap_gate.arm();
        let (request, _, _) = projection_request(&selection, unix_millis()? + 15_000);
        let authority_task = authority.clone();
        let projection =
            tokio::spawn(async move { authority_task.project_environment(request).await });
        h.provider.unwrap_gate.wait().await?;
        let changed = put(&user, "EXACT", b"changed-after-capture", &h.db.pool).await;
        h.provider.unwrap_gate.release();
        changed?;
        ensure!(projection.await?.is_err(), "changed capture was released");
        let environment_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM environments WHERE id=$1")
                .bind(selection.local_environment_id.to_string())
                .fetch_one(&h.db.pool)
                .await?;
        ensure!(
            environment_rows == 0,
            "projection forged an environment row"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn mixed_projection_filters_losers_before_material_and_rechecks_winner_rotation() -> Result<()>
{
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (mut selection, _) = setup_owner_sources(&h).await?;
        selection.platform.project_id = None;
        let organization = format!("/org-secrets/{ORGANIZATION}");
        let user = format!("/users/{ALICE}");
        put(
            &organization,
            "LOCAL_WINS",
            b"suppressed-platform",
            &h.db.pool,
        )
        .await?;
        put(
            &organization,
            "PLATFORM_WINS",
            b"lower-platform",
            &h.db.pool,
        )
        .await?;
        put(&user, "PLATFORM_WINS", b"winning-platform", &h.db.pool).await?;
        put(&user, "PLATFORM_ONLY", b"platform-only", &h.db.pool).await?;
        put(&user, "SUPPRESSED", b"ordinary-suppressed", &h.db.pool).await?;
        sqlx::query(
            "UPDATE tenant_secrets SET ciphertext=decode(repeat('00',16),'hex') \
             WHERE key='SUPPRESSED' OR (path=$1 AND key IN ('LOCAL_WINS','PLATFORM_WINS'))",
        )
        .bind(&organization)
        .execute(&h.db.pool)
        .await?;

        let authority = admitted(&h, selection.clone()).await?;
        let (mut request, recipient, context) =
            projection_request(&selection, unix_millis()? + 15_000);
        request.local_inventories = vec![v1::EnvironmentProjectionInventory {
            source: v1::EnvironmentProjectionSource::Project as i32,
            source_identity: "/projects/local-owner/local-project".into(),
            keys: vec![
                "LOCAL_ONLY".into(),
                "LOCAL_WINS".into(),
                "PLATFORM_WINS".into(),
            ],
        }];
        ensure!(
            authority
                .project_environment(request.clone())
                .await
                .is_err(),
            "ordinary projection silently ignored mixed inventories"
        );
        ensure!(
            h.provider
                .unwrap_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
        );

        let response = authority
            .project_environment_fragment(request.clone())
            .await?;
        let local = decode_local_inventories(&request.local_inventories)
            .map_err(|_| anyhow::anyhow!("local fixture inventory"))?;
        let platform = decode_platform_inventories(&response.platform_inventories)
            .map_err(|_| anyhow::anyhow!("platform response inventory"))?;
        let mut all = local.clone();
        all.extend(platform);
        all.sort_by_key(|inventory| inventory.source);
        let request_id = Uuid::parse_str(&request.request_id)?;
        let plan = ProjectionCompositionPlan::new(
            &context,
            *request_id.as_bytes(),
            recipient.public_key(),
            &all,
            &selection.platform.ordinary_keys,
            &selection.platform.reserved_keys,
            unix_millis()?,
        )?;
        let local_values = EnvironmentProjection::from_entries([
            (
                "LOCAL_ONLY".into(),
                zeroize::Zeroizing::new(b"local-only".to_vec()),
            ),
            (
                "LOCAL_WINS".into(),
                zeroize::Zeroizing::new(b"winning-local".to_vec()),
            ),
        ])?;
        let local_fragment = seal_environment_projection_fragment(
            local_values,
            &context,
            recipient.public_key(),
            ProjectionContributor::Local,
            &plan,
            unix_millis()?,
        )?;
        let sealed =
            compose_environment_projection(&local_fragment, &response.sealed_platform_fragment)?;
        ensure!(
            recipient
                .open(&sealed, &context, unix_millis()?)?
                .entries()
                .collect::<BTreeMap<_, _>>()
                == BTreeMap::from([
                    ("LOCAL_ONLY", "local-only"),
                    ("LOCAL_WINS", "winning-local"),
                    ("PLATFORM_ONLY", "platform-only"),
                    ("PLATFORM_WINS", "winning-platform"),
                ])
        );
        ensure!(
            h.provider
                .unwrap_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                == 1,
            "suppressed and lower envelopes must not cause unwraps"
        );

        h.provider.unwrap_gate.arm();
        let (mut changing, _, _) = projection_request(&selection, unix_millis()? + 15_000);
        changing.local_inventories = request.local_inventories;
        let authority_task = authority.clone();
        let projection =
            tokio::spawn(
                async move { authority_task.project_environment_fragment(changing).await },
            );
        h.provider.unwrap_gate.wait().await?;
        let changed = put(&user, "PLATFORM_ONLY", b"rotated-after-capture", &h.db.pool).await;
        h.provider.unwrap_gate.release();
        changed?;
        ensure!(projection.await?.is_err(), "rotated winner was released");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn original_oauth_client_membership_and_project_each_remain_live_fences() -> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;

        let authority = admitted(&h, selection.clone()).await?;
        sqlx::query("UPDATE oidc_clients SET disabled=true WHERE id=$1")
            .bind(CLIENT)
            .execute(&h.db.pool)
            .await?;
        ensure!(authority.current_session().await.is_err());
        sqlx::query("UPDATE oidc_clients SET disabled=false WHERE id=$1")
            .bind(CLIENT)
            .execute(&h.db.pool)
            .await?;

        let authority = admitted(&h, selection.clone()).await?;
        sqlx::query("DELETE FROM org_members WHERE org_id=$1 AND user_id=$2")
            .bind(ORGANIZATION)
            .bind(ALICE)
            .execute(&h.db.pool)
            .await?;
        ensure!(authority.current_session().await.is_err());
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES($1,$2,$3,'member')")
            .bind(Uuid::new_v4().to_string())
            .bind(ORGANIZATION)
            .bind(ALICE)
            .execute(&h.db.pool)
            .await?;

        let authority = admitted(&h, selection.clone()).await?;
        sqlx::query("DELETE FROM secret_projects WHERE id=$1")
            .bind(&project)
            .execute(&h.db.pool)
            .await?;
        ensure!(authority.current_session().await.is_err());
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'delegated')")
            .bind(&project)
            .bind(ORGANIZATION)
            .execute(&h.db.pool)
            .await?;

        let authority = admitted(&h, selection).await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE)))
            .execute(&h.db.pool)
            .await?;
        ensure!(authority.current_session().await.is_err());
        Ok(())
    }
    .await;
    h.finish(result).await
}
