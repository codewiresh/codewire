//! A bound secret in a local VM's platform projection, full and composed
//! (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its
//! placeholder takes its value's place, its row is never decrypted, and
//! without the application-secret key, or in a set with no slot, it is
//! refused and never projected raw. Every value here is synthetic.

use super::*;

use codewire_access::{
    ApplicationSecretKey, PLACEHOLDER_KEY_BYTES, PlaceholderKey, PlaceholderPrefix, SecretKind,
    SecretPlaceholder, SecretSlot,
};
use codewire_workload_secrets::ProjectionSourceInventory;

const CANARY: &str = "canary-delegated-bound-value-never-projected";
const BINDING: &str = r#"{"hosts":["api.fancy.example"],"presentation":{"kind":"header","headers":["X-Api-Key"],"scheme":null},"prefix":"ft_"}"#;

fn application_key() -> ApplicationSecretKey {
    ApplicationSecretKey::derive(&PlaceholderKey::from_slice(&[6; PLACEHOLDER_KEY_BYTES]).unwrap())
}

async fn bind(pool: &PgPool, path: &str, key: &str, generation: i64) -> Result<Uuid> {
    let binding_id = Uuid::new_v4();
    let updated = sqlx::query(
        "UPDATE tenant_secrets SET binding=$3::text::jsonb,binding_id=$4,binding_generation=$5, \
         ciphertext=decode(repeat('00',32),'hex') WHERE path=$1 AND key=$2",
    )
    .bind(path)
    .bind(key)
    .bind(BINDING)
    .bind(binding_id)
    .bind(generation)
    .execute(pool)
    .await?;
    ensure!(updated.rows_affected() == 1);
    Ok(binding_id)
}

fn unwraps(h: &Harness) -> usize {
    h.provider
        .unwrap_calls
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// The fragment for one local personal key beside the platform's, composed
/// as the local authority composes it. The platform's selection must leave
/// its user source out, since the local one stands in its rank.
async fn composed(
    authority: &OwnerLocalRuntimeAuthority,
    selection: &OwnerLocalSelection,
    key: Option<ApplicationSecretKey>,
) -> Result<BTreeMap<String, String>> {
    let (mut request, recipient, context) = projection_request(selection, unix_millis()? + 15_000);
    request.local_inventories = vec![v1::EnvironmentProjectionInventory {
        source: v1::EnvironmentProjectionSource::User as i32,
        source_identity: "local:user".into(),
        keys: vec!["LOCAL_ONLY".into()],
    }];
    let response = authority
        .project_environment_fragment(request.clone(), key)
        .await?;
    let mut inventories: Vec<ProjectionSourceInventory> =
        decode_local_inventories(&request.local_inventories)
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
    let sealed = compose_environment_projection(&local, &response.sealed_platform_fragment)?;
    Ok(recipient
        .open(&sealed, &context, unix_millis()?)?
        .entries()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn delegated_bound_secret_projects_its_placeholder_full_and_composed_never_its_canary()
-> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        let organization = format!("/org-secrets/{ORGANIZATION}");
        put(&project_path, "FANCY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        put(&organization, "PLAIN_TOKEN", b"plain-value", &h.db.pool).await?;
        let binding_id = bind(&h.db.pool, &project_path, "FANCY_TOKEN", 4).await?;
        let expected = SecretPlaceholder::derive(
            &application_key(),
            &EnvironmentId::parse(selection.local_environment_id.to_string())?,
            &SecretSlot::new(SecretKind::Project, &project, "FANCY_TOKEN")?,
            binding_id.as_bytes(),
            4,
            Some(&PlaceholderPrefix::parse("ft_")?),
        );
        let authority = admitted(&h, selection.clone()).await?;

        let (request, recipient, context) = projection_request(&selection, unix_millis()? + 15_000);
        let sealed = authority
            .project_environment(request, Some(application_key()))
            .await
            .context("full projection")?;
        let full: BTreeMap<String, String> = recipient
            .open(&sealed, &context, unix_millis()?)?
            .entries()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        ensure!(
            full == BTreeMap::from([
                ("FANCY_TOKEN".to_owned(), expected.as_str().to_owned()),
                ("PLAIN_TOKEN".to_owned(), "plain-value".to_owned()),
            ])
        );

        let mut platform_only = selection.clone();
        platform_only.platform.user_selected = false;
        let authority = admitted(&h, platform_only.clone()).await?;
        let fragment = composed(&authority, &platform_only, Some(application_key()))
            .await
            .context("composed projection")?;
        ensure!(
            fragment
                == BTreeMap::from([
                    ("FANCY_TOKEN".to_owned(), expected.as_str().to_owned()),
                    ("LOCAL_ONLY".to_owned(), "local-value".to_owned()),
                    ("PLAIN_TOKEN".to_owned(), "plain-value".to_owned()),
                ])
        );
        ensure!(
            full.values()
                .chain(fragment.values())
                .all(|value| !value.contains(CANARY))
        );
        ensure!(
            unwraps(&h) == 2,
            "only the plain secret's scope key is unwrapped, once per projection"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

/// Without the application-secret key, or for a set whose stored ID isn't
/// its kind's spelling (`mutation-alice` and `mutation-org` aren't 32
/// lowercase hex), a bound secret refuses the full and the composed
/// projection before any key is unwrapped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn delegated_bound_secret_without_a_key_or_a_slot_is_refused_never_raw() -> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;
        let mut platform_only = selection.clone();
        platform_only.platform.user_selected = false;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        let organization = format!("/org-secrets/{ORGANIZATION}");
        let user = format!("/users/{ALICE}");
        put(&project_path, "FANCY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        put(&user, "PLAIN_TOKEN", b"plain-value", &h.db.pool).await?;
        bind(&h.db.pool, &project_path, "FANCY_TOKEN", 1).await?;
        let authority = admitted(&h, selection.clone()).await?;
        let composing = admitted(&h, platform_only.clone()).await?;

        let (request, _, _) = projection_request(&selection, unix_millis()? + 15_000);
        ensure!(authority.project_environment(request, None).await.is_err());
        ensure!(composed(&composing, &platform_only, None).await.is_err());

        sqlx::query("DELETE FROM tenant_secrets WHERE path=$1")
            .bind(&project_path)
            .execute(&h.db.pool)
            .await?;
        put(&user, "USER_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        bind(&h.db.pool, &user, "USER_TOKEN", 1).await?;
        let (request, _, _) = projection_request(&selection, unix_millis()? + 15_000);
        ensure!(
            authority
                .project_environment(request, Some(application_key()))
                .await
                .is_err()
        );
        put(&organization, "ORG_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        bind(&h.db.pool, &organization, "ORG_TOKEN", 1).await?;
        ensure!(
            composed(&composing, &platform_only, Some(application_key()))
                .await
                .is_err()
        );
        ensure!(unwraps(&h) == 0, "a refused bound secret unwrapped a key");

        // Made plain since, with its value: a local VM's boot record never
        // reaches the platform, so a secret that was ever bound is refused
        // by name, never projected raw (condition A). Set again from
        // nothing, it was never bound and projects.
        sqlx::query("UPDATE tenant_secrets SET binding=NULL")
            .execute(&h.db.pool)
            .await?;
        put(&organization, "ORG_TOKEN", b"org-plain", &h.db.pool).await?;
        ensure!(
            composed(&composing, &platform_only, None).await.is_err(),
            "a secret bound once was projected raw"
        );
        let (request, _, _) = projection_request(&platform_only, unix_millis()? + 15_000);
        ensure!(composing.project_environment(request, None).await.is_err());
        sqlx::query("DELETE FROM tenant_secrets WHERE path=$1 AND key='ORG_TOKEN'")
            .bind(&organization)
            .execute(&h.db.pool)
            .await?;
        put(&organization, "ORG_TOKEN", b"org-plain", &h.db.pool).await?;
        ensure!(
            composed(&composing, &platform_only, None).await?
                == BTreeMap::from([
                    ("LOCAL_ONLY".to_owned(), "local-value".to_owned()),
                    ("ORG_TOKEN".to_owned(), "org-plain".to_owned()),
                ])
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}
