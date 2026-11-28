//! A bound secret in a hosted projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder takes
//! its value's place, its row is never decrypted, and without the
//! environment's application-secret key, or in a set with no slot, it is
//! refused and never projected raw. Every value here is synthetic.

use super::*;

use codewire_access::{
    ApplicationSecretKey, EnvironmentId, PLACEHOLDER_KEY_BYTES, PlaceholderKey, PlaceholderPrefix,
    SecretKind, SecretPlaceholder, SecretSlot,
};

const CANARY: &[u8] = b"canary-bound-value-never-projected";
const BINDING: &str = r#"{"hosts":["api.fancy.example"],"presentation":{"kind":"header","headers":["Authorization"],"scheme":"Bearer"},"prefix":"ft_"}"#;

fn application_key() -> ApplicationSecretKey {
    ApplicationSecretKey::derive(&PlaceholderKey::from_slice(&[5; PLACEHOLDER_KEY_BYTES]).unwrap())
}

/// Bind `key` at `path` as the platform store writes a binding.
async fn bind(pool: &sqlx::PgPool, path: &str, key: &str, generation: i64) -> Result<Uuid> {
    let binding_id = Uuid::new_v4();
    let updated = sqlx::query(
        "UPDATE tenant_secrets SET binding=$3::text::jsonb,binding_id=$4,binding_generation=$5 \
         WHERE path=$1 AND key=$2",
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

/// A project's bound secret projects its placeholder, derived from its
/// project's slot, binding ID and generation, beside a plain secret's raw
/// value. Its ciphertext is broken and its scope's key is never unwrapped,
/// so it was never decrypted, and the canary is in no value.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn hosted_bound_secret_projects_its_placeholder_and_never_its_canary() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        let project = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'bound')")
            .bind(&project)
            .bind(&f.scope.organization)
            .execute(&f.db.pool)
            .await?;
        sources(
            &f,
            json!({"project":format!("platform:id:{project}"),"user":"platform"}),
            json!({}),
            false,
        )
        .await?;
        let project_path = format!("/projects/{}/{project}", f.scope.organization);
        let user = format!("/users/{}", f.scope.creator);
        put(&f, &project_path, "FANCY_TOKEN", CANARY).await?;
        put(&f, &user, "PLAIN_TOKEN", b"plain-value").await?;
        let binding_id = bind(&f.db.pool, &project_path, "FANCY_TOKEN", 2).await?;
        sqlx::query(
            "UPDATE tenant_secrets SET ciphertext=decode(repeat('00',32),'hex') \
             WHERE path=$1 AND key='FANCY_TOKEN'",
        )
        .bind(&project_path)
        .execute(&f.db.pool)
        .await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f, provider.clone()).await?;
        let (message, recipient, context) = request(&authority)?;
        let sealed = authority
            .project_environment(message, Some(application_key()))
            .await?;
        let values = recipient.open(&sealed, &context, now_ms())?;
        let expected = SecretPlaceholder::derive(
            &application_key(),
            &EnvironmentId::parse(f.scope.environment_id.clone())?,
            &SecretSlot::new(SecretKind::Project, &project, "FANCY_TOKEN")?,
            binding_id.as_bytes(),
            2,
            Some(&PlaceholderPrefix::parse("ft_")?),
        );
        let entries: BTreeMap<_, _> = values.entries().collect();
        ensure!(
            entries
                == BTreeMap::from([
                    ("FANCY_TOKEN", expected.as_str()),
                    ("PLAIN_TOKEN", "plain-value"),
                ])
        );
        let canary = std::str::from_utf8(CANARY)?;
        ensure!(entries.values().all(|value| !value.contains(canary)));
        ensure!(!expected.as_str().contains(&project));
        ensure!(
            provider.calls.load(Ordering::SeqCst) == 1,
            "only the plain secret's scope key is unwrapped"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Without the application-secret key, through the authority and through a
/// lease provider whose epoch derives no placeholders, and for a set whose
/// stored ID isn't its kind's spelling, a bound secret refuses the whole
/// projection before any key is unwrapped. Made plain again, it projects raw.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn hosted_bound_secret_without_a_key_or_a_slot_is_refused_never_raw() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        grant_projection(&f).await?;
        let project = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO secret_projects(id,org_id,name) VALUES($1,$2,'bound')")
            .bind(&project)
            .bind(&f.scope.organization)
            .execute(&f.db.pool)
            .await?;
        sources(
            &f,
            json!({"project":format!("platform:id:{project}"),"user":"platform"}),
            json!({}),
            false,
        )
        .await?;
        let project_path = format!("/projects/{}/{project}", f.scope.organization);
        let user = format!("/users/{}", f.scope.creator);
        put(&f, &project_path, "FANCY_TOKEN", CANARY).await?;
        put(&f, &user, "PLAIN_TOKEN", b"plain-value").await?;
        bind(&f.db.pool, &project_path, "FANCY_TOKEN", 1).await?;
        let provider = Arc::new(ObservedProvider::default());
        let authority = admitted(&f, provider.clone()).await?;

        let (message, _, _) = request(&authority)?;
        ensure!(authority.project_environment(message, None).await.is_err());
        let broker = PlatformBrokerLeaseProvider::connect(
            authority.clone(),
            Arc::new(PlatformCredentialStore::new(
                f.pool.clone(),
                Arc::new(TestKekProvider),
                builtin_provider_catalog(),
            )),
            PlatformAccessProfileStore::new(f.pool.clone(), builtin_provider_catalog()),
        )
        .await?;
        let (message, _, _) = request(&authority)?;
        ensure!(broker.project_environment(message).await.is_err());

        // The fixture's creator, `synthetic-creator`, isn't 32 lowercase
        // hex: the user's set has no slot.
        sqlx::query("UPDATE tenant_secrets SET binding=NULL WHERE path=$1")
            .bind(&project_path)
            .execute(&f.db.pool)
            .await?;
        put(&f, &user, "USER_TOKEN", CANARY).await?;
        bind(&f.db.pool, &user, "USER_TOKEN", 1).await?;
        let (message, _, _) = request(&authority)?;
        ensure!(
            authority
                .project_environment(message, Some(application_key()))
                .await
                .is_err()
        );
        ensure!(
            provider.calls.load(Ordering::SeqCst) == 0,
            "a refused bound secret unwrapped a key"
        );

        sqlx::query("UPDATE tenant_secrets SET binding=NULL WHERE path=$1")
            .bind(&user)
            .execute(&f.db.pool)
            .await?;
        let (message, recipient, context) = request(&authority)?;
        let sealed = authority.project_environment(message, None).await?;
        let entries: BTreeMap<_, _> = recipient
            .open(&sealed, &context, now_ms())?
            .entries()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        ensure!(
            entries
                == BTreeMap::from([
                    (
                        "FANCY_TOKEN".to_owned(),
                        std::str::from_utf8(CANARY)?.to_owned()
                    ),
                    ("PLAIN_TOKEN".to_owned(), "plain-value".to_owned()),
                    (
                        "USER_TOKEN".to_owned(),
                        std::str::from_utf8(CANARY)?.to_owned()
                    ),
                ]),
            "a plain secret projects raw"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}
