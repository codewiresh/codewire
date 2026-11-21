//! Credential names are unique per owner and provider, ignoring case, and a
//! bare name two providers share resolves to neither (#4928).

use super::*;
use codewire_platform_credentials::{CredentialNameError, CredentialRegistration};

fn named(provider: &str, name: &str, kind: Kind) -> CredentialRegistration {
    let mut registration = registration(name, kind);
    registration.provider = ProviderId::parse(provider).expect("built-in provider");
    registration
}

fn provider(value: &str) -> ProviderId {
    ProviderId::parse(value).expect("built-in provider")
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_name_is_unique_within_a_provider_and_shared_across_providers() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("names-owner").await?;
        let org = db.organization("names-org").await?;
        let (pool, _) = db.broker_pool().await?;
        let store = codewire_platform_credentials::PlatformCredentialStore::new(
            pool.clone(),
            Arc::new(SyntheticKek::default()),
            builtin_provider_catalog(),
        );
        // The owner's own label, the same for each provider they sign in with.
        store
            .create(
                &owner,
                named("openai", "n@example.com", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        store
            .create(
                &owner,
                named("anthropic", "N@Example.com", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        store
            .create(
                &org,
                named("openai", "n@example.com", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        store
            .create(
                &org,
                named("anthropic", "n@example.com", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        // A Claude sign-in and a Claude key are one provider: still one name.
        for (selected, registration) in [
            (&owner, named("openai", "N@EXAMPLE.COM", Kind::ApiKey)),
            (&owner, named("anthropic", "n@example.com", Kind::OAuth)),
            (&org, named("anthropic", "N@EXAMPLE.COM", Kind::ApiKey)),
        ] {
            ensure!(
                store
                    .create(selected, registration, &value(NEW_VALUE))
                    .await
                    == Err(Error::AlreadyExists)
            );
        }

        // A rename meets the same rule.
        let spare = store
            .create(
                &owner,
                named("openai", "Spare", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store
                .rename_in(
                    &mut tx,
                    &owner,
                    &spare.metadata.id,
                    1,
                    "Spare",
                    "n@EXAMPLE.com".into()
                )
                .await
                == Err(Error::AlreadyExists)
        );
        tx.rollback().await?;
        let other_provider = store
            .create(
                &owner,
                named("anthropic", "Other", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let mut tx = pool.begin().await?;
        let renamed = store
            .rename_in(
                &mut tx,
                &owner,
                &other_provider.metadata.id,
                1,
                "Other",
                "spare".into(),
            )
            .await?;
        tx.commit().await?;
        ensure!(renamed.metadata.display_name == "spare");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_shared_name_resolves_only_with_its_provider_and_only_for_its_owner() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("resolve-owner").await?;
        let other = db.user("resolve-other").await?;
        let org = db.organization("resolve-org").await?;
        let other_org = db.organization("resolve-other-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let openai = store
            .create(
                &owner,
                named("openai", "n@example.com", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let anthropic = store
            .create(
                &owner,
                named("anthropic", "N@Example.com", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        // A literal name an older Codewire could save beside a GitHub
        // credential named after its suffix.
        let literal = store
            .create(
                &owner,
                named("openai", "github/work", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let github = store
            .create(
                &owner,
                named("github", "work", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        for organization_provider in ["openai", "anthropic"] {
            store
                .create(
                    &org,
                    named(organization_provider, "Team", Kind::ApiKey),
                    &value(OLD_VALUE),
                )
                .await?;
        }
        let (pool, _) = db.metadata_pool().await?;
        let reader = CredentialMetadataReader::new(pool, builtin_provider_catalog());

        ensure!(
            reader.resolve(&owner, "N@EXAMPLE.COM", None).await
                == Err(CredentialNameError::Ambiguous {
                    providers: vec![provider("anthropic"), provider("openai")]
                })
        );
        ensure!(
            reader
                .resolve(&owner, "n@example.com", Some(&provider("openai")))
                .await?
                == openai.metadata
        );
        ensure!(
            reader
                .resolve(&owner, "n@example.com", Some(&provider("anthropic")))
                .await?
                == anthropic.metadata
        );
        ensure!(
            reader
                .resolve(&owner, "n@example.com", Some(&provider("github")))
                .await
                == Err(Error::NotFound.into())
        );
        ensure!(reader.resolve(&owner, "github/work", None).await? == literal.metadata);
        ensure!(reader.resolve(&owner, "work", None).await? == github.metadata);
        ensure!(
            reader
                .resolve(&owner, "work", Some(&provider("github")))
                .await?
                == github.metadata
        );
        ensure!(
            reader.resolve(&org, "team", None).await
                == Err(CredentialNameError::Ambiguous {
                    providers: vec![provider("anthropic"), provider("openai")]
                })
        );

        // Authorization comes first: an owner that holds none of them learns
        // nothing, not even that the name is shared.
        for (selected, name) in [
            (&other, "n@example.com"),
            (&other_org, "n@example.com"),
            (&other_org, "Team"),
            (&owner, "Team"),
        ] {
            ensure!(
                reader.resolve(selected, name, None).await == Err(Error::NotFound.into()),
                "{name} reached an owner that holds none of it"
            );
        }
        begin_organization_deletion(&db.pool, &admin_user(), org.id().as_str()).await?;
        ensure!(reader.resolve(&org, "Team", None).await == Err(Error::NotFound.into()));
        Ok(())
    }
    .await;
    db.finish(result).await
}
