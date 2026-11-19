//! A provider narrows a credential name, and a name reaches only its owner
//! (#4928). Until migration 0042 replaces the per-owner name indexes, a name is
//! still unique across an owner's providers; the tests in which two providers
//! share a name arrive with that migration.

use super::*;
use codewire_platform_credentials::CredentialRegistration;

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
async fn a_name_resolves_with_its_provider_and_only_for_its_owner() -> Result<()> {
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
        // The per-owner index still refuses the name to another provider.
        ensure!(
            store
                .create(
                    &owner,
                    named("anthropic", "N@Example.com", Kind::ApiKey),
                    &value(NEW_VALUE),
                )
                .await
                == Err(Error::AlreadyExists)
        );
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
        let team = store
            .create(
                &org,
                named("openai", "Team", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let (pool, _) = db.metadata_pool().await?;
        let reader = CredentialMetadataReader::new(pool, builtin_provider_catalog());

        ensure!(reader.resolve(&owner, "N@EXAMPLE.COM", None).await? == openai.metadata);
        ensure!(
            reader
                .resolve(&owner, "n@example.com", Some(&provider("openai")))
                .await?
                == openai.metadata
        );
        for wrong in ["anthropic", "github"] {
            ensure!(
                reader
                    .resolve(&owner, "n@example.com", Some(&provider(wrong)))
                    .await
                    == Err(Error::NotFound.into())
            );
        }
        ensure!(reader.resolve(&owner, "github/work", None).await? == literal.metadata);
        ensure!(reader.resolve(&owner, "work", None).await? == github.metadata);
        ensure!(
            reader
                .resolve(&owner, "work", Some(&provider("github")))
                .await?
                == github.metadata
        );
        ensure!(
            reader
                .resolve(&org, "team", Some(&provider("openai")))
                .await?
                == team.metadata
        );

        // Authorization comes first: an owner that holds none of them learns
        // nothing.
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
            ensure!(
                reader
                    .resolve(selected, name, Some(&provider("openai")))
                    .await
                    == Err(Error::NotFound.into()),
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
