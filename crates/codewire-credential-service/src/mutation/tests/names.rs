//! A new or renamed credential's name may not start with a provider id and
//! `/`; a credential that already has one keeps it (#4928).

use super::*;
use codewire_access::CredentialAuthKind;
use codewire_platform_credentials::{CredentialRecord, CredentialRegistration};
use codewire_protected_store::ProtectedValue;

const RESERVED: [&str; 5] = [
    "anthropic/work",
    "OpenAI/n@example.com",
    "GITHUB/work",
    "ssh/laptop",
    "github/",
];

#[test]
fn only_new_names_are_refused_a_provider_prefix() {
    for name in RESERVED {
        assert_eq!(validate_new_name(name), Err(Error::NameReservesProvider));
        assert_eq!(
            validate_target_name(name, false),
            Err(Error::NameReservesProvider)
        );
        assert_eq!(validate_target_name(name, true), Ok(()));
        assert_eq!(validate_name(name), Ok(()));
    }
    for name in ["n@example.com", "work/github", "gitlab/work", "githubwork"] {
        assert_eq!(validate_new_name(name), Ok(()));
    }
    assert_eq!(validate_new_name(" github/work"), Err(Error::InvalidInput));
}

async fn legacy(h: &Harness, provider: &str, kind: CredentialAuthKind) -> Result<CredentialRecord> {
    Ok(h.store
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            CredentialRegistration {
                provider: ProviderId::parse(provider)?,
                authentication_kind: kind,
                display_name: "github/work".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            &ProtectedValue::from_slice(b"synthetic-legacy-credential")?,
        )
        .await?)
}

fn rename(record: &CredentialRecord, name: &str) -> Value {
    json!({"credentialId":record.metadata.id.as_str(),
        "expectedRevocationGeneration":record.metadata.revocation_generation.to_string(),
        "expectedName":record.metadata.display_name, "name":name})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_new_names_refuse_a_provider_prefix_that_existing_names_keep() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let existing = legacy(&h, "openai", CredentialAuthKind::ApiKey).await?;
        // Creating or renaming to a reserved name changes nothing.
        for name in RESERVED {
            let (status, response) = h
                .rpc
                .add_api_key(
                    Auth::Alice,
                    "openai",
                    name,
                    API_KEY_MATERIAL.as_bytes(),
                    None,
                )
                .await?;
            ensure!(!status.is_success() && response["code"] == "invalid_argument");
            let (status, response) = h
                .rpc
                .update("RenameCredential", Auth::Alice, rename(&existing, name))
                .await?;
            ensure!(!status.is_success() && response["code"] == "invalid_argument");
            h.rpc
                .enroll(Auth::Alice, name)
                .await?
                .error("invalid_argument")
                .await?;
            h.drained().await?;
        }
        ensure!(
            h.device.started() == 0,
            "a refused name started a provider login"
        );
        ensure!(h.count().await? == 1);
        // The credential that already has such a name still renames away.
        let (status, response) = h
            .rpc
            .update("RenameCredential", Auth::Alice, rename(&existing, "work"))
            .await?;
        ensure!(
            status.is_success() && response["credential"]["name"] == "work",
            "{response}"
        );
        h.drained().await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_reconnect_keeps_an_existing_provider_prefixed_name() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let existing = legacy(&h, "openai", CredentialAuthKind::OAuth).await?;
        let mut response = h
            .rpc
            .enroll_request(
                Auth::Alice,
                json!({"name":"github/work","credentialId":existing.metadata.id.as_str(),
                    "expectedRevocationGeneration":existing.metadata.revocation_generation.to_string()}),
            )
            .await?;
        response.challenge().await?;
        h.release()?;
        let metadata = response.committed().await?;
        h.drained().await?;
        ensure!(
            metadata["id"] == existing.metadata.id.as_str() && metadata["name"] == "github/work"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}
