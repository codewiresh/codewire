//! A definite refusal's reason crosses the authority's real transport, and a
//! refusal the caller has no words for carries none (#4826).

use super::*;

fn oauth(provider_id: &str, name: &str) -> NewCredential {
    NewCredential {
        provider: provider(provider_id),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: name.into(),
        account_hint: None,
        expires_at_unix: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_definite_refusal_names_its_reason_over_the_transport() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    // GitHub's single connection is a built-in provider rule.
    let (shutdown, task) = start_listening_authority(
        config.clone(),
        TestProtectedStore::default(),
        codewire_access::builtin_provider_catalog(),
        Default::default(),
    )
    .await;
    let mut client = connect_when_ready(&config).await;
    let material = || ProtectedValue::from_slice(FIRST_MATERIAL).unwrap();

    let github = client
        .add_credential(oauth("github", "work"), material())
        .await
        .unwrap();
    let second = client
        .add_credential(oauth("github", "home"), material())
        .await
        .unwrap_err();
    assert_eq!(second.code(), Code::AlreadyExists);
    assert_eq!(
        store_refusal_reason(&second),
        Some("CREDENTIAL_GITHUB_ALREADY_CONNECTED")
    );

    client.revoke_credential(&github.metadata.id).await.unwrap();
    let stale = client
        .rotate_credential_material(
            &github.metadata.id,
            github.metadata.revocation_generation,
            ProtectedValue::from_slice(SECOND_MATERIAL).unwrap(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(stale.code(), Code::FailedPrecondition);
    assert_eq!(
        store_refusal_reason(&stale),
        Some("CREDENTIAL_REVISION_CHANGED")
    );

    // A name is unique per provider (#4928): another provider's credential
    // may share it, and a taken name is told by its code alone.
    client
        .add_credential(oauth("openai", "work"), material())
        .await
        .unwrap();
    let taken = client
        .add_credential(oauth("openai", "WORK"), material())
        .await
        .unwrap_err();
    assert_eq!(taken.code(), Code::AlreadyExists);
    assert_eq!(store_refusal_reason(&taken), None);

    let reserved = client
        .add_credential(oauth("openai", "github/work"), material())
        .await
        .unwrap_err();
    assert_eq!(reserved.code(), Code::InvalidArgument);
    assert_eq!(
        store_refusal_reason(&reserved),
        Some("CREDENTIAL_NAME_RESERVES_PROVIDER")
    );

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}
