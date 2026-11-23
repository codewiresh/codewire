//! A local connect against the real authority: the store is probed before
//! any provider step, and what a failed save says (#4826).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use codewire_access::builtin_provider_catalog;
use codewire_local_credentials::{AuthorityRuntimeConfig, LocalCredentialClient};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue,
};

use super::super::CredentialConnectProviderArg;
use super::tests::connect_ready_authority;
use super::*;

/// An ephemeral store that refuses every write while `refusal` is set, and
/// holds every write unanswered while it is frozen, as a stuck keyring does.
#[derive(Clone, Default)]
struct Store {
    inner: Arc<EphemeralProtectedStore>,
    refusal: Arc<Mutex<Option<ProtectedStoreError>>>,
    frozen: Arc<(Mutex<bool>, Condvar)>,
    held: Arc<AtomicBool>,
}

impl Store {
    fn freeze(&self) -> Thaw {
        *self.frozen.0.lock().unwrap() = true;
        Thaw(self.clone())
    }
}

/// Thaws the store when dropped, so a failed test never leaves the
/// authority's worker waiting.
struct Thaw(Store);

impl Drop for Thaw {
    fn drop(&mut self) {
        *self.0.frozen.0.lock().unwrap() = false;
        self.0.frozen.1.notify_all();
    }
}

impl ProtectedStore for Store {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::ProcessLifetime
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.inner.get(id)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let mut frozen = self.frozen.0.lock().unwrap();
        while *frozen {
            self.held.store(true, Ordering::SeqCst);
            frozen = self.frozen.1.wait(frozen).unwrap();
        }
        drop(frozen);
        match *self.refusal.lock().unwrap() {
            Some(error) => Err(error),
            None => self.inner.put(id, value),
        }
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.inner.delete(id)
    }
}

struct Authority {
    _temp: tempfile::TempDir,
    config: AuthorityRuntimeConfig,
    server: tokio::task::JoinHandle<Result<(), codewire_local_credentials::AuthorityRuntimeError>>,
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn serve(store: Store) -> (Authority, LocalCredentialClient) {
    let temp = tempfile::tempdir().unwrap();
    let config = AuthorityRuntimeConfig {
        root: temp.path().join("authority"),
        executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        socket_dir: temp.path().join("authority"),
    };
    let server = tokio::spawn(
        codewire_local_credentials::serve_local_credential_authority(
            config.clone(),
            store,
            builtin_provider_catalog(),
        ),
    );
    let client = connect_ready_authority(&config, &server).await;
    (
        Authority {
            _temp: temp,
            config,
            server,
        },
        client,
    )
}

/// A locked store refuses the local connect's readiness check, which says so
/// in a save's words, so the connect stops before the sign-in starts; a
/// store that accepts the write answers it and keeps nothing.
#[tokio::test]
async fn a_store_that_refuses_a_write_is_not_ready_for_a_sign_in() {
    let store = Store::default();
    *store.refusal.lock().unwrap() = Some(ProtectedStoreError::AccessDenied);
    let (_authority, mut client) = serve(store.clone()).await;
    let error = LocalConnectStore {
        store_check_explained: false,
        client: &mut client,
        json: false,
    }
    .ready(CredentialConnectProviderArg::Claude, "work")
    .await
    .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("is locked") && text.contains("so your Claude sign-in wasn't saved"),
        "{text}"
    );
    assert!(!text.contains("locked or inaccessible"), "{text}");
    assert!(!text.contains("code:"), "{text}");
    assert!(client.list_credentials().await.unwrap().is_empty());

    *store.refusal.lock().unwrap() = None;
    LocalConnectStore {
        store_check_explained: false,
        client: &mut client,
        json: false,
    }
    .ready(CredentialConnectProviderArg::Claude, "work")
    .await
    .unwrap();
    assert!(client.list_credentials().await.unwrap().is_empty());
}

/// A store that times out or is unavailable stops the connect in a save's
/// words, never the store's (#5271), and nothing is saved.
#[tokio::test]
async fn a_store_that_times_out_or_is_unavailable_is_not_ready() {
    for (error, words) in [
        (
            ProtectedStoreError::TimedOut,
            "didn't answer within 2 minutes, so your Codex sign-in wasn't saved",
        ),
        (
            ProtectedStoreError::Unavailable,
            "the local credential store refused your Codex sign-in, so nothing was saved",
        ),
    ] {
        let store = Store::default();
        *store.refusal.lock().unwrap() = Some(error);
        let (_authority, mut client) = serve(store).await;
        let text = format!(
            "{:#}",
            LocalConnectStore {
                store_check_explained: false,
                client: &mut client,
                json: false,
            }
            .ready(CredentialConnectProviderArg::Codex, "work")
            .await
            .unwrap_err()
        );
        assert!(text.contains(words), "{text}");
        // The store's own message is for the log, never the person.
        assert!(!text.contains("protected storage"), "{text}");
        assert!(!text.contains("code:"), "{text}");
        assert!(client.list_credentials().await.unwrap().is_empty());
    }
}

/// Stderr that thaws the store once the waiting line is written, so the
/// listing can only answer after the line, however slowly the test runs.
struct ThawOnWrite {
    written: Vec<u8>,
    thaw: Option<Thaw>,
}

impl std::io::Write for ThawOnWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        self.thaw.take();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A keyring that stops answering holds up only the call that reached it
/// (#5413). That call shows the waiting line within a second, never a
/// silent pause (#5271). Another command's listing meanwhile answers at
/// once, with no line, since the authority holds no lock across the store.
#[tokio::test]
async fn only_the_call_at_a_frozen_keyring_waits_and_shows_the_waiting_line() {
    let store = Store::default();
    let thaw = store.freeze();
    let (authority, mut client) = serve(store.clone()).await;
    let mut doctor = connect_ready_authority(&authority.config, &authority.server).await;
    let probe = tokio::spawn(async move {
        let mut stderr = ThawOnWrite {
            written: Vec::new(),
            thaw: Some(thaw),
        };
        let screen = store_wait::Screen {
            live: false,
            ascii: false,
        };
        let probed =
            store_wait::waiting_on(&mut stderr, screen, doctor.probe_protected_store()).await;
        (probed, stderr.written)
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        while !store.held.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the probe reached the frozen keyring");

    // Well inside the second before the waiting line would show.
    let listing = tokio::time::timeout(Duration::from_millis(500), client.list_credentials())
        .await
        .expect("the listing answered while the keyring was frozen");
    assert!(listing.unwrap().is_empty());

    // Without the line the store never thaws, so this bound turns a hang
    // into a failure.
    let (probed, written) = tokio::time::timeout(Duration::from_secs(30), probe)
        .await
        .expect("the waiting line was written and the store thawed")
        .unwrap();
    probed.unwrap();
    // The words themselves are pinned in store_wait's tests.
    assert_eq!(
        String::from_utf8(written).unwrap(),
        format!("{}\n", store_wait::plain_line())
    );
}

/// Saves a synthetic credential straight to the store.
async fn save(
    client: &mut LocalCredentialClient,
    provider: &str,
    kind: CredentialAuthKind,
    name: &str,
) -> CredentialRecord {
    client
        .add_credential(
            NewCredential {
                provider: ProviderId::parse(provider).unwrap(),
                authentication_kind: kind,
                display_name: name.into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic-credential-value").unwrap(),
        )
        .await
        .unwrap()
}

/// The owner's case against the real store (#4928): a Claude sign-in named
/// `walk`, then a Codex sign-in under the same name, saved as `connect`
/// saves it; both stay, each with its own ID.
#[tokio::test]
async fn a_claude_sign_in_and_a_codex_sign_in_share_a_name_in_the_store() {
    let (_authority, mut client) = serve(Store::default()).await;
    let claude = save(
        &mut client,
        "anthropic",
        CredentialAuthKind::ClaudeSignIn,
        "walk",
    )
    .await;
    let records = client.list_credentials().await.unwrap();
    let target =
        select_oauth_connection_target(records, "walk", CredentialConnectProviderArg::Codex)
            .unwrap();
    assert!(target.existing.is_none());
    let codex = publish_oauth_connection(
        &mut client,
        target,
        ProtectedValue::from_slice(b"synthetic-codex-sign-in").unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_ne!(codex.metadata.id, claude.metadata.id);
    assert_eq!(codex.metadata.display_name, "walk");
    assert_eq!(client.list_credentials().await.unwrap().len(), 2);
}

/// A bare shared name is refused before anything changes; `PROVIDER/NAME`
/// deletes only the named one; a slot needs no prefix; a rename onto a name
/// its provider has is refused, onto another provider's name is not.
#[tokio::test]
async fn provider_name_acts_on_one_credential_and_a_bare_shared_name_changes_nothing() {
    let (_authority, mut client) = serve(Store::default()).await;
    let anthropic = save(&mut client, "anthropic", CredentialAuthKind::ApiKey, "walk").await;
    let openai = save(&mut client, "openai", CredentialAuthKind::ApiKey, "walk").await;
    let before = client.list_credentials().await.unwrap();

    let refusal = format!(
        "{:#}",
        delete::delete_credential(
            &mut client,
            crate::commands::CredentialDeleteArgs {
                credential: Some("walk".into()),
                yes: true,
            },
        )
        .await
        .unwrap_err()
    );
    assert_eq!(
        refusal,
        "\"walk\" names more than one credential (anthropic, openai); name one, for example anthropic/walk"
    );
    assert_eq!(client.list_credentials().await.unwrap(), before);

    // A profile's openai slot takes the bare name.
    set_profile_entry(
        &mut client,
        crate::commands::CredentialProfileSetArgs {
            profile: "daily".into(),
            slot: Some("openai".into()),
            credential: Some("walk".into()),
        },
    )
    .await
    .unwrap();
    let profile = client.list_profiles().await.unwrap().remove(0);
    assert_eq!(
        profile.profile.entries.values().collect::<Vec<_>>(),
        [&openai.metadata.id]
    );

    // A rename onto anthropic's own name is refused; another provider's
    // credential of that name is no collision.
    let other = save(
        &mut client,
        "anthropic",
        CredentialAuthKind::ApiKey,
        "other",
    )
    .await;
    let refusal = format!(
        "{:#}",
        rename_credential(
            &mut client,
            crate::commands::CredentialRenameArgs {
                credential: "other".into(),
                name: "walk".into(),
            },
        )
        .await
        .unwrap_err()
    );
    assert_eq!(
        refusal,
        "\"walk\" is in use in anthropic by an Anthropic API key; choose another name, for example walk-2"
    );
    rename_credential(
        &mut client,
        crate::commands::CredentialRenameArgs {
            credential: "id:".to_owned() + other.metadata.id.as_str(),
            name: "ssh/x".into(),
        },
    )
    .await
    .unwrap_err();
    let mut renamed = save(&mut client, "openai", CredentialAuthKind::ApiKey, "spare").await;
    rename_credential(
        &mut client,
        crate::commands::CredentialRenameArgs {
            credential: "spare".into(),
            name: "other".into(),
        },
    )
    .await
    .unwrap();
    renamed = client.get_credential(&renamed.metadata.id).await.unwrap();
    assert_eq!(renamed.metadata.display_name, "other");

    // The profile still selects openai's walk, so delete the anthropic one.
    delete::delete_credential(
        &mut client,
        crate::commands::CredentialDeleteArgs {
            credential: Some("anthropic/walk".into()),
            yes: true,
        },
    )
    .await
    .unwrap();
    let left = client.list_credentials().await.unwrap();
    assert!(
        left.iter()
            .all(|record| record.metadata.id != anthropic.metadata.id)
    );
    assert!(
        left.iter()
            .any(|record| record.metadata.id == openai.metadata.id)
    );
    // With one `walk` left, the bare name acts on it.
    assert_eq!(
        resolve_credential(&mut client, "walk", None)
            .await
            .unwrap()
            .metadata
            .id,
        openai.metadata.id
    );
}

/// #6128: a local VM keeps the profile revision it was made with, so after
/// `unset` the profile no longer selects the credential but the VM still
/// does. Each delete the store refuses changes nothing, the credential stays
/// active, and `cw` names what frees it; once the VM is moved to the
/// profile as it is now, the delete revokes and deletes it.
#[tokio::test]
async fn a_delete_a_local_vm_still_holds_changes_nothing() {
    let (_authority, mut client) = serve(Store::default()).await;
    let walk = save(&mut client, "openai", CredentialAuthKind::ApiKey, "walk").await;
    set_profile_entry(
        &mut client,
        crate::commands::CredentialProfileSetArgs {
            profile: "same".into(),
            slot: Some("openai".into()),
            credential: Some("walk".into()),
        },
    )
    .await
    .unwrap();
    let made_with = client.list_profiles().await.unwrap().remove(0).profile;
    let vm = codewire_access::EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
    client
        .create_environment_access_binding(&codewire_access::EnvironmentAccessBinding {
            environment_id: vm.clone(),
            profile_id: made_with.id.clone(),
            profile_revision: made_with.revision,
        })
        .await
        .unwrap();
    let names =
        || async { std::collections::BTreeMap::from([(vm.to_string(), "same-vm".to_owned())]) };
    let args = |credential: &str| crate::commands::CredentialDeleteArgs {
        credential: Some(credential.into()),
        yes: true,
    };
    // Without `--yes` and with no terminal, the question itself would refuse:
    // a holder named instead shows it was read before anyone was asked.
    let unasked = |credential: &str| crate::commands::CredentialDeleteArgs {
        credential: Some(credential.into()),
        yes: false,
    };
    let before = client.list_credentials().await.unwrap();

    // The profile selects it: its unset frees it.
    let refusal = delete::delete_credential_naming_vms(&mut client, unasked("openai/walk"), names)
        .await
        .unwrap_err();
    assert_eq!(
        format!("{refusal:#}"),
        "local credential \"walk\" is selected by profile \"same\"; free it with `cw credentials --local --profile same unset openai`"
    );
    assert_eq!(client.list_credentials().await.unwrap(), before);

    unset_profile_entry(
        &mut client,
        crate::commands::CredentialProfileSlotArgs {
            profile: "same".into(),
            slot: "openai".into(),
        },
    )
    .await
    .unwrap();
    // The VM's revision still selects it: refused before the question.
    let refusal = delete::delete_credential_naming_vms(&mut client, unasked("openai/walk"), names)
        .await
        .unwrap_err();
    assert_eq!(
        format!("{refusal:#}"),
        "local credential \"walk\" is still used by local VM same-vm, made with an earlier version of profile \"same\"; move it to the profile as it is now with `cw update same-vm --profile local:same`, or remove it with `cw rm same-vm`"
    );
    assert_eq!(client.list_credentials().await.unwrap(), before);
    assert_eq!(
        client
            .get_credential(&walk.metadata.id)
            .await
            .unwrap()
            .metadata
            .status,
        codewire_access::CredentialStatus::Active
    );

    // `cw update` moves the VM to the profile as it is now; the delete goes.
    let now = client.list_profiles().await.unwrap().remove(0).profile;
    client
        .replace_environment_access_binding(
            &vm,
            &made_with.id,
            made_with.revision,
            &now.id,
            now.revision,
        )
        .await
        .unwrap();
    delete::delete_credential_naming_vms(&mut client, args("openai/walk"), names)
        .await
        .unwrap();
    assert!(
        client
            .list_credentials()
            .await
            .unwrap()
            .iter()
            .all(|record| record.metadata.id != walk.metadata.id)
    );
}
