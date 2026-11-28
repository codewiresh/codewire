//! Workload secrets' store calls hold no lock a metadata request waits on,
//! and a projection reads one generation of each winner (#5413).

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use codewire_workload_secrets::{
    MAX_PROJECTION_LIFETIME_MS, ProjectionContext, ProjectionRecipient,
};

use super::*;
use crate::test_store::*;

/// Long enough for a call that doesn't wait to have answered. Only ever used
/// to show a call is still waiting, which a slow host makes surer, not less.
const STILL_WAITING: Duration = Duration::from_millis(300);

fn value(value: &str) -> ProtectedValue {
    ProtectedValue::from_slice(value.as_bytes()).unwrap()
}

fn keys(authority: &LocalCredentialAuthority<HeldStore>) -> Vec<String> {
    authority
        .list_user_workload_secrets()
        .unwrap()
        .into_iter()
        .map(|secret| secret.key)
        .collect()
}

/// A credential bound to an environment, so a lease admission can be asked
/// for while a secret's store call is held.
fn leased(
    authority: &LocalCredentialAuthority<HeldStore>,
) -> crate::CredentialOperationLeaseRequest {
    let work = authority.add_credential(codex("work"), material()).unwrap();
    bound_environment(authority, &work.metadata.id)
}

/// What the other requests must answer while a secret's store call is held:
/// the secret list, a metadata resolve, a credential listing and a VM's lease
/// admission. Returns the secret keys listed.
fn metadata_answers(
    authority: &Arc<LocalCredentialAuthority<HeldStore>>,
    lease: &crate::CredentialOperationLeaseRequest,
) -> Vec<String> {
    let authority = Arc::clone(authority);
    let lease = lease.clone();
    within(move || {
        authority
            .resolve_workload_secret_metadata(&WorkloadSecretSelection {
                user: true,
                ..Default::default()
            })
            .unwrap();
        authority.list_credentials().unwrap();
        authority
            .admit_environment_credential_operation(&lease)
            .unwrap();
        keys(&authority)
    })
}

fn spawned<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> Receiver<T> {
    let (answer, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer.send(call());
    });
    answered
}

fn launch() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 1,
        selection_sha256: [2; 32],
        deadline_unix_ms: unix_millis().unwrap() + MAX_PROJECTION_LIFETIME_MS,
    }
}

/// The user secrets a launch is given, opened by its recipient.
fn project_user_secrets(
    authority: &LocalCredentialAuthority<HeldStore>,
) -> Result<Vec<(String, String)>, LocalCredentialError> {
    let recipient = ProjectionRecipient::new();
    let context = launch();
    let sealed = authority.seal_workload_projection(
        &LocalLaunchSecretSelection {
            user: true,
            ..Default::default()
        },
        Some(&[]),
        &context,
        recipient.public_key(),
    )?;
    Ok(recipient
        .open(&sealed, &context, unix_millis().unwrap())
        .unwrap()
        .entries()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

/// A first set waiting on the store leaves every metadata request free, and
/// its key is listed only once it is ready.
#[test]
fn a_first_set_waiting_on_the_store_blocks_no_metadata_request() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    store.hold_next(Call::Put);
    let set = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.set_user_workload_secret("APP_TOKEN", value("one")))
    };
    store.wait_for_held();

    assert!(metadata_answers(&authority, &lease).is_empty());
    assert!(store.is_held());
    store.release();
    set.recv_timeout(PROMPT).unwrap().unwrap();
    assert_eq!(keys(&authority), ["APP_TOKEN"]);
}

/// A rotation waiting on the store leaves the key listed at its current
/// generation, and a rename meanwhile is kept by the rotation.
#[test]
fn a_rename_during_a_rotations_store_write_is_kept() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    authority
        .set_user_workload_secret("APP_TOKEN", value("one"))
        .unwrap();
    store.hold_next(Call::Put);
    let rotation = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.set_user_workload_secret("APP_TOKEN", value("two")))
    };
    store.wait_for_held();

    assert_eq!(metadata_answers(&authority, &lease), ["APP_TOKEN"]);
    {
        let authority = Arc::clone(&authority);
        within(move || {
            authority
                .rename_user_workload_secret("APP_TOKEN", "RENAMED")
                .unwrap()
        });
    }
    assert!(store.is_held());
    store.release();
    assert_eq!(
        rotation.recv_timeout(PROMPT).unwrap().unwrap().key,
        "RENAMED"
    );
    assert_eq!(keys(&authority), ["RENAMED"]);
    assert_eq!(
        project_user_secrets(&authority).unwrap(),
        [("RENAMED".to_owned(), "two".to_owned())]
    );
}

/// A rotation's retired-entry delete waiting on the store blocks no metadata
/// request.
#[test]
fn a_rotations_retired_delete_waiting_on_the_store_blocks_no_metadata_request() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    authority
        .set_user_workload_secret("APP_TOKEN", value("one"))
        .unwrap();
    store.hold_next(Call::Delete);
    let rotation = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.set_user_workload_secret("APP_TOKEN", value("two")))
    };
    store.wait_for_held();

    assert_eq!(metadata_answers(&authority, &lease), ["APP_TOKEN"]);
    assert!(store.is_held());
    store.release();
    rotation.recv_timeout(PROMPT).unwrap().unwrap();
}

/// A delete waiting on the store hides its key at once, and a rename of it
/// is refused as not found, never as corrupt.
#[test]
fn a_delete_waiting_on_the_store_hides_its_key_and_refuses_a_rename() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    authority
        .set_user_workload_secret("APP_TOKEN", value("one"))
        .unwrap();
    store.hold_next(Call::Delete);
    let delete = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.delete_user_workload_secret("APP_TOKEN"))
    };
    store.wait_for_held();

    assert!(metadata_answers(&authority, &lease).is_empty());
    let renamed = {
        let authority = Arc::clone(&authority);
        within(move || authority.rename_user_workload_secret("APP_TOKEN", "RENAMED"))
    };
    assert_eq!(
        renamed.unwrap_err(),
        LocalCredentialError::WorkloadSecretNotFound
    );
    assert!(store.is_held());
    store.release();
    delete.recv_timeout(PROMPT).unwrap().unwrap();
    assert!(keys(&authority).is_empty());
}

/// A project delete waiting on the store blocks no metadata request.
#[test]
fn a_project_delete_waiting_on_the_store_blocks_no_metadata_request() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    let project = authority.create_secret_project("development").unwrap();
    authority
        .set_project_workload_secret(project.id, "DATABASE_URL", value("one"))
        .unwrap();
    store.hold_next(Call::Delete);
    let delete = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.delete_secret_project(project.id))
    };
    store.wait_for_held();

    metadata_answers(&authority, &lease);
    {
        let authority = Arc::clone(&authority);
        within(move || authority.list_secret_projects().unwrap());
    }
    assert!(store.is_held());
    store.release();
    delete.recv_timeout(PROMPT).unwrap().unwrap();
    assert!(authority.list_secret_projects().unwrap().is_empty());
}

/// A projection waits for a rotation still retiring its old entry, then
/// seals the new generation: it never reads one being retired.
#[test]
fn a_projection_waits_for_a_rotation_and_seals_its_new_generation() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    authority
        .set_user_workload_secret("APP_TOKEN", value("one"))
        .unwrap();
    store.hold_next(Call::Delete);
    let rotation = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.set_user_workload_secret("APP_TOKEN", value("two")))
    };
    store.wait_for_held();
    let projection = {
        let authority = Arc::clone(&authority);
        spawned(move || project_user_secrets(&authority))
    };

    assert!(projection.recv_timeout(STILL_WAITING).is_err());
    assert!(store.is_held());
    store.release();
    rotation.recv_timeout(PROMPT).unwrap().unwrap();
    assert_eq!(
        projection.recv_timeout(PROMPT).unwrap().unwrap(),
        [("APP_TOKEN".to_owned(), "two".to_owned())]
    );
}

/// A projection waiting on the store holds a rotation back until it has
/// sealed, and blocks no metadata request.
#[test]
fn a_projection_waiting_on_the_store_holds_back_a_rotation_only() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let lease = leased(&authority);
    authority
        .set_user_workload_secret("APP_TOKEN", value("one"))
        .unwrap();
    store.hold_next(Call::Get);
    let projection = {
        let authority = Arc::clone(&authority);
        spawned(move || project_user_secrets(&authority))
    };
    store.wait_for_held();
    let rotation = {
        let authority = Arc::clone(&authority);
        spawned(move || authority.set_user_workload_secret("APP_TOKEN", value("two")))
    };

    assert_eq!(metadata_answers(&authority, &lease), ["APP_TOKEN"]);
    assert!(rotation.recv_timeout(STILL_WAITING).is_err());
    assert!(store.is_held());
    store.release();
    assert_eq!(
        projection.recv_timeout(PROMPT).unwrap().unwrap(),
        [("APP_TOKEN".to_owned(), "one".to_owned())]
    );
    rotation.recv_timeout(PROMPT).unwrap().unwrap();
}
