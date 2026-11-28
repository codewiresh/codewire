//! A local secret's binding follows the platform store's rules
//! (docs/dev/SECRETS-AND-CREDENTIALS.md, "Re-entering the value" and "The
//! record"), and nothing binds while host-bound secrets are off.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use codewire_access::{BindingError, StoredPresentation, builtin_provider_catalog};
use codewire_protected_store::EphemeralProtectedStore;
use rusqlite::{Connection, OptionalExtension as _};
use tempfile::TempDir;

use super::*;
use crate::{DATABASE_FILE, WorkloadSecretMetadata};

const ON: bool = true;

struct Store {
    _temp: TempDir,
    root: std::path::PathBuf,
    authority: LocalCredentialAuthority<EphemeralProtectedStore>,
}

impl Store {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("authority");
        let authority = LocalCredentialAuthority::open(
            &root,
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            authority,
        }
    }

    fn write(
        &self,
        key: &str,
        value: Option<&str>,
        binding: BindingWrite,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        self.authority
            .write_user_workload_secret(key, value.map(protected), binding, ON)
    }

    fn listed(&self, key: &str) -> Option<WorkloadSecretMetadata> {
        self.authority
            .list_user_workload_secrets()
            .unwrap()
            .into_iter()
            .find(|secret| secret.key == key)
    }

    /// The row's `binding_id` and value version, which no metadata carries.
    fn record(&self, key: &str) -> Option<(Option<String>, i64)> {
        Connection::open(self.root.join(DATABASE_FILE))
            .unwrap()
            .query_row(
                "SELECT binding_id, material_generation FROM workload_secrets WHERE key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .unwrap()
    }
}

fn protected(value: &str) -> ProtectedValue {
    ProtectedValue::from_slice(value.as_bytes()).unwrap()
}

fn bearer() -> StoredPresentation {
    StoredPresentation::Header {
        headers: vec!["Authorization".into()],
        scheme: Some("Bearer".into()),
    }
}

fn binding(
    hosts: &[&str],
    presentation: StoredPresentation,
    prefix: Option<&str>,
) -> StoredBinding {
    StoredBinding {
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        presentation,
        prefix: prefix.map(str::to_owned),
        preset: None,
    }
}

fn bind(hosts: &[&str]) -> BindingWrite {
    BindingWrite::Bind(binding(hosts, bearer(), None))
}

fn assert_value_required(
    result: Result<WorkloadSecretMetadata, LocalCredentialError>,
    change: &str,
) {
    match result {
        Err(LocalCredentialError::SecretValueRequired(words)) => assert_eq!(words, change),
        other => panic!("expected the value to be required for {change}, got {other:?}"),
    }
}

#[test]
fn a_plain_secret_is_written_as_before() {
    let store = Store::new();
    let set = store
        .write("PLAIN", Some("synthetic-one"), BindingWrite::Keep)
        .unwrap();
    assert_eq!((set.binding.clone(), set.binding_generation), (None, 0));
    assert_eq!(store.record("PLAIN"), Some((None, 1)));
    store
        .write("PLAIN", Some("synthetic-two"), BindingWrite::Keep)
        .unwrap();
    assert_eq!(store.record("PLAIN"), Some((None, 2)));
    // An empty value for a plain secret is refused as it always was.
    assert_eq!(
        store.write("PLAIN", None, BindingWrite::Keep),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        store.write("NEW", None, BindingWrite::Plain),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(store.record("NEW"), None);
}

#[test]
fn while_host_bound_secrets_are_off_a_bind_is_refused_and_plain_writes_work() {
    let store = Store::new();
    let off = |key, value: Option<&str>, write| {
        store
            .authority
            .write_user_workload_secret(key, value.map(protected), write, false)
    };
    assert_eq!(
        off("KEY", Some("synthetic"), bind(&["api.example.com"])),
        Err(LocalCredentialError::HostBoundSecretsUnavailable)
    );
    assert_eq!(store.record("KEY"), None);
    let plain = off("KEY", Some("synthetic"), BindingWrite::Keep).unwrap();
    assert_eq!(plain.binding, None);
    off("KEY", Some("synthetic-two"), BindingWrite::Plain).unwrap();
    assert_eq!(
        off("KEY", Some("synthetic-three"), bind(&["api.example.com"])),
        Err(LocalCredentialError::HostBoundSecretsUnavailable)
    );
    assert_eq!(store.listed("KEY").unwrap().binding, None);
    // The set every existing caller makes is unchanged.
    store
        .authority
        .set_user_workload_secret("KEY", protected("synthetic-four"))
        .unwrap();
    assert_eq!(store.record("KEY"), Some((None, 3)));
}

#[test]
fn binding_a_secret_needs_its_value() {
    let store = Store::new();
    store
        .write("KEY", Some("synthetic"), BindingWrite::Keep)
        .unwrap();
    assert_value_required(
        store.write("KEY", None, bind(&["api.example.com"])),
        "binding a secret to hosts",
    );
    assert_value_required(
        store.write("NEW", None, bind(&["api.example.com"])),
        "binding a secret to hosts",
    );
    assert_eq!(store.listed("KEY").unwrap().binding, None);
    let bound = store
        .write("KEY", Some("synthetic"), bind(&["api.example.com"]))
        .unwrap();
    assert_eq!(
        bound.binding,
        Some(binding(&["api.example.com"], bearer(), None))
    );
    assert_eq!(bound.binding_generation, 1);
    assert_eq!(store.listed("KEY").unwrap(), bound);
}

#[test]
fn removing_a_host_or_changing_the_prefix_needs_no_value() {
    let store = Store::new();
    let hosts = ["api.a.example", "api.b.example"];
    store.write("KEY", Some("synthetic"), bind(&hosts)).unwrap();
    let (id, version) = store.record("KEY").unwrap();
    let removed = store.write("KEY", None, bind(&["api.a.example"])).unwrap();
    assert_eq!(removed.binding.unwrap().hosts, ["api.a.example"]);
    // Hosts don't move the generation.
    assert_eq!(removed.binding_generation, 1);
    let prefixed = store
        .write(
            "KEY",
            None,
            BindingWrite::Bind(binding(&["api.a.example"], bearer(), Some("sk_"))),
        )
        .unwrap();
    assert_eq!(prefixed.binding.unwrap().prefix.as_deref(), Some("sk_"));
    assert_eq!(prefixed.binding_generation, 2);
    // The value was never touched, and the binding kept its id.
    assert_eq!(store.record("KEY"), Some((id, version)));
}

#[test]
fn changes_that_could_send_the_value_elsewhere_need_it_again() {
    let store = Store::new();
    store
        .write("KEY", Some("synthetic"), bind(&["api.a.example"]))
        .unwrap();
    assert_value_required(
        store.write("KEY", None, bind(&["api.a.example", "api.b.example"])),
        "adding a host",
    );
    assert_value_required(
        store.write("KEY", None, bind(&["api.b.example"])),
        "adding a host",
    );
    assert_value_required(
        store.write(
            "KEY",
            None,
            BindingWrite::Bind(binding(
                &["api.a.example"],
                StoredPresentation::Header {
                    headers: vec!["X-Api-Key".into()],
                    scheme: None,
                },
                None,
            )),
        ),
        "changing how a secret is sent",
    );
    assert_value_required(
        store.write("KEY", None, BindingWrite::Plain),
        "making a secret plain",
    );
    assert_eq!(
        store.listed("KEY").unwrap().binding,
        Some(binding(&["api.a.example"], bearer(), None))
    );
    // With the value, each is made.
    let added = store
        .write(
            "KEY",
            Some("synthetic"),
            bind(&["api.a.example", "api.b.example"]),
        )
        .unwrap();
    assert_eq!(added.binding_generation, 1);
    let plain = store
        .write("KEY", Some("synthetic"), BindingWrite::Plain)
        .unwrap();
    assert_eq!((plain.binding, plain.binding_generation), (None, 2));
}

#[test]
fn a_new_value_keeps_the_binding_and_its_preset() {
    let store = Store::new();
    let mut stored = binding(&["api.stripe.com"], bearer(), None);
    stored.preset = Some("stripe".into());
    store
        .write("KEY", Some("synthetic"), BindingWrite::Bind(stored.clone()))
        .unwrap();
    let kept = store
        .write("KEY", Some("synthetic-two"), BindingWrite::Keep)
        .unwrap();
    assert_eq!(kept.binding, Some(stored));
    assert_eq!(kept.binding_generation, 1);
    assert_eq!(store.record("KEY").unwrap().1, 2);
}

#[test]
fn a_binding_keeps_its_id_until_the_secret_is_deleted() {
    let store = Store::new();
    store
        .write("KEY", Some("synthetic"), bind(&["api.example.com"]))
        .unwrap();
    let (first, _) = store.record("KEY").unwrap();
    assert!(first.is_some());
    store
        .write("KEY", Some("synthetic"), BindingWrite::Plain)
        .unwrap();
    assert_eq!(store.record("KEY").unwrap().0, first);
    store
        .write("KEY", Some("synthetic"), bind(&["api.example.com"]))
        .unwrap();
    assert_eq!(store.record("KEY").unwrap().0, first);
    store.authority.delete_user_workload_secret("KEY").unwrap();
    let recreated = store
        .write("KEY", Some("synthetic"), bind(&["api.example.com"]))
        .unwrap();
    let (second, _) = store.record("KEY").unwrap();
    assert!(second.is_some());
    assert_ne!(second, first);
    assert_eq!(recreated.binding_generation, 1);
}

#[test]
fn provider_hosts_and_unfit_values_are_refused_and_change_nothing() {
    let store = Store::new();
    assert_eq!(
        store.write("KEY", Some("synthetic"), bind(&["api.anthropic.com"])),
        Err(LocalCredentialError::SecretBinding(
            BindingError::ProviderHost("api.anthropic.com".into())
        ))
    );
    assert_eq!(
        store.write("KEY", Some("synthetic"), bind(&["*.example.com"])),
        Err(LocalCredentialError::SecretBinding(BindingError::Wildcard(
            "*.example.com".into()
        )))
    );
    // A local store has no deployment, so no name of one is reserved.
    store
        .write(
            "REGISTRY",
            Some("synthetic"),
            bind(&["registry.example.com"]),
        )
        .unwrap();
    assert_eq!(
        store.write("KEY", Some("synthetic\tvalue"), bind(&["api.example.com"])),
        Err(LocalCredentialError::SecretBinding(
            BindingError::InvalidValue
        ))
    );
    assert_eq!(
        store.write(
            "KEY",
            Some("synthetic:value"),
            BindingWrite::Bind(binding(
                &["api.example.com"],
                StoredPresentation::BasicUser,
                None
            )),
        ),
        Err(LocalCredentialError::SecretBinding(
            BindingError::BasicUserColon
        ))
    );
    assert_eq!(store.record("KEY"), None);
}

#[test]
fn a_bound_secret_is_never_renamed() {
    let store = Store::new();
    store
        .write("KEY", Some("synthetic"), bind(&["api.example.com"]))
        .unwrap();
    assert_eq!(
        store.authority.rename_user_workload_secret("KEY", "OTHER"),
        Err(LocalCredentialError::BoundSecretRename)
    );
    assert!(store.listed("KEY").is_some());
    store
        .write("KEY", Some("synthetic"), BindingWrite::Plain)
        .unwrap();
    store
        .authority
        .rename_user_workload_secret("KEY", "OTHER")
        .unwrap();
}

#[test]
fn a_project_secret_follows_the_same_rules() {
    let store = Store::new();
    let project = store.authority.create_secret_project("walk").unwrap();
    let write = |value: Option<&str>, binding| {
        store.authority.write_project_workload_secret(
            project.id,
            "KEY",
            value.map(protected),
            binding,
            ON,
        )
    };
    assert_value_required(
        write(None, bind(&["api.example.com"])),
        "binding a secret to hosts",
    );
    let bound = write(Some("synthetic"), bind(&["api.a.example", "api.b.example"])).unwrap();
    assert_eq!(bound.binding_generation, 1);
    let removed = write(None, bind(&["api.b.example"])).unwrap();
    assert_eq!(removed.binding.unwrap().hosts, ["api.b.example"]);
    assert_eq!(
        store
            .authority
            .list_project_workload_secrets(project.id)
            .unwrap()[0]
            .binding_generation,
        1
    );
    assert_eq!(
        store
            .authority
            .rename_project_workload_secret(project.id, "KEY", "OTHER"),
        Err(LocalCredentialError::BoundSecretRename)
    );
}
