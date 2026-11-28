//! The store writes a secret with its binding as
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound application secrets",
//! says: which changes need the value again, what each change does to the
//! binding's ID and generation and to the value's version, which hosts are
//! refused, and that a bound secret is never renamed. Each test owns one
//! personal path, so the tests share one migrated schema.

use std::sync::Arc;

use codewire_access::{BindingError, ReservedHosts, StoredBinding, StoredPresentation};
use codewire_protected_store::secret_envelope::TestKekProvider;
use sqlx::PgPool;
use sqlx::types::Json;
use uuid::Uuid;

use super::super::PostgresSecretStore;
use super::{BindingWrite, BoundSecretRename, SecretWriteError};

const FIRST_VALUE: &str = "synthetic-bound-value-1";
const SECOND_VALUE: &str = "synthetic-bound-value-2";

#[derive(sqlx::FromRow)]
struct StoredRow {
    binding: Option<Json<StoredBinding>>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
    value_version: i64,
}

/// A row's binding columns, in a form a test compares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    binding: Option<StoredBinding>,
    binding_id: Option<Uuid>,
    generation: i64,
    value_version: i64,
}

struct Fixture {
    pool: PgPool,
    store: PostgresSecretStore,
    path: String,
    reserved: ReservedHosts,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("secret binding store tests require the disposable TEST_DATABASE_URL");
        codewire_server_core::migrate::ensure_schema(&url)
            .await
            .unwrap();
        let pool = PgPool::connect(&url).await.unwrap();
        let store = PostgresSecretStore::new(pool.clone(), Arc::new(TestKekProvider));
        Self {
            pool,
            store,
            path: format!("/users/binding-{}", Uuid::new_v4().simple()),
            reserved: ReservedHosts::new(["openbao.sandbox.example.dev", "*.preview.example.dev"])
                .unwrap(),
        }
    }

    async fn write(
        &self,
        key: &str,
        value: Option<&str>,
        binding: BindingWrite,
    ) -> Result<(), SecretWriteError> {
        self.store
            .write_secret_at_path(&self.path, key, value, binding, &self.reserved)
            .await
    }

    async fn record(&self, key: &str) -> Option<Record> {
        let row: Option<StoredRow> = sqlx::query_as(
            "SELECT binding, binding_id, binding_generation, value_version \
             FROM tenant_secrets WHERE path = $1 AND key = $2",
        )
        .bind(&self.path)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .unwrap();
        row.map(|row| Record {
            binding: row.binding.map(|Json(binding)| binding),
            binding_id: row.binding_id,
            generation: row.binding_generation,
            value_version: row.value_version,
        })
    }

    async fn value(&self, key: &str) -> Option<String> {
        self.store
            .get_secrets_raw_at_path(&self.path)
            .await
            .unwrap()
            .into_iter()
            .find(|secret| secret.key == key)
            .map(|secret| secret.value.clone())
    }

    async fn cleanup(self) {
        self.store.delete_path(&self.path).await.unwrap();
        self.pool.close().await;
    }
}

fn bearer() -> StoredPresentation {
    StoredPresentation::Header {
        headers: vec!["Authorization".into()],
        scheme: Some("Bearer".into()),
    }
}

/// A binding as the store keeps it: hosts in order, a header binding's
/// scheme named.
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

fn assert_value_required(result: Result<(), SecretWriteError>, change: &str) {
    match result {
        Err(SecretWriteError::ValueRequired(words)) => assert_eq!(words, change),
        other => panic!("{change}: expected the value to be required, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_a_plain_secret_is_written_as_before() {
    let fixture = Fixture::new().await;
    fixture
        .store
        .set_secret_at_path(&fixture.path, "PLAIN", FIRST_VALUE)
        .await
        .unwrap();
    let plain = Record {
        binding: None,
        binding_id: None,
        generation: 0,
        value_version: 1,
    };
    assert_eq!(fixture.record("PLAIN").await, Some(plain.clone()));
    fixture
        .write("PLAIN", Some(SECOND_VALUE), BindingWrite::Keep)
        .await
        .unwrap();
    assert_eq!(
        fixture.record("PLAIN").await,
        Some(Record {
            value_version: 2,
            ..plain
        }),
        "a new value moves only the value's version"
    );
    assert_eq!(fixture.value("PLAIN").await.as_deref(), Some(SECOND_VALUE));
    let metadata = fixture
        .store
        .get_secret_metadata_at_path(&fixture.path)
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(
        (metadata[0].binding.as_ref(), metadata[0].binding_generation),
        (None, 0)
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_binding_a_secret_needs_its_value_and_an_empty_one_stays_refused() {
    let fixture = Fixture::new().await;
    assert_value_required(
        fixture.write("NEW", None, bind(&["api.fancy.com"])).await,
        "binding a secret to hosts",
    );
    assert_eq!(fixture.record("NEW").await, None, "nothing was written");

    fixture
        .write("PLAIN", Some(FIRST_VALUE), BindingWrite::Keep)
        .await
        .unwrap();
    let before = fixture.record("PLAIN").await;
    assert_value_required(
        fixture.write("PLAIN", None, bind(&["api.fancy.com"])).await,
        "binding a secret to hosts",
    );
    for write in [BindingWrite::Keep, BindingWrite::Plain] {
        assert!(matches!(
            fixture.write("PLAIN", None, write).await,
            Err(SecretWriteError::EmptyValue)
        ));
    }
    assert_eq!(fixture.record("PLAIN").await, before, "nothing changed");
    assert_eq!(fixture.value("PLAIN").await.as_deref(), Some(FIRST_VALUE));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_removing_a_host_or_changing_the_prefix_needs_no_value() {
    let fixture = Fixture::new().await;
    fixture
        .write(
            "TOKEN",
            Some(FIRST_VALUE),
            bind(&["api.fancy.com", "uploads.fancy.com"]),
        )
        .await
        .unwrap();
    let bound = fixture.record("TOKEN").await.unwrap();
    assert_eq!(
        bound.binding,
        Some(binding(
            &["api.fancy.com", "uploads.fancy.com"],
            bearer(),
            None
        ))
    );
    assert!(bound.binding_id.is_some());
    assert_eq!((bound.generation, bound.value_version), (1, 1));

    fixture
        .write("TOKEN", None, bind(&["api.fancy.com"]))
        .await
        .unwrap();
    let removed = fixture.record("TOKEN").await.unwrap();
    assert_eq!(
        removed,
        Record {
            binding: Some(binding(&["api.fancy.com"], bearer(), None)),
            ..bound.clone()
        },
        "removing a host moves neither the generation nor the value's version"
    );

    fixture
        .write(
            "TOKEN",
            None,
            BindingWrite::Bind(binding(&["api.fancy.com"], bearer(), Some("sk_"))),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.record("TOKEN").await,
        Some(Record {
            binding: Some(binding(&["api.fancy.com"], bearer(), Some("sk_"))),
            generation: 2,
            ..bound
        }),
        "a new prefix moves the generation only"
    );
    assert_eq!(fixture.value("TOKEN").await.as_deref(), Some(FIRST_VALUE));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_changes_that_could_send_the_value_elsewhere_need_it_again() {
    let fixture = Fixture::new().await;
    fixture
        .write(
            "TOKEN",
            Some(FIRST_VALUE),
            bind(&["api.fancy.com", "uploads.fancy.com"]),
        )
        .await
        .unwrap();
    let bound = fixture.record("TOKEN").await;
    let api_key = StoredPresentation::Header {
        headers: vec!["X-Api-Key".into()],
        scheme: None,
    };
    let refused = [
        (
            bind(&["api.fancy.com", "evil.example.com", "uploads.fancy.com"]),
            "adding a host",
        ),
        (
            bind(&["api.fancy.com", "evil.example.com"]),
            "adding a host",
        ),
        (
            BindingWrite::Bind(binding(&["api.fancy.com"], api_key, None)),
            "changing how a secret is sent",
        ),
        (
            BindingWrite::Bind(binding(
                &["api.fancy.com"],
                StoredPresentation::BasicUser,
                None,
            )),
            "changing how a secret is sent",
        ),
        (BindingWrite::Plain, "making a secret plain"),
    ];
    for (write, change) in refused {
        assert_value_required(fixture.write("TOKEN", None, write).await, change);
        assert_eq!(fixture.record("TOKEN").await, bound, "{change}: changed");
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_a_binding_keeps_its_id_until_the_secret_is_deleted() {
    let fixture = Fixture::new().await;
    let hosts = ["api.fancy.com"];
    fixture
        .write("TOKEN", Some(FIRST_VALUE), bind(&hosts))
        .await
        .unwrap();
    let first = fixture.record("TOKEN").await.unwrap();
    let id = first.binding_id.unwrap();
    assert_eq!((first.generation, first.value_version), (1, 1));

    fixture
        .write("TOKEN", Some(SECOND_VALUE), BindingWrite::Keep)
        .await
        .unwrap();
    assert_eq!(
        fixture.record("TOKEN").await,
        Some(Record {
            value_version: 2,
            ..first.clone()
        }),
        "a new value keeps the binding and moves the value's version"
    );
    assert_eq!(fixture.value("TOKEN").await.as_deref(), Some(SECOND_VALUE));

    fixture
        .write("TOKEN", Some(FIRST_VALUE), BindingWrite::Plain)
        .await
        .unwrap();
    assert_eq!(
        fixture.record("TOKEN").await,
        Some(Record {
            binding: None,
            binding_id: Some(id),
            generation: 2,
            value_version: 3,
        }),
        "making it plain keeps the ID and moves the generation"
    );

    fixture
        .write("TOKEN", Some(SECOND_VALUE), bind(&hosts))
        .await
        .unwrap();
    assert_eq!(
        fixture.record("TOKEN").await,
        Some(Record {
            binding: Some(binding(&hosts, bearer(), None)),
            binding_id: Some(id),
            generation: 3,
            value_version: 4,
        }),
        "binding it again keeps the ID and moves the generation"
    );

    assert!(
        fixture
            .store
            .delete_secret_at_path(&fixture.path, "TOKEN")
            .await
            .unwrap()
    );
    fixture
        .write("TOKEN", Some(FIRST_VALUE), bind(&hosts))
        .await
        .unwrap();
    let recreated = fixture.record("TOKEN").await.unwrap();
    assert_ne!(
        recreated.binding_id,
        Some(id),
        "a re-created secret has a new ID"
    );
    assert_eq!((recreated.generation, recreated.value_version), (1, 1));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_provider_and_deployment_hosts_and_unfit_values_are_refused() {
    let fixture = Fixture::new().await;
    let refused = [
        (
            bind(&["api.github.com"]),
            FIRST_VALUE,
            BindingError::ProviderHost("api.github.com".into()),
        ),
        (
            bind(&["openbao.sandbox.example.dev"]),
            FIRST_VALUE,
            BindingError::DeploymentHost("openbao.sandbox.example.dev".into()),
        ),
        (
            bind(&["app.preview.example.dev"]),
            FIRST_VALUE,
            BindingError::DeploymentHost("app.preview.example.dev".into()),
        ),
        (
            bind(&["api.fancy.com"]),
            "synthetic\tvalue",
            BindingError::InvalidValue,
        ),
        (
            BindingWrite::Bind(binding(
                &["api.fancy.com"],
                StoredPresentation::BasicUser,
                None,
            )),
            "synthetic:value",
            BindingError::BasicUserColon,
        ),
    ];
    for (write, value, expected) in refused {
        match fixture.write("TOKEN", Some(value), write).await {
            Err(SecretWriteError::Binding(error)) => assert_eq!(error, expected),
            other => panic!("{expected}: got {other:?}"),
        }
        assert_eq!(fixture.record("TOKEN").await, None, "{expected}: written");
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_a_bound_secret_is_never_renamed_and_its_metadata_names_the_binding() {
    let fixture = Fixture::new().await;
    let stored = StoredBinding {
        preset: Some("fancy".into()),
        ..binding(
            &["api.fancy.com"],
            StoredPresentation::Basic {
                username: "x-access-token".into(),
            },
            Some("sk_"),
        )
    };
    fixture
        .write(
            "TOKEN",
            Some(FIRST_VALUE),
            BindingWrite::Bind(stored.clone()),
        )
        .await
        .unwrap();
    let before = fixture.record("TOKEN").await;
    let error = fixture
        .store
        .rename_secret_at_path(&fixture.path, "TOKEN", "RENAMED")
        .await
        .unwrap_err();
    assert!(
        error.downcast_ref::<BoundSecretRename>().is_some(),
        "{error}"
    );
    assert_eq!(fixture.record("TOKEN").await, before, "the secret moved");
    assert_eq!(fixture.record("RENAMED").await, None);

    let metadata = fixture
        .store
        .get_secret_metadata_at_path(&fixture.path)
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].binding.as_ref(), Some(&stored));
    assert_eq!(metadata[0].binding_generation, 1);

    fixture
        .write("PLAIN", Some(SECOND_VALUE), BindingWrite::Keep)
        .await
        .unwrap();
    fixture
        .store
        .rename_secret_at_path(&fixture.path, "PLAIN", "PLAIN_RENAMED")
        .await
        .unwrap();
    assert_eq!(
        fixture.value("PLAIN_RENAMED").await.as_deref(),
        Some(SECOND_VALUE),
        "a plain secret still renames"
    );
    fixture.cleanup().await;
}
