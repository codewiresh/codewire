//! A bound secret's grants and leases in the credential service (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap" steps 1 and 2): the
//! epoch's grants are the Pod's first-bind record for the selection's
//! sources, and each lease rereads the row, refusing by name a secret whose
//! binding changed, that was made plain or deleted, or that no longer names
//! the host, and reads a new value at once. Every value here is synthetic.

use super::*;

use codewire_credential_broker::bound_secret::BoundSecretLeaseError;

const HOST: &str = "api.fancy.example";

/// The user's `FANCY_TOKEN`, bound and recorded at the Pod's first bind, on
/// an admitted epoch whose selection holds the user's secrets.
async fn leased(
    f: &Fixture,
) -> Result<(
    Arc<crate::KubernetesPlatformRuntimeAuthority>,
    codewire_access::FirstBindSecret,
)> {
    grant_projection(f).await?;
    sources(f, json!({"user":"platform"}), json!({}), false).await?;
    let user = format!("/users/{}", f.scope.creator);
    put(f, &user, "FANCY_TOKEN", CANARY).await?;
    let binding_id = bind(&f.db.pool, &user, "FANCY_TOKEN", 1).await?;
    record_first_bind(f, Some(json!([recorded(&user, "FANCY_TOKEN", binding_id)]))).await?;
    let authority = admitted(f, Arc::new(ObservedProvider::default())).await?;
    let grants = authority.bound_secret_grants().await?;
    ensure!(grants.len() == 1, "one grant from the record: {grants:?}");
    Ok((authority, grants[0].clone()))
}

/// A lease that passes reads the value and its version; a new value is
/// read at the next lease, with its new version.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn a_bound_secrets_lease_reads_its_value_and_a_new_value_at_once() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (authority, secret) = leased(&f).await?;
        let row = authority.bound_secret_row(&secret, HOST).await;
        ensure!(row.is_ok(), "the row passes: {:?}", row.err());
        let (version, value) = authority.bound_secret_value(&secret, HOST).await?;
        ensure!(value.as_slice() == CANARY);
        let user = format!("/users/{}", f.scope.creator);
        put(&f, &user, "FANCY_TOKEN", b"canary-bound-second-value").await?;
        sqlx::query(
            "UPDATE tenant_secrets SET value_version=value_version+1 WHERE path=$1 AND key=$2",
        )
        .bind(&user)
        .bind("FANCY_TOKEN")
        .execute(&f.db.pool)
        .await?;
        let (next, value) = authority.bound_secret_value(&secret, HOST).await?;
        ensure!(
            next == version + 1,
            "the version moved: {version} -> {next}"
        );
        ensure!(value.as_slice() == b"canary-bound-second-value");
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Each change since the first bind refuses the next lease by name, before
/// any value is read.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn a_bound_secrets_lease_refuses_each_change_by_name() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (authority, secret) = leased(&f).await?;
        let user = format!("/users/{}", f.scope.creator);
        let refused = |result: std::result::Result<_, BoundSecretLeaseError>| result.err();

        ensure!(
            refused(
                authority
                    .bound_secret_value(&secret, "other.fancy.example")
                    .await
            ) == Some(BoundSecretLeaseError::NotBoundToHost),
            "a host the record never named"
        );
        sqlx::query(
            "UPDATE tenant_secrets SET binding_generation=binding_generation+1 \
             WHERE path=$1 AND key='FANCY_TOKEN'",
        )
        .bind(&user)
        .execute(&f.db.pool)
        .await?;
        ensure!(
            refused(authority.bound_secret_value(&secret, HOST).await)
                == Some(BoundSecretLeaseError::BindingChanged),
            "a new generation"
        );
        sqlx::query(
            "UPDATE tenant_secrets SET binding=NULL,binding_generation=binding_generation+1 \
             WHERE path=$1 AND key='FANCY_TOKEN'",
        )
        .bind(&user)
        .execute(&f.db.pool)
        .await?;
        ensure!(
            refused(authority.bound_secret_value(&secret, HOST).await)
                == Some(BoundSecretLeaseError::BindingChanged),
            "made plain"
        );
        sqlx::query("DELETE FROM tenant_secrets WHERE path=$1 AND key='FANCY_TOKEN'")
            .bind(&user)
            .execute(&f.db.pool)
            .await?;
        ensure!(
            refused(authority.bound_secret_value(&secret, HOST).await)
                == Some(BoundSecretLeaseError::Deleted),
            "deleted"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// A host removed from the binding is refused at the next lease, though the
/// record still names it.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn a_host_removed_from_the_binding_is_refused_at_the_next_lease() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (authority, secret) = leased(&f).await?;
        let user = format!("/users/{}", f.scope.creator);
        sqlx::query(
            "UPDATE tenant_secrets SET binding=jsonb_set(binding,'{hosts}','[\"other.fancy.example\"]') \
             WHERE path=$1 AND key='FANCY_TOKEN'",
        )
        .bind(&user)
        .execute(&f.db.pool)
        .await?;
        ensure!(
            authority.bound_secret_value(&secret, HOST).await.err()
                == Some(BoundSecretLeaseError::NotBoundToHost)
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}
