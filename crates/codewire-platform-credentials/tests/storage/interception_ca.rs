//! Hosted interception CAs (#5030) on synthetic PostgreSQL, as the restricted
//! broker role: one CA per Pod, created once, attached to its environment by
//! the bind, gone with the Pod, sealed to its Pod UID, and never deleted or
//! changed by the broker (cw-security's rulings on #4001).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Result, ensure};
use codewire_access::builtin_provider_catalog;
use codewire_platform_credentials::{
    InterceptedPod, MAX_LEAF_LIFETIME, PlatformCredentialError as Error, PlatformCredentialStore,
};
use sqlx::PgPool;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::support::*;

const POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const OTHER_POD: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const HOST: &str = "api.example.com";

/// `uid`'s Pod as the credential service read it from the cluster.
fn pod(uid: &str) -> InterceptedPod<'_> {
    InterceptedPod {
        uid,
        namespace: "sandboxes",
        name: "workspace",
    }
}

/// A P-256 SubjectPublicKeyInfo, as the front door sends one.
const LEAF_KEY: [u8; 91] = {
    let mut spki = [0_u8; 91];
    let prefix: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut index = 0;
    while index < prefix.len() {
        spki[index] = prefix[index];
        index += 1;
    }
    spki[26] = 0x04;
    spki
};

async fn environment(db: &TestDatabase, org: &str, id: &str) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO environment_presets(id,org_id,name,slug,project_spec)
           VALUES ($1,$2,$1,$1,'{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(format!("preset-{id}"))
    .bind(org)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,
           environment_operation_generation,project_spec)
           VALUES ($1,$2,'fixture-admin','sandbox',$3,'running','started',7,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(id)
    .bind(org)
    .bind(format!("preset-{id}"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Orchestration's claim-time binding of `pod` to `environment`.
async fn bind<'e>(executor: impl sqlx::PgExecutor<'e>, pod: &str, environment: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,\
         claim_uid,sandbox_uid,operation_generation,managed_credential_clients,credential_scope) \
         VALUES ($1,$2,'sandboxes',$3,$4,$5,7,'','environment')",
    )
    .bind(pod)
    .bind(environment)
    .bind(format!("pod-{pod}"))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(executor)
    .await?;
    Ok(())
}

/// Orchestration's release of `pod`'s binding.
async fn release(pool: &PgPool, pod: &str) -> Result<()> {
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
         WHERE pod_uid = $1 AND released_at IS NULL",
    )
    .bind(pod)
    .execute(pool)
    .await?;
    Ok(())
}

/// `pod`'s row: its environment, or `None` when it has none.
async fn row(pool: &PgPool, pod: &str) -> Result<Option<Option<String>>> {
    Ok(
        sqlx::query_scalar("SELECT environment_id FROM platform_interception_cas WHERE pod_uid=$1")
            .bind(pod)
            .fetch_optional(pool)
            .await?,
    )
}

async fn broker_store(
    db: &TestDatabase,
    kek: &Arc<SyntheticKek>,
) -> Result<(PlatformCredentialStore, PgPool)> {
    let (pool, _) = db.broker_pool().await?;
    let store = PlatformCredentialStore::new(pool.clone(), kek.clone(), builtin_provider_catalog());
    Ok((store, pool))
}

/// A SQL statement's SQLSTATE, or `None` when it succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(error) => Some(error.to_string()),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_unbound_pods_ca_is_made_once_and_signs_only_once_its_bind_attaches_it() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;

        // A warm Pod: a certificate and no environment.
        let certificate = store.ensure_interception_ca(pod(POD)).await?;
        ensure!(store.ensure_interception_ca(pod(POD)).await? == certificate);
        ensure!(store.interception_ca_certificate(POD).await? == Some(certificate.clone()));
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 1);
        ensure!(row(&db.pool, POD).await? == Some(None));
        ensure!(matches!(
            store.open_interception_ca(POD, "env-a").await,
            Err(Error::NotFound)
        ));
        ensure!(
            kek.unwrap_calls.load(Ordering::SeqCst) == 0,
            "an unbound Pod's key stays sealed"
        );

        // The claim attaches it, in the bind's own statement.
        bind(&db.pool, POD, "env-a").await?;
        ensure!(row(&db.pool, POD).await? == Some(Some("env-a".to_owned())));
        ensure!(matches!(
            store.open_interception_ca(POD, "env-b").await,
            Err(Error::NotFound)
        ));
        let ca = store.open_interception_ca(POD, "env-a").await?;
        ensure!(ca.certificate_der() == certificate);
        let leaf = ca
            .sign_leaf(&valid_leaf_key(), &[HOST], MAX_LEAF_LIFETIME)
            .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;
        let (_, authority) = X509Certificate::from_der(&certificate)?;
        let (_, leaf) = X509Certificate::from_der(&leaf)?;
        leaf.verify_signature(Some(authority.public_key()))?;

        // A Pod bound before its first admission is attached at creation.
        bind(&db.pool, OTHER_POD, "env-b").await?;
        store.ensure_interception_ca(pod(OTHER_POD)).await?;
        ensure!(row(&db.pool, OTHER_POD).await? == Some(Some("env-b".to_owned())));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A real P-256 key's SubjectPublicKeyInfo: the constant above names the
/// curve, and the store checks only its shape.
fn valid_leaf_key() -> Vec<u8> {
    let mut key = LEAF_KEY.to_vec();
    // The generator point, so x509-parser reads a key that is on the curve.
    key[27..59].copy_from_slice(&[
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ]);
    key[59..91].copy_from_slice(&[
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ]);
    key
}

// A first use that loses the insert returns the stored CA, never its own.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn two_first_uses_end_on_one_stored_ca() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let store = Arc::new(store);
        // The first use stops after finding no row, before it inserts.
        kek.generate_gate.arm();
        let first = tokio::spawn({
            let store = store.clone();
            async move { store.ensure_interception_ca(pod(POD)).await }
        });
        kek.generate_gate.wait().await?;
        let winner = store.ensure_interception_ca(pod(POD)).await?;
        kek.generate_gate.release();
        let loser = first.await??;
        ensure!(loser == winner, "both return the one stored CA");
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 2);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_interception_cas")
            .fetch_one(&db.pool)
            .await?;
        ensure!(rows == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_released_pod_loses_its_ca_and_gets_none_again() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.ensure_interception_ca(pod(POD)).await?;
        bind(&db.pool, POD, "env-a").await?;
        store.open_interception_ca(POD, "env-a").await?;
        release(&db.pool, POD).await?;
        ensure!(
            matches!(
                store.open_interception_ca(POD, "env-a").await,
                Err(Error::NotFound)
            ),
            "the released Pod's environment can't open its CA"
        );
        ensure!(
            row(&db.pool, POD).await?.is_none(),
            "the release deleted it"
        );
        ensure!(matches!(
            store.ensure_interception_ca(pod(POD)).await,
            Err(Error::NotFound)
        ));
        ensure!(row(&db.pool, POD).await?.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The insert and the release take one lock on the Pod UID, so whichever
/// goes second sees the other's commit: no order leaves a row.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_insert_racing_a_release_leaves_no_row() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, broker) = broker_store(&db, &kek).await?;
        let store = Arc::new(store);

        // The release holds the lock; the insert waits, then sees it.
        bind(&db.pool, POD, "env-a").await?;
        let mut releasing = db.pool.begin().await?;
        sqlx::query("UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) WHERE pod_uid = $1")
            .bind(POD)
            .execute(&mut *releasing)
            .await?;
        let inserting = tokio::spawn({
            let store = store.clone();
            async move { store.ensure_interception_ca(pod(POD)).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(!inserting.is_finished(), "the insert waits for the release's lock");
        releasing.commit().await?;
        ensure!(matches!(inserting.await?, Err(Error::NotFound)));
        ensure!(row(&db.pool, POD).await?.is_none());

        // The insert holds the lock; the release waits, then deletes it.
        bind(&db.pool, OTHER_POD, "env-b").await?;
        let mut inserting = broker.begin().await?;
        sqlx::query(&sealed_row(OTHER_POD)).execute(&mut *inserting).await?;
        let releasing = tokio::spawn({
            let pool = db.pool.clone();
            async move { release(&pool, OTHER_POD).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(!releasing.is_finished(), "the release waits for the insert's lock");
        inserting.commit().await?;
        releasing.await??;
        ensure!(row(&db.pool, OTHER_POD).await?.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The insert and the bind take one lock on the Pod UID, so whichever goes
/// second sees the other's commit: either order ends attached.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_insert_racing_a_bind_ends_attached() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, broker) = broker_store(&db, &kek).await?;
        let store = Arc::new(store);

        // The bind holds the lock; the insert waits, then attaches to it.
        let mut binding = db.pool.begin().await?;
        bind(&mut *binding, POD, "env-a").await?;
        let inserting = tokio::spawn({
            let store = store.clone();
            async move { store.ensure_interception_ca(pod(POD)).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(
            !inserting.is_finished(),
            "the insert waits for the bind's lock"
        );
        binding.commit().await?;
        inserting.await??;
        ensure!(row(&db.pool, POD).await? == Some(Some("env-a".to_owned())));

        // The insert holds the lock; the bind waits, then attaches it. Each
        // environment has one live binding, so this Pod binds env-b.
        let mut inserting = broker.begin().await?;
        sqlx::query(&sealed_row(OTHER_POD))
            .execute(&mut *inserting)
            .await?;
        let binding = tokio::spawn({
            let pool = db.pool.clone();
            async move { bind(&pool, OTHER_POD, "env-b").await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(
            !binding.is_finished(),
            "the bind waits for the insert's lock"
        );
        inserting.commit().await?;
        binding.await??;
        ensure!(row(&db.pool, OTHER_POD).await? == Some(Some("env-b".to_owned())));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A raw row for `pod`, shaped as the store seals one.
fn sealed_row(pod: &str) -> String {
    format!(
        "INSERT INTO platform_interception_cas (pod_uid, pod_namespace, pod_name, certificate_der, \
         not_before, not_after, kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
         ciphertext, nonce, format) \
         VALUES ('{pod}', 'sandboxes', 'workspace', '\\x30', now(), now() + interval '1 day', 'openbao-transit', \
         'codewire-credentials', 1, '\\x01', 1, decode(repeat('00', 154), 'hex'), \
         decode(repeat('00', 12), 'hex'), 1)"
    )
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_row_copied_to_another_pod_does_not_open() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.ensure_interception_ca(pod(POD)).await?;
        // An owner's copy of the sealed row under another Pod UID.
        sqlx::query(
            "INSERT INTO platform_interception_cas (pod_uid, pod_namespace, pod_name, \
             certificate_der, not_before, not_after, kek_provider, key_name, key_version, \
             wrapped_dek, wrapped_format, ciphertext, nonce, format) \
             SELECT $2, pod_namespace, pod_name, certificate_der, not_before, not_after, \
             kek_provider, key_name, \
             key_version, wrapped_dek, wrapped_format, ciphertext, nonce, format \
             FROM platform_interception_cas WHERE pod_uid = $1",
        )
        .bind(POD)
        .bind(OTHER_POD)
        .execute(&db.pool)
        .await?;
        bind(&db.pool, OTHER_POD, "env-a").await?;
        let opened = store.open_interception_ca(OTHER_POD, "env-a").await;
        ensure!(
            matches!(
                opened,
                Err(Error::CorruptRecord | Error::ProviderUnavailable)
            ),
            "a copied row opened: {:?}",
            opened.err()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Clients trust the stored certificate and leaves are signed by the opened
/// key, so a row whose certificate carries another key doesn't open.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_row_whose_certificate_carries_another_key_does_not_open() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.ensure_interception_ca(pod(POD)).await?;
        store.ensure_interception_ca(pod(OTHER_POD)).await?;
        bind(&db.pool, POD, "env-a").await?;
        store.open_interception_ca(POD, "env-a").await?;
        // An owner's edit: POD's sealed key under OTHER_POD's certificate.
        // Rows never change, so it deletes the row and stores it again; the
        // insert attaches it to POD's live binding as before.
        let columns = "pod_uid, pod_namespace, pod_name, certificate_der, not_before, not_after, \
                       kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
                       ciphertext, nonce, format";
        let mut owner = db.pool.begin().await?;
        for statement in [
            format!(
                "CREATE TEMP TABLE swapped ON COMMIT DROP AS \
                 SELECT {columns} FROM platform_interception_cas WHERE pod_uid = '{POD}'"
            ),
            format!(
                "UPDATE swapped SET certificate_der = (SELECT certificate_der \
                 FROM platform_interception_cas WHERE pod_uid = '{OTHER_POD}')"
            ),
            format!("DELETE FROM platform_interception_cas WHERE pod_uid = '{POD}'"),
            format!(
                "INSERT INTO platform_interception_cas ({columns}) SELECT {columns} FROM swapped"
            ),
        ] {
            sqlx::query(&statement).execute(&mut *owner).await?;
        }
        owner.commit().await?;
        ensure!(row(&db.pool, POD).await? == Some(Some("env-a".to_owned())));
        let opened = store.open_interception_ca(POD, "env-a").await;
        ensure!(
            matches!(opened, Err(Error::CorruptRecord)),
            "a mismatched row opened: {:?}",
            opened.err()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_broker_names_no_environment_and_changes_or_deletes_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, broker) = broker_store(&db, &kek).await?;
        store.ensure_interception_ca(pod(POD)).await?;
        bind(&db.pool, POD, "env-a").await?;

        // The inserter never chooses the environment.
        let named = sealed_row(OTHER_POD).replace(
            "(pod_uid, pod_namespace",
            "(environment_id, pod_uid, pod_namespace",
        );
        ensure!(named.contains("(environment_id, pod_uid"));
        let named = named.replace("VALUES ('", "VALUES ('env-a', '");
        ensure!(named.contains("VALUES ('env-a', '"));
        ensure!(refused(&broker, &named).await.as_deref() == Some("42501"));
        ensure!(row(&db.pool, OTHER_POD).await?.is_none());
        // Neither the broker nor anyone else changes or re-attaches a row.
        for sql in [
            format!("DELETE FROM platform_interception_cas WHERE pod_uid = '{POD}'"),
            format!("UPDATE platform_interception_cas SET environment_id = 'env-b' WHERE pod_uid = '{POD}'"),
            format!("SELECT codewire_interception_ca_lock('{POD}')"),
        ] {
            ensure!(refused(&broker, &sql).await.as_deref() == Some("42501"), "{sql}");
        }
        ensure!(
            refused(
                &db.pool,
                &format!("UPDATE platform_interception_cas SET environment_id = 'env-b' WHERE pod_uid = '{POD}'")
            )
            .await
            .as_deref()
                == Some("23514"),
            "a second attach is refused"
        );
        ensure!(row(&db.pool, POD).await? == Some(Some("env-a".to_owned())));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_sweep_forgets_only_a_pod_with_no_live_binding() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.ensure_interception_ca(pod(POD)).await?;
        store.ensure_interception_ca(pod(OTHER_POD)).await?;
        bind(&db.pool, OTHER_POD, "env-a").await?;
        ensure!(store.forget_interception_ca(POD).await?);
        ensure!(row(&db.pool, POD).await?.is_none());
        ensure!(!store.forget_interception_ca(OTHER_POD).await?);
        ensure!(
            row(&db.pool, OTHER_POD).await?.is_some(),
            "a bound Pod keeps its CA"
        );
        ensure!(
            !store.forget_interception_ca(POD).await?,
            "forgetting twice is a no-op"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
