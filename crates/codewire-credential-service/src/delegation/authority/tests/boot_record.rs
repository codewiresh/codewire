//! A local VM's platform sources under its boot's sealed record (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources"):
//! the record the question reads and seals, the delegated projection and
//! the epoch's grants that follow it once it verifies, and the Open's and
//! the question's refusals on the public route. Every value is synthetic.

use super::public_wire::{SeedRoute, opening, with_route};
use super::*;

use codewire_access::{
    ApplicationSecretKey, PLACEHOLDER_KEY_BYTES, PlaceholderKey, PlaceholderPrefix,
    PlatformBootRecord, SecretKind, SecretPlaceholder, SecretSlot,
};
use codewire_credential_broker::bound_secret::BoundSecretLeaseError;
use codewire_protected_store::secret_envelope::TestTransitHmac;
use codewire_proto::codewire::v1 as proto;

use crate::delegation::BootSeal;

const CANARY: &str = "canary-boot-record-value-never-projected";
const HOST: &str = "api.fancy.example";
const BINDING: &str = r#"{"hosts":["api.fancy.example"],"presentation":{"kind":"header","headers":["X-Api-Key"],"scheme":null},"prefix":"ft_"}"#;

fn application_key() -> ApplicationSecretKey {
    ApplicationSecretKey::derive(&PlaceholderKey::from_slice(&[6; PLACEHOLDER_KEY_BYTES]).unwrap())
}

async fn bind(pool: &PgPool, path: &str, key: &str, generation: i64) -> Result<Uuid> {
    let binding_id = Uuid::new_v4();
    let updated = sqlx::query(
        "UPDATE tenant_secrets SET binding=$3::text::jsonb,binding_id=$4,binding_generation=$5, \
         ciphertext=decode(repeat('00',32),'hex') WHERE path=$1 AND key=$2",
    )
    .bind(path)
    .bind(key)
    .bind(BINDING)
    .bind(binding_id)
    .bind(generation)
    .execute(pool)
    .await?;
    ensure!(updated.rows_affected() == 1);
    Ok(binding_id)
}

/// Makes a secret plain, its generation set as given: the product's writer
/// always moves it on that change, which only this fixture skips.
async fn unbind(pool: &PgPool, path: &str, key: &str, generation: i64) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE tenant_secrets SET binding=NULL,binding_generation=$3 WHERE path=$1 AND key=$2",
    )
    .bind(path)
    .bind(key)
    .bind(generation)
    .execute(pool)
    .await?;
    ensure!(updated.rows_affected() == 1);
    Ok(())
}

/// The boot's record read and sealed as the question answers it, and the
/// selection with that record verified, as an Open that carried it.
async fn recorded(
    h: &Harness,
    selection: &OwnerLocalSelection,
    seal: &BootSeal,
) -> Result<(PlatformBootRecord, OwnerLocalSelection)> {
    let secrets = admitted(h, selection.clone()).await?.boot_record().await?;
    let boot = selection.sealed_boot();
    let record = PlatformBootRecord {
        seal: seal
            .seal(&boot, &secrets)
            .await
            .map_err(|refusal| anyhow::anyhow!("seal: {refusal:?}"))?,
        secrets,
    };
    let verified = seal
        .verify(&boot, record.clone())
        .await
        .map_err(|refusal| anyhow::anyhow!("verify: {refusal:?}"))?;
    Ok((record, selection.clone().with_boot_record(verified)))
}

async fn projected_by(
    authority: &OwnerLocalRuntimeAuthority,
    selection: &OwnerLocalSelection,
) -> Result<BTreeMap<String, String>> {
    let (request, recipient, context) = projection_request(selection, unix_millis()? + 15_000);
    let sealed = authority
        .project_environment(request, Some(application_key()))
        .await?;
    Ok(recipient
        .open(&sealed, &context, unix_millis()?)?
        .entries()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

fn key() -> BootSeal {
    BootSeal::new(Some(Arc::new(TestTransitHmac::default())))
}

/// Condition A for a local VM's platform sources: once the boot's record
/// verified, a secret recorded bound and plain now keeps the record's
/// placeholder at any generation, never its value; one the record lacks
/// that was ever bound is refused by name, and one it lacks that was never
/// bound projects its value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_boot_record_keeps_its_placeholder_and_refuses_what_changed() -> Result<()> {
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        let organization = format!("/org-secrets/{ORGANIZATION}");
        put(&project_path, "FANCY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        put(&organization, "PLAIN_TOKEN", b"plain-value", &h.db.pool).await?;
        let binding_id = bind(&h.db.pool, &project_path, "FANCY_TOKEN", 4).await?;
        let (record, verified) = recorded(&h, &selection, &key()).await?;
        let fancy = record
            .secrets
            .iter()
            .find(|secret| secret.key == "FANCY_TOKEN")
            .context("the bound secret is recorded")?;
        ensure!(fancy.binding_generation == 4);
        let bound = fancy.bound.as_ref().context("recorded bound")?;
        ensure!(bound.binding_id == binding_id.to_string() && bound.hosts == [HOST]);
        ensure!(bound.prefix.as_deref() == Some("ft_"));
        ensure!(
            record
                .secrets
                .iter()
                .any(|secret| secret.key == "PLAIN_TOKEN" && secret.bound.is_none()),
            "a plain secret is recorded too"
        );
        let expected = SecretPlaceholder::derive(
            &application_key(),
            &EnvironmentId::parse(selection.local_environment_id.to_string())?,
            &SecretSlot::new(SecretKind::Project, &project, "FANCY_TOKEN")?,
            binding_id.as_bytes(),
            4,
            Some(&PlaceholderPrefix::parse("ft_")?),
        );

        // Plain now at its recorded generation: the record's placeholder.
        unbind(&h.db.pool, &project_path, "FANCY_TOKEN", 4).await?;
        let authority = admitted(&h, verified.clone()).await?;
        let projected = projected_by(&authority, &verified).await?;
        ensure!(
            projected
                == BTreeMap::from([
                    ("FANCY_TOKEN".to_owned(), expected.as_str().to_owned()),
                    ("PLAIN_TOKEN".to_owned(), "plain-value".to_owned()),
                ])
        );
        ensure!(projected.values().all(|value| !value.contains(CANARY)));
        // The same, with no record: refused, as a secret ever bound.
        let unrecorded = admitted(&h, selection.clone()).await?;
        ensure!(projected_by(&unrecorded, &selection).await.is_err());

        // Made plain as the store's writer does, moving its generation: still
        // the record's placeholder, never its value.
        unbind(&h.db.pool, &project_path, "FANCY_TOKEN", 5).await?;
        ensure!(
            projected_by(&authority, &verified)
                .await?
                .get("FANCY_TOKEN")
                == Some(&expected.as_str().to_owned()),
            "a secret recorded bound lost its placeholder"
        );

        // A secret ever bound that the record lacks: refused.
        put(&project_path, "NEW_TOKEN", b"new-value", &h.db.pool).await?;
        bind(&h.db.pool, &project_path, "NEW_TOKEN", 1).await?;
        unbind(&h.db.pool, &project_path, "NEW_TOKEN", 2).await?;
        // A readable value, so only the rule can refuse it.
        put(&project_path, "NEW_TOKEN", b"new-value", &h.db.pool).await?;
        ensure!(
            projected_by(&authority, &verified).await.is_err(),
            "a secret the record lacks was projected raw"
        );
        // One never bound that the record lacks projects its value.
        sqlx::query("DELETE FROM tenant_secrets WHERE path=$1 AND key='NEW_TOKEN'")
            .bind(&project_path)
            .execute(&h.db.pool)
            .await?;
        put(&project_path, "NEW_TOKEN", b"new-value", &h.db.pool).await?;
        ensure!(
            projected_by(&authority, &verified)
                .await?
                .get("NEW_TOKEN")
                .map(String::as_str)
                == Some("new-value")
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

/// The epoch's bound-secret grants come only from the verified record: an
/// epoch whose Open carried none has none, whatever is bound now. Each
/// lease rereads the row and checks it against the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn grants_come_only_from_the_verified_record() -> Result<()> {
    use codewire_credential_broker::platform::PlatformRuntimeAuthority as _;
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        put(&project_path, "FANCY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        let binding_id = bind(&h.db.pool, &project_path, "FANCY_TOKEN", 4).await?;
        let unrecorded = admitted(&h, selection.clone()).await?;
        ensure!(unrecorded.bound_secrets().await?.is_empty());

        let (_, verified) = recorded(&h, &selection, &key()).await?;
        let authority = admitted(&h, verified).await?;
        let grants = authority.bound_secrets().await?;
        ensure!(
            grants.len() == 1,
            "the record's one bound secret is granted"
        );
        let grant = &grants[0];
        ensure!(grant.key == "FANCY_TOKEN" && grant.path == project_path);
        ensure!(grant.binding_id == binding_id.to_string() && grant.binding_generation == 4);
        ensure!(authority.bound_secret_row(grant, HOST).await.is_ok());
        // Its value, set again under its binding, is read for the lease alone.
        put(&project_path, "FANCY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        let (_, value) = authority.bound_secret_value(grant, HOST).await?;
        ensure!(value.as_slice() == CANARY.as_bytes());
        ensure!(
            authority
                .bound_secret_row(grant, "api.other.example")
                .await
                .err()
                == Some(BoundSecretLeaseError::NotBoundToHost)
        );
        sqlx::query(
            "UPDATE tenant_secrets SET binding_generation=5 WHERE path=$1 AND key='FANCY_TOKEN'",
        )
        .bind(&project_path)
        .execute(&h.db.pool)
        .await?;
        ensure!(
            authority.bound_secret_row(grant, HOST).await.err()
                == Some(BoundSecretLeaseError::BindingChanged)
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

async fn question(
    route: &SeedRoute<'_>,
    selection: proto::CredentialDelegationOpen,
) -> std::result::Result<
    codewire_client::EnvironmentBoundSecretsResponse,
    codewire_client::ClientError,
> {
    route
        .client(oauth(ALICE))
        .expect("a synthetic client")
        .environment_bound_secrets(codewire_client::EnvironmentBoundSecretsRequest {
            selection: Some(selection).into(),
            ..Default::default()
        })
        .await
}

async fn delegate(
    route: &SeedRoute<'_>,
    open: proto::CredentialDelegationOpen,
) -> std::result::Result<(), codewire_client::ClientError> {
    let admitted = route
        .client(oauth(ALICE))
        .expect("a synthetic client")
        .delegate_credentials(open)
        .await?;
    drop(admitted.stream);
    Ok(())
}

fn code(
    result: std::result::Result<impl std::fmt::Debug, codewire_client::ClientError>,
) -> Option<codewire_client::ErrorCode> {
    result.err().map(|error| error.code())
}

/// The question is answered with the record and its seal; an Open that
/// carries that record is admitted with it echoed, and one whose record or
/// seal changed in any field, or whose seal is two rotations old, is
/// PERMISSION_DENIED as any refused selection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_open_carries_its_boots_record_and_a_changed_one_is_denied() -> Result<()> {
    let transit = Arc::new(TestTransitHmac::default());
    let seal = BootSeal::new(Some(transit.clone()));
    with_route(seal, async |route: &SeedRoute<'_>| {
        let project = route
            .selection
            .platform
            .project_id
            .clone()
            .context("a project")?;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        put(
            &project_path,
            "FANCY_TOKEN",
            CANARY.as_bytes(),
            &route.h.db.pool,
        )
        .await?;
        bind(&route.h.db.pool, &project_path, "FANCY_TOKEN", 4).await?;
        let record = question(route, route.open.clone())
            .await?
            .record
            .into_option()
            .context("the question answers a record")?;
        ensure!(record.seal.starts_with("vault:v1:"));
        ensure!(
            record
                .secrets
                .iter()
                .any(|secret| secret.key == "FANCY_TOKEN")
        );
        let mut carrying = opening(&route.selection);
        carrying.bound_secrets = Some(record.clone()).into();
        delegate(route, carrying.clone()).await?;

        // A question that brings a record of its own is refused.
        ensure!(
            code(question(route, carrying.clone()).await)
                == Some(codewire_client::ErrorCode::PermissionDenied)
        );

        let changed: [fn(&mut proto::CredentialDelegationOpen); 6] = [
            |open| drop(open.bound_secrets.get_or_insert_default().secrets.pop()),
            |open| open.bound_secrets.get_or_insert_default().secrets[0].binding_generation += 1,
            |open| {
                open.bound_secrets.get_or_insert_default().secrets[0]
                    .bound
                    .get_or_insert_default()
                    .hosts = vec!["api.other.example".into()];
            },
            |open| open.runtime.get_or_insert_default().environment_id = Uuid::new_v4().to_string(),
            |open| open.runtime.get_or_insert_default().environment_generation += 1,
            |open| open.selection_sha256 = vec![0x5b; 32],
        ];
        for change in changed {
            let mut open = carrying.clone();
            change(&mut open);
            ensure!(
                code(delegate(route, open).await)
                    == Some(codewire_client::ErrorCode::PermissionDenied)
            );
        }
        transit.rotate();
        delegate(route, carrying.clone()).await?;
        transit.rotate();
        ensure!(
            code(delegate(route, carrying.clone()).await)
                == Some(codewire_client::ErrorCode::PermissionDenied)
        );
        Ok(())
    })
    .await
}

/// OpenBao unavailable fails the question and an Open that carries a record
/// as UNAVAILABLE, never as a pass; with no seal key the question is
/// UNIMPLEMENTED, an Open with no record is admitted as today, and one that
/// carries a record is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_unreachable_seal_key_is_unavailable_and_none_is_unimplemented() -> Result<()> {
    let transit = Arc::new(TestTransitHmac::default());
    let seal = BootSeal::new(Some(transit.clone()));
    let carried = Arc::new(std::sync::Mutex::new(None));
    let kept = Arc::clone(&carried);
    with_route(seal, async |route: &SeedRoute<'_>| {
        let record = question(route, route.open.clone())
            .await?
            .record
            .into_option()
            .context("the question answers a record")?;
        let mut carrying = opening(&route.selection);
        carrying.bound_secrets = Some(record).into();
        *kept.lock().unwrap() = Some(carrying.clone());
        transit.set_unavailable(true);
        ensure!(
            code(question(route, route.open.clone()).await)
                == Some(codewire_client::ErrorCode::Unavailable)
        );
        ensure!(
            code(delegate(route, carrying).await) == Some(codewire_client::ErrorCode::Unavailable)
        );
        Ok(())
    })
    .await?;
    with_route(BootSeal::default(), async |route: &SeedRoute<'_>| {
        ensure!(
            code(question(route, route.open.clone()).await)
                == Some(codewire_client::ErrorCode::Unimplemented)
        );
        delegate(route, route.open.clone()).await?;
        let mut carrying = route.open.clone();
        carrying.bound_secrets = carried
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|open| open.bound_secrets.as_option().cloned())
            .into();
        ensure!(carrying.bound_secrets.as_option().is_some());
        ensure!(
            code(delegate(route, carrying).await)
                == Some(codewire_client::ErrorCode::PermissionDenied)
        );
        Ok(())
    })
    .await
}

/// An older seal for the same boot is worthless (docs/dev/SECRETS-AND-
/// CREDENTIALS.md, "The invariant"): sealed while a secret was plain at
/// generation g, it is refused once the secret has been bound (g+1) and made
/// plain again (g+2); sealed while it was bound, it gives only the
/// placeholder, and that placeholder's lease is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_older_seal_replayed_for_its_boot_gives_no_value() -> Result<()> {
    use codewire_credential_broker::platform::PlatformRuntimeAuthority as _;
    let h = Harness::unserved("127.0.0.1:0".parse()?).await?;
    let result = async {
        let (selection, project) = setup_owner_sources(&h).await?;
        let project_path = format!("/projects/{ORGANIZATION}/{project}");
        put(&project_path, "REPLAY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;
        let seal = key();
        let (plain_record, sealed_plain) = recorded(&h, &selection, &seal).await?;
        ensure!(
            plain_record
                .secrets
                .iter()
                .any(|secret| secret.key == "REPLAY_TOKEN"
                    && secret.binding_generation == 0
                    && secret.bound.is_none())
        );
        let binding_id = bind(&h.db.pool, &project_path, "REPLAY_TOKEN", 1).await?;
        let (_, sealed_bound) = recorded(&h, &selection, &seal).await?;
        unbind(&h.db.pool, &project_path, "REPLAY_TOKEN", 2).await?;
        put(&project_path, "REPLAY_TOKEN", CANARY.as_bytes(), &h.db.pool).await?;

        let replayed = admitted(&h, sealed_plain.clone()).await?;
        ensure!(
            projected_by(&replayed, &sealed_plain).await.is_err(),
            "a seal from while the secret was plain projected it raw"
        );

        let replayed = admitted(&h, sealed_bound.clone()).await?;
        let projected = projected_by(&replayed, &sealed_bound).await?;
        let expected = SecretPlaceholder::derive(
            &application_key(),
            &EnvironmentId::parse(selection.local_environment_id.to_string())?,
            &SecretSlot::new(SecretKind::Project, &project, "REPLAY_TOKEN")?,
            binding_id.as_bytes(),
            1,
            Some(&PlaceholderPrefix::parse("ft_")?),
        );
        ensure!(projected.get("REPLAY_TOKEN") == Some(&expected.as_str().to_owned()));
        ensure!(projected.values().all(|value| !value.contains(CANARY)));
        let grants = replayed.bound_secrets().await?;
        let grant = grants
            .iter()
            .find(|grant| grant.key == "REPLAY_TOKEN")
            .context("the bound seal grants the secret")?;
        ensure!(
            replayed.bound_secret_row(grant, HOST).await.err()
                == Some(BoundSecretLeaseError::BindingChanged)
        );
        ensure!(
            replayed.bound_secret_value(grant, HOST).await.err()
                == Some(BoundSecretLeaseError::BindingChanged)
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}
