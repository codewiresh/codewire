//! Restricted SQL + generated synthetic Ed25519 material + existing OpenSSH.
//! The test-only catalog admits SSH; the production catalog remains disabled.

use super::*;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

use codewire_access::{CapabilityPolicy, ProviderCatalog, ProviderDefinition, ProviderId};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_protected_store::ssh_material::{SshPublicKey, generate_ed25519};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::platform::ssh::Service;
use crate::ssh_agent::{SshAgentConfig, SshAgentOwner};

fn catalog() -> ProviderCatalog {
    ProviderCatalog::from_definitions([
        builtin_provider_catalog()
            .get(&ProviderId::parse("openai").unwrap())
            .unwrap()
            .clone(),
        ProviderDefinition {
            id: ProviderId::parse("ssh").unwrap(),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::parse("ssh").unwrap(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
                    permissions: ["ssh-identities", "ssh-sign"]
                        .into_iter()
                        .map(|operation| GrantPermission {
                            operation: BrokerOperationId::parse(operation).unwrap(),
                            route: BrokerRouteId::parse("ssh-agent").unwrap(),
                        })
                        .collect(),
                },
            )]),
        },
    ])
    .unwrap()
}

struct SshFixture {
    f: Fixture,
    adapter: Arc<Adapter>,
    record: CredentialRecord,
    public: SshPublicKey,
    service: Arc<Service>,
    accepting: Arc<Mutex<bool>>,
    stop: CancellationToken,
    workers: TaskTracker,
    root: tempfile::TempDir,
}

impl SshFixture {
    async fn create() -> Result<Self> {
        let f = Fixture::create().await?;
        let setup = async {
            let prepared = tokio::task::spawn_blocking(generate_ed25519).await??;
            let public = prepared.public_key().clone();
            let prepared = f
                .store
                .prepare_ssh_creation(&f.owner, "Synthetic SSH".into(), None, prepared)
                .await?;
            let mut tx = f.pool.begin().await?;
            let record = f
                .store
                .create_prepared_in(&mut tx, &f.owner, prepared)
                .await?;
            tx.commit().await?;
            let manager = profiles(f.db.pool.clone(), catalog());
            manager
                .delete_binding(
                    &f.context,
                    &EnvironmentAccessBinding {
                        environment_id: f.context.environment_id.clone(),
                        profile_id: f.profile.id.clone(),
                        profile_revision: f.profile.revision,
                    },
                )
                .await?;
            let profile = manager
                .create(
                    &f.owner,
                    AccessProfileName::parse("ssh-work")?,
                    BTreeMap::from([(CapabilitySlot::parse("ssh")?, record.metadata.id.clone())]),
                )
                .await?;
            let mut context = f.context.clone();
            context.authorized_credentials = BTreeSet::from([record.metadata.id.clone()]);
            manager
                .create_binding(
                    &context,
                    EnvironmentAccessBinding {
                        environment_id: context.environment_id.clone(),
                        profile_id: profile.id,
                        profile_revision: profile.revision,
                    },
                    Some(&context.user_id),
                )
                .await?;
            f.authority.change(|session| session.context = context);
            let root = tempfile::Builder::new()
                .prefix("cw-platform-ssh-db-")
                .tempdir_in("/dev/shm")?;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
            let owner = Arc::new(SshAgentOwner::new(SshAgentConfig::new(
                root.path().to_owned(),
                "/usr/bin/ssh-agent".into(),
                "/usr/bin/ssh-add".into(),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ssh_agent/askpass.sh"),
            )?));
            let accepting = Arc::new(Mutex::new(true));
            let stop = CancellationToken::new();
            let workers = TaskTracker::new();
            let service = Service::new(owner, accepting.clone(), workers.clone(), stop.clone());
            let mut adapter = Adapter::connect(
                f.authority.clone(),
                f.store.clone(),
                profiles(f.pool.clone(), catalog()),
            )
            .await?;
            adapter.ssh = Some(service.epoch());
            // As in an admitted bridge epoch, which always has a cache.
            adapter.material = Some(EpochMaterialCache::new());
            Ok::<_, anyhow::Error>((
                Arc::new(adapter),
                record,
                public,
                service,
                accepting,
                stop,
                workers,
                root,
            ))
        }
        .await;
        match setup {
            Ok((adapter, record, public, service, accepting, stop, workers, root)) => Ok(Self {
                f,
                adapter,
                record,
                public,
                service,
                accepting,
                stop,
                workers,
                root,
            }),
            Err(error) => {
                f.finish(Err(error)).await?;
                unreachable!("setup failure returns its error")
            }
        }
    }

    fn request(&self, signing: bool) -> v1::CredentialSshRequest {
        let operation = if signing {
            v1::credential_ssh_request::Operation::Sign(v1::CredentialSshSignRequest {
                public_key_blob: self.public.key_blob().to_vec(),
                data: b"synthetic SSH signature input".to_vec(),
                flags: 0,
            })
        } else {
            v1::credential_ssh_request::Operation::Identities(v1::CredentialSshIdentitiesRequest {})
        };
        v1::CredentialSshRequest {
            request_id: Uuid::new_v4().to_string(),
            deadline_unix_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                + 10_000,
            operation: Some(operation),
        }
    }

    async fn advance_material_generation(&self) -> Result<()> {
        // Generic replacement deliberately denies SSH. Exercise the original
        // full-version fence with the same relational transaction order as
        // replace_prepared_in and the storage AEAD-coordinate fixture: lock,
        // delete material, advance the record, reinsert material, then commit.
        // These retained synthetic ciphertext bytes are NOT a valid envelope
        // for the new AEAD generation; no new-version use is claimed here.
        // The blocked original-version read must deny before releasing a key.
        #[derive(sqlx::FromRow)]
        struct Material {
            kek_provider: String,
            key_name: String,
            key_version: i64,
            wrapped_dek: Vec<u8>,
            wrapped_format: i16,
            ciphertext: Vec<u8>,
            nonce: Vec<u8>,
            format: i16,
        }
        let mut tx = self.f.pool.begin().await?;
        let current = self
            .f
            .store
            .record_for_update_in(&mut tx, &self.f.owner, &self.record.metadata.id)
            .await?;
        ensure!(
            current == self.record,
            "synthetic material mutation lost its exact record"
        );
        let material: Material = sqlx::query_as(
            "DELETE FROM platform_credential_material WHERE credential_id=$1 AND material_generation=$2 \
             RETURNING kek_provider,key_name,key_version,wrapped_dek,wrapped_format,ciphertext,nonce,format",
        ).bind(self.record.metadata.id.as_str())
            .bind(i64::try_from(self.record.version.material_generation)?).fetch_one(&mut *tx).await?;
        let next = i64::try_from(self.record.version.material_generation + 1)?;
        let updated =
            sqlx::query("UPDATE platform_credentials SET material_generation=$2 WHERE id=$1")
                .bind(self.record.metadata.id.as_str())
                .bind(next)
                .execute(&mut *tx)
                .await?;
        ensure!(updated.rows_affected() == 1);
        sqlx::query(
            "INSERT INTO platform_credential_material \
             (credential_id,material_generation,kek_provider,key_name,key_version,wrapped_dek,wrapped_format,ciphertext,nonce,format) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        ).bind(self.record.metadata.id.as_str()).bind(next)
            .bind(material.kek_provider).bind(material.key_name).bind(material.key_version)
            .bind(material.wrapped_dek).bind(material.wrapped_format).bind(material.ciphertext)
            .bind(material.nonce).bind(material.format).execute(&mut *tx).await?;
        tx.commit().await?;
        let current = self
            .f
            .store
            .record(&self.f.owner, &self.record.metadata.id)
            .await?;
        ensure!(current.metadata == self.record.metadata);
        ensure!(current.version.revocation_generation == self.record.version.revocation_generation);
        ensure!(current.version.material_generation == self.record.version.material_generation + 1);
        Ok(())
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        *self.accepting.lock().unwrap() = false;
        self.stop.cancel();
        self.workers.close();
        self.workers.wait().await;
        let drained = self.service.shutdown().await.map_err(anyhow::Error::from);
        let empty = std::fs::read_dir(self.root.path())
            .map(|mut entries| entries.next().is_none())
            .map_err(anyhow::Error::from);
        let result = result.and(drained).and_then(|()| {
            ensure!(empty?, "private agent staging remained after drain");
            Ok(())
        });
        self.f.finish(result).await
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL and checked-in OpenSSH tools"]
async fn identities_are_public_only_and_each_signature_unwraps_and_drains_once() -> Result<()> {
    let f = SshFixture::create().await?;
    let result = async {
        let initial = f.f.provider.unwrap_calls.load(Ordering::SeqCst);
        let response = f.adapter.ssh_operation(f.request(false), CancellationToken::new()).await?;
        ensure!(matches!(response, v1::credential_ssh_response::Result::Identity(ref identity) if identity.public_key_blob == f.public.key_blob()));
        ensure!(f.f.provider.unwrap_calls.load(Ordering::SeqCst) == initial);
        for count in 1..=2 {
            let response = f.adapter.ssh_operation(f.request(true), CancellationToken::new()).await?;
            ensure!(matches!(response, v1::credential_ssh_response::Result::Signature(ref signature) if !signature.signature_blob.is_empty()));
            ensure!(f.f.provider.unwrap_calls.load(Ordering::SeqCst) == initial + count);
            ensure!(std::fs::read_dir(f.root.path())?.next().is_none(), "signature preceded agent drain");
        }
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL and checked-in OpenSSH tools"]
async fn ssh_signatures_and_ssh_key_leases_never_reuse_material_in_an_epoch() -> Result<()> {
    let f = SshFixture::create().await?;
    let result = async {
        let initial = f.f.provider.unwrap_calls.load(Ordering::SeqCst);
        const SIGNATURES: usize = 3;
        for count in 1..=SIGNATURES {
            let response = f
                .adapter
                .ssh_operation(f.request(true), CancellationToken::new())
                .await?;
            ensure!(matches!(
                response,
                v1::credential_ssh_response::Result::Signature(_)
            ));
            ensure!(f.f.provider.unwrap_calls.load(Ordering::SeqCst) == initial + count);
            ensure!(
                f.adapter
                    .material
                    .as_ref()
                    .is_some_and(EpochMaterialCache::is_empty)
            );
        }
        // Even an ordinary lease of an SSH key reads through every time.
        for count in 1..=2 {
            let (leased, timings) = crate::timing::measure(f.adapter.lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::parse("ssh")?,
                BrokerOperationId::parse("ssh-sign")?,
                BrokerRouteId::parse("ssh-agent")?,
            ))
            .await;
            leased?;
            ensure!(timings.material_cache == crate::timing::MaterialCacheUse::Bypass);
            ensure!(
                f.f.provider.unwrap_calls.load(Ordering::SeqCst) == initial + SIGNATURES + count
            );
            ensure!(
                f.adapter
                    .material
                    .as_ref()
                    .is_some_and(EpochMaterialCache::is_empty)
            );
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL and checked-in OpenSSH tools"]
async fn wrong_key_or_flags_and_unconfigured_adapter_fail_before_private_read() -> Result<()> {
    let f = SshFixture::create().await?;
    let result = async {
        let initial = f.f.provider.unwrap_calls.load(Ordering::SeqCst);
        for wrong_key in [false, true] {
            let mut request = f.request(true);
            let Some(v1::credential_ssh_request::Operation::Sign(sign)) =
                request.operation.as_mut()
            else {
                unreachable!()
            };
            if wrong_key {
                sign.public_key_blob[0] ^= 1;
            } else {
                sign.flags = 2;
            }
            ensure!(matches!(
                f.adapter
                    .ssh_operation(request, CancellationToken::new())
                    .await,
                Err(BrokerLeaseError::Denied)
            ));
        }
        let adapter = Adapter::connect(
            f.f.authority.clone(),
            f.f.store.clone(),
            profiles(f.f.pool.clone(), catalog()),
        )
        .await?;
        ensure!(matches!(
            adapter
                .ssh_operation(f.request(false), CancellationToken::new())
                .await,
            Err(BrokerLeaseError::Denied)
        ));
        ensure!(f.f.provider.unwrap_calls.load(Ordering::SeqCst) == initial);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL and checked-in OpenSSH tools"]
async fn signing_rechecks_revocation_environment_and_authenticated_pod_after_unwrap() -> Result<()>
{
    for mutation in [
        "revoke",
        "stop",
        "generation",
        "relay",
        "workspace",
        "identity-expiry",
        "credential-expiry",
        "profile",
        "material",
        "personal-policy",
    ] {
        let f = SshFixture::create().await?;
        let result = async {
            f.f.provider.unwrap_gate.arm();
            let request = f.request(true);
            let adapter = f.adapter.clone();
            let operation = tokio::spawn(async move { adapter.ssh_operation(request, CancellationToken::new()).await });
            f.f.provider.unwrap_gate.wait().await?;
            match mutation {
                "revoke" => { f.f.store.revoke(&f.f.owner, &f.record.metadata.id, f.record.version).await?; }
                "stop" => f.f.stop().await?,
                "generation" => {
                    sqlx::query("UPDATE environments SET environment_operation_generation=8 WHERE id=$1")
                        .bind(f.f.context.environment_id.as_str()).execute(&f.f.db.pool).await?;
                }
                "relay" => f.f.authority.change(|session| session.relay_mut().uid = Uuid::new_v4()),
                "workspace" => f.f.authority.change(|session| session.workspace_mut().uid = Uuid::new_v4()),
                "identity-expiry" => f.f.authority.change(|session| session.identity_expires_at_unix = 1),
                "credential-expiry" => {
                    sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
                        .bind(f.record.metadata.id.as_str()).execute(&f.f.db.pool).await?;
                }
                "profile" => {
                    sqlx::query("UPDATE platform_environment_access_bindings SET profile_id=$1, profile_revision=$2 WHERE environment_id=$3")
                        .bind(f.f.profile.id.as_str()).bind(i64::try_from(f.f.profile.revision).unwrap())
                        .bind(f.f.context.environment_id.as_str()).execute(&f.f.db.pool).await?;
                }
                "material" => {
                    f.advance_material_generation().await?;
                }
                "personal-policy" => f.f.authority.change(|session| session.context.allow_personal_credentials = false),
                _ => unreachable!(),
            }
            f.f.provider.unwrap_gate.release();
            ensure!(matches!(tokio::time::timeout(TIMEOUT, operation).await??, Err(BrokerLeaseError::Denied)), "stale SSH authority released a result");
            ensure!(std::fs::read_dir(f.root.path())?.next().is_none());
            Ok(())
        }.await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL and checked-in OpenSSH tools"]
async fn completed_signature_is_drained_then_revalidated_before_release() -> Result<()> {
    let f = SshFixture::create().await?;
    let result = async {
        // Two session reads for admission, two after unwrap, then the first
        // final-release read after sign_once has already proved worker drain.
        f.f.authority.gate.arm(5);
        let request = f.request(true);
        let adapter = f.adapter.clone();
        let operation = tokio::spawn(async move {
            adapter
                .ssh_operation(request, CancellationToken::new())
                .await
        });
        f.f.authority.gate.wait().await?;
        ensure!(
            std::fs::read_dir(f.root.path())?.next().is_none(),
            "final authority check preceded worker drain"
        );
        f.f.store
            .revoke(&f.f.owner, &f.record.metadata.id, f.record.version)
            .await?;
        f.f.authority.gate.release();
        // Revocation withholds the selected key: the final recheck names the
        // Reconnect it needs and the completed signature is never released.
        ensure!(
            matches!(
                tokio::time::timeout(TIMEOUT, operation).await??,
                Err(BrokerLeaseError::ReconnectRequired)
            ),
            "signature escaped a revoked post-sign binding"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}
