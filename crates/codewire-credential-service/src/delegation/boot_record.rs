//! A local VM boot's sealed record of its platform sources' secrets (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources").
//!
//! The platform keeps no row for a local boot: it seals the record it
//! answers with, under a transit HMAC key used for nothing else, and the boot
//! carries both back in its delegation's Open. The seal covers the
//! environment, its generation and the selection with the record, so a
//! record from another boot, or one changed in any field, doesn't verify.
//! Only a record whose seal verified becomes a [`VerifiedBootRecord`], the
//! one input the delegated projection and the epoch's grants take.

use std::sync::Arc;

use codewire_access::{PlatformBootBinding, PlatformBootRecord, PlatformBootSecret};
use codewire_protected_store::secret_envelope::TransitHmac;
use codewire_proto::codewire::v1 as proto;
use uuid::Uuid;

/// The sealed input's domain label, followed by one zero byte.
const DOMAIN: &[u8] = b"codewire.local-bound-secrets.v1";

/// Why a record wasn't sealed or didn't verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealRefusal {
    /// This service has no seal key: it doesn't serve the question, and an
    /// Open that carries a record is refused.
    NotConfigured,
    /// The record doesn't verify, or can't be encoded: refused as any other
    /// refused selection.
    Denied,
    /// OpenBao can't be reached: never a pass.
    Unavailable,
}

/// The boot whose record is sealed: its environment, the generation its
/// bridge Ready carries, and its selection's digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SealedBoot {
    pub(crate) environment_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) selection_sha256: [u8; 32],
}

/// A record whose seal verified for its boot. Only [`BootSeal::verify`]
/// makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBootRecord {
    secrets: Vec<PlatformBootSecret>,
}

impl VerifiedBootRecord {
    pub(crate) fn secrets(&self) -> &[PlatformBootSecret] {
        &self.secrets
    }
}

/// The service's local-boot seal key, if it has one.
#[derive(Clone, Default)]
pub(crate) struct BootSeal(Option<Arc<dyn TransitHmac>>);

impl BootSeal {
    pub(crate) fn new(key: Option<Arc<dyn TransitHmac>>) -> Self {
        Self(key)
    }

    pub(super) fn configured(&self) -> bool {
        self.0.is_some()
    }

    /// The seal over `secrets` for `boot`.
    pub(super) async fn seal(
        &self,
        boot: &SealedBoot,
        secrets: &[PlatformBootSecret],
    ) -> Result<String, SealRefusal> {
        let key = self.0.as_ref().ok_or(SealRefusal::NotConfigured)?;
        let input = sealed_input(boot, secrets).ok_or(SealRefusal::Denied)?;
        key.hmac(&input).await.map_err(|_| SealRefusal::Unavailable)
    }

    /// `record`, once its seal verifies for `boot`.
    pub(super) async fn verify(
        &self,
        boot: &SealedBoot,
        record: PlatformBootRecord,
    ) -> Result<VerifiedBootRecord, SealRefusal> {
        let key = self.0.as_ref().ok_or(SealRefusal::NotConfigured)?;
        let input = sealed_input(boot, &record.secrets).ok_or(SealRefusal::Denied)?;
        match key.verify(&input, &record.seal).await {
            Ok(true) => Ok(VerifiedBootRecord {
                secrets: record.secrets,
            }),
            Ok(false) => Err(SealRefusal::Denied),
            Err(_) => Err(SealRefusal::Unavailable),
        }
    }
}

/// The exact bytes a record is sealed over (the spec's "The sealed input"):
/// the domain label and a zero byte, then each field as a big-endian u32
/// length and its bytes. `None` for a record that can't be encoded: a
/// `binding_id` that isn't a canonical UUID, or a field too long to count.
pub(crate) fn sealed_input(boot: &SealedBoot, secrets: &[PlatformBootSecret]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(DOMAIN);
    out.push(0);
    field(&mut out, boot.environment_id.as_bytes())?;
    field(&mut out, &boot.generation.to_be_bytes())?;
    field(&mut out, &boot.selection_sha256)?;
    let mut sorted: Vec<&PlatformBootSecret> = secrets.iter().collect();
    sorted.sort_by(|a, b| (&a.path, &a.key).cmp(&(&b.path, &b.key)));
    for secret in sorted {
        field(&mut out, secret.path.as_bytes())?;
        field(&mut out, secret.key.as_bytes())?;
        field(&mut out, &secret.binding_generation.to_be_bytes())?;
        field(&mut out, &[u8::from(secret.bound.is_some())])?;
        if let Some(bound) = &secret.bound {
            let binding_id = Uuid::parse_str(&bound.binding_id)
                .ok()
                .filter(|id| id.to_string() == bound.binding_id)?;
            field(&mut out, binding_id.as_bytes())?;
            field(
                &mut out,
                bound.prefix.as_deref().unwrap_or_default().as_bytes(),
            )?;
            let mut hosts: Vec<&str> = bound.hosts.iter().map(String::as_str).collect();
            hosts.sort_unstable();
            field(&mut out, &u32::try_from(hosts.len()).ok()?.to_be_bytes())?;
            for host in hosts {
                field(&mut out, host.as_bytes())?;
            }
        }
    }
    Some(out)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

pub(crate) fn record_to_proto(record: PlatformBootRecord) -> proto::LocalBootBoundSecrets {
    proto::LocalBootBoundSecrets {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| proto::LocalBootBoundSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret
                    .bound
                    .map(|bound| proto::LocalBootBinding {
                        binding_id: bound.binding_id,
                        prefix: bound.prefix,
                        hosts: bound.hosts,
                        ..Default::default()
                    })
                    .into(),
                ..Default::default()
            })
            .collect(),
        seal: record.seal,
        ..Default::default()
    }
}

pub(crate) fn record_from_proto(record: proto::LocalBootBoundSecrets) -> PlatformBootRecord {
    PlatformBootRecord {
        secrets: record
            .secrets
            .into_iter()
            .map(|secret| PlatformBootSecret {
                path: secret.path,
                key: secret.key,
                binding_generation: secret.binding_generation,
                bound: secret.bound.into_option().map(|bound| PlatformBootBinding {
                    binding_id: bound.binding_id,
                    prefix: bound.prefix,
                    hosts: bound.hosts,
                }),
            })
            .collect(),
        seal: record.seal,
    }
}

#[cfg(test)]
mod tests;
