//! Public release resolution. Trust and transport admission finish before the
//! ordinary Store receives a candidate. The local VM runtime is fetched only by
//! the digests this cw pins (#2539); this never publishes anything.

use std::collections::BTreeMap;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::os::unix::fs::FileExt as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use codewire_cw_release::identity::{CwPayloadIdentity, Platform, is_sha256_hex};
use codewire_cw_release::local_runtime::{BlobRef, MAX_BLOB_BYTES};
use codewire_cw_release::openpgp::ReleaseKey;
use codewire_cw_release::release::{
    ChannelEnvelope, MAX_JSON_BYTES, MAX_SIGNATURE_BYTES, ObjectRef, ReleaseManifest, release_key,
    valid_release_tag,
};
use codewire_cw_release::store::{Admission, Candidate};
use codewire_local_vmm::runtime_install::{BlobSource, InstallError};

use crate::build_record::admit_incoming;

mod http;
mod scratch;

const TRUST_KEY: &[u8] = include_bytes!("../../../apps/cli/GPG_PUBLIC_KEY.asc");
const TRUST_FINGERPRINT: &str = "A38FF6BC6623FCA611A7A32B5EFBF0F4A5870815";
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// A runtime blob's deadline: a fixed base plus its size at this slowest rate.
const BLOB_BASE_DEADLINE: Duration = Duration::from_secs(30);
const BLOB_MIN_RATE: u64 = 256 * 1024;

pub(crate) enum Selection {
    Version(String),
    Stable,
}

pub(crate) struct FetchedRelease {
    pub(crate) identity: CwPayloadIdentity,
    candidate: Candidate,
    _file: File,
    scratch: Arc<scratch::Scratch>,
}

impl FetchedRelease {
    pub(crate) fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub(crate) fn cleanup(self) -> anyhow::Result<()> {
        self.scratch.cleanup()
    }
}

pub(crate) async fn fetch(selection: Selection, host: Platform) -> anyhow::Result<FetchedRelease> {
    if let Selection::Version(version) = &selection {
        anyhow::ensure!(
            valid_release_tag(version),
            "--version must be a bounded vMAJOR.MINOR.PATCH release tag"
        );
    }
    let http = http::FixedHttp::new()?;
    let scratch = Arc::new(scratch::Scratch::new()?);
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("observe public release termination")?;
    let cancellation = async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("observe public release cancellation"),
            result = termination.recv() => result.context("public release cancellation observer ended"),
        }
    };
    controlled(
        fetch_inner(
            selection,
            host,
            &http,
            scratch.clone(),
            TRUST_KEY,
            TRUST_FINGERPRINT,
        ),
        scratch.clone(),
        TOTAL_TIMEOUT,
        cancellation,
    )
    .await
}

async fn controlled<T>(
    operation: impl Future<Output = anyhow::Result<T>>,
    scratch: Arc<scratch::Scratch>,
    timeout: Duration,
    cancellation: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<T> {
    let result = tokio::select! {
        biased;
        signal = cancellation => {
            signal.and_then(|_| {
                Err(anyhow::anyhow!("the release download was canceled; nothing was installed"))
            })
        }
        result = tokio::time::timeout(timeout, operation) => {
            result.context("public release fetch exceeded its total deadline").and_then(|value| value)
        }
    };
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if scratch.cleanup().is_err() {
                return Err(
                    error.context("public release scratch retained because its cleanup is unknown")
                );
            }
            Err(error)
        }
    }
}

/// The pinned local VM runtime's files, held privately until the installer
/// has admitted them (#2539).
pub(crate) struct FetchedRuntime {
    files: BTreeMap<String, File>,
    scratch: Arc<scratch::Scratch>,
}

impl FetchedRuntime {
    pub(crate) fn cleanup(self) -> anyhow::Result<()> {
        drop(self.files);
        self.scratch.cleanup()
    }
}

impl BlobSource for FetchedRuntime {
    fn open(&self, sha256: &str) -> Result<Box<dyn Read + '_>, InstallError> {
        let file = self
            .files
            .get(sha256)
            .ok_or_else(|| InstallError::MissingBlob {
                sha256: sha256.to_owned(),
            })?;
        Ok(Box::new(HeldReader { file, offset: 0 }))
    }
}

/// Reads a held file from its start without moving its shared offset.
struct HeldReader<'a> {
    file: &'a File,
    offset: u64,
}

impl Read for HeldReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read_at(buffer, self.offset)?;
        self.offset += read as u64;
        Ok(read)
    }
}

fn blob_deadline(size: u64) -> Duration {
    BLOB_BASE_DEADLINE + Duration::from_secs(size / BLOB_MIN_RATE)
}

/// Download exactly the pinned `blobs` from the fixed release origin, each
/// checked for its size and SHA-256 within its own deadline.
pub(crate) async fn fetch_runtime(blobs: &[BlobRef]) -> anyhow::Result<FetchedRuntime> {
    let http = http::FixedHttp::for_blobs()?;
    let scratch = Arc::new(scratch::Scratch::new()?);
    let total = blobs
        .iter()
        .map(|blob| blob_deadline(blob.size))
        .sum::<Duration>()
        + BLOB_BASE_DEADLINE;
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("observe local runtime download termination")?;
    let cancellation = async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("observe local runtime download cancellation"),
            result = termination.recv() => result.context("local runtime download cancellation observer ended"),
        }
    };
    controlled(
        fetch_runtime_inner(blobs, &http, scratch.clone()),
        scratch,
        total,
        cancellation,
    )
    .await
}

async fn fetch_runtime_inner(
    blobs: &[BlobRef],
    http: &http::FixedHttp,
    scratch: Arc<scratch::Scratch>,
) -> anyhow::Result<FetchedRuntime> {
    let mut files = BTreeMap::new();
    for blob in blobs {
        anyhow::ensure!(
            is_sha256_hex(&blob.sha256) && (1..=MAX_BLOB_BYTES).contains(&blob.size),
            "pinned local runtime blob is invalid"
        );
        if files.contains_key(&blob.sha256) {
            continue;
        }
        let mut file = scratch.create(&blob.sha256)?;
        let reference = ObjectRef {
            key: format!("cw/v1/blobs/sha256/{}", blob.sha256),
            sha256: blob.sha256.clone(),
            size: blob.size,
        };
        tokio::time::timeout(
            blob_deadline(blob.size),
            http.blob(&reference, MAX_BLOB_BYTES, &mut file),
        )
        .await
        .with_context(|| format!("download of {} exceeded its deadline", blob.sha256))??;
        scratch.check_file(&file)?;
        files.insert(blob.sha256.clone(), file);
    }
    scratch.check_paths()?;
    Ok(FetchedRuntime { files, scratch })
}

async fn fetch_inner(
    selection: Selection,
    host: Platform,
    http: &http::FixedHttp,
    scratch: Arc<scratch::Scratch>,
    key: &[u8],
    fingerprint: &str,
) -> anyhow::Result<FetchedRelease> {
    let verifier = ReleaseKey::import(key, fingerprint)?;
    let pointer = match &selection {
        Selection::Stable => {
            let bytes = http
                .read("cw/v1/channels/stable.json", MAX_JSON_BYTES, None)
                .await?;
            let channel = ChannelEnvelope::decode(&bytes)?;
            verifier.verify(
                &channel.pointer.signing_bytes()?,
                channel.signature.as_bytes(),
            )?;
            Some(channel.pointer)
        }
        Selection::Version(_) => None,
    };
    let version = match (&selection, &pointer) {
        (Selection::Version(version), _) => version,
        (_, Some(pointer)) => &pointer.release_tag,
        _ => unreachable!("stable selection has an admitted pointer"),
    };
    let bytes = http
        .read(
            &release_key(version, "release.json"),
            MAX_JSON_BYTES,
            pointer.as_ref().map(|value| &value.release),
        )
        .await?;
    let signature = http
        .read(
            &release_key(version, "release.json.asc"),
            MAX_SIGNATURE_BYTES,
            pointer.as_ref().map(|value| &value.release_signature),
        )
        .await?;
    verifier.verify(&bytes, &signature)?;
    let manifest = ReleaseManifest::decode(&bytes)?;
    anyhow::ensure!(
        manifest.release_tag == *version && manifest.signing_fingerprint == fingerprint,
        "signed release tag or signer differs from the requested release"
    );
    let sums = http
        .read(
            &manifest.checksums.file.key,
            MAX_JSON_BYTES,
            Some(&manifest.checksums.file),
        )
        .await?;
    let sums_signature = http
        .read(
            &manifest.checksums.signature.key,
            MAX_SIGNATURE_BYTES,
            Some(&manifest.checksums.signature),
        )
        .await?;
    verifier.verify(&sums, &sums_signature)?;
    manifest.verify_checksums(&sums)?;
    let entry = manifest.target(host);
    let mut file = scratch.create("cw")?;
    http.executable(&entry.executable, &mut file).await?;
    scratch.check_file(&file)?;
    admit_incoming(&mut file, &scratch.path().join("cw"), &entry.identity, host)?;
    scratch.check_paths()?;
    let identity = entry.identity.clone();
    let candidate = Candidate {
        executable: scratch.path().join("cw"),
        admission: Admission::Pinned {
            sha256: identity.sha256.clone(),
            identity: identity.clone(),
        },
    };
    Ok(FetchedRelease {
        identity,
        candidate,
        _file: file,
        scratch,
    })
}

// The synthetic signer is GnuPG with Linux's supervised agent socket layout.
// The verifier's own fixtures and the pure document tests live in
// codewire-cw-release.
#[cfg(all(test, target_os = "linux"))]
mod tests;
