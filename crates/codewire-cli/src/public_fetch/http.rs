//! Fixed-origin, unauthenticated bounded requests. No ambient proxy, cookies,
//! redirects, decompression, credentials, or caller-selected origin.

use std::fs::File;
use std::io::Write as _;
use std::time::Duration;

use anyhow::Context as _;
use codewire_cw_release::identity::{MAX_EXECUTABLE_BYTES, is_sha256_hex};
use codewire_cw_release::release::{ObjectRef, valid_release_tag};
use reqwest::{Client, Response, StatusCode, Url, header};
use sha2::{Digest as _, Sha256};

const ORIGIN: &str = "https://releases.codewire.sh/";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Runtime blobs carry their own size-scaled deadline; this only bounds a
/// request the caller has not.
const BLOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct FixedHttp {
    client: Client,
    origin: Url,
}

impl FixedHttp {
    pub(super) fn new() -> anyhow::Result<Self> {
        Self::build(ORIGIN, true, REQUEST_TIMEOUT, READ_TIMEOUT)
    }

    /// For runtime blobs: the same origin and stall bound, without the
    /// document-sized request deadline.
    pub(super) fn for_blobs() -> anyhow::Result<Self> {
        Self::build(ORIGIN, true, BLOB_REQUEST_TIMEOUT, READ_TIMEOUT)
    }

    fn build(
        origin: &str,
        https_only: bool,
        request_timeout: Duration,
        read_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(request_timeout)
            .read_timeout(read_timeout)
            .build()
            .context("initialize public release HTTPS")?;
        Ok(Self {
            client,
            origin: Url::parse(origin).context("invalid fixed release origin")?,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn synthetic(origin: &str, timeout: Duration) -> anyhow::Result<Self> {
        Self::build(origin, false, timeout, timeout)
    }

    async fn request(&self, key: &str, cap: u64, size: Option<u64>) -> anyhow::Result<Response> {
        anyhow::ensure!(
            admitted_key(key),
            "release object key is outside the closed public routes"
        );
        let url = self
            .origin
            .join(key)
            .context("invalid public release object key")?;
        let response = self
            .client
            .get(url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .context("request public release object")?;
        anyhow::ensure!(
            response.status() == StatusCode::OK && response.url() == &url,
            "public release request did not return an unredirected HTTP200"
        );
        anyhow::ensure!(
            response
                .headers()
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .all(|value| value == "identity"),
            "public release response must not be content-encoded"
        );
        anyhow::ensure!(
            response
                .headers()
                .get_all(header::CONTENT_LENGTH)
                .iter()
                .count()
                <= 1,
            "public release response has ambiguous Content-Length"
        );
        if let Some(length) = response.content_length() {
            anyhow::ensure!(
                length > 0 && length <= cap && size.is_none_or(|expected| length == expected),
                "public release response length differs from its bound or signed size"
            );
        }
        Ok(response)
    }

    pub(super) async fn read(
        &self,
        key: &str,
        cap: usize,
        expected: Option<&ObjectRef>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut response = self
            .request(key, cap as u64, expected.map(|value| value.size))
            .await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read public release object")?
        {
            anyhow::ensure!(
                chunk.len() <= cap.saturating_sub(bytes.len()),
                "public release object exceeds its bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        anyhow::ensure!(!bytes.is_empty(), "public release object is empty");
        if let Some(expected) = expected {
            expected.verify_bytes(&bytes)?;
        }
        Ok(bytes)
    }

    /// Stream a release executable of exactly its signed size. Its identity
    /// admission hashes it afterwards.
    pub(super) async fn executable(
        &self,
        reference: &ObjectRef,
        file: &mut File,
    ) -> anyhow::Result<()> {
        self.stream(reference, MAX_EXECUTABLE_BYTES, file, false)
            .await
    }

    /// Stream one pinned runtime blob, refusing anything but its exact size
    /// and SHA-256.
    pub(super) async fn blob(
        &self,
        reference: &ObjectRef,
        cap: u64,
        file: &mut File,
    ) -> anyhow::Result<()> {
        self.stream(reference, cap, file, true).await
    }

    async fn stream(
        &self,
        reference: &ObjectRef,
        cap: u64,
        file: &mut File,
        check_digest: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(reference.size <= cap, "release object exceeds its bound");
        let mut response = self
            .request(&reference.key, cap, Some(reference.size))
            .await?;
        let mut size = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = response.chunk().await.context("read release object")? {
            let length = chunk.len() as u64;
            anyhow::ensure!(
                length <= reference.size.saturating_sub(size),
                "release object exceeds its pinned size"
            );
            digest.update(&chunk);
            file.write_all(&chunk)
                .context("write held release object")?;
            size += length;
        }
        anyhow::ensure!(
            size == reference.size,
            "release object is shorter than its pinned size"
        );
        anyhow::ensure!(
            !check_digest || format!("{:x}", digest.finalize()) == reference.sha256,
            "release object differs from its pinned SHA-256"
        );
        file.sync_all().context("sync held release object")?;
        Ok(())
    }
}

fn admitted_key(key: &str) -> bool {
    let parts: Vec<_> = key.split('/').collect();
    match parts.as_slice() {
        ["cw", "v1", "channels", "stable.json"] => true,
        ["cw", "v1", "blobs", "sha256", digest] => is_sha256_hex(digest),
        ["cw", "v1", "releases", version, name] => {
            valid_release_tag(version)
                && matches!(
                    *name,
                    "release.json" | "release.json.asc" | "SHA256SUMS" | "SHA256SUMS.asc"
                )
        }
        _ => false,
    }
}
