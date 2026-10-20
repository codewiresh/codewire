use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use oci_spec::image::{Descriptor, ImageConfiguration, ImageIndex, ImageManifest};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION,
    WWW_AUTHENTICATE,
};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{ContentStore, ContentStoreError, RegistryReference, Sha256Digest};
use crate::supervisor_metadata::oci::{
    DescriptorKind, MAXIMUM_DOCUMENT_BYTES, MAXIMUM_LAYERS, MAXIMUM_TOTAL_LAYER_BYTES,
    OciArchitecture, RegistryResolverError, ResolvedDescriptor, ResolvedImage, ResolvedLayer,
    is_index_media_type, is_manifest_media_type, validate_resolved_descriptor,
};
#[cfg(test)]
use crate::supervisor_metadata::oci::{OCI_CONFIG, OCI_INDEX, OCI_LAYER_GZIP, OCI_MANIFEST};

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
const MAXIMUM_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;
const MAXIMUM_MANIFESTS: usize = 256;
const MAXIMUM_REDIRECTS: usize = 3;
/// Each small document (a token or a manifest) has a one-minute deadline. A
/// blob's deadline is sized for a large layer on a slow link, so it completes;
/// each read must also arrive within the idle timeout, which fails a stalled
/// stream (#2952). The same bounds as the runtime download (`public_fetch`).
const DOCUMENT_TIMEOUT: Duration = Duration::from_secs(60);
const BLOB_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A blob whose transfer breaks (a reset or a stalled stream) is fetched
/// again from the start, at most this many times in all, within one create.
const BLOB_ATTEMPTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

impl ResolvedImage {
    pub fn verify_cached(&self, store: &ContentStore) -> Result<(), RegistryResolverError> {
        self.validate_metadata()?;
        let source_bytes = store.read_blob(
            &self.source.digest,
            self.source.size,
            MAXIMUM_DOCUMENT_BYTES,
        )?;
        if is_index_media_type(&self.source.media_type) {
            let index = ImageIndex::from_reader(source_bytes.as_slice())
                .map_err(|_| RegistryResolverError::InvalidIndex)?;
            validate_index(&index)?;
            if select_platform_manifest(&index, self.architecture)? != self.manifest {
                return Err(RegistryResolverError::DescriptorMismatch);
            }
        }
        let manifest_bytes = store.read_blob(
            &self.manifest.digest,
            self.manifest.size,
            MAXIMUM_DOCUMENT_BYTES,
        )?;
        let manifest = ImageManifest::from_reader(manifest_bytes.as_slice())
            .map_err(|_| RegistryResolverError::InvalidManifest)?;
        let (manifest_config, manifest_layers) =
            validate_manifest(&manifest, &self.manifest.media_type)?;
        if manifest_config != self.config
            || manifest_layers.len() != self.layers.len()
            || manifest_layers
                .iter()
                .zip(&self.layers)
                .any(|(manifest, resolved)| manifest != &resolved.descriptor)
        {
            return Err(RegistryResolverError::DescriptorMismatch);
        }
        let config_bytes = store.read_blob(
            &self.config.digest,
            self.config.size,
            MAXIMUM_DOCUMENT_BYTES,
        )?;
        let diff_ids = validate_image_configuration(&config_bytes, self.architecture)?;
        if diff_ids.len() != self.layers.len() {
            return Err(RegistryResolverError::InvalidConfiguration);
        }
        for (layer, diff_id) in self.layers.iter().zip(diff_ids) {
            if layer.diff_id != diff_id {
                return Err(RegistryResolverError::InvalidConfiguration);
            }
            store.open_blob(&layer.descriptor.digest, layer.descriptor.size)?;
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
    pub(crate) fn from_cached_source(
        source_reference: String,
        architecture: OciArchitecture,
        source: ResolvedDescriptor,
        store: &ContentStore,
    ) -> Result<Self, RegistryResolverError> {
        validate_resolved_descriptor(&source, DescriptorKind::Source)?;
        let source_bytes = store.read_blob(&source.digest, source.size, MAXIMUM_DOCUMENT_BYTES)?;
        let manifest = if is_index_media_type(&source.media_type) {
            let index = ImageIndex::from_reader(source_bytes.as_slice())
                .map_err(|_| RegistryResolverError::InvalidIndex)?;
            validate_index(&index)?;
            select_platform_manifest(&index, architecture)?
        } else {
            source.clone()
        };
        let manifest_bytes =
            store.read_blob(&manifest.digest, manifest.size, MAXIMUM_DOCUMENT_BYTES)?;
        let decoded = ImageManifest::from_reader(manifest_bytes.as_slice())
            .map_err(|_| RegistryResolverError::InvalidManifest)?;
        let (config, layer_descriptors) = validate_manifest(&decoded, &manifest.media_type)?;
        let config_bytes = store.read_blob(&config.digest, config.size, MAXIMUM_DOCUMENT_BYTES)?;
        let diff_ids = validate_image_configuration(&config_bytes, architecture)?;
        if diff_ids.len() != layer_descriptors.len() {
            return Err(RegistryResolverError::InvalidConfiguration);
        }
        let layers = layer_descriptors
            .into_iter()
            .zip(diff_ids)
            .map(|(descriptor, diff_id)| ResolvedLayer {
                descriptor,
                diff_id,
            })
            .collect();
        let image = Self {
            source_reference,
            architecture,
            source,
            manifest,
            config,
            layers,
        };
        image.verify_cached(store)?;
        Ok(image)
    }
}

#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
pub(crate) fn source_descriptor_from_oci(
    descriptor: &Descriptor,
) -> Result<ResolvedDescriptor, RegistryResolverError> {
    descriptor_from_oci(descriptor, DescriptorKind::Source)
}

#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
pub(crate) fn validate_layout_index(index: &ImageIndex) -> Result<(), RegistryResolverError> {
    validate_index(index)
}

pub struct RegistryResolver<'a> {
    client: Client,
    document_timeout: Duration,
    store: &'a ContentStore,
    // Every blob this resolver found verified in the store or admitted to it,
    // so a caller can keep a failed pull's downloads as cache (#2952).
    verified: std::sync::Mutex<BTreeMap<Sha256Digest, u64>>,
    architecture: OciArchitecture,
    base_override: Option<Url>,
    allow_plain_http: bool,
}

impl std::fmt::Debug for RegistryResolver<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryResolver")
            .field("architecture", &self.architecture)
            .field("base_override", &self.base_override)
            .field("allow_plain_http", &self.allow_plain_http)
            .finish_non_exhaustive()
    }
}

impl<'a> RegistryResolver<'a> {
    pub fn new(store: &'a ContentStore) -> Result<Self, RegistryResolverError> {
        Ok(Self {
            client: registry_client(true, READ_TIMEOUT)?,
            document_timeout: DOCUMENT_TIMEOUT,
            store,
            verified: Default::default(),
            architecture: OciArchitecture::native()?,
            base_override: None,
            allow_plain_http: false,
        })
    }

    #[cfg(test)]
    fn for_test(
        store: &'a ContentStore,
        base: Url,
        architecture: OciArchitecture,
    ) -> Result<Self, RegistryResolverError> {
        Self::for_test_with_timeouts(store, base, architecture, DOCUMENT_TIMEOUT, READ_TIMEOUT)
    }

    #[cfg(test)]
    fn for_test_with_timeouts(
        store: &'a ContentStore,
        base: Url,
        architecture: OciArchitecture,
        document_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, RegistryResolverError> {
        Ok(Self {
            client: registry_client(false, read_timeout)?,
            document_timeout,
            store,
            verified: Default::default(),
            architecture,
            base_override: Some(base),
            allow_plain_http: true,
        })
    }

    /// The blobs this resolver found verified or admitted, whether or not its
    /// resolution succeeded.
    pub fn verified_blobs(&self) -> BTreeMap<Sha256Digest, u64> {
        self.verified
            .lock()
            .map(|verified| verified.clone())
            .unwrap_or_default()
    }

    fn record_verified(&self, digest: &Sha256Digest, size: u64) {
        if let Ok(mut verified) = self.verified.lock() {
            verified.insert(digest.clone(), size);
        }
    }

    pub async fn resolve_anonymous(
        &self,
        image: &RegistryReference,
    ) -> Result<ResolvedImage, RegistryResolverError> {
        let base = match &self.base_override {
            Some(base) => base.clone(),
            None => image.distribution_base_url()?,
        };
        validate_transport_url(&base, self.allow_plain_http, true)?;
        let manifest_url = distribution_url(
            &base,
            image.repository(),
            "manifests",
            image.manifest_reference(),
        )?;
        let first = self.send_manifest(&manifest_url, None).await?;
        let (response, bearer) = if first.status() == StatusCode::UNAUTHORIZED {
            let challenge =
                bearer_challenge(first.headers(), image.repository(), self.allow_plain_http)?;
            let token = self.fetch_anonymous_token(challenge).await?;
            let response = self.send_manifest(&manifest_url, Some(&token)).await?;
            (response, Some(token))
        } else {
            (first, None)
        };
        let mut document = self
            .admit_manifest_response(response, image.digest(), None)
            .await?;
        let source_descriptor = document.descriptor.clone();

        if is_index_media_type(&document.descriptor.media_type) {
            let index = ImageIndex::from_reader(document.bytes.as_slice())
                .map_err(|_| RegistryResolverError::InvalidIndex)?;
            validate_index(&index)?;
            let selected = select_platform_manifest(&index, self.architecture)?;
            let selected_url = distribution_url(
                &base,
                image.repository(),
                "manifests",
                selected.digest.as_str(),
            )?;
            let response = self.send_manifest(&selected_url, bearer.as_ref()).await?;
            document = self
                .admit_manifest_response(response, Some(&selected.digest), Some(&selected))
                .await?;
        }
        if !is_manifest_media_type(&document.descriptor.media_type) {
            return Err(RegistryResolverError::UnsupportedMediaType);
        }
        let manifest = ImageManifest::from_reader(document.bytes.as_slice())
            .map_err(|_| RegistryResolverError::InvalidManifest)?;
        let (config, layers) = validate_manifest(&manifest, &document.descriptor.media_type)?;

        self.fetch_blob(&base, image.repository(), &config, bearer.as_ref())
            .await?;
        let config_bytes =
            self.store
                .read_blob(&config.digest, config.size, MAXIMUM_DOCUMENT_BYTES)?;
        let diff_ids = validate_image_configuration(&config_bytes, self.architecture)?;
        if diff_ids.len() != layers.len() {
            return Err(RegistryResolverError::InvalidConfiguration);
        }
        let mut resolved_layers = Vec::with_capacity(layers.len());
        for (layer, diff_id) in layers.into_iter().zip(diff_ids) {
            self.fetch_blob(&base, image.repository(), &layer, bearer.as_ref())
                .await?;
            resolved_layers.push(ResolvedLayer {
                descriptor: layer,
                diff_id,
            });
        }
        let resolved = ResolvedImage {
            source_reference: image.original().to_owned(),
            architecture: self.architecture,
            source: source_descriptor,
            manifest: document.descriptor,
            config,
            layers: resolved_layers,
        };
        resolved.verify_cached(self.store)?;
        Ok(resolved)
    }

    async fn send_manifest(
        &self,
        url: &Url,
        bearer: Option<&BearerToken>,
    ) -> Result<Response, RegistryResolverError> {
        let mut request = self
            .client
            .get(url.clone())
            .header(ACCEPT, MANIFEST_ACCEPT)
            .timeout(self.document_timeout);
        if let Some(bearer) = bearer {
            request = request.header(AUTHORIZATION, bearer.header_value()?);
        }
        request
            .send()
            .await
            .map_err(|_| RegistryResolverError::Transport)
    }

    async fn admit_manifest_response(
        &self,
        response: Response,
        expected_digest: Option<&Sha256Digest>,
        expected_descriptor: Option<&ResolvedDescriptor>,
    ) -> Result<FetchedDocument, RegistryResolverError> {
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status()));
        }
        let media_type = response_media_type(response.headers())?;
        if !is_index_media_type(&media_type) && !is_manifest_media_type(&media_type) {
            return Err(RegistryResolverError::UnsupportedMediaType);
        }
        let header_digest = response
            .headers()
            .get("docker-content-digest")
            .map(parse_digest_header)
            .transpose()?;
        let bytes = bounded_response_body(response, MAXIMUM_DOCUMENT_BYTES).await?;
        let size =
            u64::try_from(bytes.len()).map_err(|_| RegistryResolverError::DocumentTooLarge)?;
        let digest = Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(&bytes)))?;
        if expected_digest.is_some_and(|expected| expected != &digest)
            || header_digest
                .as_ref()
                .is_some_and(|header| header != &digest)
        {
            return Err(RegistryResolverError::DigestMismatch);
        }
        if let Some(expected) = expected_descriptor
            && (expected.digest != digest
                || expected.size != size
                || expected.media_type != media_type)
        {
            return Err(RegistryResolverError::DescriptorMismatch);
        }
        self.store
            .admit_bytes(&digest, Bytes::copy_from_slice(&bytes))
            .await?;
        self.record_verified(&digest, size);
        Ok(FetchedDocument {
            descriptor: ResolvedDescriptor {
                media_type,
                digest,
                size,
            },
            bytes,
        })
    }

    async fn fetch_blob(
        &self,
        base: &Url,
        repository: &str,
        descriptor: &ResolvedDescriptor,
        bearer: Option<&BearerToken>,
    ) -> Result<(), RegistryResolverError> {
        if self
            .store
            .contains_verified(&descriptor.digest, descriptor.size)?
        {
            self.record_verified(&descriptor.digest, descriptor.size);
            return Ok(());
        }
        let mut attempt = 1;
        loop {
            match self
                .fetch_blob_once(base, repository, descriptor, bearer)
                .await
            {
                Err(
                    RegistryResolverError::Transport
                    | RegistryResolverError::Content(ContentStoreError::Stream),
                ) if attempt < BLOB_ATTEMPTS => attempt += 1,
                Ok(()) => {
                    self.record_verified(&descriptor.digest, descriptor.size);
                    return Ok(());
                }
                result => return result,
            }
        }
    }

    async fn fetch_blob_once(
        &self,
        base: &Url,
        repository: &str,
        descriptor: &ResolvedDescriptor,
        bearer: Option<&BearerToken>,
    ) -> Result<(), RegistryResolverError> {
        let mut url = distribution_url(base, repository, "blobs", descriptor.digest.as_str())?;
        let mut response = self.send_blob(&url, bearer).await?;
        for _ in 0..MAXIMUM_REDIRECTS {
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(RegistryResolverError::UnsafeRedirect)?;
                url = url
                    .join(location)
                    .map_err(|_| RegistryResolverError::UnsafeRedirect)?;
                validate_transport_url(&url, self.allow_plain_http, false)?;
                response = self.send_blob(&url, None).await?;
                continue;
            }
            break;
        }
        if response.status().is_redirection() {
            return Err(RegistryResolverError::TooManyRedirects);
        }
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status()));
        }
        if let Some(length) = response.content_length()
            && length != descriptor.size
        {
            return Err(RegistryResolverError::DescriptorMismatch);
        }
        self.store
            .admit_stream(&descriptor.digest, descriptor.size, response.bytes_stream())
            .await?;
        Ok(())
    }

    async fn send_blob(
        &self,
        url: &Url,
        bearer: Option<&BearerToken>,
    ) -> Result<Response, RegistryResolverError> {
        let mut request = self.client.get(url.clone()).timeout(BLOB_TIMEOUT);
        if let Some(bearer) = bearer {
            request = request.header(AUTHORIZATION, bearer.header_value()?);
        }
        request
            .send()
            .await
            .map_err(|_| RegistryResolverError::Transport)
    }

    async fn fetch_anonymous_token(
        &self,
        challenge: BearerChallenge,
    ) -> Result<BearerToken, RegistryResolverError> {
        let mut url = challenge.realm;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = challenge.service {
                query.append_pair("service", &service);
            }
            query.append_pair("scope", &challenge.scope);
        }
        let response = self
            .client
            .get(url)
            .timeout(self.document_timeout)
            .send()
            .await
            .map_err(|_| RegistryResolverError::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(RegistryResolverError::AuthenticationFailed);
        }
        let bytes =
            Zeroizing::new(bounded_response_body(response, MAXIMUM_TOKEN_RESPONSE_BYTES).await?);
        let response: AnonymousTokenResponse<'_> = serde_json::from_slice(&bytes)
            .map_err(|_| RegistryResolverError::AuthenticationFailed)?;
        let token = match (response.token, response.access_token) {
            (Some(first), Some(second)) if first == second => first,
            (Some(token), None) | (None, Some(token)) => token,
            _ => return Err(RegistryResolverError::AuthenticationFailed),
        };
        BearerToken::new(token)
    }
}

fn registry_client(
    https_only: bool,
    read_timeout: Duration,
) -> Result<Client, RegistryResolverError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(https_only)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(read_timeout)
        .user_agent("codewire-local-vmm/1")
        .build()
        .map_err(|_| RegistryResolverError::Client)
}

struct FetchedDocument {
    descriptor: ResolvedDescriptor,
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct AnonymousTokenResponse<'a> {
    #[serde(borrow)]
    token: Option<&'a str>,
    #[serde(borrow)]
    access_token: Option<&'a str>,
}

struct BearerToken(Zeroizing<String>);

impl BearerToken {
    fn new(value: &str) -> Result<Self, RegistryResolverError> {
        if value.is_empty()
            || value.len() > 16 * 1024
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(RegistryResolverError::AuthenticationFailed);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    fn header_value(&self) -> Result<HeaderValue, RegistryResolverError> {
        let mut value = Zeroizing::new(String::with_capacity(self.0.len() + 7));
        value.push_str("Bearer ");
        value.push_str(&self.0);
        HeaderValue::from_str(&value).map_err(|_| RegistryResolverError::AuthenticationFailed)
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

struct BearerChallenge {
    realm: Url,
    service: Option<String>,
    scope: String,
}

fn bearer_challenge(
    headers: &HeaderMap,
    repository: &str,
    allow_plain_http: bool,
) -> Result<BearerChallenge, RegistryResolverError> {
    let mut values = headers.get_all(WWW_AUTHENTICATE).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(RegistryResolverError::AuthenticationRequired)?;
    if values.next().is_some() {
        return Err(RegistryResolverError::AuthenticationRequired);
    }
    let parameters = parse_auth_parameters(
        value
            .strip_prefix("Bearer ")
            .ok_or(RegistryResolverError::AuthenticationRequired)?,
    )?;
    let realm = parameters
        .get("realm")
        .ok_or(RegistryResolverError::AuthenticationRequired)?;
    let realm = Url::parse(realm).map_err(|_| RegistryResolverError::AuthenticationRequired)?;
    validate_transport_url(&realm, allow_plain_http, false)?;
    let expected_scope = format!("repository:{repository}:pull");
    if parameters
        .get("scope")
        .is_some_and(|scope| scope != &expected_scope)
    {
        return Err(RegistryResolverError::AuthenticationRequired);
    }
    let service = parameters.get("service").cloned();
    if service.as_ref().is_some_and(|service| {
        service.is_empty()
            || service.len() > 256
            || service.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(RegistryResolverError::AuthenticationRequired);
    }
    Ok(BearerChallenge {
        realm,
        service,
        scope: expected_scope,
    })
}

fn parse_auth_parameters(input: &str) -> Result<BTreeMap<String, String>, RegistryResolverError> {
    let bytes = input.as_bytes();
    let mut offset = 0;
    let mut result = BTreeMap::new();
    while offset < bytes.len() {
        while offset < bytes.len() && matches!(bytes[offset], b' ' | b',') {
            offset += 1;
        }
        let key_start = offset;
        while offset < bytes.len() && bytes[offset].is_ascii_alphanumeric() {
            offset += 1;
        }
        if key_start == offset || bytes.get(offset) != Some(&b'=') {
            return Err(RegistryResolverError::AuthenticationRequired);
        }
        let key = input[key_start..offset].to_ascii_lowercase();
        offset += 1;
        if bytes.get(offset) != Some(&b'"') {
            return Err(RegistryResolverError::AuthenticationRequired);
        }
        offset += 1;
        let mut value = String::new();
        let mut closed = false;
        while offset < bytes.len() {
            match bytes[offset] {
                b'"' => {
                    offset += 1;
                    closed = true;
                    break;
                }
                b'\\' => {
                    offset += 1;
                    let escaped = *bytes
                        .get(offset)
                        .filter(|byte| matches!(byte, b'"' | b'\\'))
                        .ok_or(RegistryResolverError::AuthenticationRequired)?;
                    value.push(char::from(escaped));
                    offset += 1;
                }
                byte if byte.is_ascii_control() => {
                    return Err(RegistryResolverError::AuthenticationRequired);
                }
                byte => {
                    value.push(char::from(byte));
                    offset += 1;
                }
            }
        }
        if !closed || result.insert(key, value).is_some() {
            return Err(RegistryResolverError::AuthenticationRequired);
        }
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        if offset < bytes.len() && bytes[offset] != b',' {
            return Err(RegistryResolverError::AuthenticationRequired);
        }
    }
    if result
        .keys()
        .any(|key| !matches!(key.as_str(), "realm" | "service" | "scope"))
    {
        return Err(RegistryResolverError::AuthenticationRequired);
    }
    Ok(result)
}

fn select_platform_manifest(
    index: &ImageIndex,
    architecture: OciArchitecture,
) -> Result<ResolvedDescriptor, RegistryResolverError> {
    let mut selected = None;
    for descriptor in index.manifests() {
        let Some(platform) = descriptor.platform() else {
            continue;
        };
        if platform.os().to_string() != "linux"
            || platform.architecture().to_string() != architecture.as_str()
            || !architecture.admits_variant(platform.variant().as_deref())
            || platform
                .os_features()
                .as_ref()
                .is_some_and(|features| !features.is_empty())
            || platform
                .features()
                .as_ref()
                .is_some_and(|features| !features.is_empty())
        {
            continue;
        }
        let candidate = descriptor_from_oci(descriptor, DescriptorKind::Manifest)?;
        if selected.replace(candidate).is_some() {
            return Err(RegistryResolverError::AmbiguousPlatform);
        }
    }
    selected.ok_or(RegistryResolverError::PlatformUnavailable)
}

fn validate_index(index: &ImageIndex) -> Result<(), RegistryResolverError> {
    if index.schema_version() != 2
        || index.manifests().is_empty()
        || index.manifests().len() > MAXIMUM_MANIFESTS
        || index.artifact_type().is_some()
        || index.subject().is_some()
    {
        return Err(RegistryResolverError::InvalidIndex);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ImageManifest,
    received_media_type: &str,
) -> Result<(ResolvedDescriptor, Vec<ResolvedDescriptor>), RegistryResolverError> {
    if manifest.schema_version() != 2
        || manifest.artifact_type().is_some()
        || manifest.subject().is_some()
        || manifest.layers().len() > MAXIMUM_LAYERS
        || manifest
            .media_type()
            .as_ref()
            .is_some_and(|media| media.as_ref() != received_media_type)
    {
        return Err(RegistryResolverError::InvalidManifest);
    }
    let config = descriptor_from_oci(manifest.config(), DescriptorKind::Config)?;
    let mut layers = Vec::with_capacity(manifest.layers().len());
    let mut total = 0_u64;
    for descriptor in manifest.layers() {
        let layer = descriptor_from_oci(descriptor, DescriptorKind::Layer)?;
        total = total
            .checked_add(layer.size)
            .ok_or(RegistryResolverError::ImageTooLarge)?;
        if total > MAXIMUM_TOTAL_LAYER_BYTES {
            return Err(RegistryResolverError::ImageTooLarge);
        }
        layers.push(layer);
    }
    Ok((config, layers))
}

fn descriptor_from_oci(
    descriptor: &Descriptor,
    kind: DescriptorKind,
) -> Result<ResolvedDescriptor, RegistryResolverError> {
    if descriptor.urls().is_some()
        || descriptor.data().is_some()
        || descriptor.artifact_type().is_some()
    {
        return Err(RegistryResolverError::InvalidDescriptor);
    }
    let digest = descriptor
        .as_digest_sha256()
        .ok_or(RegistryResolverError::UnsupportedDigest)?;
    let resolved = ResolvedDescriptor {
        media_type: descriptor.media_type().as_ref().to_owned(),
        digest: Sha256Digest::parse(&format!("sha256:{digest}"))?,
        size: descriptor.size(),
    };
    validate_resolved_descriptor(&resolved, kind)?;
    Ok(resolved)
}

fn validate_image_configuration(
    bytes: &[u8],
    architecture: OciArchitecture,
) -> Result<Vec<Sha256Digest>, RegistryResolverError> {
    let configuration = ImageConfiguration::from_reader(bytes)
        .map_err(|_| RegistryResolverError::InvalidConfiguration)?;
    if configuration.os().to_string() != "linux"
        || configuration.architecture().to_string() != architecture.as_str()
        || !architecture.admits_variant(configuration.variant().as_deref())
        || configuration.rootfs().typ() != "layers"
        || configuration
            .os_features()
            .as_ref()
            .is_some_and(|features| !features.is_empty())
    {
        return Err(RegistryResolverError::UnsupportedPlatform);
    }
    configuration
        .rootfs()
        .diff_ids()
        .iter()
        .map(|digest| Sha256Digest::parse(digest).map_err(Into::into))
        .collect()
}

fn distribution_url(
    base: &Url,
    repository: &str,
    collection: &str,
    reference: &str,
) -> Result<Url, RegistryResolverError> {
    let mut url = base.clone();
    url.set_path(&format!("/v2/{repository}/{collection}/{reference}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn validate_transport_url(
    url: &Url,
    allow_plain_http: bool,
    require_root_path: bool,
) -> Result<(), RegistryResolverError> {
    let plain_http_allowed = allow_plain_http
        && url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if (url.scheme() != "https" && !plain_http_allowed)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.fragment().is_some()
        || (require_root_path && url.path() != "/")
    {
        return Err(RegistryResolverError::UnsafeUrl);
    }
    Ok(())
}

fn response_media_type(headers: &HeaderMap) -> Result<String, RegistryResolverError> {
    let value = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(RegistryResolverError::UnsupportedMediaType)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.is_empty() || media_type.len() > 256 {
        return Err(RegistryResolverError::UnsupportedMediaType);
    }
    Ok(media_type.to_owned())
}

fn parse_digest_header(value: &HeaderValue) -> Result<Sha256Digest, RegistryResolverError> {
    value
        .to_str()
        .ok()
        .and_then(|value| Sha256Digest::parse(value).ok())
        .ok_or(RegistryResolverError::DigestMismatch)
}

async fn bounded_response_body(
    response: Response,
    maximum: u64,
) -> Result<Vec<u8>, RegistryResolverError> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|size| size > maximum)
    {
        return Err(RegistryResolverError::DocumentTooLarge);
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    let mut length = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RegistryResolverError::Transport)?;
        length = length
            .checked_add(
                u64::try_from(chunk.len()).map_err(|_| RegistryResolverError::DocumentTooLarge)?,
            )
            .ok_or(RegistryResolverError::DocumentTooLarge)?;
        if length > maximum {
            return Err(RegistryResolverError::DocumentTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn status_error(status: StatusCode) -> RegistryResolverError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            RegistryResolverError::AuthenticationFailed
        }
        StatusCode::NOT_FOUND => RegistryResolverError::NotFound,
        _ => RegistryResolverError::RegistryResponse,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::host::path::PrivateRoot;

    struct Fixture {
        _parent: tempfile::TempDir,
        store: ContentStore,
        config: Vec<u8>,
        config_digest: Sha256Digest,
        layer: Vec<u8>,
        layer_digest: Sha256Digest,
        diff_id: Sha256Digest,
        manifest: Vec<u8>,
        manifest_digest: Sha256Digest,
        index: Vec<u8>,
        index_digest: Sha256Digest,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = tempfile::tempdir().unwrap();
            let root_path = parent.path().join("runtime");
            fs::create_dir(&root_path).unwrap();
            fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
            let root = PrivateRoot::open(&root_path).unwrap();
            let store = ContentStore::create(&root).unwrap();

            let layer = b"synthetic-compressed-layer".to_vec();
            let layer_digest = digest(&layer);
            let diff_id = digest(b"synthetic-uncompressed-layer");
            let config = serde_json::to_vec(&json!({
                "architecture": "amd64",
                "os": "linux",
                "config": {
                    "Env": ["PATH=/usr/bin:/bin"],
                    "Cmd": ["/bin/sh"]
                },
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [diff_id.as_str()]
                },
                "history": []
            }))
            .unwrap();
            let config_digest = digest(&config);
            let manifest = serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {
                    "mediaType": OCI_CONFIG,
                    "digest": config_digest.as_str(),
                    "size": config.len()
                },
                "layers": [{
                    "mediaType": OCI_LAYER_GZIP,
                    "digest": layer_digest.as_str(),
                    "size": layer.len()
                }]
            }))
            .unwrap();
            let manifest_digest = digest(&manifest);
            let other_manifest = digest(b"other-platform-manifest");
            let index = serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": [
                    {
                        "mediaType": OCI_MANIFEST,
                        "digest": other_manifest.as_str(),
                        "size": 23,
                        "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}
                    },
                    {
                        "mediaType": OCI_MANIFEST,
                        "digest": manifest_digest.as_str(),
                        "size": manifest.len(),
                        "platform": {"os": "linux", "architecture": "amd64"}
                    }
                ]
            }))
            .unwrap();
            let index_digest = digest(&index);
            Self {
                _parent: parent,
                store,
                config,
                config_digest,
                layer,
                layer_digest,
                diff_id,
                manifest,
                manifest_digest,
                index,
                index_digest,
            }
        }
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
    }

    fn document_response(
        media_type: &str,
        digest: &Sha256Digest,
        bytes: &[u8],
    ) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header("content-type", media_type)
            .insert_header("docker-content-digest", digest.as_str())
            .set_body_bytes(bytes.to_vec())
    }

    async fn mount_authenticated_fixture(server: &MockServer, fixture: &Fixture) {
        let challenge = format!(
            "Bearer realm=\"{}/token\",service=\"registry.test\",scope=\"repository:test/workspace:pull\"",
            server.uri()
        );
        Mock::given(method("GET"))
            .and(path("/v2/test/workspace/manifests/latest"))
            .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", challenge))
            .with_priority(2)
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("service", "registry.test"))
            .and(query_param("scope", "repository:test/workspace:pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "synthetic-bearer"
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/test/workspace/manifests/latest"))
            .and(header("authorization", "Bearer synthetic-bearer"))
            .respond_with(document_response(
                OCI_INDEX,
                &fixture.index_digest,
                &fixture.index,
            ))
            .with_priority(1)
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/test/workspace/manifests/{}",
                fixture.manifest_digest
            )))
            .and(header("authorization", "Bearer synthetic-bearer"))
            .respond_with(document_response(
                OCI_MANIFEST,
                &fixture.manifest_digest,
                &fixture.manifest,
            ))
            .expect(1)
            .mount(server)
            .await;
        for (descriptor, body) in [
            (&fixture.config_digest, fixture.config.as_slice()),
            (&fixture.layer_digest, fixture.layer.as_slice()),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v2/test/workspace/blobs/{descriptor}")))
                .and(header("authorization", "Bearer synthetic-bearer"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
                .expect(1)
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn bearer_index_resolution_admits_only_verified_native_content() {
        let fixture = Fixture::new();
        let server = MockServer::start().await;
        mount_authenticated_fixture(&server, &fixture).await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let resolver =
            RegistryResolver::for_test(&fixture.store, base, OciArchitecture::Amd64).unwrap();
        let reference = RegistryReference::parse("registry.test/test/workspace:latest").unwrap();

        let resolved = resolver.resolve_anonymous(&reference).await.unwrap();
        assert_eq!(resolved.source.digest, fixture.index_digest);
        assert_eq!(resolved.manifest.digest, fixture.manifest_digest);
        assert_eq!(resolved.config.digest, fixture.config_digest);
        assert_eq!(resolved.layers[0].descriptor.digest, fixture.layer_digest);
        assert_eq!(resolved.layers[0].diff_id, fixture.diff_id);
        resolved.verify_cached(&fixture.store).unwrap();
        let encoded = serde_json::to_vec(&resolved).unwrap();
        let decoded: ResolvedImage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, resolved);
        decoded.verify_cached(&fixture.store).unwrap();
    }

    #[tokio::test]
    async fn digest_mismatch_fails_without_admitting_the_blob() {
        let fixture = Fixture::new();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/test/workspace/manifests/latest"))
            .respond_with(document_response(
                OCI_MANIFEST,
                &fixture.manifest_digest,
                &fixture.manifest,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/test/workspace/blobs/{}",
                fixture.config_digest
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture.config.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/test/workspace/blobs/{}",
                fixture.layer_digest
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; fixture.layer.len()]),
            )
            .mount(&server)
            .await;
        let resolver = RegistryResolver::for_test(
            &fixture.store,
            Url::parse(&format!("{}/", server.uri())).unwrap(),
            OciArchitecture::Amd64,
        )
        .unwrap();
        let reference = RegistryReference::parse("registry.test/test/workspace:latest").unwrap();

        assert!(matches!(
            resolver.resolve_anonymous(&reference).await,
            Err(RegistryResolverError::Content(
                ContentStoreError::DigestMismatch
            ))
        ));
        assert!(
            !fixture
                .store
                .contains_verified(&fixture.layer_digest, fixture.layer.len() as u64)
                .unwrap()
        );
        // The failed pull still reports what it verified, for the download
        // cache (#2952), and never the layer it refused.
        let verified = resolver.verified_blobs();
        assert_eq!(
            verified.get(&fixture.manifest_digest),
            Some(&(fixture.manifest.len() as u64))
        );
        assert_eq!(
            verified.get(&fixture.config_digest),
            Some(&(fixture.config.len() as u64))
        );
        assert!(!verified.contains_key(&fixture.layer_digest));
    }

    #[tokio::test]
    async fn blob_redirect_never_forwards_the_registry_bearer() {
        let fixture = Fixture::new();
        let registry = MockServer::start().await;
        let destination = MockServer::start().await;
        let redirected_path = "/redirected-layer";
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/test/workspace/blobs/{}",
                fixture.layer_digest
            )))
            .and(header("authorization", "Bearer synthetic-bearer"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "location",
                format!("{}{redirected_path}", destination.uri()),
            ))
            .expect(1)
            .mount(&registry)
            .await;
        Mock::given(method("GET"))
            .and(path(redirected_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture.layer.clone()))
            .expect(1)
            .mount(&destination)
            .await;
        let base = Url::parse(&format!("{}/", registry.uri())).unwrap();
        let resolver =
            RegistryResolver::for_test(&fixture.store, base.clone(), OciArchitecture::Amd64)
                .unwrap();
        let descriptor = ResolvedDescriptor {
            media_type: OCI_LAYER_GZIP.to_owned(),
            digest: fixture.layer_digest.clone(),
            size: fixture.layer.len() as u64,
        };
        let bearer = BearerToken::new("synthetic-bearer").unwrap();

        resolver
            .fetch_blob(&base, "test/workspace", &descriptor, Some(&bearer))
            .await
            .unwrap();
        let redirected_requests = destination.received_requests().await.unwrap();
        assert_eq!(redirected_requests.len(), 1);
        assert!(!redirected_requests[0].headers.contains_key("authorization"));
    }

    /// Answers every request with `body` in `pieces` writes, each after `gap`.
    /// The first `broken` connections close after the first piece.
    async fn drip_server(
        body: Vec<u8>,
        pieces: usize,
        gap: Duration,
        broken: usize,
    ) -> (Url, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body = body.clone();
                let breaks = counted.fetch_add(1, Ordering::SeqCst) < broken;
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for piece in body.chunks(body.len().div_ceil(pieces)) {
                        tokio::time::sleep(gap).await;
                        if socket.write_all(piece).await.is_err() || breaks {
                            return;
                        }
                    }
                });
            }
        });
        (
            Url::parse(&format!("http://{address}/")).unwrap(),
            connections,
        )
    }

    fn layer_descriptor(fixture: &Fixture) -> ResolvedDescriptor {
        ResolvedDescriptor {
            media_type: OCI_LAYER_GZIP.to_owned(),
            digest: fixture.layer_digest.clone(),
            size: fixture.layer.len() as u64,
        }
    }

    #[tokio::test]
    async fn a_slow_blob_outlasts_the_document_deadline_while_it_keeps_arriving() {
        // A large layer on a slow link takes longer than a document may, but
        // each read arrives within the idle timeout (#2952).
        let fixture = Fixture::new();
        let (base, _) = drip_server(fixture.layer.clone(), 6, Duration::from_millis(150), 0).await;
        let resolver = RegistryResolver::for_test_with_timeouts(
            &fixture.store,
            base.clone(),
            OciArchitecture::Amd64,
            Duration::from_millis(300),
            Duration::from_millis(600),
        )
        .unwrap();

        resolver
            .fetch_blob(&base, "test/workspace", &layer_descriptor(&fixture), None)
            .await
            .unwrap();
        assert!(
            fixture
                .store
                .contains_verified(&fixture.layer_digest, fixture.layer.len() as u64)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_broken_blob_transfer_is_fetched_again_from_the_start() {
        let fixture = Fixture::new();
        let (base, connections) = drip_server(
            fixture.layer.clone(),
            2,
            Duration::from_millis(10),
            BLOB_ATTEMPTS - 1,
        )
        .await;
        let resolver =
            RegistryResolver::for_test(&fixture.store, base.clone(), OciArchitecture::Amd64)
                .unwrap();

        resolver
            .fetch_blob(&base, "test/workspace", &layer_descriptor(&fixture), None)
            .await
            .unwrap();
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            BLOB_ATTEMPTS
        );
        assert!(
            fixture
                .store
                .contains_verified(&fixture.layer_digest, fixture.layer.len() as u64)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_stalled_blob_stream_fails_without_admitting_the_blob() {
        let fixture = Fixture::new();
        let (base, connections) =
            drip_server(fixture.layer.clone(), 2, Duration::from_secs(5), 0).await;
        let resolver = RegistryResolver::for_test_with_timeouts(
            &fixture.store,
            base.clone(),
            OciArchitecture::Amd64,
            DOCUMENT_TIMEOUT,
            Duration::from_millis(300),
        )
        .unwrap();

        // Each attempt stalls past the read timeout; the last one's error is
        // the result, long before the stream would have finished.
        let started = std::time::Instant::now();
        assert!(matches!(
            resolver
                .fetch_blob(&base, "test/workspace", &layer_descriptor(&fixture), None)
                .await,
            Err(RegistryResolverError::Content(ContentStoreError::Stream))
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            BLOB_ATTEMPTS
        );
        assert!(
            !fixture
                .store
                .contains_verified(&fixture.layer_digest, fixture.layer.len() as u64)
                .unwrap()
        );
    }

    #[test]
    fn bearer_challenge_is_scope_exact_and_token_debug_is_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Bearer realm=\"https://auth.example/token\",service=\"registry.example\",scope=\"repository:org/image:pull\"",
            ),
        );
        let challenge = bearer_challenge(&headers, "org/image", false).unwrap();
        assert_eq!(challenge.scope, "repository:org/image:pull");
        assert!(bearer_challenge(&headers, "other/image", false).is_err());
        let token = BearerToken::new("sensitive-synthetic-token").unwrap();
        assert!(!format!("{token:?}").contains("sensitive-synthetic-token"));
    }
}
