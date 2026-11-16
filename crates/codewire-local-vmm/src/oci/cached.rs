//! An image named by digest whose content is already in the content store,
//! resolved without the registry (#4968). A tag can move, so only a digest is
//! taken from the store; anything missing or unclear gives `None`, and the
//! caller asks the registry, which fetches only what is missing.

use serde::Deserialize;

use super::{ContentStore, OciArchitecture, RegistryReference, ResolvedDescriptor, ResolvedImage};
use crate::supervisor_metadata::oci::{
    MAXIMUM_DOCUMENT_BYTES, is_index_media_type, is_manifest_media_type,
};

/// The image `reference` names, read from `store` alone. `reference` must be
/// a digest and `size` that document's size as the supervisor recorded it;
/// the document, the manifest it selects for `architecture`, the config and
/// every layer must be stored and verified, as a pinned image is.
pub fn cached_digest_image(
    reference: &RegistryReference,
    size: u64,
    architecture: OciArchitecture,
    store: &ContentStore,
) -> Option<ResolvedImage> {
    let digest = reference.digest()?;
    let document = store.read_blob(digest, size, MAXIMUM_DOCUMENT_BYTES).ok()?;
    let source = ResolvedDescriptor {
        media_type: document_media_type(&document)?,
        digest: digest.clone(),
        size,
    };
    ResolvedImage::from_cached_source(reference.original().to_owned(), architecture, source, store)
        .ok()
}

/// The media type a stored index or manifest names for itself. A document
/// that names none, or another type, is not taken from the store: the
/// registry's answer says what it is.
fn document_media_type(document: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Named {
        #[serde(rename = "mediaType")]
        media_type: Option<String>,
    }
    let media_type = serde_json::from_slice::<Named>(document).ok()?.media_type?;
    (is_index_media_type(&media_type) || is_manifest_media_type(&media_type)).then_some(media_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_index_or_manifest_that_names_itself_is_taken() {
        for (document, expected) in [
            (
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}"#,
                Some("application/vnd.oci.image.index.v1+json"),
            ),
            (
                r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}"#,
                Some("application/vnd.docker.distribution.manifest.v2+json"),
            ),
            (r#"{"schemaVersion":2,"manifests":[]}"#, None),
            (
                r#"{"mediaType":"application/vnd.oci.image.config.v1+json"}"#,
                None,
            ),
            ("not json", None),
        ] {
            assert_eq!(
                document_media_type(document.as_bytes()).as_deref(),
                expected,
                "{document}"
            );
        }
    }
}
