use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

const MAXIMUM_REFERENCE_BYTES: usize = 1024;
const MAXIMUM_REPOSITORY_BYTES: usize = 255;
const MAXIMUM_TAG_BYTES: usize = 128;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: &str) -> Result<Self, RegistryReferenceError> {
        let hex = value
            .strip_prefix("sha256:")
            .filter(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or(RegistryReferenceError::InvalidDigest)?;
        Ok(Self(format!("sha256:{hex}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = RegistryReferenceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryReference {
    original: String,
    registry: String,
    repository: String,
    manifest_reference: String,
    digest: Option<Sha256Digest>,
}

impl RegistryReference {
    pub fn parse(value: &str) -> Result<Self, RegistryReferenceError> {
        if value.is_empty()
            || value.len() > MAXIMUM_REFERENCE_BYTES
            || !value.is_ascii()
            || value.contains(['?', '#', '\\'])
            || value.contains("://")
        {
            return Err(RegistryReferenceError::InvalidReference);
        }
        let (name, digest) = match value.split_once('@') {
            Some((name, digest)) if !name.contains('@') && !digest.contains('@') => {
                (name, Some(Sha256Digest::parse(digest)?))
            }
            Some(_) => return Err(RegistryReferenceError::InvalidReference),
            None => (value, None),
        };
        let slash = name
            .find('/')
            .ok_or(RegistryReferenceError::MissingRegistry)?;
        let registry = &name[..slash];
        let repository_and_tag = &name[slash + 1..];
        validate_registry(registry)?;

        let (repository, tag) = if digest.is_some() {
            if repository_and_tag
                .rfind(':')
                .is_some_and(|colon| colon > repository_and_tag.rfind('/').unwrap_or(0))
            {
                return Err(RegistryReferenceError::TagAndDigest);
            }
            (repository_and_tag, None)
        } else {
            match repository_and_tag.rfind(':') {
                Some(colon) if colon > repository_and_tag.rfind('/').unwrap_or(0) => (
                    &repository_and_tag[..colon],
                    Some(&repository_and_tag[colon + 1..]),
                ),
                _ => (repository_and_tag, None),
            }
        };
        validate_repository(repository)?;
        let manifest_reference = match digest.as_ref() {
            Some(digest) => digest.to_string(),
            None => {
                let tag = tag.unwrap_or("latest");
                validate_tag(tag)?;
                tag.to_owned()
            }
        };
        Ok(Self {
            original: value.to_owned(),
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            manifest_reference,
            digest,
        })
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn registry(&self) -> &str {
        &self.registry
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn manifest_reference(&self) -> &str {
        &self.manifest_reference
    }

    pub fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }

    pub fn distribution_base_url(&self) -> Result<Url, RegistryReferenceError> {
        let registry = if self.registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            &self.registry
        };
        Url::parse(&format!("https://{registry}/"))
            .map_err(|_| RegistryReferenceError::InvalidRegistry)
    }
}

fn validate_registry(registry: &str) -> Result<(), RegistryReferenceError> {
    if registry.is_empty()
        || registry.len() > 253
        || registry != registry.to_ascii_lowercase()
        || registry.contains('@')
    {
        return Err(RegistryReferenceError::InvalidRegistry);
    }
    let url = Url::parse(&format!("https://{registry}/"))
        .map_err(|_| RegistryReferenceError::InvalidRegistry)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || registry.starts_with('[')
    {
        return Err(RegistryReferenceError::InvalidRegistry);
    }
    Ok(())
}

fn validate_repository(repository: &str) -> Result<(), RegistryReferenceError> {
    if repository.is_empty()
        || repository.len() > MAXIMUM_REPOSITORY_BYTES
        || repository != repository.to_ascii_lowercase()
    {
        return Err(RegistryReferenceError::InvalidRepository);
    }
    for component in repository.split('/') {
        let bytes = component.as_bytes();
        if bytes.is_empty()
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
        {
            return Err(RegistryReferenceError::InvalidRepository);
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), RegistryReferenceError> {
    let bytes = tag.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_TAG_BYTES
        || !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
    {
        return Err(RegistryReferenceError::InvalidTag);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryReferenceError {
    #[error("OCI image reference is invalid")]
    InvalidReference,
    #[error("OCI image reference must include an explicit registry")]
    MissingRegistry,
    #[error("OCI registry is invalid")]
    InvalidRegistry,
    #[error("OCI repository is invalid")]
    InvalidRepository,
    #[error("OCI tag is invalid")]
    InvalidTag,
    #[error("only lowercase sha256 OCI digests are supported")]
    InvalidDigest,
    #[error("OCI image references must not combine a tag and digest")]
    TagAndDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_tag_and_digest_references_are_exact() {
        let tagged = RegistryReference::parse("ghcr.io/codewiresh/workspace:v1").unwrap();
        assert_eq!(tagged.registry(), "ghcr.io");
        assert_eq!(tagged.repository(), "codewiresh/workspace");
        assert_eq!(tagged.manifest_reference(), "v1");
        assert!(tagged.digest().is_none());

        let digest = format!("sha256:{}", "a".repeat(64));
        let pinned = RegistryReference::parse(&format!("registry.example/a/b@{digest}")).unwrap();
        assert_eq!(pinned.manifest_reference(), digest);
        assert_eq!(pinned.digest().unwrap().hex(), "a".repeat(64));
    }

    #[test]
    fn ambiguous_or_credential_bearing_references_fail_closed() {
        for rejected in [
            "ubuntu:latest",
            "https://ghcr.io/codewiresh/workspace:latest",
            "user@ghcr.io/codewiresh/workspace:latest",
            "GHCR.io/codewiresh/workspace:latest",
            "ghcr.io/../workspace:latest",
            "ghcr.io/codewiresh/workspace:bad tag",
            "ghcr.io/codewiresh/workspace:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ghcr.io/codewiresh/workspace@sha256:ABCDEF",
        ] {
            assert!(RegistryReference::parse(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn docker_hub_uses_the_distribution_registry_endpoint() {
        let image = RegistryReference::parse("docker.io/library/alpine:latest").unwrap();
        assert_eq!(
            image.distribution_base_url().unwrap().as_str(),
            "https://registry-1.docker.io/"
        );
    }
}
