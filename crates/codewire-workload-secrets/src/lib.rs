#![forbid(unsafe_code)]

//! Bounded workload-secret metadata resolution and input validation.
//!
//! Selecting protected storage is metadata-only. This crate deliberately has
//! no material-delivery format: child-visible values require a separate,
//! explicit per-process projection.

use std::collections::BTreeMap;

use thiserror::Error;

pub const MAX_WORKLOAD_SECRETS: usize = 256;
pub const MAX_WORKLOAD_SECRET_KEY_BYTES: usize = 255;
pub const MAX_WORKLOAD_SECRET_VALUE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadSecretSource {
    Organization,
    Project,
    User,
    ExplicitEnvironment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedWorkloadSecretMetadata {
    pub key: String,
    pub source: WorkloadSecretSource,
    pub overridden_sources: Vec<WorkloadSecretSource>,
}

/// Resolves key-only source metadata supplied from lowest to highest precedence.
pub fn resolve_workload_secret_metadata<'a>(
    source_keys: impl IntoIterator<Item = (WorkloadSecretSource, &'a str)>,
) -> Result<Vec<ResolvedWorkloadSecretMetadata>, WorkloadSecretCodecError> {
    let mut sources = BTreeMap::<String, Vec<WorkloadSecretSource>>::new();
    let mut previous_source = None;
    for (source, key) in source_keys {
        if previous_source.is_some_and(|previous| source < previous) {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        previous_source = Some(source);
        validate_workload_secret_key(key)?;
        let entry = sources.entry(key.to_owned()).or_default();
        if entry.last() == Some(&source) {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        entry.push(source);
        if sources.len() > MAX_WORKLOAD_SECRETS {
            return Err(WorkloadSecretCodecError::InvalidEntryCount);
        }
    }
    sources
        .into_iter()
        .map(|(key, mut ordered)| {
            let source = ordered
                .pop()
                .ok_or(WorkloadSecretCodecError::InvalidEntryCount)?;
            Ok(ResolvedWorkloadSecretMetadata {
                key,
                source,
                overridden_sources: ordered,
            })
        })
        .collect()
}

/// Validates one canonical environment-style workload-secret key.
pub fn validate_workload_secret_key(key: &str) -> Result<(), WorkloadSecretCodecError> {
    let mut bytes = key.bytes();
    if key.is_empty()
        || key.len() > MAX_WORKLOAD_SECRET_KEY_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(WorkloadSecretCodecError::InvalidKey);
    }
    Ok(())
}

/// Validates one workload-secret value without rendering or retaining it.
pub fn validate_workload_secret_value(value: &[u8]) -> Result<(), WorkloadSecretCodecError> {
    if value.is_empty()
        || value.len() > MAX_WORKLOAD_SECRET_VALUE_BYTES
        || value.contains(&0)
        || std::str::from_utf8(value).is_err()
    {
        return Err(WorkloadSecretCodecError::InvalidValue);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WorkloadSecretCodecError {
    #[error("workload-secret entry count is invalid")]
    InvalidEntryCount,
    #[error("workload-secret key is invalid")]
    InvalidKey,
    #[error("workload-secret value is invalid")]
    InvalidValue,
    #[error("workload-secret entries are not canonically ordered")]
    NonCanonicalOrdering,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_secret_key_validation_uses_one_canonical_grammar() {
        let below_maximum = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES - 2));
        let maximum = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES - 1));
        let too_long = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES));

        assert_eq!(below_maximum.len(), 254);
        assert_eq!(maximum.len(), 255);
        assert_eq!(too_long.len(), 256);
        for valid in [&below_maximum, &maximum] {
            assert!(validate_workload_secret_key(valid).is_ok());
        }
        assert!(validate_workload_secret_key(&too_long).is_err());
        assert!(validate_workload_secret_key("_UNDERSCORE_FIRST").is_ok());
        assert!(validate_workload_secret_key("1DIGIT_FIRST").is_err());
    }

    #[test]
    fn shared_value_validation_is_bounded_and_content_preserving() {
        assert!(validate_workload_secret_value(b" leading and trailing \n").is_ok());
        assert!(validate_workload_secret_value(b"").is_err());
        assert!(validate_workload_secret_value(b"contains\0nul").is_err());
        assert!(validate_workload_secret_value(&[0xff]).is_err());
        assert!(
            validate_workload_secret_value(&vec![b'x'; MAX_WORKLOAD_SECRET_VALUE_BYTES]).is_ok()
        );
        assert!(
            validate_workload_secret_value(&vec![b'x'; MAX_WORKLOAD_SECRET_VALUE_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn metadata_resolution_is_sorted_bounded_and_uses_last_source_as_winner() {
        let inputs = [
            (WorkloadSecretSource::Organization, "SHARED"),
            (WorkloadSecretSource::Project, "PROJECT_ONLY"),
            (WorkloadSecretSource::Project, "SHARED"),
            (WorkloadSecretSource::User, "SHARED"),
            (WorkloadSecretSource::ExplicitEnvironment, "EXPLICIT"),
            (WorkloadSecretSource::ExplicitEnvironment, "SHARED"),
        ];
        assert_eq!(
            resolve_workload_secret_metadata(inputs).unwrap(),
            vec![
                ResolvedWorkloadSecretMetadata {
                    key: "EXPLICIT".into(),
                    source: WorkloadSecretSource::ExplicitEnvironment,
                    overridden_sources: vec![],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "PROJECT_ONLY".into(),
                    source: WorkloadSecretSource::Project,
                    overridden_sources: vec![],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "SHARED".into(),
                    source: WorkloadSecretSource::ExplicitEnvironment,
                    overridden_sources: vec![
                        WorkloadSecretSource::Organization,
                        WorkloadSecretSource::Project,
                        WorkloadSecretSource::User,
                    ],
                },
            ]
        );
        assert!(
            resolve_workload_secret_metadata([
                (WorkloadSecretSource::User, "SHARED"),
                (WorkloadSecretSource::Project, "SHARED"),
            ])
            .is_err()
        );
        assert!(
            resolve_workload_secret_metadata([
                (WorkloadSecretSource::User, "SHARED"),
                (WorkloadSecretSource::User, "SHARED"),
            ])
            .is_err()
        );
        assert!(
            resolve_workload_secret_metadata([(
                WorkloadSecretSource::Organization,
                "1DIGIT_FIRST",
            )])
            .is_err()
        );
        assert!(
            resolve_workload_secret_metadata([(WorkloadSecretSource::Organization, "unsafe/key",)])
                .is_err()
        );
    }
}
