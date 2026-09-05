use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, Owner, Placement,
    ProviderCatalog, ProviderId,
};
use codewire_protected_store::secret_envelope::{DekContext, TenantSecretScope};

use crate::PlatformCredentialError as Error;

/// Authority-side comparison token, not a profile or environment generation.
/// Both counters must match before replacing a persisted credential value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialVersion {
    pub revocation_generation: u64,
    pub material_generation: u64,
}

impl CredentialVersion {
    pub(crate) fn validate(self) -> Result<(), Error> {
        for generation in [self.revocation_generation, self.material_generation] {
            if generation == 0 || i64::try_from(generation).is_err() {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }

    pub(crate) fn replaced(self) -> Result<Self, Error> {
        self.validate()?;
        let next = Self {
            revocation_generation: self.revocation_generation + 1,
            material_generation: self.material_generation + 1,
        };
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn revoked(self) -> Result<Self, Error> {
        self.validate()?;
        let next = Self {
            revocation_generation: self.revocation_generation + 1,
            ..self
        };
        next.validate()?;
        Ok(next)
    }
}

/// Non-secret registration fields. Identity and initial versions are generated
/// by the authority; callers cannot import a protected-store reference.
#[derive(Clone, Debug)]
pub struct CredentialRegistration {
    pub provider: ProviderId,
    pub authentication_kind: CredentialAuthKind,
    pub display_name: String,
    pub account_hint: Option<String>,
    /// Hard credential-use deadline, not the OAuth access-token expiry stored
    /// inside protected material. Refresh cannot clear or extend this deadline.
    pub expires_at_unix: Option<u64>,
}

/// Authority-side record. Public metadata queries return only `metadata`, not
/// the internal material comparison token. Neither type contains an envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecord {
    pub metadata: CredentialMetadata,
    pub version: CredentialVersion,
}

impl CredentialRecord {
    pub(crate) fn registered(
        owner: &Owner,
        registration: CredentialRegistration,
        catalog: &ProviderCatalog,
    ) -> Result<Self, Error> {
        let version = CredentialVersion {
            revocation_generation: 1,
            material_generation: 1,
        };
        let record = Self {
            metadata: CredentialMetadata {
                id: CredentialId::parse(uuid::Uuid::new_v4().to_string())
                    .map_err(|_| Error::InvalidInput)?,
                placement: Placement::Platform,
                owner: owner.clone(),
                provider: registration.provider,
                authentication_kind: registration.authentication_kind,
                display_name: registration.display_name,
                account_hint: registration.account_hint,
                status: CredentialStatus::Active,
                expires_at_unix: registration.expires_at_unix,
                revocation_generation: version.revocation_generation,
            },
            version,
        };
        record.validate(catalog)?;
        Ok(record)
    }

    pub(crate) fn validate(&self, catalog: &ProviderCatalog) -> Result<(), Error> {
        self.metadata.validate().map_err(|_| Error::InvalidInput)?;
        self.version.validate()?;
        if self.metadata.placement != Placement::Platform
            || self.metadata.revocation_generation != self.version.revocation_generation
            || self
                .metadata
                .expires_at_unix
                .is_some_and(|value| i64::try_from(value).is_err())
        {
            return Err(Error::InvalidInput);
        }
        if !catalog
            .get(&self.metadata.provider)
            .is_some_and(|provider| {
                provider.supports_authentication_kind(self.metadata.authentication_kind)
            })
        {
            return Err(Error::UnsupportedCredential);
        }
        Ok(())
    }

    pub(crate) fn active(&self, now: u64) -> Result<(), Error> {
        if self.metadata.status != CredentialStatus::Active {
            return Err(Error::Inactive);
        }
        if self
            .metadata
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now)
        {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub(crate) fn context(&self) -> DekContext {
        DekContext {
            scope: match self.metadata.owner {
                Owner::User(_) => TenantSecretScope::User,
                Owner::Organization(_) => TenantSecretScope::Organization,
            },
            scope_id: self.metadata.owner.id().as_str().to_owned(),
        }
    }

    pub(crate) fn path(&self) -> String {
        format!("/platform-credentials/v1/{}", self.metadata.id.as_str())
    }

    pub(crate) fn key(&self) -> String {
        // Identifier grammar excludes '/', auth kinds are a closed enum, and
        // the counter has one checked decimal encoding. Existing length-
        // prefixed envelope AAD also binds the exact owner and path.
        format!(
            "{}/{}/{}",
            self.metadata.provider.as_str(),
            auth_kind(self.metadata.authentication_kind),
            self.version.material_generation,
        )
    }
}

pub(crate) fn auth_kind(kind: CredentialAuthKind) -> &'static str {
    match kind {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
    }
}

pub(crate) fn parse_auth_kind(value: &str) -> Result<CredentialAuthKind, Error> {
    match value {
        "oauth" => Ok(CredentialAuthKind::OAuth),
        "api_key" => Ok(CredentialAuthKind::ApiKey),
        "access_token" => Ok(CredentialAuthKind::AccessToken),
        "github_app" => Ok(CredentialAuthKind::GitHubApp),
        _ => Err(Error::CorruptRecord),
    }
}

pub(crate) fn parse_status(value: &str) -> Result<CredentialStatus, Error> {
    match value {
        "active" => Ok(CredentialStatus::Active),
        "expired" => Ok(CredentialStatus::Expired),
        "refresh_failed" => Ok(CredentialStatus::RefreshFailed),
        "revoked" => Ok(CredentialStatus::Revoked),
        _ => Err(Error::CorruptRecord),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_access::{OwnerId, builtin_provider_catalog};
    use codewire_protected_store::secret_envelope::{
        SecretCoordinates, decrypt_secret, encrypt_secret,
    };

    fn record() -> CredentialRecord {
        CredentialRecord::registered(
            &Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
            CredentialRegistration {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "Work Codex".into(),
                account_hint: Some("Synthetic account".into()),
                expires_at_unix: None,
            },
            &builtin_provider_catalog(),
        )
        .unwrap()
    }

    #[test]
    fn registration_uses_shared_model_but_only_the_platform_placement() {
        let record = record();
        assert_eq!(record.metadata.placement, Placement::Platform);
        assert_eq!(record.metadata.status, CredentialStatus::Active);
        assert_eq!(
            record.version,
            CredentialVersion {
                revocation_generation: 1,
                material_generation: 1
            }
        );
        assert_eq!(record.metadata.revocation_generation, 1);
        assert_ne!(record.metadata.id, self::record().metadata.id);
    }

    #[test]
    fn unsupported_or_invalid_metadata_never_becomes_storable() {
        let catalog = builtin_provider_catalog();
        let mut input = record();
        input.metadata.provider = ProviderId::parse("not-a-provider").unwrap();
        assert_eq!(input.validate(&catalog), Err(Error::UnsupportedCredential));
        input = record();
        input.metadata.authentication_kind = CredentialAuthKind::GitHubApp;
        assert_eq!(input.validate(&catalog), Err(Error::UnsupportedCredential));
        for label in ["", "leading ", "line\nbreak", "nul\0byte"] {
            input = record();
            input.metadata.display_name = label.into();
            assert_eq!(input.validate(&catalog), Err(Error::InvalidInput));
        }
        input = record();
        input.metadata.account_hint = Some("\tunsafe".into());
        assert_eq!(input.validate(&catalog), Err(Error::InvalidInput));
        input = record();
        input.metadata.placement = Placement::Local;
        assert_eq!(input.validate(&catalog), Err(Error::InvalidInput));
        input = record();
        input.metadata.expires_at_unix = Some(u64::MAX);
        assert_eq!(input.validate(&catalog), Err(Error::InvalidInput));
        input = record();
        input.metadata.revocation_generation += 1;
        assert_eq!(input.validate(&catalog), Err(Error::InvalidInput));
    }

    #[test]
    fn material_and_revocation_versions_have_checked_distinct_transitions() {
        let initial = record().version;
        assert_eq!(
            initial.replaced().unwrap(),
            CredentialVersion {
                revocation_generation: 2,
                material_generation: 2
            }
        );
        assert_eq!(
            initial.revoked().unwrap(),
            CredentialVersion {
                revocation_generation: 2,
                material_generation: 1
            }
        );
        for invalid in [0, i64::MAX as u64 + 1, u64::MAX] {
            let version = CredentialVersion {
                revocation_generation: invalid,
                material_generation: 1,
            };
            assert_eq!(version.validate(), Err(Error::InvalidInput));
            assert_eq!(version.replaced(), Err(Error::InvalidInput));
            assert_eq!(version.revoked(), Err(Error::InvalidInput));
        }
        let max = CredentialVersion {
            revocation_generation: i64::MAX as u64,
            material_generation: 1,
        };
        assert_eq!(max.replaced(), Err(Error::InvalidInput));
        assert_eq!(max.revoked(), Err(Error::InvalidInput));
        let max_material = CredentialVersion {
            revocation_generation: 1,
            material_generation: i64::MAX as u64,
        };
        assert_eq!(max_material.replaced(), Err(Error::InvalidInput));
        assert_eq!(
            max_material.revoked().unwrap().material_generation,
            i64::MAX as u64
        );
    }

    #[test]
    fn authority_coordinates_bind_owner_kind_identity_provider_kind_and_material_version() {
        let original = record();
        let context = original.context();
        let envelope = encrypt_secret(
            &[7; 32],
            &SecretCoordinates {
                context: &context,
                path: &original.path(),
                key: &original.key(),
            },
            b"synthetic-only-credential",
        )
        .unwrap();
        let read = |candidate: &CredentialRecord| {
            decrypt_secret(
                &[7; 32],
                &SecretCoordinates {
                    context: &candidate.context(),
                    path: &candidate.path(),
                    key: &candidate.key(),
                },
                &envelope,
            )
        };
        assert_eq!(
            read(&original).unwrap().as_slice(),
            b"synthetic-only-credential"
        );
        let mut substitutions = Vec::new();
        let mut changed = original.clone();
        changed.metadata.owner = Owner::Organization(original.metadata.owner.id().clone());
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.metadata.owner = Owner::User(OwnerId::parse("other-owner").unwrap());
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.metadata.id = CredentialId::parse("another-credential").unwrap();
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.metadata.provider = ProviderId::parse("github").unwrap();
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.metadata.authentication_kind = CredentialAuthKind::ApiKey;
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.version.material_generation += 1;
        substitutions.push(changed);
        for changed in substitutions {
            assert!(read(&changed).is_err());
        }
        assert!(DekContext::from_secret_path(&original.path()).is_err());
        // Revocation is an admission fence, not an encryption-format rewrite.
        let mut revoked = original.clone();
        revoked.metadata.revocation_generation += 1;
        revoked.version.revocation_generation += 1;
        assert!(read(&revoked).is_ok());
    }

    #[test]
    fn normal_material_admission_checks_status_and_exact_expiry() {
        let mut record = record();
        assert!(record.active(100).is_ok());
        record.metadata.expires_at_unix = Some(100);
        assert!(record.active(99).is_ok());
        assert_eq!(record.active(100), Err(Error::Expired));
        for status in [
            CredentialStatus::Revoked,
            CredentialStatus::Expired,
            CredentialStatus::RefreshFailed,
        ] {
            record.metadata.status = status;
            assert_eq!(record.active(0), Err(Error::Inactive));
        }
    }

    #[test]
    fn persisted_enums_are_closed_without_legacy_aliases() {
        for kind in [
            CredentialAuthKind::OAuth,
            CredentialAuthKind::ApiKey,
            CredentialAuthKind::AccessToken,
            CredentialAuthKind::GitHubApp,
        ] {
            assert_eq!(parse_auth_kind(auth_kind(kind)), Ok(kind));
        }
        for value in ["OAuth", "token", "pat", "ssh", "", "enabled"] {
            assert_eq!(parse_auth_kind(value), Err(Error::CorruptRecord));
            assert_eq!(parse_status(value), Err(Error::CorruptRecord));
        }
    }

    #[test]
    fn public_metadata_has_no_material_reference_or_internal_material_version() {
        let record = record();
        let value = serde_json::to_value(record.metadata).unwrap();
        for field in [
            "material",
            "ciphertext",
            "wrapped_dek",
            "protected_entry_id",
            "protected_store_reference",
            "material_generation",
            "version",
        ] {
            assert!(
                value.get(field).is_none(),
                "unexpected metadata field: {field}"
            );
        }
    }

    #[test]
    fn errors_are_closed_and_have_no_opaque_sources() {
        use std::error::Error as _;
        for error in [
            Error::InvalidInput,
            Error::UnsupportedCredential,
            Error::NotFound,
            Error::AlreadyExists,
            Error::StaleVersion,
            Error::Inactive,
            Error::Expired,
            Error::CorruptRecord,
            Error::DatabaseUnavailable,
            Error::ProviderUnavailable,
            Error::ProviderTimedOut,
            Error::ClockUnavailable,
        ] {
            assert!(error.source().is_none());
            assert!(!error.to_string().is_empty());
            assert!(!format!("{error:?}").contains("synthetic-only-credential"));
        }
    }
}
