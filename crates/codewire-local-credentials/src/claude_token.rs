//! A Claude subscription token (`claude setup-token`) is admitted locally as
//! the cloud admits it (#4945): its shape is checked and its hard expiry is
//! one year after it is saved, whatever the caller asked for.

use codewire_access::{
    AccessError, CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS, CredentialAuthKind,
    CredentialMetadata, ProviderId, is_claude_subscription_token_shape,
};
use codewire_protected_store::ProtectedValue;

use crate::{LocalCredentialError, NewCredential, unix_seconds};

/// `input` as it is saved with `material`: a Claude subscription token's
/// expiry set one year out, any other credential unchanged.
pub(crate) fn admit(
    mut input: NewCredential,
    material: &ProtectedValue,
) -> Result<NewCredential, LocalCredentialError> {
    input.expires_at_unix = admitted_expiry(
        &input.provider,
        input.authentication_kind,
        material,
        input.expires_at_unix,
    )?;
    Ok(input)
}

/// Sets the expiry of `metadata` as its new `material` is saved: one year out
/// for a Claude subscription token, `requested` for any other credential.
pub(crate) fn set_expiry(
    metadata: &mut CredentialMetadata,
    material: &ProtectedValue,
    requested: Option<u64>,
) -> Result<(), LocalCredentialError> {
    metadata.expires_at_unix = admitted_expiry(
        &metadata.provider,
        metadata.authentication_kind,
        material,
        requested,
    )?;
    Ok(())
}

/// The expiry a credential of `provider` and `kind` is saved with: for a
/// Claude subscription token, one year from now once its shape is checked;
/// for any other credential, `requested`.
fn admitted_expiry(
    provider: &ProviderId,
    kind: CredentialAuthKind,
    material: &ProtectedValue,
    requested: Option<u64>,
) -> Result<Option<u64>, LocalCredentialError> {
    if provider.as_str() != "anthropic" || kind != CredentialAuthKind::OAuth {
        return Ok(requested);
    }
    if !is_claude_subscription_token_shape(material.expose_secret()) {
        return Err(AccessError::InvalidField {
            field: "Claude subscription token",
        }
        .into());
    }
    unix_seconds()?
        .checked_add(CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS)
        .map(Some)
        .ok_or(LocalCredentialError::InvalidTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anthropic() -> ProviderId {
        ProviderId::parse("anthropic").unwrap()
    }

    #[test]
    fn a_token_expires_one_year_after_it_is_saved_whatever_was_asked() {
        let token = ProtectedValue::from_slice(b"sk-ant-oat01-synthetic-token").unwrap();
        let before = unix_seconds().unwrap();
        let expiry = admitted_expiry(&anthropic(), CredentialAuthKind::OAuth, &token, Some(1))
            .unwrap()
            .unwrap();
        let after = unix_seconds().unwrap();
        assert!(
            (before + CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS
                ..=after + CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS)
                .contains(&expiry)
        );
    }

    #[test]
    fn a_malformed_token_is_refused_and_other_credentials_keep_their_expiry() {
        for bad in [&b"short"[..], b"sk-ant-oat01 with spaces in it"] {
            let value = ProtectedValue::from_slice(bad).unwrap();
            assert!(matches!(
                admitted_expiry(&anthropic(), CredentialAuthKind::OAuth, &value, None),
                Err(LocalCredentialError::Access(
                    AccessError::InvalidField { .. }
                ))
            ));
        }
        let key = ProtectedValue::from_slice(b"x").unwrap();
        assert_eq!(
            admitted_expiry(&anthropic(), CredentialAuthKind::ApiKey, &key, Some(7)).unwrap(),
            Some(7)
        );
        assert_eq!(
            admitted_expiry(
                &ProviderId::parse("openai").unwrap(),
                CredentialAuthKind::OAuth,
                &key,
                None
            )
            .unwrap(),
            None
        );
    }
}
