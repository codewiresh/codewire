//! Personal credential metadata only: no material store, KEK, or lifecycle writes.

use codewire_access::{
    CredentialId, CredentialMetadata, Owner, OwnerId, ProviderId, builtin_provider_catalog,
    is_credential_name_provider,
};
use codewire_platform_credentials::{
    CredentialMetadataReader, CredentialNameError, PlatformCredentialError,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

#[derive(Clone)]
pub struct Credentials {
    reader: CredentialMetadataReader,
}

impl Credentials {
    pub fn new(pool: PgPool) -> Self {
        Self {
            reader: CredentialMetadataReader::new(pool, builtin_provider_catalog()),
        }
    }

    pub async fn list(
        &self,
        user: &AuthUser,
        page_size: i32,
        page_token: &str,
    ) -> AppResult<(Vec<CredentialMetadata>, String)> {
        let owner = personal_owner(user)?;
        let size = match page_size {
            0 => 100,
            1..=100 => page_size as u32,
            _ => return Err(invalid()),
        };
        let after = if page_token.is_empty() {
            None
        } else {
            Some(credential_id(page_token)?)
        };
        let mut credentials = self
            .reader
            .list(&owner, after.as_ref(), size + 1)
            .await
            .map_err(metadata_error)?;
        let next = if credentials.len() > size as usize {
            credentials.truncate(size as usize);
            credentials
                .last()
                .expect("positive page size")
                .id
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        Ok((credentials, next))
    }

    /// The owner is the caller, so a name another account uses is not found,
    /// and an ambiguous name lists only the caller's own providers.
    pub async fn get(
        &self,
        user: &AuthUser,
        selector: CredentialSelector<'_>,
    ) -> AppResult<CredentialLookup> {
        let owner = personal_owner(user)?;
        match selector {
            CredentialSelector::Id(id) => self
                .reader
                .get(&owner, &credential_id(id)?)
                .await
                .map(CredentialLookup::Found)
                .map_err(metadata_error),
            CredentialSelector::Name { name, provider } => {
                let provider = provider.map(credential_provider).transpose()?;
                match self.reader.resolve(&owner, name, provider.as_ref()).await {
                    Ok(credential) => Ok(CredentialLookup::Found(credential)),
                    Err(CredentialNameError::Ambiguous { providers }) => {
                        Ok(CredentialLookup::Ambiguous(providers))
                    }
                    Err(CredentialNameError::Credential(error)) => Err(metadata_error(error)),
                }
            }
        }
    }
}

pub enum CredentialSelector<'a> {
    Id(&'a str),
    /// A provider narrows the name to that provider's credential.
    Name {
        name: &'a str,
        provider: Option<&'a str>,
    },
}

pub enum CredentialLookup {
    Found(CredentialMetadata),
    /// The name matches the caller's credentials of these providers, sorted.
    Ambiguous(Vec<ProviderId>),
}

fn personal_owner(user: &AuthUser) -> AppResult<Owner> {
    user.require_account_credential()?;
    Ok(Owner::User(
        OwnerId::parse(&user.user_id).map_err(|_| AppError::Unauthorized)?,
    ))
}

fn credential_provider(value: &str) -> AppResult<ProviderId> {
    if !is_credential_name_provider(value) {
        return Err(invalid());
    }
    ProviderId::parse(value).map_err(|_| invalid())
}

fn credential_id(value: &str) -> AppResult<CredentialId> {
    CredentialId::parse(value).map_err(|_| invalid())
}

fn invalid() -> AppError {
    AppError::BadRequest("invalid credential metadata selector or pagination".into())
}

fn metadata_error(error: PlatformCredentialError) -> AppError {
    match error {
        PlatformCredentialError::InvalidInput => invalid(),
        PlatformCredentialError::NotFound => AppError::NotFound("credential not found".into()),
        _ => AppError::ServiceUnavailable("credential metadata unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_owner_never_inherits_api_key_or_administrator_authority() {
        let mut user = AuthUser {
            user_id: "synthetic-user".into(),
            org_id: Some("synthetic-org".into()),
            is_admin: true,
            via_api_key: true,
        };
        assert!(personal_owner(&user).is_err());
        user.via_api_key = false;
        assert_eq!(
            personal_owner(&user).unwrap(),
            Owner::User(OwnerId::parse("synthetic-user").unwrap())
        );
    }
}
