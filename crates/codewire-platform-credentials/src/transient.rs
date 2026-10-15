//! Short-lived values sealed with the credential store's KEK and handed to the
//! caller instead of being stored, such as a Claude sign-in's PKCE verifier
//! and state between its Start and Complete.
//!
//! Each value gets the envelope stored material uses: a fresh data key that
//! the KEK wraps under the owner's DEK context, and AES-256-GCM over the value
//! with associated data naming the owner, the value's fixed purpose and its
//! public binding (for a sign-in, its issue time). Only the same owner opens
//! it, for the same purpose and binding; anything else, including any change
//! to the text, is refused. Nothing is written to the database, and the text
//! carries no plaintext.

use codewire_access::Owner;
use codewire_protected_store::secret_envelope::{
    DekContext, EncryptedTenantSecret, SECRET_FORMAT_V1, SecretCoordinates, TenantSecretScope,
    WRAPPED_DEK_FORMAT_V1, WrappedDek, decrypt_secret, encrypt_secret,
};
use zeroize::Zeroizing;

use crate::PlatformCredentialError as Error;
use crate::PlatformCredentialStore;
use crate::store::{provider_call, validate_wrapper};

/// The sealed form's version and its text prefix.
const VERSION: u8 = 1;
/// The longest sealed text accepted: a wrapped data key, a nonce and a value
/// of at most [`MAX_TRANSIENT_VALUE_BYTES`], hex encoded, with room to spare.
pub const MAX_SEALED_TRANSIENT_TEXT_BYTES: usize = 4096;
/// The longest value that may be sealed.
pub const MAX_TRANSIENT_VALUE_BYTES: usize = 512;
const MAX_PURPOSE_BYTES: usize = 64;
const MAX_BINDING_BYTES: usize = 64;
const NONCE_BYTES: usize = 12;

impl PlatformCredentialStore {
    /// Seal `value` for `owner` under `purpose` (lowercase letters and `-`)
    /// and the public `binding` (ASCII letters, digits, `.`, `_` and `-`).
    /// Returns lowercase hex text that only [`Self::open_transient`] with the
    /// same owner, purpose and binding opens.
    pub async fn seal_transient(
        &self,
        owner: &Owner,
        purpose: &str,
        binding: &str,
        value: &[u8],
    ) -> Result<Zeroizing<String>, Error> {
        validate_labels(purpose, binding)?;
        if value.is_empty() || value.len() > MAX_TRANSIENT_VALUE_BYTES {
            return Err(Error::InvalidInput);
        }
        let context = owner_context(owner);
        let generated = provider_call(self.provider().generate(&context)).await?;
        validate_wrapper(&generated.wrapped, self.provider().kind())?;
        let path = transient_path(purpose);
        let envelope = encrypt_secret(
            &generated.plaintext,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: binding,
            },
            value,
        )
        .map_err(|_| Error::CorruptRecord)?;
        drop(generated.plaintext);
        Ok(encode(&generated.wrapped, &envelope))
    }

    /// Open text from [`Self::seal_transient`] for exactly this owner,
    /// purpose and binding. A malformed or altered text, or one sealed for
    /// another purpose or binding, is [`Error::InvalidInput`].
    pub async fn open_transient(
        &self,
        owner: &Owner,
        purpose: &str,
        binding: &str,
        sealed: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        validate_labels(purpose, binding)?;
        let (wrapped, envelope) = decode(sealed, self.provider().kind())?;
        let context = owner_context(owner);
        // A data key wrapped under another owner's context does not unwrap;
        // the provider cannot tell that from an outage, so it is reported as
        // unavailable, and nothing opens either way.
        let dek = provider_call(self.provider().unwrap(&context, &wrapped)).await?;
        let path = transient_path(purpose);
        let value = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: binding,
            },
            &envelope,
        )
        .map_err(|_| Error::InvalidInput)?;
        drop(dek);
        if value.is_empty() || value.len() > MAX_TRANSIENT_VALUE_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(value)
    }
}

fn owner_context(owner: &Owner) -> DekContext {
    DekContext {
        scope: match owner {
            Owner::User(_) => TenantSecretScope::User,
            Owner::Organization(_) => TenantSecretScope::Organization,
        },
        scope_id: owner.id().as_str().to_owned(),
    }
}

/// Never a stored credential's path (`/platform-credentials/v1/...`).
fn transient_path(purpose: &str) -> String {
    format!("/transient/v1/{purpose}")
}

fn validate_labels(purpose: &str, binding: &str) -> Result<(), Error> {
    let purpose_ok = !purpose.is_empty()
        && purpose.len() <= MAX_PURPOSE_BYTES
        && purpose
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
    let binding_ok = !binding.is_empty()
        && binding.len() <= MAX_BINDING_BYTES
        && binding
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if purpose_ok && binding_ok {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// `version | key version (u32) | key name | wrapped key | nonce | ciphertext`,
/// each variable part with a u16 length, as lowercase hex.
fn encode(wrapped: &WrappedDek, envelope: &EncryptedTenantSecret) -> Zeroizing<String> {
    let mut bytes = Vec::with_capacity(
        16 + wrapped.key_name.len()
            + wrapped.ciphertext.len()
            + envelope.nonce.len()
            + envelope.ciphertext.len(),
    );
    bytes.push(VERSION);
    bytes.extend_from_slice(&wrapped.key_version.to_be_bytes());
    for part in [
        wrapped.key_name.as_bytes(),
        &wrapped.ciphertext,
        &envelope.nonce,
        &envelope.ciphertext,
    ] {
        bytes.extend_from_slice(&(part.len() as u16).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in &bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn decode(
    text: &str,
    provider: codewire_protected_store::secret_envelope::KekProviderKind,
) -> Result<(WrappedDek, EncryptedTenantSecret), Error> {
    if text.is_empty()
        || text.len() > MAX_SEALED_TRANSIENT_TEXT_BYTES
        || !text.len().is_multiple_of(2)
    {
        return Err(Error::InvalidInput);
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Some((nibble(high)? << 4) | nibble(low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or(Error::InvalidInput)?;
    let mut reader = Reader(&bytes);
    if reader.take(1)? != [VERSION] {
        return Err(Error::InvalidInput);
    }
    let key_version = u32::from_be_bytes(
        reader
            .take(4)?
            .try_into()
            .map_err(|_| Error::InvalidInput)?,
    );
    let key_name = std::str::from_utf8(reader.part()?)
        .map_err(|_| Error::InvalidInput)?
        .to_owned();
    let wrapped_key = reader.part()?.to_vec();
    let nonce = reader.part()?.to_vec();
    let ciphertext = reader.part()?.to_vec();
    if !reader.0.is_empty() || nonce.len() != NONCE_BYTES {
        return Err(Error::InvalidInput);
    }
    let wrapped = WrappedDek {
        provider,
        key_name,
        key_version,
        ciphertext: wrapped_key,
        nonce: None,
        format: WRAPPED_DEK_FORMAT_V1,
    };
    validate_wrapper(&wrapped, provider).map_err(|_| Error::InvalidInput)?;
    Ok((
        wrapped,
        EncryptedTenantSecret {
            ciphertext,
            nonce,
            format: SECRET_FORMAT_V1,
        },
    ))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < length {
            return Err(Error::InvalidInput);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }

    fn part(&mut self) -> Result<&'a [u8], Error> {
        let length = u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| Error::InvalidInput)?);
        self.take(usize::from(length))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use codewire_access::{OwnerId, builtin_provider_catalog};
    use codewire_protected_store::secret_envelope::TestKekProvider;
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    const PURPOSE: &str = "claude-sign-in-handle";
    const VALUE: &[u8] = b"cwcs1.synthetic-state.synthetic-verifier.1800000000";

    fn store() -> PlatformCredentialStore {
        // Sealing reads no rows: a lazy pool that never connects suffices.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .unwrap();
        PlatformCredentialStore::new(pool, Arc::new(TestKekProvider), builtin_provider_catalog())
    }

    fn user(id: &str) -> Owner {
        Owner::User(OwnerId::parse(id).unwrap())
    }

    #[tokio::test]
    async fn only_the_same_owner_purpose_and_binding_open_a_sealed_value() {
        let store = store();
        let owner = user("synthetic-user-a");
        let sealed = store
            .seal_transient(&owner, PURPOSE, "1800000000", VALUE)
            .await
            .unwrap();
        assert!(sealed.len() <= MAX_SEALED_TRANSIENT_TEXT_BYTES);
        assert!(!sealed.contains("synthetic-verifier"));
        assert_eq!(
            &*store
                .open_transient(&owner, PURPOSE, "1800000000", &sealed)
                .await
                .unwrap(),
            VALUE
        );
        // Another owner, purpose or binding opens nothing.
        for (owner, purpose, binding) in [
            (user("synthetic-user-b"), PURPOSE, "1800000000"),
            (owner.clone(), "other-purpose", "1800000000"),
            (owner.clone(), PURPOSE, "1800000001"),
        ] {
            assert_eq!(
                store
                    .open_transient(&owner, purpose, binding, &sealed)
                    .await
                    .err(),
                Some(Error::InvalidInput),
                "{purpose} {binding}"
            );
        }
        // Two seals of one value differ: a fresh key and nonce each time.
        let again = store
            .seal_transient(&owner, PURPOSE, "1800000000", VALUE)
            .await
            .unwrap();
        assert_ne!(*again, *sealed);
    }

    #[tokio::test]
    async fn any_change_to_the_text_is_refused() {
        let store = store();
        let owner = user("synthetic-user-a");
        let sealed = store
            .seal_transient(&owner, PURPOSE, "1800000000", VALUE)
            .await
            .unwrap();
        // Flip each hex digit of the nonce and ciphertext region in turn.
        for index in (sealed.len() - 64..sealed.len()).step_by(7) {
            let mut altered = sealed.as_bytes().to_vec();
            altered[index] = if altered[index] == b'0' { b'1' } else { b'0' };
            let altered = String::from_utf8(altered).unwrap();
            assert_eq!(
                store
                    .open_transient(&owner, PURPOSE, "1800000000", &altered)
                    .await
                    .err(),
                Some(Error::InvalidInput)
            );
        }
        for malformed in [
            String::new(),
            "zz".into(),
            sealed[..sealed.len() - 2].to_owned(),
            format!("{}00", *sealed),
            sealed.to_uppercase(),
            "0".repeat(MAX_SEALED_TRANSIENT_TEXT_BYTES + 2),
        ] {
            assert_eq!(
                store
                    .open_transient(&owner, PURPOSE, "1800000000", &malformed)
                    .await
                    .err(),
                Some(Error::InvalidInput)
            );
        }
    }

    #[tokio::test]
    async fn labels_and_values_are_bounded() {
        let store = store();
        let owner = user("synthetic-user-a");
        for (purpose, binding, value) in [
            ("", "1", VALUE),
            ("Upper", "1", VALUE),
            (PURPOSE, "", VALUE),
            (PURPOSE, "with space", VALUE),
            (PURPOSE, "1", b"".as_slice()),
            (PURPOSE, "1", &[0_u8; MAX_TRANSIENT_VALUE_BYTES + 1]),
        ] {
            assert_eq!(
                store
                    .seal_transient(&owner, purpose, binding, value)
                    .await
                    .err(),
                Some(Error::InvalidInput)
            );
        }
    }
}
