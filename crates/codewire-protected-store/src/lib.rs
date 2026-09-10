#![forbid(unsafe_code)]

//! Opaque protected-value storage for Codewire credential authorities.
//!
//! The OS-store API supports only exact-entry get, put, and delete. It
//! exposes no list or namespace sweep operation, so recovery code must act on
//! entry IDs recorded in its metadata journal. Provider material must not be
//! passed to a VM supervisor or serialized into placement metadata.
//!
//! The opt-in `platform` feature adds authenticated tenant-secret envelopes,
//! OpenBao Transit wrapping, and pod-bound Kubernetes workload identities.

#[cfg(feature = "platform")]
pub mod openbao_workload_identity;
#[cfg(feature = "platform")]
pub mod secret_envelope;
#[cfg(feature = "ssh-material")]
pub mod ssh_material;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::future::Future;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use secret_service::{EncryptionType, SecretService};

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const CODEWIRE_CREDENTIAL_SERVICE: &str = "sh.codewire.credentials";
pub const MAX_PROTECTED_ENTRY_ID_BYTES: usize = 240;
pub const MAX_PROTECTED_VALUE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const LINUX_SECRET_SERVICE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedStorePersistence {
    OperatingSystem,
    ProcessLifetime,
}

/// Stable, redacted failures. Underlying keyring errors are never retained as
/// sources because their payloads and `Debug` implementations are not part of
/// Codewire's non-disclosure contract.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProtectedStoreError {
    #[error("protected entry ID is invalid")]
    InvalidEntryId,
    #[error("protected value must not be empty")]
    EmptyValue,
    #[error("protected value exceeds the supported size")]
    ValueTooLarge,
    #[error("operating-system protected storage is locked or inaccessible")]
    AccessDenied,
    #[error("operating-system protected storage is unavailable")]
    Unavailable,
    #[error("operating-system protected storage did not respond in time")]
    TimedOut,
    #[error("protected entry is ambiguous")]
    AmbiguousEntry,
    #[error("protected entry is corrupt")]
    CorruptEntry,
    #[error("operating-system protected storage is unsupported on this platform")]
    UnsupportedPlatform,
}

/// An exact metadata-owned keyring entry. Debug output is redacted because the
/// reference is internal placement metadata even though it is not itself a
/// credential.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtectedEntryId(String);

impl ProtectedEntryId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProtectedStoreError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROTECTED_ENTRY_ID_BYTES {
            return Err(ProtectedStoreError::InvalidEntryId);
        }
        for segment in value.split('/') {
            if segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                || !segment
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
            {
                return Err(ProtectedStoreError::InvalidEntryId);
            }
        }
        Ok(Self(value))
    }

    /// Deliberate exposure for the protected-store backend only.
    pub fn expose_reference(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProtectedEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedEntryId([REDACTED])")
    }
}

/// Zeroizing credential payload. It has no serialization or cloning trait;
/// every copy must be deliberate inside a protected-store implementation.
pub struct ProtectedValue(Zeroizing<Vec<u8>>);

impl ProtectedValue {
    pub fn new(mut value: Vec<u8>) -> Result<Self, ProtectedStoreError> {
        if value.is_empty() {
            value.zeroize();
            return Err(ProtectedStoreError::EmptyValue);
        }
        if value.len() > MAX_PROTECTED_VALUE_BYTES {
            value.zeroize();
            return Err(ProtectedStoreError::ValueTooLarge);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn from_slice(value: &[u8]) -> Result<Self, ProtectedStoreError> {
        Self::new(value.to_vec())
    }

    /// Deliberate exposure to the authority operation that consumes or stores
    /// the value. Callers must not format, log, or persist this slice elsewhere.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for ProtectedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedValue([REDACTED])")
    }
}

pub trait ProtectedStore: Send + Sync {
    fn persistence(&self) -> ProtectedStorePersistence;
    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError>;
    fn put(&self, id: &ProtectedEntryId, value: &ProtectedValue)
    -> Result<(), ProtectedStoreError>;
    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError>;
}

/// Explicit process-lifetime store for headless or one-shot use. Losing the
/// process loses every value; callers must surface that behavior to users.
#[derive(Default)]
pub struct EphemeralProtectedStore {
    entries: Mutex<BTreeMap<ProtectedEntryId, Zeroizing<Vec<u8>>>>,
}

impl fmt::Debug for EphemeralProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralProtectedStore([REDACTED])")
    }
}

impl ProtectedStore for EphemeralProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::ProcessLifetime
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        entries
            .get(id)
            .map(|value| ProtectedValue::from_slice(value.as_slice()))
            .transpose()
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        entries.insert(id.clone(), Zeroizing::new(value.expose_secret().to_vec()));
        Ok(())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        entries.remove(id);
        Ok(())
    }
}

/// Persistent OS keyring store. Calls are synchronous and belong on the
/// credential authority's blocking thread, never on a VM supervisor loop.
#[derive(Clone, Copy, Default)]
pub struct OsProtectedStore;

impl fmt::Debug for OsProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsProtectedStore([REDACTED])")
    }
}

impl ProtectedStore for OsProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        #[cfg(target_os = "linux")]
        {
            linux_get(id)
        }
        #[cfg(target_os = "macos")]
        {
            let entry = keyring_entry(id)?;
            match entry.get_secret() {
                Ok(value) => protected_value_from_store(value).map(Some),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(map_keyring_error(error)),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = id;
            Err(ProtectedStoreError::UnsupportedPlatform)
        }
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        #[cfg(target_os = "linux")]
        {
            linux_put(id, value)
        }
        #[cfg(target_os = "macos")]
        {
            keyring_entry(id)?
                .set_secret(value.expose_secret())
                .map_err(map_keyring_error)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (id, value);
            Err(ProtectedStoreError::UnsupportedPlatform)
        }
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        #[cfg(target_os = "linux")]
        {
            linux_delete(id)
        }
        #[cfg(target_os = "macos")]
        {
            match keyring_entry(id)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(map_keyring_error(error)),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = id;
            Err(ProtectedStoreError::UnsupportedPlatform)
        }
    }
}

/// Linux operating-system store bound to one already-negotiated encrypted
/// Secret Service session. Isolated broker processes construct this before
/// denying new Unix-socket creation, then reuse only that exact connection.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct ConnectedOsProtectedStore {
    service: Arc<Mutex<SecretService<'static>>>,
}

#[cfg(target_os = "linux")]
impl ConnectedOsProtectedStore {
    pub fn connect() -> Result<Self, ProtectedStoreError> {
        let service = linux_run(linux_secret_service())?;
        Ok(Self {
            service: Arc::new(Mutex::new(service)),
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for ConnectedOsProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedOsProtectedStore([REDACTED])")
    }
}

#[cfg(target_os = "linux")]
impl ProtectedStore for ConnectedOsProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        let service = self
            .service
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        linux_run(linux_get_with_service(&service, id))
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let service = self
            .service
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        linux_run(linux_put_with_service(&service, id, value))
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        let service = self
            .service
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        linux_run(linux_delete_with_service(&service, id))
    }
}

#[cfg(target_os = "linux")]
fn linux_get(id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
    linux_run(linux_get_async(id))
}

#[cfg(target_os = "linux")]
async fn linux_get_async(
    id: &ProtectedEntryId,
) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
    let service = linux_secret_service().await?;
    linux_get_with_service(&service, id).await
}

#[cfg(target_os = "linux")]
async fn linux_get_with_service(
    service: &SecretService<'_>,
    id: &ProtectedEntryId,
) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
    let search = service
        .search_items(linux_attributes(id))
        .await
        .map_err(map_linux_secret_service_error)?;
    let count = search.unlocked.len() + search.locked.len();
    if count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(ProtectedStoreError::AmbiguousEntry);
    }
    let item = search
        .unlocked
        .first()
        .or_else(|| search.locked.first())
        .ok_or(ProtectedStoreError::Unavailable)?;
    linux_unlock_item(item).await?;
    let value = item
        .get_secret()
        .await
        .map_err(map_linux_secret_service_error)?;
    protected_value_from_store(value).map(Some)
}

fn protected_value_from_store(value: Vec<u8>) -> Result<ProtectedValue, ProtectedStoreError> {
    ProtectedValue::new(value).map_err(|_| ProtectedStoreError::CorruptEntry)
}

#[cfg(target_os = "linux")]
fn linux_put(id: &ProtectedEntryId, value: &ProtectedValue) -> Result<(), ProtectedStoreError> {
    linux_run(linux_put_async(id, value))
}

#[cfg(target_os = "linux")]
async fn linux_put_async(
    id: &ProtectedEntryId,
    value: &ProtectedValue,
) -> Result<(), ProtectedStoreError> {
    let service = linux_secret_service().await?;
    linux_put_with_service(&service, id, value).await
}

#[cfg(target_os = "linux")]
async fn linux_put_with_service(
    service: &SecretService<'_>,
    id: &ProtectedEntryId,
    value: &ProtectedValue,
) -> Result<(), ProtectedStoreError> {
    let search = service
        .search_items(linux_attributes(id))
        .await
        .map_err(map_linux_secret_service_error)?;
    let count = search.unlocked.len() + search.locked.len();
    if count > 1 {
        return Err(ProtectedStoreError::AmbiguousEntry);
    }
    if let Some(item) = search.unlocked.first().or_else(|| search.locked.first()) {
        linux_unlock_item(item).await?;
        return item
            .set_secret(value.expose_secret(), "application/octet-stream")
            .await
            .map_err(map_linux_secret_service_error);
    }

    let collection = service
        .get_default_collection()
        .await
        .map_err(map_linux_secret_service_error)?;
    if collection
        .is_locked()
        .await
        .map_err(map_linux_secret_service_error)?
    {
        collection
            .unlock()
            .await
            .map_err(map_linux_secret_service_error)?;
    }
    collection
        .create_item(
            "Codewire credential",
            linux_attributes(id),
            value.expose_secret(),
            true,
            "application/octet-stream",
        )
        .await
        .map_err(map_linux_secret_service_error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_delete(id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
    linux_run(linux_delete_async(id))
}

#[cfg(target_os = "linux")]
async fn linux_delete_async(id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
    let service = linux_secret_service().await?;
    linux_delete_with_service(&service, id).await
}

#[cfg(target_os = "linux")]
async fn linux_delete_with_service(
    service: &SecretService<'_>,
    id: &ProtectedEntryId,
) -> Result<(), ProtectedStoreError> {
    let search = service
        .search_items(linux_attributes(id))
        .await
        .map_err(map_linux_secret_service_error)?;
    let count = search.unlocked.len() + search.locked.len();
    if count == 0 {
        return Ok(());
    }
    if count != 1 {
        return Err(ProtectedStoreError::AmbiguousEntry);
    }
    let item = search
        .unlocked
        .first()
        .or_else(|| search.locked.first())
        .ok_or(ProtectedStoreError::Unavailable)?;
    linux_unlock_item(item).await?;
    item.delete().await.map_err(map_linux_secret_service_error)
}

#[cfg(target_os = "linux")]
async fn linux_secret_service() -> Result<SecretService<'static>, ProtectedStoreError> {
    // Do not use a plaintext Secret Service session: the protected value must
    // be opaque to D-Bus observers as well as absent from Codewire metadata.
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(map_linux_secret_service_error)
}

#[cfg(target_os = "linux")]
async fn linux_unlock_item(item: &secret_service::Item<'_>) -> Result<(), ProtectedStoreError> {
    if item
        .is_locked()
        .await
        .map_err(map_linux_secret_service_error)?
    {
        item.unlock()
            .await
            .map_err(map_linux_secret_service_error)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_run<T>(
    operation: impl Future<Output = Result<T, ProtectedStoreError>>,
) -> Result<T, ProtectedStoreError> {
    linux_run_with_timeout(LINUX_SECRET_SERVICE_TIMEOUT, operation)
}

#[cfg(target_os = "linux")]
fn linux_run_with_timeout<T>(
    timeout: Duration,
    operation: impl Future<Output = Result<T, ProtectedStoreError>>,
) -> Result<T, ProtectedStoreError> {
    async_io::block_on(futures_lite::future::race(operation, async move {
        async_io::Timer::after(timeout).await;
        Err(ProtectedStoreError::TimedOut)
    }))
}

#[cfg(target_os = "linux")]
fn linux_attributes(id: &ProtectedEntryId) -> HashMap<&str, &str> {
    HashMap::from([
        ("application", "codewire"),
        ("service", CODEWIRE_CREDENTIAL_SERVICE),
        ("entry", id.expose_reference()),
    ])
}

#[cfg(target_os = "linux")]
fn map_linux_secret_service_error(error: secret_service::Error) -> ProtectedStoreError {
    match error {
        secret_service::Error::Locked | secret_service::Error::Prompt => {
            ProtectedStoreError::AccessDenied
        }
        secret_service::Error::Crypto(_)
        | secret_service::Error::PromptDisconnected
        | secret_service::Error::Zbus(_)
        | secret_service::Error::ZbusFdo(_)
        | secret_service::Error::Zvariant(_)
        | secret_service::Error::NoResult
        | secret_service::Error::Unavailable => ProtectedStoreError::Unavailable,
        _ => ProtectedStoreError::Unavailable,
    }
}

#[cfg(target_os = "macos")]
fn keyring_entry(id: &ProtectedEntryId) -> Result<keyring::Entry, ProtectedStoreError> {
    keyring::Entry::new(CODEWIRE_CREDENTIAL_SERVICE, id.expose_reference())
        .map_err(map_keyring_error)
}

#[cfg(target_os = "macos")]
fn map_keyring_error(error: keyring::Error) -> ProtectedStoreError {
    match error {
        keyring::Error::NoStorageAccess(_) => ProtectedStoreError::AccessDenied,
        keyring::Error::PlatformFailure(_) => ProtectedStoreError::Unavailable,
        keyring::Error::NoEntry => ProtectedStoreError::Unavailable,
        keyring::Error::BadEncoding(mut value) => {
            value.zeroize();
            ProtectedStoreError::CorruptEntry
        }
        keyring::Error::TooLong(mut attribute, _) => {
            attribute.zeroize();
            ProtectedStoreError::InvalidEntryId
        }
        keyring::Error::Invalid(mut attribute, mut reason) => {
            attribute.zeroize();
            reason.zeroize();
            ProtectedStoreError::InvalidEntryId
        }
        keyring::Error::Ambiguous(_) => ProtectedStoreError::AmbiguousEntry,
        _ => ProtectedStoreError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &str) -> ProtectedEntryId {
        ProtectedEntryId::parse(value).expect("protected entry ID")
    }

    #[test]
    fn entry_ids_are_exact_canonical_and_redacted() {
        let id = entry("credentials/0199aa11-bb22-cc33-dd44-556677889900/generations/2");
        assert_eq!(
            id.expose_reference(),
            "credentials/0199aa11-bb22-cc33-dd44-556677889900/generations/2"
        );
        assert_eq!(format!("{id:?}"), "ProtectedEntryId([REDACTED])");

        for invalid in [
            "",
            "/credentials/a",
            "credentials//a",
            "credentials/../a",
            "credentials/UPPER",
            "credentials/a ",
            "credentials/a@b",
        ] {
            assert_eq!(
                ProtectedEntryId::parse(invalid),
                Err(ProtectedStoreError::InvalidEntryId),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn values_are_bounded_nonempty_and_never_debuggable() {
        assert!(matches!(
            ProtectedValue::new(Vec::new()),
            Err(ProtectedStoreError::EmptyValue)
        ));
        assert!(matches!(
            ProtectedValue::new(vec![0; MAX_PROTECTED_VALUE_BYTES + 1]),
            Err(ProtectedStoreError::ValueTooLarge)
        ));
        let value = ProtectedValue::from_slice(b"synthetic-token-value").unwrap();
        assert_eq!(value.expose_secret(), b"synthetic-token-value");
        assert_eq!(format!("{value:?}"), "ProtectedValue([REDACTED])");
    }

    #[test]
    fn invalid_values_loaded_from_a_backend_are_reported_as_corrupt() {
        assert!(matches!(
            protected_value_from_store(Vec::new()),
            Err(ProtectedStoreError::CorruptEntry)
        ));
        assert!(matches!(
            protected_value_from_store(vec![0; MAX_PROTECTED_VALUE_BYTES + 1]),
            Err(ProtectedStoreError::CorruptEntry)
        ));
    }

    #[test]
    fn ephemeral_store_supports_only_exact_idempotent_operations() {
        let store = EphemeralProtectedStore::default();
        let first = entry("credentials/first/generations/1");
        let second = entry("credentials/second/generations/1");
        let value = ProtectedValue::new(vec![0, 159, 146, 150, 255]).unwrap();

        assert_eq!(
            store.persistence(),
            ProtectedStorePersistence::ProcessLifetime
        );
        assert!(store.get(&first).unwrap().is_none());
        store.put(&first, &value).unwrap();
        assert_eq!(
            store.get(&first).unwrap().unwrap().expose_secret(),
            value.expose_secret()
        );
        assert!(store.get(&second).unwrap().is_none());
        store.delete(&second).unwrap();
        store.delete(&first).unwrap();
        store.delete(&first).unwrap();
        assert!(store.get(&first).unwrap().is_none());
        assert_eq!(format!("{store:?}"), "EphemeralProtectedStore([REDACTED])");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_errors_are_classified_and_flattened_without_sources_or_payloads() {
        for (error, expected) in [
            (
                secret_service::Error::Locked,
                ProtectedStoreError::AccessDenied,
            ),
            (
                secret_service::Error::Prompt,
                ProtectedStoreError::AccessDenied,
            ),
            (
                secret_service::Error::Unavailable,
                ProtectedStoreError::Unavailable,
            ),
            (
                secret_service::Error::NoResult,
                ProtectedStoreError::Unavailable,
            ),
            (
                secret_service::Error::PromptDisconnected,
                ProtectedStoreError::Unavailable,
            ),
            (
                secret_service::Error::Crypto("synthetic-secret-that-must-not-escape"),
                ProtectedStoreError::Unavailable,
            ),
        ] {
            let mapped = map_linux_secret_service_error(error);
            assert_eq!(mapped, expected);
            assert!(!format!("{mapped:?} {mapped}").contains("synthetic-secret"));
            assert!(std::error::Error::source(&mapped).is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_operations_have_a_fail_closed_deadline() {
        let pending = std::future::pending::<Result<(), ProtectedStoreError>>();
        assert_eq!(
            linux_run_with_timeout(Duration::ZERO, pending),
            Err(ProtectedStoreError::TimedOut)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keyring_errors_are_flattened_without_sources_or_payloads() {
        let secret = b"synthetic-secret-that-must-not-escape".to_vec();
        let mapped = map_keyring_error(keyring::Error::BadEncoding(secret.clone()));
        assert_eq!(mapped, ProtectedStoreError::CorruptEntry);
        assert!(!format!("{mapped:?} {mapped}").contains("synthetic-secret"));
        assert!(std::error::Error::source(&mapped).is_none());

        assert_eq!(
            map_keyring_error(keyring::Error::Invalid(
                "user".into(),
                "synthetic-secret-that-must-not-escape".into(),
            )),
            ProtectedStoreError::InvalidEntryId
        );
    }

    #[test]
    fn os_store_identity_is_stable_without_touching_a_real_keyring() {
        let store = OsProtectedStore;
        assert_eq!(
            store.persistence(),
            ProtectedStorePersistence::OperatingSystem
        );
        assert_eq!(format!("{store:?}"), "OsProtectedStore([REDACTED])");
        assert_eq!(CODEWIRE_CREDENTIAL_SERVICE, "sh.codewire.credentials");
    }
}
