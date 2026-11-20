//! The authority's store as its credential children (the broker and the
//! repository executor) receive and open it, on Linux and macOS alike.
//!
//! The authority names its own store on each child's command line; a child
//! that reads material opens exactly that store, never a platform default.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;
use codewire_local_credentials::{
    AuthorityProtectedStore, FILE_STORE_DIRECTORY, RefreshStagingStore, RefreshStagingWrite,
};
#[cfg(target_os = "linux")]
use codewire_protected_store::ConnectedOsProtectedStore;
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreBackend, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue, SelectedProtectedStore,
};

/// The authority store as a child receives it on its command line.
#[derive(Debug, Args)]
pub(crate) struct ChildStoreArgs {
    /// The authority's store: children read the selected backend, not a
    /// platform default.
    #[arg(long)]
    pub(crate) protected_store: String,
    /// The file backend's entry directory inside the authority root.
    #[arg(long)]
    pub(crate) protected_store_directory: Option<PathBuf>,
    /// Test-only explicit keychain file for the keychain backend.
    #[cfg(target_os = "macos")]
    #[arg(long)]
    pub(crate) keychain: Option<PathBuf>,
}

/// The authority's store arguments for a child it launches.
pub(crate) fn child_store_arguments(
    store: &AuthorityProtectedStore,
    authority_root: &Path,
) -> Option<Vec<OsString>> {
    let mut arguments = vec![
        OsString::from("--protected-store"),
        store.backend.as_str().into(),
    ];
    match (store.backend, &store.keychain) {
        #[cfg(target_os = "linux")]
        (ProtectedStoreBackend::SecretService, None) => {}
        #[cfg(target_os = "macos")]
        (ProtectedStoreBackend::Keychain, keychain) => {
            if let Some(keychain) = keychain {
                arguments.push("--keychain".into());
                arguments.push(keychain.clone().into_os_string());
            }
        }
        (ProtectedStoreBackend::File, None) => {
            arguments.push("--protected-store-directory".into());
            arguments.push(authority_root.join(FILE_STORE_DIRECTORY).into_os_string());
        }
        _ => return None,
    }
    Some(arguments)
}

/// The authority store a child reads, validated before any effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChildStore {
    /// One owner-only file per entry in this directory.
    File { directory: PathBuf },
    /// The session's Secret Service, reached once over its bus.
    #[cfg(target_os = "linux")]
    SecretService,
    /// The login keychain, or an explicit test keychain file.
    #[cfg(target_os = "macos")]
    Keychain { keychain: Option<PathBuf> },
}

impl ChildStore {
    pub(crate) fn from_args(args: &ChildStoreArgs) -> anyhow::Result<Self> {
        let backend = ProtectedStoreBackend::parse(&args.protected_store)
            .filter(|backend| backend.supported())
            .context("invalid child protected store")?;
        #[cfg(target_os = "macos")]
        let keychain = &args.keychain;
        #[cfg(not(target_os = "macos"))]
        let keychain: &Option<PathBuf> = &None;
        match (backend, &args.protected_store_directory, keychain) {
            (ProtectedStoreBackend::File, Some(directory), None) => {
                anyhow::ensure!(
                    directory.file_name() == Some(OsStr::new(FILE_STORE_DIRECTORY))
                        && plain_path(directory).is_some(),
                    "invalid child protected store"
                );
                Ok(Self::File {
                    directory: directory.clone(),
                })
            }
            #[cfg(target_os = "linux")]
            (ProtectedStoreBackend::SecretService, None, None) => Ok(Self::SecretService),
            #[cfg(target_os = "macos")]
            (ProtectedStoreBackend::Keychain, None, keychain) => {
                if let Some(keychain) = keychain {
                    anyhow::ensure!(
                        plain_path(keychain).is_some(),
                        "invalid child protected store"
                    );
                }
                Ok(Self::Keychain {
                    keychain: keychain.clone(),
                })
            }
            _ => anyhow::bail!("invalid child protected store"),
        }
    }

    /// The file store's directory, the only path a Linux broker may read.
    #[cfg(target_os = "linux")]
    pub(crate) fn file_directory(&self) -> Option<&Path> {
        match self {
            Self::File { directory } => Some(directory),
            Self::SecretService => None,
        }
    }

    /// Opening reads no value. Secret Service is connected here, once: a
    /// confined broker can make no new Unix connection afterwards.
    pub(crate) fn open(&self) -> anyhow::Result<OpenedChildStore> {
        match self {
            Self::File { directory } => {
                SelectedProtectedStore::open(ProtectedStoreBackend::File, directory, None)
                    .map(OpenedChildStore::Selected)
                    .map_err(|error| anyhow::anyhow!("{error}"))
            }
            #[cfg(target_os = "linux")]
            Self::SecretService => ConnectedOsProtectedStore::connect()
                .map(OpenedChildStore::SecretService)
                .map_err(|error| anyhow::anyhow!("{error}")),
            #[cfg(target_os = "macos")]
            Self::Keychain { keychain } => SelectedProtectedStore::open(
                ProtectedStoreBackend::Keychain,
                Path::new("/"),
                keychain.as_deref(),
            )
            .map(OpenedChildStore::Selected)
            .map_err(|error| anyhow::anyhow!("{error}")),
        }
    }
}

/// A child's opened store, read-only: children only read the material the
/// authority names, and the authority alone writes it.
#[derive(Clone, Debug)]
pub(crate) enum OpenedChildStore {
    Selected(SelectedProtectedStore),
    #[cfg(target_os = "linux")]
    SecretService(ConnectedOsProtectedStore),
}

impl OpenedChildStore {
    fn store(&self) -> &dyn ProtectedStore {
        match self {
            Self::Selected(store) => store,
            #[cfg(target_os = "linux")]
            Self::SecretService(store) => store,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn selected(&self) -> &SelectedProtectedStore {
        match self {
            Self::Selected(store) => store,
        }
    }
}

impl ProtectedStore for OpenedChildStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.store().persistence()
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.store().get(id)
    }

    fn put(&self, _: &ProtectedEntryId, _: &ProtectedValue) -> Result<(), ProtectedStoreError> {
        Err(ProtectedStoreError::AccessDenied)
    }

    fn delete(&self, _: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        Err(ProtectedStoreError::AccessDenied)
    }
}

/// The one write a child makes (#5537): a started refresh's bundle, into the
/// entry its [`RefreshStagingWrite`] names, staged in the store this child
/// opened. `put` and `delete` above still refuse everything. Only Secret
/// Service takes it. A `file` store does not, since the broker's Landlock
/// domain only reads it, and neither does a keychain until a staged write is
/// recorded working inside the broker's Seatbelt profile, which allows only
/// reads of it. Their refresh is refused before Start (#5539).
impl RefreshStagingStore for OpenedChildStore {
    fn can_stage_refresh(&self) -> bool {
        match self {
            Self::Selected(_) => false,
            #[cfg(target_os = "linux")]
            Self::SecretService(_) => true,
        }
    }

    fn stage_refresh(
        &self,
        write: RefreshStagingWrite,
        material: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        if !self.can_stage_refresh() {
            return Err(ProtectedStoreError::AccessDenied);
        }
        write.stage(self.store(), material)
    }
}

/// An absolute path made only of characters that need no quoting in a
/// Seatbelt string, without `.` or `..` components.
pub(crate) fn plain_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    let plain = path.is_absolute()
        && text.len() <= 512
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
        && text.split('/').all(|part| !matches!(part, "." | ".."));
    plain.then_some(text)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
