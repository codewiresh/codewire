//! A development build of cw never takes the account's own local VM store
//! by default (#4819). A dev build's supervisor on that store serves every
//! `cw` the account runs, and outlives the worktree it was built in
//! (2026-11-14: one served it for 20 hours). A dev build runs with its own
//! HOME or `CW_MESH_DATA_DIR`, or names a root in
//! `CODEWIRE_NATIVE_STATE_ROOT`, which may be the account's own on purpose.

use std::path::{Path, PathBuf};

use super::{NATIVE_STATE_ROOT_ENV, absolute_override};

/// The local VM state root: `CODEWIRE_NATIVE_STATE_ROOT`, else
/// `MESH_DATA_DIR/native-v1`, which a development build refuses when it is
/// the account's own store.
pub(super) fn state_root(mesh_data_dir: &Path) -> anyhow::Result<PathBuf> {
    if let Some(root) = absolute_override(NATIVE_STATE_ROOT_ENV)? {
        return Ok(root);
    }
    let root = mesh_data_dir.join("native-v1");
    let development = crate::local_runtime_pin::embedded()?.is_none();
    if development && let Ok(home) = crate::config::account::home_directory() {
        refuse_own_store(&root, &home)?;
    }
    Ok(root)
}

fn refuse_own_store(root: &Path, account_home: &Path) -> anyhow::Result<()> {
    let own = account_home.join(".codewire").join("native-v1");
    // The leaf may not exist yet on a first run: canonicalize what does exist
    // (the parent) and join the name, so a link to the account's own
    // `.codewire` is still seen.
    let same = |path: &Path| {
        std::fs::canonicalize(path).unwrap_or_else(|_| match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                .map_or_else(|_| path.to_owned(), |parent| parent.join(name)),
            _ => path.to_owned(),
        })
    };
    anyhow::ensure!(
        same(root) != same(&own),
        "this cw is a development build and would use your own local VM store at {}; \
         run it with its own HOME, or set {NATIVE_STATE_ROOT_ENV} to a scratch root, \
         or to that path to use it on purpose",
        root.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_accounts_own_store_is_refused() {
        let account = tempfile::tempdir().unwrap();
        let own = account.path().join(".codewire").join("native-v1");
        let error = refuse_own_store(&own, account.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("development build"), "{error}");
        assert!(error.contains(NATIVE_STATE_ROOT_ENV), "{error}");
        assert!(error.contains(&own.display().to_string()), "{error}");

        // Another HOME, or CW_MESH_DATA_DIR, leads elsewhere.
        let scratch = tempfile::tempdir().unwrap();
        let elsewhere = scratch.path().join(".codewire").join("native-v1");
        refuse_own_store(&elsewhere, account.path()).unwrap();
    }

    /// On a first run the store doesn't exist yet, but a HOME whose
    /// `.codewire` links to the account's own is still the account's.
    #[test]
    fn a_link_to_the_accounts_codewire_is_refused_before_the_store_exists() {
        let account = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(account.path().join(".codewire")).unwrap();
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            account.path().join(".codewire"),
            home.path().join(".codewire"),
        )
        .unwrap();
        let root = home.path().join(".codewire").join("native-v1");
        assert!(!root.exists());
        assert!(refuse_own_store(&root, account.path()).is_err());
    }

    #[test]
    fn the_same_store_through_a_link_is_still_the_accounts() {
        let account = tempfile::tempdir().unwrap();
        let own = account.path().join(".codewire").join("native-v1");
        std::fs::create_dir_all(&own).unwrap();
        let links = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(account.path().join(".codewire"), links.path().join("mesh"))
            .unwrap();
        let through = links.path().join("mesh").join("native-v1");
        assert!(refuse_own_store(&through, account.path()).is_err());
    }
}
