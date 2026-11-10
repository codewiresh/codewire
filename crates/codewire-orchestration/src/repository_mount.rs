//! Repository workspace-path normalization shared by the create API and setup
//! worker. Setup removes an existing checkout before cloning, so every path is
//! validated here before it can reach that destructive operation.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryMountError {
    detail: String,
}

impl RepositoryMountError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for RepositoryMountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for RepositoryMountError {}

/// Return the explicit canonical mount path.
///
/// User-facing project parsing may derive a destination before constructing a
/// canonical `ProjectSpec`, but the setup boundary never does. That keeps a
/// missing or stale wire value from changing the target of the worker's
/// destructive pre-clone removal.
pub(crate) fn canonical_repository_mount(
    repo_url: &str,
    mount_path: &str,
) -> Result<String, RepositoryMountError> {
    validate_repository_mounts([(repo_url, mount_path)]).map(|mut paths| paths.remove(0))
}

/// Validate every canonical checkout path and reject duplicate repositories.
/// A repository may sit inside another (#4024): the setup worker clones a
/// parent before the repositories inside it, and refuses a nested path the
/// parent tracks before its pre-clone removal could delete the parent's files.
pub(crate) fn validate_repository_mounts<'a>(
    repos: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<String>, RepositoryMountError> {
    let repos = repos.into_iter().collect::<Vec<_>>();
    if repos.iter().any(|(_, destination)| destination.is_empty()) {
        return Err(RepositoryMountError::new(
            "repository destination is required at the setup boundary",
        ));
    }
    let normalized = codewire_project::validate_repository_destinations(repos.iter().copied())
        .map_err(|error| RepositoryMountError::new(error.to_string()))?;
    if repos
        .iter()
        .zip(&normalized)
        .any(|((_, destination), normalized)| *destination != normalized)
    {
        return Err(RepositoryMountError::new(
            "repository destination must already be canonical",
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_repository_mount() {
        assert!(canonical_repository_mount("https://github.com/org/app.git", "").is_err());
        assert!(canonical_repository_mount("git@host:org/app.git", "").is_err());
    }

    #[test]
    fn accepts_normalized_workspace_descendants() {
        assert_eq!(
            canonical_repository_mount("https://example.com/app", "/workspace/services/app")
                .unwrap(),
            "/workspace/services/app"
        );
    }

    #[test]
    fn rejects_unsafe_or_non_normalized_paths() {
        for path in [
            "/workspace",
            "/workspace/",
            "/tmp/app",
            "workspace/app",
            "/workspace/../app",
            "/workspace/./app",
            "/workspace/app//src",
            "/workspace/app/",
            "/workspace/app\nother",
        ] {
            assert!(
                canonical_repository_mount("https://example.com/app", path).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_repository_sources() {
        assert!(canonical_repository_mount("..", "/workspace/app").is_err());
        assert!(canonical_repository_mount("https://example.com/", "/workspace/app").is_err());
    }

    #[test]
    fn rejects_noncanonical_destination_whitespace() {
        assert!(canonical_repository_mount("https://example.com/app", " /workspace/app ").is_err());
    }

    #[test]
    fn rejects_duplicate_mounts_and_allows_nested_ones() {
        assert!(
            validate_repository_mounts([
                ("https://example.com/a", "/workspace/app"),
                ("https://example.com/b", "/workspace/app"),
            ])
            .is_err()
        );
        assert!(
            validate_repository_mounts([
                ("https://example.com/a", "/workspace/app"),
                ("https://example.com/b", "/workspace/app/docs"),
            ])
            .is_ok()
        );
        assert!(
            validate_repository_mounts([
                ("https://example.com/a", "/workspace/app"),
                ("https://example.com/b", "/workspace/application"),
            ])
            .is_ok()
        );
    }
}
