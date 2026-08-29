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

/// Return the explicit mount path, or the legacy repository-name-derived path.
/// The result is always a normalized descendant of `/workspace`.
pub(crate) fn effective_repository_mount(
    repo_url: &str,
    mount_path: &str,
) -> Result<String, RepositoryMountError> {
    codewire_project::validate_repository_destinations([(repo_url, mount_path)])
        .map(|mut paths| paths.remove(0))
        .map_err(|error| RepositoryMountError::new(error.to_string()))
}

/// Validate every effective checkout path and reject duplicate or nested
/// repositories. Nested targets make the setup worker's pre-clone removal
/// order-dependent and can destroy a sibling checkout.
pub(crate) fn validate_repository_mounts<'a>(
    repos: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<String>, RepositoryMountError> {
    codewire_project::validate_repository_destinations(repos)
        .map_err(|error| RepositoryMountError::new(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_legacy_repository_mount() {
        assert_eq!(
            effective_repository_mount("https://github.com/org/app.git", "").unwrap(),
            "/workspace/app"
        );
        assert_eq!(
            effective_repository_mount("git@host:org/app.git", "").unwrap(),
            "/workspace/app"
        );
    }

    #[test]
    fn accepts_normalized_workspace_descendants() {
        assert_eq!(
            effective_repository_mount("https://example.com/app", "/workspace/services/app")
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
                effective_repository_mount("https://example.com/app", path).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn rejects_unsafe_default_repository_names() {
        assert!(effective_repository_mount("..", "").is_err());
        assert!(effective_repository_mount("https://example.com/", "").is_err());
    }

    #[test]
    fn rejects_duplicate_and_nested_mounts() {
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
            .is_err()
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
