//! Repository workspace-path normalization shared by the create API and setup
//! worker. Setup removes an existing checkout before cloning, so every path is
//! validated here before it can reach that destructive operation.

use std::fmt;

const WORKSPACE_ROOT: &str = "/workspace";

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

/// Trim a `.git` suffix, then take the last URL path segment.
pub(crate) fn repo_name_from_url(repo_url: &str) -> String {
    let trimmed = repo_url.strip_suffix(".git").unwrap_or(repo_url);
    let no_frag = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    match no_frag.rsplit('/').next() {
        Some(segment) if !segment.is_empty() => segment.to_string(),
        _ => no_frag.to_string(),
    }
}

/// Return the explicit mount path, or the legacy repository-name-derived path.
/// The result is always a normalized descendant of `/workspace`.
pub(crate) fn effective_repository_mount(
    repo_url: &str,
    mount_path: &str,
) -> Result<String, RepositoryMountError> {
    let path = if mount_path.is_empty() {
        format!("{WORKSPACE_ROOT}/{}", repo_name_from_url(repo_url))
    } else {
        mount_path.to_string()
    };
    validate_repository_mount(&path)?;
    Ok(path)
}

/// Validate every effective checkout path and reject duplicate or nested
/// repositories. Nested targets make the setup worker's pre-clone removal
/// order-dependent and can destroy a sibling checkout.
pub(crate) fn validate_repository_mounts<'a>(
    repos: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<String>, RepositoryMountError> {
    let mut paths = repos
        .into_iter()
        .map(|(url, mount_path)| effective_repository_mount(url, mount_path))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();

    for pair in paths.windows(2) {
        let parent = &pair[0];
        let child = &pair[1];
        if child == parent {
            return Err(RepositoryMountError::new(format!(
                "repository mount paths must be unique: {child}"
            )));
        }
        if child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(RepositoryMountError::new(format!(
                "repository mount paths must not overlap: {parent} and {child}"
            )));
        }
    }
    Ok(paths)
}

fn validate_repository_mount(path: &str) -> Result<(), RepositoryMountError> {
    if path.chars().any(char::is_control) {
        return Err(RepositoryMountError::new(
            "repository mount path must not contain control characters",
        ));
    }
    let Some(relative) = path.strip_prefix("/workspace/") else {
        return Err(RepositoryMountError::new(
            "repository mount path must be strictly under /workspace",
        ));
    };
    if relative.is_empty() || path.ends_with('/') {
        return Err(RepositoryMountError::new(
            "repository mount path must name a directory under /workspace",
        ));
    }
    if relative
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(RepositoryMountError::new(
            "repository mount path must be normalized without empty, . or .. segments",
        ));
    }
    Ok(())
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
