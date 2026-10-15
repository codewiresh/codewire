//! Default runtime images, by Harbor digest.
//!
//! Orchestration, the dashboard, publication, audit and browser tests read
//! them from here. The daemon digest is written only here; the workspace digest
//! is the published pin in `codewire-workspace-image`, which support-images.yaml
//! proposes after each publication. Deployments still pin the daemon per
//! release through `SANDBOX_DAEMON_IMAGE`; this default applies only when that
//! is unset.

pub use codewire_workspace_image as workspace_image;

/// Workspace image used when a Sandbox does not choose one.
pub const DEFAULT_WORKSPACE_IMAGE: &str = codewire_workspace_image::HARBOR_IMAGE;

/// The same workspace image at its public mirror: what cw sends as its
/// default and what local environments pull.
pub const PUBLIC_WORKSPACE_IMAGE: &str = codewire_workspace_image::PUBLIC_IMAGE;

/// Whether a reference names the canonical workspace image: the current
/// digest, or an earlier one older clients and stored presets still send, at
/// Harbor or its public mirror.
pub fn is_canonical_workspace_image(image_ref: &str) -> bool {
    codewire_workspace_image::is_canonical(image_ref)
}

/// Support image the workspace daemon runs from when `SANDBOX_DAEMON_IMAGE`
/// is unset: the daemon Production runs since v0.3.384.
pub const DEFAULT_DAEMON_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:adaba1f8e5ca50ed7aaeaf1b15d0588e441cadd1830e508a83108f798f66e029";

/// Every repository a release renders the support (daemon) image from, and
/// so the daemon of an existing Sandbox. A Start re-pins a Sandbox's daemon
/// only from an image in one of these, compared exactly, never by suffix. Add
/// a repository here before deployments render from it.
pub const SUPPORT_IMAGE_REPOSITORIES: [&str; 1] = [
    // Harbor, Dev and Production.
    "registry.example.invalid/codewire/daemon",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn harbor_digest(image: &str, repository: &str) {
        let digest = image
            .strip_prefix(&format!("{repository}@sha256:"))
            .expect("default must be an exact Harbor digest reference");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn defaults_are_harbor_digest_references() {
        harbor_digest(
            DEFAULT_WORKSPACE_IMAGE,
            "registry.example.invalid/codewire/workspace",
        );
        harbor_digest(DEFAULT_DAEMON_IMAGE, "registry.example.invalid/codewire/daemon");
    }

    #[test]
    fn support_image_repositories_are_exact_and_name_the_default() {
        let (default_repository, _) = DEFAULT_DAEMON_IMAGE.split_once('@').unwrap();
        assert!(SUPPORT_IMAGE_REPOSITORIES.contains(&default_repository));
        assert_eq!(
            SUPPORT_IMAGE_REPOSITORIES[0],
            "registry.example.invalid/codewire/daemon"
        );
        let mut unique = SUPPORT_IMAGE_REPOSITORIES.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), SUPPORT_IMAGE_REPOSITORIES.len());
        for repository in SUPPORT_IMAGE_REPOSITORIES {
            let (host, path) = repository.split_once('/').unwrap();
            assert!(host.contains('.'), "{repository} names no registry host");
            assert!(path.ends_with("/daemon"), "{repository}");
            assert!(
                !repository.contains('@') && !path.contains(':'),
                "{repository} carries a digest or tag"
            );
        }
    }
}
