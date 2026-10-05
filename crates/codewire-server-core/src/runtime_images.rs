//! Default runtime images, by Harbor digest.
//!
//! This is the only place these digests are written. Orchestration, the
//! dashboard, publication, audit and browser tests all read them from here.
//! Deployments still pin the gateway per release through `SANDBOX_GATEWAY_IMAGE`;
//! this default applies only when that is unset.

/// Workspace image used when a Sandbox does not choose one.
pub const DEFAULT_WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:ad1f2db5ff86c616ea7fb7b8c3f196b271a0bc5b75a636f4b4ffd77fb1ee2313";

/// Gateway sidecar image used when `SANDBOX_GATEWAY_IMAGE` is unset.
pub const DEFAULT_GATEWAY_IMAGE: &str = "registry.example.invalid/codewire/gateway@sha256:1f5972c44d7063815d4d5163f06fc8db5428a5a57dacc4816841cc5cd97ce190";

/// Every repository a release has rendered the support (gateway) image from,
/// and so the daemon of an existing Sandbox. A Start re-pins a Sandbox's
/// daemon only from an image in one of these, compared exactly, never by
/// suffix. Add a repository here before deployments render from it.
pub const SUPPORT_IMAGE_REPOSITORIES: [&str; 6] = [
    // Harbor, Dev and Production since 2026-09-25.
    "registry.example.invalid/codewire/gateway",
    // Nexus, Dev and Production from 2026-08-15 to 2026-09-28.
    "nexus.example.invalid/oci-approved/codewire/gateway",
    // Nexus over the tailnet, Dev and Production from 2026-08-12 to 2026-08-15.
    "nexus-system-cluster.example.invalid/oci-approved/codewire/gateway",
    // Nexus release candidates, which Dev candidate smokes rendered from
    // 2026-08-12 to 2026-09-24.
    "nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway",
    // GHCR, Dev and Production from 2026-08-04 to 2026-08-15.
    "ghcr.io/codewiresh/gateway",
    // The Forgejo registry: deployments before 2026-08-04, and Production's
    // checked-in pin.
    "git.example.invalid/codewire/gateway",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_harbor_digest_references() {
        for (image, family) in [
            (DEFAULT_WORKSPACE_IMAGE, "workspace"),
            (DEFAULT_GATEWAY_IMAGE, "gateway"),
        ] {
            let digest = image
                .strip_prefix(&format!("registry.example.invalid/codewire/{family}@sha256:"))
                .expect("default must be an exact Harbor digest reference");
            assert_eq!(digest.len(), 64);
            assert!(
                digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
        }
    }

    #[test]
    fn support_image_repositories_are_exact_and_name_the_default() {
        let (default_repository, _) = DEFAULT_GATEWAY_IMAGE.split_once('@').unwrap();
        assert_eq!(SUPPORT_IMAGE_REPOSITORIES[0], default_repository);
        let mut unique = SUPPORT_IMAGE_REPOSITORIES.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), SUPPORT_IMAGE_REPOSITORIES.len());
        for repository in SUPPORT_IMAGE_REPOSITORIES {
            let (host, path) = repository.split_once('/').unwrap();
            assert!(host.contains('.'), "{repository} names no registry host");
            assert!(
                path.ends_with("/gateway") || path == "gateway",
                "{repository}"
            );
            assert!(
                !repository.contains('@') && !path.contains(':'),
                "{repository} carries a digest or tag"
            );
        }
    }
}
