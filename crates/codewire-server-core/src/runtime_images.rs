//! Default runtime images, by Harbor digest.
//!
//! This is the only place these digests are written. Orchestration, the
//! dashboard, publication, audit and browser tests all read them from here.
//! Deployments still pin the gateway per release through `SANDBOX_GATEWAY_IMAGE`;
//! this default applies only when that is unset.

/// Workspace image used when a Sandbox does not choose one.
pub const DEFAULT_WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:920add04d53620ffbefc5df89738381c5268466538211d297a81d16fba10338a";

/// Gateway sidecar image used when `SANDBOX_GATEWAY_IMAGE` is unset.
pub const DEFAULT_GATEWAY_IMAGE: &str = "registry.example.invalid/codewire/gateway@sha256:1f5972c44d7063815d4d5163f06fc8db5428a5a57dacc4816841cc5cd97ce190";

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
}
