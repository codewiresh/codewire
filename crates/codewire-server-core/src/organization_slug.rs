//! Organization slug rules shared by HTTP adapters and product services.
//!
//! Organization slugs are the first segment of authenticated dashboard URLs.
//! They therefore must not collide with public, authentication, asset, service,
//! or administrative routes owned by the same origin.

/// Route segments that can never be used as organization slugs.
pub const RESERVED_ORGANIZATION_SLUGS: &[&str] = &[
    "accept-invite",
    "admin",
    "api",
    "assets",
    "auth",
    "connect",
    "dashboard",
    "device",
    "docs",
    "forgot-password",
    "grpc",
    "healthz",
    "login",
    "oauth",
    "organizations",
    "preview",
    "reset-password",
    "settings",
    "setup-2fa",
    "signup",
    "ssh-proxy",
    "terminal",
    "two-factor",
    "verify-email",
];

/// Validate the canonical lowercase organization slug contract.
pub fn valid_organization_slug(slug: &str) -> bool {
    (3..=48).contains(&slug.len())
        && !RESERVED_ORGANIZATION_SLUGS.contains(&slug)
        && slug.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_route_segments() {
        for slug in ["acme", "acme-2", "a2b", "123"] {
            assert!(valid_organization_slug(slug), "expected {slug} to be valid");
        }
    }

    #[test]
    fn rejects_invalid_and_reserved_route_segments() {
        for slug in [
            "ab",
            "Acme",
            "-acme",
            "acme-",
            "acme--corp",
            "acme_corp",
            "admin",
            "api",
            "assets",
            "dashboard",
            "docs",
            "organizations",
            "settings",
            "terminal",
        ] {
            assert!(
                !valid_organization_slug(slug),
                "expected {slug:?} to be invalid"
            );
        }
    }
}
