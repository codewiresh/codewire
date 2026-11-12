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
    "privacy",
    "reset-password",
    "settings",
    "setup-2fa",
    "signup",
    "ssh-proxy",
    "terminal",
    "terms",
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
            "privacy",
            "settings",
            "terminal",
            "terms",
        ] {
            assert!(
                !valid_organization_slug(slug),
                "expected {slug:?} to be invalid"
            );
        }
    }

    /// The database's `organizations_route_slug_check`, as the newest
    /// migration that replaces it writes it, reserves exactly this list. A
    /// change to the list is a new migration and a new path here.
    #[test]
    fn the_database_check_reserves_the_same_slugs() {
        let migration = include_str!("../migrations/0017_reserve_legal_page_slugs.sql");
        let check = migration
            .split("ADD CONSTRAINT organizations_route_slug_check")
            .nth(1)
            .expect("the migration adds the check");
        let array = check
            .split("ARRAY[")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("the check lists the reserved slugs");
        let reserved: Vec<&str> = array
            .split(", ")
            .map(|item| {
                item.strip_prefix('\'')
                    .and_then(|item| item.strip_suffix("'::text"))
                    .expect("a text literal")
            })
            .collect();
        assert_eq!(reserved, RESERVED_ORGANIZATION_SLUGS);
    }
}
