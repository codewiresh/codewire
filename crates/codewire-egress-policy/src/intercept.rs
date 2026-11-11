//! Interception bindings (#3999): exact names whose TCP dials on one port are
//! handed to a local receiver instead of being dialled.
//!
//! A binding names only where to intercept. What the receiver does with an
//! intercepted connection belongs to that receiver, not to this policy state.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::hostname::{canonical_hostname, protected_name};

pub const MAX_INTERCEPT_BINDINGS: usize = 32;

/// One exact, canonical, unprotected hostname and one non-zero TCP port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterceptBinding {
    hostname: String,
    port: u16,
}

impl InterceptBinding {
    pub fn new(hostname: &str, port: u16) -> Result<Self, InterceptError> {
        if port == 0 {
            return Err(InterceptError::ZeroPort);
        }
        // A pattern would intercept names nobody listed; only exact names.
        if hostname.contains('*') {
            return Err(InterceptError::Pattern);
        }
        let hostname = canonical_hostname(hostname).map_err(InterceptError::InvalidHostname)?;
        if protected_name(&hostname).is_some() {
            return Err(InterceptError::ProtectedName);
        }
        Ok(Self { hostname, port })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A bounded set of bindings, sorted and without duplicates. The default is
/// empty: nothing is intercepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterceptSet {
    bindings: Vec<InterceptBinding>,
}

impl InterceptSet {
    pub fn new(
        bindings: impl IntoIterator<Item = InterceptBinding>,
    ) -> Result<Self, InterceptError> {
        let mut unique = BTreeSet::new();
        for binding in bindings {
            unique.insert(binding);
            // Refuse as soon as the bound is passed, so an oversized input is
            // never held whole.
            if unique.len() > MAX_INTERCEPT_BINDINGS {
                return Err(InterceptError::TooManyBindings {
                    maximum: MAX_INTERCEPT_BINDINGS,
                });
            }
        }
        Ok(Self {
            bindings: unique.into_iter().collect(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// The bindings, ordered by hostname and then port.
    pub fn bindings(&self) -> &[InterceptBinding] {
        &self.bindings
    }

    /// Whether `hostname`, already canonical, is bound on `port`.
    pub fn binds(&self, hostname: &str, port: u16) -> bool {
        self.bindings
            .binary_search_by(|binding| {
                (binding.hostname.as_str(), binding.port).cmp(&(hostname, port))
            })
            .is_ok()
    }

    /// Whether `hostname`, already canonical, is bound on any port.
    pub fn binds_name(&self, hostname: &str) -> bool {
        let first = self
            .bindings
            .partition_point(|binding| binding.hostname.as_str() < hostname);
        self.bindings
            .get(first)
            .is_some_and(|binding| binding.hostname == hostname)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InterceptError {
    #[error("interception hostname is invalid: {0}")]
    InvalidHostname(String),
    #[error("interception hostname must be one exact name, not a pattern")]
    Pattern,
    #[error("interception hostname is protected")]
    ProtectedName,
    #[error("interception port must be non-zero")]
    ZeroPort,
    #[error("interception set has more than {maximum} bindings")]
    TooManyBindings { maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(hostname: &str, port: u16) -> InterceptBinding {
        InterceptBinding::new(hostname, port).unwrap()
    }

    #[test]
    fn a_binding_is_one_canonical_exact_unprotected_name_and_a_port() {
        let bound = binding("API.Example.COM.", 443);
        assert_eq!(bound.hostname(), "api.example.com");
        assert_eq!(bound.port(), 443);

        for pattern in ["*", "*.example.com", "api.*.com"] {
            assert_eq!(
                InterceptBinding::new(pattern, 443),
                Err(InterceptError::Pattern),
                "{pattern}"
            );
        }
        for literal in ["93.184.216.34", "2606:4700:4700::1111", "127.0.0.1"] {
            assert!(
                matches!(
                    InterceptBinding::new(literal, 443),
                    Err(InterceptError::InvalidHostname(detail)) if detail.contains("IP literal")
                ),
                "{literal}"
            );
        }
        for invalid in [
            "",
            ".",
            "two..dots",
            "bad_name.example.com",
            " api.example.com",
        ] {
            assert!(
                matches!(
                    InterceptBinding::new(invalid, 443),
                    Err(InterceptError::InvalidHostname(_))
                ),
                "{invalid:?}"
            );
        }
        for protected in [
            "localhost",
            "api.localhost",
            "service.internal",
            "metadata.google.internal",
            "printer.local",
            "router.home.arpa",
        ] {
            assert_eq!(
                InterceptBinding::new(protected, 443),
                Err(InterceptError::ProtectedName),
                "{protected}"
            );
        }
        assert_eq!(
            InterceptBinding::new("api.example.com", 0),
            Err(InterceptError::ZeroPort)
        );
    }

    #[test]
    fn errors_do_not_echo_the_refused_input() {
        for (hostname, port) in [
            ("secret-name.local", 443),
            ("*.secret-name.com", 443),
            ("secret_name.com", 443),
            ("secret-name.com", 0),
        ] {
            let error = InterceptBinding::new(hostname, port).unwrap_err();
            assert!(!error.to_string().contains("secret"), "{error}");
        }
    }

    #[test]
    fn a_set_is_sorted_deduplicated_and_bounded() {
        let set = InterceptSet::new([
            binding("b.example.com", 443),
            binding("a.example.com", 8443),
            binding("A.example.com.", 443),
            binding("b.example.com", 443),
        ])
        .unwrap();
        assert_eq!(
            set.bindings(),
            [
                binding("a.example.com", 443),
                binding("a.example.com", 8443),
                binding("b.example.com", 443),
            ]
        );
        assert_eq!(set.len(), 3);
        assert!(set.binds("a.example.com", 8443));
        assert!(set.binds("b.example.com", 443));
        assert!(!set.binds("b.example.com", 8443));
        assert!(!set.binds("c.example.com", 443));
        assert!(set.binds_name("a.example.com"));
        assert!(set.binds_name("b.example.com"));
        assert!(!set.binds_name("example.com"));
        assert!(!set.binds_name("c.example.com"));

        let empty = InterceptSet::default();
        assert!(empty.is_empty());
        assert!(!empty.binds_name("a.example.com"));
        assert_eq!(InterceptSet::new([]).unwrap(), empty);

        let full = (0..MAX_INTERCEPT_BINDINGS)
            .map(|index| binding(&format!("host-{index}.example.com"), 443))
            .collect::<Vec<_>>();
        // Duplicates do not count towards the bound.
        let at_bound = InterceptSet::new(full.iter().cloned().chain(full.iter().cloned())).unwrap();
        assert_eq!(at_bound.len(), MAX_INTERCEPT_BINDINGS);
        assert_eq!(
            InterceptSet::new(
                full.into_iter()
                    .chain([binding("one-more.example.com", 443)])
            ),
            Err(InterceptError::TooManyBindings {
                maximum: MAX_INTERCEPT_BINDINGS,
            })
        );
    }
}
