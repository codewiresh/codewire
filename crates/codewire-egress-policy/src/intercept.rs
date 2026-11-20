//! Interception bindings (#3999): exact names whose TCP dials on one port are
//! handed to a local receiver instead of being dialled, and suffixes whose
//! every subname is.
//!
//! A binding names only where to intercept. What the receiver does with an
//! intercepted connection belongs to that receiver, not to this policy state.
//! A suffix exists for a name a provider chooses at run time, such as the
//! origin Codex's account routing names under `chatgpt.com`: the broker sees
//! only a dial's name and port, so every subname on that port is handed over,
//! and the receiver serves only what it recognises.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::hostname::{canonical_hostname, protected_name};

pub const MAX_INTERCEPT_BINDINGS: usize = 32;
pub const MAX_INTERCEPT_SUFFIXES: usize = 8;
/// The most other bound names an intercepted dial's address carries to the
/// receiver, beside the one it is attributed to (#3999).
pub const MAX_INTERCEPT_ALIASES: usize = 6;

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

/// Every name strictly under one canonical, unprotected name of at least two
/// labels, on one non-zero TCP port: `chatgpt.com` covers `a.chatgpt.com`
/// and `a.b.chatgpt.com`, never `chatgpt.com` itself or `xchatgpt.com`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterceptSuffix {
    suffix: String,
    port: u16,
}

impl InterceptSuffix {
    pub fn new(suffix: &str, port: u16) -> Result<Self, InterceptError> {
        let InterceptBinding { hostname, port } = InterceptBinding::new(suffix, port)?;
        // A one-label suffix would intercept a whole top-level domain.
        if !hostname.contains('.') {
            return Err(InterceptError::SuffixTooShort);
        }
        Ok(Self {
            suffix: hostname,
            port,
        })
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether `hostname`, already canonical, is strictly under this suffix.
    pub fn covers(&self, hostname: &str) -> bool {
        hostname
            .strip_suffix(self.suffix.as_str())
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty())
    }
}

/// A bounded set of bindings and suffixes, each sorted and without
/// duplicates. The default is empty: nothing is intercepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterceptSet {
    bindings: Vec<InterceptBinding>,
    suffixes: Vec<InterceptSuffix>,
}

impl InterceptSet {
    pub fn new(
        bindings: impl IntoIterator<Item = InterceptBinding>,
    ) -> Result<Self, InterceptError> {
        Self::with_suffixes(bindings, [])
    }

    /// [`Self::new`], with every subname of each suffix bound too.
    pub fn with_suffixes(
        bindings: impl IntoIterator<Item = InterceptBinding>,
        suffixes: impl IntoIterator<Item = InterceptSuffix>,
    ) -> Result<Self, InterceptError> {
        Ok(Self {
            bindings: bounded(bindings, MAX_INTERCEPT_BINDINGS)?,
            suffixes: bounded(suffixes, MAX_INTERCEPT_SUFFIXES)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty() && self.suffixes.is_empty()
    }

    /// How many exact bindings the set holds; its suffixes are counted by
    /// [`Self::suffixes`].
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// The bindings, ordered by hostname and then port.
    pub fn bindings(&self) -> &[InterceptBinding] {
        &self.bindings
    }

    /// The suffixes, ordered by suffix and then port.
    pub fn suffixes(&self) -> &[InterceptSuffix] {
        &self.suffixes
    }

    /// Whether `hostname`, already canonical, is bound on `port`: exactly, or
    /// under a suffix bound on that port.
    pub fn binds(&self, hostname: &str, port: u16) -> bool {
        self.bindings
            .binary_search_by(|binding| {
                (binding.hostname.as_str(), binding.port).cmp(&(hostname, port))
            })
            .is_ok()
            || self
                .suffixes
                .iter()
                .any(|suffix| suffix.port == port && suffix.covers(hostname))
    }

    /// Whether `hostname`, already canonical, is bound on any port.
    pub fn binds_name(&self, hostname: &str) -> bool {
        let first = self
            .bindings
            .partition_point(|binding| binding.hostname.as_str() < hostname);
        self.bindings
            .get(first)
            .is_some_and(|binding| binding.hostname == hostname)
            || self.suffixes.iter().any(|suffix| suffix.covers(hostname))
    }
}

/// `items` sorted and without duplicates, refused as soon as more than
/// `maximum` distinct ones are seen, so an oversized input is never held
/// whole.
fn bounded<T: Ord>(
    items: impl IntoIterator<Item = T>,
    maximum: usize,
) -> Result<Vec<T>, InterceptError> {
    let mut unique = BTreeSet::new();
    for item in items {
        unique.insert(item);
        if unique.len() > maximum {
            return Err(InterceptError::TooManyBindings { maximum });
        }
    }
    Ok(unique.into_iter().collect())
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
    #[error("interception suffix must have at least two labels")]
    SuffixTooShort,
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

    fn suffix(suffix: &str, port: u16) -> InterceptSuffix {
        InterceptSuffix::new(suffix, port).unwrap()
    }

    #[test]
    fn a_suffix_covers_every_name_strictly_under_it_and_nothing_else() {
        let bound = suffix("ChatGPT.com.", 443);
        assert_eq!(bound.suffix(), "chatgpt.com");
        for covered in ["a.chatgpt.com", "routed-1.chatgpt.com", "a.b.chatgpt.com"] {
            assert!(bound.covers(covered), "{covered}");
        }
        for other in [
            "chatgpt.com",
            "xchatgpt.com",
            "a.xchatgpt.com",
            ".chatgpt.com",
            "chatgpt.com.evil.test",
            "com",
        ] {
            assert!(!bound.covers(other), "{other}");
        }
        assert_eq!(
            InterceptSuffix::new("com", 443),
            Err(InterceptError::SuffixTooShort)
        );
        assert_eq!(
            InterceptSuffix::new("*.chatgpt.com", 443),
            Err(InterceptError::Pattern)
        );
        assert_eq!(
            InterceptSuffix::new("home.arpa", 443),
            Err(InterceptError::ProtectedName)
        );
        assert_eq!(
            InterceptSuffix::new("chatgpt.com", 0),
            Err(InterceptError::ZeroPort)
        );
    }

    /// A set binds a suffix's subnames on its own port only, beside its exact
    /// bindings, which keep their meaning.
    #[test]
    fn a_set_binds_a_suffixs_subnames_on_its_port() {
        let set = InterceptSet::with_suffixes(
            [
                binding("chatgpt.com", 443),
                binding("api.anthropic.com", 443),
            ],
            [suffix("chatgpt.com", 443), suffix("chatgpt.com", 443)],
        )
        .unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.suffixes(), [suffix("chatgpt.com", 443)]);
        assert!(set.binds("chatgpt.com", 443));
        assert!(set.binds("routed.chatgpt.com", 443));
        assert!(!set.binds("routed.chatgpt.com", 80));
        assert!(!set.binds("routed.anthropic.com", 443));
        assert!(set.binds_name("routed.chatgpt.com"));
        assert!(!set.binds_name("xchatgpt.com"));

        let only_exact = InterceptSet::new([binding("chatgpt.com", 443)]).unwrap();
        assert!(!only_exact.binds("routed.chatgpt.com", 443));
        assert!(!only_exact.binds_name("routed.chatgpt.com"));

        let suffixes = (0..=MAX_INTERCEPT_SUFFIXES)
            .map(|index| suffix(&format!("host-{index}.example.com"), 443))
            .collect::<Vec<_>>();
        assert_eq!(
            InterceptSet::with_suffixes([], suffixes),
            Err(InterceptError::TooManyBindings {
                maximum: MAX_INTERCEPT_SUFFIXES,
            })
        );
        assert!(
            !InterceptSet::with_suffixes([], [suffix("chatgpt.com", 443)])
                .unwrap()
                .is_empty()
        );
    }
}
