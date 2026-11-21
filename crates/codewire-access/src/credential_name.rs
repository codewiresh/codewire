//! Credential names are unique per owner and provider, case-insensitively, in
//! both stores (docs/dev/SECRETS-AND-CREDENTIALS.md, "Credential names").

/// The provider ids a credential name is unique within. A reference
/// `PROVIDER/NAME` names a provider only when its prefix is one of these.
pub const CREDENTIAL_NAME_PROVIDERS: [&str; 4] = ["anthropic", "openai", "github", "ssh"];

/// The prefixes a new name may not start with, as a refusal lists them:
/// `anthropic/, openai/, github/ or ssh/`. Each refusal writes its sentence
/// out, and its tests check it against this.
pub fn credential_name_provider_prefixes() -> String {
    let prefixes: Vec<String> = CREDENTIAL_NAME_PROVIDERS
        .iter()
        .map(|provider| format!("{provider}/"))
        .collect();
    match prefixes.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    }
}

/// Whether `value` is exactly one of [`CREDENTIAL_NAME_PROVIDERS`].
pub fn is_credential_name_provider(value: &str) -> bool {
    CREDENTIAL_NAME_PROVIDERS.contains(&value)
}

/// Whether a new or renamed credential may not take `name`: it starts with a
/// provider id and `/`, ignoring case, so `PROVIDER/NAME` would read it as a
/// different credential. An existing credential that already has such a name
/// keeps it; only creation and renaming check this.
pub fn reserves_provider_prefix(name: &str) -> bool {
    name.split_once('/').is_some_and(|(prefix, _)| {
        CREDENTIAL_NAME_PROVIDERS
            .iter()
            .any(|provider| prefix.eq_ignore_ascii_case(provider))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_starting_with_a_provider_and_slash_is_reserved_in_any_case() {
        for name in [
            "anthropic/work",
            "OpenAI/work",
            "GITHUB/work",
            "ssh/",
            "github/work/nested",
        ] {
            assert!(reserves_provider_prefix(name), "{name}");
        }
    }

    #[test]
    fn other_names_with_a_slash_stay_whole_names() {
        for name in [
            "n@example.com",
            "work/github",
            "gitlab/work",
            "githubx/work",
            " github/work",
            "/github",
            "anthropic",
        ] {
            assert!(!reserves_provider_prefix(name), "{name}");
        }
    }

    #[test]
    fn only_the_exact_stored_provider_ids_select_a_provider() {
        for provider in ["anthropic", "openai", "github", "ssh"] {
            assert!(is_credential_name_provider(provider));
        }
        for value in ["Anthropic", "OPENAI", "gitlab", "", "ssh "] {
            assert!(!is_credential_name_provider(value), "{value}");
        }
    }

    #[test]
    fn a_refusal_lists_every_provider_prefix() {
        assert_eq!(
            credential_name_provider_prefixes(),
            "anthropic/, openai/, github/ or ssh/"
        );
    }
}
