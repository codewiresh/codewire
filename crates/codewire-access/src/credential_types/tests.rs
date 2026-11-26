use std::collections::BTreeSet;
use std::path::Path;

use super::*;
use crate::{
    CREDENTIAL_NAME_PROVIDERS, CapabilitySlot, CredentialId, CredentialMetadata, CredentialStatus,
    Owner, OwnerId, PROJECTED_PLACEHOLDER_SLOTS, Placement, ProviderId, builtin_provider_catalog,
};

const DOCS_PAGE: &str = "../../apps/docs/zola/content/reference/cli/secrets-and-credentials.md";
const DOCS_START: &str = "<!-- credential-types: generated from codewire_access::CREDENTIAL_TYPES; UPDATE_CREDENTIAL_TYPES_DOCS=1 cargo test -p codewire-access credential_types -->\n\n";
const DOCS_END: &str = "\n<!-- /credential-types -->";

fn repo_file(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn each_word_and_each_label_names_one_type() {
    let words: BTreeSet<_> = CREDENTIAL_TYPES.iter().map(|row| row.word).collect();
    let labels: BTreeSet<_> = CREDENTIAL_TYPES.iter().map(|row| row.label).collect();
    let forms: BTreeSet<_> = CREDENTIAL_TYPES
        .iter()
        .map(|row| (row.provider, row.form))
        .collect();
    assert_eq!(words.len(), CREDENTIAL_TYPES.len());
    assert_eq!(labels.len(), CREDENTIAL_TYPES.len());
    assert_eq!(forms.len(), CREDENTIAL_TYPES.len());
    for row in &CREDENTIAL_TYPES {
        assert_eq!(credential_type(row.word), Some(row));
        assert_eq!(credential_type_of(row.provider, row.form), Some(row));
    }
}

/// The catalog stays hand-written (its forms are a boundary), and holds
/// exactly the rows' providers, forms and slots.
#[test]
fn the_catalog_admits_exactly_the_rows_forms() {
    let catalog = serde_json::to_value(builtin_provider_catalog()).unwrap();
    let providers: BTreeSet<&str> = catalog
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let row_providers: BTreeSet<&str> = CREDENTIAL_TYPES.iter().map(|row| row.provider).collect();
    assert_eq!(providers, row_providers);
    let catalog = builtin_provider_catalog();
    for provider in row_providers {
        let definition = catalog.get(&ProviderId::parse(provider).unwrap()).unwrap();
        let forms: BTreeSet<_> = CREDENTIAL_TYPES
            .iter()
            .filter(|row| row.provider == provider)
            .map(|row| row.form)
            .collect();
        assert_eq!(definition.authentication_kinds, forms, "{provider}");
        for (slot, policy) in &definition.capabilities {
            let forms: BTreeSet<_> = CREDENTIAL_TYPES
                .iter()
                .filter(|row| row.provider == provider && row.slots.contains(&slot.as_str()))
                .map(|row| row.form)
                .collect();
            assert_eq!(policy.authentication_kinds, forms, "{provider} {slot:?}");
        }
        for row in CREDENTIAL_TYPES
            .iter()
            .filter(|row| row.provider == provider)
        {
            for slot in row.slots {
                assert!(
                    definition
                        .capabilities
                        .contains_key(&CapabilitySlot::parse(*slot).unwrap()),
                    "{} in {slot}",
                    row.word
                );
            }
        }
    }
}

/// Each row's family is the one the broker picks for it in each of its
/// slots, and every family a profile can select has a row.
#[test]
fn each_row_names_the_family_the_broker_selects() {
    let mut credential = CredentialMetadata {
        id: CredentialId::parse("synthetic-credential").unwrap(),
        placement: Placement::Local,
        owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
        provider: ProviderId::parse("openai").unwrap(),
        authentication_kind: CredentialAuthKind::ApiKey,
        display_name: "synthetic-only".into(),
        account_hint: None,
        ssh_public_key: None,
        status: CredentialStatus::Active,
        expires_at_unix: None,
        revocation_generation: 1,
    };
    for row in &CREDENTIAL_TYPES {
        credential.provider = ProviderId::parse(row.provider).unwrap();
        credential.authentication_kind = row.form;
        for slot in row.slots {
            assert_eq!(
                HttpProvider::for_credential(&CapabilitySlot::parse(*slot).unwrap(), &credential),
                row.http,
                "{} in {slot}",
                row.word
            );
        }
    }
    let selectable = |provider: HttpProvider| match provider {
        HttpProvider::OpenAiApiKey
        | HttpProvider::CodexOAuth
        | HttpProvider::AnthropicApiKey
        | HttpProvider::AnthropicSubscriptionToken
        | HttpProvider::AnthropicClaudeSignIn
        | HttpProvider::GeminiApiKey
        | HttpProvider::AntigravityOAuth
        | HttpProvider::GitHubOAuth => true,
        HttpProvider::GitHubAppAuthorization
        | HttpProvider::CodexDeviceEnrollment
        | HttpProvider::ClaudeSignInEnrollment
        | HttpProvider::CodexTokenRevocation
        | HttpProvider::GitHubAppTokenRevocation
        | HttpProvider::AntigravitySignInEnrollment
        | HttpProvider::AntigravityTokenRevocation => false,
    };
    for provider in [
        HttpProvider::OpenAiApiKey,
        HttpProvider::CodexOAuth,
        HttpProvider::AnthropicApiKey,
        HttpProvider::AnthropicSubscriptionToken,
        HttpProvider::AnthropicClaudeSignIn,
        HttpProvider::GeminiApiKey,
        HttpProvider::AntigravityOAuth,
        HttpProvider::GitHubOAuth,
        HttpProvider::GitHubAppAuthorization,
        HttpProvider::CodexDeviceEnrollment,
        HttpProvider::ClaudeSignInEnrollment,
        HttpProvider::CodexTokenRevocation,
        HttpProvider::GitHubAppTokenRevocation,
        HttpProvider::AntigravitySignInEnrollment,
        HttpProvider::AntigravityTokenRevocation,
    ] {
        assert_eq!(
            CREDENTIAL_TYPES
                .iter()
                .any(|row| row.http == Some(provider)),
            selectable(provider),
            "{provider:?}"
        );
    }
}

#[test]
fn an_agents_variable_is_one_its_family_reserves() {
    for row in &CREDENTIAL_TYPES {
        if let AgentHolds::Placeholder(name) | AgentHolds::StandIn(name) = row.agent {
            let http = row.http.expect("a variable implies an HTTP family");
            assert!(
                http.reserved_environment_keys().contains(&name),
                "{} holds {name}",
                row.word
            );
        }
    }
}

/// The projected slots stay a literal (wire order is a boundary), and are
/// exactly the slots of the rows whose placeholder the environment holds.
#[test]
fn projected_placeholder_slots_are_the_rows_with_a_placeholder() {
    assert_eq!(
        PROJECTED_PLACEHOLDER_SLOTS,
        ["anthropic", "github", "gemini"]
    );
    let slots: BTreeSet<&str> = CREDENTIAL_TYPES
        .iter()
        .filter(|row| {
            matches!(
                row.agent,
                AgentHolds::Placeholder(_) | AgentHolds::GitHelper
            )
        })
        .flat_map(|row| row.slots.iter().copied())
        .collect();
    assert_eq!(slots, BTreeSet::from(PROJECTED_PLACEHOLDER_SLOTS));
}

#[test]
fn reserved_name_prefixes_are_the_rows_providers() {
    let providers: BTreeSet<&str> = CREDENTIAL_TYPES.iter().map(|row| row.provider).collect();
    assert_eq!(BTreeSet::from(CREDENTIAL_NAME_PROVIDERS), providers);
}

#[test]
fn each_type_runs_one_subcommands_flow() {
    let words = |verb| {
        credential_types_for(verb)
            .map(|row| row.word)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        words(CredentialVerb::Connect),
        ["codex", "github", "claude", "claude-token", "antigravity"]
    );
    assert_eq!(
        words(CredentialVerb::Add),
        ["anthropic", "openai", "gemini", "ssh"]
    );
}

/// The glossary names each type once, by its label.
#[test]
fn the_glossary_names_every_type() {
    let glossary = std::fs::read_to_string(repo_file("../../docs/GLOSSARY.md")).unwrap();
    let line = glossary
        .split("The kinds, in lists and messages:")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("the glossary's kinds line");
    let named: BTreeSet<&str> = line.split('`').skip(1).step_by(2).collect();
    let labels: BTreeSet<&str> = CREDENTIAL_TYPES.iter().map(|row| row.label).collect();
    assert_eq!(named, labels);
}

/// The docs' table is the generated one; `UPDATE_CREDENTIAL_TYPES_DOCS=1`
/// writes it.
#[test]
fn the_docs_table_is_generated_from_the_rows() {
    let path = repo_file(DOCS_PAGE);
    let page = std::fs::read_to_string(&path).unwrap();
    let (before, rest) = page.split_once(DOCS_START).expect("the docs' start marker");
    let (committed, after) = rest.split_once(DOCS_END).expect("the docs' end marker");
    let table = credential_types_docs_table();
    if std::env::var_os("UPDATE_CREDENTIAL_TYPES_DOCS").is_some() {
        std::fs::write(
            &path,
            format!("{before}{DOCS_START}{table}{DOCS_END}{after}"),
        )
        .unwrap();
    } else {
        assert_eq!(
            committed, table,
            "the docs' credential table is stale; run UPDATE_CREDENTIAL_TYPES_DOCS=1 cargo test -p codewire-access credential_types"
        );
    }
}
