//! A credential name is unique per provider, and `PROVIDER/NAME` names one
//! (#4928): name resolution, connect targets, admission and when an older
//! authority is replaced.

use codewire_access::{CredentialAuthKind, ProviderId};

use super::super::credential_input::{ParsedCredentialSelector, parse_credential_selector};
use super::names::{names_per_provider_needed, select_credential_by_name};
use super::tests::credential_with;
use super::*;

fn named_record(
    id: &str,
    provider: &str,
    kind: CredentialAuthKind,
    name: &str,
) -> CredentialRecord {
    let mut record = credential_with(id, name);
    record.metadata.provider = ProviderId::parse(provider).unwrap();
    record.metadata.authentication_kind = kind;
    record
}

const CLAUDE_WALK: &str = "11111111-1111-4111-8111-111111111111";
const CODEX_WALK: &str = "22222222-2222-4222-8222-222222222222";

/// The owner's two sign-ins under one name (#4928).
fn walk_records() -> Vec<CredentialRecord> {
    vec![
        named_record(
            CLAUDE_WALK,
            "anthropic",
            CredentialAuthKind::ClaudeSignIn,
            "walk",
        ),
        named_record(CODEX_WALK, "openai", CredentialAuthKind::OAuth, "walk"),
    ]
}

fn selected(records: &[CredentialRecord], selector: &str, scope: Option<&str>) -> String {
    let ParsedCredentialSelector::Name(name) = parse_credential_selector(selector).unwrap() else {
        panic!("{selector} is a name");
    };
    match select_credential_by_name(records, name, scope) {
        Ok(record) => record.metadata.id.to_string(),
        Err(error) => format!("{error:#}"),
    }
}

/// A bare name two providers share is refused with the choice; the
/// provider's form, or a slot's provider, picks one (#4928).
#[test]
fn a_bare_name_two_providers_share_is_refused_and_provider_name_picks_one() {
    let records = walk_records();
    assert_eq!(
        selected(&records, "walk", None),
        "\"walk\" names more than one credential (anthropic, openai); name one, for example anthropic/walk"
    );
    assert_eq!(
        selected(&records, "WALK", None).split(';').next(),
        Some("\"WALK\" names more than one credential (anthropic, openai)")
    );
    assert_eq!(selected(&records, "openai/walk", None), CODEX_WALK);
    assert_eq!(selected(&records, "anthropic/WALK", None), CLAUDE_WALK);
    assert_eq!(
        selected(&records, "github/walk", None),
        "no local credential is named \"github/walk\"; `cw credentials --local list` shows them"
    );
    // A slot fixes the provider, so its bare name needs no prefix; a name
    // only another provider has is still found, for the slot to refuse.
    assert_eq!(selected(&records, "walk", Some("openai")), CODEX_WALK);
    assert_eq!(selected(&records, "walk", Some("anthropic")), CLAUDE_WALK);
    assert_eq!(selected(&records[..1], "walk", Some("openai")), CLAUDE_WALK);
}

/// cw-security's first condition on #4928: a literal `github/work` an
/// older Codewire saved beside a GitHub credential `work` is never
/// silently read as either.
#[test]
fn a_literal_provider_name_beside_that_providers_name_acts_only_when_one_matches() {
    const LITERAL: &str = "33333333-3333-4333-8333-333333333333";
    const GITHUB: &str = "44444444-4444-4444-8444-444444444444";
    let literal = named_record(LITERAL, "ssh", CredentialAuthKind::SshKey, "github/work");
    let github = named_record(GITHUB, "github", CredentialAuthKind::OAuth, "work");
    let both = [literal.clone(), github.clone()];
    assert_eq!(
        selected(&both, "github/work", None),
        "\"github/work\" names more than one credential (github \"work\", ssh \"github/work\"); name one, for example ssh/github/work"
    );
    assert_eq!(selected(&both, "ssh/github/work", None), LITERAL);
    assert_eq!(selected(&both, "name:github/work", None), LITERAL);
    assert_eq!(selected(&both, "work", None), GITHUB);
    // With only one of them, either reading acts on it.
    assert_eq!(
        selected(std::slice::from_ref(&literal), "github/work", None),
        LITERAL
    );
    assert_eq!(
        selected(std::slice::from_ref(&github), "github/work", None),
        GITHUB
    );
    // A literal GitHub `github/work` beside GitHub `work`: both named.
    let mut github_literal = literal;
    github_literal.metadata.provider = ProviderId::parse("github").unwrap();
    assert_eq!(
        selected(&[github_literal, github], "github/work", None),
        "\"github/work\" names more than one credential (github \"github/work\", github \"work\"); name one, for example github/github/work"
    );
}

/// The owner's case (2026-11-19): a Claude sign-in named `walk`, then
/// `connect codex --name walk`, is a new Codex credential, not a refusal.
#[test]
fn a_codex_connect_may_take_the_name_of_a_claude_sign_in() {
    let records = walk_records()[..1].to_vec();
    let target =
        select_oauth_connection_target(records, "walk", CredentialConnectProviderArg::Codex)
            .unwrap();
    assert!(target.existing.is_none());
    assert_eq!(target.display_name, "walk");
    assert_eq!(target.provider.as_str(), "openai");
    // With both, each connect reconnects its own provider's credential,
    // by its bare name or as PROVIDER/NAME.
    for (connect, name, id) in [
        (CredentialConnectProviderArg::Codex, "walk", CODEX_WALK),
        (
            CredentialConnectProviderArg::Codex,
            "openai/walk",
            CODEX_WALK,
        ),
        (CredentialConnectProviderArg::Claude, "WALK", CLAUDE_WALK),
    ] {
        let target = select_oauth_connection_target(walk_records(), name, connect).unwrap();
        assert_eq!(target.existing.unwrap().metadata.id.as_str(), id, "{name}");
        assert_eq!(target.display_name, "walk");
    }
}

/// One provider's name is still unique: a Claude token can't take a
/// Claude sign-in's name, and the refusal names it and a free name.
#[test]
fn a_same_provider_collision_names_the_holder_and_a_free_name() {
    let mut records = walk_records();
    let refused = |records: Vec<CredentialRecord>| {
        format!(
            "{:#}",
            select_oauth_connection_target(
                records,
                "walk",
                CredentialConnectProviderArg::ClaudeToken
            )
            .err()
            .unwrap()
        )
    };
    assert_eq!(
        refused(records.clone()),
        "\"walk\" is in use in anthropic by a Claude (sign-in) credential; choose another name, for example walk-2"
    );
    records.push(named_record(
        "55555555-5555-4555-8555-555555555555",
        "anthropic",
        CredentialAuthKind::ApiKey,
        "Walk-2",
    ));
    assert!(refused(records.clone()).ends_with("for example walk-3"));
    // Another provider's walk-3 doesn't make it taken in anthropic.
    records.push(named_record(
        "66666666-6666-4666-8666-666666666666",
        "openai",
        CredentialAuthKind::ApiKey,
        "walk-3",
    ));
    assert!(refused(records.clone()).ends_with("for example walk-3"));
    // add and rename refuse the same way, before anything is asked.
    let error = admit_name("openai", "WALK", &records, None, local_kind).unwrap_err();
    assert_eq!(
        error.to_string(),
        "\"walk\" is in use in openai by a Codex credential; choose another name, for example walk-2"
    );
    admit_name("ssh", "walk", &records, None, local_kind).unwrap();
    // A rename to its own name, in another case, is no collision.
    admit_name("openai", "WALK", &records, Some(&records[1]), local_kind).unwrap();
}

/// A new name may not start with a provider id and `/`; one an older
/// Codewire saved keeps working.
#[test]
fn a_new_name_with_a_provider_prefix_is_refused_before_anything_is_asked() {
    let error = select_oauth_connection_target(
        walk_records(),
        "anthropic/walk",
        CredentialConnectProviderArg::Codex,
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "a credential's name can't start with anthropic/, which reads as a provider; choose another name"
    );
    for name in ["GitHub/work", "ssh/deploy", "openai/x"] {
        assert!(admit_name("ssh", name, &walk_records(), None, local_kind).is_err());
    }
    admit_name("ssh", "gitlab/work", &walk_records(), None, local_kind).unwrap();
    let legacy = named_record(
        "77777777-7777-4777-8777-777777777777",
        "ssh",
        CredentialAuthKind::SshKey,
        "github/deploy",
    );
    admit_name(
        "ssh",
        "github/deploy",
        std::slice::from_ref(&legacy),
        Some(&legacy),
        local_kind,
    )
    .unwrap();
}

/// An older authority is replaced (or the command refused while a VM
/// runs) only for a name another provider's credential has (#4928).
#[test]
fn only_a_name_another_provider_has_needs_names_per_provider() {
    let claude = walk_records()[..1].to_vec();
    let connect = |provider, name: &str| {
        CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
            credential_type: None,
            provider: Some(provider),
            name: Some(name.into()),
            yes: false,
            output: crate::commands::OutputFormat::Text,
            expires_at: None,
            key_file: None,
            account_hint: None,
            guided: false,
        }))
    };
    assert!(
        names_per_provider_needed(
            &connect(CredentialConnectProviderArg::Codex, "walk"),
            &claude
        )
        .is_some()
    );
    for (operation, records) in [
        (
            connect(CredentialConnectProviderArg::Codex, "other"),
            &claude,
        ),
        (
            connect(CredentialConnectProviderArg::Claude, "walk"),
            &claude,
        ),
        (
            connect(CredentialConnectProviderArg::Codex, "walk"),
            &Vec::new(),
        ),
    ] {
        assert_eq!(names_per_provider_needed(&operation, records), None);
    }
    let add = |provider: &str| {
        CredentialOperation::Credential(CredentialsCommand::Add(CredentialAddArgs {
            provider: Some(provider.into()),
            name: Some(" walk ".into()),
            account_hint: None,
            expires_at: None,
            key_file: None,
            yes: false,
            output: crate::commands::OutputFormat::Text,
            guided: false,
        }))
    };
    assert!(names_per_provider_needed(&add("openai"), &claude).is_some());
    assert!(names_per_provider_needed(&add("anthropic"), &claude).is_none());
    let rename =
        CredentialOperation::Credential(CredentialsCommand::Rename(CredentialRenameArgs {
            credential: "openai/walk".into(),
            name: "other".into(),
        }));
    let mut records = walk_records();
    assert!(names_per_provider_needed(&rename, &records).is_none());
    records[0].metadata.display_name = "other".into();
    assert!(names_per_provider_needed(&rename, &records).is_some());
    // Lookups never need it: names are resolved here.
    let get = CredentialOperation::Credential(CredentialsCommand::Revoke(
        confirm::CredentialRevokeArgs {
            credential: "openai/walk".into(),
            yes: true,
            output: OutputFormat::Text,
        },
    ));
    assert!(names_per_provider_needed(&get, &walk_records()).is_none());
}
