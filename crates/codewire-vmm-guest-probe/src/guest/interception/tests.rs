use codewire_access::{
    CapabilitySlot, CredentialId, CredentialPlaceholder, EnvironmentId, ManagedCredentialClients,
    PLACEHOLDER_KEY_BYTES, PlaceholderKey,
};
use uuid::Uuid;

use super::*;
use crate::{EgressCaCertificate, SeedPlaceholders};

fn placeholder(credential: &str) -> CredentialPlaceholder {
    CredentialPlaceholder::derive(
        &PlaceholderKey::from_slice(&[9; PLACEHOLDER_KEY_BYTES]).unwrap(),
        &EnvironmentId::parse("environment-a").unwrap(),
        1,
        &CapabilitySlot::parse("anthropic").unwrap(),
        &CredentialId::parse(credential).unwrap(),
    )
}

fn ca() -> EgressCaCertificate {
    let ca = codewire_egress_front_door::EnvironmentCa::generate(["api.anthropic.com"]).unwrap();
    EgressCaCertificate::from_der(ca.certificate_der().to_vec()).unwrap()
}

/// A seed selecting `clients`, with the CA when `intercepted`, and both
/// Anthropic forms' placeholders beside it.
fn seed(clients: ManagedCredentialClients, intercepted: bool) -> Seed {
    let seed = Seed::new(
        Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
        7,
        17_777,
        "0123456789abcdef0123456789abcdef",
    )
    .unwrap()
    .with_managed_credential_clients(clients);
    if !intercepted {
        return seed;
    }
    seed.with_egress_ca(ca())
        .with_credential_placeholders(
            SeedPlaceholders::new([
                (PlaceholderSlot::AnthropicApiKey, placeholder("api-key")),
                (
                    PlaceholderSlot::AnthropicSubscriptionToken,
                    placeholder("subscription"),
                ),
            ])
            .unwrap(),
        )
        .unwrap()
}

fn anthropic() -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap()
}

#[test]
fn a_seed_without_the_ca_is_not_intercepted() {
    assert!(from_seed(&seed(anthropic(), false)).is_none());
}

/// The selected form names the placeholder: the API-key form's, the
/// subscription-token form's, and none for the sign-in form, whose login
/// carries it.
#[test]
fn the_selected_anthropic_form_names_the_placeholder() {
    let api_key = from_seed(&seed(anthropic(), true)).unwrap();
    assert!(api_key.anthropic().unwrap().ct_eq(&placeholder("api-key")));

    let subscription = anthropic().with_anthropic_subscription_token().unwrap();
    let subscription = from_seed(&seed(subscription, true)).unwrap();
    assert!(
        subscription
            .anthropic()
            .unwrap()
            .ct_eq(&placeholder("subscription"))
    );

    let sign_in = anthropic().with_anthropic_sign_in().unwrap();
    assert!(
        from_seed(&seed(sign_in, true))
            .unwrap()
            .anthropic()
            .is_none()
    );
}

/// A seed with the `github` slot's placeholder gives the interception
/// GitHub's part, with the workspace's bundle for Git; without one, GitHub
/// keeps its loopback route (#4001).
#[test]
fn a_github_placeholder_in_the_seed_intercepts_github() {
    let selected = ManagedCredentialClients::from_profile_slots(["anthropic", "github"]).unwrap();
    assert!(from_seed(&seed(selected, true)).unwrap().github().is_none());

    let github = seed(selected, false)
        .with_egress_ca(ca())
        .with_credential_placeholders(
            SeedPlaceholders::new([
                (PlaceholderSlot::AnthropicApiKey, placeholder("api-key")),
                (PlaceholderSlot::GitHub, placeholder("github")),
            ])
            .unwrap(),
        )
        .unwrap();
    let interception = from_seed(&github).unwrap();
    assert!(
        interception
            .anthropic()
            .unwrap()
            .ct_eq(&placeholder("api-key"))
    );
    assert!(interception.github().unwrap().ct_eq(&placeholder("github")));
    assert_eq!(
        interception.github_trust_bundle(),
        Some("/run/codewire-host/ca-certificates.crt")
    );
    let projection = selected.for_placement_intercepted(
        codewire_access::ManagedCredentialClientPlacement::Native,
        Some(&interception),
    );
    assert_eq!(projection.gh.unwrap().config_yml(), "version: 1\n");
    assert_eq!(
        projection.environment["GH_TOKEN"],
        placeholder("github").as_str()
    );
}
