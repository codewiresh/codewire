use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot, CredentialAuthKind,
    GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
};

/// Return the provider capabilities implemented by the current Codewire
/// credential stack.
///
/// The catalog is deliberately narrower than the type system. GitHub, SSH,
/// Claude, and other adapters are added only with their owning
/// refresh, routing, and compatibility tests. An absent combination is
/// unsupported rather than inferred from ambient host configuration.
pub fn builtin_provider_catalog() -> ProviderCatalog {
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: ProviderId::parse("openai").expect("built-in OpenAI provider ID"),
        capabilities: BTreeMap::from([(
            CapabilitySlot::codex(),
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([
                    CredentialAuthKind::OAuth,
                    CredentialAuthKind::ApiKey,
                ]),
                permissions: BTreeSet::from([GrantPermission {
                    operation: BrokerOperationId::parse("responses")
                        .expect("built-in Responses operation ID"),
                    route: BrokerRouteId::parse("openai-api").expect("built-in OpenAI route ID"),
                }]),
            },
        )]),
    }])
    .expect("built-in provider catalog")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_admit_only_implemented_openai_codex_capabilities() {
        let catalog = builtin_provider_catalog();
        let provider = catalog
            .get(&ProviderId::parse("openai").unwrap())
            .expect("OpenAI provider");
        let codex = provider
            .capabilities
            .get(&CapabilitySlot::codex())
            .expect("Codex capability");

        assert_eq!(
            codex.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey,])
        );
        assert_eq!(
            codex.permissions,
            BTreeSet::from([GrantPermission {
                operation: BrokerOperationId::parse("responses").unwrap(),
                route: BrokerRouteId::parse("openai-api").unwrap(),
            }])
        );
        assert!(catalog.get(&ProviderId::parse("github").unwrap()).is_none());
    }
}
