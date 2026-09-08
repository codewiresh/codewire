use super::*;
use std::collections::BTreeMap;

fn inputs() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (DAEMON_AUTH_TOKEN_ENV, "synthetic-daemon".into()),
        (
            ENVIRONMENT_ID_ENV,
            "a206cb4d-01d0-4f22-882e-c1bb273140fe".into(),
        ),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "7".into()),
        (
            CREDENTIAL_HTTPS_AUTHORITY_ENV,
            "environment.gateway.internal:8443".into(),
        ),
        (CREDENTIAL_HTTPS_LISTEN_ADDR_ENV, "0.0.0.0:8443".into()),
        (CREDENTIAL_GATEWAY_TOKEN_FILE_ENV, "/projected/token".into()),
        (CREDENTIAL_TLS_CERT_FILE_ENV, "/gateway-tls/tls.crt".into()),
        (CREDENTIAL_TLS_KEY_FILE_ENV, "/gateway-tls/tls.key".into()),
        (
            CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
            "https://broker.internal:8443".into(),
        ),
        (
            CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV,
            "/broker-trust/ca.crt".into(),
        ),
    ])
}

#[test]
fn credential_group_absence_preserves_credential_free_gateway() {
    let mut vars = inputs();
    for name in CREDENTIAL_ENV_GROUP {
        vars.remove(name);
    }
    let config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    assert!(config.credentials.is_none());
}

#[test]
fn hosted_relay_requires_canonical_immutable_selection_without_changing_direct_ingress() {
    let mut vars = inputs();
    let config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    assert!(
        config
            .credentials
            .as_ref()
            .unwrap()
            .hosted_bridge()
            .unwrap()
            .is_none()
    );
    assert!(config.credentials.as_ref().unwrap().ingress().is_ok());
    vars.insert(HOSTED_PROJECTION_SHA256_ENV, "ab".repeat(32));
    let config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    assert!(
        config
            .credentials
            .as_ref()
            .unwrap()
            .hosted_bridge()
            .unwrap()
            .is_some()
    );
    for digest in [
        String::new(),
        "00".repeat(32),
        "AB".repeat(32),
        "canary".into(),
    ] {
        vars.insert(HOSTED_PROJECTION_SHA256_ENV, digest);
        assert_eq!(
            GatewayConfig::from_getenv(|name| vars.get(name).cloned()),
            Err(ConfigError::InvalidCredentialRuntime)
        );
    }
    vars.insert(HOSTED_PROJECTION_SHA256_ENV, "ab".repeat(32));
    for field in CREDENTIAL_ENV_GROUP {
        vars.remove(field);
    }
    assert_eq!(
        GatewayConfig::from_getenv(|name| vars.get(name).cloned()),
        Err(ConfigError::InvalidCredentialRuntime)
    );
}

#[test]
fn credential_group_requires_every_field_and_exact_existing_identity() {
    let vars = inputs();
    let config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    let credentials = config.credentials.unwrap();
    assert_eq!(credentials.operation_generation, 7);
    assert_eq!(credentials.listen_addr.port(), CREDENTIAL_HTTPS_PORT);
    assert_eq!(
        credentials.environment_id.to_string(),
        vars[ENVIRONMENT_ID_ENV]
    );
    for missing in CREDENTIAL_ENV_GROUP.into_iter().chain([ENVIRONMENT_ID_ENV]) {
        for replacement in [None, Some(String::new()), Some(" ".into())] {
            let mut changed = vars.clone();
            match replacement {
                Some(value) => {
                    changed.insert(missing, value);
                }
                None => {
                    changed.remove(missing);
                }
            }
            assert_eq!(
                GatewayConfig::from_getenv(|name| changed.get(name).cloned()),
                Err(ConfigError::InvalidCredentialRuntime)
            );
        }
    }
}

#[test]
fn credential_group_rejects_noncanonical_coordinates_and_insecure_transports() {
    for (name, bad) in [
        (ENVIRONMENT_ID_ENV, "A206CB4D-01D0-4F22-882E-C1BB273140FE"),
        (ENVIRONMENT_ID_ENV, "a206cb4d01d04f22882ec1bb273140fe"),
        (ENVIRONMENT_ID_ENV, "00000000-0000-0000-0000-000000000000"),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "0"),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "07"),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "9223372036854775808"),
        (CREDENTIAL_HTTPS_LISTEN_ADDR_ENV, "0.0.0.0:8080"),
        (CREDENTIAL_HTTPS_LISTEN_ADDR_ENV, "localhost:8443"),
        (CREDENTIAL_HTTPS_AUTHORITY_ENV, "https://gateway.internal"),
        (CREDENTIAL_HTTPS_AUTHORITY_ENV, "user@gateway.internal:8443"),
        (CREDENTIAL_HTTPS_AUTHORITY_ENV, "gateway.internal:0"),
        (CREDENTIAL_GATEWAY_TOKEN_FILE_ENV, "relative-token"),
        (CREDENTIAL_TLS_KEY_FILE_ENV, "/gateway-tls/tls.crt"),
        (CREDENTIAL_TLS_CERT_FILE_ENV, "relative-cert"),
        (
            CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
            "http://broker.internal:8443",
        ),
        (
            CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
            "https://broker.internal:8443/other",
        ),
        (
            CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
            "https://user@broker.internal:8443",
        ),
        (CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV, "/"),
    ] {
        let mut vars = inputs();
        vars.insert(name, bad.into());
        assert_eq!(
            GatewayConfig::from_getenv(|key| vars.get(key).cloned()),
            Err(ConfigError::InvalidCredentialRuntime),
            "field {name}"
        );
    }
}

#[test]
fn credential_configuration_debug_and_error_are_value_blind() {
    let mut vars = inputs();
    vars.insert(
        CREDENTIAL_TLS_KEY_FILE_ENV,
        "/synthetic-private-config-canary".into(),
    );
    let config = GatewayConfig::from_getenv(|key| vars.get(key).cloned()).unwrap();
    assert!(!format!("{config:?}").contains("synthetic-private-config-canary"));
    vars.insert(
        CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
        "synthetic-private-config-canary".into(),
    );
    let error = GatewayConfig::from_getenv(|key| vars.get(key).cloned()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("synthetic-private-config-canary"));
}
