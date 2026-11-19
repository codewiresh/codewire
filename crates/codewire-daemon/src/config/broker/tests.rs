use super::*;

const STREAM: &str = "10.44.0.21:8089";
const BINDING: &str = "10.44.0.87:8087";
const API: &str = "10.44.0.10:443";
const COORDINATOR: &str = "10.44.0.11:443";
const MESH: &str = "10.44.0.12:443";
const DERP: &str = "derp.codewire.example=10.44.0.30:8443";

fn parse(values: &[(&'static str, &str)]) -> Result<Option<BrokerPlatform>, ConfigError> {
    BrokerPlatform::from_lookup(&|name: &str| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(*value))
    })
}

/// Everything a broker-mode Pod is rendered with, `name` left out.
fn rendered_without(name: &str) -> Vec<(&'static str, &'static str)> {
    [
        (EGRESS_STREAM_ADDR_ENV, STREAM),
        (WORKSPACE_BINDING_ADDR_ENV, BINDING),
        (API_ADDR_ENV, API),
        (MESH_ADDR_ENV, MESH),
        (DERP_ADDR_ENV, DERP),
    ]
    .into_iter()
    .filter(|(key, _)| *key != name)
    .collect()
}

#[test]
fn no_stream_address_is_not_broker_mode() {
    assert_eq!(parse(&rendered_without(EGRESS_STREAM_ADDR_ENV)), Ok(None));
    assert_eq!(parse(&[]), Ok(None));
}

#[test]
fn a_broker_pod_has_every_platform_address() {
    let platform = parse(&rendered_without("")).unwrap().unwrap();
    assert_eq!(platform.stream(), STREAM.parse().unwrap());
    assert_eq!(platform.binding(), BINDING.parse().unwrap());
    assert_eq!(platform.coordinator(), API.parse().unwrap());
    assert_eq!(platform.mesh(), Some(MESH.parse().unwrap()));
    assert_eq!(platform.derp().host(), "derp.codewire.example");
    assert_eq!(
        platform.derp().address(),
        "10.44.0.30:8443".parse().unwrap()
    );
}

#[test]
fn the_coordinator_is_its_own_address_else_the_apis_else_none() {
    let mut values = rendered_without("");
    values.push((COORDINATOR_ADDR_ENV, COORDINATOR));
    let platform = parse(&values).unwrap().unwrap();
    assert_eq!(platform.coordinator(), COORDINATOR.parse().unwrap());

    let mut without_api = rendered_without(API_ADDR_ENV);
    without_api.push((COORDINATOR_ADDR_ENV, COORDINATOR));
    let platform = parse(&without_api).unwrap().unwrap();
    assert_eq!(platform.coordinator(), COORDINATOR.parse().unwrap());

    assert_eq!(
        parse(&rendered_without(API_ADDR_ENV)),
        Err(ConfigError::BrokerAddress(API_ADDR_ENV))
    );
}

#[test]
fn a_missing_required_address_names_its_variable() {
    assert_eq!(
        parse(&rendered_without(WORKSPACE_BINDING_ADDR_ENV)),
        Err(ConfigError::BrokerAddress(WORKSPACE_BINDING_ADDR_ENV))
    );
    assert_eq!(
        parse(&rendered_without(DERP_ADDR_ENV)),
        Err(ConfigError::BrokerDerpAddress)
    );
    // Mesh is rendered only with a Mesh URL.
    assert_eq!(
        parse(&rendered_without(MESH_ADDR_ENV))
            .unwrap()
            .unwrap()
            .mesh(),
        None
    );
}

#[test]
fn only_an_ipv4_address_and_nonzero_port_is_an_address() {
    for name in [
        EGRESS_STREAM_ADDR_ENV,
        WORKSPACE_BINDING_ADDR_ENV,
        API_ADDR_ENV,
        COORDINATOR_ADDR_ENV,
        MESH_ADDR_ENV,
    ] {
        for bad in [
            "",
            " ",
            "10.44.0.87",
            "10.44.0.87:0",
            " 10.44.0.87:8087",
            "10.44.0.87:8087 ",
            "binding.codewire.example:8087",
            "[fd00::1]:8087",
            "10.44.0.87:65536",
        ] {
            let mut values = rendered_without(name);
            values.push((name, bad));
            assert_eq!(
                parse(&values),
                Err(ConfigError::BrokerAddress(name)),
                "{name}={bad:?}"
            );
        }
    }
}

#[test]
fn derp_is_a_lowercase_hostname_paired_with_an_address() {
    for bad in [
        "10.44.0.30:8443",
        "derp.codewire.example",
        "derp.codewire.example=",
        "=10.44.0.30:8443",
        "derp=10.44.0.30:8443",
        "Derp.codewire.example=10.44.0.30:8443",
        "derp.codewire.example.=10.44.0.30:8443",
        "-derp.codewire.example=10.44.0.30:8443",
        "derp..example=10.44.0.30:8443",
        "derp.codewire.example=derp.internal:8443",
        "derp.codewire.example=10.44.0.30:0",
        "derp.codewire.example=10.44.0.30:8443=x",
    ] {
        let mut values = rendered_without(DERP_ADDR_ENV);
        values.push((DERP_ADDR_ENV, bad));
        assert_eq!(
            parse(&values),
            Err(ConfigError::BrokerDerpAddress),
            "{bad:?}"
        );
    }
}
