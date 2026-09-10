use super::*;

fn inventory(source: v1::EnvironmentProjectionSource) -> v1::EnvironmentProjectionInventory {
    v1::EnvironmentProjectionInventory {
        source: source as i32,
        source_identity: "selected-exact-scope".into(),
        keys: vec!["A".into(), "Z".into()],
    }
}

#[test]
fn role_is_fixed_by_transport_field_and_cannot_be_chosen_in_an_inventory() {
    let wire = vec![inventory(v1::EnvironmentProjectionSource::Project)];
    let local = decode_local_inventories(&wire).unwrap();
    let platform = decode_platform_inventories(&wire).unwrap();
    assert_eq!(local[0].contributor, ProjectionContributor::Local);
    assert_eq!(platform[0].contributor, ProjectionContributor::Platform);
    assert_eq!(encode_local_inventories(&local).unwrap(), wire);
    assert_eq!(encode_platform_inventories(&platform).unwrap(), wire);
    assert!(encode_local_inventories(&platform).is_err());
    assert!(encode_platform_inventories(&local).is_err());
    let organization = vec![inventory(v1::EnvironmentProjectionSource::Organization)];
    assert!(decode_local_inventories(&organization).is_err());
    assert!(decode_platform_inventories(&organization).is_ok());
}

#[test]
fn empty_selected_source_is_preserved_but_missing_source_is_not_an_inventory() {
    let mut wire = inventory(v1::EnvironmentProjectionSource::User);
    wire.keys.clear();
    let decoded = decode_local_inventories(&[wire]).unwrap();
    assert_eq!(decoded.len(), 1);
    assert!(decoded[0].keys.is_empty());
    assert!(decode_local_inventories(&[]).is_err());
    assert!(decode_platform_inventories(&[]).is_err());
}

#[test]
fn malformed_names_scopes_ranks_and_limits_fail_before_set_normalization() {
    let original = inventory(v1::EnvironmentProjectionSource::Project);
    for field in 0..11 {
        let mut invalid = original.clone();
        match field {
            0 => invalid.source = 0,
            1 => invalid.source = 99,
            2 => invalid.keys.swap(0, 1),
            3 => invalid.keys[1] = invalid.keys[0].clone(),
            4 => invalid.keys = vec!["invalid-key".into()],
            5 => invalid.keys = (0..257).map(|i| format!("K_{i:03}")).collect(),
            6 => invalid.source_identity.clear(),
            7 => invalid.source_identity = "x".repeat(513),
            8 => invalid.source_identity.push('\n'),
            9 => invalid.source_identity.push(' '),
            _ => invalid.keys = vec!["X".repeat(256)],
        }
        assert!(
            decode_local_inventories(&[invalid]).is_err(),
            "field {field}"
        );
    }
    assert!(decode_local_inventories(&[original.clone(), original.clone()]).is_err());
    let user = inventory(v1::EnvironmentProjectionSource::User);
    assert!(decode_local_inventories(&[user.clone(), original.clone()]).is_err());
    assert!(decode_local_inventories(&[original.clone(), user]).is_ok());
    assert!(decode_platform_inventories(&vec![original; 4]).is_err());
}

#[test]
fn exact_maximum_names_and_identity_round_trip_without_a_second_allowance() {
    let mut wire = inventory(v1::EnvironmentProjectionSource::User);
    wire.source_identity = "x".repeat(512);
    wire.keys = (0..256).map(|i| format!("K_{i:03}")).collect();
    let decoded = decode_local_inventories(std::slice::from_ref(&wire)).unwrap();
    assert_eq!(encode_local_inventories(&decoded).unwrap(), [wire]);
    // The complete multi-source/ordinary union bound is applied by the shared
    // composition plan, not separately waived by this wire-framing check.
}
