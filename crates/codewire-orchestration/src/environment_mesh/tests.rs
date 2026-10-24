use super::*;

#[test]
fn enrollment_codes_are_fresh_well_formed_and_stored_only_as_digests() {
    let first = generate_enrollment_code().expect("code");
    let second = generate_enrollment_code().expect("code");
    assert_ne!(first, second);
    for code in [&first, &second] {
        assert!(well_formed_enrollment_code(code), "{code}");
        let digest = enrollment_code_sha256(code);
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains(code.trim_start_matches(ENROLLMENT_CODE_PREFIX)));
    }
    for malformed in [
        "",
        "cw_eenr_",
        "cw_enr_0000000000000000000000000000000000000000000000000000000000000000",
        "cw_eenr_000000000000000000000000000000000000000000000000000000000000000",
        "cw_eenr_00000000000000000000000000000000000000000000000000000000000000000",
        "cw_eenr_000000000000000000000000000000000000000000000000000000000000000G",
        "cw_eenr_000000000000000000000000000000000000000000000000000000000000000A",
    ] {
        assert!(!well_formed_enrollment_code(malformed), "{malformed}");
    }
}

#[test]
fn network_and_node_names_follow_mesh_rules() {
    for valid in ["work", "Team_1", "a-b", &"n".repeat(128)] {
        assert!(valid_network_id(valid), "{valid}");
    }
    for invalid in ["", "a b", "a.b", "a/b", &"n".repeat(129)] {
        assert!(!valid_network_id(invalid), "{invalid}");
    }
    for valid in ["env-abc123", "app.1", "A_b-c", &"n".repeat(63)] {
        assert!(valid_node_name(valid), "{valid}");
    }
    for invalid in ["", "-env", ".env", "env name", "env/x", &"n".repeat(64)] {
        assert!(!valid_node_name(invalid), "{invalid}");
    }
}
