use super::*;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

fn sample_seed() -> Seed {
    Seed::new(
        Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
        7,
        17777,
        TOKEN,
    )
    .unwrap()
}

#[test]
fn seed_round_trip_is_exact_and_stable() {
    let seed = sample_seed();
    let encoded = seed.encode();

    assert_eq!(encoded.len(), SEED_LEN);
    assert_eq!(&encoded[..8], MAGIC);
    assert_eq!(
        format!("{:x}", Sha256::digest(encoded)),
        "169f0b6ec3c6d32b03e2a4e34fc15a5d551cf24c7ebf3c395aca25896b6a16c9"
    );
    assert_eq!(Seed::decode(&encoded).unwrap(), seed);
    assert_eq!(seed.encode(), encoded);
}

#[test]
fn managed_clients_are_exact_boot_metadata_not_new_authority_or_identity() {
    let base = sample_seed();
    for clients in [
        "v1:none",
        "v1:codex",
        "v1:openai",
        "v1:codex,openai",
        "v1:anthropic",
        "v1:codex,anthropic",
        "v1:openai,anthropic",
        "v1:codex,openai,anthropic",
        "v1:ssh",
        "v1:codex,ssh",
        "v1:openai,ssh",
        "v1:codex,openai,ssh",
        "v1:anthropic,ssh",
        "v1:codex,anthropic,ssh",
        "v1:openai,anthropic,ssh",
        "v1:codex,openai,anthropic,ssh",
        "v2:10",
        "v2:11",
        "v2:12",
        "v2:13",
        "v2:14",
        "v2:15",
        "v2:16",
        "v2:17",
        "v2:18",
        "v2:19",
        "v2:1a",
        "v2:1b",
        "v2:1c",
        "v2:1d",
        "v2:1e",
        "v2:1f",
    ] {
        assert!(clients.len() < MANAGED_CREDENTIAL_CLIENTS_END - MANAGED_CREDENTIAL_CLIENTS_OFFSET);
        let clients = ManagedCredentialClients::decode(clients).unwrap();
        let seed = base.clone().with_managed_credential_clients(clients);
        assert_eq!(seed.vm_id(), base.vm_id());
        assert_eq!(seed.generation(), base.generation());
        assert_eq!(seed.auth_token(), base.auth_token());
        assert_eq!(seed.environment_projection_sha256(), None);
        let encoded = seed.encode();
        assert!(
            encoded[RESERVED_OFFSET..HEADER_LEN]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        let decoded = Seed::decode(&encoded).unwrap();
        assert_eq!(decoded.managed_credential_clients(), clients);
        assert_eq!(decoded, seed);
    }
    for invalid in ["", "codex", "v1:openai,codex", "v1:github", "v1:ssh,codex"] {
        let mut bytes = base.encode();
        bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..MANAGED_CREDENTIAL_CLIENTS_END].fill(0);
        bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..MANAGED_CREDENTIAL_CLIENTS_OFFSET + invalid.len()]
            .copy_from_slice(invalid.as_bytes());
        refresh_checksum(&mut bytes);
        assert_eq!(
            Seed::decode(&bytes),
            Err(SeedError::InvalidManagedCredentialClients)
        );
    }
    let mut bytes = base.encode();
    bytes[MANAGED_CREDENTIAL_CLIENTS_END - 1] = 1;
    refresh_checksum(&mut bytes);
    assert_eq!(
        Seed::decode(&bytes),
        Err(SeedError::InvalidManagedCredentialClients)
    );
    let maximum =
        ManagedCredentialClients::from_profile_slots(["codex", "openai", "anthropic", "ssh"])
            .unwrap()
            .encode();
    assert_eq!(maximum.len(), 29);
    let encoded = base
        .clone()
        .with_managed_credential_clients(ManagedCredentialClients::decode(maximum).unwrap())
        .encode();
    assert_eq!(encoded[MANAGED_CREDENTIAL_CLIENTS_OFFSET + 29], 0);
    assert!(
        encoded[MANAGED_CREDENTIAL_CLIENTS_OFFSET + 30..MANAGED_CREDENTIAL_CLIENTS_END]
            .iter()
            .all(|byte| *byte == 0)
    );
    let mut retired = base.encode();
    put_u16(&mut retired, VERSION_OFFSET, 7);
    refresh_checksum(&mut retired);
    assert_eq!(Seed::decode(&retired), Err(SeedError::UnsupportedVersion));
}

#[test]
fn runtime_catalog_binding_keeps_credential_framing_and_rejects_unbound_bytes() {
    assert_eq!(
        GUEST_RUNTIME_ABI_MARKER,
        format!(
            "\0CWGUESTABI\0seed={FORMAT_VERSION};cw_catalog=1;net={}\0",
            codewire_network_session::NETWORK_PROTOCOL_VERSION
        )
        .as_bytes()
    );
    let clients = ManagedCredentialClients::decode("v2:1f").unwrap();
    let hash = Sha256Value::from_bytes([0xa5; 32]);
    let seed = sample_seed()
        .with_managed_credential_clients(clients)
        .with_cw_runtime_catalog_sha256(hash);
    let encoded = seed.encode();
    let decoded = Seed::decode(&encoded).unwrap();
    assert_eq!(decoded, seed);
    assert_eq!(decoded.managed_credential_clients(), clients);
    assert_eq!(decoded.cw_runtime_catalog_sha256(), Some(hash));
    assert_eq!(
        &encoded[CW_RUNTIME_CATALOG_SHA256_OFFSET..EGRESS_CA_LEN_OFFSET],
        &hash.as_bytes()
    );
    let mut corrupt = encoded;
    let flags = get_u16(&corrupt, FLAGS_OFFSET);
    put_u16(
        &mut corrupt,
        FLAGS_OFFSET,
        flags & !CW_RUNTIME_CATALOG_PRESENT_FLAG,
    );
    refresh_checksum(&mut corrupt);
    assert_eq!(Seed::decode(&corrupt), Err(SeedError::NonZeroReserved));
    let mut retired = encoded;
    put_u16(&mut retired, VERSION_OFFSET, 8);
    refresh_checksum(&mut retired);
    assert_eq!(Seed::decode(&retired), Err(SeedError::UnsupportedVersion));
    let unbound = sample_seed().encode();
    assert_eq!(
        &unbound[CW_RUNTIME_CATALOG_SHA256_OFFSET..EGRESS_CA_LEN_OFFSET],
        &[0; 32]
    );
}

#[test]
fn seed_rejects_corruption_even_in_padding() {
    let mut encoded = sample_seed().encode();
    encoded[2000] ^= 1;
    assert_eq!(Seed::decode(&encoded), Err(SeedError::ChecksumMismatch));

    let mut encoded = sample_seed().encode();
    encoded[2000] = 1;
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroPadding));
}

#[test]
fn seed_rejects_bad_framing_and_token_data() {
    let mut encoded = sample_seed().encode();
    put_u16(&mut encoded, FLAGS_OFFSET, 1 << 15);
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));

    let mut encoded = sample_seed().encode();
    encoded[TOKEN_OFFSET] = b' ';
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(
        Seed::decode(&encoded),
        Err(SeedError::InvalidTokenCharacters)
    );
}

#[test]
fn debug_never_exposes_the_token() {
    let rendered = format!("{:?}", sample_seed());
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(TOKEN));

    let mut corrupt = sample_seed().encode();
    corrupt[TOKEN_OFFSET] = b'!';
    let error = Seed::decode(&corrupt).unwrap_err().to_string();
    assert!(!error.contains(TOKEN));
    assert!(!error.contains("012345"));
}

#[test]
fn constructor_rejects_ambiguous_values() {
    let id = Uuid::new_v4();
    assert_eq!(
        Seed::new(id, 0, 17777, TOKEN),
        Err(SeedError::InvalidGeneration)
    );
    assert_eq!(Seed::new(id, 1, 0, TOKEN), Err(SeedError::InvalidVsockPort));
    assert_eq!(
        Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN)),
        Ok(Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN)).unwrap())
    );
    assert_eq!(
        Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN - 1)),
        Err(SeedError::InvalidTokenLength {
            actual: TOKEN_MIN_LEN - 1
        })
    );
}

#[test]
fn current_seed_binds_one_boot_setup_with_source_compatible_constructor() {
    let setup = SetupBinding::new(
        SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
        Sha256Value::calculate(b"root-generation"),
        Sha256Value::calculate(b"setup-header"),
    )
    .unwrap();
    let seed = Seed::new_with_setup(
        Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
        7,
        17777,
        TOKEN,
        setup,
    )
    .unwrap();
    let encoded = seed.encode();
    assert_eq!(
        format!("{:x}", Sha256::digest(encoded)),
        "a25b6677da015db4db896ae816582b40558608d8775fece09ceb0d683b917742"
    );
    assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
    assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
    assert_eq!(Seed::decode(&encoded).unwrap(), seed);
    assert_eq!(seed.setup(), Some(setup));
    assert_eq!(sample_seed().setup(), None);

    let mut corrupt = encoded;
    corrupt[RESERVED_OFFSET] = 1;
    let checksum = Sha256::digest(&corrupt[..CHECKSUM_OFFSET]);
    corrupt[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(Seed::decode(&corrupt), Err(SeedError::NonZeroReserved));
}

#[test]
fn current_seed_binds_direct_share_plan_with_or_without_setup() {
    let direct_shares = Sha256Value::calculate(b"direct-share-plan");
    for setup in [
        None,
        Some(
            SetupBinding::new(
                SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
                Sha256Value::calculate(b"root-generation"),
                Sha256Value::calculate(b"setup-header"),
            )
            .unwrap(),
        ),
    ] {
        let seed = Seed::new_with_bindings(
            Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
            7,
            17777,
            TOKEN,
            setup,
            Some(direct_shares),
        )
        .unwrap();
        let encoded = seed.encode();
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.setup(), setup);
        assert_eq!(seed.direct_shares_sha256(), Some(direct_shares));
    }
}

#[test]
fn current_seed_binds_skill_snapshot_with_optional_existing_bindings() {
    let setup = SetupBinding::new(
        SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
        Sha256Value::calculate(b"root-generation"),
        Sha256Value::calculate(b"setup-header"),
    )
    .unwrap();
    let direct_shares = Sha256Value::calculate(b"direct-share-plan");
    let skill_snapshot = Sha256Value::calculate(b"skill-snapshot-plan");
    for (setup, direct_shares) in [
        (None, None),
        (Some(setup), None),
        (None, Some(direct_shares)),
        (Some(setup), Some(direct_shares)),
    ] {
        let seed = Seed::new_with_all_bindings(
            Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
            7,
            17777,
            TOKEN,
            setup,
            direct_shares,
            Some(skill_snapshot),
        )
        .unwrap();
        let encoded = seed.encode();
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.setup(), setup);
        assert_eq!(seed.direct_shares_sha256(), direct_shares);
        assert_eq!(seed.skill_snapshot_sha256(), Some(skill_snapshot));
    }
}

#[test]
fn current_seed_binds_docker_disk_presence_with_optional_bindings() {
    let setup = SetupBinding::new(
        SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
        Sha256Value::calculate(b"root-generation"),
        Sha256Value::calculate(b"setup-header"),
    )
    .unwrap();
    let direct_shares = Sha256Value::calculate(b"direct-share-plan");
    let skill_snapshot = Sha256Value::calculate(b"skill-snapshot-plan");
    for (setup, direct_shares, skill_snapshot) in [
        (None, None, None),
        (Some(setup), None, None),
        (None, Some(direct_shares), None),
        (None, None, Some(skill_snapshot)),
        (Some(setup), Some(direct_shares), Some(skill_snapshot)),
    ] {
        let seed = Seed::new_with_all_bindings(
            Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
            7,
            17777,
            TOKEN,
            setup,
            direct_shares,
            skill_snapshot,
        )
        .unwrap()
        .with_docker_data_disk();
        let encoded = seed.encode();
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
        assert_ne!(
            get_u16(&encoded, FLAGS_OFFSET) & DOCKER_DATA_DISK_PRESENT_FLAG,
            0
        );
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert!(seed.docker_data_disk());
        assert_eq!(seed.setup(), setup);
        assert_eq!(seed.direct_shares_sha256(), direct_shares);
        assert_eq!(seed.skill_snapshot_sha256(), skill_snapshot);
    }
}

#[test]
fn current_seed_docker_flag_is_explicit_and_unknown_flags_are_rejected() {
    let seed = sample_seed().with_docker_data_disk();
    let mut encoded = seed.encode();
    put_u16(&mut encoded, FLAGS_OFFSET, 0);
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(Seed::decode(&encoded).unwrap(), sample_seed());

    let mut encoded = seed.encode();
    put_u16(
        &mut encoded,
        FLAGS_OFFSET,
        DOCKER_DATA_DISK_PRESENT_FLAG | (1 << 15),
    );
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
}

#[test]
fn checksum_valid_retired_v6_seed_is_rejected() {
    // V6 was the unshipped one-boot workload-secret format. Construct its
    // historical framing locally so compatibility stays explicitly
    // fail-closed without restoring a production material decoder.
    const RETIRED_V6: u16 = 6;
    const RETIRED_HEADER_LEN: usize = 240;
    const RETIRED_SECRET_TOTAL_LEN_OFFSET: usize = 184;
    const RETIRED_SECRET_SHA256_OFFSET: usize = 192;
    const RETIRED_SECRET_ENTRY_COUNT_OFFSET: usize = 224;
    const RETIRED_SECRET_PRESENT_FLAG: u16 = 1 << 4;

    let mut encoded = sample_seed().with_docker_data_disk().encode();
    encoded[RETIRED_SECRET_TOTAL_LEN_OFFSET..RETIRED_HEADER_LEN + TOKEN.len()].fill(0);
    put_u16(&mut encoded, VERSION_OFFSET, RETIRED_V6);
    put_u16(&mut encoded, HEADER_LEN_OFFSET, RETIRED_HEADER_LEN as u16);
    put_u16(
        &mut encoded,
        FLAGS_OFFSET,
        DOCKER_DATA_DISK_PRESENT_FLAG | RETIRED_SECRET_PRESENT_FLAG,
    );
    put_u64(&mut encoded, RETIRED_SECRET_TOTAL_LEN_OFFSET, 4096);
    encoded[RETIRED_SECRET_SHA256_OFFSET..RETIRED_SECRET_SHA256_OFFSET + 32].fill(0x5a);
    put_u32(&mut encoded, RETIRED_SECRET_ENTRY_COUNT_OFFSET, 1);
    encoded[RETIRED_HEADER_LEN..RETIRED_HEADER_LEN + TOKEN.len()].copy_from_slice(TOKEN.as_bytes());
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);

    assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
}

#[test]
fn every_optional_binding_combination_uses_only_current_format() {
    let setup = SetupBinding::new(
        SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
        Sha256Value::calculate(b"root-generation"),
        Sha256Value::calculate(b"setup-header"),
    )
    .unwrap();
    let direct = Sha256Value::calculate(b"direct-share-plan");
    let skill = Sha256Value::calculate(b"skill-snapshot-plan");
    let projection = Sha256Value::calculate(b"canonical-project-selection");
    for flags in 0_u16..32 {
        let selected_setup = (flags & SETUP_PRESENT_FLAG != 0).then_some(setup);
        let selected_direct = (flags & DIRECT_SHARES_PRESENT_FLAG != 0).then_some(direct);
        let selected_skill = (flags & SKILL_SNAPSHOT_PRESENT_FLAG != 0).then_some(skill);
        let mut seed = Seed::new_with_all_bindings(
            sample_seed().vm_id(),
            7,
            17777,
            TOKEN,
            selected_setup,
            selected_direct,
            selected_skill,
        )
        .unwrap();
        if flags & DOCKER_DATA_DISK_PRESENT_FLAG != 0 {
            seed = seed.with_docker_data_disk();
        }
        if flags & ENVIRONMENT_PROJECTION_PRESENT_FLAG != 0 {
            seed = seed.with_environment_projection_sha256(projection);
        }
        let encoded = seed.encode();
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
        assert_eq!(get_u16(&encoded, FLAGS_OFFSET), flags);
        assert_eq!(
            &encoded[TOKEN_OFFSET..TOKEN_OFFSET + TOKEN.len()],
            TOKEN.as_bytes()
        );
        let decoded = Seed::decode(&encoded).unwrap();
        assert_eq!(decoded, seed);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.setup(), selected_setup);
        assert_eq!(decoded.direct_shares_sha256(), selected_direct);
        assert_eq!(decoded.skill_snapshot_sha256(), selected_skill);
        assert_eq!(
            decoded.docker_data_disk(),
            flags & DOCKER_DATA_DISK_PRESENT_FLAG != 0
        );
        assert_eq!(
            decoded.environment_projection_sha256(),
            (flags & ENVIRONMENT_PROJECTION_PRESENT_FLAG != 0).then_some(projection)
        );
    }
}

#[test]
fn projection_binding_is_optional_checksum_bound_and_does_not_change_operation_identity() {
    let base = sample_seed();
    assert_eq!(base.environment_projection_sha256(), None);
    let hash = Sha256Value::calculate(b"canonical-project-selection");
    let seed = base.clone().with_environment_projection_sha256(hash);
    assert_eq!(seed.vm_id(), base.vm_id());
    assert_eq!(seed.generation(), base.generation());
    assert_eq!(seed.auth_token(), base.auth_token());
    let mut encoded = seed.encode();
    assert_eq!(&encoded[184..216], &hash.as_bytes());
    assert_eq!(&encoded[216..223], b"v1:none");
    assert!(encoded[223..256].iter().all(|byte| *byte == 0));
    encoded[184] ^= 1;
    assert_eq!(Seed::decode(&encoded), Err(SeedError::ChecksumMismatch));

    let mut encoded = seed.encode();
    put_u16(&mut encoded, FLAGS_OFFSET, 0);
    refresh_checksum(&mut encoded);
    assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
}

#[test]
fn absent_binding_storage_and_reserved_bytes_cannot_hide_data() {
    for offset in [48, 56, 88, 120, 152, 184, 215, 248, 255] {
        let mut encoded = sample_seed().encode();
        encoded[offset] = 1;
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
    }
    for header in [0, 48, 192, 223, 224, 225, 240, 255, 257, u16::MAX] {
        let mut encoded = sample_seed().encode();
        put_u16(&mut encoded, HEADER_LEN_OFFSET, header);
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::InvalidFraming));
    }
}

#[test]
fn checksum_valid_retired_versions_one_through_five_are_rejected() {
    // Historical byte shapes are test-only fixtures, not decoder branches.
    for (version, header, flags) in [
        (1, 48, 0),
        (2, 128, 1),
        (3, 160, 2),
        (4, 192, 4),
        (5, 192, 8),
    ] {
        let mut encoded = [0; SEED_LEN];
        encoded[..48].copy_from_slice(&sample_seed().encode()[..48]);
        put_u16(&mut encoded, VERSION_OFFSET, version);
        put_u16(&mut encoded, HEADER_LEN_OFFSET, header);
        put_u16(&mut encoded, FLAGS_OFFSET, flags);
        match version {
            2 => {
                put_u64(&mut encoded, 48, SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT);
                encoded[56..88].fill(0x11);
                encoded[88..120].fill(0x22);
            }
            3 => encoded[120..152].fill(0x33),
            4 => encoded[152..184].fill(0x44),
            _ => {}
        }
        let offset = usize::from(header);
        encoded[offset..offset + TOKEN.len()].copy_from_slice(TOKEN.as_bytes());
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
    }
    for version in [0, FORMAT_VERSION + 1, u16::MAX] {
        let mut encoded = sample_seed().encode();
        put_u16(&mut encoded, VERSION_OFFSET, version);
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
    }
}

fn refresh_checksum(encoded: &mut [u8; SEED_LEN]) {
    let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
    encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
}

/// The hosts a boot may intercept: the agent routes today, and GitHub's two
/// next (#3997). A real front-door CA for all of them, beside the longest
/// token, must fit the seed.
const INTERCEPTED_HOSTS: [&str; 5] = [
    "api.anthropic.com",
    "api.openai.com",
    "chatgpt.com",
    "github.com",
    "api.github.com",
];

fn front_door_ca() -> EgressCaCertificate {
    let ca = codewire_egress_front_door::EnvironmentCa::generate(INTERCEPTED_HOSTS).unwrap();
    EgressCaCertificate::from_der(ca.certificate_der().to_vec()).unwrap()
}

#[test]
fn a_real_front_door_ca_fits_beside_the_longest_token_and_round_trips() {
    let certificate = front_door_ca();
    let longest_token = "a".repeat(TOKEN_MAX_LEN);
    let seed = Seed::new(
        Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
        7,
        7_777,
        longest_token.as_str(),
    )
    .unwrap()
    .with_egress_ca(certificate.clone());
    let decoded = Seed::decode(&seed.encode()).unwrap();
    assert_eq!(decoded, seed);
    assert_eq!(decoded.egress_ca(), Some(&certificate));
    assert_eq!(decoded.auth_token(), longest_token);
}

#[test]
fn a_seed_without_a_ca_has_none_and_keeps_the_ca_bytes_zero() {
    let encoded = sample_seed().encode();
    assert_eq!(Seed::decode(&encoded).unwrap().egress_ca(), None);
    assert!(
        encoded[EGRESS_CA_LEN_OFFSET..EGRESS_CA_LEN_OFFSET + 2]
            .iter()
            .chain(&encoded[EGRESS_CA_OFFSET..CHECKSUM_OFFSET])
            .all(|byte| *byte == 0)
    );
}

#[test]
fn ca_bytes_without_their_flag_or_beyond_their_length_are_refused() {
    let with_ca = sample_seed().with_egress_ca(front_door_ca()).encode();
    let der_len = usize::from(get_u16(&with_ca, EGRESS_CA_LEN_OFFSET));

    let mut unflagged = with_ca;
    let flags = get_u16(&unflagged, FLAGS_OFFSET) & !EGRESS_CA_PRESENT_FLAG;
    put_u16(&mut unflagged, FLAGS_OFFSET, flags);
    refresh_checksum(&mut unflagged);
    assert_eq!(Seed::decode(&unflagged), Err(SeedError::NonZeroReserved));

    let mut trailing = with_ca;
    trailing[EGRESS_CA_OFFSET + der_len] = 1;
    refresh_checksum(&mut trailing);
    assert_eq!(Seed::decode(&trailing), Err(SeedError::NonZeroPadding));

    for length in [MAX_EGRESS_CA_DER_BYTES + 1, usize::from(u16::MAX)] {
        let mut overlong = with_ca;
        put_u16(
            &mut overlong,
            EGRESS_CA_LEN_OFFSET,
            u16::try_from(length).unwrap(),
        );
        refresh_checksum(&mut overlong);
        assert!(matches!(
            Seed::decode(&overlong),
            Err(SeedError::InvalidEgressCa(EgressCaError::TooLarge { .. }))
        ));
    }

    let mut truncated = with_ca;
    put_u16(
        &mut truncated,
        EGRESS_CA_LEN_OFFSET,
        u16::try_from(der_len - 1).unwrap(),
    );
    truncated[EGRESS_CA_OFFSET + der_len - 1] = 0;
    refresh_checksum(&mut truncated);
    assert_eq!(
        Seed::decode(&truncated),
        Err(SeedError::InvalidEgressCa(EgressCaError::NotACertificate))
    );
}

#[test]
fn a_checksum_valid_v9_or_v10_seed_is_refused() {
    for version in [9, 10] {
        let mut encoded = sample_seed().encode();
        put_u16(&mut encoded, VERSION_OFFSET, version);
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
    }
}

#[test]
fn a_runtime_move_names_another_catalog_than_its_bound_one() {
    let bound = Sha256Value::from_bytes([0xa5; 32]);
    let earlier = Sha256Value::from_bytes([0x5a; 32]);
    let seed = sample_seed()
        .with_cw_runtime_catalog_sha256(bound)
        .with_cw_runtime_moved_from_sha256(earlier)
        .unwrap();
    let encoded = seed.encode();
    let decoded = Seed::decode(&encoded).unwrap();
    assert_eq!(decoded, seed);
    assert_eq!(decoded.cw_runtime_moved_from_sha256(), Some(earlier));
    assert_eq!(
        &encoded[CW_RUNTIME_MOVED_FROM_SHA256_OFFSET..HEADER_LEN],
        &earlier.as_bytes()
    );
    assert!(
        encoded[RESERVED_OFFSET..RESERVED_END]
            .iter()
            .all(|byte| *byte == 0)
    );
    // A boot that is no move carries none.
    let unmoved = sample_seed().with_cw_runtime_catalog_sha256(bound);
    assert_eq!(unmoved.cw_runtime_moved_from_sha256(), None);
    assert!(
        unmoved.encode()[CW_RUNTIME_MOVED_FROM_SHA256_OFFSET..HEADER_LEN]
            .iter()
            .all(|byte| *byte == 0)
    );
    // Only with a bound catalog, and never that catalog.
    assert_eq!(
        sample_seed().with_cw_runtime_moved_from_sha256(earlier),
        Err(SeedError::InvalidRuntimeMove)
    );
    assert_eq!(
        unmoved.clone().with_cw_runtime_moved_from_sha256(bound),
        Err(SeedError::InvalidRuntimeMove)
    );
    // Decoding refuses the same, and move bytes without the flag.
    let mut same = encoded;
    same[CW_RUNTIME_MOVED_FROM_SHA256_OFFSET..HEADER_LEN].copy_from_slice(&bound.as_bytes());
    refresh_checksum(&mut same);
    assert_eq!(Seed::decode(&same), Err(SeedError::InvalidRuntimeMove));
    let mut unflagged = encoded;
    let flags = get_u16(&unflagged, FLAGS_OFFSET);
    put_u16(
        &mut unflagged,
        FLAGS_OFFSET,
        flags & !CW_RUNTIME_MOVED_FROM_PRESENT_FLAG,
    );
    refresh_checksum(&mut unflagged);
    assert_eq!(Seed::decode(&unflagged), Err(SeedError::NonZeroReserved));
    let mut reserved = unmoved.encode();
    reserved[RESERVED_END - 1] = 1;
    refresh_checksum(&mut reserved);
    assert_eq!(Seed::decode(&reserved), Err(SeedError::NonZeroReserved));
}

fn placeholder(slot: &str, credential: &str) -> codewire_access::CredentialPlaceholder {
    codewire_access::CredentialPlaceholder::derive(
        &codewire_access::PlaceholderKey::from_slice(&[5; codewire_access::PLACEHOLDER_KEY_BYTES])
            .unwrap(),
        &codewire_access::EnvironmentId::parse("environment-a").unwrap(),
        7,
        &codewire_access::CapabilitySlot::parse(slot).unwrap(),
        &codewire_access::CredentialId::parse(credential).unwrap(),
    )
}

fn both_placeholders() -> SeedPlaceholders {
    SeedPlaceholders::new([
        (
            PlaceholderSlot::AnthropicSubscriptionToken,
            placeholder("anthropic", "cred-subscription"),
        ),
        (
            PlaceholderSlot::AnthropicApiKey,
            placeholder("anthropic", "cred-api-key"),
        ),
    ])
    .unwrap()
}

#[test]
fn a_real_ca_and_every_placeholder_fit_beside_the_longest_token() {
    let longest_token = "a".repeat(TOKEN_MAX_LEN);
    let seed = Seed::new(
        Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
        7,
        7_777,
        longest_token.as_str(),
    )
    .unwrap()
    .with_egress_ca(front_door_ca())
    .with_credential_placeholders(both_placeholders())
    .unwrap();
    let decoded = Seed::decode(&seed.encode()).unwrap();
    assert_eq!(decoded, seed);
    let entries = decoded.credential_placeholders().entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, PlaceholderSlot::AnthropicApiKey);
    assert!(
        entries[0]
            .1
            .ct_eq(&placeholder("anthropic", "cred-api-key"))
    );
    assert_eq!(entries[1].0, PlaceholderSlot::AnthropicSubscriptionToken);
}

#[test]
fn placeholders_need_the_ca() {
    assert_eq!(
        sample_seed().with_credential_placeholders(both_placeholders()),
        Err(SeedError::InvalidPlaceholders)
    );
    let mut without_ca_flag = sample_seed()
        .with_egress_ca(front_door_ca())
        .with_credential_placeholders(both_placeholders())
        .unwrap()
        .encode();
    let flags = get_u16(&without_ca_flag, FLAGS_OFFSET) & !EGRESS_CA_PRESENT_FLAG;
    put_u16(&mut without_ca_flag, FLAGS_OFFSET, flags);
    put_u16(&mut without_ca_flag, EGRESS_CA_LEN_OFFSET, 0);
    without_ca_flag[EGRESS_CA_OFFSET..CHECKSUM_OFFSET].fill(0);
    refresh_checksum(&mut without_ca_flag);
    assert_eq!(
        Seed::decode(&without_ca_flag),
        Err(SeedError::InvalidPlaceholders)
    );
}

#[test]
fn a_malformed_placeholder_region_is_refused() {
    let valid = sample_seed()
        .with_egress_ca(front_door_ca())
        .with_credential_placeholders(both_placeholders())
        .unwrap()
        .encode();
    let entry = 1 + codewire_access::CREDENTIAL_PLACEHOLDER_LENGTH;
    let mutate = |change: &dyn Fn(&mut [u8; SEED_LEN])| {
        let mut bytes = valid;
        change(&mut bytes);
        refresh_checksum(&mut bytes);
        Seed::decode(&bytes)
    };
    for (case, change) in [
        (
            "count past the slot kinds",
            &(|bytes: &mut [u8; SEED_LEN]| bytes[PLACEHOLDERS_OFFSET] = 3)
                as &dyn Fn(&mut [u8; SEED_LEN]),
        ),
        ("an unknown kind", &|bytes: &mut [u8; SEED_LEN]| {
            bytes[PLACEHOLDERS_OFFSET + 1] = 3
        }),
        ("a duplicate kind", &|bytes: &mut [u8; SEED_LEN]| {
            bytes[PLACEHOLDERS_OFFSET + 1 + entry] = bytes[PLACEHOLDERS_OFFSET + 1]
        }),
        (
            "a value that is not a placeholder",
            &|bytes: &mut [u8; SEED_LEN]| bytes[PLACEHOLDERS_OFFSET + 2] = b'x',
        ),
        ("a flag with no entries", &|bytes: &mut [u8; SEED_LEN]| {
            bytes[PLACEHOLDERS_OFFSET..EGRESS_CA_OFFSET].fill(0)
        }),
    ] {
        assert_eq!(
            mutate(change),
            Err(SeedError::InvalidPlaceholders),
            "{case}"
        );
    }
    let one = SeedPlaceholders::new([(
        PlaceholderSlot::AnthropicApiKey,
        placeholder("anthropic", "cred-api-key"),
    )])
    .unwrap();
    let mut trailing = sample_seed()
        .with_egress_ca(front_door_ca())
        .with_credential_placeholders(one)
        .unwrap()
        .encode();
    trailing[PLACEHOLDERS_OFFSET + 1 + entry] = 1;
    refresh_checksum(&mut trailing);
    assert_eq!(Seed::decode(&trailing), Err(SeedError::NonZeroPadding));
}

#[test]
fn placeholders_are_never_printed() {
    let seed = sample_seed()
        .with_egress_ca(front_door_ca())
        .with_credential_placeholders(both_placeholders())
        .unwrap();
    let printed = format!("{seed:?}");
    assert!(printed.contains("AnthropicApiKey"));
    assert!(!printed.contains(codewire_access::CREDENTIAL_PLACEHOLDER_TAG));
}

fn sample_setup() -> SetupBinding {
    SetupBinding::new(
        SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
        Sha256Value::calculate(b"image-disk-id"),
        Sha256Value::calculate(b"build-pack-header"),
    )
    .unwrap()
}

#[test]
fn a_builder_seed_carries_only_its_setup_pack_and_build_mode() {
    let build_vm = Uuid::new_v4();
    let seed = Seed::for_image_build(build_vm, 17777, TOKEN, sample_setup()).unwrap();
    let encoded = seed.encode();
    assert_eq!(
        get_u16(&encoded, FLAGS_OFFSET),
        SETUP_PRESENT_FLAG | IMAGE_BUILD_FLAG
    );
    let decoded = Seed::decode(&encoded).unwrap();
    assert_eq!(decoded, seed);
    assert!(decoded.image_build());
    assert!(!decoded.image_disk());
    assert_eq!(decoded.vm_id(), build_vm);
    assert_eq!(decoded.setup(), Some(sample_setup()));
    assert_eq!(decoded.direct_shares_sha256(), None);
    assert_eq!(decoded.skill_snapshot_sha256(), None);
    assert!(!decoded.docker_data_disk());
    assert_eq!(decoded.environment_projection_sha256(), None);
    assert_eq!(
        decoded.managed_credential_clients(),
        ManagedCredentialClients::default()
    );
    assert_eq!(decoded.cw_runtime_catalog_sha256(), None);
    // Every environment constructor leaves build mode off.
    assert!(!sample_seed().image_build());
    assert!(!sample_seed().with_image_disk().image_build());
}

#[test]
fn build_mode_with_anything_else_is_refused_before_use() {
    let hash = Sha256Value::calculate(b"other");
    let base = || Seed::new_with_setup(Uuid::new_v4(), 1, 17777, TOKEN, sample_setup()).unwrap();
    let others = [
        base().with_docker_data_disk(),
        base().with_image_disk(),
        base().with_environment_projection_sha256(hash),
        base().with_cw_runtime_catalog_sha256(hash),
        base().with_egress_ca(front_door_ca()),
        Seed::new_with_all_bindings(
            Uuid::new_v4(),
            1,
            17777,
            TOKEN,
            Some(sample_setup()),
            Some(hash),
            None,
        )
        .unwrap(),
        Seed::new_with_all_bindings(
            Uuid::new_v4(),
            1,
            17777,
            TOKEN,
            Some(sample_setup()),
            None,
            Some(hash),
        )
        .unwrap(),
        // A builder without its setup pack.
        sample_seed(),
    ];
    for other in others {
        let mut encoded = other.encode();
        let flags = get_u16(&encoded, FLAGS_OFFSET);
        put_u16(&mut encoded, FLAGS_OFFSET, flags | IMAGE_BUILD_FLAG);
        refresh_checksum(&mut encoded);
        assert_eq!(
            Seed::decode(&encoded),
            Err(SeedError::InvalidImageBuild),
            "{other:?}"
        );
    }
}

#[test]
fn an_image_disk_seed_round_trips_and_older_flags_are_unchanged() {
    let seed = sample_seed().with_docker_data_disk().with_image_disk();
    let encoded = seed.encode();
    assert_eq!(
        get_u16(&encoded, FLAGS_OFFSET),
        DOCKER_DATA_DISK_PRESENT_FLAG | IMAGE_DISK_FLAG
    );
    let decoded = Seed::decode(&encoded).unwrap();
    assert!(decoded.image_disk());
    assert!(!decoded.image_build());
    assert_eq!(get_u16(&sample_seed().encode(), FLAGS_OFFSET), 0);
}
