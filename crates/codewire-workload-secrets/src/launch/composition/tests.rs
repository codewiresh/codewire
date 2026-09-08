use std::collections::BTreeSet;

use crate::{ProjectionSourceInventory, WorkloadSecretSource};

use super::*;

const NOW: u64 = 1_000_000;
const CANARY: &str = "synthetic-composition-value-never-relay-plaintext";

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 7,
        selection_sha256: [2; 32],
        deadline_unix_ms: NOW + 5_000,
    }
}

fn values(keys: &[&str]) -> EnvironmentProjection {
    EnvironmentProjection::from_entries(keys.iter().map(|key| {
        (
            (*key).to_owned(),
            Zeroizing::new(CANARY.as_bytes().to_vec()),
        )
    }))
    .unwrap()
}

fn plan_for(
    context: &ProjectionContext,
    recipient: [u8; 32],
    local: &[&str],
    platform: &[&str],
) -> ProjectionCompositionPlan {
    ProjectionCompositionPlan::new(
        context,
        [3; 16],
        recipient,
        &[
            ProjectionSourceInventory {
                contributor: ProjectionContributor::Local,
                source: WorkloadSecretSource::Project,
                source_identity: "synthetic-local-project".into(),
                keys: local.iter().map(|name| (*name).to_owned()).collect(),
            },
            ProjectionSourceInventory {
                contributor: ProjectionContributor::Platform,
                source: WorkloadSecretSource::User,
                source_identity: "synthetic-platform-user".into(),
                keys: platform.iter().map(|name| (*name).to_owned()).collect(),
            },
        ],
        &BTreeSet::new(),
        &BTreeSet::new(),
        NOW,
    )
    .unwrap()
}

fn fragment(
    plan: &ProjectionCompositionPlan,
    recipient: [u8; 32],
    contributor: ProjectionContributor,
    keys: &[&str],
) -> Vec<u8> {
    seal_environment_projection_fragment(
        values(keys),
        &context(),
        recipient,
        contributor,
        plan,
        NOW,
    )
    .unwrap()
}

// Test-only producer bypass: construct malicious, validly encrypted parts to
// exercise recipient checks independently of the trusted producer's plan check.
fn raw_part(
    recipient: [u8; 32],
    contributor: ProjectionContributor,
    projection: EnvironmentProjection,
    winners: [u8; 32],
) -> Vec<u8> {
    seal_part(
        projection,
        &context(),
        recipient,
        Some(contributor),
        [4; 32],
        winners,
        NOW,
    )
    .unwrap()
}

#[test]
fn single_bundle_contains_standard_crypto_box_seal_and_zero_composition() {
    let secret = SecretKey::generate(&mut OsRng);
    let encrypted = seal_environment_projection(
        values(&["A"]),
        &context(),
        secret.public_key().to_bytes(),
        NOW,
    )
    .unwrap();
    let (parts, count) = decode_bundle(&encrypted).unwrap();
    assert_eq!(count, 1);
    let plaintext = Zeroizing::new(secret.unseal(parts[0]).unwrap());
    assert!(plaintext.starts_with(MAGIC));
    assert_eq!(
        &plaintext[BINDING_BYTES..BINDING_BYTES + 2],
        &[SINGLE_ROLE, 1]
    );
    assert_eq!(&plaintext[BINDING_BYTES + 2..HEADER_BYTES], &[0; 64]);
    assert_eq!(
        EnvironmentProjection::decode(&plaintext[HEADER_BYTES..])
            .unwrap()
            .entries()
            .next(),
        Some(("A", CANARY))
    );
}

#[test]
fn mixed_round_trip_opens_once_and_keeps_relay_bytes_value_blind() {
    let recipient = ProjectionRecipient::new();
    let plan = plan_for(&context(), recipient.public_key(), &["Z"], &["A"]);
    let local = fragment(
        &plan,
        recipient.public_key(),
        ProjectionContributor::Local,
        &["Z"],
    );
    let platform = fragment(
        &plan,
        recipient.public_key(),
        ProjectionContributor::Platform,
        &["A"],
    );
    let bundle = compose_environment_projection(&local, &platform).unwrap();
    for ciphertext in [&local, &platform, &bundle] {
        assert!(
            !ciphertext
                .windows(CANARY.len())
                .any(|bytes| bytes == CANARY.as_bytes())
        );
    }
    let opened = recipient.open(&bundle, &context(), NOW).unwrap();
    assert_eq!(
        opened.entries().collect::<Vec<_>>(),
        [("A", CANARY), ("Z", CANARY)]
    );
    assert!(!format!("{opened:?}").contains(CANARY));
}

#[test]
fn empty_contributors_are_required_and_round_trip() {
    for (local_names, platform_names) in [
        (&[][..], &["A"][..]),
        (&["A"][..], &[][..]),
        (&[][..], &[][..]),
    ] {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(
            &context(),
            recipient.public_key(),
            local_names,
            platform_names,
        );
        let local = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Local,
            local_names,
        );
        let platform = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Platform,
            platform_names,
        );
        assert!(compose_environment_projection(&local, &[]).is_err());
        assert!(compose_environment_projection(&[], &platform).is_err());
        let bundle = compose_environment_projection(&local, &platform).unwrap();
        assert_eq!(
            recipient
                .open(&bundle, &context(), NOW)
                .unwrap()
                .entries()
                .len(),
            local_names.len() + platform_names.len()
        );
    }
}

#[test]
fn fragment_sealing_requires_exact_plan_keys_and_original_context_recipient() {
    let recipient = ProjectionRecipient::new();
    let plan = plan_for(&context(), recipient.public_key(), &["A", "B"], &["C"]);
    for names in [&[][..], &["A"][..], &["A", "B", "X"][..], &["C"][..]] {
        assert_eq!(
            seal_environment_projection_fragment(
                values(names),
                &context(),
                recipient.public_key(),
                ProjectionContributor::Local,
                &plan,
                NOW
            )
            .unwrap_err(),
            ProjectionError::InvalidValues
        );
    }
    let mut other = context();
    other.operation_generation += 1;
    assert_eq!(
        seal_environment_projection_fragment(
            values(&["A", "B"]),
            &other,
            recipient.public_key(),
            ProjectionContributor::Local,
            &plan,
            NOW
        )
        .unwrap_err(),
        ProjectionError::InvalidContext
    );
    assert_eq!(
        seal_environment_projection_fragment(
            values(&["A", "B"]),
            &context(),
            ProjectionRecipient::new().public_key(),
            ProjectionContributor::Local,
            &plan,
            NOW
        )
        .unwrap_err(),
        ProjectionError::InvalidContext
    );
    assert_eq!(
        seal_environment_projection_fragment(
            values(&["A", "B"]),
            &context(),
            recipient.public_key(),
            ProjectionContributor::Local,
            &plan,
            context().deadline_unix_ms
        )
        .unwrap_err(),
        ProjectionError::InvalidContext
    );
}

#[test]
fn same_role_duplicate_and_reordered_parts_are_rejected() {
    for variant in 0..4 {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(&context(), recipient.public_key(), &["A"], &["B"]);
        let local = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Local,
            &["A"],
        );
        let platform = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Platform,
            &["B"],
        );
        let bundle = match variant {
            0 => compose_environment_projection(&local, &local),
            1 => compose_environment_projection(&platform, &platform),
            2 => compose_environment_projection(&platform, &local),
            _ => {
                let another_local = fragment(
                    &plan,
                    recipient.public_key(),
                    ProjectionContributor::Local,
                    &["A"],
                );
                compose_environment_projection(&local, &another_local)
            }
        }
        .unwrap();
        assert_eq!(
            recipient.open(&bundle, &context(), NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn mixed_parts_cannot_be_opened_as_single_or_incomplete_bundle() {
    for variant in 0..3 {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(&context(), recipient.public_key(), &["A"], &["B"]);
        let local = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Local,
            &["A"],
        );
        let bytes = match variant {
            0 => local,
            1 => encode_bundle(&[decode_fragment(&local).unwrap()]).unwrap(),
            _ => {
                let mut missing = encode_bundle(&[decode_fragment(&local).unwrap()]).unwrap();
                missing[BUNDLE_MAGIC.len()] = 2;
                missing
            }
        };
        assert_eq!(
            recipient.open(&bytes, &context(), NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn ordinary_single_outputs_cannot_be_assembled_into_mixed_projection() {
    let recipient = ProjectionRecipient::new();
    let single =
        seal_environment_projection(values(&["A"]), &context(), recipient.public_key(), NOW)
            .unwrap();
    assert!(compose_environment_projection(&single, &single).is_err());
    // Changing only unauthenticated outer framing must not turn Single into Local.
    let (parts, _) = decode_bundle(&single).unwrap();
    let mixed = encode_bundle(&[parts[0], parts[0]]).unwrap();
    assert_eq!(
        recipient.open(&mixed, &context(), NOW).unwrap_err(),
        ProjectionError::InvalidEnvelope
    );
}

#[test]
fn different_group_context_and_recipient_fail_complete_open() {
    for variant in 0..6 {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(&context(), recipient.public_key(), &["A"], &["B"]);
        let local = fragment(
            &plan,
            recipient.public_key(),
            ProjectionContributor::Local,
            &["A"],
        );
        let mut other = context();
        let mut other_recipient = recipient.public_key();
        match variant {
            0 => {}
            1 => other.environment_id[0] ^= 1,
            2 => other.operation_generation += 1,
            3 => other.selection_sha256[0] ^= 1,
            4 => other.deadline_unix_ms += 1,
            _ => other_recipient = ProjectionRecipient::new().public_key(),
        }
        let other_plan = plan_for(
            &other,
            other_recipient,
            if variant == 0 { &["DIFFERENT"] } else { &["A"] },
            &["B"],
        );
        let platform = seal_environment_projection_fragment(
            values(&["B"]),
            &other,
            other_recipient,
            ProjectionContributor::Platform,
            &other_plan,
            NOW,
        )
        .unwrap();
        let bundle = compose_environment_projection(&local, &platform).unwrap();
        assert_eq!(
            recipient.open(&bundle, &context(), NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn matching_group_still_requires_full_winning_key_digest() {
    for variant in 0..3 {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(&context(), recipient.public_key(), &["A", "B"], &["C"]);
        let digest = if variant == 0 {
            [5; 32]
        } else {
            plan.winning_keys_digest()
        };
        let local = raw_part(
            recipient.public_key(),
            ProjectionContributor::Local,
            values(if variant == 1 { &["A"] } else { &["A", "B"] }),
            digest,
        );
        let platform = raw_part(
            recipient.public_key(),
            ProjectionContributor::Platform,
            values(&["C"]),
            if variant == 2 { [6; 32] } else { digest },
        );
        let bundle = encode_bundle(&[&local, &platform]).unwrap();
        assert_eq!(
            recipient.open(&bundle, &context(), NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn overlap_is_rejected_even_with_matching_malicious_winner_digest() {
    let recipient = ProjectionRecipient::new();
    let names = BTreeSet::from(["A".to_owned()]);
    let digest = composition_winning_keys_digest(&names, &names);
    let local = raw_part(
        recipient.public_key(),
        ProjectionContributor::Local,
        values(&["A"]),
        digest,
    );
    let platform = raw_part(
        recipient.public_key(),
        ProjectionContributor::Platform,
        values(&["A"]),
        digest,
    );
    let bundle = encode_bundle(&[&local, &platform]).unwrap();
    assert_eq!(
        recipient.open(&bundle, &context(), NOW).unwrap_err(),
        ProjectionError::InvalidValues
    );
}

#[test]
fn aggregate_key_count_is_enforced_after_two_individually_bounded_opens() {
    for count in [MAX_WORKLOAD_SECRETS, MAX_WORKLOAD_SECRETS + 1] {
        let recipient = ProjectionRecipient::new();
        let local_names = (0..128)
            .map(|i| format!("LOCAL_{i}"))
            .collect::<BTreeSet<_>>();
        let platform_names = (128..count)
            .map(|i| format!("PLATFORM_{i}"))
            .collect::<BTreeSet<_>>();
        let digest = composition_winning_keys_digest(&local_names, &platform_names);
        let local = raw_part(
            recipient.public_key(),
            ProjectionContributor::Local,
            values(&local_names.iter().map(String::as_str).collect::<Vec<_>>()),
            digest,
        );
        let platform = raw_part(
            recipient.public_key(),
            ProjectionContributor::Platform,
            values(
                &platform_names
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            ),
            digest,
        );
        let bundle = encode_bundle(&[&local, &platform]).unwrap();
        let result = recipient.open(&bundle, &context(), NOW);
        if count == MAX_WORKLOAD_SECRETS {
            assert_eq!(result.unwrap().entries().len(), count);
        } else {
            assert_eq!(result.unwrap_err(), ProjectionError::InvalidValues);
        }
    }
}

#[test]
fn aggregate_byte_limit_includes_only_one_final_count_word() {
    for extra in [0, 1] {
        let recipient = ProjectionRecipient::new();
        let plan = plan_for(&context(), recipient.public_key(), &["A", "B"], &["C", "D"]);
        let final_value_len = MAX_ENVIRONMENT_PROJECTION_BYTES
            - 4
            - 4 * 9
            - 3 * crate::MAX_WORKLOAD_SECRET_VALUE_BYTES;
        let local = EnvironmentProjection::from_entries(["A", "B"].map(|key| {
            (
                key.to_owned(),
                Zeroizing::new(vec![b'x'; crate::MAX_WORKLOAD_SECRET_VALUE_BYTES]),
            )
        }))
        .unwrap();
        let platform = EnvironmentProjection::from_entries([
            (
                "C".to_owned(),
                Zeroizing::new(vec![b'x'; crate::MAX_WORKLOAD_SECRET_VALUE_BYTES]),
            ),
            (
                "D".to_owned(),
                Zeroizing::new(vec![b'x'; final_value_len + extra]),
            ),
        ])
        .unwrap();
        let local = seal_environment_projection_fragment(
            local,
            &context(),
            recipient.public_key(),
            ProjectionContributor::Local,
            &plan,
            NOW,
        )
        .unwrap();
        let platform = seal_environment_projection_fragment(
            platform,
            &context(),
            recipient.public_key(),
            ProjectionContributor::Platform,
            &plan,
            NOW,
        )
        .unwrap();
        let result = compose_environment_projection(&local, &platform);
        if extra == 0 {
            let bundle = result.unwrap();
            assert_eq!(bundle.len(), MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES);
            assert_eq!(
                recipient
                    .open(&bundle, &context(), NOW)
                    .unwrap()
                    .encoded_len,
                MAX_ENVIRONMENT_PROJECTION_BYTES
            );
        } else {
            assert_eq!(result.unwrap_err(), ProjectionError::InvalidEnvelope);
        }
    }
}

#[test]
fn zero_mixed_digest_or_nonzero_single_digest_is_not_sealable() {
    let recipient = ProjectionRecipient::new().public_key();
    for (role, group, winners) in [
        (Some(ProjectionContributor::Local), [0; 32], [1; 32]),
        (Some(ProjectionContributor::Platform), [1; 32], [0; 32]),
        (None, [1; 32], [0; 32]),
        (None, [0; 32], [1; 32]),
    ] {
        assert_eq!(
            seal_part(
                values(&[]),
                &context(),
                recipient,
                role,
                group,
                winners,
                NOW
            )
            .unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn malformed_authenticated_plaintext_fails_public_open() {
    for malformed in 0..8 {
        let recipient = ProjectionRecipient::new();
        let encrypted =
            seal_environment_projection(values(&["A"]), &context(), recipient.public_key(), NOW)
                .unwrap();
        let (parts, _) = decode_bundle(&encrypted).unwrap();
        let mut plaintext = Zeroizing::new(recipient.0.unseal(parts[0]).unwrap());
        match malformed {
            0 => plaintext[0] ^= 1,
            1 => plaintext[BINDING_BYTES - 1] ^= 1,
            2 => plaintext[BINDING_BYTES] = 0,
            3 => plaintext[BINDING_BYTES + 1] = 2,
            4 => plaintext[GROUP_END - 1] ^= 1,
            5 => plaintext[HEADER_BYTES - 1] ^= 1,
            6 => plaintext[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes()),
            _ => plaintext.push(0),
        }
        let cipher = PublicKey::from(recipient.public_key())
            .seal(&mut OsRng, &plaintext)
            .unwrap();
        let bundle = encode_bundle(&[&cipher]).unwrap();
        assert!(recipient.open(&bundle, &context(), NOW).is_err());
    }
}

#[test]
fn outer_lengths_count_trailing_and_legacy_formats_fail_before_open() {
    let recipient = ProjectionRecipient::new();
    let encrypted =
        seal_environment_projection(values(&["A"]), &context(), recipient.public_key(), NOW)
            .unwrap();
    for length in 0..encrypted.len() {
        assert!(decode_bundle(&encrypted[..length]).is_err());
    }
    for count in [0, 3, 255] {
        let mut bytes = encrypted.clone();
        bytes[BUNDLE_MAGIC.len()] = count;
        assert!(decode_bundle(&bytes).is_err());
    }
    for length in [
        0_u32,
        (MIN_CIPHER_BYTES - 1) as u32,
        (MAX_CIPHER_BYTES + 1) as u32,
        u32::MAX,
    ] {
        let mut bytes = encrypted.clone();
        bytes[BUNDLE_HEADER_BYTES..BUNDLE_HEADER_BYTES + 4].copy_from_slice(&length.to_be_bytes());
        assert!(decode_bundle(&bytes).is_err());
    }
    let mut trailing = encrypted.clone();
    trailing.push(0);
    assert!(decode_bundle(&trailing).is_err());
    let (parts, _) = decode_bundle(&encrypted).unwrap();
    assert!(decode_bundle(parts[0]).is_err());
    assert!(decode_bundle(&vec![0; MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES + 1]).is_err());
    // The retired bare sealed-box payload is not an alternate accepted decoder.
    let mut legacy = Zeroizing::new(b"CWENV\0\0\x01".to_vec());
    context().encode(&mut legacy);
    legacy.extend_from_slice(&recipient.public_key());
    values(&["A"]).encode(&mut legacy);
    let legacy = PublicKey::from(recipient.public_key())
        .seal(&mut OsRng, &legacy)
        .unwrap();
    assert_eq!(
        recipient.open(&legacy, &context(), NOW).unwrap_err(),
        ProjectionError::InvalidEnvelope
    );
}

#[test]
fn opaque_fragment_framing_is_bounded_and_has_no_trailing_extension() {
    let recipient = ProjectionRecipient::new();
    let plan = plan_for(&context(), recipient.public_key(), &["A"], &["B"]);
    let local = fragment(
        &plan,
        recipient.public_key(),
        ProjectionContributor::Local,
        &["A"],
    );
    let platform = fragment(
        &plan,
        recipient.public_key(),
        ProjectionContributor::Platform,
        &["B"],
    );
    for length in 0..local.len() {
        assert!(compose_environment_projection(&local[..length], &platform).is_err());
    }
    for bad_length in [0_u32, (MAX_CIPHER_BYTES + 1) as u32, u32::MAX] {
        let mut bytes = local.clone();
        bytes[FRAGMENT_MAGIC.len()..FRAGMENT_HEADER_BYTES]
            .copy_from_slice(&bad_length.to_be_bytes());
        assert!(compose_environment_projection(&bytes, &platform).is_err());
    }
    let mut trailing = local;
    trailing.push(0);
    assert!(compose_environment_projection(&trailing, &platform).is_err());
    assert!(decode_fragment(&vec![0; FRAGMENT_HEADER_BYTES + MAX_CIPHER_BYTES + 1]).is_err());
}
