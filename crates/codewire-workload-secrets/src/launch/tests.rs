use super::*;

const NOW: u64 = 1_000_000;
const CANARY: &str = "synthetic-application-value-never-metadata";

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 7,
        selection_sha256: [2; 32],
        deadline_unix_ms: NOW + 5_000,
    }
}

fn projection() -> EnvironmentProjection {
    EnvironmentProjection::from_entries([
        (
            "DATABASE_URL".into(),
            Zeroizing::new(CANARY.as_bytes().to_vec()),
        ),
        (
            "MULTILINE".into(),
            Zeroizing::new(b" leading\nand trailing ".to_vec()),
        ),
    ])
    .unwrap()
}

#[test]
fn only_selected_recipient_opens_exact_context_and_original_values() {
    let recipient = ProjectionRecipient::new();
    let encrypted =
        seal_environment_projection(projection(), &context(), recipient.public_key(), NOW).unwrap();
    assert!(
        !encrypted
            .windows(CANARY.len())
            .any(|part| part == CANARY.as_bytes())
    );
    let opened = recipient.open(&encrypted, &context(), NOW + 1).unwrap();
    assert_eq!(
        opened.entries().collect::<Vec<_>>(),
        [
            ("DATABASE_URL", CANARY),
            ("MULTILINE", " leading\nand trailing "),
        ]
    );
    assert!(!format!("{opened:?}").contains(CANARY));
    assert!(!format!("{opened:?}").contains("DATABASE_URL"));
}

#[test]
fn empty_selection_round_trips_without_ambient_values() {
    let recipient = ProjectionRecipient::new();
    let encrypted = seal_environment_projection(
        EnvironmentProjection::from_entries([]).unwrap(),
        &context(),
        recipient.public_key(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        recipient
            .open(&encrypted, &context(), NOW)
            .unwrap()
            .entries()
            .len(),
        0
    );
}

#[test]
fn every_context_field_is_bound_without_extending_the_deadline() {
    for field in 0..4 {
        let recipient = ProjectionRecipient::new();
        let encrypted =
            seal_environment_projection(projection(), &context(), recipient.public_key(), NOW)
                .unwrap();
        let mut wrong = context();
        match field {
            0 => wrong.environment_id[0] ^= 1,
            1 => wrong.operation_generation += 1,
            2 => wrong.selection_sha256[0] ^= 1,
            _ => wrong.deadline_unix_ms += 1,
        }
        assert_eq!(
            recipient.open(&encrypted, &wrong, NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn wrong_recipient_and_modified_or_truncated_ciphertext_fail_closed() {
    let recipient = ProjectionRecipient::new();
    let encrypted =
        seal_environment_projection(projection(), &context(), recipient.public_key(), NOW).unwrap();
    assert_eq!(
        ProjectionRecipient::new()
            .open(&encrypted, &context(), NOW)
            .unwrap_err(),
        ProjectionError::InvalidEnvelope
    );
    for variant in 0..3 {
        let recipient = ProjectionRecipient::new();
        let mut encrypted =
            seal_environment_projection(projection(), &context(), recipient.public_key(), NOW)
                .unwrap();
        match variant {
            0 => encrypted[80] ^= 1,
            1 => {
                encrypted.pop();
            }
            _ => encrypted.push(0),
        }
        assert_eq!(
            recipient.open(&encrypted, &context(), NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn context_must_be_live_bounded_and_have_an_existing_operation_identity() {
    for field in 0..6 {
        let mut invalid = context();
        match field {
            0 => invalid.environment_id = [0; 16],
            1 => invalid.operation_generation = 0,
            2 => invalid.selection_sha256 = [0; 32],
            3 => invalid.deadline_unix_ms = NOW,
            4 => invalid.deadline_unix_ms = NOW - 1,
            _ => invalid.deadline_unix_ms = NOW + MAX_PROJECTION_LIFETIME_MS + 1,
        }
        assert_eq!(
            seal_environment_projection(
                projection(),
                &invalid,
                ProjectionRecipient::new().public_key(),
                NOW
            )
            .unwrap_err(),
            ProjectionError::InvalidContext
        );
    }
    let recipient = ProjectionRecipient::new();
    let encrypted =
        seal_environment_projection(projection(), &context(), recipient.public_key(), NOW).unwrap();
    assert_eq!(
        recipient
            .open(&encrypted, &context(), context().deadline_unix_ms)
            .unwrap_err(),
        ProjectionError::InvalidContext
    );
}

#[test]
fn low_order_recipient_keys_are_rejected() {
    let mut one = [0; 32];
    one[0] = 1;
    let mut high_bit_zero = [0; 32];
    high_bit_zero[31] = 128;
    for key in [[0; 32], one, high_bit_zero] {
        assert_eq!(
            seal_environment_projection(projection(), &context(), key, NOW).unwrap_err(),
            ProjectionError::InvalidEnvelope
        );
    }
}

#[test]
fn duplicate_invalid_and_oversized_values_are_rejected_as_a_whole() {
    for entries in [
        vec![
            ("A".into(), Zeroizing::new(b"one".to_vec())),
            ("A".into(), Zeroizing::new(b"two".to_vec())),
        ],
        vec![("1KEY".into(), Zeroizing::new(b"value".to_vec()))],
        vec![("KEY".into(), Zeroizing::new(b"nul\0value".to_vec()))],
        vec![("KEY".into(), Zeroizing::new(vec![0xff]))],
        vec![(
            "KEY".into(),
            Zeroizing::new(vec![b'x'; crate::MAX_WORKLOAD_SECRET_VALUE_BYTES + 1]),
        )],
    ] {
        assert_eq!(
            EnvironmentProjection::from_entries(entries).unwrap_err(),
            ProjectionError::InvalidValues
        );
    }
    let oversized = (0..4).map(|i| {
        (
            format!("KEY_{i}"),
            Zeroizing::new(vec![b'x'; crate::MAX_WORKLOAD_SECRET_VALUE_BYTES]),
        )
    });
    assert_eq!(
        EnvironmentProjection::from_entries(oversized).unwrap_err(),
        ProjectionError::InvalidValues
    );
    let too_many =
        (0..=MAX_WORKLOAD_SECRETS).map(|i| (format!("KEY_{i}"), Zeroizing::new(b"value".to_vec())));
    assert_eq!(
        EnvironmentProjection::from_entries(too_many).unwrap_err(),
        ProjectionError::InvalidValues
    );
}

#[test]
fn maximum_entry_count_and_bounded_large_value_are_accepted() {
    let entries = (0..MAX_WORKLOAD_SECRETS)
        .map(|i| (format!("KEY_{i:03}"), Zeroizing::new(b"value".to_vec())));
    assert_eq!(
        EnvironmentProjection::from_entries(entries)
            .unwrap()
            .entries()
            .len(),
        MAX_WORKLOAD_SECRETS
    );
    assert!(
        EnvironmentProjection::from_entries([(
            "LARGE".into(),
            Zeroizing::new(vec![b'x'; crate::MAX_WORKLOAD_SECRET_VALUE_BYTES])
        )])
        .is_ok()
    );
}

#[test]
fn malformed_plaintext_framing_is_bounded_and_never_partially_delivered() {
    let mut valid = Zeroizing::new(Vec::new());
    projection().encode(&mut valid);
    for cut in 0..valid.len() {
        assert!(EnvironmentProjection::decode(&valid[..cut]).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(EnvironmentProjection::decode(&trailing).is_err());
    for bytes in [
        u32::MAX.to_be_bytes().as_slice(),
        &[0, 0, 0, 1, 255, 255, 255, 255],
    ] {
        assert!(EnvironmentProjection::decode(bytes).is_err());
    }
    // Two identically named entries and non-sorted entries both fail.
    for keys in [["A", "A"], ["B", "A"]] {
        let mut bytes = Zeroizing::new(2_u32.to_be_bytes().to_vec());
        for key in keys {
            bytes.extend_from_slice(&1_u32.to_be_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&1_u32.to_be_bytes());
            bytes.push(b'x');
        }
        assert!(EnvironmentProjection::decode(&bytes).is_err());
    }
}

#[test]
fn oversized_wire_input_is_rejected_before_decryption() {
    let recipient = ProjectionRecipient::new();
    let oversized = vec![0; MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES + 1];
    assert_eq!(
        recipient.open(&oversized, &context(), NOW).unwrap_err(),
        ProjectionError::InvalidEnvelope
    );
}

#[test]
fn aggregate_encoded_size_accepts_exact_limit_and_rejects_one_more_byte() {
    // Four one-byte names: count4 + 4*(key-length4 + key1 + value-length4).
    let overhead = 4 + 4 * 9;
    let final_len =
        MAX_ENVIRONMENT_PROJECTION_BYTES - overhead - 3 * crate::MAX_WORKLOAD_SECRET_VALUE_BYTES;
    for extra in [0, 1] {
        let entries = (0..4).map(|i| {
            let size = if i < 3 {
                crate::MAX_WORKLOAD_SECRET_VALUE_BYTES
            } else {
                final_len + extra
            };
            (
                (char::from(b'A' + i)).to_string(),
                Zeroizing::new(vec![b'x'; size]),
            )
        });
        let result = EnvironmentProjection::from_entries(entries);
        assert_eq!(result.is_ok(), extra == 0);
        if let Ok(projection) = result {
            assert_eq!(projection.encoded_len, MAX_ENVIRONMENT_PROJECTION_BYTES);
        }
    }
}
