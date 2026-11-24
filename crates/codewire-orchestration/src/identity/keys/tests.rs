use serde_json::json;

use super::*;

/// Two P-256 public keys OpenBao 2.5.4 generated for an `ecdsa-p256`
/// transit key.
pub(crate) const PEM_1: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg4tPUaiDWhxczk51f4VKfnJTczec\nN+6mSYSviVNo8CWuBC883s6UqB6z4m2exA0lTYzvXqdZB1pxh4RuJRueaA==\n-----END PUBLIC KEY-----\n";
pub(crate) const PEM_2: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc9L0JHUYUrZZcLCOSJHlSmeiS/3d\nAMiCr7NbEKXP1+07TwFgfOAqHhvN+is1wSCKvFI2fwI2uEPxBtelm/JqRw==\n-----END PUBLIC KEY-----\n";

pub(crate) fn at(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .with_timezone(&Utc)
}

/// A key read as OpenBao returns it, with the given (version, creation
/// time) pairs listed and the given minimums.
pub(crate) fn key_read(
    versions: &[(u32, &str)],
    min_decryption: u32,
    min_encryption: u32,
) -> serde_json::Value {
    let keys: serde_json::Map<_, _> = versions
        .iter()
        .map(|(version, created)| {
            let pem = if version % 2 == 1 { PEM_1 } else { PEM_2 };
            (
                version.to_string(),
                json!({"certificate_chain": "", "creation_time": created, "name": "P-256", "public_key": pem}),
            )
        })
        .collect();
    json!({
        "allow_plaintext_backup": false, "auto_rotate_period": 0, "deletion_allowed": false,
        "derived": false, "exportable": false, "imported_key": false, "keys": keys,
        "latest_version": versions.iter().map(|(v, _)| *v).max().unwrap_or(0),
        "min_available_version": 0, "min_decryption_version": min_decryption,
        "min_encryption_version": min_encryption, "name": "sandbox-identity",
        "soft_deleted": false, "supports_decryption": false, "supports_derivation": false,
        "supports_encryption": false, "supports_signing": true, "type": "ecdsa-p256"
    })
}

pub(crate) fn key_set(value: serde_json::Value) -> Result<KeySet, KeySetError> {
    KeySet::from_read(serde_json::from_value(value).unwrap())
}

// The expected coordinates were read from the PEMs with `openssl ec
// -pubin -text`, not from this code.
#[test]
fn every_listed_version_is_an_es256_signing_jwk() {
    let set = key_set(key_read(
        &[
            (1, "2026-11-01T00:00:00Z"),
            (2, "2026-11-02T00:00:00.123456789+01:00"),
        ],
        1,
        0,
    ))
    .unwrap();
    let jwks = serde_json::to_value(set.jwks()).unwrap();
    assert_eq!(
        jwks,
        json!({"keys": [
            {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "sandbox-identity-1",
             "x": "g4tPUaiDWhxczk51f4VKfnJTczecN-6mSYSviVNo8CU",
             "y": "rgQvPN7OlKges-JtnsQNJU2M716nWQdacYeEbiUbnmg"},
            {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "sandbox-identity-2",
             "x": "c9L0JHUYUrZZcLCOSJHlSmeiS_3dAMiCr7NbEKXP1-0",
             "y": "O08BYHzgKh4bzforNcEgirxSNn8CNrhD8QbXpZvyakc"}
        ]})
    );
}

#[test]
fn a_key_that_is_not_p256_or_lists_nothing_is_never_published() {
    let mut wrong_type = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
    wrong_type["type"] = json!("ed25519");
    assert_eq!(key_set(wrong_type), Err(KeySetError::WrongType));
    assert_eq!(key_set(key_read(&[], 1, 0)), Err(KeySetError::Empty));

    for (number, pem) in [
        ("01", PEM_1),
        ("x", PEM_1),
        (
            "1",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ),
        // A P-384 key in the same armour.
        (
            "1",
            "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n-----END PUBLIC KEY-----",
        ),
    ] {
        let mut read = key_read(&[], 1, 0);
        read["keys"] =
            json!({number: {"creation_time": "2026-11-01T00:00:00Z", "public_key": pem}});
        assert!(
            matches!(key_set(read), Err(KeySetError::MalformedVersion(_))),
            "version {number:?} is refused"
        );
    }
}

#[test]
fn a_version_signs_after_24_hours_published_and_leaves_24_hours_after_it_stops() {
    // v2 is created at t0 while v1 signs.
    let t0 = "2026-12-01T00:00:00Z";
    let set = key_set(key_read(&[(1, "2026-11-01T00:00:00Z"), (2, t0)], 1, 1)).unwrap();

    let before = at("2026-12-01T23:59:59Z");
    assert_eq!(set.signing_version(before).unwrap().version, 1);
    assert_eq!(set.rotation_plan(before), RotationPlan::default());

    let switched = at("2026-12-02T00:00:00Z");
    assert_eq!(set.signing_version(switched).unwrap().version, 2);
    // v1's last tokens are still live: it stays published.
    assert_eq!(
        set.rotation_plan(at("2026-12-02T23:59:59Z")),
        RotationPlan::default()
    );

    assert_eq!(
        set.rotation_plan(at("2026-12-03T00:00:00Z")),
        RotationPlan {
            retire_below: Some(2),
            rotate: false
        }
    );
}

#[test]
fn a_stalled_rotation_job_leaves_signing_and_verifying_intact() {
    // The job last ran when v2 was created and has not run for three days:
    // v1 is still listed, v2 signs, and both stay in the JWKS.
    let set = key_set(key_read(
        &[(1, "2026-11-01T00:00:00Z"), (2, "2026-12-01T00:00:00Z")],
        1,
        1,
    ))
    .unwrap();
    let later = at("2026-12-04T00:00:00Z");
    assert_eq!(set.signing_version(later).unwrap().version, 2);
    assert_eq!(set.jwks().keys.len(), 2);
    assert_eq!(set.rotation_plan(later).retire_below, Some(2));
}

#[test]
fn the_job_rotates_once_the_signing_version_is_30_days_old() {
    let set = key_set(key_read(&[(3, "2026-11-01T00:00:00Z")], 3, 3)).unwrap();
    assert!(!set.rotation_plan(at("2026-11-30T23:59:59Z")).rotate);
    assert_eq!(
        set.rotation_plan(at("2026-12-01T00:00:00Z")),
        RotationPlan {
            retire_below: None,
            rotate: true
        }
    );
    // A pending version is already published: no second rotation.
    let pending = key_set(key_read(
        &[(3, "2026-11-01T00:00:00Z"), (4, "2026-12-01T00:00:00Z")],
        3,
        3,
    ))
    .unwrap();
    assert!(!pending.rotation_plan(at("2026-12-01T12:00:00Z")).rotate);
}

#[test]
fn a_new_key_signs_nothing_until_its_first_version_is_24_hours_old() {
    let set = key_set(key_read(&[(1, "2026-11-14T12:00:00Z")], 1, 0)).unwrap();
    for not_yet in [
        "2026-11-14T12:00:00Z",
        "2026-11-15T11:59:00Z",
        "2026-11-15T11:59:59Z",
    ] {
        assert_eq!(
            set.signing_version(at(not_yet)),
            Err(NotYetPublished),
            "{not_yet}"
        );
        assert_eq!(
            set.rotation_plan(at(not_yet)),
            RotationPlan::default(),
            "{not_yet}"
        );
    }
    assert_eq!(
        set.signing_version(at("2026-11-15T12:00:00Z"))
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        NotYetPublished.to_string(),
        "no sandbox identity key version has been published for 24 hours yet"
    );
}

#[test]
fn a_just_created_version_is_served_before_it_signs() {
    let set = key_set(key_read(&[(1, "2026-11-14T12:00:00Z")], 1, 0)).unwrap();
    assert!(set.signing_version(at("2026-11-14T12:00:00Z")).is_err());
    let kids: Vec<_> = set.jwks().keys.into_iter().map(|key| key.kid).collect();
    assert_eq!(kids, [key_id(1)]);
}

#[test]
fn a_signing_key_is_the_signing_version_of_a_pinned_key_only() {
    let read = key_read(
        &[(1, "2026-11-01T00:00:00Z"), (2, "2026-11-14T12:00:00Z")],
        1,
        1,
    );
    let now = at("2026-11-14T12:00:00Z");
    let key = key_set(read.clone()).unwrap().signing_key(now).unwrap();
    assert_eq!(
        (key.version(), key.kid()),
        (1, "sandbox-identity-1".to_owned())
    );

    let fresh = key_set(key_read(&[(1, "2026-11-14T12:00:00Z")], 1, 0)).unwrap();
    assert_eq!(
        fresh.signing_key(now),
        Err(SigningRefusal::NotYetPublished(NotYetPublished))
    );

    let mut drifted = read;
    drifted["exportable"] = json!(true);
    assert_eq!(
        key_set(drifted).unwrap().signing_key(now),
        Err(SigningRefusal::Drift)
    );
}

#[test]
fn custody_is_pinned_only_when_every_setting_matches() {
    let set = key_set(key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0)).unwrap();
    assert!(set.custody.is_pinned());
    for field in ["exportable", "allow_plaintext_backup", "deletion_allowed"] {
        let mut read = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
        read[field] = json!(true);
        assert!(!key_set(read).unwrap().custody.is_pinned(), "{field}");
    }
    let mut read = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
    read["auto_rotate_period"] = json!(3600);
    assert!(!key_set(read).unwrap().custody.is_pinned());
}
