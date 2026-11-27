use super::*;

const TIME: &str = "2026-11-27T13:10:00.123456789Z";
const VMM_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUNTIME_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DISK_ID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BUILD_ID: &str = "dddddddddddddddddddddddddddddddd";

fn line(text: &str) -> String {
    format!("{TIME} {text}\n")
}

fn hibernated_json(generation: u64) -> String {
    format!(
        r#"{{"event":"hibernated","restore_generation":{generation},"vmm_sha256":"{VMM_SHA}","runtime_image_digest":"{RUNTIME_DIGEST}","image_disk_id":"{DISK_ID}","build_id":"{BUILD_ID}","memory_bytes":4294967296,"at_unix_ms":1764249000000}}"#
    )
}

#[test]
fn the_runtimes_hibernate_restore_and_fallback_records_are_read_in_order() {
    let log = [
        line("standard runtime: hibernating the VM"),
        line(&format!("{RECORD_MARKER}{}", hibernated_json(3))),
        line(&format!(
            r#"{RECORD_MARKER}{{"event":"restored","restore_generation":3,"at_unix_ms":1764249100000}}"#
        )),
        line(&format!(
            r#"{RECORD_MARKER}{{"event":"fallback","restore_generation":4,"reason":"damaged-memory-file","at_unix_ms":1764249200000}}"#
        )),
        line(&format!(
            r#"{RECORD_MARKER}{{"event":"hibernate-failed","reason":"hibernate-timed-out","at_unix_ms":1764249300000}}"#
        )),
    ]
    .concat();
    let parsed = read(log.as_bytes());
    assert_eq!(parsed.refused, 0);
    assert_eq!(
        parsed.records(),
        [
            HibernateRecord::Hibernated(HibernatedRecord {
                restore_generation: 3,
                vmm_sha256: VMM_SHA.into(),
                runtime_image_digest: RUNTIME_DIGEST.into(),
                image_disk_id: DISK_ID.into(),
                build_id: BUILD_ID.into(),
                memory_bytes: 4_294_967_296,
                at_unix_ms: 1_764_249_000_000,
            }),
            HibernateRecord::Restored(RestoredRecord {
                restore_generation: 3,
                at_unix_ms: 1_764_249_100_000,
            }),
            HibernateRecord::Fallback(FallbackRecord {
                restore_generation: 4,
                reason: "damaged-memory-file".into(),
                at_unix_ms: 1_764_249_200_000,
            }),
            HibernateRecord::HibernateFailed(HibernateFailedRecord {
                reason: "hibernate-timed-out".into(),
                at_unix_ms: 1_764_249_300_000,
            }),
        ]
    );
    let (_, hib) = parsed.last_hibernated().expect("hibernated record");
    assert_eq!(
        HibernatedRecord::from_metadata_json(&hib.to_metadata_json()),
        Some(hib.clone())
    );
    assert!(matches!(
        parsed.last_restore_outcome(3),
        Some(HibernateRecord::Restored(_))
    ));
    assert!(matches!(
        parsed.last_restore_outcome(4),
        Some(HibernateRecord::Fallback(_))
    ));
    assert!(parsed.last_restore_outcome(99).is_none());
}

/// Guest output reaches the container log only prefixed `guest-daemon: `, so a
/// forged `vm-hibernate-record` emitted by any guest process is ignored.
#[test]
fn only_a_marker_right_after_the_time_counts() {
    let payload = format!("{RECORD_MARKER}{}", hibernated_json(2));
    let log = [
        line(&format!("guest-daemon: {payload}")),
        line(&format!("guest-daemon: \\n{payload}")),
        format!("{payload}\n"),
        format!("yesterday {payload}\n"),
        line(&format!(" {payload}")),
        line(&format!("x{payload}")),
    ]
    .concat();
    assert_eq!(read(log.as_bytes()), Read::default());
}

/// Strict schema and digest/reason validation: extra fields, bad types,
/// generation 0, malformed hashes, unknown fallback reasons, duplicate fields,
/// or trailing text are refused.
#[test]
fn malformed_or_invalid_marked_lines_are_refused() {
    let refused = [
        // Unknown extra field.
        r#"{"event":"restored","restore_generation":2,"at_unix_ms":1,"extra":"no"}"#.into(),
        // Zero generation or zero memory_bytes.
        hibernated_json(0),
        format!(
            r#"{{"event":"hibernated","restore_generation":2,"vmm_sha256":"{VMM_SHA}","runtime_image_digest":"{RUNTIME_DIGEST}","image_disk_id":"{DISK_ID}","build_id":"{BUILD_ID}","memory_bytes":0,"at_unix_ms":1}}"#
        ),
        r#"{"event":"restored","restore_generation":0,"at_unix_ms":1}"#.into(),
        r#"{"event":"fallback","restore_generation":0,"reason":"rebind-failed","at_unix_ms":1}"#
            .into(),
        // Bad vmm_sha256 / runtime_image_digest / image_disk_id / build_id.
        format!(
            r#"{{"event":"hibernated","restore_generation":2,"vmm_sha256":"short","runtime_image_digest":"{RUNTIME_DIGEST}","image_disk_id":"{DISK_ID}","build_id":"{BUILD_ID}","memory_bytes":1024,"at_unix_ms":1}}"#
        ),
        format!(
            r#"{{"event":"hibernated","restore_generation":2,"vmm_sha256":"{VMM_SHA}","runtime_image_digest":"md5:1234","image_disk_id":"{DISK_ID}","build_id":"{BUILD_ID}","memory_bytes":1024,"at_unix_ms":1}}"#
        ),
        // Unknown fallback reason.
        r#"{"event":"fallback","restore_generation":2,"reason":"arbitrary-guest-text","at_unix_ms":1}"#
            .into(),
        // Invalid hibernate-failed reason (uppercase / spaces).
        r#"{"event":"hibernate-failed","reason":"bad reason!","at_unix_ms":1}"#.into(),
        // Trailing bytes / duplicate key / not JSON.
        r#"{"event":"restored","restore_generation":2,"at_unix_ms":1} trailing"#.into(),
        r#"{"event":"restored","restore_generation":2,"restore_generation":3,"at_unix_ms":1}"#
            .into(),
        "not json".into(),
    ];
    let log: String = refused
        .iter()
        .map(|json| line(&format!("{RECORD_MARKER}{json}")))
        .collect();
    let parsed = read(log.as_bytes());
    assert!(parsed.logged.is_empty(), "{:?}", parsed.logged);
    assert_eq!(parsed.refused, refused.len());
}

/// Nothing from dropped or refused lines is retained, even in Debug output.
#[test]
fn nothing_of_a_dropped_or_refused_line_is_kept() {
    let secret = "guest-secret-value-9876";
    let log = [
        line(&format!("guest-daemon: {secret}")),
        line(&format!(
            r#"{RECORD_MARKER}{{"event":"restored","note":"{secret}"}}"#
        )),
        format!("{TIME} \u{fffd}{secret}\n"),
        "\u{ff}not utf-8\n".to_owned(),
    ]
    .concat();
    let parsed = read(log.as_bytes());
    assert_eq!(parsed.refused, 1);
    assert!(!format!("{parsed:?}").contains(secret));
}
