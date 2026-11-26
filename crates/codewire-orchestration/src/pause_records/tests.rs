use super::*;

const TIME: &str = "2026-11-25T16:24:34.044779812Z";

fn line(text: &str) -> String {
    format!("{TIME} {text}\n")
}

fn paused(sequence: u64) -> String {
    line(&format!(
        "{RECORD_MARKER}{{\"event\":\"paused\",\"generation\":7,\"sequence\":{sequence},\"at_unix_ms\":1764087874000}}"
    ))
}

#[test]
fn the_runtimes_records_are_read_in_order() {
    let log = [
        line("standard runtime: the guest is up after 2100 ms"),
        paused(1),
        line(&format!(
            "{STATE_MARKER}{{\"generation\":7,\"sequence\":1,\"state\":\"paused\",\"since_unix_ms\":1764087874000}}"
        )),
        line(&format!(
            "{RECORD_MARKER}{{\"event\":\"resumed\",\"generation\":7,\"sequence\":2,\"at_unix_ms\":1764087934000}}"
        )),
    ]
    .concat();
    let read = read(log.as_bytes());
    assert_eq!(read.refused, 0);
    assert_eq!(
        read.records(),
        [
            Record::Pause(PauseRecord {
                event: PauseEvent::Paused,
                generation: 7,
                sequence: 1,
                at_unix_ms: 1_764_087_874_000,
            }),
            Record::State(StateRecord {
                generation: 7,
                sequence: 1,
                state: VmState::Paused,
                since_unix_ms: 1_764_087_874_000,
            }),
            Record::Pause(PauseRecord {
                event: PauseEvent::Resumed,
                generation: 7,
                sequence: 2,
                at_unix_ms: 1_764_087_934_000,
            }),
        ]
    );
}

/// cw-security's first term: a marker counts only at the start of the text
/// after the kubelet's time. A guest's line carries the marker only after
/// its prefix, so it is dropped, as is anything else that isn't the
/// runtime's.
#[test]
fn only_a_marker_right_after_the_time_counts() {
    let record = paused(1);
    let record_text = record.split_once(' ').unwrap().1.trim_end();
    let log = [
        // The guest wrote the record's text; the runtime escaped and
        // prefixed it.
        line(&format!("guest-daemon: {record_text}")),
        line(&format!("guest-daemon: \\n{record_text}")),
        // No time, a bad time, or the marker not at the start.
        format!("{record_text}\n"),
        format!("yesterday {record_text}\n"),
        line(&format!(" {record_text}")),
        line(&format!("x{record_text}")),
    ]
    .concat();
    assert_eq!(read(log.as_bytes()), Read::default());
}

/// cw-security's third term: a marked line's JSON is parsed strictly, so no
/// field can be added, retyped or doubled.
#[test]
fn a_marked_line_that_isnt_exactly_one_record_is_refused() {
    let refused = [
        r#"{"event":"paused","generation":7,"sequence":1,"at_unix_ms":1,"rate":"free"}"#,
        r#"{"event":"paused","generation":"7","sequence":1,"at_unix_ms":1}"#,
        r#"{"event":"frozen","generation":7,"sequence":1,"at_unix_ms":1}"#,
        r#"{"event":"paused","generation":7,"sequence":1}"#,
        r#"{"event":"paused","generation":7,"generation":8,"sequence":1,"at_unix_ms":1}"#,
        r#"{"event":"paused","generation":7,"sequence":-1,"at_unix_ms":1}"#,
        r#"{"event":"paused","generation":7,"sequence":1,"at_unix_ms":1} trailing"#,
        r#"{"event":"paused","generation":7,"sequence":1,"at_unix_ms":1}{}"#,
        "not json",
    ];
    let mut log: String = refused
        .iter()
        .map(|json| line(&format!("{RECORD_MARKER}{json}")))
        .collect();
    log.push_str(&line(&format!(
        "{STATE_MARKER}{{\"generation\":7,\"sequence\":1,\"state\":\"paused\",\"since_unix_ms\":1,\"extra\":0}}"
    )));
    let read = read(log.as_bytes());
    assert!(read.logged.is_empty(), "{:?}", read.logged);
    assert_eq!(read.refused, refused.len() + 1);
}

/// cw-security's second term: what a read keeps of a dropped or refused
/// line is nothing at all, not even in its debug form.
#[test]
fn nothing_of_a_dropped_or_refused_line_is_kept() {
    let secret = "guest-secret-value-0123";
    let log = [
        line(&format!("guest-daemon: {secret}")),
        line(&format!(
            "{RECORD_MARKER}{{\"event\":\"paused\",\"note\":\"{secret}\"}}"
        )),
        format!("{TIME} \u{fffd}{secret}\n"),
        "\u{ff}not utf-8\n".to_owned(),
    ]
    .concat();
    let read = read(log.as_bytes());
    assert_eq!(read.refused, 1);
    assert!(!format!("{read:?}").contains(secret));
}
