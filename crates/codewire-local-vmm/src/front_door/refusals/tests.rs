use codewire_egress_broker::refusals::Folded;

use super::*;

fn key(host: &str, code: RefusalCode) -> RowKey {
    RowKey {
        host: host.to_owned(),
        port: 443,
        code,
    }
}

fn batch(rows: &[(&str, RefusalCode, u64)], dropped: u64) -> FoldBatch<RowKey, ()> {
    FoldBatch {
        rows: rows
            .iter()
            .map(|(host, code, count)| Folded {
                key: key(host, *code),
                value: (),
                count: *count,
            })
            .collect(),
        dropped,
    }
}

fn row(host: &str, code: RefusalCode, count: u64) -> InterceptedRow {
    InterceptedRow {
        host: host.to_owned(),
        port: 443,
        code,
        count,
    }
}

/// A word carries each row's host, port, code and count, and nothing else:
/// its length is exactly theirs, so no other byte can travel in it.
#[test]
fn a_report_round_trips_and_holds_only_host_port_code_and_count() {
    let word = encode_report(&batch(
        &[
            ("api.anthropic.com", RefusalCode::NameNotAllowed, 5),
            ("api.openai.com", RefusalCode::PathNotServed, u64::MAX),
        ],
        70_000,
    ));
    let report = decode_report(&word).unwrap();
    assert_eq!(report.dropped, u64::from(u16::MAX));
    let mut rows = report.rows;
    rows.sort_by(|a, b| a.host.cmp(&b.host));
    assert_eq!(
        rows,
        [
            row("api.anthropic.com", RefusalCode::NameNotAllowed, 5),
            row("api.openai.com", RefusalCode::PathNotServed, u64::MAX),
        ]
    );
    let fields = |host: &str| 1 + host.len() + 2 + 1 + 8;
    assert_eq!(
        word.len(),
        FRONT_DOOR_REFUSALS_PREFIX.len()
            + 3
            + fields("api.anthropic.com")
            + fields("api.openai.com")
    );
}

/// The sink folds what the front door's back end tells it: a host, a port
/// and a code, which is all it can be told.
#[test]
fn the_sink_folds_each_refusal_by_host_port_and_code() {
    let refusals = FrontDoorRefusals::new();
    for _ in 0..3 {
        refusals.refused("api.anthropic.com", 443, RefusalCode::NameNotAllowed);
    }
    refusals.refused("api.anthropic.com", 443, RefusalCode::Busy);
    let mut rows = decode_report(&encode_report(&refusals.fold().take()))
        .unwrap()
        .rows;
    rows.sort_by_key(|row| row.code);
    assert_eq!(
        rows,
        [
            row("api.anthropic.com", RefusalCode::Busy, 1),
            row("api.anthropic.com", RefusalCode::NameNotAllowed, 3),
        ]
    );
}

/// The largest word fits the runner's bound, and one row past it is
/// refused whole.
#[test]
fn the_largest_report_fits_and_more_rows_are_refused() {
    let host = format!("{}.example", "a".repeat(245));
    let rows: Vec<(&str, RefusalCode, u64)> =
        vec![(host.as_str(), RefusalCode::Busy, u64::MAX); MAX_FRONT_DOOR_REPORT_ROWS];
    let word = encode_report(&batch(&rows, 0));
    assert_eq!(word.len(), MAX_FRONT_DOOR_REPORT_BYTES);
    assert_eq!(
        decode_report(&word).unwrap().rows.len(),
        MAX_FRONT_DOOR_REPORT_ROWS
    );
    let mut over = word.clone();
    let count_at = FRONT_DOOR_REFUSALS_PREFIX.len() + 2;
    over[count_at] = u8::try_from(MAX_FRONT_DOOR_REPORT_ROWS + 1).unwrap();
    assert!(decode_report(&over).is_err());
    let mut longer = word;
    longer.push(0);
    assert_eq!(decode_report(&longer), Err(MalformedReport::Length));
}

/// Every field is checked, and any failure rejects the whole word.
#[test]
fn a_malformed_report_is_rejected_whole() {
    let word = encode_report(&batch(&[("api.anthropic.com", RefusalCode::Busy, 1)], 0));
    let host_at = FRONT_DOOR_REFUSALS_PREFIX.len() + 3 + 1;
    let code_at = word.len() - 8 - 1;
    let port_at = code_at - 2;
    let corrupt = |at: usize, byte: u8| {
        let mut word = word.clone();
        word[at] = byte;
        decode_report(&word)
    };
    assert_eq!(corrupt(host_at, 0x1b), Err(MalformedReport::Host));
    assert_eq!(corrupt(host_at, b'A'), Err(MalformedReport::Host));
    assert_eq!(corrupt(host_at, b' '), Err(MalformedReport::Host));
    assert_eq!(corrupt(code_at, 18), Err(MalformedReport::Field));
    let mut no_port = word.clone();
    no_port[port_at..port_at + 2].copy_from_slice(&[0, 0]);
    assert_eq!(decode_report(&no_port), Err(MalformedReport::Field));
    let mut no_count = word.clone();
    let count_at = word.len() - 8;
    no_count[count_at..].copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(decode_report(&no_count), Err(MalformedReport::Field));
    assert_eq!(
        decode_report(&word[..word.len() - 1]),
        Err(MalformedReport::Length)
    );
    assert_eq!(
        decode_report(b"CWFD1 refusal\n\0\0\0"),
        Err(MalformedReport::Length)
    );
    assert!(!is_refusal_report(b"CWFD1 serving 1\n"));
}
