use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111));

fn digest(byte: u8) -> PolicyDigest {
    PolicyDigest::from_bytes([byte; 32])
}

fn row(destination: Destination, transport: Transport, reason: RefusalReason) -> RefusedRow {
    RefusedRow {
        destination,
        address: Some(V4),
        transport,
        reason,
        policy_digest: digest(1),
        count: 3,
    }
}

fn batch() -> RefusalBatch {
    RefusalBatch {
        rows: vec![
            RefusedRow {
                address: None,
                ..row(
                    Destination::checked_name("example.org"),
                    Transport::Dns,
                    RefusalReason::NameNotAllowed,
                )
            },
            row(
                Destination::checked_name("example.com"),
                Transport::Tcp { port: 8080 },
                RefusalReason::PortNotAllowed,
            ),
            RefusedRow {
                address: Some(V6),
                ..row(
                    Destination::Address(V6),
                    Transport::Udp { port: 443 },
                    RefusalReason::ProtectedAddress,
                )
            },
            row(
                Destination::checked_name("evil\x1b[2J.example.com"),
                Transport::Dns,
                RefusalReason::NameNotAllowed,
            ),
        ],
        dropped: 7,
    }
}

async fn read(frame: &[u8]) -> io::Result<RefusalBatch> {
    let mut reader = frame;
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    assert_eq!(magic, REFUSAL_FRAME_MAGIC);
    read_refusal_frame_after_magic(&mut reader).await
}

#[tokio::test]
async fn a_report_round_trips_and_a_withheld_name_keeps_no_text() {
    let frame = encode_refusal_frame(&batch()).unwrap();
    assert_eq!(read(&frame).await.unwrap(), batch());
    assert_eq!(batch().rows[3].destination, Destination::Withheld);
    assert!(!frame.windows(4).any(|window| window == b"evil"));
    assert!(!frame.contains(&0x1b));
}

#[tokio::test]
async fn an_oversized_report_is_refused_before_its_body_is_read() {
    let mut frame = REFUSAL_FRAME_MAGIC.to_vec();
    frame.push(REFUSAL_FRAME_VERSION);
    frame.extend_from_slice(
        &u32::try_from(MAX_REFUSAL_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes(),
    );
    let error = read(&frame).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut body = 0_u64.to_be_bytes().to_vec();
    body.extend_from_slice(
        &u16::try_from(MAX_REFUSAL_FRAME_ROWS + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert!(decode_refusal_body(&body).is_err());

    let too_many = RefusalBatch {
        rows: vec![batch().rows[1].clone(); MAX_REFUSAL_FRAME_ROWS + 1],
        dropped: 0,
    };
    assert!(encode_refusal_frame(&too_many).is_err());
}

#[test]
fn the_largest_report_fits_its_byte_bound() {
    let longest = RefusedRow {
        address: Some(V6),
        count: u64::MAX,
        ..row(
            Destination::checked_name(&"a".repeat(253)),
            Transport::Tcp { port: 65_535 },
            RefusalReason::InterceptUnavailable,
        )
    };
    let full = RefusalBatch {
        rows: vec![longest; MAX_REFUSAL_FRAME_ROWS],
        dropped: u64::MAX,
    };
    assert!(encode_refusal_frame(&full).is_ok());
}

#[test]
fn a_malformed_report_is_refused() {
    let frame = encode_refusal_frame(&RefusalBatch {
        rows: vec![batch().rows[1].clone()],
        dropped: 0,
    })
    .unwrap();
    let body = &frame[9..];
    assert!(decode_refusal_body(body).is_ok());
    let name_at = 8 + 2 + 2;
    let corrupt = |at: usize, byte: u8| {
        let mut body = body.to_vec();
        body[at] = byte;
        decode_refusal_body(&body)
    };
    // An escape in a name, an upper-case name, an unknown destination kind.
    assert!(corrupt(name_at, 0x1b).is_err());
    assert!(corrupt(name_at, b'E').is_err());
    assert!(corrupt(10, 9).is_err());
    let count_at = body.len() - 8;
    let mut zero = body.to_vec();
    zero[count_at..].copy_from_slice(&0_u64.to_be_bytes());
    assert!(decode_refusal_body(&zero).is_err());
    let reason_at = count_at - 32 - 1;
    assert!(corrupt(reason_at, 200).is_err());
    let mut trailing = body.to_vec();
    trailing.push(0);
    assert!(decode_refusal_body(&trailing).is_err());
    assert!(decode_refusal_body(&body[..body.len() - 1]).is_err());
}

#[test]
fn the_runner_labels_each_row_with_the_policy_it_sent_for_its_digest() {
    let log = RunnerRefusalLog::new(1_000);
    log.label(digest(1), "walk-log".to_owned(), 1);
    log.file(batch(), 2_000);
    // A report under a revision the runner names after it arrived.
    log.file(
        RefusalBatch {
            rows: vec![RefusedRow {
                policy_digest: digest(2),
                count: 2,
                ..batch().rows[1].clone()
            }],
            dropped: 1,
        },
        3_000,
    );
    log.label(digest(2), "walk-log".to_owned(), 2);

    let snapshot = log.snapshot();
    assert_eq!(snapshot.started_unix_ms, 1_000);
    assert_eq!(snapshot.refused, 3 * 4 + 2);
    assert_eq!(snapshot.last_unix_ms, Some(3_000));
    assert_eq!(snapshot.dropped, 8);
    assert_eq!(snapshot.records.len(), 4);
    let newest = &snapshot.records[0];
    assert_eq!(
        newest.destination,
        Destination::Name("example.com".to_owned())
    );
    assert_eq!(
        (newest.policy.name.as_str(), newest.policy.revision),
        ("walk-log", 2)
    );
    assert_eq!(newest.count, 5);
    assert_eq!(
        (newest.first_seen_unix_ms, newest.last_seen_unix_ms),
        (2_000, 3_000)
    );
    for record in &snapshot.records[1..] {
        assert_eq!(
            (record.policy.name.as_str(), record.policy.revision),
            ("walk-log", 1)
        );
    }
}

#[test]
fn past_its_bound_the_runner_log_drops_the_least_recently_seen_and_says_so() {
    let log = RunnerRefusalLog::new(0);
    for index in 0..1_100_u64 {
        log.file(
            RefusalBatch {
                rows: vec![RefusedRow {
                    count: 1,
                    ..row(
                        Destination::checked_name(&format!("h{index}.example.com")),
                        Transport::Dns,
                        RefusalReason::NameNotAllowed,
                    )
                }],
                dropped: 0,
            },
            index,
        );
    }
    let snapshot = log.snapshot();
    assert_eq!(snapshot.records.len(), 1_000);
    assert_eq!(snapshot.dropped, 100);
    assert_eq!(snapshot.refused, 1_100);
    assert_eq!(
        snapshot.records[0].destination,
        Destination::Name("h1099.example.com".to_owned())
    );
}
