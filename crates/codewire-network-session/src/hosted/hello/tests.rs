use super::*;

fn hello(version: u16, token: &str) -> GuestHello {
    GuestHello {
        version,
        token: Zeroizing::new(token.to_owned()),
        nonce: [7; NONCE_LEN],
    }
}

/// Decodes `bytes` the way cw-egress reads a stream: the prefix, the token's
/// length, then the body.
fn decode(bytes: &[u8]) -> Result<GuestHello, HelloError> {
    let (prefix, rest) = bytes.split_at(PREFIX_LEN);
    let version = decode_prefix(prefix.try_into().unwrap())?;
    let (length, body) = rest.split_at(TOKEN_LEN_LEN);
    assert_eq!(body_len(length.try_into().unwrap())?, body.len());
    decode_body(version, body)
}

/// Every session version a released daemon has sent, oldest first, each with
/// the hello it sends for the token `a.b.c` and the nonce `[7; 32]`. A new
/// session version appends its row; a row never changes or goes.
const SHIPPED: &[(u16, &[u8])] = &[(
    2,
    b"CWEGRS01\x02\x00\x05\x00a.b.c\
      \x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\
      \x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07",
)];

#[test]
fn cw_egress_accepts_the_current_and_the_previous_shipped_session_version() {
    let (current, _) = SHIPPED[SHIPPED.len() - 1];
    assert_eq!(
        current, NETWORK_PROTOCOL_VERSION,
        "the newest row is today's version"
    );
    assert_eq!(*ACCEPTED_VERSIONS.end(), current);
    for &(version, bytes) in SHIPPED.iter().rev().take(2) {
        assert!(ACCEPTED_VERSIONS.contains(&version), "version {version}");
        let decoded = decode(bytes).unwrap();
        assert_eq!(decoded.version, version);
        assert_eq!(decoded.token.as_str(), "a.b.c");
        assert_eq!(decoded.nonce, [7; NONCE_LEN]);
    }
    // The current daemon sends exactly the pinned bytes.
    assert_eq!(
        hello(current, "a.b.c").encode().unwrap(),
        SHIPPED[SHIPPED.len() - 1].1
    );
}

#[test]
fn a_version_outside_the_accepted_range_is_refused_from_the_prefix_alone() {
    let below = ACCEPTED_VERSIONS.start().checked_sub(1);
    let above = ACCEPTED_VERSIONS.end().checked_add(1);
    for version in [Some(0), below, above, Some(u16::MAX)]
        .into_iter()
        .flatten()
    {
        let mut prefix = [0_u8; PREFIX_LEN];
        prefix[..MAGIC.len()].copy_from_slice(&MAGIC);
        prefix[MAGIC.len()..].copy_from_slice(&version.to_le_bytes());
        assert_eq!(decode_prefix(&prefix), Err(HelloError::Version(version)));
    }
}

#[test]
fn the_version_answer_is_one_constant_naming_the_accepted_range() {
    let lowest = ACCEPTED_VERSIONS.start().to_le_bytes();
    let highest = ACCEPTED_VERSIONS.end().to_le_bytes();
    let mut expected = b"CWEGRSV\0".to_vec();
    expected.extend_from_slice(&lowest);
    expected.extend_from_slice(&highest);
    assert_eq!(VERSION_ANSWER.as_slice(), expected.as_slice());
    assert_eq!(VERSION_ANSWER_LEN, 12);

    let (magic, tail) = VERSION_ANSWER.split_at(ANSWER_MAGIC_LEN);
    let magic: &[u8; ANSWER_MAGIC_LEN] = magic.try_into().unwrap();
    assert_eq!(answer_tail_len(magic), Ok(4));
    assert_eq!(
        decode_answer(magic, tail),
        Ok(Answer::VersionRefused {
            lowest: *ACCEPTED_VERSIONS.start(),
            highest: *ACCEPTED_VERSIONS.end(),
        })
    );
}

#[test]
fn the_admitted_answer_round_trips_and_a_wrong_magic_is_refused() {
    let answer = encode_answer(&[9; NONCE_LEN]);
    let (magic, tail) = answer.split_at(ANSWER_MAGIC_LEN);
    let magic: &[u8; ANSWER_MAGIC_LEN] = magic.try_into().unwrap();
    assert_eq!(answer_tail_len(magic), Ok(NONCE_LEN));
    assert_eq!(
        decode_answer(magic, tail),
        Ok(Answer::Admitted {
            nonce: [9; NONCE_LEN]
        })
    );
    assert_eq!(
        decode_answer(magic, &tail[..4]),
        Err(HelloError::Length {
            actual: 4,
            expected: NONCE_LEN
        })
    );
    let mut wrong = *magic;
    wrong[0] ^= 1;
    assert_eq!(answer_tail_len(&wrong), Err(HelloError::Magic));
}

#[test]
fn a_stream_that_is_not_an_egress_hello_is_refused_before_the_token_is_read() {
    let mut prefix = [0_u8; PREFIX_LEN];
    prefix[..4].copy_from_slice(b"GET ");
    assert_eq!(decode_prefix(&prefix), Err(HelloError::Magic));
}

#[test]
fn an_empty_or_oversized_token_is_refused_from_its_length() {
    assert_eq!(body_len(&[0, 0]), Err(HelloError::TokenLength(0)));
    let over = u16::try_from(MAX_TOKEN_LEN + 1).unwrap();
    assert_eq!(
        body_len(&over.to_le_bytes()),
        Err(HelloError::TokenLength(MAX_TOKEN_LEN + 1))
    );
    assert!(hello(NETWORK_PROTOCOL_VERSION, "").encode().is_err());
}
