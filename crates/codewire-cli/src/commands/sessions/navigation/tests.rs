use super::*;

/// What one fresh decoder makes of `input`: the action, if any, and the bytes
/// it forwards to the session.
fn decode(input: &[u8]) -> (Option<AttachExit>, Vec<u8>) {
    AttachNavigationDecoder::default().feed(input)
}

#[test]
fn ctrl_b_starts_the_prefix_in_both_forms() {
    let cases: [(&[u8], Option<AttachExit>, &[u8]); 9] = [
        // Without the kitty keyboard protocol.
        (b"\x02d", Some(AttachExit::Detached), b""),
        (b"\x02h", Some(AttachExit::PreviousSession), b""),
        (b"\x02b", None, b"\x02"),
        (b"\x02x", None, b"\x02x"),
        // With it: the press alone, the press with its event, then the
        // release before the key, and with Caps Lock on.
        (b"\x1b[98;5ud", Some(AttachExit::Detached), b""),
        (
            b"\x1b[98;5:1u\x1b[98;5:3ud",
            Some(AttachExit::Detached),
            b"",
        ),
        (b"\x1b[98;69ul", Some(AttachExit::NextSession), b""),
        // A repeat counts as a press.
        (b"\x1b[98;5:2uj", Some(AttachExit::NextEnvironment), b""),
        // Ctrl+Shift+B is another key.
        (b"\x1b[98;6u", None, b"\x1b[98;6u"),
    ];
    for (input, action, forwarded) in cases {
        assert_eq!(
            decode(input),
            (action, forwarded.to_vec()),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn an_unused_kitty_prefix_reaches_the_session_as_it_came() {
    // `b` sends one Ctrl-B, in the form the terminal used.
    assert_eq!(decode(b"\x1b[98;5ub"), (None, b"\x1b[98;5u".to_vec()));
    // Another key after it: both, unchanged, a kitty key included.
    assert_eq!(
        decode(b"\x1b[98;5u\x1b[100;5u"),
        (None, b"\x1b[98;5u\x1b[100;5u".to_vec())
    );
    assert_eq!(decode(b"\x1b[98;5uq"), (None, b"\x1b[98;5uq".to_vec()));
    // Left pending when the input ends.
    let mut decoder = AttachNavigationDecoder::default();
    assert_eq!(decoder.feed(b"\x1b[98;5:1u"), (None, Vec::new()));
    assert_eq!(decoder.finish(), b"\x1b[98;5:1u".to_vec());
    assert_eq!(decoder.finish(), Vec::<u8>::new());
}

#[test]
fn a_ctrl_b_release_alone_is_dropped() {
    assert_eq!(decode(b"\x1b[98;5:3u"), (None, Vec::new()));
    assert_eq!(decode(b"a\x1b[98;5:3ub"), (None, b"ab".to_vec()));
}

#[test]
fn the_prefix_and_its_key_may_come_in_separate_reads() {
    let mut decoder = AttachNavigationDecoder::default();
    assert_eq!(decoder.feed(b"\x1b[98;5:1u"), (None, Vec::new()));
    assert_eq!(decoder.feed(b"\x1b[98;5:3u"), (None, Vec::new()));
    assert_eq!(decoder.feed(b"d"), (Some(AttachExit::Detached), Vec::new()));
}

#[test]
fn other_sequences_pass_through_byte_for_byte() {
    let cases: [&[u8]; 7] = [
        // An SGR mouse report.
        b"\x1b[<0;98;5M",
        // Bracketed paste around text that looks like a key.
        b"\x1b[200~98;5u\x1b[201~",
        // Cursor keys, another kitty key, and a lone Escape.
        b"\x1b[A\x1b[1;5C",
        b"\x1b[100;5u",
        b"\x1b",
        // `CSI u` with no parameters isn't a key.
        b"\x1b[u",
        // An unfinished sequence.
        b"\x1b[98;5",
    ];
    for input in cases {
        assert_eq!(
            decode(input),
            (None, input.to_vec()),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn a_plain_shell_forwards_every_key() {
    let mut decoder = AttachNavigationDecoder::new(true);
    for input in [b"\x02d".as_slice(), b"\x1b[98;5ud", b"\x1b[98;5:3u"] {
        assert_eq!(decoder.feed(input), (None, input.to_vec()));
    }
    assert_eq!(decoder.finish(), Vec::<u8>::new());
}
