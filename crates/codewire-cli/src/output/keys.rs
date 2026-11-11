//! Decodes raw-mode terminal input into the keys the picker understands.

const ESC: u8 = 0x1b;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Enter,
    Escape,
    Backspace,
    CtrlC,
    /// In raw mode Ctrl-D is a byte rather than an EOF. Menus cancel on it,
    /// as on a closed input stream; the feedback editor sends.
    CtrlD,
    CtrlU,
    Char(char),
    /// Anything else, such as another escape sequence; ignored.
    Other,
}

enum Decoded {
    Key(Key, usize),
    /// The bytes end inside a sequence that more input could complete.
    Incomplete,
}

/// Decodes one complete read. A trailing lone ESC is the Escape key; any
/// other unfinished sequence at the end is [`Key::Other`]. Callers wait
/// briefly for more input first while [`needs_more_input`] says so.
pub(crate) fn decode_keys(bytes: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        match decode_one(rest) {
            Decoded::Key(key, used) => {
                keys.push(key);
                rest = &rest[used..];
            }
            Decoded::Incomplete => {
                keys.push(if rest == [ESC] {
                    Key::Escape
                } else {
                    Key::Other
                });
                break;
            }
        }
    }
    keys
}

/// The bytes end inside an escape sequence or a multi-byte character, so a
/// short wait could complete it (a lone ESC may begin an arrow key).
pub(crate) fn needs_more_input(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    while !rest.is_empty() {
        match decode_one(rest) {
            Decoded::Key(_, used) => rest = &rest[used..],
            Decoded::Incomplete => return true,
        }
    }
    false
}

fn decode_one(bytes: &[u8]) -> Decoded {
    match bytes[0] {
        ESC => decode_escape(bytes),
        b'\r' if bytes.get(1) == Some(&b'\n') => Decoded::Key(Key::Enter, 2),
        b'\r' | b'\n' => Decoded::Key(Key::Enter, 1),
        0x7f | 0x08 => Decoded::Key(Key::Backspace, 1),
        0x03 => Decoded::Key(Key::CtrlC, 1),
        0x04 => Decoded::Key(Key::CtrlD, 1),
        0x15 => Decoded::Key(Key::CtrlU, 1),
        byte if byte < 0x20 => Decoded::Key(Key::Other, 1),
        byte if byte < 0x80 => Decoded::Key(Key::Char(char::from(byte)), 1),
        _ => decode_utf8(bytes),
    }
}

fn decode_escape(bytes: &[u8]) -> Decoded {
    match bytes.get(1) {
        None => Decoded::Incomplete,
        // CSI: parameter and intermediate bytes, then one final byte.
        Some(b'[') => {
            let body = bytes[2..]
                .iter()
                .take_while(|byte| (0x20..=0x3f).contains(*byte))
                .count();
            match bytes.get(2 + body) {
                None => Decoded::Incomplete,
                Some(&last) if (0x40..=0x7e).contains(&last) => {
                    let key = match last {
                        b'A' => Key::Up,
                        b'B' => Key::Down,
                        _ => Key::Other,
                    };
                    Decoded::Key(key, 3 + body)
                }
                // Malformed: drop the introducer and decode what follows.
                Some(_) => Decoded::Key(Key::Other, 2 + body),
            }
        }
        // SS3: application cursor keys.
        Some(b'O') => match bytes.get(2) {
            None => Decoded::Incomplete,
            Some(b'A') => Decoded::Key(Key::Up, 3),
            Some(b'B') => Decoded::Key(Key::Down, 3),
            Some(_) => Decoded::Key(Key::Other, 3),
        },
        // ESC ESC: the first is the Escape key.
        Some(&ESC) => Decoded::Key(Key::Escape, 1),
        // ESC with another key is an Alt chord, which the picker ignores.
        Some(_) => match decode_one(&bytes[1..]) {
            Decoded::Key(_, used) => Decoded::Key(Key::Other, used + 1),
            Decoded::Incomplete => Decoded::Incomplete,
        },
    }
}

fn decode_utf8(bytes: &[u8]) -> Decoded {
    let width = match bytes[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Decoded::Key(Key::Other, 1),
    };
    if bytes.len() < width {
        return if bytes[1..].iter().all(|byte| byte & 0xc0 == 0x80) {
            Decoded::Incomplete
        } else {
            Decoded::Key(Key::Other, 1)
        };
    }
    match std::str::from_utf8(&bytes[..width])
        .ok()
        .and_then(|text| text.chars().next())
    {
        Some(c) if !c.is_control() => Decoded::Key(Key::Char(c), width),
        Some(_) => Decoded::Key(Key::Other, width),
        None => Decoded::Key(Key::Other, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrows_decode_in_csi_and_ss3_forms() {
        assert_eq!(decode_keys(b"\x1b[A\x1b[B"), [Key::Up, Key::Down]);
        assert_eq!(decode_keys(b"\x1bOA\x1bOB"), [Key::Up, Key::Down]);
        assert_eq!(decode_keys(b"\x1b[1;5A"), [Key::Up]);
        assert_eq!(decode_keys(b"\x1b[C\x1b[3~\x1bOP"), [Key::Other; 3]);
        assert_eq!(
            decode_keys(b"\x1b[\x03A"),
            [Key::Other, Key::CtrlC, Key::Char('A')]
        );
    }

    #[test]
    fn enter_backspace_and_control_keys() {
        assert_eq!(decode_keys(b"\r"), [Key::Enter]);
        assert_eq!(decode_keys(b"\n"), [Key::Enter]);
        assert_eq!(decode_keys(b"\r\n"), [Key::Enter]);
        assert_eq!(decode_keys(b"\x7f\x08"), [Key::Backspace, Key::Backspace]);
        assert_eq!(decode_keys(b"\x03"), [Key::CtrlC]);
        assert_eq!(decode_keys(b"\x04"), [Key::CtrlD]);
        assert_eq!(decode_keys(b"\x15"), [Key::CtrlU]);
        assert_eq!(decode_keys(b"\x01\t"), [Key::Other, Key::Other]);
    }

    #[test]
    fn lone_escape_is_escape_and_waits_for_more_first() {
        assert_eq!(decode_keys(b"\x1b"), [Key::Escape]);
        assert!(needs_more_input(b"\x1b"));
        assert_eq!(decode_keys(b"a\x1b"), [Key::Char('a'), Key::Escape]);
        assert_eq!(decode_keys(b"\x1b\x1b"), [Key::Escape, Key::Escape]);
        assert_eq!(decode_keys(b"\x1b\x1b[A"), [Key::Escape, Key::Up]);
        assert!(!needs_more_input(b"\x1b[A"));
        assert!(!needs_more_input(b"abc"));
        assert!(!needs_more_input(b""));
    }

    #[test]
    fn unfinished_sequences_wait_then_are_ignored() {
        for partial in [
            &b"\x1b["[..],
            b"\x1b[1;5",
            b"\x1bO",
            b"\xc3",
            b"\xe2\x86",
            b"x\xf0\x9f\x98",
        ] {
            assert!(needs_more_input(partial), "{partial:?}");
            assert_eq!(
                decode_keys(partial).last(),
                Some(&Key::Other),
                "{partial:?}"
            );
        }
        assert_eq!(decode_keys(b"\x1b[1;5"), [Key::Other]);
    }

    #[test]
    fn alt_chords_are_ignored() {
        assert_eq!(decode_keys(b"\x1bx"), [Key::Other]);
        assert_eq!(decode_keys(b"\x1b\xc3\xa9a"), [Key::Other, Key::Char('a')]);
    }

    #[test]
    fn printable_text_including_multi_byte_characters() {
        assert_eq!(
            decode_keys("ab é→😀".as_bytes()),
            [
                Key::Char('a'),
                Key::Char('b'),
                Key::Char(' '),
                Key::Char('é'),
                Key::Char('→'),
                Key::Char('😀'),
            ]
        );
    }

    #[test]
    fn invalid_and_control_bytes_are_ignored() {
        assert_eq!(
            decode_keys(b"\xff\x80a"),
            [Key::Other, Key::Other, Key::Char('a')]
        );
        assert_eq!(decode_keys(b"\xc3a"), [Key::Other, Key::Char('a')]);
        // U+009B is a C1 control (single-byte CSI).
        assert_eq!(decode_keys("\u{9b}".as_bytes()), [Key::Other]);
        assert_eq!(
            decode_keys(b"\xed\xa0\x80"),
            [Key::Other, Key::Other, Key::Other]
        );
    }
}
