//! Reports a terminal sends by itself, not for a key: mouse and focus events
//! (#5090). Typed during a drop, they describe a pointer and focus that have
//! moved by the time the keys go out, so the input stream drops them rather
//! than hold them where they would push real keys past its bound.

/// `keys` without the complete mouse and focus reports in it. A report cut
/// across two reads, or anything not recognised, stays as keys.
pub(super) fn without_reports(keys: &[u8]) -> Vec<u8> {
    let mut kept = Vec::with_capacity(keys.len());
    let mut at = 0;
    while at < keys.len() {
        match report_len(&keys[at..]) {
            Some(len) => at += len,
            None => {
                kept.push(keys[at]);
                at += 1;
            }
        }
    }
    kept
}

/// How many bytes of `keys` are not part of a complete report.
pub(super) fn key_count(keys: &[u8]) -> u64 {
    without_reports(keys).len() as u64
}

/// The length of the report `keys` starts with, if it starts with a complete
/// one: focus `ESC [ I` or `ESC [ O`, X10 mouse `ESC [ M` and three bytes,
/// or SGR mouse `ESC [ < digits ; digits ; digits` and `M` or `m`.
fn report_len(keys: &[u8]) -> Option<usize> {
    let rest = keys.strip_prefix(b"\x1b[")?;
    match rest.first()? {
        b'I' | b'O' => Some(3),
        // Each X10 byte is a value plus 32, so a control byte is not one.
        b'M' => rest
            .get(1..4)
            .is_some_and(|fields| fields.iter().all(|byte| *byte >= 0x20))
            .then_some(6),
        b'<' => sgr_mouse_len(&rest[1..]).map(|len| 3 + len),
        _ => None,
    }
}

/// The length of `digits ; digits ; digits` and `M` or `m` at the start of
/// `rest`.
fn sgr_mouse_len(rest: &[u8]) -> Option<usize> {
    let mut at = 0;
    for field in 0..3 {
        let digits = rest[at..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        at += digits;
        match (field, *rest.get(at)?) {
            (0 | 1, b';') => at += 1,
            (2, b'M' | b'm') => return Some(at + 1),
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_of_report_is_dropped() {
        for report in [
            b"\x1b[<35;120;40M".as_slice(),
            b"\x1b[<0;1;2m",
            b"\x1b[M #!",
            b"\x1b[I",
            b"\x1b[O",
        ] {
            assert_eq!(without_reports(report), b"", "{report:?}");
        }
    }

    #[test]
    fn keys_around_reports_are_kept_in_order() {
        assert_eq!(
            without_reports(b"a\x1b[<35;1;2Mb\x1b[Ic\x1b[M !!d\x1b[O"),
            b"abcd"
        );
        assert_eq!(key_count(b"ls\x1b[<35;1;2M\x1b[<35;1;3M\r"), 3);
    }

    #[test]
    fn an_incomplete_or_unknown_sequence_stays_as_keys() {
        for keys in [
            b"\x1b[<35;1;2".as_slice(), // the rest is in the next read
            b";2M",
            b"\x1b[<35;1M",   // two fields
            b"\x1b[<;1;2M",   // an empty field
            b"\x1b[<35;1;2x", // not M or m
            b"\x1b[M!",       // X10 with one byte of three
            b"\x1b[M\x1b[A",  // a control byte where X10 has a value
            b"\x1b[A",        // the up arrow
            b"\x1b",
            b"\x1b[",
        ] {
            assert_eq!(without_reports(keys), keys, "{keys:?}");
        }
    }
}
