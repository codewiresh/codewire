//! `mailto:` links with a subject. The address and subject are
//! percent-encoded, so no character in either can add a recipient or a header.

pub(crate) fn mailto(address: &str, subject: &str) -> String {
    format!(
        "mailto:{}?subject={}",
        encode(address, b"@.-_+"),
        encode(subject, b"-_.~")
    )
}

/// Keeps ASCII letters, digits and `keep`; percent-encodes every other byte.
fn encode(value: &str, keep: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || keep.contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::mailto;

    #[test]
    fn the_address_and_subject_are_encoded() {
        assert_eq!(
            mailto("support@codewire.sh", "[Support]"),
            "mailto:support@codewire.sh?subject=%5BSupport%5D"
        );
        assert_eq!(
            mailto("ada+cw@example.test", "Re: your Codewire feedback"),
            "mailto:ada+cw@example.test?subject=Re%3A%20your%20Codewire%20feedback"
        );
    }

    #[test]
    fn a_crafted_address_cannot_add_a_header_or_a_recipient() {
        assert_eq!(
            mailto("a@b.test?bcc=c@d.test&body=x y", "s"),
            "mailto:a@b.test%3Fbcc%3Dc@d.test%26body%3Dx%20y?subject=s"
        );
    }
}
