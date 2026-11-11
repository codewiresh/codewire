//! A disco message's plaintext comes from a peer: authenticated, not trusted.
//! Parsing never panics, and every version 0 message it accepts marshals to
//! bytes that parse as the same kind of message.
//!
//! Field values are not compared: the parser is deliberately lax, as upstream
//! Tailscale's is, and marshal writes the canonical form. A ping's 32 bytes
//! after its transaction ID read as a node key, and a zero key means none, so
//! a keyless ping with 32 or more padding bytes comes back with a zero key and
//! less padding. A later version parses to a placeholder for forward
//! compatibility, which is never sent on.
#![no_main]

use std::mem::discriminant;

use codewire_tailnet::disco::Message;
use libfuzzer_sys::fuzz_target;

// The second header byte is the version; marshal always writes version 0.
const VERSION_0: u8 = 0;

fuzz_target!(|payload: &[u8]| {
    let Ok(message) = Message::parse(payload) else {
        return;
    };
    if payload[1] != VERSION_0 {
        return;
    }
    let reparsed = Message::parse(&message.marshal()).expect("a marshalled message parses");
    assert_eq!(discriminant(&reparsed), discriminant(&message));
});
