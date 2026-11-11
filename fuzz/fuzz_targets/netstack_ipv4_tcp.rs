//! IPv4 TCP packets come from the guest. Parsing never panics; an initial SYN
//! is a canonical packet with the same flow, and its refusal can be built.
#![no_main]

use codewire_netstack::{
    build_ipv4_tcp_refusal, parse_canonical_ipv4_tcp_packet, parse_initial_ipv4_tcp_syn,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|packet: &[u8]| {
    let canonical = parse_canonical_ipv4_tcp_packet(packet);
    let Ok(syn) = parse_initial_ipv4_tcp_syn(packet) else {
        return;
    };
    let canonical = canonical.expect("an initial SYN is a canonical IPv4 TCP packet");
    assert!(canonical.initial_syn);
    assert_eq!(
        (canonical.source, canonical.destination),
        (syn.source, syn.destination)
    );
    build_ipv4_tcp_refusal(packet).expect("an initial SYN can be refused");
});
