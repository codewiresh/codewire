//! DNS questions come from the guest. Parsing never panics, and every answer
//! to a question it accepts either builds or is refused with an error.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use codewire_netstack::{DnsAnswer, build_ipv4_dns_response, parse_ipv4_dns_question};
use libfuzzer_sys::fuzz_target;

// The local VM's resolver address and message limit.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const MESSAGE_LIMIT: usize = 1_232;
const MTU: usize = 1_280;

fuzz_target!(|packet: &[u8]| {
    let Ok(question) = parse_ipv4_dns_question(packet, RESOLVER, MESSAGE_LIMIT) else {
        return;
    };
    for answer in [
        DnsAnswer::Ipv4(Ipv4Addr::new(203, 0, 113, 7)),
        DnsAnswer::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
        DnsAnswer::NoData,
        DnsAnswer::NameError,
        DnsAnswer::ServerFailure,
    ] {
        if let Ok(response) = build_ipv4_dns_response(&question, answer, 60, MTU) {
            assert!(response.len() <= MTU, "a response fits the MTU");
        }
    }
});
