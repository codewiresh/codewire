//! A UDP relay packet comes from any host that can reach the relay's socket.
//! Decoding never panics, and every packet it accepts encodes back to one that
//! decodes the same.
#![no_main]

use codewire_tailnet::udp_relay::{
    RelayPacket, decode_packet, encode_control_packet, encode_data_packet, encode_disco_packet,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|packet: &[u8]| {
    let Ok(decoded) = decode_packet(packet) else {
        return;
    };
    let encoded = match decoded {
        RelayPacket::Control { vni, payload } => encode_control_packet(vni, payload),
        RelayPacket::Disco { vni, payload } => encode_disco_packet(vni, payload),
        RelayPacket::Data { vni, payload } => encode_data_packet(vni, payload),
    };
    assert_eq!(
        decode_packet(&encoded).expect("an encoded packet decodes"),
        decoded
    );
});
