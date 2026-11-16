#!/usr/bin/env python3
"""Write protocol-v2.json, the network session's cross-language fixture.

It derives every value from the protocol's published construction, with no
code shared with codewire-network-session, so the crate's fixture test checks
its codec against an independent one. Run it after a protocol change and
commit the result:

    python3 testdata/local-vm-network/protocol-v2.py > testdata/local-vm-network/protocol-v2.json
"""

import hashlib
import hmac
import json
import sys
import uuid

TOKEN = "guest-network-test-token-0123456789abcdef"
VM_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
GENERATION = 7
NONCE = bytes(range(32))
PACKET_BOUND = 2048

GUEST_TO_HOST = 1
HOST_TO_GUEST = 2
FRAME_KIND_PACKET = 0
FRAME_KIND_CONTROL = 1
CONTROL_EGRESS_TRUST = 2


def tag(key, domain, *parts):
    mac = hmac.new(key, domain, hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


def frame(session_key, direction, sequence, kind, body):
    header = (
        b"CWNETF2\0"
        + sequence.to_bytes(8, "little")
        + len(body).to_bytes(2, "little")
        + bytes([kind, 0])
    )
    return header + body + tag(session_key, b"codewire-network-frame-v2\0", bytes([direction]), header, body)


def main():
    key = tag(
        TOKEN.encode(),
        b"codewire-network-key-v1\0",
        VM_ID.bytes,
        GENERATION.to_bytes(8, "little"),
    )
    bound = PACKET_BOUND.to_bytes(2, "little")
    hello = b"CWNETH2\0" + VM_ID.bytes + GENERATION.to_bytes(8, "little") + NONCE + bound
    hello += tag(key, b"codewire-network-host-hello-v2\0", hello)
    ack = b"CWNETA2\0" + NONCE + bound
    ack += tag(key, b"codewire-network-guest-ack-v2\0", ack)
    ready = b"CWNETR1\0" + NONCE
    ready += tag(key, b"codewire-network-host-ready-v1\0", ready)
    session_key = tag(key, b"codewire-network-session-v1\0", NONCE)
    fixture = {
        "token": TOKEN,
        "vm_id": str(VM_ID),
        "generation": GENERATION,
        "nonce_hex": NONCE.hex(),
        "packet_bound": PACKET_BOUND,
        "synthetic_hmac_fixture_hex": key.hex(),
        "host_hello_hex": hello.hex(),
        "guest_ack_hex": ack.hex(),
        "host_ready_hex": ready.hex(),
        "guest_packet_hex": frame(
            session_key, GUEST_TO_HOST, 1, FRAME_KIND_PACKET, b"synthetic-guest-packet"
        ).hex(),
        # The host's frame 1 is always its egress trust; a local VM's is none.
        "host_egress_trust_hex": frame(
            session_key, HOST_TO_GUEST, 1, FRAME_KIND_CONTROL, bytes([CONTROL_EGRESS_TRUST])
        ).hex(),
        "host_packet_hex": frame(
            session_key, HOST_TO_GUEST, 2, FRAME_KIND_PACKET, b"synthetic-host-packet"
        ).hex(),
    }
    json.dump(fixture, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
