#!/usr/bin/env python3
"""Hostile-guest network probes, run as root inside a local VM's workload (#2615).

Each case tries one way out of the guest's network boundary and prints one JSON
line: {"case": ..., "outcome": ..., "detail": ...}. The host harness
(test-local-vm-hostile-guest-macos.py) judges the outcomes; this program only
observes, with a short timeout per attempt. Standard library only, so it also
runs in a plain python image inside the VM's Docker.

  hostile-guest-probe.py [--host-address IP]... [--skip-vsock]

`--host-address` adds an address of the host or its network (its LAN address,
the default gateway) to the protected-destination cases. The network's public
address is found from inside the guest through an allowed HTTPS request and is
never printed.
"""
import argparse
import errno
import json
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request

TIMEOUT = 4.0
# Protected destinations: every class the egress policy must refuse.
PROTECTED = ("10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254",
             "192.0.2.1", "198.18.0.1")
# Public destinations on ports the developer baseline does not allow.
DENIED_PORTS = (("8.8.8.8", 853), ("1.1.1.1", 25), ("1.1.1.1", 8080), ("1.1.1.1", 3389))
# The guest's own vsock listeners and the host ports a guest may dial.
GUEST_VSOCK_PORTS = (7775, 7777)
HOST_VSOCK_PORTS = (22, 80, 443, 1024, 2049, 7775, 7776, 7777, 7778, 7779, 8080)
VMADDR_CID_LOCAL, VMADDR_CID_HOST = 1, 2


def emit(case, outcome, detail=""):
    print(json.dumps({"case": case, "outcome": outcome, "detail": str(detail)[:200]}), flush=True)


def error_name(error):
    return errno.errorcode.get(error.errno, type(error).__name__) if isinstance(error, OSError) \
        else type(error).__name__


def tcp(case, host, port, family=socket.AF_INET):
    """connected, refused (RST), timeout (silent drop) or the error's name."""
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((host, port))
            emit(case, "connected")
    except socket.timeout:
        emit(case, "timeout")
    except ConnectionRefusedError:
        emit(case, "refused")
    except OSError as error:
        emit(case, error_name(error))


def udp(case, host, port, payload):
    """reply or no-reply within the timeout, or the error's name."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendto(payload, (host, port))
            sock.recvfrom(4096)
            emit(case, "reply")
    except socket.timeout:
        emit(case, "no-reply")
    except OSError as error:
        emit(case, error_name(error))


def dns_query(name):
    """A minimal A query for `name`."""
    header = struct.pack(">HHHHHH", 0x2615, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return header + question + struct.pack(">HH", 1, 1)


def resolve(case, name):
    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(name, 443, socket.AF_INET)})
        emit(case, "resolved", " ".join(addresses))
    except socket.gaierror as error:
        emit(case, "unresolved", error.args[-1] if error.args else "")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    return ~(total + (total >> 16)) & 0xFFFF


def icmp_echo(ident):
    body = struct.pack(">BBHHH", 8, 0, 0, ident, 1) + b"hostile"
    return body[:2] + struct.pack(">H", checksum(body)) + body[4:]


def ipv4(source, destination, protocol, payload, ident=0x2615, flags_fragment=0, options=b""):
    """An IPv4 packet for an IP_HDRINCL raw socket (the kernel fills length and checksum)."""
    words = 5 + len(options) // 4
    return struct.pack(">BBHHHBBH4s4s", 0x40 | words, 0, 0, ident, flags_fragment, 64, protocol, 0,
                       socket.inet_aton(source), socket.inet_aton(destination)) + options + payload


def raw_icmp():
    """A raw socket is denied to the workload; Docker grants containers CAP_NET_RAW, so
    there the question is whether anything sent on one gets out."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as error:
        emit("raw-icmp-socket", error_name(error))
        return False
    emit("raw-icmp-socket", "created")
    with sock:
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(icmp_echo(0x2616), ("1.1.1.1", 0))
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                packet, peer = sock.recvfrom(4096)
                if peer[0] == "1.1.1.1" and packet[20:21] == b"\0":
                    emit("raw-icmp-echo-1.1.1.1", "reply")
                    return True
            emit("raw-icmp-echo-1.1.1.1", "no-reply")
        except socket.timeout:
            emit("raw-icmp-echo-1.1.1.1", "no-reply")
        except OSError as error:
            emit("raw-icmp-echo-1.1.1.1", error_name(error))
    return True


def raw_burst():
    """Crafted packets toward the network worker: fragments, spoofed sources, IP options
    and odd TCP flags. Only the controls afterwards are judged."""
    sent = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except OSError as error:
        emit("raw-crafted-burst", error_name(error))
        return
    tcp_syn_fin = struct.pack(">HHIIBBHHH", 40000, 443, 1, 0, 0x50, 0x03, 1024, 0, 0)
    tcp_null = struct.pack(">HHIIBBHHH", 40001, 443, 1, 0, 0x50, 0x00, 1024, 0, 0)
    udp_dns = struct.pack(">HHHH", 40002, 53, 8 + 12, 0) + b"\x26\x15" + b"\0" * 10
    with sock:
        for n in range(200):
            for packet, destination in (
                    (ipv4("10.0.0.5", "1.1.1.1", 6, tcp_syn_fin, ident=n), "1.1.1.1"),
                    (ipv4("0.0.0.0", "1.1.1.1", 6, tcp_null, ident=n), "1.1.1.1"),
                    (ipv4("0.0.0.0", "1.1.1.1", 1, icmp_echo(n)[:4], ident=n, flags_fragment=0x2000), "1.1.1.1"),
                    (ipv4("0.0.0.0", "1.1.1.1", 1, b"\0" * 8, ident=n, flags_fragment=0x0001), "1.1.1.1"),
                    (ipv4("0.0.0.0", "192.0.2.1", 17, udp_dns, ident=n, options=b"\x07\x07\x04" + b"\0" * 5),
                     "192.0.2.1"),
                    (ipv4("169.254.169.254", "192.0.2.1", 17, udp_dns, ident=n), "192.0.2.1")):
                try:
                    sock.sendto(packet, (destination, 0))
                    sent += 1
                except OSError:
                    pass
    emit("raw-crafted-burst", "sent", sent)


def dns_burst():
    """Malformed questions to the guest resolver address, which the worker parses itself."""
    shapes = [
        b"",
        b"\x26",
        b"\x26\x15\x01\x00",
        struct.pack(">HHHHHH", 1, 0x0100, 0xFFFF, 0, 0, 0),
        struct.pack(">HHHHHH", 2, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1),
        struct.pack(">HHHHHH", 3, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"a" * 63 + b"\x3f" + b"b" * 63 + b"\x3f",
        struct.pack(">HHHHHH", 4, 0x8180, 1, 1, 0, 0) + dns_query("example.com")[12:],
        struct.pack(">HHHHHH", 5, 0x0100, 1, 0, 0, 5) + dns_query("example.com")[12:] + b"\0" * 64,
        dns_query("example.com") + b"\xff" * 1200,
        os.urandom(512),
    ]
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(30):
            for shape in shapes:
                try:
                    sock.sendto(shape, ("192.0.2.1", 53))
                    sent += 1
                except OSError:
                    pass
    emit("dns-malformed-burst", "sent", sent)


def connect_burst():
    """Many parallel connects to an allowed destination, then all closed."""
    sockets, refused = [], 0
    for _ in range(300):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            sock.connect(("1.1.1.1", 443))
        except BlockingIOError:
            pass
        except OSError:
            refused += 1
        sockets.append(sock)
    time.sleep(3)
    for sock in sockets:
        sock.close()
    emit("tcp-connect-burst", "opened", f"{len(sockets)} sockets, {refused} failed at once")


def http_head(case, host, port=80):
    """An HTTP request over TCP that must be answered end to end, not just accepted
    by the worker's local handshake."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = sock.recv(64)
            emit(case, "answered" if data.startswith(b"HTTP/") else "no-http", data[:12])
    except socket.timeout:
        emit(case, "timeout")
    except OSError as error:
        emit(case, error_name(error))


def tls(case, host, server_name):
    try:
        context = ssl.create_default_context()
        if server_name is None:
            context.check_hostname = False
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as sock:
                emit(case, "handshake", sock.version())
    except socket.timeout:
        emit(case, "timeout")
    except (OSError, ssl.SSLError) as error:
        emit(case, error_name(error), error)


def while_dial_pends():
    """TLS and DNS must keep working while another connection's dial hangs: TCP to an
    allowed port where nothing answers completes the worker's local handshake, then
    waits on the broker's dial (#2638)."""
    pending = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pending.settimeout(TIMEOUT)
    try:
        pending.connect(("1.1.1.1", 22))
    except OSError:
        pass
    time.sleep(0.5)
    tls("concurrency-tls-while-dial-pends", "1.1.1.1", "one.one.one.one")
    resolve("concurrency-dns-while-dial-pends", "example.com")
    pending.close()


def controls(label):
    """The allowed controls again after a burst. A lookup may stall while the worker
    drains the burst; record how long it took to answer again, up to 10 s."""
    started = time.monotonic()
    while True:
        try:
            socket.getaddrinfo("example.com", 443, socket.AF_INET)
            emit(f"control-after-{label}-dns", "resolved", f"{time.monotonic() - started:.1f}")
            break
        except socket.gaierror:
            if time.monotonic() - started > 10:
                emit(f"control-after-{label}-dns", "unresolved", f"{time.monotonic() - started:.1f}")
                break
            time.sleep(0.5)
    http_head(f"control-after-{label}-http", "1.1.1.1")


def ping_socket():
    """An unprivileged ICMP echo (ping socket) to a public address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as error:
        emit("ping-socket-1.1.1.1", error_name(error))
        return
    with sock:
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(struct.pack(">BBHHH", 8, 0, 0, 0x2615, 1) + b"hostile", ("1.1.1.1", 0))
            sock.recvfrom(4096)
            emit("ping-socket-1.1.1.1", "reply")
        except socket.timeout:
            emit("ping-socket-1.1.1.1", "no-reply")
        except OSError as error:
            emit("ping-socket-1.1.1.1", error_name(error))


def interfaces():
    names = sorted(os.listdir("/sys/class/net"))
    emit("interfaces", " ".join(names))
    for case, command in (("ip-link-add", ["ip", "link", "add", "cwhostile0", "type", "dummy"]),
                          ("ip-route-add", ["ip", "route", "add", "203.0.113.0/24", "dev", "lo"]),
                          ("ip-addr-add", ["ip", "addr", "add", "10.99.0.1/24", "dev", "lo"])):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            emit(case, "ok" if result.returncode == 0 else "failed", result.stderr.strip())
        except FileNotFoundError:
            emit(case, "no-ip-tool")


def public_address():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=10) as response:
            return response.read().decode().strip()
    except OSError:
        return None


def vsock():
    family = getattr(socket, "AF_VSOCK", None)
    try:
        socket.socket(family, socket.SOCK_STREAM).close()
    except (OSError, TypeError) as error:
        emit("vsock-socket", error_name(error) if isinstance(error, OSError) else "unsupported")
        return
    emit("vsock-socket", "created")

    def dial(case, cid, port):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((cid, port))
                # A listener that authenticates closes on garbage; one that
                # serves an unauthenticated peer answers or keeps reading.
                sock.sendall(b"\0" * 64 + b"hostile-guest\n")
                try:
                    data = sock.recv(256)
                    emit(case, "connected", f"answered {len(data)} bytes" if data else "closed by peer")
                except socket.timeout:
                    emit(case, "connected", "silent")
                except OSError as error:
                    emit(case, "connected", f"then {error_name(error)}")
        except socket.timeout:
            emit(case, "timeout")
        except ConnectionRefusedError:
            emit(case, "refused")
        except OSError as error:
            emit(case, error_name(error))

    for port in HOST_VSOCK_PORTS:
        dial(f"vsock-host-{port}", VMADDR_CID_HOST, port)
    for port in GUEST_VSOCK_PORTS:
        dial(f"vsock-local-{port}", VMADDR_CID_LOCAL, port)
    for port in GUEST_VSOCK_PORTS:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.bind((socket.VMADDR_CID_ANY, port))
                emit(f"vsock-bind-{port}", "bound")
        except OSError as error:
            emit(f"vsock-bind-{port}", error_name(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host-address", action="append", default=[])
    parser.add_argument("--skip-vsock", action="store_true")
    args = parser.parse_args()
    started = time.monotonic()

    # Controls: the battery means nothing unless allowed traffic works.
    resolve("control-dns-example.com", "example.com")
    tcp("control-tcp-1.1.1.1-443", "1.1.1.1", 443)
    http_head("control-http-1.1.1.1-80", "1.1.1.1")
    tls("control-tls-1.1.1.1", "1.1.1.1", "one.one.one.one")
    try:
        with urllib.request.urlopen("https://example.com", timeout=10) as response:
            emit("control-https-example.com", "status", response.status)
    except OSError as error:
        emit("control-https-example.com", error_name(error))

    raw = raw_icmp()
    ping_socket()
    udp("udp-8.8.8.8-53", "8.8.8.8", 53, dns_query("example.com"))
    udp("udp-1.1.1.1-123", "1.1.1.1", 123, b"\x1b" + b"\0" * 47)
    udp("udp-192.0.2.1-123", "192.0.2.1", 123, b"\x1b" + b"\0" * 47)
    udp("udp-192.0.2.1-5353", "192.0.2.1", 5353, dns_query("example.com"))
    tcp("tcp-192.0.2.1-53", "192.0.2.1", 53)
    for host, port in DENIED_PORTS:
        tcp(f"tcp-{host}-{port}", host, port)
    for host in PROTECTED + tuple(args.host_address):
        for port in (22, 80, 443):
            tcp(f"tcp-protected-{host}-{port}", host, port)
    public = public_address()
    if public is None:
        emit("tcp-public-address", "unknown", "the public address lookup failed")
    else:
        for port in (22, 80, 443):
            tcp(f"tcp-public-address-{port}", public, port)
    tcp("tcp6-2606:4700:4700::1111-443", "2606:4700:4700::1111", 443, socket.AF_INET6)
    tcp("tcp6-mapped-10.0.0.1-80", "::ffff:10.0.0.1", 80, socket.AF_INET6)
    resolve("dns-private-answer-10.0.0.1.nip.io", "10.0.0.1.nip.io")
    resolve("dns-loopback-answer-localtest.me", "localtest.me")
    resolve("dns-metadata-answer-169.254.169.254.nip.io", "169.254.169.254.nip.io")
    # Allowed by the v1 policy, recorded for the record: an allowed port to a
    # public address with nothing listening, and DNS over HTTPS.
    tls("info-tls-1.1.1.1-no-sni", "1.1.1.1", None)
    try:
        request = urllib.request.Request("https://1.1.1.1/dns-query?name=example.com&type=A",
                                         headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            emit("info-doh-1.1.1.1", "status", response.status)
    except urllib.error.HTTPError as error:
        emit("info-doh-1.1.1.1", "status", error.code)
    except OSError as error:
        emit("info-doh-1.1.1.1", error_name(error), getattr(error, "reason", ""))
    while_dial_pends()
    interfaces()
    if not args.skip_vsock:
        vsock()
    dns_burst()
    controls("dns-burst")
    connect_burst()
    controls("connect-burst")
    if raw:
        raw_burst()
        controls("raw-burst")
    emit("done", "ok", f"{time.monotonic() - started:.1f} s")


if __name__ == "__main__":
    main()
