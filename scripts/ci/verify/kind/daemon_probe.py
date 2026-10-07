#!/usr/bin/env python3
"""Managed Kind only: proxied Codex requests through the workspace daemon.

The caller pipes this file into the actual workspace's python3. Each request
crosses the daemon's loopback ingress and its long-lived bridge epoch, then
orchestration's credential relay and the broker, exactly as stock Codex's
proxy provider does. One bridge epoch serves many requests, so this is where
the broker reuses that epoch's authority decision and decrypted material, and
where an authority change must reach an epoch that is still connected.
The daemon supplies the epoch: no capability, token or provider credential is
read or sent here.

    daemon_probe.py MODE              one request, which must answer MODE
    daemon_probe.py MODE WITHIN_MS    requests until one answers MODE

With WITHIN_MS the probe waits for an authority change to take effect: it
repeats the request once a second until one answers MODE, and fails unless
that happens within WITHIN_MS of the first request. The broker reuses an
epoch's authority decision for up to a minute, so a membership or binding
change can take that long. Until then a request may only answer what it did
before the change: 200 while a denial is awaited, 403 while success is
awaited.

The input carries no fixture scenario marker, so the synthetic provider
answers every served request as a baseline request. stdout is one closed
event: the mode and final status, how many requests were made, how many the
provider served (200), the milliseconds from the first request to the answer,
and the bound it was given, if any. No request or response body, header or
token is ever printed.
"""

import http.client
import json
import sys
import time


HOST = "127.0.0.1"
PORT = 38081
TARGET = "/v1/responses"
BODY = json.dumps({"model": "codewire-synthetic", "input": "CW_KIND_DAEMON_PATH", "stream": True},
                  separators=(",", ":"))
HEADERS = {"Host": "localhost", "Content-Type": "application/json"}
MODES = {"success": 200, "denied": 403, "revoked": 403}
MARKER = b"CWCODEX149 kind"
MAX_RESPONSE = 64 * 1024
REQUEST_TIMEOUT = 20
POLL_SECONDS = 1.0
MAX_WITHIN_MS = 70_000


def request():
    """One proxied request; only its status leaves here."""
    connection = http.client.HTTPConnection(HOST, PORT, timeout=REQUEST_TIMEOUT)
    try:
        connection.request("POST", TARGET, body=BODY, headers=HEADERS)
        response = connection.getresponse()
        payload = response.read(MAX_RESPONSE + 1)
        status = response.status
    finally:
        connection.close()
    if len(payload) > MAX_RESPONSE:
        raise ValueError("response-bound")
    if b"CW_KIND_SYNTHETIC_REFRESH_" in payload or b"synthetic-kind-signature" in payload:
        raise ValueError("provider-response-exposure")
    if status == 200 and MARKER not in payload:
        raise ValueError("response-marker")
    return status


def probe(mode, within_ms=None):
    if mode not in MODES:
        raise ValueError("selection")
    if within_ms is not None and not 0 < within_ms <= MAX_WITHIN_MS:
        raise ValueError("bound")
    expected = MODES[mode]
    before = 403 if expected == 200 else 200
    started = time.monotonic()
    requests = served = 0
    while True:
        status = request()
        waited_ms = int((time.monotonic() - started) * 1000)
        requests += 1
        served += status == 200
        if status == expected:
            break
        if within_ms is None or status != before or waited_ms >= within_ms:
            raise ValueError("response-status")
        time.sleep(POLL_SECONDS)
    if within_ms is not None and waited_ms > within_ms:
        raise ValueError("bound")
    print(json.dumps({"event": "daemon_probe", "mode": mode, "status": status,
                      "requests": requests, "served": served, "waited_ms": waited_ms,
                      "within_ms": within_ms}, separators=(",", ":")), flush=True)


def arguments(argv):
    if len(argv) == 2:
        return argv[1], None
    if len(argv) == 3 and argv[2].isdigit() and not argv[2].startswith("0"):
        return argv[1], int(argv[2])
    raise ValueError("arguments")


if __name__ == "__main__":
    try:
        probe(*arguments(sys.argv))
    except Exception:
        # No traceback, URL, header or raw provider response leaves the
        # workspace through a diagnostic failure.
        print(json.dumps({"event": "daemon_probe_failed"}), flush=True)
        sys.exit(1)
