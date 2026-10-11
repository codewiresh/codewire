#!/usr/bin/env python3
"""Managed Kind only: proxied requests across a natural bridge epoch renewal.

The caller pipes this file into the actual workspace's python3 while another
step idles past at least one renewal, then creates the stop file. Each request
crosses the daemon's loopback ingress, the bridge epoch, the gateway and the
broker. It names the Anthropic slot, which the native flow's profile never
selects, so the broker answers every request Denied (403) before any provider
call and the synthetic provider's exact counters stay untouched. A 503 means
the bridge had no admitted epoch for it. About one request a second still
catches any gap of a second or more, without flooding the fixture's logs.

stdout is one closed event. No request or response body, header or token is
ever printed; response bodies are read only to release the connection.
"""

import http.client
import json
import os
import re
import signal
import sys
import time


HOST = "127.0.0.1"
PORT = 38081
TARGET = "/_codewire/anthropic/v1/messages"
# A fixed public synthetic request; the broker denies it before any upstream.
BODY = json.dumps({
    "model": "codewire-synthetic",
    "max_tokens": 1,
    "messages": [{"role": "user", "content": "CW_KIND_BRIDGE_RENEWAL"}],
}, separators=(",", ":"))
HEADERS = {"Host": "localhost", "Content-Type": "application/json"}
INTERVAL = 1.0
REQUEST_TIMEOUT = 20
MAX_SECONDS = 1800
MAX_RESPONSE = 64 * 1024
STOP_FILE = re.compile(r"/tmp/codewire-kind-bridge-renewal-[0-9]{1,12}")
SECONDS = re.compile(r"[1-9][0-9]{0,3}")


class Failure(Exception):
    """Only the fixed failure event leaves this probe."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def now_ms():
    return time.time_ns() // 1_000_000


def arguments(argv):
    if len(argv) != 3 or not STOP_FILE.fullmatch(argv[1]) or not SECONDS.fullmatch(argv[2]):
        raise Failure("arguments")
    seconds = int(argv[2])
    if seconds > MAX_SECONDS:
        raise Failure("arguments")
    if os.path.lexists(argv[1]):
        raise Failure("stale_stop_file")
    return argv[1], seconds


def request():
    """One proxied request; only its closed status class leaves here."""
    connection = http.client.HTTPConnection(HOST, PORT, timeout=REQUEST_TIMEOUT)
    try:
        connection.request("POST", TARGET, body=BODY, headers=HEADERS)
        response = connection.getresponse()
        response.read(MAX_RESPONSE + 1)
        status = response.status
    except (OSError, http.client.HTTPException):
        return "error"
    finally:
        connection.close()
    if not isinstance(status, int) or not 100 <= status <= 599:
        return "error"
    return str(status)


def run(stop, seconds):
    started = now_ms()
    deadline = time.monotonic() + seconds
    statuses = {}
    requests = 0
    while not os.path.lexists(stop) and time.monotonic() < deadline:
        status = request()
        statuses[status] = statuses.get(status, 0) + 1
        requests += 1
        time.sleep(INTERVAL)
    return {"started_unix_ms": started, "ended_unix_ms": now_ms(),
            "requests": requests, "statuses": statuses}


def main(argv):
    def interrupted(_signum, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        stop, seconds = arguments(argv)
        result = run(stop, seconds)
    except Exception:
        emit("bridge_renewal_probe_failed")
        return 1
    emit("bridge_renewal_probe", **result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
