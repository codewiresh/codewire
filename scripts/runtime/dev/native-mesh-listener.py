#!/usr/bin/env python3
"""Synthetic named-Mesh responder; the owning guest lifecycle stops it."""

import argparse
import re
import socket
import sys
import time


IO_TIMEOUT_SECONDS = 5.0
REQUEST_LIMIT = 66
RESPONSE_PREFIX = b"codewire-native-mesh:"


def handle_connection(connection):
    """Require one nonce line and write-half EOF within one fixed deadline."""
    deadline = time.monotonic() + IO_TIMEOUT_SECONDS
    with connection:
        try:
            request = bytearray()
            while len(request) < REQUEST_LIMIT:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                connection.settimeout(remaining)
                chunk = connection.recv(REQUEST_LIMIT - len(request))
                if not chunk:
                    break
                request.extend(chunk)
            if re.fullmatch(rb"[0-9a-f]{64}\n", request) is None:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            connection.settimeout(remaining)
            connection.sendall(RESPONSE_PREFIX + request)
        except OSError:
            # Request bodies, peer addresses and failures are never logged.
            return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", args.port))
            listener.listen(8)
            while True:
                connection, _ = listener.accept()
                handle_connection(connection)
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("native-mesh-listener: unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
