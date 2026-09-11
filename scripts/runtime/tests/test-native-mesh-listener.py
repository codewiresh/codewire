#!/usr/bin/env python3
"""Local-only protocol and lifetime tests for the synthetic guest listener."""

import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import threading
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "dev" / "native-mesh-listener.py"
SPEC = importlib.util.spec_from_file_location("native_mesh_listener", SOURCE)
listener = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(listener)
NONCE = b"0123456789abcdef" * 4


class ListenerTests(unittest.TestCase):
    @contextlib.contextmanager
    def pair(self):
        client, server = socket.socketpair()
        client.settimeout(1)
        worker = threading.Thread(target=listener.handle_connection, args=(server,))
        worker.start()
        try:
            yield client
        finally:
            client.close()
            worker.join(1)
            self.assertFalse(worker.is_alive(), "owned connection worker did not stop")

    def read_all(self, client):
        response = bytearray()
        while True:
            chunk = client.recv(256)
            if not chunk:
                return bytes(response)
            response.extend(chunk)
            self.assertLessEqual(len(response), 86)

    def test_fragmented_valid_request_has_exact_reply_and_eof(self):
        with self.pair() as client:
            for chunk in (NONCE[:3], NONCE[3:47], NONCE[47:], b"\n"):
                client.sendall(chunk)
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(self.read_all(client), b"codewire-native-mesh:" + NONCE + b"\n")

    def test_malformed_requests_are_closed_without_reply_or_diagnostics(self):
        output, errors = io.StringIO(), io.StringIO()
        for request in (
            b"", NONCE, NONCE[:-1] + b"\n", NONCE + b"0\n",
            NONCE.upper() + b"\n", b"g" * 64 + b"\n", NONCE + b"\r\n",
            NONCE + b"\n!", b"\x00" + NONCE[1:] + b"\n",
        ):
            with self.subTest(length=len(request)):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    with self.pair() as client:
                        client.sendall(request)
                        client.shutdown(socket.SHUT_WR)
                        self.assertEqual(self.read_all(client), b"")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")

    def test_oversized_request_is_rejected_without_waiting_for_eof(self):
        with self.pair() as client:
            client.sendall(b"a" * 66)
            self.assertEqual(self.read_all(client), b"")

    def test_valid_line_without_write_half_eof_times_out(self):
        with mock.patch.object(listener, "IO_TIMEOUT_SECONDS", 0.05):
            with self.pair() as client:
                client.sendall(NONCE + b"\n")
                self.assertEqual(self.read_all(client), b"")

    def test_partial_reads_do_not_extend_the_deadline(self):
        # Deterministic clock advancement proves the total bound without a
        # timing-sensitive slow-client test or a five-second sleep.
        connection = mock.MagicMock()
        connection.recv.side_effect = [b"a", b"b", AssertionError("read after deadline")]
        with mock.patch.object(listener.time, "monotonic", side_effect=[10.0, 10.0, 14.0, 15.1]):
            listener.handle_connection(connection)
        self.assertEqual(connection.settimeout.call_args_list, [mock.call(5.0), mock.call(1.0)])
        self.assertEqual(connection.recv.call_args_list, [mock.call(66), mock.call(65)])
        connection.sendall.assert_not_called()
        connection.__exit__.assert_called_once()

    def test_real_loopback_tcp_exchange(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as accepting:
            accepting.bind(("127.0.0.1", 0))
            accepting.listen(1)
            accepting.settimeout(1)
            failures = []

            def serve_once():
                try:
                    connection, _ = accepting.accept()
                    listener.handle_connection(connection)
                except Exception as error:
                    failures.append(type(error).__name__)

            worker = threading.Thread(target=serve_once)
            worker.start()
            try:
                with socket.create_connection(accepting.getsockname(), timeout=1) as client:
                    client.sendall(NONCE + b"\n")
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(self.read_all(client), b"codewire-native-mesh:" + NONCE + b"\n")
            finally:
                worker.join(2)
                self.assertFalse(worker.is_alive(), "owned TCP worker did not stop")
            self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
