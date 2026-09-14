#!/usr/bin/env python3
"""Mutation fixtures for the real shared static guard, without source writes."""

import contextlib
import io
from pathlib import Path
import unittest
from unittest import mock


GUARD = Path(__file__).with_name("test_static_contract.py").resolve()
GUARD_SOURCE = GUARD.read_text()
ROOT = GUARD.parents[4]
PACKAGE = ROOT / "crates/codewire-local-vmm/macos-vz-runner"
READ_TEXT = Path.read_text


class ConsolePairBoundaryTests(unittest.TestCase):
    def check(self, path=None, old=None, new=None):
        def read(candidate, *args, **kwargs):
            value = READ_TEXT(candidate, *args, **kwargs)
            if candidate == path:
                self.assertIn(old, value)
                return value.replace(old, new, 1)
            return value

        output = io.StringIO()
        with mock.patch.object(Path, "read_text", read), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(compile(GUARD_SOURCE, str(GUARD), "exec"), {"__file__": str(GUARD)})
        return output.getvalue()

    def test_current_source_passes(self):
        self.assertIn("macOS VZ runner static boundary: OK", self.check())

    def test_console_pair_mutations_fail_the_shared_guard(self):
        runtime = PACKAGE / "Sources/CodewireVZRunnerRuntime/ConsolePairRuntime.swift"
        protocol = PACKAGE / "Sources/CodewireVZRunnerProtocol/ConsolePair.swift"
        for path, old, new in (
            (runtime, "configuration.networkDevices = []", "configuration.networkDevices = addedNICs"),
            (runtime, "packetPort.isConsole = false", "packetPort.isConsole = true"),
            (runtime, "guard input.isEmpty", "guard true"),
            (runtime, "let packetPair = try makePacketPair()",
             "let packetPair = try makePacketPair(); Darwin.read(packetPair.0.fileDescriptor, nil, 0)"),
            (protocol, "schemaVersion = 3", "schemaVersion = 1"),
            (ROOT / "crates/codewire-local-vmm/Cargo.toml",
             'required-features = ["macos-console-pair-fixture"]', 'required-features = []'),
            (ROOT / "crates/codewire-local-vmm/Cargo.toml",
             'required-features = ["macos-product-network-fixture"]', 'required-features = []'),
            (ROOT / "crates/codewire-local-vmm/src/bin/codewire-macos-product-network-fixture.rs",
             'feature = "macos-product-network-fixture"', 'feature = "default"'),
        ):
            with self.subTest(contract=old):
                with self.assertRaises(SystemExit) as failure:
                    self.check(path, old, new)
                self.assertEqual(failure.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
