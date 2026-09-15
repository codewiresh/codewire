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
    def check(self, path=None, old=None, new=None, output=None):
        def read(candidate, *args, **kwargs):
            value = READ_TEXT(candidate, *args, **kwargs)
            if candidate == path:
                self.assertIn(old, value)
                return value.replace(old, new, 1)
            return value

        if output is None:
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

    def test_workload_network_mutations_fail_without_success(self):
        protocol = PACKAGE / "Sources/CodewireVZRunnerProtocol/WorkloadNetwork.swift"
        runtime = PACKAGE / "Sources/CodewireVZRunnerRuntime/WorkloadNetworkRuntime.swift"
        lifecycle = PACKAGE / "Sources/CodewireVZRunnerRuntime/WorkloadNetworkLifecycle.swift"
        machine = PACKAGE / "Sources/CodewireVZRunnerRuntime/WorkloadNetworkMachine.swift"
        for path, old, new in (
            (protocol, "descriptorCount = 10", "descriptorCount = 11"),
            (protocol, "schemaVersion = 4", "schemaVersion = 3"),
            (protocol, "serviceBinding, progress, daemon", "serviceBinding, network, progress, daemon"),
            (machine, "configuration.networkDevices = []", "configuration.networkDevices = addedNICs"),
            (runtime, "closeOnDealloc: false", "closeOnDealloc: true"),
            (runtime, "port.attachment = nil", "port.attachment = packet.attachment"),
            (runtime, "let connection = try self.connect(port: 7775)",
             "let connection = try self.connect(port: 7775); Darwin.read(connection.fileDescriptor, nil, 0)"),
            (lifecycle, "actualStops == [1, 2] && daemonDrained", "actualStops == [1, 2]"),
            (runtime, "daemonDrained = true",
             "daemonDrained = true; let stopDeadline = workloadNow() + WorkloadNetworkProtocol.stopSeconds"),
            (runtime, "daemonDrained = true",
             "daemonDrained = true; site = .daemonStopDeadline"),
            (runtime, "actualStops: actualStops, daemonDrained: daemonDrainedNow",
             "actualStops: actualStops, daemonDrained: true"),
            (runtime, "let stopDeadline = workloadNow() + WorkloadNetworkProtocol.stopSeconds",
             "let stopDeadline = Double.infinity"),
            (ROOT / "crates/codewire-local-vmm/Cargo.toml",
             'required-features = ["macos-workload-network-fixture"]', 'required-features = []'),
            (ROOT / "crates/codewire-vmm-guest-probe/src/lib.rs",
             '#[cfg(feature = "macos-workload-network-fixture")]\npub mod macos_workload_network_fixture;',
             'pub mod macos_workload_network_fixture;'),
            (ROOT / "crates/codewire-vmm-guest-probe/src/main.rs",
             '#[cfg(feature = "macos-workload-network-fixture")]\n        Some("macos-workload-network-client")',
             'Some("macos-workload-network-client")'),
            (ROOT / "crates/codewire-local-vmm/src/bin/vz_workload_network_fixture/mod.rs",
             "use std::", "use codewire_netstack::run_network_session;\nuse std::"),
        ):
            with self.subTest(contract=old):
                output = io.StringIO()
                with self.assertRaises(SystemExit) as failure:
                    self.check(path, old, new, output)
                self.assertEqual(failure.exception.code, 1)
                self.assertNotIn("macOS VZ runner static boundary: OK", output.getvalue())


if __name__ == "__main__":
    unittest.main()
