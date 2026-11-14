"""The planner Cargo oracle fetches its inputs unless every root resolves offline
(cargo-oracle-inputs.sh).

On 2026-11-13 a warm Cargo home held russh 0.65.0 but not 0.65.1, the lock bump
only codewire-cli-bin uses. The check returned the last root's status alone, so
it reported the inputs present, skipped the fetch, and the oracle then failed
offline. These tests run the check against a fake cargo that resolves only the
roots named in RESOLVES.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

LIBRARY = Path(__file__).resolve().parents[1] / "cargo-oracle-inputs.sh"

FAKE_CARGO = """#!/usr/bin/env bash
# Succeed for `cargo tree ... -p PACKAGE` only when PACKAGE is in $RESOLVES.
package=''
while [ $# -gt 0 ]; do
  if [ "$1" = -p ]; then package="$2"; shift; fi
  shift
done
case " $RESOLVES " in *" $package "*) exit 0 ;; esac
exit 101
"""


def available(roots: list[str], resolves: list[str]) -> int:
    with tempfile.TemporaryDirectory() as work:
        bin_dir = Path(work, "bin")
        bin_dir.mkdir()
        cargo = bin_dir / "cargo"
        cargo.write_text(FAKE_CARGO)
        cargo.chmod(0o755)
        artifacts = " ".join(f"$'{root}\\tCargo.toml'" for root in roots)
        script = f"source {LIBRARY}; rust_artifacts=({artifacts}); cargo_oracle_inputs_available"
        return subprocess.run(
            ["bash", "-c", script],
            env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "RESOLVES": " ".join(resolves)},
            timeout=20,
        ).returncode


class CargoOracleInputsTests(unittest.TestCase):
    def test_every_root_resolving_means_available(self) -> None:
        self.assertEqual(available(["cli", "desktop"], ["cli", "desktop"]), 0)

    def test_an_earlier_root_missing_means_unavailable(self) -> None:
        # The 2026-11-13 case: the first root misses an input, the last resolves.
        self.assertNotEqual(available(["cli", "desktop"], ["desktop"]), 0)

    def test_the_last_root_missing_means_unavailable(self) -> None:
        self.assertNotEqual(available(["cli", "desktop"], ["cli"]), 0)

    def test_nothing_resolving_means_unavailable(self) -> None:
        self.assertNotEqual(available(["cli", "desktop"], []), 0)


if __name__ == "__main__":
    unittest.main()
