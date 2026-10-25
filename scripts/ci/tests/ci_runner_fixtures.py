"""The exact `runs-on` values the workflows use.

Runner labels are repository Actions variables (docs/dev/CI-CONFIGURATION.md).
A missing one leaves the job queued on an `unset-<variable>` label that no
runner advertises; a main push never falls through to the untrusted runner.
Keep in step with scripts/ci/tests/fixtures/ci-runners.sh.
"""

MAIN_PUSH = "github.event_name == 'push' && github.ref == 'refs/heads/main'"


def one(variable: str) -> str:
    return f"${{{{ vars.{variable} || 'unset-{variable}' }}}}"


def by_trust(trusted: str, untrusted: str) -> str:
    return (f"${{{{ {MAIN_PUSH} && (vars.{trusted} || 'unset-{trusted}') "
            f"|| (vars.{untrusted} || 'unset-{untrusted}') }}}}")


UNTRUSTED_LIGHT = one("CODEWIRE_CI_RUNNER_UNTRUSTED_LIGHT")
TRUSTED_LIGHT = one("CODEWIRE_CI_RUNNER_TRUSTED_LIGHT")
MACOS = one("CODEWIRE_CI_RUNNER_MACOS")
UNTRUSTED_BUILD = one("CODEWIRE_CI_RUNNER_UNTRUSTED_BUILD")
HEAVY = by_trust("CODEWIRE_CI_RUNNER_TRUSTED_HEAVY", "CODEWIRE_CI_RUNNER_UNTRUSTED_HEAVY")
# The medium metal class (infra#1534): every verification group that needs a
# metal guest but not the heavy one's memory.
MEDIUM = by_trust("CODEWIRE_CI_RUNNER_TRUSTED_MEDIUM", "CODEWIRE_CI_RUNNER_UNTRUSTED_MEDIUM")
KIND = by_trust("CODEWIRE_CI_RUNNER_TRUSTED_KIND", "CODEWIRE_CI_RUNNER_UNTRUSTED_KIND")
# Compile once (infra#1632): main on trusted Heavy, every other run on the build runner.
BUILD = by_trust("CODEWIRE_CI_RUNNER_TRUSTED_BUILD", "CODEWIRE_CI_RUNNER_UNTRUSTED_BUILD")
