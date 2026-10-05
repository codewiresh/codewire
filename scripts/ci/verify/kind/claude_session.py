#!/usr/bin/env python3
"""Managed Kind only: stock Claude Code in a session the workspace daemon launched.

credentials.sh stages this file in the workspace and launches it through the
public `cw run` path: orchestration's EnvironmentSessionService asks the
workspace daemon to start the session, and the daemon projects the managed
client environment into it exactly as it does for a user's terminal. This
driver therefore observes what the Sandbox actually receives; it never writes,
derives or repairs any of the four Anthropic names. It checks those values,
runs the stock pinned `claude -p` with them inherited unchanged, and reports
the outcome as a closed event stream on stdout. Never print raw output,
stderr, environment values or credential bytes.

Arguments: the expected credential form (`api_key` or `subscription_token`)
and the expected outcome:

    success   Claude Code exits 0 and prints the fixture's reply marker.
    refused   Claude Code reports the provider's 401 and exits non-zero. The
              fixture refuses a well-formed synthetic subscription token this
              way, as a real provider refuses an expired or revoked one.

Pinned to Claude Code 2.1.238, whose probe showed that `claude -p` sends only
POST /v1/messages?beta=true to the base URL, that CLAUDE_CODE_OAUTH_TOKEN
selects its subscription mode, that the empty ANTHROPIC_AUTH_TOKEN and
ANTHROPIC_API_KEY are treated as unset, and that a 401 `authentication_error`
prints "API Error: 401" and exits 1 at once. The fresh HOME and
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC are harness-local: no saved login,
telemetry or update call. Neither changes authentication.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile


CLAUDE = "/opt/codewire/agents/npm/bin/claude"
CLAUDE_ARGV = (CLAUDE,)
BASE_URL = "http://127.0.0.1:38081"
PLACEHOLDER = "codewire-managed"
MARKER = "CWCLAUDE kind"
PROMPT = "Reply with the Codewire Kind marker."
NAMES = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
# The daemon's exact values for each form (codewire-access projection.rs).
PROJECTIONS = {
    "api_key": {
        "ANTHROPIC_BASE_URL": BASE_URL,
        "ANTHROPIC_AUTH_TOKEN": PLACEHOLDER,
        "ANTHROPIC_API_KEY": "",
        "CLAUDE_CODE_OAUTH_TOKEN": "",
    },
    "subscription_token": {
        "ANTHROPIC_BASE_URL": BASE_URL,
        "CLAUDE_CODE_OAUTH_TOKEN": PLACEHOLDER,
        "ANTHROPIC_AUTH_TOKEN": "",
        "ANTHROPIC_API_KEY": "",
    },
}
OUTCOMES = ("success", "refused")
# Distinctive parts of the fixture's synthetic credentials
# (credential-service runtime/kind/provider.rs). None may appear anywhere in
# the session's environment, Claude Code's environment or its output.
CREDENTIAL_MARKERS = (
    "CW_KIND_SYNTHETIC_ANTHROPIC_KEY",
    "CW_KIND_SYNTHETIC_CLAUDE_TOKEN",
    "CW_KIND_SYNTHETIC_REFUSED_TOKEN",
)
REFUSAL = b"401"
SESSION_TIMEOUT = 120.0
VERSION_TIMEOUT = 30.0
MAX_OUTPUT = 256 * 1024
VERSION = re.compile(r"(\d{1,4}\.\d{1,4}\.\d{1,6}) \(Claude Code\)")


class Failure(Exception):
    """Only fixed reason identifiers may enter the public event stream."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def parse_arguments(argv):
    if len(argv) != 2 or argv[0] not in PROJECTIONS or argv[1] not in OUTCOMES:
        raise Failure("arguments")
    return argv[0], argv[1]


def exposed(environ):
    return any(marker in name or marker in value
               for name, value in environ.items() for marker in CREDENTIAL_MARKERS)


def projection(form, environ):
    """The four values the daemon projected, which must be exactly the form's."""
    values = {name: environ.get(name) for name in NAMES}
    if any(value is None for value in values.values()):
        raise Failure("projection_missing")
    if values != PROJECTIONS[form]:
        other = next(name for name in PROJECTIONS if name != form)
        raise Failure("projection_other_form" if values == PROJECTIONS[other]
                      else "projection_values")
    return values


def child_environment(environ, home):
    """The session's own environment with a fresh harness-local home only."""
    child = dict(environ)
    child.update({
        "HOME": home,
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "XDG_CACHE_HOME": os.path.join(home, ".cache"),
        "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    })
    if any(child.get(name) != environ.get(name) for name in NAMES):
        raise Failure("projection_rewritten")
    if exposed(child):
        raise Failure("credential_in_child_environment")
    return child


def run(argv, env, cwd, timeout, reason):
    """Bounded child run with closed stdin; output never leaves this module."""
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError:
        raise Failure(f"{reason}_start") from None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise Failure(f"{reason}_timeout") from None
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
        raise Failure(f"{reason}_output_limit")
    if any(marker.encode() in output
           for output in (stdout, stderr) for marker in CREDENTIAL_MARKERS):
        raise Failure("credential_in_output")
    return process.returncode, stdout, stderr


def client_version(env, cwd):
    status, stdout, _ = run([*CLAUDE_ARGV, "--version"], env, cwd, VERSION_TIMEOUT,
                            "claude_version")
    match = VERSION.match(stdout.decode("utf-8", "replace").strip())
    if status != 0 or match is None:
        raise Failure("claude_version")
    return match.group(1)


def session(form, outcome, environ):
    if exposed(environ):
        raise Failure("credential_in_environment")
    projection(form, environ)
    emit("claude_projection", form=form, source="daemon_session")
    with tempfile.TemporaryDirectory(prefix="kind-claude-") as home:
        env = child_environment(environ, home)
        version = client_version(env, home)
        status, stdout, stderr = run([*CLAUDE_ARGV, "-p", PROMPT], env, home,
                                     SESSION_TIMEOUT, "claude")
    marker = MARKER.encode() in stdout
    if outcome == "success":
        if status != 0:
            raise Failure("claude_exit")
        if not marker:
            raise Failure("missing_marker")
    else:
        if status == 0 or marker:
            raise Failure("refusal_not_reported")
        if REFUSAL not in stdout + stderr:
            raise Failure("refusal_status_missing")
    emit("claude_session", form=form, outcome=outcome, client_version=version)


def main(argv=None, environ=None):
    form = outcome = None

    def interrupted(_signum, _frame):
        raise Failure("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        form, outcome = parse_arguments(sys.argv[1:] if argv is None else argv)
        session(form, outcome, dict(os.environ if environ is None else environ))
    except Failure as error:
        emit("failed", form=form, outcome=outcome, reason=str(error))
        return 1
    except Exception:
        emit("failed", form=form, outcome=outcome, reason="driver_failure")
        return 1
    emit("complete", form=form, outcome=outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
