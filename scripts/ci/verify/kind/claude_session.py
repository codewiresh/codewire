#!/usr/bin/env python3
"""Managed Kind only: stock Claude Code through the managed Anthropic route.

The caller pipes this file into the actual workspace's python3 with two
arguments: the expected credential form (`api_key` or `subscription_token`)
and the managed client selection the workspace binding recorded for this exact
Pod (sandbox_workspace_bindings.managed_credential_clients, the record launch
authority also reads). Never print raw output, stderr, environment values or
credential bytes: stdout is the closed acceptance event stream.

How the projected environment reaches this process. An environment-token
workspace Pod renders the managed client environment (codewire-access
`ManagedCredentialClients::for_placement`) and its selection into the
container, so a kubectl-exec'd process inherits them: the driver uses those
exact rendered values and requires the rendered selection to equal the
recorded one. An identity-free Pod (the default binding mode) renders neither;
its daemon projects the same values only into the sessions it launches, and a
kubectl exec is not one. There the driver applies the values the renderer
defines for the recorded selection, after requiring that the container itself
carries none of those names. Either way every value is the fixed loopback
route or the `codewire-managed` placeholder; nothing here reads, invents or
receives a credential. The form decision is the product's: orchestration
recorded the bound credential's kind in the selection, and the synthetic
provider answers only when the broker presented the real synthetic credential
in exactly that form and never the placeholder.

Pinned to Claude Code 2.1.238, whose probe showed that `claude -p` sends only
POST /v1/messages?beta=true to the base URL, that CLAUDE_CODE_OAUTH_TOKEN
selects its subscription mode, and that the empty ANTHROPIC_AUTH_TOKEN and
ANTHROPIC_API_KEY are treated as unset. The fresh HOME and
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
SELECTION_ENV = "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"
NAMES = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
# The renderer's exact values for each form (codewire-access projection.rs).
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
# An Anthropic-only personal profile selects the Anthropic client, plus GitHub
# while the creator's connection is active. Bit 0x20 is the subscription form.
SELECTIONS = {
    "api_key": frozenset({"v1:anthropic", "v2:14"}),
    "subscription_token": frozenset({"v2:24", "v2:34"}),
}
# Distinctive parts of the fixture's synthetic credentials
# (credential-service runtime/kind/provider.rs). Neither may appear anywhere in
# the Sandbox, Claude Code's environment or its output.
CREDENTIAL_MARKERS = (
    "CW_KIND_SYNTHETIC_ANTHROPIC_KEY",
    "CW_KIND_SYNTHETIC_CLAUDE_TOKEN",
)
SESSION_TIMEOUT = 120.0
VERSION_TIMEOUT = 30.0
MAX_OUTPUT = 256 * 1024
VERSION = re.compile(r"(\d{1,4}\.\d{1,4}\.\d{1,6}) \(Claude Code\)")


class Failure(Exception):
    """Only fixed reason identifiers may enter the public event stream."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def parse_arguments(argv):
    if len(argv) != 2 or argv[0] not in PROJECTIONS:
        raise Failure("arguments")
    return argv[0], argv[1]


def exposed(environ):
    return any(marker in name or marker in value
               for name, value in environ.items() for marker in CREDENTIAL_MARKERS)


def projection(kind, selection, environ):
    """The exact projected values and where they came from."""
    if selection not in SELECTIONS[kind]:
        raise Failure("unexpected_selection")
    rendered = environ.get(SELECTION_ENV)
    if rendered is not None:
        if rendered != selection:
            raise Failure("selection_mismatch")
        values = {name: environ.get(name) for name in NAMES}
        if values != PROJECTIONS[kind]:
            raise Failure("projection_values")
        return values, "container"
    if any(name in environ for name in NAMES):
        raise Failure("unexpected_inherited_auth")
    return dict(PROJECTIONS[kind]), "binding"


def child_environment(environ, values, home):
    child = dict(environ)
    child.update(values)
    child.update({
        "HOME": home,
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "XDG_CACHE_HOME": os.path.join(home, ".cache"),
        "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    })
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
    return process.returncode, stdout


def client_version(env, cwd):
    status, stdout = run([*CLAUDE_ARGV, "--version"], env, cwd, VERSION_TIMEOUT,
                         "claude_version")
    match = VERSION.match(stdout.decode("utf-8", "replace").strip())
    if status != 0 or match is None:
        raise Failure("claude_version")
    return match.group(1)


def session(kind, selection, environ):
    if exposed(environ):
        raise Failure("credential_in_environment")
    values, source = projection(kind, selection, environ)
    emit("claude_projection", kind=kind, selection=selection, source=source)
    with tempfile.TemporaryDirectory(prefix="kind-claude-") as home:
        env = child_environment(environ, values, home)
        version = client_version(env, home)
        status, stdout = run([*CLAUDE_ARGV, "-p", PROMPT], env, home, SESSION_TIMEOUT, "claude")
        if status != 0:
            raise Failure("claude_exit")
        if MARKER.encode() not in stdout:
            raise Failure("missing_marker")
    emit("claude_session", kind=kind, client_version=version, marker=True)


def main(argv=None, environ=None):
    kind = None

    def interrupted(_signum, _frame):
        raise Failure("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        kind, selection = parse_arguments(sys.argv[1:] if argv is None else argv)
        session(kind, selection, dict(os.environ if environ is None else environ))
    except Failure as error:
        emit("failed", kind=kind, reason=str(error))
        return 1
    except Exception:
        emit("failed", kind=kind, reason="driver_failure")
        return 1
    emit("complete", kind=kind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
