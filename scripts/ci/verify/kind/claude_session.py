#!/usr/bin/env python3
"""Managed Kind only: stock Claude Code in a session the workspace daemon launched.

credentials.sh stages this file in the workspace and launches it through the
public `cw run` path: orchestration's EnvironmentSessionService asks the
workspace daemon to start the session, and the daemon projects the managed
client environment into it exactly as it does for a user's terminal. This
driver therefore observes what the Sandbox actually receives; it never writes,
derives or repairs any of the four Anthropic names. It checks those values
and that the daemon marked Claude Code's onboarding complete and the
workspace root trusted in the workspace user's own `~/.claude.json`, runs the stock pinned `claude -p` with
the values inherited unchanged, and reports the outcome as a closed event
stream on stdout. Never print raw output, stderr, environment values,
file contents or credential bytes.

Arguments: the expected credential form (`api_key`, `subscription_token` or
`sign_in`) and the expected outcome:

    success     Claude Code exits 0 and prints the fixture's reply marker.
    refused     Claude Code reports the provider's 401 and exits non-zero. The
                fixture refuses a well-formed synthetic subscription token this
                way, as a real provider refuses an expired or revoked one.
    withheld    Claude Code reports the broker's 403 and exits non-zero: the
                selected credential was revoked, so the broker withholds the
                capability and nothing reaches the provider.
    logged_out  `sign_in` only. The daemon removed its delivered login after
                the sign-in was revoked; Claude Code exits non-zero without the
                marker, reporting either that it has no login ("/login") or,
                if it still sent a request without one, the broker's 403. The
                closed `cause` names which.

The `sign_in` form projects ANTHROPIC_BASE_URL alone: Claude Code reads its
own claude.ai login, which the workspace daemon delivered as `claudeAiOauth`
in the session user's `~/.claude/.credentials.json`. That form therefore runs
Claude Code with the session's own HOME, where the login lives, instead of a
fresh harness HOME, and checks only the login's presence and Codewire's marker
(claude_login.py checks the login itself). It never prints the file.

Pinned to Claude Code 2.1.288, whose probe showed that `claude -p` sends only
POST /v1/messages?beta=true to the base URL, that CLAUDE_CODE_OAUTH_TOKEN
selects its subscription mode, and that a 401 `authentication_error` prints
"API Error: 401" and exits 1 at once. Each form projects only its own
variable; the other Anthropic names are absent, never empty. The fresh HOME and
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC are harness-local: no saved login,
telemetry or update call. Neither changes authentication. The `sign_in` form
keeps the session's HOME, because its authentication is the saved login.
"""

import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile


CLAUDE = "/opt/codewire/agents/npm/bin/claude"
CLAUDE_ARGV = (CLAUDE,)
BASE_URL = "http://127.0.0.1:38081/_codewire/anthropic"
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
# Every other name in NAMES must be absent from the session.
PROJECTIONS = {
    "api_key": {
        "ANTHROPIC_BASE_URL": BASE_URL,
        "ANTHROPIC_AUTH_TOKEN": PLACEHOLDER,
    },
    "subscription_token": {
        "ANTHROPIC_BASE_URL": BASE_URL,
        "CLAUDE_CODE_OAUTH_TOKEN": PLACEHOLDER,
    },
    "sign_in": {
        "ANTHROPIC_BASE_URL": BASE_URL,
    },
}
OUTCOMES = ("success", "refused", "withheld", "logged_out")
# The outcomes each form can have. A sign-in is never refused by the fixture
# (the broker refreshes it); its revocation removes the delivered login.
FORM_OUTCOMES = {
    "api_key": ("success", "refused", "withheld"),
    "subscription_token": ("success", "refused", "withheld"),
    "sign_in": ("success", "withheld", "logged_out"),
}
# Claude Code's own login, as the workspace daemon delivers it for the
# `sign_in` form (codewire-daemon claude_home/login.rs), relative to HOME.
CREDENTIALS = os.path.join(".claude", ".credentials.json")
MANAGED_MARKER = "codewireManaged"
LOGIN_KEY = "claudeAiOauth"
PLACEHOLDER_REFRESH_PREFIX = "codewire-managed-no-refresh-token-"
MAX_CREDENTIALS = 1024 * 1024
# What Claude Code prints with no login at all (2.1.288: "Not logged in ·
# Please run /login").
NO_LOGIN = b"/login"
# What the daemon sets in the workspace user's own Claude Code configuration
# while the Anthropic client is selected (codewire-daemon claude_home.rs).
CLAUDE_CONFIG = ".claude.json"
ONBOARDING_KEYS = ("hasCompletedOnboarding", "hasAcknowledgedCostThreshold")
# The workspace root, under which every repository is checked out; Claude Code
# applies its trust to every folder beneath it.
WORKSPACE_ROOT = "/workspace"
MAX_CLAUDE_CONFIG = 1024 * 1024
# Distinctive parts of the fixture's synthetic credentials
# (credential-service runtime/kind/provider.rs). None may appear anywhere in
# the session's environment, Claude Code's environment or its output.
CREDENTIAL_MARKERS = (
    "CW_KIND_SYNTHETIC_ANTHROPIC_KEY",
    "CW_KIND_SYNTHETIC_CLAUDE_TOKEN",
    "CW_KIND_SYNTHETIC_REFUSED_TOKEN",
    "CW_KIND_SYNTHETIC_SIGN_IN",
)
REFUSAL = b"401"
WITHHELD = b"403"
SESSION_TIMEOUT = 120.0
VERSION_TIMEOUT = 30.0
MAX_OUTPUT = 256 * 1024
VERSION = re.compile(r"(\d{1,4}\.\d{1,4}\.\d{1,6}) \(Claude Code\)")


class Failure(Exception):
    """Only fixed reason identifiers may enter the public event stream."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def parse_arguments(argv):
    if (len(argv) != 2 or argv[0] not in PROJECTIONS or argv[1] not in OUTCOMES
            or argv[1] not in FORM_OUTCOMES[argv[0]]):
        raise Failure("arguments")
    return argv[0], argv[1]


def exposed(environ):
    return any(marker in name or marker in value
               for name, value in environ.items() for marker in CREDENTIAL_MARKERS)


def projection(form, environ):
    """The Anthropic names the daemon projected: exactly the form's, with its
    values, and none of the others, not even empty."""
    values = {name: environ[name] for name in NAMES if name in environ}
    expected = PROJECTIONS[form]
    if values == expected:
        return values
    if any(values == PROJECTIONS[other] for other in PROJECTIONS if other != form):
        raise Failure("projection_other_form")
    if any(name not in values for name in expected):
        raise Failure("projection_missing")
    raise Failure("projection_values")


def onboarding(environ):
    """The session user's own ~/.claude.json, as the daemon left it: a private
    regular file of this uid, never a symlink, that marks onboarding complete
    and the workspace root trusted, and holds no credential or placeholder.
    Read only, never repaired."""
    home = environ.get("HOME", "")
    if not os.path.isabs(home):
        raise Failure("onboarding_home")
    try:
        descriptor = os.open(os.path.join(home, CLAUDE_CONFIG),
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise Failure("onboarding_missing") from None
    except OSError:
        # ELOOP: a symlink, refused by O_NOFOLLOW and never read through.
        raise Failure("onboarding_file") from None
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid()
                or status.st_mode & 0o077):
            raise Failure("onboarding_file")
        with os.fdopen(descriptor, "rb", closefd=False) as config:
            contents = config.read(MAX_CLAUDE_CONFIG + 1)
    finally:
        os.close(descriptor)
    if len(contents) > MAX_CLAUDE_CONFIG:
        raise Failure("onboarding_file")
    if any(marker.encode() in contents for marker in (*CREDENTIAL_MARKERS, PLACEHOLDER)):
        raise Failure("credential_in_claude_config")
    try:
        document = json.loads(contents)
    except ValueError:
        raise Failure("onboarding_not_marked") from None
    if not isinstance(document, dict) or any(document.get(key) is not True
                                             for key in ONBOARDING_KEYS):
        raise Failure("onboarding_not_marked")
    projects = document.get("projects")
    workspace = projects.get(WORKSPACE_ROOT) if isinstance(projects, dict) else None
    if not isinstance(workspace, dict) or workspace.get("hasTrustDialogAccepted") is not True:
        raise Failure("workspace_not_trusted")


def delivered_login(environ):
    """Whether the session user's ~/.claude/.credentials.json holds Codewire's
    delivered login: a private regular file of this uid, never a symlink, with
    Codewire's marker and a `claudeAiOauth` whose refresh token is Codewire's
    placeholder. False when the file or the login is absent. Only presence and
    shape are read; no value leaves this function."""
    home = environ.get("HOME", "")
    if not os.path.isabs(home):
        raise Failure("onboarding_home")
    try:
        descriptor = os.open(os.path.join(home, CREDENTIALS),
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    except OSError:
        raise Failure("login_file") from None
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid()
                or status.st_mode & 0o077):
            raise Failure("login_file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            contents = source.read(MAX_CREDENTIALS + 1)
    finally:
        os.close(descriptor)
    if len(contents) > MAX_CREDENTIALS:
        raise Failure("login_file")
    try:
        document = json.loads(contents)
    except ValueError:
        raise Failure("login_not_codewires") from None
    if not isinstance(document, dict):
        raise Failure("login_not_codewires")
    login = document.get(LOGIN_KEY)
    if login is None:
        return False
    refresh = login.get("refreshToken") if isinstance(login, dict) else None
    if (document.get(MANAGED_MARKER) != 1 or not isinstance(refresh, str)
            or not refresh.startswith(PLACEHOLDER_REFRESH_PREFIX)
            or not isinstance(login.get("accessToken"), str) or not login["accessToken"]):
        raise Failure("login_not_codewires")
    return True


def child_environment(environ, home):
    """The session's own environment with a fresh harness-local home only, or,
    when home is None, with the session's own home."""
    child = dict(environ)
    if home is not None:
        child.update({
            "HOME": home,
            "XDG_CONFIG_HOME": os.path.join(home, ".config"),
            "XDG_CACHE_HOME": os.path.join(home, ".cache"),
            "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
        })
    child["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
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
    onboarding(environ)
    if form == "sign_in":
        delivered = delivered_login(environ)
        if outcome == "logged_out" and delivered:
            raise Failure("login_kept")
        if outcome != "logged_out" and not delivered:
            raise Failure("login_missing")
    emit("claude_projection", form=form, source="daemon_session")
    with tempfile.TemporaryDirectory(prefix="kind-claude-") as scratch:
        # The sign-in form authenticates with the session user's own saved
        # login; every other form gets a fresh home without one.
        env = child_environment(environ, None if form == "sign_in" else scratch)
        version = client_version(env, scratch)
        status, stdout, stderr = run([*CLAUDE_ARGV, "-p", PROMPT], env, scratch,
                                     SESSION_TIMEOUT, "claude")
    marker = MARKER.encode() in stdout
    fields = {}
    if outcome == "success":
        if status != 0:
            raise Failure("claude_exit")
        if not marker:
            raise Failure("missing_marker")
    elif outcome == "logged_out":
        if status == 0 or marker:
            raise Failure("refusal_not_reported")
        output = stdout + stderr
        if WITHHELD in output:
            fields["cause"] = "withheld"
        elif NO_LOGIN in output:
            fields["cause"] = "no_login"
        else:
            raise Failure("refusal_status_missing")
    else:
        if status == 0 or marker:
            raise Failure("refusal_not_reported")
        if (REFUSAL if outcome == "refused" else WITHHELD) not in stdout + stderr:
            raise Failure("refusal_status_missing")
    emit("claude_session", form=form, outcome=outcome, client_version=version, **fields)


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
