#!/usr/bin/env python3
"""Managed Kind only: Claude Code's own claude.ai login, kept by the workspace daemon.

The caller pipes this file into the actual workspace's python3, as with
codex_login.py, with a mode and its arguments. Protocol is pinned to Claude
Code 2.1.288. With a Claude sign-in selected, the hosted daemon keeps the
Sandbox creator's login as `claudeAiOauth` in Claude Code's own
`~/.claude/.credentials.json`, beside a top-level `codewireManaged` marker,
with a per-delivery placeholder refresh token (codewire-daemon
claude_home/login.rs). Stdout is the closed acceptance event stream: never a
token, header, file content, Claude Code output or digest. Only the fixture's
public synthetic token generation numbers are reported.

Modes, in the order the credential suite runs them:

  deliver MIN_GENERATION
        Codewire's login appears: 0600 in a 0700 ~/.claude, the marker, a
        placeholder refresh token with its nonce and never the broker's, the
        granted scopes, the Max plan and tier, and an access token of the
        fixture's sign-in generation MIN_GENERATION or later with at least 25
        minutes left. Stock Claude Code with the session user's own HOME then
        completes a turn presenting exactly that token in its OAuth form. A
        key unrelated to the login is then planted in the file; later modes
        prove the daemon keeps it.
  rotation PREVIOUS READY
        One long-lived stock Claude Code (`-p` with stream-json input) answers
        a turn with the delivered token of generation PREVIOUS or later, then
        creates the file READY so the suite reconnects the sign-in. Once the
        daemon has written the later generation, with a new nonce and the
        planted key kept, the same process answers a second turn presenting
        the new token: a re-delivered token is adopted without a restart.
  own-login
        A user's own login written in place of Codewire's stays untouched for
        a full check period; Codewire's file is then put back.
  logout
        `claudeAiOauth` is deleted with the marker and other keys kept, as
        Claude Code's /logout does; nothing is written for a full check period.
  redelivered
        After Stop/Start (a new container) the login is back.
  revoked
        After revocation `claudeAiOauth` and the marker are gone, and the
        planted key is kept.

Why the turns use a synthetic Messages backend on 127.0.0.1 rather than the
managed route: the broker drops the guest's bearer and injects the stored
token, so the provider cannot tell which token Claude Code held. Pointing only
this probe's Claude Code child at a loopback backend lets the probe see the
bearer Claude Code itself sends: the delivered login's access token, in
Claude Code's OAuth form. The managed route itself is proven by
claude_session.py's `sign_in` form in a daemon-launched session.

Why the probe's Claude Code has no route but loopback: a Kind Sandbox has
open egress, and stock Claude Code sends its own account calls (the OAuth
profile, claude.ai MCP servers, org settings) straight to api.anthropic.com
whatever `ANTHROPIC_BASE_URL` says. With the fixture's synthetic login the
real provider answers 401, Claude Code then refreshes with Codewire's
placeholder at the real token endpoint, and that `invalid_grant` makes it
clear the login on disk and drop its claude.ai headers until it re-reads the
file (#2891). A real Sandbox login is accepted there, so none of that happens
outside Kind. Every proxy variable of the probe's Claude Code therefore names
a loopback port that refuses connections, with only loopback exempt: no
synthetic credential or placeholder ever reaches a provider, and a login
Claude Code cleared itself fails the probe.

Why `logout` edits the file instead of running `claude auth logout`: stock
logout also asks platform.claude.com to revoke the placeholder, which must not
reach a provider; the daemon's rule depends only on the file it leaves, which
is what this mode writes.
"""

import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


CLAUDE = "/opt/codewire/agents/npm/bin/claude"
# How Claude Code is started; hermetic tests replace it with a synthetic program.
CLAUDE_COMMAND = (CLAUDE,)
HOME = Path("/home/codewire")
CLAUDE_DIR = HOME / ".claude"
CREDENTIALS = CLAUDE_DIR / ".credentials.json"
WORKDIR = "/workspace"
LOGIN_KEY = "claudeAiOauth"
MARKER_KEY = "codewireManaged"
PLACEHOLDER_PREFIX = "codewire-managed-no-refresh-token-"
NONCE = re.compile(r"[0-9a-f]{32}")
# The Kind credential fixture's public synthetic sign-in
# (credential-service runtime/kind/provider.rs).
ACCESS = re.compile(r"sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-([0-9]{6})")
FIXTURE_REFRESH = b"CW_KIND_SYNTHETIC_SIGN_IN_REFRESH"
CREDENTIAL_MARKER = b"CW_KIND_SYNTHETIC_SIGN_IN"
SCOPES = ["user:profile", "user:inference", "user:sessions:claude_code",
          "user:mcp_servers", "user:file_upload", "user:plugins"]
PLAN = "max"
TIER = "default_claude_max_20x"
OAUTH_BETA = "oauth-2025-04-20"
# The key `deliver` plants beside Codewire's: the daemon must keep every key
# that is not its own.
UNRELATED_KEY = "codewireKindUnrelated"
UNRELATED_VALUE = {"kept": True}
# A synthetic user login for `own-login`: its refresh token is not Codewire's.
USER_REFRESH = "kind-synthetic-user-refresh-token"
MARKER = "CWCLAUDELOGIN kind"
PROMPT = "CW_KIND_CLAUDE_LOGIN"
# The broker delivers a token with at least 30 minutes left.
MIN_VALIDITY_MS = 25 * 60 * 1000
MAX_CREDENTIALS = 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_OUTPUT = 8 * MAX_LINE
MAX_BODY = 4 * 1024 * 1024
READY = re.compile(r"/tmp/codewire-kind-claude-rotation-[0-9]{1,12}")
# The daemon checks the Claude login at the Codex login's period, at most
# CHECK_PERIOD apart once a login is delivered, so any FULL_CHECK window holds
# at least one check. configure() derives every window from the period the
# Kind deployment rendered into this container.
CHECK_PERIOD_ENV = "CODEWIRE_CODEX_LOGIN_CHECK_PERIOD_SECONDS"
CHECK_PERIOD = 120.0
FULL_CHECK = CHECK_PERIOD + 15.0
NEXT_CHECK = CHECK_PERIOD + 30.0
DELIVERY_TIMEOUT = 180.0
# How long the suite may take to reconnect the sign-in after READY.
RECONNECT_ALLOWANCE = 240.0
TURN_TIMEOUT = 120.0
SHUTDOWN_GRACE = 5.0
POLL = 1.0
MODES = {"deliver", "rotation", "own-login", "logout", "redelivered", "revoked"}
ARGUMENTS = {"deliver": 1, "rotation": 2, "own-login": 0, "logout": 0,
             "redelivered": 0, "revoked": 0}
# The Anthropic names the sign-in form leaves to Claude Code's own login.
OUTRANKING = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
SIGN_IN_SELECTIONS = {f"v2:{bits:02x}" for bits in
                      (0x44, 0x45, 0x46, 0x47, 0x4c, 0x4d, 0x4e, 0x4f,
                       0x54, 0x55, 0x56, 0x57, 0x5c, 0x5d, 0x5e, 0x5f)}
MANAGED_BASE_URL = "http://127.0.0.1:38081/_codewire/anthropic"


class Failure(Exception):
    """Only fixed reason identifiers may enter the public event stream."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Failure("duplicate_json_field")
        result[key] = value
    return result


def read_private(path, limit=MAX_CREDENTIALS):
    """(mode, bytes) of a regular file of this uid, never through a symlink;
    None when absent."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise Failure("login_file_not_regular") from None
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid():
        os.close(descriptor)
        raise Failure("login_file_not_regular")
    with os.fdopen(descriptor, "rb") as source:
        contents = source.read(limit + 1)
    if len(contents) > limit:
        raise Failure("login_file_limit")
    return stat.S_IMODE(status.st_mode), contents


def parse(contents):
    """The file's JSON object, or None while it does not parse (Claude Code or
    the daemon may be rewriting it)."""
    try:
        document = json.loads(contents, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        return None
    return document if isinstance(document, dict) else None


def generation_of(token):
    match = ACCESS.fullmatch(token) if isinstance(token, str) else None
    if match is None:
        raise Failure("access_token_not_fixtures")
    return int(match.group(1))


def delivered(now_ms=None):
    """Validate Codewire's delivered login. Returns (generation, nonce), or
    None while the file or its login is absent."""
    found = read_private(CREDENTIALS)
    if found is None:
        return None
    mode, contents = found
    document = parse(contents)
    if document is None:
        return None
    login = document.get(LOGIN_KEY)
    if login is None:
        return None
    refresh = login.get("refreshToken") if isinstance(login, dict) else None
    if refresh == "" and document.get(MARKER_KEY) == 1:
        # Claude Code cleared Codewire's login after its own refresh with the
        # placeholder was refused. The daemon would rewrite it, but nothing
        # here may make Claude Code refresh: it reached a token endpoint.
        raise Failure("login_cleared_by_claude")
    if not isinstance(refresh, str) or not refresh.startswith(PLACEHOLDER_PREFIX):
        raise Failure("login_not_codewires")
    if not NONCE.fullmatch(refresh[len(PLACEHOLDER_PREFIX):]):
        raise Failure("placeholder_nonce")
    if document.get(MARKER_KEY) != 1:
        raise Failure("marker_missing")
    if mode != 0o600:
        raise Failure("login_file_mode")
    try:
        directory = os.lstat(CLAUDE_DIR)
    except OSError:
        raise Failure("login_directory") from None
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) & 0o077):
        raise Failure("login_directory")
    # The broker's refresh token never leaves Codewire.
    if FIXTURE_REFRESH in contents:
        raise Failure("refresh_token_delivered")
    if set(login) - {"accessToken", "refreshToken", "expiresAt", "scopes",
                     "subscriptionType", "rateLimitTier"}:
        raise Failure("login_shape")
    expires = login.get("expiresAt")
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if type(expires) is not int or expires < now_ms + MIN_VALIDITY_MS:
        raise Failure("login_expiry")
    if (login.get("scopes") != SCOPES or login.get("subscriptionType") != PLAN
            or login.get("rateLimitTier") != TIER):
        raise Failure("login_shape")
    return generation_of(login.get("accessToken")), refresh[len(PLACEHOLDER_PREFIX):]


def unrelated_kept():
    found = read_private(CREDENTIALS)
    document = parse(found[1]) if found is not None else None
    return document is not None and document.get(UNRELATED_KEY) == UNRELATED_VALUE


def kept(document, key, value):
    """The closed state of one member for an event: never its value."""
    return "kept" if document is not None and document.get(key) == value else "absent"


def wait_for(condition, timeout, reason):
    """The first result of condition() that is neither None nor False (0 is
    a result), or Failure(reason) after timeout."""
    deadline = time.monotonic() + timeout
    while True:
        result = condition()
        if result is not None and result is not False:
            return result
        if time.monotonic() >= deadline:
            raise Failure(reason)
        time.sleep(POLL)


def write_in_place(contents):
    """Rewrite the file as Claude Code does: in place, never through a link."""
    descriptor = os.open(CREDENTIALS, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "wb") as target:
        target.write(contents)
        target.flush()
        os.fsync(target.fileno())


def validate_projection():
    """The exec environment is the Pod's: an environment-token Pod renders the
    sign-in selection and the base URL alone; an identity-free Pod renders
    neither. Nothing that would outrank the delivered login is present."""
    selection = os.environ.get("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS")
    base = os.environ.get("ANTHROPIC_BASE_URL")
    if (any(name in os.environ for name in OUTRANKING)
            or (selection, base) != (None, None)
            and (selection not in SIGN_IN_SELECTIONS or base != MANAGED_BASE_URL)):
        raise Failure("unexpected_projection")


SSE = "".join(
    f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"
    for name, data in (
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_codewire_kind_login", "type": "message", "role": "assistant",
            "model": "claude-sonnet-4-6", "content": [], "stop_reason": None,
            "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": MARKER}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta",
                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    )
).encode()


# The most refused requests whose credential form a failure reports.
MAX_REJECTIONS = 8


def credential_form(headers):
    """The closed form of the credential one request presented, and whether it
    carried the OAuth beta: never a value."""
    authorization = headers.get_all("Authorization") or []
    keys = headers.get_all("x-api-key") or []
    betas = headers.get_all("anthropic-beta") or []
    oauth_beta = any(OAUTH_BETA in [part.strip() for part in beta.split(",")] for beta in betas)
    bearer = authorization[0][len("Bearer "):] if authorization and \
        authorization[0].startswith("Bearer ") else ""
    if len(authorization) + len(keys) > 1:
        form = "several"
    elif keys:
        form = "api_key"
    elif not authorization:
        form = "none"
    elif not bearer.strip():
        form = "malformed_bearer"
    elif ACCESS.fullmatch(bearer):
        form = "fixture_bearer"
    else:
        form = "other_bearer"
    return form, oauth_beta, int(ACCESS.fullmatch(bearer).group(1)) if form == "fixture_bearer" else None


class Backend:
    """A synthetic Anthropic Messages API on loopback. It records the fixture
    generation of every bearer Claude Code presents (never the bearer), and
    answers any other credential 403, never 401: Claude Code would then try to
    refresh with the placeholder. A refused request keeps only its closed
    credential form, whether it carried the OAuth beta and, for a fixture
    bearer, its public generation.

    It also holds a loopback port bound but never listening: Claude Code's
    proxy for every host but loopback, so its own account calls are refused
    at once instead of reaching a provider."""

    def __init__(self):
        self.lock = threading.Lock()
        self.generations = []
        self.rejected = 0
        self.rejections = []
        self.unknown = 0
        self.no_route = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.no_route.bind(("127.0.0.1", 0))
        backend = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                backend.handle(self, "GET")

            def do_POST(self):
                backend.handle(self, "POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def respond(self, request, status, body=b"", content_type="application/json"):
        request.close_connection = True
        request.send_response(status)
        request.send_header("Content-Type", content_type)
        request.send_header("Content-Length", str(len(body)))
        request.send_header("Connection", "close")
        request.end_headers()
        if body:
            request.wfile.write(body)

    def handle(self, request, method):
        try:
            self.route(request, method)
        except Exception:
            with self.lock:
                self.unknown += 1
            try:
                self.respond(request, 500)
            except OSError:
                pass

    def generation(self, request):
        """The fixture generation of a lone OAuth bearer, else None."""
        authorization = request.headers.get_all("Authorization") or []
        betas = request.headers.get_all("anthropic-beta") or []
        if (len(authorization) != 1 or request.headers.get_all("x-api-key")
                or not authorization[0].startswith("Bearer ")
                or not any(OAUTH_BETA in [part.strip() for part in beta.split(",")]
                           for beta in betas)):
            return None
        match = ACCESS.fullmatch(authorization[0][len("Bearer "):])
        return int(match.group(1)) if match else None

    def route(self, request, method):
        path = request.path.split("?", 1)[0]
        if method != "POST" or path not in ("/v1/messages", "/v1/messages/count_tokens"):
            with self.lock:
                self.unknown += 1
            return self.respond(request, 404)
        generation = self.generation(request)
        if generation is None:
            form, oauth_beta, presented = credential_form(request.headers)
            rejection = {"route": "count_tokens" if path.endswith("/count_tokens") else "messages",
                         "credential": form, "oauth_beta": oauth_beta}
            if presented is not None:
                rejection["generation"] = presented
            with self.lock:
                self.rejected += 1
                if len(self.rejections) < MAX_REJECTIONS:
                    self.rejections.append(rejection)
            return self.respond(request, 403, json.dumps({
                "type": "error", "error": {"type": "permission_error",
                                           "message": "synthetic Kind refusal"}}).encode())
        length = request.headers.get("Content-Length")
        if length is None or not length.isdigit() or int(length) > MAX_BODY:
            with self.lock:
                self.unknown += 1
            return self.respond(request, 400)
        body = parse(request.rfile.read(int(length)))
        if body is None:
            with self.lock:
                self.unknown += 1
            return self.respond(request, 400)
        with self.lock:
            self.generations.append(generation)
        if path.endswith("/count_tokens"):
            return self.respond(request, 200, b'{"input_tokens":1}')
        if body.get("stream") is True:
            return self.respond(request, 200, SSE, "text/event-stream")
        return self.respond(request, 200, json.dumps({
            "id": "msg_codewire_kind_login", "type": "message", "role": "assistant",
            "model": "claude-sonnet-4-6", "content": [{"type": "text", "text": MARKER}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}).encode())

    def take(self):
        """The generations seen since the last take, and whether anything
        was refused or unknown."""
        with self.lock:
            seen, self.generations = self.generations, []
            return seen, self.rejected, self.unknown

    def refused(self):
        """Fail the turn for its refused credential, naming the forms seen."""
        with self.lock:
            rejections = list(self.rejections)
        emit("backend_rejected", rejections=rejections)
        raise Failure("backend_rejected")

    @property
    def no_route_url(self):
        return f"http://127.0.0.1:{self.no_route.getsockname()[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.no_route.close()


# Claude Code's proxy variables; each names the backend's refusing port.
PROXIES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def claude_environment(backend):
    """The exec environment for stock Claude Code: the session user's own
    HOME, where the delivered login lives, and this probe's loopback backend
    as its only API base. Nothing that would outrank the login, and no route
    to any host but loopback (see the module documentation)."""
    environment = {name: value for name, value in os.environ.items()
                   if name not in OUTRANKING}
    environment.update({
        "HOME": str(HOME),
        "ANTHROPIC_BASE_URL": backend.base_url,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        **{name: backend.no_route_url for name in PROXIES},
    })
    return environment


class Claude:
    """One stock `claude -p` with stream-json input and output: one process
    for every turn of a mode."""

    def __init__(self, backend):
        argv = [*CLAUDE_COMMAND, "-p", "--input-format", "stream-json",
                "--output-format", "stream-json", "--verbose"]
        self.pending = bytearray()
        self.total = 0
        self.results = []
        try:
            self.process = subprocess.Popen(
                argv, cwd=WORKDIR, env=claude_environment(backend),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True, bufsize=0,
            )
        except OSError:
            raise Failure("claude_start") from None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def feed(self, data):
        self.total += len(data)
        if self.total > MAX_OUTPUT:
            raise Failure("claude_output_limit")
        if CREDENTIAL_MARKER in data or FIXTURE_REFRESH in data:
            raise Failure("credential_in_output")
        self.pending.extend(data)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            if not line.strip():
                continue
            if len(line) > MAX_LINE:
                raise Failure("claude_line_limit")
            value = parse(bytes(line))
            if value is not None and value.get("type") == "result":
                self.results.append(value)
        if len(self.pending) > MAX_LINE:
            raise Failure("claude_line_limit")

    def pump(self, timeout):
        for key, _ in self.selector.select(max(0, timeout)):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                raise Failure("claude_exited")
            self.feed(data)
        if self.process.poll() is not None:
            raise Failure("claude_exited")

    def turn(self):
        """Send one user turn and wait for its result."""
        before = len(self.results)
        message = {"type": "user", "message": {"role": "user", "content": PROMPT},
                   "parent_tool_use_id": None, "session_id": "default"}
        try:
            self.process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
            self.process.stdin.flush()
        except OSError:
            raise Failure("claude_input_closed") from None
        deadline = time.monotonic() + TURN_TIMEOUT
        while len(self.results) == before:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("turn_timeout")
            self.pump(min(remaining, 0.25))
        result = self.results[before]
        if (result.get("subtype") != "success" or result.get("is_error") is not False
                or MARKER not in str(result.get("result", ""))):
            raise Failure("turn_failed")

    def close(self):
        try:
            self.process.stdin.close()
        except OSError:
            pass
        for next_signal in (None, signal.SIGTERM, signal.SIGKILL):
            if next_signal is not None:
                try:
                    os.killpg(self.process.pid, next_signal)
                except ProcessLookupError:
                    pass
            try:
                self.process.wait(timeout=SHUTDOWN_GRACE)
                break
            except subprocess.TimeoutExpired:
                continue
        self.selector.close()
        self.process.stdout.close()


def turn_generations(backend, claude):
    """One turn; the single generation every request of it presented. A turn
    the backend refused for its credential names that, not the failed turn."""
    try:
        claude.turn()
    except Failure:
        if backend.take()[1]:
            backend.refused()
        raise
    seen, rejected, _unknown = backend.take()
    if rejected:
        backend.refused()
    if not seen:
        raise Failure("turn_never_reached_backend")
    if len(set(seen)) != 1:
        raise Failure("turn_mixed_tokens")
    return seen[0], len(seen)


def plant_unrelated():
    """Add a key Codewire does not own, in place, as another tool would."""
    found = read_private(CREDENTIALS)
    document = parse(found[1]) if found is not None else None
    if document is None:
        raise Failure("login_not_delivered")
    document[UNRELATED_KEY] = UNRELATED_VALUE
    write_in_place(json.dumps(document, indent=2).encode())


def deliver(minimum):
    def current():
        login = delivered()
        return login if login is not None and login[0] >= minimum else None

    generation, nonce = wait_for(current, DELIVERY_TIMEOUT, "login_not_delivered")
    backend = Backend()
    claude = None
    try:
        claude = Claude(backend)
        presented, requests = turn_generations(backend, claude)
    finally:
        if claude is not None:
            claude.close()
        backend.close()
    if presented != generation:
        raise Failure("turn_used_another_token")
    # Claude Code itself never rewrote the delivered login.
    if delivered() != (generation, nonce):
        raise Failure("login_changed_during_turn")
    plant_unrelated()
    emit("delivered", generation=generation, file_mode="0600", directory_mode="0700",
         refresh_token="placeholder", plan=PLAN, scopes=len(SCOPES), requests=requests)


def rotation(previous, ready):
    login = delivered()
    if login is None:
        raise Failure("login_not_delivered")
    generation, nonce = login
    if generation < previous:
        raise Failure("login_older_than_previous")
    if not unrelated_kept():
        raise Failure("unrelated_key_dropped")
    backend = Backend()
    claude = None
    started = None
    try:
        claude = Claude(backend)
        first, _ = turn_generations(backend, claude)
        if first != generation:
            raise Failure("turn_used_another_token")
        # The suite reconnects the sign-in once this file exists.
        try:
            os.close(os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600))
        except OSError:
            raise Failure("ready_file") from None
        started = time.monotonic()

        def rotated():
            # The FILE, not Claude Code's memory: the daemon's next check
            # rewrites it.
            current = delivered()
            return current if current is not None and current[0] > generation else None

        later, later_nonce = wait_for(rotated, RECONNECT_ALLOWANCE + NEXT_CHECK,
                                      "rotation_not_delivered")
        waited = time.monotonic() - started
        if later_nonce == nonce:
            raise Failure("nonce_unchanged")
        if not unrelated_kept():
            raise Failure("unrelated_key_dropped")
        second, _ = turn_generations(backend, claude)
        if claude.process.poll() is not None:
            raise Failure("claude_exited")
    finally:
        if claude is not None:
            claude.close()
        backend.close()
    if second != later:
        raise Failure("rotation_not_adopted")
    emit("rotation_adopted", previous=generation, generation=later, nonce="changed",
         first_turn=first, second_turn=second, restarted=False,
         waited_ms=int(waited * 1000))


def own_login():
    if delivered() is None:
        raise Failure("login_not_delivered")
    codewires = read_private(CREDENTIALS)[1]
    document = parse(codewires)
    # Reported, not judged: whether the key `deliver` planted reached here.
    unrelated = kept(document, UNRELATED_KEY, UNRELATED_VALUE)
    # `claude /login` rewrites claudeAiOauth with its own refresh token and
    # keeps every other key, Codewire's marker included.
    document[LOGIN_KEY] = {
        "accessToken": "kind-synthetic-user-access-token",
        "refreshToken": USER_REFRESH,
        "expiresAt": int(time.time() * 1000) + 3_600_000,
        "scopes": SCOPES,
        "subscriptionType": PLAN,
    }
    users = json.dumps(document, indent=2).encode()
    write_in_place(users)
    try:
        time.sleep(FULL_CHECK)
        found = read_private(CREDENTIALS)
        if found is None or found[1] != users or found[0] != 0o600:
            raise Failure("own_login_touched")
    finally:
        # Put Codewire's file back only over this synthetic user login.
        current = read_private(CREDENTIALS)
        if current is not None and current[1] == users:
            write_in_place(codewires)
    emit("own_login_untouched", unrelated=unrelated, waited_ms=int(FULL_CHECK * 1000))


def logout():
    if delivered() is None:
        raise Failure("login_not_delivered")
    document = parse(read_private(CREDENTIALS)[1])
    del document[LOGIN_KEY]
    logged_out = json.dumps(document, indent=2).encode()
    write_in_place(logged_out)
    time.sleep(FULL_CHECK)
    found = read_private(CREDENTIALS)
    current = parse(found[1]) if found is not None else None
    if current is None or LOGIN_KEY in current:
        raise Failure("logout_undone")
    emit("logout_stays_logged_out", marker=kept(current, MARKER_KEY, 1),
         unrelated=kept(current, UNRELATED_KEY, UNRELATED_VALUE),
         waited_ms=int(FULL_CHECK * 1000))


def redelivered():
    generation, _ = wait_for(delivered, DELIVERY_TIMEOUT, "login_not_redelivered")
    found = read_private(CREDENTIALS)
    document = parse(found[1]) if found is not None else None
    # How many members are neither Codewire's nor the planted key: a count,
    # never a name or value.
    others = len(set(document or ()) - {LOGIN_KEY, MARKER_KEY, UNRELATED_KEY})
    emit("redelivered", generation=generation,
         unrelated=kept(document, UNRELATED_KEY, UNRELATED_VALUE), other_keys=others)


def revoked():
    started = time.monotonic()

    def removed():
        found = read_private(CREDENTIALS)
        document = parse(found[1]) if found is not None else None
        return document is not None and LOGIN_KEY not in document \
            and MARKER_KEY not in document

    wait_for(removed, NEXT_CHECK, "revoked_login_kept")
    if not unrelated_kept():
        raise Failure("unrelated_key_dropped")
    emit("revoked_login_removed", unrelated="kept",
         waited_ms=int((time.monotonic() - started) * 1000))


def configure(environ):
    """Derive every window from the period the daemon was given: whole
    seconds from 10 to 120, as it accepts them. Unset keeps 120 seconds."""
    global CHECK_PERIOD, FULL_CHECK, NEXT_CHECK
    value = environ.get(CHECK_PERIOD_ENV)
    if value is None:
        return
    if not re.fullmatch(r"[1-9][0-9]{0,2}", value) or not 10 <= int(value) <= 120:
        raise Failure("check_period")
    CHECK_PERIOD = float(value)
    FULL_CHECK = CHECK_PERIOD + 15.0
    NEXT_CHECK = CHECK_PERIOD + 30.0


def arguments(argv):
    mode = argv[0] if argv else None
    if mode not in MODES or len(argv) != 1 + ARGUMENTS[mode]:
        raise Failure("arguments")
    if mode == "deliver":
        if not re.fullmatch(r"[1-9][0-9]{0,8}", argv[1]):
            raise Failure("arguments")
        return mode, (int(argv[1]),)
    if mode == "rotation":
        if not re.fullmatch(r"[1-9][0-9]{0,8}", argv[1]) or not READY.fullmatch(argv[2]):
            raise Failure("arguments")
        return mode, (int(argv[1]), argv[2])
    return mode, ()


def main(argv):
    mode = argv[0] if argv and argv[0] in MODES else None

    def interrupted(_signum, _frame):
        raise Failure("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        mode, values = arguments(argv)
        configure(os.environ)
        validate_projection()
        {
            "deliver": deliver,
            "rotation": rotation,
            "own-login": own_login,
            "logout": logout,
            "redelivered": redelivered,
            "revoked": revoked,
        }[mode](*values)
    except Failure as error:
        emit("failed", mode=mode, reason=str(error))
        return 1
    except Exception:
        emit("failed", mode=mode, reason="driver_failure")
        return 1
    emit("complete", mode=mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
