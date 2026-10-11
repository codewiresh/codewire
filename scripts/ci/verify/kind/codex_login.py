#!/usr/bin/env python3
"""Managed Kind only: Codex's own ChatGPT login, kept by the workspace daemon.

The caller pipes this file into the actual workspace's python3, as with
codex_session.py, with one mode argument. Protocol is pinned to Codex 0.160.0
commit a956835d020762cb2b570053af06f643a11c0ecc. The synthetic ChatGPT backend
listens only on 127.0.0.1 and accepts only the bearer the daemon delivered.
Stdout is the closed acceptance event stream: never a token, header, file
content, RPC payload, Codex stderr or digest.

Modes, in the order the credential suite runs them:

  deliver              Codewire's auth.json appears: 0600, three-part JWTs,
                       the placeholder refresh token and never the broker's.
                       Stock Codex reads the account as ChatGPT, reads usage
                       (wham/usage) and completes a turn against the synthetic
                       backend with the delivered bearer.
  rotation GENERATION  The file holds a later synthetic token generation at
                       the daemon's next check after the broker refreshed.
  own-login            A user's own login written in place of Codewire's stays
                       untouched for a full check period; Codewire's file is
                       then put back.
  logout               Stock `codex logout` revokes only the placeholder and
                       deletes the file; the daemon records the logout and
                       writes nothing for a full check period.
  redelivered          After Stop/Start (a new container) the login is back.
  revoked              After revocation Codewire's auth.json is gone and its
                       proxy config.toml is back.
"""

import base64
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


CODEX = "/opt/codewire/agents/npm/bin/codex"
# How Codex is started; hermetic tests replace it with a synthetic program.
CODEX_COMMAND = (CODEX,)
CODEX_HOME = Path("/home/codewire/.codex")
WORKDIR = "/workspace"
AUTH = CODEX_HOME / "auth.json"
CONFIG = CODEX_HOME / "config.toml"
# The daemon's container-local logout record (codex_home/login.rs).
STATE = Path("/tmp/codewire-codex-login")
MANAGED_HEADER = b"# Managed by Codewire. Delete this line to manage this file yourself."
PLACEHOLDER = "codewire-managed-no-refresh-token"
# The Kind credential fixture's public synthetic identity.
ACCOUNT = "codewire-kind-synthetic-account"
FIXTURE_TOKEN = "codewire-kind-credential-fixture"
FIXTURE_REFRESH_PREFIX = b"CW_KIND_SYNTHETIC_REFRESH_"
PLAN = "plus"
MARKER = "CWCODEXLOGIN kind"
PROMPT = "CW_KIND_CHATGPT_LOGIN"
MAX_AUTH = 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_OUTPUT = 8 * MAX_LINE
MAX_BODY = 4 * 1024 * 1024
# The daemon checks at most CHECK_PERIOD apart once a login is delivered, so
# any FULL_CHECK window holds at least one check.
CHECK_PERIOD = 120.0
FULL_CHECK = CHECK_PERIOD + 15.0
NEXT_CHECK = CHECK_PERIOD + 30.0
DELIVERY_TIMEOUT = 180.0
# The check that writes auth.json removes Codewire's config.toml right after.
CONFIG_REMOVAL_TIMEOUT = 10.0
RPC_TIMEOUT = 60.0
SHUTDOWN_GRACE = 5.0
POLL = 1.0
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
MODES = {"deliver", "rotation", "own-login", "logout", "redelivered", "revoked"}

SSE = "".join(
    f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
    for event in (
        {"type": "response.created", "response": {"id": "resp_codewire_kind_login"}},
        {"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant", "id": "msg_codewire_kind_login",
            "content": [{"type": "output_text", "text": MARKER}]}},
        {"type": "response.completed", "response": {
            "id": "resp_codewire_kind_login", "usage": {
                "input_tokens": 0, "input_tokens_details": None, "output_tokens": 0,
                "output_tokens_details": None, "total_tokens": 0}}},
    )
).encode()


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


def read_private(path, limit=MAX_AUTH):
    """(mode, bytes) of a regular file of this uid, never through a symlink;
    None when absent."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise Failure("auth_file_not_regular") from None
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid():
        os.close(descriptor)
        raise Failure("auth_file_not_regular")
    with os.fdopen(descriptor, "rb") as source:
        contents = source.read(limit + 1)
    if len(contents) > limit:
        raise Failure("auth_file_limit")
    return stat.S_IMODE(status.st_mode), contents


def jwt_claims(token):
    """Unverified claims of a three-part JWT, read the way Codex reads them."""
    if not isinstance(token, str):
        raise Failure("token_shape")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise Failure("token_shape")
    try:
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(payload, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise Failure("token_claims") from None
    if not isinstance(claims, dict):
        raise Failure("token_claims")
    return claims


def codewire_login(contents):
    """The parsed document when it is Codewire's file, else None."""
    try:
        document = json.loads(contents, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(document, dict) or document.get("auth_mode") != "chatgpt":
        return None
    tokens = document.get("tokens")
    if not isinstance(tokens, dict) or tokens.get("refresh_token") != PLACEHOLDER:
        return None
    return document


def delivered_generation(now=None):
    """Validate Codewire's delivered login and return its synthetic access
    token generation; None while the file is absent."""
    found = read_private(AUTH)
    if found is None:
        return None
    mode, contents = found
    document = codewire_login(contents)
    if document is None:
        raise Failure("auth_file_not_codewires")
    if mode != 0o600:
        raise Failure("auth_file_mode")
    # The broker's refresh token never leaves Codewire.
    if FIXTURE_REFRESH_PREFIX in contents:
        raise Failure("refresh_token_delivered")
    tokens = document["tokens"]
    if (document.get("OPENAI_API_KEY", "missing") is not None
            or tokens.get("account_id") != ACCOUNT
            or not isinstance(document.get("last_refresh"), str)
            or not RFC3339.fullmatch(document["last_refresh"])):
        raise Failure("auth_file_shape")
    identity = jwt_claims(tokens.get("id_token"))
    auth_claims = identity.get("https://api.openai.com/auth")
    if (not isinstance(auth_claims, dict)
            or auth_claims.get("chatgpt_account_id") != ACCOUNT
            or auth_claims.get("chatgpt_plan_type") != PLAN):
        raise Failure("id_token_claims")
    access = jwt_claims(tokens.get("access_token"))
    generation = access.get("generation")
    expiry = access.get("exp")
    if (access.get("synthetic") != FIXTURE_TOKEN
            or type(generation) is not int or generation < 0
            or type(expiry) is not int
            or expiry <= (time.time() if now is None else now)):
        raise Failure("access_token_claims")
    return generation


def managed_config():
    """Whether config.toml is Codewire's: regular, not a symlink, first line
    exactly the managed header."""
    try:
        if not stat.S_ISREG(os.lstat(CONFIG).st_mode):
            return False
        descriptor = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    with os.fdopen(descriptor, "rb") as source:
        return source.read(64 * 1024 + 1).split(b"\n", 1)[0] == MANAGED_HEADER


def logout_markers():
    """The daemon's logout records, or None when there are none."""
    try:
        return sorted(path.name for path in STATE.glob("generation-*.logged-out.*")) or None
    except OSError:
        return None


def validate_projection():
    # Like codex_session.py: an environment-token Pod renders the selection
    # and CODEX_HOME; an identity-free Pod renders neither.
    rendered = (os.environ.get("CODEX_HOME"),
                os.environ.get("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"))
    if (rendered not in {(None, None), (str(CODEX_HOME), "v1:codex")}
            or "CODEX_CA_CERTIFICATE" in os.environ
            or Path(CODEX_HOME).resolve() != CODEX_HOME):
        raise Failure("unexpected_projection")


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


class Backend:
    """The synthetic ChatGPT backend: two loopback origins, as Codex needs
    for its inference base and its ChatGPT base. Never answers 401: Codex
    would then try to refresh with the placeholder."""

    def __init__(self, bearer):
        self.bearer = bearer
        self.lock = threading.Lock()
        self.routes = {}
        self.rejected = 0
        self.unknown = 0
        self.refreshes = 0
        self.revocations = []
        backend = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                backend.handle(self, "GET")

            def do_POST(self):
                backend.handle(self, "POST")

        self.openai = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.chatgpt = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.openai.daemon_threads = self.chatgpt.daemon_threads = True
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                        for server in (self.openai, self.chatgpt)]
        for thread in self.threads:
            thread.start()

    def url(self, server, path):
        return f"http://127.0.0.1:{server.server_address[1]}{path}"

    @property
    def openai_base_url(self):
        return self.url(self.openai, "/backend-api/codex")

    @property
    def chatgpt_base_url(self):
        return self.url(self.chatgpt, "/backend-api/")

    def environment(self):
        # Codex's own overrides: a refresh or revocation stays on loopback.
        return {
            **os.environ,
            "CODEX_REFRESH_TOKEN_URL_OVERRIDE": self.url(self.chatgpt, "/oauth/token"),
            "CODEX_REVOKE_TOKEN_URL_OVERRIDE": self.url(self.chatgpt, "/oauth/revoke"),
        }

    def count(self, name):
        with self.lock:
            self.routes[name] = self.routes.get(name, 0) + 1

    def authorized(self, request):
        return (request.headers.get("Authorization") == f"Bearer {self.bearer}"
                and request.headers.get("ChatGPT-Account-ID") == ACCOUNT)

    def respond(self, request, status, body=b"", content_type="application/json"):
        request.close_connection = True
        request.send_response(status)
        request.send_header("Content-Type", content_type)
        request.send_header("Content-Length", str(len(body)))
        request.send_header("Connection", "close")
        request.end_headers()
        if body:
            request.wfile.write(body)

    def json(self, request, value):
        self.respond(request, 200, json.dumps(value).encode())

    def body(self, request):
        length = request.headers.get("Content-Length")
        if length is None or not length.isdigit() or int(length) > MAX_BODY:
            return None
        return request.rfile.read(int(length))

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

    def route(self, request, method):
        server = request.server
        path = request.path.split("?", 1)[0]
        if server is self.chatgpt and method == "POST" and path == "/oauth/revoke":
            body = self.body(request)
            try:
                value = json.loads(body or b"null")
            except ValueError:
                value = None
            if not isinstance(value, dict):
                value = {}
            with self.lock:
                self.revocations.append((value.get("token_type_hint"),
                                         value.get("token") == PLACEHOLDER))
            return self.json(request, {})
        if server is self.chatgpt and method == "POST" and path == "/oauth/token":
            with self.lock:
                self.refreshes += 1
            return self.respond(request, 503)
        if not self.authorized(request):
            with self.lock:
                self.rejected += 1
            return self.respond(request, 403)
        if server is self.chatgpt and method == "GET":
            if path == "/backend-api/wham/accounts/check":
                self.count("accounts_check")
                return self.json(request, {"accounts": [{
                    "id": ACCOUNT, "workspace_backend_origin": "https://chatgpt.com",
                    "account_routing_override": "NO_CONSTRAINT"}]})
            if path == "/backend-api/wham/usage":
                self.count("usage")
                return self.json(request, {"plan_type": PLAN, "rate_limit": {
                    "allowed": True, "limit_reached": False, "primary_window": {
                        "used_percent": 12, "limit_window_seconds": 18000,
                        "reset_after_seconds": 3600, "reset_at": int(time.time()) + 3600}}})
            if path == "/backend-api/wham/settings/user":
                self.count("settings")
                return self.json(request, {"commit_attribution_enabled": False})
            if path == "/backend-api/wham/config/bundle":
                self.count("config_bundle")
                return self.json(request, {})
        if server is self.openai:
            if method == "GET" and path == "/backend-api/codex/models":
                self.count("models")
                return self.json(request, {"models": []})
            if method == "GET" and path == "/backend-api/codex/responses":
                # Codex prefers WebSockets; 426 makes it fall back to HTTP.
                self.count("websocket")
                return self.respond(request, 426)
            if method == "POST" and path == "/backend-api/codex/responses":
                body = self.body(request)
                try:
                    value = json.loads(body or b"null")
                except ValueError:
                    value = None
                if not isinstance(value, dict) or "input" not in value:
                    with self.lock:
                        self.unknown += 1
                    return self.respond(request, 400)
                self.count("responses")
                return self.respond(request, 200, SSE, "text/event-stream")
        with self.lock:
            self.unknown += 1
        self.respond(request, 404)

    def close(self):
        for server in (self.openai, self.chatgpt):
            server.shutdown()
            server.server_close()


class Codex:
    """One stock `codex app-server --stdio` with a minimal JSON-RPC driver."""

    def __init__(self, backend):
        self.argv = [
            *CODEX_COMMAND, "app-server", "--stdio", "--strict-config",
            "-c", f'openai_base_url="{backend.openai_base_url}"',
            "-c", f'chatgpt_base_url="{backend.chatgpt_base_url}"',
            # The synthetic backend reads plain JSON bodies.
            "-c", "features.enable_request_compression=false",
            # No background traffic the synthetic backend does not serve.
            "-c", "features.apps=false",
            "-c", "features.plugins=false",
            "-c", "analytics.enabled=false",
        ]
        self.pending = bytearray()
        self.total = 0
        self.responses = {}
        self.completed = {}
        self.markers = set()
        self.next_id = 0
        try:
            self.process = subprocess.Popen(
                self.argv, cwd=WORKDIR, env=backend.environment(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True, bufsize=0,
            )
        except OSError:
            raise Failure("codex_start") from None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def feed(self, data):
        self.total += len(data)
        if self.total > MAX_OUTPUT:
            raise Failure("rpc_output_limit")
        self.pending.extend(data)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            if not line or len(line) > MAX_LINE:
                raise Failure("invalid_rpc_line")
            try:
                value = json.loads(line, object_pairs_hook=unique_object)
            except (ValueError, UnicodeError):
                raise Failure("invalid_rpc_json") from None
            if not isinstance(value, dict):
                raise Failure("invalid_rpc_shape")
            self.receive(value)
        if len(self.pending) > MAX_LINE:
            raise Failure("rpc_line_limit")

    def receive(self, value):
        if "id" in value:
            if "method" in value:
                raise Failure("unexpected_server_request")
            if value["id"] in self.responses or ("result" in value) == ("error" in value):
                raise Failure("invalid_rpc_response")
            self.responses[value["id"]] = value
            return
        params = value.get("params")
        if not isinstance(params, dict):
            return
        if value.get("method") == "item/completed":
            item = params.get("item")
            if isinstance(item, dict) and item.get("type") == "agentMessage":
                if item.get("text") != MARKER:
                    raise Failure("unexpected_agent_output")
                self.markers.add((params.get("threadId"), params.get("turnId")))
        elif value.get("method") == "turn/completed":
            turn = params.get("turn")
            if isinstance(turn, dict):
                self.completed[(params.get("threadId"), turn.get("id"))] = turn

    def pump(self, timeout):
        for key, _ in self.selector.select(max(0, timeout)):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                raise Failure("codex_exited")
            self.feed(data)
        if self.process.poll() is not None:
            raise Failure("codex_exited")

    def until(self, predicate, deadline):
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("rpc_timeout")
            self.pump(min(remaining, 0.25))

    def send(self, value):
        encoded = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        try:
            self.process.stdin.write(encoded)
            self.process.stdin.flush()
        except OSError:
            raise Failure("codex_input_closed") from None

    def request(self, method, params):
        self.next_id += 1
        request_id = self.next_id
        self.send({"id": request_id, "method": method, "params": params})
        self.until(lambda: request_id in self.responses, time.monotonic() + RPC_TIMEOUT)
        response = self.responses.pop(request_id)
        if "error" in response or not isinstance(response.get("result"), dict):
            raise Failure(f"rpc_rejected_{method.replace('/', '_')}")
        return response["result"]

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


def chatgpt_session(backend):
    """Account, usage and one turn through Codex's built-in provider."""
    codex = Codex(backend)
    try:
        result = codex.request("initialize", {"clientInfo": {
            "name": "codewire_kind_login", "title": "Codewire Kind", "version": "1"}})
        if result.get("codexHome") != str(CODEX_HOME):
            raise Failure("unexpected_codex_home")
        codex.send({"method": "initialized"})
        account = codex.request("account/read", {"refreshToken": False}).get("account")
        if not isinstance(account, dict) or account.get("type") != "chatgpt" \
                or account.get("planType") != PLAN:
            raise Failure("account_not_chatgpt")
        limits = codex.request("account/rateLimits/read",
                               {"excludeResetCreditDetails": True}).get("rateLimits")
        primary = limits.get("primary") if isinstance(limits, dict) else None
        if (not isinstance(primary, dict) or primary.get("usedPercent") != 12
                or primary.get("windowDurationMins") != 300 or limits.get("planType") != PLAN):
            raise Failure("usage_not_read")
        started = codex.request("thread/start", {
            "model": "codewire-synthetic", "cwd": WORKDIR,
            "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": True})
        thread = started.get("thread")
        if started.get("modelProvider") != "openai" or not isinstance(thread, dict) \
                or not isinstance(thread.get("id"), str):
            raise Failure("unexpected_model_provider")
        turn = codex.request("turn/start", {
            "threadId": thread["id"], "input": [{"type": "text", "text": PROMPT}]}).get("turn")
        if not isinstance(turn, dict):
            raise Failure("invalid_started_turn")
        key = (thread["id"], turn.get("id"))
        codex.until(lambda: key in codex.completed, time.monotonic() + RPC_TIMEOUT)
        if codex.completed[key].get("status") != "completed" or key not in codex.markers:
            raise Failure("turn_failed")
    finally:
        codex.close()
    with backend.lock:
        routes = dict(backend.routes)
        if backend.rejected or backend.refreshes or backend.revocations:
            raise Failure("backend_rejected_or_refreshed")
    if not (routes.get("usage") and routes.get("responses") and routes.get("accounts_check")):
        raise Failure("backend_calls_missing")
    return routes


def config_absent():
    return not os.path.lexists(CONFIG)


def deliver():
    generation = wait_for(delivered_generation, DELIVERY_TIMEOUT, "login_not_delivered")
    wait_for(config_absent, CONFIG_REMOVAL_TIMEOUT, "proxy_config_kept")
    bearer = json.loads(read_private(AUTH)[1])["tokens"]["access_token"]
    backend = Backend(bearer)
    try:
        routes = chatgpt_session(backend)
    finally:
        backend.close()
    # Codex itself never rewrote the delivered login.
    if delivered_generation() != generation:
        raise Failure("login_changed_during_session")
    emit("delivered", generation=generation, auth_mode="chatgpt", file_mode="0600",
         refresh_token="placeholder", account="chatgpt", plan=PLAN,
         usage_calls=routes["usage"], responses_calls=routes["responses"])


def rotation(previous):
    started = time.monotonic()

    def rotated():
        # The FILE, not Codex's memory: the daemon's next check rewrites it.
        current = delivered_generation()
        return current if current is not None and current > previous else None

    generation = wait_for(rotated, NEXT_CHECK, "rotation_not_adopted")
    emit("rotation_adopted", previous=previous, generation=generation,
         waited_ms=int((time.monotonic() - started) * 1000))


def own_login():
    if delivered_generation() is None:
        raise Failure("login_not_delivered")
    codewires = read_private(AUTH)[1]
    now = int(time.time())
    header = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()

    def token(claims):
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        return f"{header}.{payload}.kind-user-signature"

    users = json.dumps({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": token({"email": "kind-user@example.test"}),
            "access_token": token({"exp": now + 3600, "synthetic": "kind-user-login"}),
            "refresh_token": "kind-synthetic-user-refresh-token",
            "account_id": "kind-synthetic-user-account",
        },
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }, indent=2).encode()
    # `codex login` rewrites auth.json in place.
    write_in_place(users)
    try:
        time.sleep(FULL_CHECK)
        found = read_private(AUTH)
        if found is None or found[1] != users or found[0] != 0o600:
            raise Failure("own_login_touched")
        if not config_absent():
            raise Failure("proxy_config_over_own_login")
    finally:
        # Put Codewire's file back only over this synthetic user login.
        current = read_private(AUTH)
        if current is not None and current[1] == users:
            write_in_place(codewires)
    emit("own_login_untouched", waited_ms=int(FULL_CHECK * 1000))


def write_in_place(contents):
    descriptor = os.open(AUTH, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "wb") as target:
        target.write(contents)
        target.flush()
        os.fsync(target.fileno())


def logout():
    if delivered_generation() is None:
        raise Failure("login_not_delivered")
    if logout_markers():
        raise Failure("logout_already_recorded")
    backend = Backend(bearer="")
    try:
        try:
            result = subprocess.run(
                [*CODEX_COMMAND, "logout"], cwd=WORKDIR, env=backend.environment(),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=RPC_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure("codex_logout_failed") from None
        if result.returncode != 0:
            raise Failure("codex_logout_failed")
        with backend.lock:
            revocations = list(backend.revocations)
            others = backend.rejected + backend.unknown + backend.refreshes + sum(
                backend.routes.values())
    finally:
        backend.close()
    # The placeholder is non-empty, so Codex revokes it, never the access token.
    if revocations != [("refresh_token", True)] or others:
        raise Failure("logout_revoked_more_than_placeholder")
    if read_private(AUTH) is not None:
        raise Failure("logout_kept_auth_file")
    started = time.monotonic()
    wait_for(logout_markers, NEXT_CHECK, "logout_not_recorded")
    recorded = time.monotonic() - started
    time.sleep(FULL_CHECK)
    if read_private(AUTH) is not None:
        raise Failure("logout_undone")
    if not config_absent():
        raise Failure("proxy_config_after_logout")
    emit("logout_stays_logged_out", revoked="placeholder",
         recorded_ms=int(recorded * 1000), waited_ms=int(FULL_CHECK * 1000))


def redelivered():
    generation = wait_for(delivered_generation, DELIVERY_TIMEOUT, "login_not_redelivered")
    if logout_markers():
        raise Failure("logout_survived_new_container")
    emit("redelivered", generation=generation)


def revoked():
    started = time.monotonic()
    wait_for(lambda: read_private(AUTH) is None and managed_config(), NEXT_CHECK,
             "revoked_login_kept")
    emit("revoked_login_removed", proxy_config="restored",
         waited_ms=int((time.monotonic() - started) * 1000))


def main(argv):
    mode = argv[0] if argv else None
    def interrupted(_signum, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if mode not in MODES or len(argv) != (2 if mode == "rotation" else 1):
            raise Failure("arguments")
        validate_projection()
        if mode == "deliver":
            deliver()
        elif mode == "rotation":
            if not argv[1].isdigit():
                raise Failure("arguments")
            rotation(int(argv[1]))
        elif mode == "own-login":
            own_login()
        elif mode == "logout":
            logout()
        elif mode == "redelivered":
            redelivered()
        else:
            revoked()
    except Failure as error:
        emit("failed", mode=mode if mode in MODES else None, reason=str(error))
        return 1
    except Exception:
        emit("failed", mode=mode if mode in MODES else None, reason="driver_failure")
        return 1
    emit("complete", mode=mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
