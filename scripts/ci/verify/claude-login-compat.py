#!/usr/bin/env python3
"""Run the pinned Claude Code against a fake provider and check what it does
with the login file Codewire writes (#3999).

With interception on, an environment's Claude Code holds a placeholder access
token and a placeholder refresh token. Its API requests carry the placeholder,
and its refresh is answered by Codewire. Nothing documents what Claude Code
sends or how it rewrites its login file, and both have changed between
releases, so this runs the real agent and checks each:

- it refreshes at the token host Codewire answers for, with the request this
  file names, carrying the refresh token from its login file;
- it stores what the answer gives it, and does not refresh again on its next
  run;
- it sends the placeholder only as a bearer token, only to the API host, and
  only in the requests this file names: the placeholder is searched for in
  every other header, in the request line and in the body, at both hosts;
- a refused refresh leaves the login file as the daemon recognises a cleared
  one, and an unavailable one leaves it alone;
- when the API rejects its token, each refresh carries the refresh token the
  last answer returned;
- it takes the placeholder from each environment variable it reads an
  Anthropic credential from, and sends its request with it: a release that
  began to refuse a token for its shape would fail here, not in an
  environment;
- `/usage` in print mode asks the API host for the sign-in's usage with the
  placeholder, asks no other host, and shows what the answer says.

The agent runs as it does in an environment: nothing here turns off any of
its own traffic. It runs with no network but loopback, and this program
refuses to start it otherwise: run it in a network namespace of its own
(`unshare -rn`) or in a container with no network. The fake provider
is a proxy on loopback that ends TLS for the two provider hosts with a
certificate made here. Every credential is made up here; nothing real is
read.

That the agent reaches no other host rests on the namespace, not on the
proxy: a dial that went around the proxy has no route and fails, and the
proxy never sees it. What the proxy adds is the name of a host the agent
asked it for. Print mode has been seen to ask for the two provider hosts
only, with no update check; a new host fails the run and is named, to be
looked at and then recorded here.

It is offline, in print mode. It does not show the real provider accepting
a swapped token, nor the requests an interactive session makes, `/status`
among them.
"""
import argparse
import dataclasses
import fcntl
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

TOKEN_HOST = "platform.claude.com"
API_HOST = "api.anthropic.com"
TOKEN_PATH = "/v1/oauth/token"
# Claude Code's OAuth client, as it names itself in a refresh.
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
# The API requests the agent sends the placeholder with, and those it sends
# with no credential at all, each a method and a pattern its whole path
# matches. A request in neither list is one nobody has looked at: the run
# fails and names it. The feature-flag request names a client key in its path.
EVALUATION = ("POST", "/api/eval/sdk-[A-Za-z0-9]+")
USAGE_PATH = "/api/oauth/usage"
PLACEHOLDER_REQUESTS = (
    ("POST", "/v1/messages"), ("GET", "/v1/mcp_servers"), ("GET", "/api/oauth/profile"),
    ("GET", USAGE_PATH),
    ("GET", "/api/claude_cli/bootstrap"), ("GET", "/api/claude_code_penguin_mode"),
    EVALUATION, ("POST", "/api/event_logging/v2/batch"),
)
# The image's version asks for the server list at the first path, and newer
# releases, which an environment updates itself to, at the second.
OPEN_REQUESTS = (
    ("GET", "/mcp-registry/v0/servers"), ("GET", "/api/directory/server-urls"),
    ("POST", "/api/event_logging/v2/batch"),
)


@dataclasses.dataclass(frozen=True)
class Place:
    """A place the agent reads its Anthropic credential from: what this
    program calls it, the header the agent then sends the credential in, what
    comes before it there, and the API requests seen to carry it."""
    name: str
    header: str
    scheme: str
    requests: tuple

    def carries(self, access):
        return self.scheme + access


LOGIN_FILE = Place("the login file", "authorization", "Bearer ", PLACEHOLDER_REQUESTS)
# The environment variables, each named as the agent reads it. The first is
# a subscription sign-in's long-lived token, the second any bearer token, the
# third an API key.
VARIABLES = (
    Place("CLAUDE_CODE_OAUTH_TOKEN", "authorization", "Bearer ", (
        ("POST", "/v1/messages"), ("GET", "/api/claude_cli/bootstrap"),
        ("GET", "/api/claude_code/policy_limits"), ("GET", "/api/claude_code/settings"),
        EVALUATION,
    )),
    Place("ANTHROPIC_AUTH_TOKEN", "authorization", "Bearer ", (("POST", "/v1/messages"), EVALUATION)),
    Place("ANTHROPIC_API_KEY", "x-api-key", "", (
        ("POST", "/v1/messages"), ("GET", "/api/claude_cli/bootstrap"),
        ("GET", "/api/claude_code/organizations/metrics_enabled"),
        ("GET", "/api/claude_code/policy_limits"), ("GET", "/api/claude_code/settings"),
        ("GET", "/api/claude_code_penguin_mode"), EVALUATION,
        ("POST", "/api/event_logging/v2/batch"),
    )),
)
CREDENTIAL_HEADERS = ("authorization", "x-api-key")
MANAGED_REFRESH_PREFIX = "codewire-managed-no-refresh-token-"
MANAGED_REFRESH = re.compile(re.escape(MANAGED_REFRESH_PREFIX) + "[0-9a-f]{32}")
# What a managed refresh answers as the access token's life: ten years.
MANAGED_LIFETIME_SECONDS = 315_360_000
# The fake's usage answer, in the fields the pinned Claude Code reads, and
# the lines `/usage` prints for it.
USAGE_ANSWER = {
    "five_hour": {"utilization": 37.0, "resets_at": "2030-01-01T05:00:00+00:00"},
    "seven_day": {"utilization": 61.0, "resets_at": "2030-01-07T00:00:00+00:00"},
    "seven_day_oauth_apps": None,
    "seven_day_opus": None,
}
USAGE_SHOWN = ("Current session: 37% used", "Current week (all models): 61% used")
AGENT_TIMEOUT_SECONDS = 90
OPENSSL_TIMEOUT_SECONDS = 60
MAX_BODY = 4 * 1024 * 1024

SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1


class Failure(Exception):
    """The run cannot start, or cannot be trusted."""


def isolate():
    """Refuse to go on with any network but loopback, and bring loopback up
    where it is down, as it is in a new network namespace."""
    interfaces = sorted(name for _, name in socket.if_nameindex())
    if interfaces != ["lo"]:
        raise Failure(
            "the agent must run with no network but loopback, and this one has "
            + ", ".join(interfaces)
            + ": run this under `unshare -rn` or in a container with no network")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        request = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(control, SIOCGIFFLAGS, request))[1]
        # A container with no network has loopback up already, and may not
        # set it.
        if not flags & IFF_UP:
            fcntl.ioctl(control, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))


def certificates(directory):
    """A certificate authority for this run and one certificate for both
    provider hosts. Returns the authority's certificate and a server context."""
    config = directory / "authority.cnf"
    config.write_text(
        "[req]\ndistinguished_name = name\nx509_extensions = authority\nprompt = no\n"
        "[name]\nCN = Codewire agent compatibility test\n"
        "[authority]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n"
        "subjectKeyIdentifier = hash\n"
        "[provider]\nbasicConstraints = critical,CA:FALSE\n"
        f"subjectAltName = DNS:{TOKEN_HOST},DNS:{API_HOST}\n")
    authority, authority_key = directory / "authority.pem", directory / "authority.key"
    provider, provider_key = directory / "provider.pem", directory / "provider.key"
    request = directory / "provider.csr"
    for command in (
        ["req", "-x509", "-config", config, "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", authority_key, "-out", authority],
        ["req", "-new", "-config", config, "-newkey", "rsa:2048", "-nodes",
         "-subj", f"/CN={TOKEN_HOST}", "-keyout", provider_key, "-out", request],
        ["x509", "-req", "-in", request, "-CA", authority, "-CAkey", authority_key,
         "-CAcreateserial", "-days", "2", "-extfile", config, "-extensions", "provider",
         "-out", provider],
    ):
        try:
            made = subprocess.run(["openssl", *command], capture_output=True, text=True,
                                  check=False, timeout=OPENSSL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise Failure(f"openssl {command[0]} did not finish in {OPENSSL_TIMEOUT_SECONDS} s") from None
        if made.returncode != 0:
            raise Failure(f"openssl {command[0]} failed: {made.stderr.strip().splitlines()[-1:]}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(provider, provider_key)
    return authority, context


@dataclasses.dataclass(frozen=True)
class Case:
    """One run of the agent: how the fake answers a refresh and the API."""
    name: str
    refresh: str  # "issue", "refuse" or "unavailable"
    api: str      # "answer" or "reject"


@dataclasses.dataclass
class Request:
    host: str
    method: str
    path: str
    headers: dict
    body: object
    # The request line's target and the body as sent, to search.
    target: str = ""
    raw: bytes = b""
    # Seconds since the case began.
    at: float = 0.0


class Provider:
    """What the fake provider was asked and what it answered, for one case."""

    def __init__(self, case, access, scopes):
        self.case = case
        # The environment's placeholder access token. A refresh returns the
        # same one: it names the environment's credential, not a grant.
        self.access = access
        self.scopes = scopes
        self.lock = threading.Lock()
        self.requests = []
        # The refresh token each answered refresh returned, in order.
        self.issued = []
        # Anything that must not happen, in words.
        self.strays = []
        self.began = time.monotonic()

    def stray(self, what):
        with self.lock:
            self.strays.append(what)

    def answer(self, request):
        """Record `request` and return its status, content type and body."""
        with self.lock:
            request.at = time.monotonic() - self.began
            self.requests.append(request)
            if request.host == TOKEN_HOST:
                return self._refresh(request)
            return self._api(request)

    def _refresh(self, request):
        if request.method != "POST" or request.path != TOKEN_PATH:
            self.strays.append(f"{request.method} {request.host}{request.path}")
            return 404, "application/json", b"{}"
        if self.case.refresh == "refuse":
            return 400, "application/json", json.dumps({
                "error": "invalid_grant",
                "error_description": "Codewire: this environment's Claude sign-in needs to be renewed",
            }).encode()
        if self.case.refresh == "unavailable":
            return 503, "application/json", json.dumps({
                "error": "temporarily_unavailable",
                "error_description": "Codewire: try again shortly",
            }).encode()
        issued = MANAGED_REFRESH_PREFIX + secrets.token_hex(16)
        self.issued.append(issued)
        return 200, "application/json", json.dumps({
            "access_token": self.access,
            "refresh_token": issued,
            "expires_in": MANAGED_LIFETIME_SECONDS,
            # The scopes of the stored grant, whatever the agent asked for.
            "scope": " ".join(self.scopes),
            "token_type": "Bearer",
        }).encode()

    def _api(self, request):
        if self.case.api == "reject":
            return 401, "application/json", json.dumps({"type": "error", "error": {
                "type": "authentication_error", "message": "invalid bearer token"}}).encode()
        if request.path == "/v1/messages":
            model = request.body.get("model", "") if isinstance(request.body, dict) else ""
            return 200, "text/event-stream", reply_stream(model)
        if request.path == "/v1/mcp_servers":
            return 200, "application/json", b'{"data":[],"has_more":false}'
        if request.method == "GET" and request.path == USAGE_PATH:
            return 200, "application/json", json.dumps(USAGE_ANSWER).encode()
        return 404, "application/json", json.dumps({"type": "error", "error": {
            "type": "not_found_error", "message": "not found"}}).encode()


class PlaceholderShape:
    """The shape of an environment's placeholder, as the fixture of the
    token answer states it for `access_token`: what it begins with, and how
    many base64url characters follow. A test beside the code that mints
    placeholders holds that fixture to the code, so a made-up placeholder
    here has the shape that ships."""

    def __init__(self, token_answer):
        stated = token_answer.get("access_token") if isinstance(token_answer, dict) else None
        shape = re.fullmatch(r"([^<>]+)<([0-9]+) base64url characters>", stated or "")
        if shape is None:
            raise Failure("the token answer's fixture does not state the placeholder's shape "
                          "as a beginning and a number of base64url characters")
        self.begins, self.characters = shape.group(1), int(shape.group(2))
        # Unpadded base64url of whole bytes, as the real one is.
        self.bytes = self.characters * 6 // 8
        if len(secrets.token_urlsafe(self.bytes)) != self.characters:
            raise Failure(f"{self.characters} base64url characters are not a whole number of bytes")

    def make(self):
        """A made-up placeholder of this shape."""
        return self.begins + secrets.token_urlsafe(self.bytes)


def reply_stream(model):
    """A complete streamed reply whose text is `ok`."""
    events = (
        ("message_start", {"message": {
            "id": "msg_compat", "type": "message", "role": "assistant", "model": model,
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        ("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
        ("content_block_stop", {"index": 0}),
        ("message_delta", {"delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {}),
    )
    return "".join(
        f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n" for kind, data in events
    ).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    """The proxy the agent is given, and behind it the two provider hosts.

    A CONNECT to a provider host is accepted and its TLS ended here, so the
    requests inside are read as that host's. A CONNECT to anywhere else, and
    a request in the clear, is refused and recorded.
    """
    protocol_version = "HTTP/1.1"
    tunnel = None

    def log_message(self, format, *args):  # noqa: A002 (the base class's name)
        pass

    def do_CONNECT(self):
        provider = self.server.provider
        host, _, port = self.path.rpartition(":")
        if self.tunnel is not None or port != "443" or host not in (TOKEN_HOST, API_HOST):
            provider.stray(f"a connection to {self.path}, which this test does not stand in for")
            self.send_error(502)
            self.close_connection = True
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError) as error:
            provider.stray(f"a TLS handshake for {host} that failed ({type(error).__name__})")
            self.close_connection = True
            return
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)
        self.tunnel = host
        self.close_connection = False

    def _serve(self):
        provider = self.server.provider
        self.close_connection = True
        if self.tunnel is None:
            provider.stray(f"a request in the clear: {self.command} {self.path}")
            self.send_error(502)
            return
        path = self.path.partition("?")[0]
        headers = {name.lower(): value for name, value in self.headers.items()}
        if headers.get("host") != self.tunnel:
            provider.stray(f"a request for {headers.get('host')} inside a connection to {self.tunnel}")
            self.send_error(421)
            return
        if "upgrade" in headers:
            provider.stray(f"an upgrade to {headers['upgrade']} at {self.tunnel}{path}")
            self.send_error(403)
            return
        raw = self._body(headers)
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = raw
        status, content_type, reply = provider.answer(
            Request(self.tunnel, self.command, path, headers, body, self.path, raw))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(reply)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)

    def _body(self, headers):
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while len(body) <= MAX_BODY:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
            return body
        return self.rfile.read(min(int(headers.get("content-length", "0")), MAX_BODY))

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _serve


class Proxy(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, tls, provider):
        super().__init__(("127.0.0.1", 0), Handler)
        self.tls = tls
        self.provider = provider

    def handle_error(self, request, client_address):
        # A connection the agent drops is its business. Anything else is a
        # request this fake could not serve, and the run cannot be trusted.
        error = sys.exc_info()[1]
        if not isinstance(error, (ConnectionError, TimeoutError, ssl.SSLError)):
            self.provider.stray(f"a request the fake provider failed on ({type(error).__name__})")


def run_agent(agent, home, project, proxy_port, authority, variables, prompt):
    """Run `claude -p prompt` once, with `variables` added to its
    environment. Returns its exit status and what it printed."""
    proxy = f"http://127.0.0.1:{proxy_port}"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TERM": "dumb",
        "HTTPS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "NODE_EXTRA_CA_CERTS": str(authority),
        **variables,
    }
    process = subprocess.Popen(
        [str(agent), "-p", prompt], cwd=project, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        output, errors = process.communicate(timeout=AGENT_TIMEOUT_SECONDS)
        result = process.returncode, (output.strip() or errors.strip())
    except subprocess.TimeoutExpired:
        result = None, f"no result within {AGENT_TIMEOUT_SECONDS} s"
    finally:
        # The agent's own session: nothing it started outlives the run.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
    return result


def starting_login(recorded, access):
    """The recorded login file as an environment holds it once its access
    token has run out: the placeholder `access`, already expired, and a
    placeholder refresh token."""
    login = json.loads(json.dumps(recorded))
    oauth = login["claudeAiOauth"]
    if oauth["refreshToken"] != MANAGED_REFRESH_PREFIX + "<nonce>":
        raise Failure("the recorded login file's refresh token is not the placeholder this test knows")
    oauth["accessToken"] = access
    oauth["refreshToken"] = MANAGED_REFRESH_PREFIX + secrets.token_hex(16)
    oauth["expiresAt"] = int((time.time() - 3600) * 1000)
    return login


def shape(value):
    """`value` for a failure message: never a token, even a made-up one."""
    if not isinstance(value, str):
        return repr(value)
    if value.startswith("Bearer "):
        return "Bearer " + shape(value[len("Bearer "):])
    if MANAGED_REFRESH.fullmatch(value):
        return MANAGED_REFRESH_PREFIX + "<nonce>"
    if len(value) > 24:
        return f"{value[:5]}… ({len(value)} characters)"
    return repr(value)


def named(request, requests):
    return any(request.method == method and re.fullmatch(pattern, request.path)
               for method, pattern in requests)


def carried_elsewhere(request, access, place):
    """Where `request` carries the placeholder other than as `place` has
    the agent send it: the names of those places."""
    places = [f"the {name} header" for name, value in request.headers.items()
              if access in value and (name, value) != (place.header, place.carries(access))]
    if access in request.target:
        places.append("the request line")
    if access.encode() in request.raw:
        places.append("the body")
    return places


def requests_wrong(provider, held, place=LOGIN_FILE):
    """What is wrong with the requests of one run of the agent, which read
    its credential from `place` and began holding the refresh token `held`."""
    wrong = [f"the agent made {what}" for what in provider.strays]
    # Each refresh is the request Codewire answers, and carries the refresh
    # token the agent was last given.
    refresh_tokens = [held] + provider.issued
    refreshes = [r for r in provider.requests if r.host == TOKEN_HOST and r.path == TOKEN_PATH]
    for index, request in enumerate(refreshes):
        body = request.body if isinstance(request.body, dict) else {}
        expected = {
            "content type": (request.headers.get("content-type", "").split(";")[0], "application/json"),
            "grant_type": (body.get("grant_type"), "refresh_token"),
            "client_id": (body.get("client_id"), CLIENT_ID),
            "refresh_token": (body.get("refresh_token"),
                              refresh_tokens[min(index, len(refresh_tokens) - 1)]),
        }
        for name, (got, want) in expected.items():
            if got != want:
                wrong.append(f"refresh {index + 1} has {name} {shape(got)}, not {shape(want)}")
        if not isinstance(body.get("scope"), str) or not body["scope"]:
            wrong.append(f"refresh {index + 1} names no scope")
        for header in CREDENTIAL_HEADERS:
            if header in request.headers:
                wrong.append(f"refresh {index + 1} carries a {header} header")
    # An API request carries the placeholder in the place's header, in a
    # request recorded for it, or no credential, in a request recorded for
    # that.
    for request in (r for r in provider.requests if r.host == API_HOST):
        asked = f"{request.method} {request.path}"
        carried = request.headers.get(place.header)
        for header in CREDENTIAL_HEADERS:
            if header != place.header and header in request.headers:
                wrong.append(f"{asked} carries an {header} header")
        if carried is None:
            if not named(request, OPEN_REQUESTS):
                wrong.append(f"{asked} carries no credential, and is not recorded as a request that does not")
        elif carried != place.carries(provider.access):
            wrong.append(f"{asked} carries {place.header} {shape(carried)}, not the placeholder")
        elif not named(request, place.requests):
            wrong.append(f"{asked} carries the placeholder, and is not recorded as a request that does")
    # Nowhere else: not in another header, the request line or a body, and
    # never at the token host.
    for request in provider.requests:
        for where in carried_elsewhere(request, provider.access, place):
            wrong.append(f"{request.method} {request.host}{request.path} carries the placeholder in {where}")
        if (request.host == TOKEN_HOST
                and request.headers.get(place.header) == place.carries(provider.access)):
            wrong.append(f"{request.method} {request.host}{request.path} carries the placeholder")
    return wrong


def answered(status, printed, provider):
    """What is wrong with a run that should have got its reply."""
    wrong = []
    if status != 0 or printed != "ok":
        wrong.append(f"the agent ended with status {status}: {printed[:200]!r}")
    if not any(r.host == API_HOST and r.path == "/v1/messages" for r in provider.requests):
        wrong.append("no request to /v1/messages")
    return wrong


def stored(provider, before, after, started, finished):
    """What is wrong with the login file after an answered refresh."""
    if not provider.issued:
        return ["no refresh was answered"]
    end = after["claudeAiOauth"]
    wrong = []
    if end.get("accessToken") != provider.access:
        wrong.append(f"the login file holds access token {shape(end.get('accessToken'))}, not the placeholder")
    if end.get("refreshToken") != provider.issued[-1]:
        wrong.append(f"the login file holds refresh token {shape(end.get('refreshToken'))}, not the last one returned")
    lifetime = MANAGED_LIFETIME_SECONDS * 1000
    expires = end.get("expiresAt")
    if not isinstance(expires, int) or not started + lifetime <= expires <= finished + lifetime:
        wrong.append(f"the login file expires at {expires}, not ten years from the refresh")
    if end.get("scopes") != provider.scopes:
        wrong.append(f"the login file holds scopes {end.get('scopes')}, not the answer's {provider.scopes}")
    return wrong + rest_kept(before, after)


def rest_kept(before, after):
    """What is wrong with the parts of the login file a refresh never owns:
    the plan fields, and Codewire's marker beside the login."""
    owned = ("accessToken", "refreshToken", "expiresAt", "scopes")
    def rest(login):
        return ({k: v for k, v in login["claudeAiOauth"].items() if k not in owned},
                {k: v for k, v in login.items() if k != "claudeAiOauth"})
    return [] if rest(after) == rest(before) else ["the login file's other fields changed"]


def check(case, provider, before, after, status, printed, started, finished):
    """Everything wrong with one case's first run, in words."""
    wrong = requests_wrong(provider, before["claudeAiOauth"]["refreshToken"])
    if after is None or not isinstance(after.get("claudeAiOauth"), dict):
        return wrong + ["the login file no longer holds claudeAiOauth"]
    refreshes = sum(1 for r in provider.requests if r.host == TOKEN_HOST and r.path == TOKEN_PATH)
    if case.refresh == "issue" and case.api == "answer":
        if refreshes != 1:
            wrong.append(f"{refreshes} refreshes, not one")
        wrong += answered(status, printed, provider) + stored(provider, before, after, started, finished)
    elif case.refresh == "issue":
        # The API rejects the token every time: the agent refreshes again,
        # each time with what the last answer gave it (checked above), and
        # gives up.
        if refreshes < 2:
            wrong.append(f"{refreshes} refreshes after a rejected token, not a second one")
        if status in (0, None):
            wrong.append(f"the agent ended with status {status} though every request was rejected")
        wrong += stored(provider, before, after, started, finished)
    elif case.refresh == "refuse":
        if refreshes != 1:
            wrong.append(f"{refreshes} refreshes, not one")
        if status in (0, None):
            wrong.append(f"the agent ended with status {status} though its refresh was refused")
        # What the daemon reads as Claude Code's cleared copy of Codewire's
        # login: an empty refresh token beside the marker.
        end = after["claudeAiOauth"]
        if end.get("refreshToken") != "" or end.get("accessToken") != "":
            wrong.append("a refused refresh did not leave the login file's tokens empty")
        wrong += rest_kept(before, after)
    else:
        if refreshes == 0:
            wrong.append("no refresh")
        wrong += answered(status, printed, provider)
        if after != before:
            wrong.append("an unavailable refresh changed the login file")
    return wrong


CASES = (
    Case("a refresh that is answered", "issue", "answer"),
    Case("a refresh that is refused", "refuse", "answer"),
    Case("a refresh that is unavailable", "unavailable", "answer"),
    Case("a token the API rejects", "issue", "reject"),
)


class Run:
    """One run of the agent in `work`'s home against a new fake provider,
    holding the placeholder `access` with `scopes`, given `variables` and
    asked `prompt`."""

    def __init__(self, case, access, scopes, agent, tls, authority, work, variables=None,
                 prompt="say ok"):
        self.provider = Provider(case, access, list(scopes))
        proxy = Proxy(tls, self.provider)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.started = int(time.time() * 1000)
        try:
            self.status, self.printed = run_agent(
                agent, work / "home", work / "project", proxy.server_address[1], authority,
                variables or {}, prompt)
        finally:
            self.finished = int(time.time() * 1000)
            proxy.shutdown()
            proxy.server_close()

    def report(self, name, wrong):
        provider = self.provider
        refreshes = sum(1 for r in provider.requests if r.host == TOKEN_HOST)
        calls = sum(1 for r in provider.requests if r.host == API_HOST)
        print(f"claude-login-compat: {name}: {refreshes} refresh(es), {calls} API request(s), "
              f"status {self.status}: {'ok' if not wrong else 'WRONG'}")
        for line in wrong:
            print(f"claude-login-compat:   {line}", file=sys.stderr)
        if wrong:
            # What the agent asked, in order, to read the failure by.
            for request in provider.requests:
                carried = next((request.headers[header] for header in CREDENTIAL_HEADERS
                                if header in request.headers), None)
                if request.host == TOKEN_HOST and isinstance(request.body, dict):
                    carried = request.body.get("refresh_token")
                print(f"claude-login-compat:   {request.at:6.1f} s  {request.method} "
                      f"{request.host}{request.path}  {shape(carried)}", file=sys.stderr)
        return not wrong


def read_login(login_file):
    try:
        return json.loads(login_file.read_text())
    except (OSError, ValueError):
        return None


def run_case(case, agent, recorded, placeholders, tls, authority, work):
    before = starting_login(recorded, placeholders.make())
    oauth = before["claudeAiOauth"]
    login_file = work / "home" / ".claude" / ".credentials.json"
    login_file.parent.mkdir(parents=True)
    login_file.write_text(json.dumps(before))
    login_file.chmod(0o600)
    (work / "project").mkdir()

    first = Run(case, oauth["accessToken"], oauth["scopes"], agent, tls, authority, work)
    after = read_login(login_file)
    passed = first.report(case.name, check(
        case, first.provider, before, after, first.status, first.printed, first.started, first.finished))
    if not passed or (case.refresh, case.api) != ("issue", "answer"):
        return passed
    # The answer's ten years hold: the next run asks for no refresh, and
    # leaves the login file as it is.
    stored_login = after["claudeAiOauth"]
    again = Run(case, stored_login["accessToken"], stored_login["scopes"], agent, tls, authority, work)
    wrong = requests_wrong(again.provider, after["claudeAiOauth"]["refreshToken"])
    wrong += answered(again.status, again.printed, again.provider)
    if any(r.host == TOKEN_HOST for r in again.provider.requests):
        wrong.append("a refresh, though the last one's answer has not run out")
    if read_login(login_file) != after:
        wrong.append("the login file changed")
    return again.report("the run after an answered refresh", wrong)


def run_variable(place, agent, placeholders, tls, authority, work):
    """The agent with no login file and the placeholder in the environment
    variable `place` names: it sends its request with it, in the header the
    place names, and asks the token host for nothing."""
    access = placeholders.make()
    login_file = work / "home" / ".claude" / ".credentials.json"
    login_file.parent.mkdir(parents=True)
    (work / "project").mkdir()
    run = Run(Case(f"the placeholder in {place.name}", "issue", "answer"), access, (), agent,
              tls, authority, work, {place.name: access})
    provider = run.provider
    wrong = requests_wrong(provider, None, place) + answered(run.status, run.printed, provider)
    if not any(r.host == API_HOST and r.path == "/v1/messages"
               and r.headers.get(place.header) == place.carries(access) for r in provider.requests):
        wrong.append(f"no request to /v1/messages carries the placeholder in its {place.header} header")
    if any(r.host == TOKEN_HOST for r in provider.requests):
        wrong.append("a request to the token host, though a variable's token has no refresh")
    if login_file.exists():
        wrong.append("the agent wrote a login file")
    return run.report(provider.case.name, wrong)


def run_usage(agent, recorded, placeholders, tls, authority, work):
    """`/usage` with the login file: the agent asks the API host for the
    usage with the placeholder, asks no other host, and prints the answer."""
    before = starting_login(recorded, placeholders.make())
    oauth = before["claudeAiOauth"]
    login_file = work / "home" / ".claude" / ".credentials.json"
    login_file.parent.mkdir(parents=True)
    login_file.write_text(json.dumps(before))
    login_file.chmod(0o600)
    (work / "project").mkdir()
    run = Run(Case("/usage with the login file", "issue", "answer"), oauth["accessToken"],
              oauth["scopes"], agent, tls, authority, work, prompt="/usage")
    provider = run.provider
    wrong = requests_wrong(provider, oauth["refreshToken"])
    if run.status != 0:
        wrong.append(f"the agent ended with status {run.status}: {run.printed[:200]!r}")
    if not any(r.host == API_HOST and r.method == "GET" and r.path == USAGE_PATH
               and r.headers.get(LOGIN_FILE.header) == LOGIN_FILE.carries(provider.access)
               for r in provider.requests):
        wrong.append(f"no GET {USAGE_PATH} carries the placeholder")
    for line in USAGE_SHOWN:
        if line not in run.printed:
            wrong.append(f"the agent did not print {line!r}")
    return run.report(provider.case.name, wrong)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--agent", required=True, type=Path, help="the installed claude command")
    parser.add_argument("--login", required=True, type=Path,
                        help="the recorded login file, claude-code.credentials.json")
    parser.add_argument("--token-answer", required=True, type=Path,
                        help="the token answer's fixture, claude-oauth-token/refresh-response.json, "
                             "which states the placeholder's shape")
    parser.add_argument("--work", required=True, type=Path, help="an existing directory to work in")
    arguments = parser.parse_args()
    try:
        isolate()
        recorded = json.loads(arguments.login.read_text())
        placeholders = PlaceholderShape(json.loads(arguments.token_answer.read_text()))
        certificate_directory = arguments.work / "certificates"
        certificate_directory.mkdir()
        authority, tls = certificates(certificate_directory)
        passed = True
        for number, case in enumerate(CASES):
            case_work = arguments.work / f"case-{number}"
            case_work.mkdir()
            passed &= run_case(case, arguments.agent, recorded, placeholders, tls, authority, case_work)
        for place in VARIABLES:
            variable_work = arguments.work / place.name
            variable_work.mkdir()
            passed &= run_variable(place, arguments.agent, placeholders, tls, authority, variable_work)
        usage_work = arguments.work / "usage"
        usage_work.mkdir()
        passed &= run_usage(arguments.agent, recorded, placeholders, tls, authority, usage_work)
    except Failure as failure:
        print(f"claude-login-compat: {failure}", file=sys.stderr)
        return 2
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
