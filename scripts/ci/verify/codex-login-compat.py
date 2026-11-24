#!/usr/bin/env python3
"""Run the pinned Codex against a fake provider and check how it refreshes
the login file Codewire writes (#6197).

With interception on, an environment's Codex holds a placeholder access
token, an unsigned placeholder ID token and Codewire's managed marker as its
refresh token. Codewire answers only one request on Codex's token host: a
refresh at `POST https://auth.openai.com/oauth/token` with
`grant_type=refresh_token` and the marker. Anything else there is the user's
own. Nothing documents when Codex refreshes or what it sends, so this runs
the real agent and checks that:

- it refreshes at that endpoint only, with exactly the request recorded in
  `crates/codewire-access/tests/fixtures/codex-oauth-token/refresh-request.json`,
  carrying the marker from its login file and no credential header;
- it refreshes on its own when the login's `last_refresh` is old, and after
  its provider answers 401, and not when the login is recent;
- it stores what the answer gives it, the placeholders and the marker, and
  leaves its login as it was when the refresh is refused;
- it sends the placeholder only as a bearer token to `chatgpt.com`, never to
  the token host;
- every case ends as a turn does: the agent answers `ok` and exits 0. A
  refused refresh leaves it on the token it holds, which the stand-in still
  accepts. A run that ends any other way fails: the checks above are read
  only from a run that finished as Codex means to. A handshake Codex
  abandons, which it does under load, is counted and does not fail it.

A new pin that refreshes at another endpoint or host, or with another grant,
fails here, and the token host's rule must be looked at again before the pin
moves.

The agent runs as it does in an environment: nothing here turns off any of
its own traffic. It runs with no network but loopback, and this program
refuses to start it otherwise: run it in a network namespace of its own
(`unshare -rn`) or in a container with no network. The fake provider is a
proxy on loopback that ends TLS for `chatgpt.com`, `auth.openai.com` and
`ab.chatgpt.com`, where Codex sends its events after a turn, with a
certificate made here, named to Codex as `CODEX_CA_CERTIFICATE`, as Codewire
names its own. Every credential is made up here; nothing real is read.
`chatgpt.com` answers the account check and the model call, and 404 to
everything else Codex asks, which it works without.
"""
import argparse
import base64
import dataclasses
import datetime
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

TOKEN_HOST = "auth.openai.com"
API_HOST = "chatgpt.com"
# Where Codex sends its product events once a turn is answered: stood in
# for, answered 404, and searched for the placeholder like the others.
EVENTS_HOST = "ab.chatgpt.com"
HOSTS = (TOKEN_HOST, API_HOST, EVENTS_HOST)
TOKEN_PATH = "/oauth/token"
ACCOUNTS_CHECK_PATH = "/backend-api/wham/accounts/check"
RESPONSES_PATH = "/backend-api/codex/responses"
JSON = "application/json"
MARKER = "codewire-managed-no-refresh-token"
CREDENTIAL_HEADERS = ("authorization", "x-api-key", "proxy-authorization", "cookie")
ACCOUNT_ID = "codewire-synthetic-account"
# Codex refreshes a login whose `last_refresh` is older than eight days.
OLD_LOGIN = datetime.timedelta(days=30)
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
        if not flags & IFF_UP:
            fcntl.ioctl(control, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))


def certificates(directory):
    """A certificate authority for this run and one certificate for every
    host stood in for. Returns the authority's certificate and a server
    context."""
    config = directory / "authority.cnf"
    config.write_text(
        "[req]\ndistinguished_name = name\nx509_extensions = authority\nprompt = no\n"
        "[name]\nCN = Codewire agent compatibility test\n"
        "[authority]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n"
        "subjectKeyIdentifier = hash\n"
        "[provider]\nbasicConstraints = critical,CA:FALSE\n"
        "subjectAltName = " + ",".join(f"DNS:{host}" for host in HOSTS) + "\n")
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


class PlaceholderShape:
    """The placeholder's shape, as the token answer's fixture states it for
    `access_token`: what it begins with, and how many base64url characters
    follow. A test beside the code that mints placeholders holds that
    fixture to the code."""

    def __init__(self, token_answer):
        stated = token_answer.get("access_token") if isinstance(token_answer, dict) else None
        shape = re.fullmatch(r"([^<>]+)<([0-9]+) base64url characters>", stated or "")
        if shape is None:
            raise Failure("the token answer's fixture does not state the placeholder's shape "
                          "as a beginning and a number of base64url characters")
        self.begins, self.characters = shape.group(1), int(shape.group(2))
        self.bytes = self.characters * 6 // 8
        if len(secrets.token_urlsafe(self.bytes)) != self.characters:
            raise Failure(f"{self.characters} base64url characters are not a whole number of bytes")

    def make(self):
        return self.begins + secrets.token_urlsafe(self.bytes)


def placeholder_id_token():
    """An unsigned ID token of the claims Codewire's placeholder carries."""
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    claims = {
        "email": "synthetic@example.invalid",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "plus",
            "chatgpt_user_id": "user-synthetic",
            "chatgpt_account_id": ACCOUNT_ID,
            "chatgpt_account_is_fedramp": False,
        },
        "exp": 4_070_908_800,
    }
    return encode({"alg": "none", "typ": "JWT"}) + "." + encode(claims) + ".codewire-placeholder"


@dataclasses.dataclass(frozen=True)
class Case:
    """One run of the agent: how old its login is, how a refresh is
    answered, and whether `chatgpt.com` rejects the placeholder until a
    refresh is answered, as the provider rejects an expired token."""
    name: str
    login_age: datetime.timedelta
    refresh: str          # "answer" or "refuse"
    reject: bool
    # How many refreshes: exactly this many, or at least it when `at_least`.
    refreshes: int
    at_least: bool = False


CASES = (
    Case("an old login, refreshed by Codex itself", OLD_LOGIN, "answer", False, 1),
    # Codex tries again from more than one of its clients, never past the
    # marker it holds.
    Case("an old login whose refresh is refused", OLD_LOGIN, "refuse", False, 1, at_least=True),
    Case("a recent login", datetime.timedelta(0), "answer", False, 0),
    Case("a recent login whose token is rejected", datetime.timedelta(0), "answer", True, 1,
         at_least=True),
)


@dataclasses.dataclass
class Request:
    host: str
    method: str
    target: str
    path: str
    headers: dict
    raw: bytes


class Provider:
    """What the fake provider was asked and what it answered, for one run."""

    def __init__(self, case, access, id_token):
        self.case = case
        self.access = access
        self.id_token = id_token
        self.lock = threading.Lock()
        self.requests = []
        self.strays = []
        # Handshakes the agent abandoned.
        self.dropped = 0
        self.rejected = 0
        self.answered = 0

    def stray(self, what):
        with self.lock:
            self.strays.append(what)

    def drop(self):
        with self.lock:
            self.dropped += 1

    def answer(self, request):
        with self.lock:
            self.requests.append(request)
            if request.host == TOKEN_HOST:
                return self._token(request)
            if (self.case.reject and not self.answered
                    and request.headers.get("authorization") == "Bearer " + self.access):
                self.rejected += 1
                return 401, JSON, json.dumps({"error": {"message": "invalid token",
                                                        "code": "token_invalid"}}).encode()
            return self._api(request)

    def _api(self, request):
        """The two answers a turn needs: the account check, which names
        `chatgpt.com` as the account's origin, and the model call, which
        replies `ok`. Anything else, the WebSocket model call among it, is
        404, which Codex works without."""
        if request.host != API_HOST:
            return 404, JSON, b'{"error":{"message":"not found"}}'
        if request.method == "GET" and request.path == ACCOUNTS_CHECK_PATH:
            account = request.headers.get("chatgpt-account-id", "")
            return 200, JSON, json.dumps({"accounts": [{
                "id": account, "workspace_backend_origin": f"https://{API_HOST}",
                "account_routing_override": "NO_CONSTRAINT"}]}).encode()
        if (request.method == "POST" and request.path == RESPONSES_PATH
                and "upgrade" not in request.headers):
            return 200, "text/event-stream", reply_stream()
        return 404, JSON, b'{"error":{"message":"not found"}}'

    def _token(self, request):
        if request.method != "POST" or request.target != TOKEN_PATH:
            return 404, JSON, b'{"error":"not_found"}'
        if self.case.refresh == "refuse":
            return 400, JSON, json.dumps({
                "error": "invalid_grant",
                "error_description": "Codewire: this environment's Codex sign-in needs to be renewed",
            }).encode()
        self.answered += 1
        return 200, JSON, json.dumps({
            "id_token": self.id_token, "access_token": self.access, "refresh_token": MARKER,
        }).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    """The proxy the agent is given, and behind it the hosts stood in for. A
    CONNECT to one is accepted and its TLS ended here; a CONNECT anywhere else,
    and a request in the clear, is refused and recorded."""
    protocol_version = "HTTP/1.1"
    tunnel = None

    def log_message(self, format, *args):  # noqa: A002 (the base class's name)
        pass

    def do_CONNECT(self):
        provider = self.server.provider
        host, _, port = self.path.rpartition(":")
        if self.tunnel is not None or port != "443" or host not in HOSTS:
            provider.stray(f"a connection to {self.path}, which this test does not stand in for")
            self.send_error(502)
            self.close_connection = True
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLEOFError, ConnectionError):
            # The agent closed the connection before the handshake ended, as
            # Codex does on a loaded machine when its own timeouts give up on
            # a connection, and when its exit cuts one short. Nothing was
            # asked on it, so it is counted, not failed. A certificate the
            # agent refuses is an alert, below, and fails the run.
            provider.drop()
            self.close_connection = True
            return
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
        headers = {name.lower(): value for name, value in self.headers.items()}
        if headers.get("host") != self.tunnel:
            provider.stray(f"a request for {headers.get('host')} inside a connection to {self.tunnel}")
            self.send_error(421)
            return
        status, content_type, reply = provider.answer(Request(
            self.tunnel, self.command, self.path, self.path.partition("?")[0], headers,
            self._body(headers)))
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
        error = sys.exc_info()[1]
        if not isinstance(error, (ConnectionError, TimeoutError, ssl.SSLError)):
            self.provider.stray(f"a request the fake provider failed on ({type(error).__name__})")


def reply_stream():
    """A complete streamed model reply whose text is `ok`."""
    events = (
        {"type": "response.created", "response": {"id": "resp_compat"}},
        {"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant", "id": "msg_compat",
            "content": [{"type": "output_text", "text": "ok"}]}},
        {"type": "response.completed", "response": {"id": "resp_compat", "usage": {
            "input_tokens": 1, "input_tokens_details": None, "output_tokens": 1,
            "output_tokens_details": None, "total_tokens": 2}}},
    )
    return "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                   for event in events).encode()


def run_agent(agent, home, project, proxy_port, authority):
    """Run `codex exec` once. Returns its exit status, or None when it did
    not end in time, and its last line of output."""
    proxy = f"http://127.0.0.1:{proxy_port}"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "TERM": "dumb",
        "HTTPS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "CODEX_CA_CERTIFICATE": str(authority),
    }
    process = subprocess.Popen(
        [str(agent), "exec", "--skip-git-repo-check", "Reply with the single word ok."],
        cwd=project, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, start_new_session=True)
    printed = ""
    try:
        printed, _ = process.communicate(timeout=AGENT_TIMEOUT_SECONDS)
        status = process.returncode
    except subprocess.TimeoutExpired:
        status = None
    finally:
        # The agent's own session: nothing it started outlives the run.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
    lines = printed.strip().splitlines()
    return status, lines[-1] if lines else ""


def shape(value):
    """`value` for a failure message: never a token, even a made-up one."""
    if not isinstance(value, str):
        return repr(value)
    if value.startswith("Bearer "):
        return "Bearer " + shape(value[len("Bearer "):])
    if value == MARKER:
        return value
    if len(value) > 24:
        return f"{value[:5]}… ({len(value)} characters)"
    return repr(value)


def refresh_wrong(index, request, expected):
    """What is wrong with one request to the token endpoint."""
    wrong = []
    label = f"refresh {index + 1}"
    content_type = request.headers.get("content-type", "").split(";")[0].strip()
    if content_type != "application/json":
        wrong.append(f"{label} has content type {content_type!r}, not application/json")
    try:
        body = json.loads(request.raw)
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return wrong + [f"{label} has a body that is not a JSON object"]
    if sorted(body) != sorted(expected):
        wrong.append(f"{label} has members {sorted(body)}, not {sorted(expected)}")
    for name, want in expected.items():
        if body.get(name) != want:
            wrong.append(f"{label} has {name} {shape(body.get(name))}, not {shape(want)}")
    for header in CREDENTIAL_HEADERS:
        if header in request.headers:
            wrong.append(f"{label} carries a {header} header")
    return wrong


def requests_wrong(provider, expected):
    """What is wrong with the requests of one run."""
    wrong = [f"the agent made {what}" for what in provider.strays]
    refreshes = [r for r in provider.requests if r.host == TOKEN_HOST]
    for index, request in enumerate(refreshes):
        if request.method != "POST" or request.target != TOKEN_PATH:
            wrong.append(f"the agent asked {request.method} {TOKEN_HOST}{request.target}, "
                         f"not POST {TOKEN_PATH}")
            continue
        wrong += refresh_wrong(index, request, expected)
    bearer = "Bearer " + provider.access
    for request in provider.requests:
        asked = f"{request.method} {request.host}{request.path}"
        elsewhere = [name for name, value in request.headers.items()
                     if provider.access in value and (name, value) != ("authorization", bearer)]
        if request.host == TOKEN_HOST and request.headers.get("authorization") == bearer:
            elsewhere.append("authorization")
        if provider.access in request.target:
            elsewhere.append("the request line")
        if provider.access.encode() in request.raw:
            elsewhere.append("the body")
        for where in elsewhere:
            wrong.append(f"{asked} carries the placeholder in {where}")
    return wrong, len(refreshes)


def login_wrong(case, before, after, refreshes, started, finished):
    """What is wrong with the login file after the run."""
    if not isinstance(after, dict) or not isinstance(after.get("tokens"), dict):
        return ["the login file no longer holds its tokens"]
    wrong = []
    kept = {k: v for k, v in before.items() if k not in ("tokens", "last_refresh")}
    if {k: v for k, v in after.items() if k not in ("tokens", "last_refresh")} != kept:
        wrong.append("the login file's other fields changed")
    if after["tokens"] != before["tokens"]:
        changed = sorted(name for name in set(before["tokens"]) | set(after["tokens"])
                         if before["tokens"].get(name) != after["tokens"].get(name))
        wrong.append(f"the login file's tokens changed: {', '.join(changed)}")
    stored = after.get("last_refresh")
    if case.refresh == "answer" and refreshes:
        try:
            at = datetime.datetime.fromisoformat(stored.replace("Z", "+00:00")).timestamp()
        except (AttributeError, ValueError):
            at = None
        if at is None or not started - 1 <= at <= finished + 1:
            wrong.append(f"last_refresh is {stored!r}, not the time of the answered refresh")
    elif stored != before.get("last_refresh"):
        wrong.append(f"last_refresh moved to {stored!r} though no refresh was answered")
    return wrong


def run_case(case, agent, recorded, expected, placeholders, tls, authority, work):
    access = placeholders.make()
    id_token = placeholder_id_token()
    login = json.loads(json.dumps(recorded))
    tokens = login["tokens"]
    if tokens.get("refresh_token") != MARKER:
        raise Failure("the recorded login file's refresh token is not the marker this test knows")
    tokens.update(access_token=access, id_token=id_token, account_id=ACCOUNT_ID)
    login["last_refresh"] = (datetime.datetime.now(datetime.timezone.utc) - case.login_age
                             ).strftime("%Y-%m-%dT%H:%M:%SZ")
    home = work / "home"
    login_file = home / ".codex" / "auth.json"
    login_file.parent.mkdir(parents=True)
    login_file.write_text(json.dumps(login))
    login_file.chmod(0o600)
    (work / "project").mkdir()

    provider = Provider(case, access, id_token)
    proxy = Proxy(tls, provider)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    started = time.time()
    try:
        status, printed = run_agent(agent, home, work / "project", proxy.server_address[1],
                                    authority)
    finally:
        finished = time.time()
        proxy.shutdown()
        proxy.server_close()
    try:
        after = json.loads(login_file.read_text())
    except (OSError, ValueError):
        after = None

    wrong, refreshes = requests_wrong(provider, expected)
    if status is None:
        wrong.append(f"the agent did not end within {AGENT_TIMEOUT_SECONDS} s")
    elif (status, printed) != (0, "ok"):
        wrong.append(f"the agent ended with status {status}, printing {printed[:200]!r}, "
                     "not 0 and 'ok'")
    if refreshes < case.refreshes or (refreshes > case.refreshes and not case.at_least):
        wrong.append(f"{refreshes} refresh(es), not {'at least ' if case.at_least else ''}"
                     f"{case.refreshes}")
    if case.reject and not provider.rejected:
        wrong.append("no request carried the placeholder to be rejected")
    wrong += login_wrong(case, login, after, refreshes, started, finished)
    calls = sum(1 for r in provider.requests if r.host == API_HOST)
    print(f"codex-login-compat: {case.name}: {refreshes} refresh(es), {calls} request(s) to "
          f"{API_HOST}, {provider.dropped} abandoned handshake(s), status {status}: "
          f"{'ok' if not wrong else 'WRONG'}")
    for line in wrong:
        print(f"codex-login-compat:   {line}", file=sys.stderr)
    return not wrong


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--agent", required=True, type=Path, help="the installed codex command")
    parser.add_argument("--login", required=True, type=Path,
                        help="the recorded login file, codex.auth.json")
    parser.add_argument("--token-request", required=True, type=Path,
                        help="the refresh request's fixture, codex-oauth-token/refresh-request.json")
    parser.add_argument("--token-answer", required=True, type=Path,
                        help="the token answer's fixture, codex-oauth-token/refresh-response.json, "
                             "which states the placeholder's shape")
    parser.add_argument("--work", required=True, type=Path, help="an existing directory to work in")
    arguments = parser.parse_args()
    try:
        isolate()
        recorded = json.loads(arguments.login.read_text())
        expected = json.loads(arguments.token_request.read_text())
        if not isinstance(expected, dict) or expected.get("refresh_token") != MARKER \
                or expected.get("grant_type") != "refresh_token":
            raise Failure("the request fixture is not a refresh with the marker")
        placeholders = PlaceholderShape(json.loads(arguments.token_answer.read_text()))
        certificate_directory = arguments.work / "certificates"
        certificate_directory.mkdir()
        authority, tls = certificates(certificate_directory)
        passed = True
        for number, case in enumerate(CASES):
            case_work = arguments.work / f"case-{number}"
            case_work.mkdir()
            passed &= run_case(case, arguments.agent, recorded, expected, placeholders, tls,
                               authority, case_work)
    except Failure as failure:
        print(f"codex-login-compat: {failure}", file=sys.stderr)
        return 2
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
