#!/usr/bin/env python3
"""Observe guided launch with a built cw, isolated state and synthetic RPCs.

Requires Python 3.10+, protoc and requirements-cli-guided-launch.txt installed
in a temporary virtualenv, and a host supported by local VMs (Linux or macOS).
No provider account or VM is used. Run:
  python scripts/dev/test-cli-guided-launch.py --cw target/debug/cw
Pass --evidence-dir to retain terminal observations at a chosen new directory.
The h2 fixture follows the existing Connect client's loopback test topology.
"""
import argparse
import atexit
import fcntl
import json
import os
import pathlib
import pty
import select
import shutil
import socketserver
import struct
import subprocess
import tempfile
import termios
import threading
import time
import h2.config
import h2.connection
import h2.events

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--cw", type=pathlib.Path, required=True, help="Built cw binary to observe"
)
parser.add_argument(
    "--evidence-dir",
    type=pathlib.Path,
    help="New directory to retain synthetic terminal observations",
)
args = parser.parse_args()
binary = str(args.cw.resolve())
if not pathlib.Path(binary).is_file():
    parser.error("--cw must name a built binary")
protoc = shutil.which("protoc")
if not protoc:
    parser.error("protoc is required (the same compiler used to build cw)")
if args.evidence_dir:
    root = args.evidence_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
else:
    root = pathlib.Path(tempfile.mkdtemp(prefix="cw-guided-launch-"))
owned_processes = []


def cleanup():
    for proc in owned_processes:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


atexit.register(cleanup)


class Session:
    def __init__(self, name, args, extra_env=None, setup=None):
        self.dir = root / name
        self.dir.mkdir()
        self.buf = b""
        self.marker = 0
        self.env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "en_US.UTF-8"}
        self.env.update(
            TERM="xterm-256color",
            NO_COLOR="1",
            CW_CONFIG_DIR=str(self.dir / "platform"),
            CW_MESH_DATA_DIR=str(self.dir / "mesh"),
            CODEWIRE_NATIVE_STATE_ROOT=str(self.dir / "native"),
            CODEWIRE_LOCAL_CREDENTIAL_ROOT=str(self.dir / "credentials"),
            CODEWIRE_NATIVE_ARTIFACT_ROOT=str(self.dir / "artifacts"),
            CODEWIRE_NATIVE_ARTIFACT_LOCK=str(self.dir / "artifacts.lock.json"),
        )
        self.env.update(extra_env or {})
        if setup:
            setup(self)
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        self.proc = subprocess.Popen(
            [binary] + args,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=self.dir,
            env=self.env,
        )
        owned_processes.append(self.proc)
        os.close(slave)

    def expect(self, text, seconds=10):
        deadline = time.monotonic() + seconds
        needle = text.encode()
        while needle not in self.buf[self.marker :] and time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    break
                if not data:
                    break
                self.buf += data
        assert needle in self.buf[self.marker :], (
            text,
            self.buf.decode(errors="replace")[-6000:],
        )

    def send(self, data):
        self.marker = len(self.buf)
        os.write(self.master, data)
        time.sleep(0.15)

    def finish(self, code=None):
        self.proc.wait(timeout=10)
        try:
            while select.select([self.master], [], [], 0.05)[0]:
                data = os.read(self.master, 65536)
                if not data:
                    break
                self.buf += data
        except OSError:
            pass
        os.close(self.master)
        (self.dir / "terminal.log").write_bytes(self.buf)
        print(self.dir.name + ": exit " + str(self.proc.returncode), flush=True)
        if code is not None:
            assert self.proc.returncode == code, self.buf.decode(errors="replace")[
                -3000:
            ]
        return self.proc.returncode

    def no_create(self):
        assert not (self.dir / "native").exists(), "Canceled flow started native state"
        assert not (self.dir / "codewire.yaml").exists(), "Canceled flow wrote config"


results = []
s = Session("run-agent-cancel", ["run"])
s.expect("Open an agent")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("bare run asks agent first; cancel creates nothing")
s = Session("run-placement-cancel", ["run", "claude"])
s.expect("Where would you like to work?")
s.send(b"\x03")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append(
    "native-agent run with no selection offers environment flow; Ctrl-C cancels"
)
for agent in ["noel", "kimi"]:
    s = Session(
        "run-unsupported-managed-" + agent, ["run", "--agent", agent, "--detach"]
    )
    s.expect("this run requires an existing supported environment")
    s.finish(1)
    assert b"Where would you like to work?" not in s.buf
    s.no_create()
    results.append(
        "unsupported managed " + agent + " refuses before sandbox setup or creation"
    )
s = Session(
    "run-parent-needs-existing", ["run", "claude", "--parent", "existing-session"]
)
s.expect("this run requires an existing supported environment")
s.finish(1)
assert b"Where would you like to work?" not in s.buf
s.no_create()
results.append(
    "parent-session request refuses before creating an environment that cannot contain it"
)
s = Session(
    "run-managed-local-env-review",
    ["--local", "run", "--agent", "codex", "--env", "MODE=synthetic", "--detach"],
)
s.expect("Where would you like to work?")
s.send(b"\r")
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("Create with these settings?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append(
    "local managed session overrides remain supported through pre-create review"
)
s = Session("run-empty-inventory", ["--local", "run", "claude"])
s.expect("Where would you like to work?")
s.send(b"\x1b[B\r")
s.expect("No environments are available to choose.")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("empty inventory returns to creation choices without writes")
s = Session(
    "create-invalid-retry", ["--local", "create", "--cpu", "3", "--memory", "5120MiB"]
)
s.expect("Environment name")
s.send(b"../bad\r")
s.expect("Use 1 to 63")
s.send(b"\x15valid-app\r")
s.expect("Create with these settings?")
s.expect("3 vCPU")
s.expect("5 GiB")
s.expect("App secrets")
s.expect("Policy")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append(
    "invalid local name retries, valid name reaches resolved review, Esc does not boot supervisor"
)
s = Session("create-cloud-login-cancel", ["--cloud", "create"])
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("Sign in to Codewire to continue cloud setup?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("cloud setup offers supported sign-in and cancels without opening login")
s = Session("init-success", ["init"])
s.expect("Which workspace image?")
s.send(b"\r")
s.expect("Configuration settings")
s.send(b"\r")
s.expect("Write this configuration?")
s.send(b"\r")
s.expect("codewire.yaml written")
s.finish(0)
data = (s.dir / "codewire.yaml").read_text()
assert "image:" in data
assert not (s.dir / "native").exists()
results.append("bare init writes reviewed workspace configuration offline")
s = Session(
    "init-refuses-overwrite",
    ["init"],
    setup=lambda session: (session.dir / "codewire.yaml").write_text(
        "image: custom-image\n"
    ),
)
s.expect("already exists")
s.finish(1)
assert b"Which workspace image?" not in s.buf
assert (s.dir / "codewire.yaml").read_text() == "image: custom-image\n"
results.append("existing configuration is refused before prompting or overwriting")
s = Session("init-cancel", ["init"])
s.expect("Which workspace image?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("init cancellation leaves no file")
s = Session("run-json-refusal", ["run", "--output", "json"])
s.expect("needs an agent or a command")
s.finish(1)
s.no_create()
assert b"Where would you like" not in s.buf
results.append("JSON bare run refuses at terminal before menu/effects")
s = Session("run-json-missing-target", ["run", "claude", "--output", "json"])
s.expect("no environment selected")
s.finish(1)
s.no_create()
assert b"Where would you like" not in s.buf
results.append("JSON agent run with no target refuses at terminal without creation")
s = Session(
    "init-explicit",
    [
        "init",
        "--image",
        "workspace",
        "--profile",
        "local:work",
        "--secrets",
        "platform:app-dev",
    ],
)
s.expect("codewire.yaml written")
s.finish(0)
assert b"Which workspace image?" not in s.buf
data = (s.dir / "codewire.yaml").read_text()
assert "local:work" in data and "platform:app-dev" in data
results.append("explicit init flags skip interview and write only source references")

s = Session("init-cloud-profile-login-cancel", ["init"])
s.expect("Which workspace image?")
s.send(b"\r")
s.expect("Configuration settings")
s.send(b"\x1b[B" * 4 + b"\r")
s.expect("Choose or set up a profile")
s.send(b"\r")
s.expect("Where should Codewire store this credential?")
s.send(b"\x1b[B\r")
s.expect("Sign in to Codewire to continue cloud setup?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("init cloud source selection offers sign-in and cancels without writing")


def saved_selection(session, kind="env"):
    mesh = session.dir / "mesh"
    mesh.mkdir(mode=0o700)
    file = mesh / "config.toml"
    file.write_text(
        f'[current_target]\nkind = "{kind}"\nref = "22222222-2222-4222-8222-222222222222"\nname = "gone"\n'
    )
    file.chmod(0o600)


s = Session(
    "run-stale-local",
    ["--local", "run", "claude"],
    setup=lambda session: saved_selection(session, "local"),
)
s.expect("selected local environment no longer exists")
s.expect("Where would you like to work?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
assert 'name = "gone"' in (s.dir / "mesh" / "config.toml").read_text()
results.append(
    "confirmed stale local selection offers recovery and preserves saved selection on cancel"
)

# Closed terminal and piped metadata must not create or consume input.
s = Session("run-terminal-closed", ["run", "claude"])
s.expect("Where would you like to work?")
(s.dir / "terminal.log").write_bytes(s.buf)
os.close(s.master)
s.proc.wait(timeout=10)
assert s.proc.returncode != 0
s.no_create()
results.append("closed terminal while choosing an environment creates nothing")
pipe_read, pipe_write = os.pipe()
canary = b"synthetic-metadata-must-remain-unread"
os.write(pipe_write, canary)
os.close(pipe_write)
sdir = root / "run-pipe"
sdir.mkdir()
env = dict(s.env)
env.update(
    CW_CONFIG_DIR=str(sdir / "platform"),
    CW_MESH_DATA_DIR=str(sdir / "mesh"),
    CODEWIRE_NATIVE_STATE_ROOT=str(sdir / "native"),
)
proc = subprocess.run(
    [binary, "run", "claude"],
    stdin=pipe_read,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=sdir,
    env=env,
    timeout=10,
)
assert proc.returncode != 0 and b"no environment selected" in proc.stderr
assert os.read(pipe_read, 4096) == canary
os.close(pipe_read)
assert not (sdir / "native").exists()
results.append(
    "noninteractive missing-target refusal leaves piped synthetic input unread"
)

# Synthetic Connect server: protobuf response bodies use the checked-in schema.
repo = str(pathlib.Path(__file__).resolve().parents[2])
include = pathlib.Path(protoc).resolve().parent.parent / "include"


def encode(typ, body, file):
    return subprocess.check_output(
        [
            protoc,
            "-I" + repo + "/proto",
            "-I" + str(include),
            "--encode=codewire.v1." + typ,
            "codewire/v1/" + file + ".proto",
        ],
        input=body.encode(),
        env={"PATH": os.environ.get("PATH", os.defpath)},
    )


org = "11111111-1111-4111-8111-111111111111"
eid = "22222222-2222-4222-8222-222222222222"
orgs = encode(
    "ListOrganizationsResponse",
    f'organizations {{ organization {{ id: "{org}" name: "Fixture team" slug: "fixture" }} role: ORG_ROLE_OWNER }}',
    "organization",
)
created = encode(
    "CreateEnvironmentResponse",
    f'environment {{ id: "{eid}" org_id: "{org}" name: "test-app" state: ENVIRONMENT_STATE_CREATING desired_state: DESIRED_STATE_STARTED operation_generation: 1 source_selection {{}} }}',
    "environment",
)


class Handler(socketserver.BaseRequestHandler):
    calls = []
    lookup = "not_found"
    org_response = orgs
    target_org = org
    create_response = created
    list_response = b""

    def handle(self):
        connection = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        connection.initiate_connection()
        self.request.sendall(connection.data_to_send())
        streams = {}
        while True:
            raw = self.request.recv(65535)
            if not raw:
                return
            for event in connection.receive_data(raw):
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = [dict(event.headers), b""]
                elif isinstance(event, h2.events.DataReceived):
                    streams[event.stream_id][1] += event.data
                    connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    headers, data = streams.pop(event.stream_id)
                    path = headers[":path"]
                    self.calls.append((path, data))
                    status = "200"
                    content_type = "application/proto"
                    if path.endswith("/ListOrganizations"):
                        body = self.org_response
                    elif path.endswith("/CreateOrganization"):
                        body = encode(
                            "CreateOrganizationResponse",
                            f'organization {{ id: "{org}" name: "Fixture team" slug: "fixture" }}',
                            "organization",
                        )
                    elif path.endswith("/ListSecretProjects"):
                        body = b""
                    elif path.endswith("/ListEnvironments"):
                        body = self.list_response
                    elif path.endswith("/ListAccessProfiles") or path.endswith(
                        "/ListSessions"
                    ):
                        body = b""
                    elif path.endswith("/CreateEnvironment"):
                        body = self.create_response
                    elif path.endswith("/StreamLogs"):
                        content_type = "application/connect+proto"
                        log = encode(
                            "StreamLogsResponse",
                            f'log {{ id: "fixture-complete" environment_id: "{eid}" phase: "complete" status: "completed" }}',
                            "environment",
                        )
                        body = (
                            b"\0" + struct.pack("!I", len(log)) + log + b"\2\0\0\0\2{}"
                        )
                    elif path.endswith("/GetEnvironmentDaemonStatus"):
                        body = encode(
                            "GetEnvironmentDaemonStatusResponse",
                            "status { state: ENVIRONMENT_DAEMON_STATE_READY }",
                            "environment",
                        )
                    elif path.endswith("/LaunchSession"):
                        body = encode(
                            "LaunchSessionResponse",
                            'session { session_id: "44444444-4444-4444-8444-444444444444" name: "claude" state: ENVIRONMENT_SESSION_STATE_RUNNING command: "claude" working_dir: "/workspace" pty: true launch_generation: 1 }',
                            "environment_session",
                        )
                    elif path.endswith("/GetEnvironment") and self.lookup == "ready":
                        body = encode(
                            "GetEnvironmentResponse",
                            f'environment {{ id: "{eid}" org_id: "{self.target_org}" name: "test-app" state: ENVIRONMENT_STATE_RUNNING desired_state: DESIRED_STATE_STARTED operation_generation: 1 }}',
                            "environment",
                        )
                    elif path.endswith("/GetEnvironment"):
                        status = "404" if self.lookup == "not_found" else "503"
                        content_type = "application/json"
                        body = json.dumps(
                            {
                                "code": self.lookup,
                                "message": "synthetic fixture lookup failure",
                            }
                        ).encode()
                    else:
                        raise AssertionError("unexpected fixture RPC")
                    connection.send_headers(
                        event.stream_id,
                        [(":status", status), ("content-type", content_type)],
                    )
                    connection.send_data(event.stream_id, body, end_stream=True)
            self.request.sendall(connection.data_to_send())


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
fixture = {
    "CODEWIRE_SERVER_URL": f"http://127.0.0.1:{server.server_address[1]}",
    "CODEWIRE_API_KEY": "synthetic-guided-fixture-key",
}


def mutation_count(method):
    return sum(path.endswith("/" + method) for path, _ in Handler.calls)


before = len(Handler.calls)
s = Session(
    "run-managed-cloud-env-refusal",
    ["--cloud", "run", "--agent", "codex", "--env", "MODE=synthetic", "--detach"],
    fixture,
)
s.expect("Where would you like to work?")
s.send(b"\x1b[B\r")
s.expect("managed platform conversations accept")
s.finish(1)
assert b"Environment name" not in s.buf
assert len(Handler.calls) == before
s.no_create()
results.append(
    "cloud managed overrides fail shared placement validation before setup or creation"
)


Handler.list_response = encode(
    "ListEnvironmentsResponse",
    f'environments {{ id: "{eid}" org_id: "{org}" name: "stopped-app" type: "sandbox" state: ENVIRONMENT_STATE_STOPPED desired_state: DESIRED_STATE_STOPPED }}',
    "environment",
)
before = len(Handler.calls)
s = Session(
    "run-managed-cloud-env-before-start",
    ["--cloud", "run", "--agent", "codex", "--env", "MODE=synthetic", "--detach"],
    fixture,
)
s.expect("Where would you like to work?")
s.send(b"\r")
s.expect("Choose an environment")
s.send(b"\r")
s.expect("managed platform conversations accept")
s.finish(1)
assert b"Start stopped-app" not in s.buf
assert not any(
    path.endswith("/StartEnvironment") or path.endswith("/CreateEnvironment")
    for path, _ in Handler.calls[before:]
)
s.no_create()
results.append(
    "cloud managed placement validation also runs before starting an existing stopped environment"
)
Handler.list_response = b""


def malformed_selection(session):
    mesh = session.dir / "mesh"
    mesh.mkdir(mode=0o700)
    (mesh / "config.toml").write_text(
        '[current_target]\nkind = "broken"\ninvalid_field = "synthetic"\n'
    )


before = len(Handler.calls)
s = Session(
    "run-explicit-ignores-malformed-selection",
    ["--cloud", "run", "claude", "--in", "missing", "--output", "json"],
    fixture,
    malformed_selection,
)
s.expect('platform environment "missing" not found')
s.finish(1)
assert b"parse mesh config" not in s.buf
assert any(path.endswith("/ListEnvironments") for path, _ in Handler.calls[before:])
assert not any(
    path.endswith("/CreateEnvironment") for path, _ in Handler.calls[before:]
)
assert b"Where would you like to work?" not in s.buf
s.no_create()
results.append(
    "explicit --in resolves directly despite malformed unrelated saved selection"
)

# Missing account setup uses the supported organization route, with its own
# explicit consent. Canceling the later environment preserves that saved org.
Handler.org_response = b""
for create_org in [False, True]:
    org_before = mutation_count("CreateOrganization")
    env_before = mutation_count("CreateEnvironment")
    s = Session(
        "cloud-empty-organizations-" + ("create" if create_org else "cancel"),
        ["--cloud", "create", "--no-profile", "--no-network", "--no-wait"],
        fixture,
    )
    s.expect("Environment name")
    s.send(b"test-app\r")
    s.expect("No organizations found. Create one?")
    if create_org:
        s.send(b"\r")
        s.expect("Organization name")
        s.send(b"Fixture team\r")
        s.expect("Organization slug")
        s.send(b"\r")
        s.expect("Create organization?")
        assert mutation_count("CreateOrganization") == org_before
        s.send(b"\r")
        s.expect("Environment settings")
        assert mutation_count("CreateOrganization") == org_before + 1
    s.send(b"\x1b")
    s.expect("canceled")
    s.finish(1)
    assert mutation_count("CreateOrganization") == org_before + int(create_org)
    assert mutation_count("CreateEnvironment") == env_before
    assert not (s.dir / "platform" / "config.toml").exists()
    s.no_create()
    results.append(
        "empty organization inventory "
        + (
            "explicitly creates only the confirmed org, then cancels environment"
            if create_org
            else "can cancel without organization or environment mutation"
        )
    )

# A separately saved setup state survives cancellation of organization creation.
Handler.org_response = b""


def prior_setup(session):
    platform = session.dir / "platform"
    platform.mkdir(mode=0o700)
    (platform / "setup-state").write_text("previous synthetic setup remains\n")


before = len(Handler.calls)
s = Session(
    "cloud-organization-final-cancel",
    ["--cloud", "create", "--no-profile", "--no-network"],
    fixture,
    prior_setup,
)
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("No organizations found. Create one?")
s.send(b"\r")
s.expect("Organization name")
s.send(b"Fixture team\r")
s.expect("Organization slug")
s.send(b"\r")
s.expect("Create organization?")
s.send(b"\x1b[B\r")
s.expect("canceled; no organization selected")
s.finish(1)
assert b"nothing changed" not in s.buf
assert (
    s.dir / "platform" / "setup-state"
).read_text() == "previous synthetic setup remains\n"
assert not any(
    path.endswith("/CreateOrganization") or path.endswith("/CreateEnvironment")
    for path, _ in Handler.calls[before:]
)
s.no_create()
results.append(
    "organization review cancellation scopes its message and preserves prior setup"
)

other_org = "33333333-3333-4333-8333-333333333333"
Handler.org_response = encode(
    "ListOrganizationsResponse",
    f'organizations {{ organization {{ id: "{org}" name: "First team" slug: "first" }} role: ORG_ROLE_OWNER }} '
    f'organizations {{ organization {{ id: "{other_org}" name: "Second team" slug: "second" }} role: ORG_ROLE_OWNER }}',
    "organization",
)
before = len(Handler.calls)
s = Session("init-project-needs-org-context", ["init"], fixture)
s.expect("Which workspace image?")
s.send(b"\r")
s.expect("Configuration settings")
s.send(b"\x1b[B" * 5 + b"\r")
s.expect("Where should Codewire store these secrets?")
s.send(b"\x1b[B\r")
s.expect("cw org set ID_OR_SLUG")
s.finish(1)
assert (
    b"Choose an organization" not in s.buf and b"Choose a secret project" not in s.buf
)
assert b"--org ID_OR_SLUG" not in s.buf
assert not any(
    path.endswith("/ListSecretProjects") or path.endswith("/CreateSecretProject")
    for path, _ in Handler.calls[before:]
)
s.no_create()
results.append(
    "portable project reference requires existing org context and gives the supported cw org set repair"
)

s = Session(
    "cloud-organization-choice",
    ["--cloud", "create", "--no-profile", "--no-network"],
    fixture,
)
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("Choose an organization")
s.send(b"\x1b[B\r")
s.expect("Environment settings")
s.send(b"\r")
s.expect("Create this environment?")
s.expect(other_org)
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
assert not (s.dir / "platform" / "config.toml").exists()
s.no_create()
results.append(
    "multiple organizations select an explicit context without saving a default"
)
s = Session(
    "cloud-project-org-context-cancel",
    ["--cloud", "create", "--no-profile", "--no-network"],
    fixture,
)
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("Choose an organization")
s.send(b"\x1b[B\r")
s.expect("Environment settings")
s.send(b"\x1b[B" * 5 + b"\r")
s.expect("Choose a secret project")
s.send(b"\r")
s.expect("Secret project name")
s.send(b"fixture-app\r")
s.expect("Create secret project fixture-app?")
assert mutation_count("CreateSecretProject") == 0
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
assert mutation_count("CreateSecretProject") == 0
payload = [
    data for path, data in Handler.calls if path.endswith("/ListSecretProjects")
][-1]
decoded = subprocess.check_output(
    [
        protoc,
        "-I" + repo + "/proto",
        "-I" + str(include),
        "--decode=codewire.v1.ListSecretProjectsRequest",
        "codewire/v1/secret.proto",
    ],
    input=payload,
).decode()
assert f'org_id: "{other_org}"' in decoded
s.no_create()
results.append(
    "secret-project metadata keeps the chosen organization; creation requires separate confirmation"
)
# First run creates a synthetic environment in the second org, then hands its
# exact identity and organization through every subsequent session RPC.
Handler.target_org = other_org
Handler.create_response = encode(
    "CreateEnvironmentResponse",
    f'environment {{ id: "{eid}" org_id: "{other_org}" name: "test-app" state: ENVIRONMENT_STATE_CREATING desired_state: DESIRED_STATE_STARTED operation_generation: 1 source_selection {{}} }}',
    "environment",
)
Handler.lookup = "ready"
before = len(Handler.calls)
s = Session(
    "run-cloud-multi-org-handoff", ["--cloud", "run", "claude", "--detach"], fixture
)
s.expect("Where would you like to work?")
s.send(b"\x1b[B\r")
s.expect("Environment name")
s.send(b"test-app\r")
s.expect("Choose an organization")
s.send(b"\x1b[B\r")
s.expect("Environment settings")
s.send(b"\r")
s.expect("Create this environment?")
s.expect(other_org)
s.send(b"\r")
s.expect("Started", seconds=20)
s.finish(0)
methods = {
    "CreateEnvironment": ("CreateEnvironmentRequest", "environment"),
    "StreamLogs": ("StreamLogsRequest", "environment"),
    "GetEnvironment": ("GetEnvironmentRequest", "environment"),
    "GetEnvironmentDaemonStatus": ("GetEnvironmentDaemonStatusRequest", "environment"),
    "ListSessions": ("ListSessionsRequest", "environment_session"),
    "LaunchSession": ("LaunchSessionRequest", "environment_session"),
}
seen = set()
for path, payload in Handler.calls[before:]:
    method = path.rsplit("/", 1)[-1]
    if method not in methods:
        continue
    seen.add(method)
    typ, file = methods[method]
    if method == "StreamLogs":
        payload = payload[5 : 5 + struct.unpack("!I", payload[1:5])[0]]
    decoded = subprocess.check_output(
        [
            protoc,
            "-I" + repo + "/proto",
            "-I" + str(include),
            "--decode=codewire.v1." + typ,
            "codewire/v1/" + file + ".proto",
        ],
        input=payload,
    ).decode()
    assert f'org_id: "{other_org}"' in decoded, method
    if method != "CreateEnvironment":
        assert f'environment_id: "{eid}"' in decoded, method
assert set(methods) <= seen, seen
assert not (s.dir / "platform" / "config.toml").exists()
s.no_create()
results.append(
    "first cloud launch binds every create, readiness and session RPC to the selected organization and exact created environment"
)
Handler.lookup = "not_found"
Handler.target_org = org
Handler.create_response = created
Handler.org_response = orgs

for cancel in [True, False]:
    before = sum(path.endswith("/CreateEnvironment") for path, _ in Handler.calls)
    s = Session(
        "cloud-review-" + ("cancel" if cancel else "success"),
        [
            "--cloud",
            "create",
            "--no-profile",
            "--no-network",
            "--no-wait",
            "--image",
            "workspace",
        ],
        fixture,
    )
    s.expect("Environment name")
    s.send(b"test-app\r")
    s.expect("Environment settings")
    s.send(b"\r")
    s.expect("Create this environment?")
    assert (
        sum(path.endswith("/CreateEnvironment") for path, _ in Handler.calls) == before
    ), "create before review approval"
    s.send(b"\x1b" if cancel else b"\r")
    s.expect("canceled" if cancel else "test-app")
    s.finish(1 if cancel else 0)
    after = sum(path.endswith("/CreateEnvironment") for path, _ in Handler.calls)
    assert after == before + (0 if cancel else 1)
    if not cancel:
        payload = [
            data for path, data in Handler.calls if path.endswith("/CreateEnvironment")
        ][-1]
        decoded = subprocess.check_output(
            [
                protoc,
                "-I" + repo + "/proto",
                "-I" + str(include),
                "--decode=codewire.v1.CreateEnvironmentRequest",
                "codewire/v1/environment.proto",
            ],
            input=payload,
        ).decode()
        assert f'org_id: "{org}"' in decoded and 'name: "test-app"' in decoded
        image = next(
            line.split('"')[1]
            for line in decoded.splitlines()
            if line.strip().startswith("image:")
        )
        assert (
            image.encode() in s.buf
        ), "submitted image differs from the reviewed image"
        assert "credentials {" not in decoded and "network:" not in decoded
    s.no_create()
    results.append(
        "synthetic cloud "
        + (
            "cancel sends no create request"
            if cancel
            else "confirmation sends one create request with exact sources"
        )
    )

s = Session("run-stale-cloud", ["--cloud", "run", "claude"], fixture, saved_selection)
s.expect("selected cloud environment no longer exists")
s.expect("Where would you like to work?")
s.send(b"\x1b")
s.expect("canceled")
s.finish(1)
s.no_create()
results.append("confirmed cloud not-found offers recovery before creation")
Handler.lookup = "unavailable"
s = Session(
    "run-cloud-unavailable", ["--cloud", "run", "claude"], fixture, saved_selection
)
s.expect("synthetic fixture lookup failure")
s.finish(1)
s.no_create()
assert b"Where would you like to work?" not in s.buf
results.append(
    "unavailable cloud authority remains an error and never offers replacement creation"
)
server.shutdown()
server.server_close()

print(
    json.dumps(
        {"root": str(root), "passed": len(results), "observed": results}, indent=2
    )
)
