"""Tests for the Codewire Python SDK using in-process Connect services."""

import io
import os
import sys
import threading
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError, ErrorDetail
from google.protobuf.timestamp_pb2 import Timestamp
from google.rpc.error_details_pb2 import BadRequest, ErrorInfo
from protobuf.wkt import Any

from codewire import Codewire, CodewireError
from codewire.environment import Environment
from codewire.v1.api_key_connect import ApiKeyServiceWSGIApplication
from codewire.v1.api_key_pb2 import (
    ApiKey,
    CreateApiKeyResponse,
    DeleteApiKeyResponse,
    ListApiKeysResponse,
    UpdateApiKeyResponse,
)
from codewire.v1.environment_connect import EnvironmentServiceWSGIApplication
from codewire.v1.environment_pb2 import (
    CreateEnvironmentResponse,
    DeleteEnvironmentResponse,
    DesiredState,
    Environment as ProtoEnvironment,
    EnvironmentState,
    GetEnvironmentResponse,
    ListEnvironmentsResponse,
    StartEnvironmentResponse,
    StopEnvironmentResponse,
)
from codewire.v1.exec_connect import ExecServiceWSGIApplication
from codewire.v1.exec_pb2 import ExecResponse
from codewire.v1.file_connect import FileServiceWSGIApplication
from codewire.v1.file_pb2 import (
    DownloadFileResponse,
    FileEntry,
    ListFilesResponse,
    UploadFileResponse,
)
from codewire.v1.port_connect import PortServiceWSGIApplication
from codewire.v1.port_pb2 import (
    CreatePortResponse,
    DeletePortResponse,
    ListPortsResponse,
    Port,
    PortAccess,
)
from codewire.v1.preset_connect import PresetServiceWSGIApplication
from codewire.v1.preset_pb2 import (
    CreatePresetResponse,
    DeletePresetResponse,
    GetPresetResponse,
    ListPresetsResponse,
    Preset,
    UpdatePresetResponse,
)
from codewire.v1.secret_connect import SecretServiceWSGIApplication
from codewire.v1.secret_pb2 import (
    CreateSecretProjectResponse,
    DeleteProjectSecretResponse,
    DeleteSecretProjectResponse,
    DeleteSecretResponse,
    DeleteUserSecretResponse,
    ListProjectSecretsResponse,
    ListSecretProjectsResponse,
    ListSecretsResponse,
    ListUserSecretsResponse,
    RenameProjectSecretResponse,
    RenameSecretResponse,
    RenameUserSecretResponse,
    SecretMetadata,
    SecretProject,
    SetProjectSecretResponse,
    SetSecretResponse,
    SetUserSecretResponse,
)


ENV_JSON = {
    "id": "env_123",
    "org_id": "org_test",
    "state": "running",
    "desired_state": "running",
    "type": "sandbox",
    "created_by": "user_1",
    "template_id": "tmpl_1",
    "recoverable": True,
    "state_changed_at": "2026-01-01T00:00:00Z",
    "cpu_millicores": 2000,
    "memory_mb": 4096,
    "disk_gb": 20,
    "total_running_seconds": 0,
    "created_at": "2026-01-01T00:00:00Z",
    "retry_count": 0,
}

TMPL_JSON = {
    "id": "tmpl_1",
    "org_id": "org_test",
    "name": "Go",
    "type": "sandbox",
    "build_status": "ready",
    "default_cpu_millicores": 2000,
    "default_memory_mb": 4096,
    "default_disk_gb": 20,
    "official": False,
    "created_at": "2026-01-01T00:00:00Z",
}


def _timestamp(value: str) -> Timestamp:
    timestamp = Timestamp()
    timestamp.FromJsonString(value)
    return timestamp


def _connect_detail(message: BadRequest | ErrorInfo) -> ErrorDetail:
    return ErrorDetail(
        Any(
            type_url=f"type.googleapis.com/{message.DESCRIPTOR.full_name}",
            value=message.SerializeToString(),
        )
    )


def _api_key(*, disabled: bool = False) -> ApiKey:
    value = ApiKey(
        id="key_1",
        user_id="user_1",
        org_id="org_test",
        name="test",
        key_prefix="cw_abc",
        scopes=[],
        created_at=_timestamp("2026-01-01T00:00:00.987654321Z"),
    )
    if disabled:
        value.disabled_at.CopyFrom(_timestamp("2026-01-02T00:00:00Z"))
    return value


class ApiKeyServiceFixture:
    """In-process generated Connect app for the API-key transport fixture."""

    @staticmethod
    def _require_auth(ctx):
        if ctx.request_headers.get("authorization") != "Bearer test-key":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")

    def list_api_keys(self, request, ctx):
        self._require_auth(ctx)
        if request.org_id != "org_test":
            raise ConnectError(Code.NOT_FOUND, "organization not found")
        return ListApiKeysResponse(api_keys=[_api_key()])

    def create_api_key(self, request, ctx):
        self._require_auth(ctx)
        if request.name == "invalid":
            raise ConnectError(
                Code.INVALID_ARGUMENT,
                "invalid API key",
                [
                    _connect_detail(
                        BadRequest(
                            field_violations=[
                                BadRequest.FieldViolation(
                                    field="name", description="must not be blank"
                                )
                            ]
                        )
                    ),
                    _connect_detail(
                        ErrorInfo(metadata={"request_id": "req_api_key"})
                    ),
                ],
            )
        return CreateApiKeyResponse(api_key=_api_key(), key="cw_abc123")

    def update_api_key(self, request, ctx):
        self._require_auth(ctx)
        if not request.HasField("disabled"):
            raise ConnectError(Code.INVALID_ARGUMENT, "disabled is required")
        return UpdateApiKeyResponse(api_key=_api_key(disabled=request.disabled))

    def delete_api_key(self, request, ctx):
        self._require_auth(ctx)
        if request.key_id == "missing":
            raise ConnectError(Code.NOT_FOUND, "not found")
        return DeleteApiKeyResponse()


class RecordingHTTPTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._transport = httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


def _environment(data: dict | None = None) -> ProtoEnvironment:
    value = data or ENV_JSON
    states = {
        "running": EnvironmentState.ENVIRONMENT_STATE_RUNNING,
        "provisioning": EnvironmentState.ENVIRONMENT_STATE_CREATING,
        "error": EnvironmentState.ENVIRONMENT_STATE_ERROR,
        "destroyed": EnvironmentState.ENVIRONMENT_STATE_DESTROYED,
    }
    return ProtoEnvironment(
        id=value["id"],
        org_id=value["org_id"],
        preset_id=value.get("preset_id", value.get("template_id", "")),
        type=value["type"],
        created_by=value["created_by"],
        state=states[value["state"]],
        desired_state=DesiredState.DESIRED_STATE_STARTED,
        error_reason=value.get("error_reason", ""),
        recoverable=value["recoverable"],
        state_changed_at=_timestamp(value["state_changed_at"]),
        cpu_millicores=value["cpu_millicores"],
        memory_mb=value["memory_mb"],
        disk_gb=value["disk_gb"],
        total_running_seconds=value["total_running_seconds"],
        created_at=_timestamp(value["created_at"]),
        retry_count=value["retry_count"],
    )


def _preset() -> Preset:
    return Preset(
        id=TMPL_JSON["id"],
        org_id=TMPL_JSON["org_id"],
        name=TMPL_JSON["name"],
        build_status=TMPL_JSON["build_status"],
        default_cpu_millicores=TMPL_JSON["default_cpu_millicores"],
        default_memory_mb=TMPL_JSON["default_memory_mb"],
        default_disk_gb=TMPL_JSON["default_disk_gb"],
        official=TMPL_JSON["official"],
        created_at=_timestamp(TMPL_JSON["created_at"]),
    )


class ControlPlaneFixture:
    """Generated Connect service doubles for the unchanged public drivers."""

    uploaded_files: dict[str, bytes] = {}
    env_get_count = 0
    env_get_sequence: list[dict] | None = None
    last_create_secret_project = ""

    def __getattr__(self, name):
        def unimplemented(*args, **kwargs):
            raise ConnectError(Code.UNIMPLEMENTED, f"fixture method not used: {name}")

        return unimplemented

    @staticmethod
    def _require_auth(ctx) -> None:
        if ctx.request_headers.get("authorization") != "Bearer test-key":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")

    def list_api_keys(self, request, ctx):
        return ApiKeyServiceFixture().list_api_keys(request, ctx)

    def create_api_key(self, request, ctx):
        return ApiKeyServiceFixture().create_api_key(request, ctx)

    def update_api_key(self, request, ctx):
        return ApiKeyServiceFixture().update_api_key(request, ctx)

    def delete_api_key(self, request, ctx):
        return ApiKeyServiceFixture().delete_api_key(request, ctx)

    def list_environments(self, request, ctx):
        self._require_auth(ctx)
        return ListEnvironmentsResponse(environments=[_environment()])

    def create_environment(self, request, ctx):
        self._require_auth(ctx)
        type(self).last_create_secret_project = request.secret_project
        return CreateEnvironmentResponse(environment=_environment())

    def get_environment(self, request, ctx):
        self._require_auth(ctx)
        if request.environment_id == "nonexistent-id":
            raise ConnectError(Code.NOT_FOUND, "not found")
        if self.env_get_sequence is not None:
            index = min(self.env_get_count, len(self.env_get_sequence) - 1)
            self.env_get_count += 1
            return GetEnvironmentResponse(environment=_environment(self.env_get_sequence[index]))
        return GetEnvironmentResponse(environment=_environment())

    def delete_environment(self, request, ctx):
        self._require_auth(ctx)
        return DeleteEnvironmentResponse()

    def stop_environment(self, request, ctx):
        self._require_auth(ctx)
        return StopEnvironmentResponse(status="stopped")

    def start_environment(self, request, ctx):
        self._require_auth(ctx)
        return StartEnvironmentResponse(status="started")

    def exec(self, request, ctx):
        self._require_auth(ctx)
        return ExecResponse(exit_code=0, stdout=b"hello\n", stderr=b"")

    def list_files(self, request, ctx):
        self._require_auth(ctx)
        return ListFilesResponse(
            entries=[
                FileEntry(
                    name="test.txt",
                    is_dir=False,
                    size=10,
                    mode=0o644,
                    mod_time=_timestamp("2026-01-01T00:00:00Z"),
                )
            ]
        )

    def download_file(self, request, ctx):
        self._require_auth(ctx)
        yield DownloadFileResponse(chunk=self.uploaded_files.get(request.path, b""))

    def upload_file(self, request, ctx):
        self._require_auth(ctx)
        header = None
        chunks: list[bytes] = []
        for item in request:
            if item.WhichOneof("payload") == "header":
                header = item.header
            else:
                chunks.append(item.chunk)
        assert header is not None
        data = b"".join(chunks)
        self.uploaded_files[header.path] = data
        return UploadFileResponse(path=header.path, size=len(data))

    def list_ports(self, request, ctx):
        self._require_auth(ctx)
        return ListPortsResponse(ports=[self._port()])

    def create_port(self, request, ctx):
        self._require_auth(ctx)
        return CreatePortResponse(port=self._port())

    def delete_port(self, request, ctx):
        self._require_auth(ctx)
        return DeletePortResponse()

    @staticmethod
    def _port() -> Port:
        return Port(
            id="port_1",
            environment_id="env_123",
            port=8080,
            label="web",
            access=PortAccess.PORT_ACCESS_PUBLIC,
            created_at=_timestamp("2026-01-01T00:00:00Z"),
        )

    def list_presets(self, request, ctx):
        self._require_auth(ctx)
        return ListPresetsResponse(presets=[_preset()])

    def create_preset(self, request, ctx):
        self._require_auth(ctx)
        return CreatePresetResponse(preset=_preset())

    def get_preset(self, request, ctx):
        self._require_auth(ctx)
        return GetPresetResponse(preset=_preset())

    def update_preset(self, request, ctx):
        self._require_auth(ctx)
        return UpdatePresetResponse(preset=_preset())

    def delete_preset(self, request, ctx):
        self._require_auth(ctx)
        return DeletePresetResponse()

    def list_secrets(self, request, ctx):
        self._require_auth(ctx)
        return ListSecretsResponse(secrets=[SecretMetadata(key="DB_URL")])

    def set_secret(self, request, ctx):
        self._require_auth(ctx)
        return SetSecretResponse()

    def delete_secret(self, request, ctx):
        self._require_auth(ctx)
        return DeleteSecretResponse()

    def rename_secret(self, request, ctx):
        self._require_auth(ctx)
        return RenameSecretResponse()

    def list_user_secrets(self, request, ctx):
        self._require_auth(ctx)
        return ListUserSecretsResponse(secrets=[SecretMetadata(key="TOKEN")])

    def set_user_secret(self, request, ctx):
        self._require_auth(ctx)
        return SetUserSecretResponse()

    def delete_user_secret(self, request, ctx):
        self._require_auth(ctx)
        return DeleteUserSecretResponse()

    def rename_user_secret(self, request, ctx):
        self._require_auth(ctx)
        return RenameUserSecretResponse()

    def list_secret_projects(self, request, ctx):
        self._require_auth(ctx)
        return ListSecretProjectsResponse(secret_projects=[self._project()])

    def create_secret_project(self, request, ctx):
        self._require_auth(ctx)
        return CreateSecretProjectResponse(secret_project=self._project())

    def delete_secret_project(self, request, ctx):
        self._require_auth(ctx)
        return DeleteSecretProjectResponse()

    def list_project_secrets(self, request, ctx):
        self._require_auth(ctx)
        return ListProjectSecretsResponse(secrets=[SecretMetadata(key="PROJECT_TOKEN")])

    def set_project_secret(self, request, ctx):
        self._require_auth(ctx)
        return SetProjectSecretResponse()

    def delete_project_secret(self, request, ctx):
        self._require_auth(ctx)
        return DeleteProjectSecretResponse()

    def rename_project_secret(self, request, ctx):
        self._require_auth(ctx)
        return RenameProjectSecretResponse()

    @staticmethod
    def _project() -> SecretProject:
        return SecretProject(
            id="proj_1",
            org_id="org_test",
            name="myapp",
            created_at=_timestamp("2026-01-01T00:00:00Z"),
        )

FIXTURE = ControlPlaneFixture()
CONNECT_APPS = {
    "/codewire.v1.ApiKeyService/": ApiKeyServiceWSGIApplication(FIXTURE),
    "/codewire.v1.EnvironmentService/": EnvironmentServiceWSGIApplication(FIXTURE),
    "/codewire.v1.ExecService/": ExecServiceWSGIApplication(FIXTURE),
    "/codewire.v1.FileService/": FileServiceWSGIApplication(FIXTURE),
    "/codewire.v1.PortService/": PortServiceWSGIApplication(FIXTURE),
    "/codewire.v1.PresetService/": PresetServiceWSGIApplication(FIXTURE),
    "/codewire.v1.SecretService/": SecretServiceWSGIApplication(FIXTURE),
}


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))
        chunks: list[bytes] = []
        while True:
            size = int(self.rfile.readline().split(b";", 1)[0], 16)
            if size == 0:
                self.rfile.readline()
                return b"".join(chunks)
            chunks.append(self.rfile.read(size))
            self.rfile.read(2)

    def _serve_connect(self):
        path, _, query = self.path.partition("?")
        app = next((app for prefix, app in CONNECT_APPS.items() if path.startswith(prefix)), None)
        if app is None:
            self.send_error(404)
            return
        environ = {
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "SERVER_NAME": self.server.server_address[0],
            "SERVER_PORT": str(self.server.server_address[1]),
            "SERVER_PROTOCOL": self.request_version,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(self._read_body()),
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        for name, value in self.headers.items():
            key = name.upper().replace("-", "_")
            environ[key if key in {"CONTENT_LENGTH", "CONTENT_TYPE"} else f"HTTP_{key}"] = value
        response: dict[str, object] = {}

        def start_response(status, headers, exc_info=None):
            response["status"] = status
            response["headers"] = headers

        chunks = app(environ, start_response)
        try:
            body = b"".join(chunks)
        finally:
            close = getattr(chunks, "close", None)
            if close is not None:
                close()
        self.send_response(int(str(response["status"]).split(" ", 1)[0]))
        for name, value in response["headers"]:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve_connect
    do_POST = _serve_connect
    do_PUT = _serve_connect
    do_PATCH = _serve_connect
    do_DELETE = _serve_connect


class SDKTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.cw = Codewire(
            api_key="test-key",
            org_id="org_test",
            base_url=cls.base_url,
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.cw.close()

    def test_environment_create(self):
        env = self.cw.environments.create(template_slug="python")
        self.assertIsInstance(env, Environment)
        self.assertEqual(env.id, "env_123")
        self.assertEqual(env.state, "running")

    def test_environment_get(self):
        env = self.cw.environments.get("env_123")
        self.assertEqual(env.id, "env_123")

    def test_environment_list(self):
        envs = self.cw.environments.list()
        self.assertEqual(len(envs), 1)
        self.assertIsInstance(envs[0], Environment)

    def test_environment_exec(self):
        env = self.cw.environments.create(template_slug="python")
        result = env.exec(command=["echo", "hello"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "hello\n")

    def test_environment_stop(self):
        env = self.cw.environments.create(template_slug="python")
        env.stop()  # should not raise

    def test_environment_remove(self):
        env = self.cw.environments.create(template_slug="python")
        env.remove()  # should not raise

    def test_environment_list_files(self):
        env = self.cw.environments.create(template_slug="python")
        files = env.list_files("/workspace")
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["name"], "test.txt")

    def test_environment_list_ports(self):
        env = self.cw.environments.create(template_slug="python")
        ports = env.list_ports()
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], 8080)

    def test_templates_crud(self):
        tmpl = self.cw.templates.create(name="Go", type="sandbox")
        self.assertEqual(tmpl["name"], "Go")

        tmpl2 = self.cw.templates.get("tmpl_1")
        self.assertEqual(tmpl2["id"], "tmpl_1")

        tmpls = self.cw.templates.list()
        self.assertEqual(len(tmpls), 1)
        # The REST handler accepted but did not implement this optional filter.
        # The Connect-backed wrapper keeps the frozen public behavior.
        self.assertEqual(len(self.cw.templates.list(type="non-sandbox")), 1)

        updated = self.cw.templates.update("tmpl_1", name="Golang")
        self.assertEqual(updated["name"], "Go")  # mock returns same

        self.cw.templates.delete("tmpl_1")

    def test_api_keys(self):
        key = self.cw.api_keys.create(name="test")
        self.assertEqual(key["key"], "cw_abc123")

        keys = self.cw.api_keys.list()
        self.assertEqual(len(keys), 1)

        self.cw.api_keys.delete("key_1")

    def test_api_key_connect_validation_error(self):
        with self.assertRaises(CodewireError) as raised:
            self.cw.api_keys.create(name="invalid")

        self.assertEqual(raised.exception.status, 400)
        self.assertEqual(raised.exception.request_id, "req_api_key")
        self.assertEqual(
            raised.exception.violations,
            [{"field": "name", "description": "must not be blank"}],
        )

    def test_secrets(self):
        secrets = self.cw.secrets.list()
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["key"], "DB_URL")

        self.cw.secrets.set("DB_URL", "postgres://...")
        self.cw.secrets.delete("DB_URL")

    def test_user_secrets(self):
        secrets = self.cw.secrets.list_user()
        self.assertEqual(len(secrets), 1)

        self.cw.secrets.set_user("TOKEN", "abc")
        self.cw.secrets.delete_user("TOKEN")

    def test_secret_projects(self):
        proj = self.cw.secret_projects.create("myapp")
        self.assertEqual(proj["name"], "myapp")

        projects = self.cw.secret_projects.list()
        self.assertEqual(len(projects), 1)

        self.cw.secret_projects.delete("proj_1")

    def test_error_handling(self):
        bad_cw = Codewire(
            api_key="wrong-key",
            org_id="org_test",
            base_url=self.base_url,
        )
        with self.assertRaises(CodewireError) as cm:
            bad_cw.environments.list()
        self.assertEqual(cm.exception.status, 401)
        bad_cw.close()

    def test_missing_org_id(self):
        no_org = Codewire(api_key="test-key", base_url=self.base_url)
        with self.assertRaises(ValueError) as cm:
            no_org.environments.list()
        self.assertIn("org_id is required", str(cm.exception))
        no_org.close()

    def test_environment_repr(self):
        env = self.cw.environments.create(template_slug="python")
        r = repr(env)
        self.assertIn("env_123", r)
        self.assertIn("running", r)

    def test_file_upload_download(self):
        ControlPlaneFixture.uploaded_files.clear()
        env = self.cw.environments.create(template_slug="python")
        env.upload(b"hello world", "/workspace/test.txt")
        data = env.download("/workspace/test.txt")
        self.assertEqual(data, b"hello world")

    def test_port_create_delete(self):
        env = self.cw.environments.create(template_slug="python")
        port = env.create_port(port=8080, label="web")
        self.assertEqual(port["id"], "port_1")
        self.assertEqual(port["port"], 8080)
        self.assertEqual(port["label"], "web")
        self.assertEqual(port["access"], "public")
        env.delete_port("port_1")  # should not raise

    def test_error_404(self):
        with self.assertRaises(CodewireError) as cm:
            self.cw.environments.get("nonexistent-id")
        self.assertEqual(cm.exception.status, 404)

    def test_wait_ready(self):
        provisioning_env = dict(ENV_JSON, state="provisioning")
        running_env = dict(ENV_JSON, state="running")
        ControlPlaneFixture.env_get_sequence = [provisioning_env, running_env]
        ControlPlaneFixture.env_get_count = 0
        try:
            env = Environment(
                dict(ENV_JSON, state="provisioning"), self.cw._context
            )
            env.wait_ready(timeout=10, interval=0.1)
            self.assertEqual(env.state, "running")
        finally:
            ControlPlaneFixture.env_get_sequence = None
            ControlPlaneFixture.env_get_count = 0

    def test_wait_ready_error(self):
        error_env = dict(ENV_JSON, state="error", error_reason="out of resources")
        ControlPlaneFixture.env_get_sequence = [error_env]
        ControlPlaneFixture.env_get_count = 0
        try:
            env = Environment(
                dict(ENV_JSON, state="provisioning"), self.cw._context
            )
            with self.assertRaises(CodewireError) as cm:
                env.wait_ready(timeout=10, interval=0.1)
            self.assertIn("error", str(cm.exception).lower())
        finally:
            ControlPlaneFixture.env_get_sequence = None
            ControlPlaneFixture.env_get_count = 0

    def test_create_with_wait(self):
        provisioning_env = dict(ENV_JSON, state="provisioning")
        running_env = dict(ENV_JSON, state="running")
        ControlPlaneFixture.env_get_sequence = [provisioning_env, running_env]
        ControlPlaneFixture.env_get_count = 0
        try:
            env = self.cw.environments.create(
                template_slug="python", wait=True, wait_timeout=10
            )
            self.assertEqual(env.state, "running")
        finally:
            ControlPlaneFixture.env_get_sequence = None
            ControlPlaneFixture.env_get_count = 0

    def test_api_key_update(self):
        result = self.cw.api_keys.update("key-1", disabled=True)
        self.assertEqual(result["id"], "key_1")
        self.assertEqual(result["disabled_at"], "2026-01-02T00:00:00Z")

    def test_injected_http_client_remains_available_to_connect_services(self):
        transport = RecordingHTTPTransport()
        with httpx.Client(base_url=self.base_url, transport=transport) as http_client:
            client = Codewire(
                api_key="test-key",
                org_id="org_test",
                base_url=self.base_url,
                http_client=http_client,
            )
            try:
                self.assertEqual(len(client.api_keys.list()), 1)
                self.assertEqual(client.environments.get("env_123").id, "env_123")
            finally:
                client.close()
            self.assertFalse(http_client.is_closed)
        self.assertEqual(
            [request.url.path for request in transport.requests],
            [
                "/codewire.v1.ApiKeyService/ListApiKeys",
                "/codewire.v1.EnvironmentService/GetEnvironment",
            ],
        )
        self.assertEqual(
            transport.requests[0].headers["authorization"], "Bearer test-key"
        )

    def test_injected_http_client_handles_connect_streaming(self):
        ControlPlaneFixture.uploaded_files.clear()
        transport = RecordingHTTPTransport()
        with httpx.Client(base_url=self.base_url, transport=transport) as http_client:
            with Codewire(
                api_key="test-key",
                org_id="org_test",
                base_url=self.base_url,
                http_client=http_client,
            ) as client:
                environment = client.environments.get("env_123")
                environment.files.upload(b"injected transport", "/workspace/injected.txt")
                self.assertEqual(
                    environment.files.download("/workspace/injected.txt"),
                    b"injected transport",
                )
            self.assertFalse(http_client.is_closed)

        self.assertEqual(
            [request.url.path for request in transport.requests],
            [
                "/codewire.v1.EnvironmentService/GetEnvironment",
                "/codewire.v1.FileService/UploadFile",
                "/codewire.v1.FileService/DownloadFile",
            ],
        )

    def test_timeout_constructor(self):
        cw = Codewire(
            api_key="cw_test",
            org_id="test",
            base_url=self.base_url,
            timeout=60,
        )
        self.assertIsNotNone(cw)
        cw.close()

    def test_environment_base_url_override_targets_connect_origin(self):
        with patch.dict(os.environ, {"CODEWIRE_BASE_URL": self.base_url}):
            with Codewire(api_key="test-key", org_id="org_test") as client:
                self.assertEqual(client.environments.get("env_123").id, "env_123")

    def test_typed_params(self):
        env = self.cw.environments.create(template_slug="python")
        self.assertIsInstance(env, Environment)

    def test_environment_create_keeps_secret_project_name_selector(self):
        try:
            self.cw.environments.create(
                template_slug="python", secret_project="myapp"
            )
            self.assertEqual(ControlPlaneFixture.last_create_secret_project, "myapp")
        finally:
            ControlPlaneFixture.last_create_secret_project = ""


if __name__ == "__main__":
    unittest.main()
