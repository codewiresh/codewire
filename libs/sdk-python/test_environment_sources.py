"""Synthetic generated-Connect proof for complete source selections."""

from copy import deepcopy
import unittest
from unittest.mock import patch

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError
from google.protobuf.json_format import ParseError

from codewire import Codewire, CodewireError
from codewire import _convert
from codewire.v1 import common_pb2 as common
from codewire.v1 import environment_pb2 as pb
from codewire.v1.environment_connect import EnvironmentServiceWSGIApplication


EXACT = 9_007_199_254_741_009
MAXIMUM = (1 << 64) - 1
PROFILE = "platform:id:00000000-0000-4000-8000-000000000011"
PROJECT = "platform:id:00000000-0000-4000-8000-000000000022"
SELECTION = {
    "secrets": {"project": PROJECT, "organization": True, "user": "platform"},
    "credentials": {"profile": PROFILE},
    "profile_revision": EXACT,
}


class SourceFixture:
    def __init__(self):
        self.calls = []
        self.outcome = pb.ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED
        self.response_mutation = lambda response: None
        self.failure = None

    def __getattr__(self, name):
        def unimplemented(*args, **kwargs):
            raise ConnectError(Code.UNIMPLEMENTED, "unused synthetic method")
        return unimplemented

    def record(self, method, request, ctx):
        if ctx.request_headers.get("authorization") != "Bearer synthetic-source-user":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")
        if request.org_id != "organization-one":
            raise ConnectError(Code.PERMISSION_DENIED, "wrong organization")
        self.calls.append((method, request))

    def create_environment(self, request, ctx):
        self.record("CreateEnvironment", request, ctx)
        return pb.CreateEnvironmentResponse(environment=pb.Environment(
            id="environment-one", operation_generation=EXACT,
            source_selection=_convert.environment_source_selection_from_dict(SELECTION),
        ))

    def update_environment_sources(self, request, ctx):
        self.record("UpdateEnvironmentSources", request, ctx)
        if self.failure is not None:
            raise ConnectError(self.failure, "synthetic source update denied")
        if not request.HasField("expected") or not request.HasField("replacement"):
            raise ConnectError(Code.INVALID_ARGUMENT, "complete selections required")
        response = pb.UpdateEnvironmentSourcesResponse(
            environment_id=request.environment_id,
            operation_generation=request.expected_operation_generation,
            selection=request.replacement,
            outcome=self.outcome,
        )
        self.response_mutation(response)
        return response


class EnvironmentSourcesTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = SourceFixture()
        app = EnvironmentServiceWSGIApplication(self.fixture)
        self.paths = []

        def recording_app(environ, start_response):
            self.paths.append(environ["PATH_INFO"])
            return app(environ, start_response)

        self.http = httpx.Client(transport=httpx.WSGITransport(app=recording_app))
        self.cw = Codewire(
            api_key="synthetic-source-user", org_id="organization-one",
            base_url="https://sdk.example.test", http_client=self.http,
        )

    def tearDown(self):
        self.cw.close()
        self.assertFalse(self.http.is_closed)
        self.http.close()

    def update(self, **overrides):
        arguments = {
            "expected_operation_generation": EXACT,
            "expected": deepcopy(SELECTION), "replacement": {},
        }
        arguments.update(overrides)
        return self.cw.environments.update_sources("environment-one", **arguments)

    def test_project_roundtrip_preserves_origin_credentials_and_ssh_trust(self):
        project = {
            "schema_version": 1, "working_directory": "/workspace/app",
            "repositories": [{
                "source": "ssh://git@example.test/repository", "destination": "/workspace/app",
                "known_hosts": ["example.test ssh-ed25519 synthetic-public-host-key"],
            }],
            "secrets": deepcopy(SELECTION["secrets"]),
            "credentials": deepcopy(SELECTION["credentials"]),
        }
        original = deepcopy(project)
        encoded = _convert.project_spec_from_dict(project)
        decoded = _convert.project_spec_to_dict(encoded)
        self.assertEqual(project, original)
        self.assertEqual(decoded["secrets"], project["secrets"])
        self.assertEqual(decoded["credentials"], project["credentials"])
        self.assertEqual(decoded["repositories"][0]["known_hosts"], project["repositories"][0]["known_hosts"])
        self.assertNotIn("access", decoded)
        for placement in ("local", "platform"):
            value = _convert.project_spec_from_dict({"secrets": {"user": placement}})
            self.assertEqual(_convert.project_spec_to_dict(value)["secrets"]["user"], placement)
        value = _convert.project_spec_from_dict({"secrets": {"project": PROJECT}})
        self.assertFalse(value.secrets.HasField("user"))
        self.assertNotIn("user", _convert.project_spec_to_dict(value)["secrets"])

    def test_create_carries_confirmation_revision_and_returned_selection(self):
        environment = self.cw.environments.create(
            project_spec={"secrets": SELECTION["secrets"], "credentials": SELECTION["credentials"]},
            expected_profile_revision=MAXIMUM,
            confirm_personal_credentials=True, confirm_personal_secrets=True,
        )
        request = self.fixture.calls[-1][1]
        self.assertEqual(request.expected_profile_revision, MAXIMUM)
        self.assertTrue(request.confirm_personal_credentials)
        self.assertTrue(request.confirm_personal_secrets)
        self.assertEqual(request.project_spec.credentials.profile, PROFILE)
        self.assertEqual(request.project_spec.secrets.user, common.PROJECT_STORAGE_PLACEMENT_PLATFORM)
        self.assertEqual(environment.operation_generation, EXACT)
        self.assertEqual(environment.source_selection, SELECTION)
        self.assertEqual(self.paths, ["/codewire.v1.EnvironmentService/CreateEnvironment"])

    def test_create_preview_omission_is_explicit_and_boolean(self):
        self.cw.environments.create(project_spec={})
        self.assertFalse(self.fixture.calls[-1][1].omit_application_previews)
        for omit in (True, False):
            self.cw.environments.create(project_spec={}, omit_application_previews=omit)
            self.assertEqual(self.fixture.calls[-1][1].omit_application_previews, omit)
        count = len(self.fixture.calls)
        for invalid in (1, 0, "true", None):
            with self.assertRaisesRegex(ValueError, "explicit boolean"):
                self.cw.environments.create(project_spec={}, omit_application_previews=invalid)
        self.assertEqual(len(self.fixture.calls), count)

    def test_create_joins_a_named_network_only_when_asked(self):
        self.cw.environments.create(project_spec={})
        self.assertEqual(self.fixture.calls[-1][1].network, "")
        self.cw.environments.create(project_spec={}, network="work")
        self.assertEqual(self.fixture.calls[-1][1].network, "work")
        count = len(self.fixture.calls)
        for invalid in ("", 1):
            with self.assertRaisesRegex(ValueError, "Mesh network name"):
                self.cw.environments.create(project_spec={}, network=invalid)
        self.assertEqual(len(self.fixture.calls), count)

    def test_create_never_infers_personal_consent_or_a_revision(self):
        self.cw.environments.create(project_spec={})
        request = self.fixture.calls[-1][1]
        self.assertFalse(request.HasField("expected_profile_revision"))
        self.assertFalse(request.confirm_personal_credentials)
        self.assertFalse(request.confirm_personal_secrets)
        count = len(self.fixture.calls)
        for field in ("confirm_personal_credentials", "confirm_personal_secrets"):
            with self.assertRaisesRegex(ValueError, "explicit boolean"):
                self.cw.environments.create(project_spec={}, **{field: 1})
        for revision in (0, -1, True, 1.5, MAXIMUM + 1):
            with self.assertRaisesRegex(ValueError, "positive uint64"):
                self.cw.environments.create(project_spec={}, expected_profile_revision=revision)
        with self.assertRaisesRegex(ValueError, "exact revision"):
            self.cw.environments.create(project_spec={"credentials": {"profile": PROFILE}})
        with self.assertRaisesRegex(ValueError, "exact revision"):
            self.cw.environments.create(project_spec={}, expected_profile_revision=EXACT)
        self.assertEqual(len(self.fixture.calls), count)

    def test_update_clear_preserves_both_objects_and_exact_cas(self):
        expected = deepcopy(SELECTION)
        result = self.update(expected=expected, expected_operation_generation=MAXIMUM)
        request = self.fixture.calls[-1][1]
        self.assertEqual(request.expected_operation_generation, MAXIMUM)
        self.assertEqual(_convert.proto_to_dict(request.expected), SELECTION)
        self.assertTrue(request.HasField("replacement"))
        self.assertEqual(_convert.proto_to_dict(request.replacement), {})
        self.assertFalse(request.allow_restart)
        self.assertFalse(request.confirm_personal_credentials)
        self.assertFalse(request.confirm_personal_secrets)
        self.assertEqual(expected, SELECTION)
        self.assertEqual(result, {"environment_id": "environment-one", "operation_generation": MAXIMUM,
                                  "selection": {}, "outcome": "stored"})
        self.assertEqual(self.paths, ["/codewire.v1.EnvironmentService/UpdateEnvironmentSources"])

    def test_update_outcomes_and_explicit_permissions_survive_the_wire(self):
        for outcome, expected in ((pb.ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNCHANGED, "unchanged"),
                                  (pb.ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED, "stored"),
                                  (pb.ENVIRONMENT_SOURCES_UPDATE_OUTCOME_RESTART_REQUIRED, "restart_required")):
            self.fixture.outcome = outcome
            result = self.update(expected={}, replacement=SELECTION, allow_restart=True,
                                 confirm_personal_credentials=True, confirm_personal_secrets=True)
            request = self.fixture.calls[-1][1]
            self.assertTrue(request.HasField("expected"))
            self.assertTrue(request.allow_restart)
            self.assertTrue(request.confirm_personal_credentials)
            self.assertTrue(request.confirm_personal_secrets)
            self.assertEqual(result["selection"], SELECTION)
            self.assertEqual(result["outcome"], expected)

    def test_update_denial_and_stale_cas_are_not_retried(self):
        for code, status in ((Code.ABORTED, 409), (Code.PERMISSION_DENIED, 403),
                             (Code.FAILED_PRECONDITION, 400)):
            self.fixture.failure = code
            count = len(self.fixture.calls)
            with self.assertRaises(CodewireError) as error:
                self.update()
            self.assertEqual(error.exception.status, status)
            self.assertEqual(len(self.fixture.calls), count + 1)

    def test_invalid_source_shapes_and_flags_fail_before_transport(self):
        for value in (None, False, "", []):
            with self.assertRaisesRegex(ValueError, "explicit object"):
                self.update(expected=value)
            with self.assertRaisesRegex(ValueError, "explicit object"):
                self.update(replacement=value)
        for value in (True, False, 1, 0, "user", "unspecified", None):
            with self.assertRaisesRegex(ValueError, "placement"):
                self.update(replacement={"secrets": {"user": value}})
        for value in ({"credentials": {"profile": PROFILE}}, {"profile_revision": EXACT}):
            with self.assertRaisesRegex(ValueError, "exact revision"):
                self.update(replacement=value)
        for value in (0, -1, True, 1.5, MAXIMUM + 1):
            with self.assertRaisesRegex(ValueError, "positive uint64"):
                self.update(expected_operation_generation=value)
            with self.assertRaisesRegex(ValueError, "positive uint64"):
                self.update(replacement={**SELECTION, "profile_revision": value})
        for field in ("allow_restart", "confirm_personal_credentials", "confirm_personal_secrets"):
            with self.assertRaisesRegex(ValueError, "explicit boolean"):
                self.update(**{field: 1})
        self.assertEqual(self.fixture.calls, [])

    def test_malformed_source_update_responses_are_not_success(self):
        mutations = [
            lambda response: response.ClearField("selection"),
            lambda response: setattr(response, "outcome", 0),
            lambda response: setattr(response, "outcome", 999),
            lambda response: setattr(response, "environment_id", "another-environment"),
            lambda response: setattr(response, "operation_generation", 0),
        ]
        for mutation in mutations:
            self.fixture.response_mutation = mutation
            with self.assertRaises((RuntimeError, ValueError)):
                self.update()

    def test_removed_project_grammar_is_not_translated(self):
        with self.assertRaises(ParseError):
            self.cw.environments.create(project_spec={"access": {"profile": PROFILE}})
        with self.assertRaisesRegex(ValueError, "placement"):
            self.cw.environments.create(project_spec={"secrets": {"user": True}})
        self.assertEqual(self.fixture.calls, [])

    def test_partial_observed_selections_are_not_returned_as_cas_state(self):
        for selection in (
            pb.EnvironmentSourceSelection(credentials=common.ProjectCredentialBinding(profile=PROFILE)),
            pb.EnvironmentSourceSelection(profile_revision=EXACT),
            pb.EnvironmentSourceSelection(
                credentials=common.ProjectCredentialBinding(profile=PROFILE), profile_revision=0),
        ):
            with self.assertRaises((RuntimeError, ValueError)):
                _convert.environment_to_dict(pb.Environment(source_selection=selection))
            with self.assertRaises((RuntimeError, ValueError)):
                _convert.environment_sources_update_to_dict(pb.UpdateEnvironmentSourcesResponse(
                    operation_generation=EXACT, selection=selection,
                    outcome=pb.ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED))

    def test_new_source_fields_remain_in_the_descriptor_guard(self):
        with patch.dict(_convert._SOURCE_DESCRIPTOR_FIELDS, {
            "EnvironmentSourceSelection": {1: "secrets", 2: "credentials"},
        }):
            with self.assertRaisesRegex(RuntimeError, "converter covers"):
                _convert.assert_environment_converter_coverage()
