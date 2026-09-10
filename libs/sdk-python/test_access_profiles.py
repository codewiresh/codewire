"""Synthetic in-process generated Connect access-profile consumer proof."""

import unittest

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError

from codewire import Codewire, CodewireError
from codewire.v1 import access_profile_pb2 as pb
from codewire.v1.access_profile_connect import AccessProfileServiceWSGIApplication


EXACT = 9_007_199_254_741_009
MAXIMUM = (1 << 64) - 1
ENTRY = {"capability_slot": "codex", "credential_id": "credential-one"}
BINDING = {"environment_id": "environment-one", "access_profile_id": "profile-one",
           "access_profile_revision": EXACT}


class AccessProfileFixture:
    def __init__(self):
        self.calls = []

    def record(self, name, request, ctx):
        if ctx.request_headers.get("authorization") != "Bearer synthetic-opaque-oauth":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")
        if "org_id" in request.DESCRIPTOR.fields_by_name:
            raise AssertionError("personal profiles must not inherit organization scope")
        self.calls.append((name, request))

    @staticmethod
    def profile():
        return pb.AccessProfile(id="profile-one", name="personal", revision=EXACT,
                                entries=[pb.AccessProfileEntry(**ENTRY)])

    def list_access_profiles(self, request, ctx):
        self.record("ListAccessProfiles", request, ctx)
        return pb.ListAccessProfilesResponse(
            access_profiles=[self.profile()], next_page_token="page-two" if not request.page_token else "")

    def get_access_profile(self, request, ctx):
        self.record("GetAccessProfile", request, ctx)
        if request.access_profile_id == "missing":
            raise ConnectError(Code.NOT_FOUND, "not found")
        if request.access_profile_id == "missing-response":
            return pb.GetAccessProfileResponse()
        return pb.GetAccessProfileResponse(access_profile=self.profile())

    def create_access_profile(self, request, ctx):
        self.record("CreateAccessProfile", request, ctx)
        return pb.CreateAccessProfileResponse(access_profile=self.profile())

    def update_access_profile(self, request, ctx):
        self.record("UpdateAccessProfile", request, ctx)
        if request.access_profile_id == "stale":
            raise ConnectError(Code.ABORTED, "stale revision")
        return pb.UpdateAccessProfileResponse(access_profile=self.profile())

    def delete_access_profile(self, request, ctx):
        self.record("DeleteAccessProfile", request, ctx)
        return pb.DeleteAccessProfileResponse()

    def get_environment_access_profile(self, request, ctx):
        self.record("GetEnvironmentAccessProfile", request, ctx)
        if request.environment_id == "unbound":
            return pb.GetEnvironmentAccessProfileResponse()
        return pb.GetEnvironmentAccessProfileResponse(
            binding=pb.EnvironmentAccessProfileBinding(**BINDING), personal_credentials_confirmed=True)

class AccessProfilesTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = AccessProfileFixture()
        app = AccessProfileServiceWSGIApplication(self.fixture)
        self.paths = []

        def recording_app(environ, start_response):
            self.paths.append(environ["PATH_INFO"])
            return app(environ, start_response)

        self.http = httpx.Client(transport=httpx.WSGITransport(app=recording_app))
        self.cw = Codewire(api_key="synthetic-opaque-oauth", base_url="https://sdk.example.test",
                           http_client=self.http)

    def tearDown(self):
        self.cw.close()
        self.assertFalse(self.http.is_closed, "SDK must not close caller-owned transport")
        self.http.close()

    def test_list_pagination_uses_generated_path_and_default_size(self):
        profiles = self.cw.access_profiles.list()
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0]["revision"], EXACT)
        self.assertEqual(profiles[0]["entries"], [ENTRY])
        self.assertEqual([request.page_token for _, request in self.fixture.calls], ["", "page-two"])
        self.assertTrue(all(request.page_size == 0 for _, request in self.fixture.calls))
        self.assertEqual(self.paths, ["/codewire.v1.AccessProfileService/ListAccessProfiles"] * 2)

    def test_id_name_selectors_and_revision_presence_are_exact(self):
        self.assertEqual(self.cw.access_profiles.get("profile-one")["revision"], EXACT)
        request = self.fixture.calls[-1][1]
        self.assertEqual(request.WhichOneof("selector"), "access_profile_id")
        self.assertEqual(request.access_profile_id, "profile-one")
        self.assertFalse(request.HasField("revision"))
        self.cw.access_profiles.get_by_name("personal", revision=EXACT)
        request = self.fixture.calls[-1][1]
        self.assertEqual(request.WhichOneof("selector"), "name")
        self.assertEqual(request.name, "personal")
        self.assertEqual(request.revision, EXACT)

    def test_create_update_delete_preserve_uint64_and_empty_replacement(self):
        self.cw.access_profiles.create("personal", [ENTRY])
        self.assertEqual(self.fixture.calls[-1][1].name, "personal")
        self.assertEqual(self.fixture.calls[-1][1].entries[0].credential_id, "credential-one")
        self.cw.access_profiles.update("profile-one", EXACT, [])
        self.assertEqual(self.fixture.calls[-1][1].expected_revision, EXACT)
        self.assertEqual(len(self.fixture.calls[-1][1].entries), 0)
        self.cw.access_profiles.delete("profile-one", MAXIMUM)
        self.assertEqual(self.fixture.calls[-1][1].expected_revision, MAXIMUM)
        self.assertEqual(self.paths, [f"/codewire.v1.AccessProfileService/{method}" for method in
                                    ["CreateAccessProfile", "UpdateAccessProfile", "DeleteAccessProfile"]])

    def test_duplicate_slots_and_invalid_revisions_fail_before_transport(self):
        for invoke in [lambda: self.cw.access_profiles.create("personal", [ENTRY, ENTRY]),
                       lambda: self.cw.access_profiles.update("profile-one", EXACT, [ENTRY, ENTRY])]:
            with self.assertRaisesRegex(ValueError, "duplicate"):
                invoke()
        for revision in [0, -1, MAXIMUM + 1, True, 1.5]:
            with self.assertRaisesRegex(ValueError, "positive uint64"):
                self.cw.access_profiles.get("profile-one", revision=revision)
        self.assertEqual(self.fixture.calls, [])

    def test_binding_read_preserves_presence_and_stored_consent(self):
        self.assertEqual(self.cw.access_profiles.get_environment_binding("unbound"),
                         {"binding": None, "personal_credentials_confirmed": False})
        self.assertEqual(self.cw.access_profiles.get_environment_binding("environment-one"),
                         {"binding": BINDING, "personal_credentials_confirmed": True})
        self.assertEqual(self.paths[-1], "/codewire.v1.AccessProfileService/GetEnvironmentAccessProfile")

    def test_retired_binding_mutation_methods_are_absent(self):
        self.assertFalse(hasattr(self.cw.access_profiles, "set_environment_binding"))
        self.assertFalse(hasattr(self.cw.access_profiles, "clear_environment_binding"))
        self.assertEqual(self.fixture.calls, [])

    def test_stale_cas_and_not_found_map_without_automatic_retry(self):
        with self.assertRaises(CodewireError) as stale:
            self.cw.access_profiles.update("stale", EXACT, [])
        self.assertEqual(stale.exception.status, 409)
        self.assertEqual(len(self.fixture.calls), 1)
        with self.assertRaises(CodewireError) as missing:
            self.cw.access_profiles.get("missing")
        self.assertEqual(missing.exception.status, 404)
        self.assertEqual(len(self.fixture.calls), 2)

    def test_missing_profile_response_is_not_an_empty_success(self):
        with self.assertRaisesRegex(RuntimeError, "omitted access_profile"):
            self.cw.access_profiles.get("missing-response")
