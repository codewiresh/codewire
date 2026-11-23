"""Synthetic in-process generated Connect sandbox identity consumer proof."""

import unittest

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError

from codewire import Codewire, CodewireError
from codewire.v1 import sandbox_identity_pb2 as pb
from codewire.v1.sandbox_identity_connect import SandboxIdentityServiceWSGIApplication


class SandboxIdentityFixture:
    def __init__(self):
        self.calls = []

    def record(self, name, request):
        self.calls.append((name, request))

    @staticmethod
    def audience():
        value = pb.IdentityAudience(
            org_id="org-one", audience="https://vault.example.com/v1/auth/jwt",
            claim_created_by=True, file_name="vault", version=1794600000000000,
            created_by="user-one")
        value.visible_groups.names.append("readers")
        value.lifetime.seconds = 300
        value.created_at.FromJsonString("2026-11-21T18:00:00Z")
        return value

    def get_environment_identity_groups(self, request, ctx):
        self.record("GetEnvironmentIdentityGroups", request)
        if request.environment_id == "never":
            return pb.GetEnvironmentIdentityGroupsResponse(
                groups=pb.EnvironmentIdentityGroups(environment_id="never"))
        groups = pb.EnvironmentIdentityGroups(
            environment_id=request.environment_id, groups=["builders"], version=2)
        groups.updated_at.FromJsonString("2026-11-21T18:00:00Z")
        return pb.GetEnvironmentIdentityGroupsResponse(groups=groups)

    def set_environment_identity_groups(self, request, ctx):
        self.record("SetEnvironmentIdentityGroups", request)
        if "all" in request.groups:
            raise ConnectError(Code.INVALID_ARGUMENT, "group name `all` is reserved: every token carries it")
        return pb.SetEnvironmentIdentityGroupsResponse(
            groups=pb.EnvironmentIdentityGroups(
                environment_id=request.environment_id, groups=list(request.groups), version=3),
            previous_groups=["builders"], changed=True,
            can_run_code=[
                pb.IdentityGroupUser(user_id="user-one", email="one@example.com",
                                     reason=pb.IDENTITY_GROUP_USER_REASON_CREATOR),
                pb.IdentityGroupUser(user_id="user-two", email="two@example.com", reason=99),
            ])

    def register_identity_audience(self, request, ctx):
        self.record("RegisterIdentityAudience", request)
        return pb.RegisterIdentityAudienceResponse(audience=self.audience())

    def list_identity_audiences(self, request, ctx):
        self.record("ListIdentityAudiences", request)
        return pb.ListIdentityAudiencesResponse(audiences=[
            self.audience(), pb.IdentityAudience(org_id="org-one", audience="https://k8s.example", version=2)])

    def remove_identity_audience(self, request, ctx):
        self.record("RemoveIdentityAudience", request)
        return pb.RemoveIdentityAudienceResponse(audience="https://k8s.example")

    def stop_identity_minting(self, request, ctx):
        self.record("StopIdentityMinting", request)
        return pb.StopIdentityMintingResponse(changed=True)

    def resume_identity_minting(self, request, ctx):
        self.record("ResumeIdentityMinting", request)
        return pb.ResumeIdentityMintingResponse(changed=False)


class SandboxIdentityTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = SandboxIdentityFixture()
        app = SandboxIdentityServiceWSGIApplication(self.fixture)
        self.http = httpx.Client(transport=httpx.WSGITransport(app=app))
        self.cw = Codewire(api_key="synthetic", base_url="https://sdk.example.test",
                           org_id="org-one", http_client=self.http)

    def tearDown(self):
        self.cw.close()
        self.http.close()

    def last(self):
        return self.fixture.calls[-1][1]

    def test_groups_are_read_and_replaced_with_who_can_use_them(self):
        read = self.cw.sandbox_identity.get_groups("env-one")
        self.assertEqual(read, {"environment_id": "env-one", "groups": ["builders"], "version": 2,
                                "updated_at": "2026-11-21T18:00:00Z"})
        never = self.cw.sandbox_identity.get_groups("never")
        self.assertEqual((never["groups"], never["version"], never["updated_at"]), ([], 0, None))

        result = self.cw.sandbox_identity.set_groups("env-one", ["data-readers"])
        self.assertEqual(list(self.last().groups), ["data-readers"])
        self.assertTrue(result["changed"])
        self.assertEqual(result["previous_groups"], ["builders"])
        # A reason this SDK does not know yet never fails the call.
        self.assertEqual([(user["email"], user["reason"]) for user in result["can_run_code"]],
                         [("one@example.com", "creator"), ("two@example.com", "unknown")])
        with self.assertRaises(CodewireError):
            self.cw.sandbox_identity.set_groups("env-one", ["all"])

    def test_an_audience_is_registered_listed_and_removed(self):
        registered = self.cw.sandbox_identity.register_audience(
            "https://vault.example.com/v1/auth/jwt", visible_groups=["readers"],
            lifetime_seconds=300, claim_created_by=True, file_name="vault")
        request = self.last()
        self.assertEqual(list(request.visible_groups.names), ["readers"])
        self.assertEqual(request.lifetime.seconds, 300)
        self.assertEqual((request.claim_created_by, request.claim_environment_name), (True, False))
        self.assertEqual(request.file_name, "vault")
        self.assertEqual(registered, {
            "org_id": "org-one", "audience": "https://vault.example.com/v1/auth/jwt",
            "visible_groups": ["readers"], "lifetime_seconds": 300, "claim_created_by": True,
            "claim_environment_name": False, "file_name": "vault", "version": 1794600000000000,
            "created_by": "user-one", "created_at": "2026-11-21T18:00:00Z"})

        self.cw.sandbox_identity.register_audience("https://k8s.example")
        request = self.last()
        self.assertFalse(request.HasField("visible_groups"), "every group unless named")
        self.assertFalse(request.HasField("lifetime"), "ten minutes unless named")
        self.assertFalse(request.HasField("file_name"))
        self.cw.sandbox_identity.register_audience("https://none.example", visible_groups=[])
        self.assertTrue(self.last().HasField("visible_groups"), "an empty list sees none but all")

        listed = self.cw.sandbox_identity.list_audiences()
        self.assertEqual(len(listed), 2)
        self.assertEqual((listed[1]["visible_groups"], listed[1]["lifetime_seconds"], listed[1]["file_name"]),
                         (None, 600, None))
        self.assertEqual(self.cw.sandbox_identity.remove_audience("HTTPS://K8S.EXAMPLE:443"),
                         "https://k8s.example")
        self.assertTrue(all(request.org_id == "org-one" for _, request in self.fixture.calls))

    def test_minting_stops_for_a_sandbox_or_the_organization(self):
        self.assertTrue(self.cw.sandbox_identity.stop_minting("env-one"))
        self.assertEqual(self.last().environment_id, "env-one")
        self.cw.sandbox_identity.stop_minting()
        self.assertEqual(self.last().environment_id, "", "no Sandbox stops the organization")
        self.assertFalse(self.cw.sandbox_identity.resume_minting("env-one"))
        self.assertEqual(self.fixture.calls[-1][0], "ResumeIdentityMinting")


if __name__ == "__main__":
    unittest.main()
