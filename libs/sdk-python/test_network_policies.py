"""Synthetic in-process generated Connect network-policy consumer proof."""

import unittest

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError

from codewire import Codewire, CodewireError
from codewire.v1 import network_policy_pb2 as pb
from codewire.v1.network_policy_connect import NetworkPolicyServiceWSGIApplication


POLICY_ID = "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a"


class NetworkPolicyFixture:
    def __init__(self):
        self.calls = []

    def record(self, name, request):
        self.calls.append((name, request))

    @staticmethod
    def policy():
        return pb.NetworkPolicy(
            id=POLICY_ID, org_id="org-one", name="web", revision=2, current_revision=2,
            rules=[pb.NetworkPolicyRule(target="github.com", ports=[22, 443])],
            digest="ab" * 32, created_by="user-one")

    def create_network_policy(self, request, ctx):
        self.record("CreateNetworkPolicy", request)
        return pb.CreateNetworkPolicyResponse(policy=self.policy())

    def list_network_policies(self, request, ctx):
        self.record("ListNetworkPolicies", request)
        return pb.ListNetworkPoliciesResponse(policies=[self.policy()])

    def get_network_policy(self, request, ctx):
        self.record("GetNetworkPolicy", request)
        if request.policy.name == "off":
            raise ConnectError(Code.UNAVAILABLE, "platform network policies are not enabled")
        return pb.GetNetworkPolicyResponse(policy=self.policy())

    def update_network_policy(self, request, ctx):
        self.record("UpdateNetworkPolicy", request)
        return pb.UpdateNetworkPolicyResponse(policy=self.policy())

    def delete_network_policy(self, request, ctx):
        self.record("DeleteNetworkPolicy", request)
        return pb.DeleteNetworkPolicyResponse(policy=self.policy())

    def update_environment_network_policy(self, request, ctx):
        self.record("UpdateEnvironmentNetworkPolicy", request)
        if request.environment_id == "future":
            return pb.UpdateEnvironmentNetworkPolicyResponse(network_policy=pb.EnvironmentNetworkPolicy(
                reference="hosted-default", name="hosted-default", digest="cd" * 32, enforcement=99))
        return pb.UpdateEnvironmentNetworkPolicyResponse(network_policy=pb.EnvironmentNetworkPolicy(
            reference="hosted-default", name="hosted-default", digest="cd" * 32,
            enforcement=pb.NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED))


class NetworkPoliciesTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = NetworkPolicyFixture()
        app = NetworkPolicyServiceWSGIApplication(self.fixture)
        self.http = httpx.Client(transport=httpx.WSGITransport(app=app))
        self.cw = Codewire(api_key="synthetic", base_url="https://sdk.example.test",
                           org_id="org-one", http_client=self.http)

    def tearDown(self):
        self.cw.close()
        self.http.close()

    def test_every_method_names_the_organization_and_its_policy(self):
        listed = self.cw.network_policies.list()
        self.assertEqual(listed[0]["rules"], [{"target": "github.com", "ports": [22, 443]}])
        self.assertEqual(listed[0]["current_revision"], 2)

        self.cw.network_policies.create("web", [{"target": "github.com", "ports": [443]}],
                                        from_policy="base")
        request = self.fixture.calls[-1][1]
        self.assertEqual(getattr(request, "from").name, "base")
        self.assertEqual(list(request.allow[0].ports), [443])

        self.cw.network_policies.get({"id": POLICY_ID}, revision=1)
        request = self.fixture.calls[-1][1]
        self.assertEqual((request.policy.WhichOneof("selector"), request.revision), ("id", 1))

        self.cw.network_policies.update("web", remove=["pypi.org"], expected_revision=2)
        request = self.fixture.calls[-1][1]
        self.assertEqual((list(request.remove), request.expected_revision), (["pypi.org"], 2))

        self.cw.network_policies.delete("web")
        selected = self.cw.network_policies.select("environment-one", "hosted-default")
        self.assertEqual(selected["enforcement"], "not_enforced")
        self.assertEqual(self.fixture.calls[-1][1].network_policy, "hosted-default")
        self.assertTrue(all(request.org_id == "org-one" for _, request in self.fixture.calls))

    def test_an_unknown_enforcement_state_never_fails_a_read(self):
        selected = self.cw.network_policies.select("future", "hosted-default")
        self.assertEqual((selected["enforcement"], selected["enforced_at"]), ("unknown", None))

    def test_a_deployment_with_policies_off_raises_codewire_error(self):
        with self.assertRaises(CodewireError):
            self.cw.network_policies.get("off")


if __name__ == "__main__":
    unittest.main()
