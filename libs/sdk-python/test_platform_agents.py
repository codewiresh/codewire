import hashlib
import unittest

from codewire.platform_agents import PlatformAgents, PlatformAgentOutcomeUnknownError
from codewire.v1 import environment_agent_pb2 as pb
from codewire.v1 import environment_cw_runtime_pb2 as runtime

REQUEST = "6a162b2b-a758-4c8c-bccb-794502c82f09"
MAXIMUM = (1 << 64) - 1


def scope():
    return pb.EnvironmentAgentScope(incarnation=runtime.EnvironmentCwRuntimeIncarnation(
        org_id="org", environment_id="env", binding_generation=MAXIMUM, pod_uid="original-pod"),
        support_image_sha256=b"s" * 32, support_image_size=123)


def mutation():
    return pb.MutateEnvironmentAgentRequest(org_id="org", environment_id="env", request_id=REQUEST,
        expected_scope=scope(), control=pb.EnvironmentAgentControl(
            action=pb.ENVIRONMENT_AGENT_ACTION_STOP, session_id="session", driver_id="driver",
            expected_launch_generation=MAXIMUM))


class Context:
    def __init__(self):
        self.transport = self
        self.calls = []
        self.mode = "ok"
    def client(self, _): return self
    def resolve_org_id(self): return "org"
    def mutate_environment_agent(self): pass
    def observe_environment_agent(self): pass
    def read_environment_agent(self): pass
    def list_environment_agents(self): pass
    def unary(self, method, request, **options):
        self.calls.append(method.__name__)
        if method.__name__ == "mutate_environment_agent":
            assert request.control.expected_launch_generation == MAXIMUM
            if self.mode == "lost": raise RuntimeError("synthetic lost response after dispatch")
            operation = pb.EnvironmentAgentOperation(request_id=request.request_id,
                scope=request.expected_scope, phase=pb.ENVIRONMENT_AGENT_PHASE_UNKNOWN)
            if self.mode == "wrong-id": operation.request_id = "6d370dab-3d67-4d76-93c3-3bd31581fbe9"
            if self.mode == "wrong-scope": operation.scope.incarnation.pod_uid = "replacement-pod"
            return pb.MutateEnvironmentAgentResponse(operation=operation)
        if method.__name__ == "observe_environment_agent":
            return pb.ObserveEnvironmentAgentResponse(operation=pb.EnvironmentAgentOperation(
                request_id=request.request_id, scope=scope(), phase=pb.ENVIRONMENT_AGENT_PHASE_UNKNOWN))
        if method.__name__ == "list_environment_agents":
            return pb.ListEnvironmentAgentsResponse(scope=request.expected_scope,
                sessions=[{"session_id": "session"}] * (9 if self.mode == "oversized-page" else 1))
        data = b'{"record":"synthetic"}'
        response = pb.ReadEnvironmentAgentResponse(scope=request.expected_scope,
            session_id=request.session_id, driver_id=request.driver_id,
            launch_generation=request.expected_launch_generation,
            kind=request.kind, message_id=request.message_id,
            record_json=data, record_sha256=hashlib.sha256(data).digest())
        if self.mode == "wrong-generation": response.launch_generation -= 1
        if self.mode == "wrong-digest": response.record_json += b" "
        return response


class PlatformAgentsTests(unittest.TestCase):
    def test_lost_response_retains_original_uuid_for_observation_without_replay(self):
        context = Context(); context.mode = "lost"; agents = PlatformAgents(context, "env")
        with self.assertRaises(PlatformAgentOutcomeUnknownError) as caught:
            agents.mutate(mutation())
        self.assertEqual(caught.exception.request_id, REQUEST)
        self.assertEqual(agents.observe(REQUEST).phase, pb.ENVIRONMENT_AGENT_PHASE_UNKNOWN)
        self.assertEqual(context.calls, ["mutate_environment_agent", "observe_environment_agent"])

    def test_wrong_uuid_or_original_pod_is_uncertain_and_not_retried(self):
        for mode in ("wrong-id", "wrong-scope"):
            with self.subTest(mode=mode):
                context = Context(); context.mode = mode
                with self.assertRaises(PlatformAgentOutcomeUnknownError) as caught:
                    PlatformAgents(context, "env").mutate(mutation())
                self.assertEqual(caught.exception.request_id, REQUEST)
                self.assertEqual(context.calls, ["mutate_environment_agent"])

    def test_scope_and_request_bound_refusal_precedes_transport(self):
        for bad in ("scope", "id", "bound"):
            context = Context(); request = mutation()
            if bad == "scope": request.expected_scope.incarnation.environment_id = "other"
            if bad == "id": request.request_id = "not-a-uuid"
            if bad == "bound": request.control.text = "x" * (256 * 1024)
            with self.assertRaises(ValueError): PlatformAgents(context, "env").mutate(request)
            self.assertEqual(context.calls, [])

    def test_exact_uint64_scope_generation_and_record_digest(self):
        context = Context(); agents = PlatformAgents(context, "env")
        request = pb.ReadEnvironmentAgentRequest(org_id="org", environment_id="env", expected_scope=scope(),
            session_id="session", driver_id="driver", expected_launch_generation=MAXIMUM,
            kind=pb.ENVIRONMENT_AGENT_RECORD_KIND_MESSAGE, message_id=REQUEST)
        result = agents.read(request)
        self.assertEqual(result.launch_generation, MAXIMUM)
        self.assertEqual(result.scope.incarnation.binding_generation, MAXIMUM)
        for mode in ("wrong-generation", "wrong-digest"):
            context.mode = mode
            with self.assertRaises(RuntimeError): agents.read(request)

    def test_list_page_bound_is_enforced(self):
        context = Context(); context.mode = "oversized-page"
        with self.assertRaises(RuntimeError):
            PlatformAgents(context, "env").list(pb.ListEnvironmentAgentsRequest(
                org_id="org", environment_id="env", expected_scope=scope()))


if __name__ == "__main__": unittest.main()
