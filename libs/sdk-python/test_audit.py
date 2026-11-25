"""Synthetic in-process generated Connect audit log consumer proof."""

import unittest
from datetime import datetime, timedelta, timezone

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError

from codewire import Codewire, CodewireError
from codewire.v1 import audit_pb2 as pb
from codewire.v1.audit_connect import AuditServiceWSGIApplication

_FIRST = "2026-11-24T09:00:00Z"
_LAST = "2026-11-24T09:00:01Z"


def _events():
    user = pb.AuditActor(user=pb.AuditUser(id="user-one", email="one@example.com",
                                           role=pb.AUDIT_ROLE_ADMIN))
    key = pb.AuditActor(api_key=pb.AuditApiKey(id="key-one", name="ci"))
    platform = pb.AuditActor(platform=pb.AuditPlatform())
    sandbox = pb.AuditActor(sandbox=pb.AuditSandbox())
    access = pb.AuditEvent(id="event-access", kind=pb.AUDIT_EVENT_KIND_ACCESS, count=1, actor=user,
                           access=pb.AuditAccess(surface=pb.AUDIT_SURFACE_SSH, client_ip="203.0.113.7"))
    access.first.FromJsonString(_FIRST)
    lifecycle = pb.AuditEvent(
        id="event-lifecycle", kind=pb.AUDIT_EVENT_KIND_LIFECYCLE, count=1, actor=platform,
        lifecycle=pb.AuditLifecycle(
            action=pb.AuditLifecycle.ACTION_STOPPED, reason=pb.AUDIT_PLATFORM_REASON_IDLE,
            preset="go", from_snapshot="snap-one", to=pb.AuditSize(vcpu=4, memory_mib=8192),
            snapshot="snap-two", idle_stop_seconds=1800))
    getattr(lifecycle.lifecycle, "from").CopyFrom(pb.AuditSize(vcpu=2, memory_mib=4096))
    lifecycle.first.FromJsonString(_FIRST)
    lifecycle.last.FromJsonString(_LAST)
    policy = pb.AuditEvent(
        id="event-policy", kind=pb.AUDIT_EVENT_KIND_POLICY, count=1, actor=key,
        policy=pb.AuditPolicyChange(
            action=pb.AuditPolicyChange.ACTION_EDITED, to="web", policy="web", from_revision=2,
            to_revision=3, added=["github.com:443"], removed=["example.com:80"], revision=3,
            failure_code="self_check_failed"))
    setattr(policy.policy, "from", "open")
    refused = pb.AuditEvent(
        id="event-refused", kind=pb.AUDIT_EVENT_KIND_REFUSED, count=7, actor=sandbox,
        refused=pb.AuditRefusal(
            destination="evil.example", address="198.51.100.9", port=443,
            protocol=pb.AUDIT_PROTOCOL_TCP, reason="name_not_allowed", source="egress",
            policy="web", revision=3, allowed_since_revision=4))
    dns = pb.AuditEvent(
        id="event-dns", kind=pb.AUDIT_EVENT_KIND_REFUSED, count=1, actor=sandbox,
        refused=pb.AuditRefusal(withheld=True, protocol=pb.AUDIT_PROTOCOL_DNS,
                                reason="host_check_failed"))
    credentials = pb.AuditEvent(
        id="event-credentials", kind=pb.AUDIT_EVENT_KIND_CREDENTIALS, count=2, actor=sandbox,
        credentials=pb.AuditCredentials(action=pb.AuditCredentials.ACTION_USED, provider="github",
                                        name="work", host="api.github.com", withheld=True))
    overflow = pb.AuditEvent(
        id="event-overflow", kind=pb.AUDIT_EVENT_KIND_REFUSED, count=4200, actor=sandbox,
        refused_overflow=pb.AuditRefusalOverflow(subjects=1000, at_least=True))
    future = pb.AuditEvent(id="event-future", kind=99, actor=pb.AuditActor())
    return [access, lifecycle, policy, refused, dns, credentials, overflow, future]


class AuditFixture:
    def __init__(self):
        self.calls = []

    def list_audit_events(self, request, ctx):
        self.calls.append(request)
        if request.environment_name == "missing":
            raise ConnectError(Code.NOT_FOUND, "environment not found")
        if request.environment_name == "unselected":
            return pb.ListAuditEventsResponse(
                environment=pb.AuditEnvironment(id="env-two", name="unselected"))
        return pb.ListAuditEventsResponse(
            environment=pb.AuditEnvironment(id="env-one", name="web", deleted=True),
            policy=pb.AuditPolicyRevision(name="web", revision=3),
            events=_events(), next_cursor="cursor-two", left_out=5)


def _detail(**value):
    base = {"access": None, "lifecycle": None, "policy": None, "refused": None, "credentials": None,
            "refused_overflow": None}
    base.update(value)
    return base


class AuditTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = AuditFixture()
        app = AuditServiceWSGIApplication(self.fixture)
        self.http = httpx.Client(transport=httpx.WSGITransport(app=app))
        self.cw = Codewire(api_key="synthetic", base_url="https://sdk.example.test",
                           org_id="org-one", http_client=self.http)

    def tearDown(self):
        self.cw.close()
        self.http.close()

    def test_every_filter_is_sent_and_every_kind_is_converted(self):
        since = datetime(2026, 11, 24, 8, 0, tzinfo=timezone.utc)
        page = self.cw.audit.list_audit_events(
            environment_id="env-one", kinds=["refused", "credentials"], since=since,
            until=since + timedelta(hours=1), limit=50, cursor="cursor-one", group_by_subject=True)
        request = self.fixture.calls[-1]
        self.assertEqual((request.org_id, request.WhichOneof("environment"), request.environment_id),
                         ("org-one", "environment_id", "env-one"))
        self.assertEqual(list(request.kinds), [pb.AUDIT_EVENT_KIND_REFUSED, pb.AUDIT_EVENT_KIND_CREDENTIALS])
        self.assertEqual((request.since.ToJsonString(), request.until.ToJsonString()),
                         ("2026-11-24T08:00:00Z", "2026-11-24T09:00:00Z"))
        self.assertEqual((request.limit, request.cursor, request.group_by_subject), (50, "cursor-one", True))

        self.assertEqual(page["environment"], {"id": "env-one", "name": "web", "deleted": True})
        self.assertEqual(page["policy"], {"name": "web", "revision": 3})
        self.assertEqual((page["next_cursor"], page["left_out"]), ("cursor-two", 5))
        sandbox = {"sandbox": {}}
        self.assertEqual(page["events"], [
            {"id": "event-access", "kind": "access", "first": _FIRST, "last": None, "count": 1,
             "actor": {"user": {"id": "user-one", "email": "one@example.com", "role": "admin"}},
             **_detail(access={"surface": "ssh", "client_ip": "203.0.113.7"})},
            {"id": "event-lifecycle", "kind": "lifecycle", "first": _FIRST, "last": _LAST, "count": 1,
             "actor": {"platform": {}},
             **_detail(lifecycle={
                 "action": "stopped", "reason": "idle", "preset": "go", "from_snapshot": "snap-one",
                 "from": {"vcpu": 2, "memory_mib": 4096}, "to": {"vcpu": 4, "memory_mib": 8192},
                 "snapshot": "snap-two", "idle_stop_seconds": 1800})},
            {"id": "event-policy", "kind": "policy", "first": None, "last": None, "count": 1,
             "actor": {"api_key": {"id": "key-one", "name": "ci"}},
             **_detail(policy={
                 "action": "edited", "from": "open", "to": "web", "policy": "web", "from_revision": 2,
                 "to_revision": 3, "added": ["github.com:443"], "removed": ["example.com:80"],
                 "revision": 3, "failure_code": "self_check_failed"})},
            {"id": "event-refused", "kind": "refused", "first": None, "last": None, "count": 7,
             "actor": sandbox,
             **_detail(refused={
                 "destination": "evil.example", "withheld": False, "address": "198.51.100.9",
                 "port": 443, "protocol": "tcp", "reason": "name_not_allowed", "source": "egress",
                 "policy": "web", "revision": 3, "allowed_since_revision": 4})},
            {"id": "event-dns", "kind": "refused", "first": None, "last": None, "count": 1,
             "actor": sandbox,
             **_detail(refused={
                 "destination": "", "withheld": True, "address": "", "port": None, "protocol": "dns",
                 "reason": "host_check_failed", "source": "", "policy": "", "revision": 0,
                 "allowed_since_revision": None})},
            {"id": "event-credentials", "kind": "credentials", "first": None, "last": None, "count": 2,
             "actor": sandbox,
             **_detail(credentials={"action": "used", "provider": "github", "name": "work",
                                    "host": "api.github.com", "withheld": True})},
            {"id": "event-overflow", "kind": "refused", "first": None, "last": None, "count": 4200,
             "actor": sandbox, **_detail(refused_overflow={"subjects": 1000, "at_least": True})},
            # A kind or actor this SDK does not know yet never fails the read.
            {"id": "event-future", "kind": "unknown", "first": None, "last": None, "count": 0,
             "actor": {}, **_detail()},
        ])

    def test_the_environment_is_named_once_and_the_rest_defaults(self):
        page = self.cw.audit.list_audit_events(environment_name="unselected")
        self.assertEqual((page["policy"], page["events"], page["next_cursor"]), (None, [], ""))
        request = self.fixture.calls[-1]
        self.assertEqual(request.WhichOneof("environment"), "environment_name")
        self.assertFalse(request.HasField("since"), "7 days ago unless named")
        self.assertFalse(request.HasField("until"), "now unless named")
        self.assertEqual((list(request.kinds), request.limit, request.group_by_subject), ([], 0, False))

        with self.assertRaises(ValueError):
            self.cw.audit.list_audit_events()
        with self.assertRaises(ValueError):
            self.cw.audit.list_audit_events(environment_id="env-one", environment_name="web")
        for kind in ("unspecified", "", "logins"):
            with self.assertRaises(ValueError):
                self.cw.audit.list_audit_events(environment_id="env-one", kinds=[kind])
        self.assertEqual(len(self.fixture.calls), 1, "a refused option reached the server")
        with self.assertRaises(CodewireError):
            self.cw.audit.list_audit_events(environment_name="missing")

    def test_the_converter_covers_every_audit_message_and_enum_value(self):
        from codewire import audit

        expected = {
            "ListAuditEventsResponse": ["environment", "policy", "events", "next_cursor", "left_out"],
            "AuditEnvironment": ["id", "name", "deleted"],
            "AuditPolicyRevision": ["name", "revision"],
            "AuditEvent": ["id", "kind", "first", "last", "count", "actor",
                           "access", "lifecycle", "policy", "refused", "credentials", "refused_overflow"],
            "AuditActor": ["user", "api_key", "platform", "sandbox"],
            "AuditUser": ["id", "email", "role"],
            "AuditApiKey": ["id", "name"],
            "AuditPlatform": [],
            "AuditSandbox": [],
            "AuditAccess": ["surface", "client_ip"],
            "AuditSize": ["vcpu", "memory_mib"],
            "AuditLifecycle": ["action", "reason", "preset", "from_snapshot", "from", "to", "snapshot",
                               "idle_stop_seconds"],
            "AuditPolicyChange": ["action", "from", "to", "policy", "from_revision", "to_revision",
                                  "added", "removed", "revision", "failure_code"],
            "AuditRefusal": ["destination", "withheld", "address", "port", "protocol", "reason",
                             "source", "policy", "revision", "allowed_since_revision"],
            "AuditRefusalOverflow": ["subjects", "at_least"],
            "AuditCredentials": ["action", "provider", "name", "host", "withheld"],
        }
        self.assertEqual(len(expected), 16)
        self.assertEqual(set(pb.DESCRIPTOR.message_types_by_name) - {"ListAuditEventsRequest"}, set(expected))
        for name, fields in expected.items():
            self.assertEqual([field.name for field in getattr(pb, name).DESCRIPTOR.fields], fields, name)
        for converted, message in ((audit.AuditEvent, pb.AuditEvent),
                                   (audit.AuditLifecycle, pb.AuditLifecycle),
                                   (audit.AuditPolicyChange, pb.AuditPolicyChange),
                                   (audit.AuditRefusal, pb.AuditRefusal),
                                   (audit.AuditRefusalOverflow, pb.AuditRefusalOverflow),
                                   (audit.AuditCredentials, pb.AuditCredentials)):
            self.assertEqual(list(converted.__annotations__), [f.name for f in message.DESCRIPTOR.fields])
        for enum, prefix in ((pb.AuditEventKind, "AUDIT_EVENT_KIND_"), (pb.AuditRole, "AUDIT_ROLE_"),
                             (pb.AuditSurface, "AUDIT_SURFACE_"),
                             (pb.AuditPlatformReason, "AUDIT_PLATFORM_REASON_"),
                             (pb.AuditProtocol, "AUDIT_PROTOCOL_"),
                             (pb.AuditLifecycle.Action, "ACTION_"),
                             (pb.AuditPolicyChange.Action, "ACTION_"),
                             (pb.AuditCredentials.Action, "ACTION_")):
            for value in enum.DESCRIPTOR.values:
                name = audit._enum(enum, value.number, prefix)
                self.assertEqual(name, "" if value.number == 0 else value.name[len(prefix):].lower())
            self.assertEqual(audit._enum(enum, 99, prefix), "unknown")


if __name__ == "__main__":
    unittest.main()
