"""The desktop calls with generated messages and a synthetic in-process transport."""
import unittest

from codewire.desktop import Desktop, START_TIMEOUT_MS, desktop_to_dict
from codewire.v1 import environment_desktop_pb2 as pb


def running():
    desktop = pb.EnvironmentDesktop(
        state=pb.ENVIRONMENT_DESKTOP_STATE_RUNNING,
        running=pb.EnvironmentDesktopRunning(display=":1", port=5901, viewer_password="a1b2c3d4"),
    )
    desktop.running.started_at.FromJsonString("2026-11-20T10:00:00Z")
    return desktop


class FakeContext:
    """Answers each call by the bound method the SDK asked for."""

    def __init__(self):
        self.transport = self
        self.calls = []
        self.omit = False

    def client(self, _):
        return self

    def resolve_org_id(self):
        return "org"

    def start_desktop(self):
        pass

    def get_desktop(self):
        pass

    def stop_desktop(self):
        pass

    def unary(self, call, request, *, timeout_ms=None):
        self.calls.append((call.__name__, request.org_id, request.environment_id, timeout_ms))
        if call.__name__ == "start_desktop":
            return pb.StartDesktopResponse() if self.omit else pb.StartDesktopResponse(desktop=running())
        if call.__name__ == "get_desktop":
            return pb.GetDesktopResponse(desktop=running())
        return pb.StopDesktopResponse(
            desktop=pb.EnvironmentDesktop(state=pb.ENVIRONMENT_DESKTOP_STATE_STOPPED)
        )


class DesktopTest(unittest.TestCase):
    def test_each_call_names_its_environment_and_a_running_desktop_arrives_whole(self):
        context = FakeContext()
        desktop = Desktop(context, "env")
        expected = {
            "state": "running",
            "running": {
                "display": ":1",
                "port": 5901,
                "viewer_password": "a1b2c3d4",
                "started_at": "2026-11-20T10:00:00Z",
            },
        }
        self.assertEqual(desktop.start(), expected)
        self.assertEqual(desktop.get(), expected)
        self.assertEqual(desktop.stop(), {"state": "stopped"})
        # A start waits longer than the server's own 40 seconds; the others
        # keep the transport's default.
        self.assertEqual(
            context.calls,
            [
                ("start_desktop", "org", "env", START_TIMEOUT_MS),
                ("get_desktop", "org", "env", None),
                ("stop_desktop", "org", "env", None),
            ],
        )
        self.assertGreater(START_TIMEOUT_MS, 40_000)

    def test_an_image_without_a_desktop_says_what_it_lacks_and_each_state_has_its_name(self):
        self.assertEqual(
            desktop_to_dict(
                pb.EnvironmentDesktop(
                    state=pb.ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE,
                    unavailable_reason="its launcher is not in the image",
                )
            ),
            {"state": "unavailable", "unavailable_reason": "its launcher is not in the image"},
        )
        for state, name in [
            (pb.ENVIRONMENT_DESKTOP_STATE_STOPPED, "stopped"),
            (pb.ENVIRONMENT_DESKTOP_STATE_STARTING, "starting"),
            (pb.ENVIRONMENT_DESKTOP_STATE_RUNNING, "running"),
            (pb.ENVIRONMENT_DESKTOP_STATE_UNSPECIFIED, "unknown"),
        ]:
            self.assertEqual(desktop_to_dict(pb.EnvironmentDesktop(state=state))["state"], name)

    def test_a_response_without_a_desktop_is_refused(self):
        context = FakeContext()
        context.omit = True
        with self.assertRaisesRegex(RuntimeError, "omitted desktop"):
            Desktop(context, "env").start()

    def test_the_converter_carries_every_field_of_both_messages(self):
        # A field added to either message fails here until desktop_to_dict has it.
        self.assertEqual(
            [field.name for field in pb.EnvironmentDesktop.DESCRIPTOR.fields],
            ["state", "unavailable_reason", "running"],
        )
        self.assertEqual(
            [field.name for field in pb.EnvironmentDesktopRunning.DESCRIPTOR.fields],
            ["display", "port", "started_at", "viewer_password"],
        )


if __name__ == "__main__":
    unittest.main()
