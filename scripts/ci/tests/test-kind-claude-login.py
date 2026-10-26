#!/usr/bin/env python3
"""Focused stdlib-only fixtures for claude_login.py; never runs Claude Code,
Kubernetes or real auth. A synthetic Claude Code reads its own login from
~/.claude/.credentials.json before every turn and sends the Messages request
stock Claude Code 2.1.308 sends with a claude.ai login."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / "verify/kind/claude_login.py"
SPEC = importlib.util.spec_from_file_location("kind_claude_login", SOURCE)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)

ROOT = Path(__file__).resolve().parents[3]
PROVIDER = ROOT / "crates/codewire-credential-service/src/runtime/kind/provider.rs"
NOW_MS = int(time.time() * 1000)


def token(generation):
    return f"sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-{generation:06d}"


def login(generation=2, *, nonce="a" * 32, expires=None, refresh=None, marker=True,
          extra=None, **changes):
    oauth = {
        "accessToken": token(generation),
        "refreshToken": driver.PLACEHOLDER_PREFIX + nonce if refresh is None else refresh,
        "expiresAt": NOW_MS + 8 * 3_600_000 if expires is None else expires,
        "scopes": list(driver.SCOPES),
        "subscriptionType": driver.PLAN,
        "rateLimitTier": driver.TIER,
    }
    oauth.update(changes)
    document = {"claudeAiOauth": oauth}
    if marker:
        document["codewireManaged"] = 1
    document.update(extra or {})
    return json.dumps(document, indent=2).encode()


# A synthetic Claude Code: stream-json in and out, rereading its login before
# every turn as stock Claude Code does when the file changes.
FAKE = r'''
import json, os, sys, urllib.request, urllib.error
mode = os.environ.get("SYNTHETIC_CLAUDE_MODE", "ok")
args = sys.argv[1:]
assert args == ["-p", "--input-format", "stream-json", "--output-format", "stream-json",
                "--verbose"], args
assert not any(name in os.environ for name in
               ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"))
path = os.path.join(os.environ["HOME"], ".claude", ".credentials.json")
def access():
    return json.load(open(path))["claudeAiOauth"]["accessToken"]
cached = access()
print(json.dumps({"type": "system", "subtype": "init", "apiKeySource": "none"}), flush=True)
for line in sys.stdin:
    value = json.loads(line)
    assert value["type"] == "user" and value["message"]["role"] == "user"
    bearer = cached if mode == "stale" else access()
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01",
               "anthropic-beta": "claude-code-20250219,oauth-2025-04-20"}
    if mode == "api-key":
        headers["x-api-key"] = bearer
    else:
        headers["Authorization"] = "Bearer " + bearer
    if mode == "leak":
        print(json.dumps({"type": "assistant", "token": bearer}), flush=True)
    request = urllib.request.Request(
        os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages?beta=true", method="POST",
        data=json.dumps({"model": "claude-sonnet-4-6", "stream": True,
                         "messages": [value["message"]]}).encode(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode()
        ok = "CWCLAUDELOGIN kind" in body and mode != "error-result"
    except urllib.error.HTTPError:
        ok = False
    print(json.dumps({"type": "result", "subtype": "success" if ok else "error_during_execution",
                      "is_error": not ok, "result": "CWCLAUDELOGIN kind" if ok else ""}),
          flush=True)
'''


class DriverClock:
    """The driver's clock, with the synthetic daemon's checks in its waits.

    The driver relies on every window it waits out (POLL, FULL_CHECK) holding
    a daemon check. A timer thread holds that only while the machine is fast:
    under load its check lands after the window ends, and the thread outlives
    its test (main run 23394). So each queued check runs at the driver's next
    sleep, inside the window that sleep waits out.
    """

    def __init__(self):
        self.checks = []

    def __getattr__(self, name):
        return getattr(time, name)

    def sleep(self, seconds):
        if self.checks:
            self.checks.pop(0)()
        time.sleep(seconds)


class Workspace:
    """A synthetic workspace home in place of the Pod's."""

    def __init__(self, test):
        scratch = tempfile.TemporaryDirectory(prefix="kind-claude-login-")
        test.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.claude = self.home / ".claude"
        self.claude.mkdir(mode=0o700)
        self.claude.chmod(0o700)
        self.credentials = self.claude / ".credentials.json"
        self.workdir = self.root / "workspace"
        self.workdir.mkdir()
        self.output = io.StringIO()
        self.clock = DriverClock()
        environ = {name: value for name, value in os.environ.items()
                   if not name.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "CODEWIRE_",
                                           "SYNTHETIC_CLAUDE"))}
        for fixture in (
            patch.object(driver, "HOME", self.home),
            patch.object(driver, "CLAUDE_DIR", self.claude),
            patch.object(driver, "CREDENTIALS", self.credentials),
            patch.object(driver, "WORKDIR", str(self.workdir)),
            patch.object(driver, "CLAUDE_COMMAND", (sys.executable, "-u", "-c", FAKE)),
            patch.object(driver, "READY", re.compile(re.escape(str(self.root)) + r"/ready-[0-9]+")),
            patch.object(driver, "POLL", 0.02),
            patch.object(driver, "FULL_CHECK", 0.2),
            patch.object(driver, "NEXT_CHECK", 1.0),
            patch.object(driver, "DELIVERY_TIMEOUT", 1.0),
            patch.object(driver, "RECONNECT_ALLOWANCE", 2.0),
            patch.object(driver, "TURN_TIMEOUT", 120.0),
            patch.object(driver, "time", self.clock),
            patch.dict(os.environ, environ, clear=True),
            patch.object(driver.signal, "signal"),
            contextlib.redirect_stdout(self.output),
        ):
            fixture.__enter__()
            test.addCleanup(fixture.__exit__, None, None, None)
        test.addCleanup(lambda: test.assertEqual(self.clock.checks, [],
                                                 "the driver never waited for a daemon check"))

    def daemon_check(self, action):
        """The daemon's next check does action, inside the driver's next wait."""
        self.clock.checks.append(action)

    def deliver(self, contents=None, mode=0o600):
        # As the daemon does: a new file renamed into place, the first one
        # too. Created in place, the driver's poll could read it empty or
        # before its mode was set.
        temporary = self.claude / ".credentials.json.new"
        temporary.write_bytes(login() if contents is None else contents)
        temporary.chmod(mode)
        temporary.rename(self.credentials)

    def document(self):
        return json.loads(self.credentials.read_bytes())

    def events(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def reset(self):
        self.output.truncate(0)
        self.output.seek(0)


class CheckPeriod(unittest.TestCase):
    def setUp(self):
        saved = (driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK)
        self.addCleanup(lambda: setattr(driver, "CHECK_PERIOD", saved[0]))
        self.addCleanup(lambda: setattr(driver, "FULL_CHECK", saved[1]))
        self.addCleanup(lambda: setattr(driver, "NEXT_CHECK", saved[2]))

    def test_every_window_follows_the_daemons_configured_period(self):
        driver.configure({})
        self.assertEqual((driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK),
                         (120.0, 135.0, 150.0))
        driver.configure({driver.CHECK_PERIOD_ENV: "30"})
        self.assertEqual((driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK),
                         (30.0, 45.0, 60.0))
        for value in ("", "9", "121", "030", "30s"):
            with self.subTest(value=value), self.assertRaisesRegex(driver.Failure, "check_period"):
                driver.configure({driver.CHECK_PERIOD_ENV: value})

    def test_the_period_is_the_daemons_and_the_codex_probes(self):
        config = (ROOT / "crates/codewire-daemon/src/config.rs").read_text()
        self.assertIn(f'pub const CODEX_LOGIN_CHECK_PERIOD_ENV: &str = "{driver.CHECK_PERIOD_ENV}";',
                      config)
        codex = (ROOT / "scripts/ci/verify/kind/codex_login.py").read_text()
        self.assertIn(f'CHECK_PERIOD_ENV = "{driver.CHECK_PERIOD_ENV}"', codex)


class Fixture(unittest.TestCase):
    def test_the_probe_matches_the_kind_fixtures_sign_in(self):
        provider = PROVIDER.read_text()
        self.assertIn('format!("sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-{generation:06}")',
                      provider)
        self.assertIn('format!("sk-ant-ort01-CW_KIND_SYNTHETIC_SIGN_IN_REFRESH-{generation:06}")',
                      provider)
        self.assertIn(f'const CLAUDE_SIGN_IN_SCOPES: &str = "{" ".join(driver.SCOPES)}";',
                      provider)
        self.assertIn('"organization_type": "claude_max"', provider)
        self.assertIn(f'"rate_limit_tier": "{driver.TIER}"', provider)
        self.assertEqual(driver.generation_of(token(7)), 7)
        for value in (token(7) + "x", "sk-ant-oat01-CW_KIND_SYNTHETIC_CLAUDE_TOKEN-0123", None):
            with self.subTest(value=value), self.assertRaises(driver.Failure):
                driver.generation_of(value)

    def test_sign_in_selections_are_the_sixteen_with_bit_0x40(self):
        self.assertEqual(len(driver.SIGN_IN_SELECTIONS), 16)
        for selection in driver.SIGN_IN_SELECTIONS:
            bits = int(selection.split(":")[1], 16)
            self.assertEqual(bits & 0x64, 0x44, selection)


class LoginFile(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(self)

    def test_codewires_delivered_login_yields_its_generation_and_nonce(self):
        self.assertIsNone(driver.delivered())
        self.workspace.deliver(login(4, nonce="b" * 32))
        self.assertEqual(driver.delivered(), (4, "b" * 32))
        # Other keys are allowed beside Codewire's.
        self.workspace.deliver(login(4, extra={"mcpOAuth": {}}))
        self.assertEqual(driver.delivered()[0], 4)
        # A file without the login, or one being rewritten, is not a login yet.
        self.workspace.deliver(json.dumps({"codewireManaged": 1}).encode())
        self.assertIsNone(driver.delivered())
        self.workspace.deliver(login()[:30])
        self.assertIsNone(driver.delivered())
        # Claude Code cleared Codewire's login after its own refresh was
        # refused: it reached a token endpoint, which the probe forbids
        # (#2891). Without the marker it is not Codewire's.
        self.workspace.deliver(login(refresh="", accessToken="", expiresAt=0))
        with self.assertRaisesRegex(driver.Failure, "^login_cleared_by_claude$"):
            driver.delivered()
        self.workspace.deliver(login(refresh="", marker=False))
        with self.assertRaisesRegex(driver.Failure, "^login_not_codewires$"):
            driver.delivered()

    def test_anything_but_codewires_exact_login_fails_closed(self):
        cases = {
            "login_file_mode": (login(), 0o644),
            "login_not_codewires": (login(refresh="users-own-refresh-token"), 0o600),
            "placeholder_nonce": (login(nonce="A" * 32), 0o600),
            "marker_missing": (login(marker=False), 0o600),
            "login_expiry": (login(expires=NOW_MS + 60_000), 0o600),
            "login_shape": (login(subscriptionType="pro"), 0o600),
            "access_token_not_fixtures": (login(accessToken="sk-ant-oat01-other"), 0o600),
        }
        for reason, (contents, mode) in cases.items():
            with self.subTest(reason=reason):
                self.workspace.deliver(contents, mode)
                with self.assertRaisesRegex(driver.Failure, f"^{reason}$"):
                    driver.delivered()
        self.workspace.deliver(login(clientId="9d1c250a"))
        with self.assertRaisesRegex(driver.Failure, "^login_shape$"):
            driver.delivered()
        # The broker's refresh token anywhere in the file fails.
        self.workspace.deliver(login(extra={"x": "sk-ant-ort01-CW_KIND_SYNTHETIC_SIGN_IN_REFRESH-000002"}))
        with self.assertRaisesRegex(driver.Failure, "^refresh_token_delivered$"):
            driver.delivered()

    def test_a_shared_directory_symlink_or_directory_is_never_read_as_the_login(self):
        self.workspace.deliver(login())
        self.workspace.claude.chmod(0o755)
        with self.assertRaisesRegex(driver.Failure, "^login_directory$"):
            driver.delivered()
        self.workspace.claude.chmod(0o700)
        outside = self.workspace.root / "outside.json"
        outside.write_bytes(login())
        outside.chmod(0o600)
        self.workspace.credentials.unlink()
        self.workspace.credentials.symlink_to(outside)
        with self.assertRaisesRegex(driver.Failure, "^login_file_not_regular$"):
            driver.delivered()
        self.workspace.credentials.unlink()
        self.workspace.credentials.mkdir()
        with self.assertRaisesRegex(driver.Failure, "^login_file_not_regular$"):
            driver.delivered()


class SyntheticBackend(unittest.TestCase):
    def setUp(self):
        self.backend = driver.Backend()
        self.addCleanup(self.backend.close)

    def call(self, path="/v1/messages?beta=true", headers=None, body=None, method="POST"):
        request = urllib.request.Request(
            self.backend.base_url + path, method=method,
            data=None if method == "GET" else json.dumps(body or {"stream": True}).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read()

    def oauth(self, generation=3):
        return {"Authorization": f"Bearer {token(generation)}",
                "anthropic-beta": "claude-code-20250219,oauth-2025-04-20"}

    def test_only_a_fixture_sign_in_bearer_in_oauth_form_is_answered(self):
        status, body = self.call(headers=self.oauth())
        self.assertEqual(status, 200)
        self.assertIn(driver.MARKER.encode(), body)
        self.assertIn(b"event: message_stop", body)
        status, body = self.call(headers=self.oauth(4), body={"stream": False})
        self.assertEqual((status, json.loads(body)["content"][0]["text"]), (200, driver.MARKER))
        self.assertEqual(self.call("/v1/messages/count_tokens", self.oauth(4))[0], 200)
        for headers in ({"Authorization": f"Bearer {token(3)}"},
                        {"x-api-key": token(3), "anthropic-beta": "oauth-2025-04-20"},
                        {"Authorization": "Bearer codewire-managed",
                         "anthropic-beta": "oauth-2025-04-20"},
                        {}):
            with self.subTest(headers=sorted(headers)):
                self.assertEqual(self.call(headers=headers)[0], 403)
        self.assertEqual(self.call("/v1/models", self.oauth(), method="GET")[0], 404)
        self.assertEqual(self.backend.take(), ([3, 4, 4], 4, 1))
        self.assertEqual(self.backend.take()[0], [])
        # Each refusal keeps only its closed form, never a value.
        # A fixture bearer without the OAuth beta is the #2891 refusal: it
        # names its public generation.
        self.assertEqual(self.backend.rejections, [
            {"route": "messages", "credential": "fixture_bearer", "oauth_beta": False,
             "generation": 3},
            {"route": "messages", "credential": "api_key", "oauth_beta": True},
            {"route": "messages", "credential": "other_bearer", "oauth_beta": True},
            {"route": "messages", "credential": "none", "oauth_beta": False},
        ])

    def test_a_refusal_names_the_credential_form_only(self):
        beta = {"anthropic-beta": "oauth-2025-04-20"}
        cases = (
            ({"Authorization": "Basic x", **beta}, "malformed_bearer"),
            ({"Authorization": f"Bearer {token(3)}", "x-api-key": "k", **beta}, "several"),
            ({"Authorization": "Bearer sk-ant-oat01-somebody-else", **beta}, "other_bearer"),
        )
        for headers, form in cases:
            with self.subTest(form=form):
                self.assertEqual(self.call("/v1/messages/count_tokens", headers=headers)[0], 403)
                self.assertEqual(self.backend.rejections[-1],
                                 {"route": "count_tokens", "credential": form, "oauth_beta": True})
        self.assertNotIn("somebody", json.dumps(self.backend.rejections))
        for index in range(driver.MAX_REJECTIONS + 2):
            self.call(headers={})
        self.assertEqual(len(self.backend.rejections), driver.MAX_REJECTIONS)


class NoRouteButLoopback(unittest.TestCase):
    """#2891: the probe's Claude Code reaches its loopback backend and
    nothing else, so a synthetic login never meets a real provider."""

    def setUp(self):
        self.workspace = Workspace(self)
        self.backend = driver.Backend()
        self.addCleanup(self.backend.close)

    def test_every_proxy_names_a_refusing_loopback_port_and_only_loopback_is_exempt(self):
        environment = driver.claude_environment(self.backend)
        url = self.backend.no_route_url
        self.assertRegex(url, r"^http://127\.0\.0\.1:[1-9][0-9]*$")
        self.assertEqual({name: environment[name] for name in driver.PROXIES},
                         dict.fromkeys(("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                                        "ALL_PROXY", "all_proxy"), url))
        self.assertEqual((environment["NO_PROXY"], environment["no_proxy"]),
                         ("127.0.0.1,localhost", "127.0.0.1,localhost"))
        port = int(url.rsplit(":", 1)[1])
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=60).close()

    def test_a_client_that_honours_the_proxy_reaches_only_the_backend(self):
        # A stock HTTP client in Claude Code's environment: the backend
        # answers; any other host is refused at the proxy, never resolved.
        probe = (
            "import sys, urllib.request, urllib.error\n"
            "def get(url):\n"
            "    try:\n"
            "        urllib.request.urlopen(url, timeout=60)\n"
            "    except urllib.error.HTTPError as error:\n"
            "        return f'http {error.code}'\n"
            "    except urllib.error.URLError as error:\n"
            "        return type(error.reason).__name__\n"
            "print(get(sys.argv[1] + '/v1/models'))\n"
            "print(get('http://api.anthropic.invalid/api/oauth/profile'))\n"
            "print(get('https://platform.claude.invalid/v1/oauth/token'))\n")
        environment = driver.claude_environment(self.backend)
        result = subprocess.run([sys.executable, "-I", "-c", probe, self.backend.base_url],
                                env=environment, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.stdout.split(), ["http", "404", "ConnectionRefusedError",
                                                 "ConnectionRefusedError"], result.stderr)

    def test_the_refusing_port_is_released_with_the_backend(self):
        backend = driver.Backend()
        backend.close()
        self.assertEqual(backend.no_route.fileno(), -1)


class Modes(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(self)

    def run_mode(self, *argv, synthetic=None):
        environ = {"SYNTHETIC_CLAUDE_MODE": synthetic} if synthetic else {}
        with patch.dict(os.environ, environ):
            status = driver.main(list(argv))
        events = self.workspace.events()
        # The stream is closed: never a token, placeholder or file content.
        output = self.workspace.output.getvalue()
        for secret in ("CW_KIND_SYNTHETIC", driver.PLACEHOLDER_PREFIX, "Bearer", "aaaa"):
            self.assertNotIn(secret, output)
        return status, events

    def test_deliver_runs_a_turn_with_the_delivered_token_and_plants_a_key(self):
        self.workspace.daemon_check(lambda: self.workspace.deliver(login(3)))
        status, events = self.run_mode("deliver", "2")
        self.assertEqual(status, 0, events)
        self.assertEqual(events[0]["event"], "delivered")
        self.assertEqual((events[0]["generation"], events[0]["requests"]), (3, 1))
        self.assertEqual(events[-1], {"event": "complete", "mode": "deliver"})
        document = self.workspace.document()
        self.assertEqual(document[driver.UNRELATED_KEY], driver.UNRELATED_VALUE)
        self.assertEqual(document["claudeAiOauth"]["accessToken"], token(3))

    def test_deliver_waits_for_a_late_enough_generation(self):
        self.workspace.deliver(login(1))
        status, events = self.run_mode("deliver", "2")
        self.assertEqual((status, events[-1]["reason"]), (1, "login_not_delivered"))

    def test_deliver_fails_on_a_wrong_credential_form_failed_turn_or_leak(self):
        for synthetic, reason in (("api-key", "backend_rejected"),
                                  ("error-result", "turn_failed"),
                                  ("leak", "credential_in_output")):
            with self.subTest(synthetic=synthetic):
                self.workspace.reset()
                self.workspace.deliver(login(3))
                status, events = self.run_mode("deliver", "1", synthetic=synthetic)
                self.assertEqual(status, 1)
                # A refused turn names the closed form it presented (#2891).
                named = [{"event": "backend_rejected", "rejections": [
                    {"route": "messages", "credential": "api_key", "oauth_beta": True}]}]
                self.assertEqual(events, (named if reason == "backend_rejected" else [])
                                 + [{"event": "failed", "mode": "deliver", "reason": reason}])

    def rotate_when_ready(self, ready, generation, nonce="c" * 32, keep=True):
        def run():
            deadline = time.monotonic() + 120
            while not os.path.exists(ready) and time.monotonic() < deadline:
                time.sleep(0.01)
            extra = {driver.UNRELATED_KEY: driver.UNRELATED_VALUE} if keep else {}
            self.workspace.deliver(login(generation, nonce=nonce, extra=extra))
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def test_rotation_is_adopted_by_the_same_claude_process(self):
        self.workspace.deliver(login(3, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}))
        ready = str(self.workspace.root / "ready-1")
        self.rotate_when_ready(ready, 5)
        status, events = self.run_mode("rotation", "3", ready)
        self.assertEqual(status, 0, events)
        self.assertEqual(events[0]["event"], "rotation_adopted")
        self.assertEqual((events[0]["previous"], events[0]["generation"], events[0]["first_turn"],
                          events[0]["second_turn"], events[0]["restarted"]),
                         (3, 5, 3, 5, False))
        self.assertTrue(os.path.exists(ready))

    def test_rotation_fails_when_claude_keeps_the_old_token_or_nothing_changes(self):
        cases = (
            ("stale", 5, "c" * 32, True, "rotation_not_adopted"),
            (None, 5, "a" * 32, True, "nonce_unchanged"),
            (None, 5, "c" * 32, False, "unrelated_key_dropped"),
            (None, None, None, True, "rotation_not_delivered"),
        )
        for index, (synthetic, generation, nonce, keep, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                self.workspace.reset()
                self.workspace.deliver(login(3, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}))
                ready = str(self.workspace.root / f"ready-{index + 10}")
                if generation is not None:
                    self.rotate_when_ready(ready, generation, nonce, keep)
                status, events = self.run_mode("rotation", "3", ready, synthetic=synthetic)
                self.assertEqual((status, events[-1]["reason"]), (1, reason))

    def test_rotation_refuses_an_older_login_or_an_existing_ready_file(self):
        self.workspace.deliver(login(3, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}))
        ready = self.workspace.root / "ready-2"
        status, events = self.run_mode("rotation", "4", str(ready))
        self.assertEqual(events[-1]["reason"], "login_older_than_previous")
        ready.write_text("")
        self.workspace.reset()
        status, events = self.run_mode("rotation", "3", str(ready))
        self.assertEqual(events[-1]["reason"], "ready_file")

    def test_own_login_stays_untouched_and_codewires_file_comes_back(self):
        self.workspace.deliver(login(3))
        original = self.workspace.credentials.read_bytes()
        status, events = self.run_mode("own-login")
        self.assertEqual(status, 0, events)
        self.assertEqual(self.workspace.credentials.read_bytes(), original)
        # It reports whether the planted key reached it, and judges nothing.
        self.assertEqual(events[0]["unrelated"], "absent")
        self.workspace.reset()
        self.workspace.deliver(login(3, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}))
        status, events = self.run_mode("own-login")
        self.assertEqual((status, events[0]["unrelated"]), (0, "kept"), events)

    def test_own_login_fails_when_the_daemon_replaces_it(self):
        self.workspace.deliver(login(3))
        self.workspace.daemon_check(lambda: self.workspace.deliver(login(3)))
        status, events = self.run_mode("own-login")
        self.assertEqual((status, events[-1]["reason"]), (1, "own_login_touched"))

    def test_logout_removes_only_the_login_and_stays_logged_out(self):
        self.workspace.deliver(login(3, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}))
        status, events = self.run_mode("logout")
        self.assertEqual(status, 0, events)
        self.assertEqual((events[0]["marker"], events[0]["unrelated"]), ("kept", "kept"))
        self.assertNotIn("claudeAiOauth", self.workspace.document())
        self.workspace.reset()
        self.workspace.deliver(login(3))
        self.workspace.daemon_check(lambda: self.workspace.deliver(login(3)))
        status, events = self.run_mode("logout")
        self.assertEqual((status, events[-1]["reason"]), (1, "logout_undone"))

    def test_redelivery_and_revocation(self):
        self.workspace.deliver(json.dumps({"codewireManaged": 1,
                                           driver.UNRELATED_KEY: driver.UNRELATED_VALUE}).encode())
        self.workspace.daemon_check(lambda: self.workspace.deliver(
            login(6, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE})))
        status, events = self.run_mode("redelivered")
        self.assertEqual(status, 0, events)
        self.assertEqual(
            (events[0]["generation"], events[0]["unrelated"], events[0]["other_keys"]),
            (6, "kept", 0))
        # A login redelivered without the planted key is reported, with how
        # many other members the file holds and never their names.
        self.workspace.reset()
        self.workspace.deliver(login(7, extra={"anotherToolsKey": {"x": 1}}))
        status, events = self.run_mode("redelivered")
        self.assertEqual(status, 0, events)
        self.assertEqual((events[0]["unrelated"], events[0]["other_keys"]), ("absent", 1))
        self.assertNotIn("anotherToolsKey", self.workspace.output.getvalue())

        self.workspace.reset()
        self.workspace.daemon_check(lambda: self.workspace.deliver(
            json.dumps({driver.UNRELATED_KEY: driver.UNRELATED_VALUE}).encode()))
        status, events = self.run_mode("revoked")
        self.assertEqual(status, 0, events)
        self.assertEqual(events[0]["unrelated"], "kept")
        for contents, reason in (
                (login(6, extra={driver.UNRELATED_KEY: driver.UNRELATED_VALUE}),
                 "revoked_login_kept"),
                (json.dumps({"codewireManaged": 1,
                             driver.UNRELATED_KEY: driver.UNRELATED_VALUE}).encode(),
                 "revoked_login_kept"),
                (json.dumps({}).encode(), "unrelated_key_dropped")):
            with self.subTest(reason=reason):
                self.workspace.reset()
                self.workspace.deliver(contents)
                status, events = self.run_mode("revoked")
                self.assertEqual((status, events[-1]["reason"]), (1, reason))

    def test_arguments_and_projection_are_closed(self):
        ready = str(self.workspace.root / "ready-3")
        for argv in ([], ["unknown"], ["deliver"], ["deliver", "0"], ["deliver", "x"],
                     ["rotation", "3"], ["rotation", "3", "/tmp/elsewhere"],
                     ["rotation", "x", ready], ["revoked", "extra"], ["logout", "1"]):
            with self.subTest(argv=argv):
                self.workspace.reset()
                status, events = self.run_mode(*argv)
                self.assertEqual(status, 1)
                self.assertEqual(events[-1]["reason"], "arguments")
        self.workspace.deliver(login(3))
        for environ in ({"CLAUDE_CODE_OAUTH_TOKEN": "codewire-managed"},
                        {"ANTHROPIC_API_KEY": ""},
                        {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v2:24",
                         "ANTHROPIC_BASE_URL": driver.MANAGED_BASE_URL},
                        {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v2:44"}):
            with self.subTest(environ=sorted(environ)), patch.dict(os.environ, environ):
                self.workspace.reset()
                self.assertEqual(self.run_mode("own-login")[1][-1]["reason"],
                                 "unexpected_projection")
        # An environment-token Pod renders the sign-in selection and base URL.
        with patch.dict(os.environ, {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v2:54",
                                     "ANTHROPIC_BASE_URL": driver.MANAGED_BASE_URL}):
            self.workspace.reset()
            self.assertEqual(self.run_mode("redelivered")[0], 0)

    def test_the_rotation_ready_path_is_the_suites(self):
        self.assertTrue(re.fullmatch(SOURCE_READY, "/tmp/codewire-kind-claude-rotation-123"))
        self.assertFalse(re.fullmatch(SOURCE_READY, "/tmp/codewire-kind-claude-rotation-"))
        self.assertFalse(re.fullmatch(SOURCE_READY, "/tmp/codewire-kind-claude-rotation-1/x"))


SOURCE_READY = driver.READY.pattern


if __name__ == "__main__":
    unittest.main()
