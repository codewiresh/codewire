#!/usr/bin/env python3
"""Focused stdlib-only fixtures for codex_login.py; never runs Codex,
Kubernetes or real auth. A synthetic Codex makes the HTTP calls stock Codex
0.160 makes with a ChatGPT login."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / "verify/kind/codex_login.py"
SPEC = importlib.util.spec_from_file_location("kind_codex_login", SOURCE)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)

NOW = int(time.time())


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def jwt(claims):
    return f"e30.{b64(claims)}.synthetic-kind-signature"


def access_token(generation=0, exp=None):
    return jwt({"exp": NOW + 86_400 if exp is None else exp, "generation": generation,
                "synthetic": driver.FIXTURE_TOKEN})


def id_token(plan=driver.PLAN):
    return jwt({"email": "kind-fixture@example.test", "https://api.openai.com/auth": {
        "chatgpt_account_id": driver.ACCOUNT, "chatgpt_plan_type": plan,
        "chatgpt_user_id": "user-codewire-kind-synthetic"}})


def login(generation=0, *, refresh=driver.PLACEHOLDER, plan=driver.PLAN, exp=None, **changes):
    document = {
        "auth_mode": "chatgpt", "OPENAI_API_KEY": None,
        "tokens": {"id_token": id_token(plan), "access_token": access_token(generation, exp),
                   "refresh_token": refresh, "account_id": driver.ACCOUNT},
        "last_refresh": "2026-10-03T04:50:07Z",
    }
    document.update(changes)
    return json.dumps(document, indent=2).encode()


MANAGED_CONFIG = driver.MANAGED_HEADER + b'\nmodel_provider = "codewire_openai"\n'

# A synthetic Codex: JSON-RPC over stdio for `app-server`, revoke-then-delete
# for `logout`. It reads auth.json and sends the calls Codex 0.160 sends with
# a ChatGPT login, to the base URLs the driver passed with -c.
FAKE = r'''
import json, os, sys, urllib.request, urllib.error
mode = os.environ.get("SYNTHETIC_CODEX_MODE", "success")
args = sys.argv[1:]
overrides = dict(arg.split("=", 1) for arg in args[args.index("--strict-config") + 1:][1::2]) \
    if "app-server" in args else {}
home = os.environ["CODEX_HOME"]
auth = json.load(open(os.path.join(home, "auth.json")))
tokens = auth["tokens"]
def call(url, method="GET", body=None, bearer=None):
    headers = {"Authorization": "Bearer " + (bearer or tokens["access_token"]),
               "ChatGPT-Account-ID": tokens["account_id"]}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                     headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
if args[0] == "logout":
    token = tokens["access_token"] if mode == "revoke-access" else tokens["refresh_token"]
    hint = "access_token" if mode == "revoke-access" else "refresh_token"
    call(os.environ["CODEX_REVOKE_TOKEN_URL_OVERRIDE"], "POST",
         {"token": token, "token_type_hint": hint, "client_id": "synthetic"})
    os.unlink(os.path.join(home, "auth.json"))
    sys.exit(0)
chatgpt = overrides["chatgpt_base_url"].strip('"').rstrip("/")
openai = overrides["openai_base_url"].strip('"')
bearer = "wrong-synthetic-bearer" if mode == "wrong-bearer" else None
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    value = json.loads(line)
    if "id" not in value:
        continue
    request_id, method = value["id"], value["method"]
    if method == "initialize":
        send({"id": request_id, "result": {"codexHome": home, "platformOs": "linux"}})
    elif method == "account/read":
        status, _ = call(chatgpt + "/wham/accounts/check", bearer=bearer)
        if status != 200:
            send({"id": request_id, "error": {"code": -32000, "message": "synthetic"}})
            continue
        kind = "apiKey" if mode == "api-key" else "chatgpt"
        send({"id": request_id, "result": {"account": {"type": kind, "planType": "plus"},
                                           "requiresOpenaiAuth": True}})
    elif method == "account/rateLimits/read":
        status, body = (200, b'{"plan_type":"plus","rate_limit":{"primary_window":{"used_percent":12,"limit_window_seconds":18000}}}') \
            if mode == "skip-usage" else call(chatgpt + "/wham/usage")
        usage = json.loads(body)
        window = usage["rate_limit"]["primary_window"]
        send({"id": request_id, "result": {"rateLimits": {"limitId": "codex", "planType": usage["plan_type"],
              "primary": {"usedPercent": window["used_percent"],
                          "windowDurationMins": window["limit_window_seconds"] // 60}}}})
    elif method == "thread/start":
        call(openai + "/models?client_version=0.160.0")
        websocket = call(openai + "/responses")[0]
        assert websocket == 426, websocket
        send({"id": request_id, "result": {"thread": {"id": "thread-1", "ephemeral": True,
              "path": None}, "modelProvider": "openai"}})
    elif method == "turn/start":
        if mode == "refresh":
            call(os.environ["CODEX_REFRESH_TOKEN_URL_OVERRIDE"], "POST",
                 {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]})
        status, body = call(openai + "/responses", "POST", {"model": "codewire-synthetic",
            "input": [{"type": "message", "content": value["params"]["input"]}]})
        thread_id = value["params"]["threadId"]
        send({"id": request_id, "result": {"turn": {"id": "turn-1", "status": "inProgress"}}})
        if status == 200 and b"CWCODEXLOGIN kind" in body:
            send({"method": "item/completed", "params": {"threadId": thread_id, "turnId": "turn-1",
                  "item": {"type": "agentMessage", "text": "CWCODEXLOGIN kind"}}})
            send({"method": "turn/completed", "params": {"threadId": thread_id,
                  "turn": {"id": "turn-1", "status": "completed", "error": None}}})
        else:
            send({"method": "turn/completed", "params": {"threadId": thread_id,
                  "turn": {"id": "turn-1", "status": "failed", "error": {"message": "x"}}}})
'''


class Workspace:
    """A synthetic Codex home and daemon state directory in place of the Pod's."""

    def __init__(self, test):
        scratch = tempfile.TemporaryDirectory(prefix="kind-codex-login-")
        test.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.home = root / ".codex"
        self.home.mkdir(mode=0o700)
        self.state = root / "tmp/codewire-codex-login"
        self.workdir = root / "workspace"
        self.workdir.mkdir()
        self.auth = self.home / "auth.json"
        self.config = self.home / "config.toml"
        self.output = io.StringIO()
        for fixture in (
            patch.object(driver, "CODEX_HOME", self.home),
            patch.object(driver, "AUTH", self.auth),
            patch.object(driver, "CONFIG", self.config),
            patch.object(driver, "STATE", self.state),
            patch.object(driver, "WORKDIR", str(self.workdir)),
            patch.object(driver, "CODEX_COMMAND", (sys.executable, "-u", "-c", FAKE)),
            patch.object(driver, "POLL", 0.02),
            patch.object(driver, "FULL_CHECK", 0.2),
            patch.object(driver, "NEXT_CHECK", 1.0),
            # Generous: on a loaded CI guest the synthetic delivery thread and
            # the fake Codex can take over a second; no case tests its length.
            patch.object(driver, "DELIVERY_TIMEOUT", 10.0),
            patch.object(driver, "CONFIG_REMOVAL_TIMEOUT", 0.3),
            patch.dict(os.environ, {"CODEX_HOME": str(self.home),
                                    "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"},
                       clear=False),
            patch.object(driver.signal, "signal"),
            contextlib.redirect_stdout(self.output),
        ):
            fixture.__enter__()
            test.addCleanup(fixture.__exit__, None, None, None)
        os.environ.pop("CODEX_CA_CERTIFICATE", None)
        os.environ.pop("SYNTHETIC_CODEX_MODE", None)

    def deliver(self, contents=None, mode=0o600):
        # As the daemon does: a new file renamed into place. Written in
        # place, the driver's poll could read it half-written or before its
        # mode was set (auth_file_not_codewires under load, main run 22757).
        temporary = self.home / ".auth.json.new"
        temporary.write_bytes(login() if contents is None else contents)
        temporary.chmod(mode)
        temporary.rename(self.auth)

    def mark_logout(self):
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "generation-7.logged-out.cred-synthetic").write_bytes(b"")

    def events(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]


def daemon_after_logout(workspace, redeliver_after=None):
    """The daemon's side of a logout: once auth.json is gone, record the
    logout; with redeliver_after, wrongly write the login again later."""
    def run():
        deadline = time.monotonic() + 120
        while workspace.auth.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        workspace.mark_logout()
        if redeliver_after is not None:
            time.sleep(redeliver_after)
            workspace.deliver(login(1))
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def later(delay, action):
    """Run action after delay, as the daemon would between two checks."""
    thread = threading.Timer(delay, action)
    thread.start()
    return thread


class CheckPeriod(unittest.TestCase):
    def setUp(self):
        saved = (driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK)
        self.addCleanup(lambda: setattr(driver, "CHECK_PERIOD", saved[0]))
        self.addCleanup(lambda: setattr(driver, "FULL_CHECK", saved[1]))
        self.addCleanup(lambda: setattr(driver, "NEXT_CHECK", saved[2]))

    def test_unset_keeps_the_production_period(self):
        driver.configure({})
        self.assertEqual((driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK),
                         (120.0, 135.0, 150.0))

    def test_every_window_follows_the_daemons_configured_period(self):
        driver.configure({driver.CHECK_PERIOD_ENV: "30"})
        self.assertEqual((driver.CHECK_PERIOD, driver.FULL_CHECK, driver.NEXT_CHECK),
                         (30.0, 45.0, 60.0))

    def test_a_period_the_daemon_would_refuse_fails_closed(self):
        for value in ("", "9", "121", "030", "30s", " 30"):
            with self.subTest(value=value), self.assertRaisesRegex(driver.Failure, "check_period"):
                driver.configure({driver.CHECK_PERIOD_ENV: value})

    def test_the_period_bounds_match_the_daemon(self):
        config = SOURCE.parents[4] / "crates/codewire-daemon/src/config.rs"
        text = config.read_text()
        self.assertIn(f'pub const CODEX_LOGIN_CHECK_PERIOD_ENV: &str = "{driver.CHECK_PERIOD_ENV}";', text)
        self.assertIn("pub const CODEX_LOGIN_CHECK_PERIOD: Duration = Duration::from_secs(120);", text)
        self.assertIn("pub const CODEX_LOGIN_CHECK_PERIOD_MIN: Duration = Duration::from_secs(10);", text)


class LoginFile(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(self)

    def test_codewires_delivered_login_yields_its_generation(self):
        self.assertIsNone(driver.delivered_generation())
        self.workspace.deliver(login(4))
        self.assertEqual(driver.delivered_generation(), 4)

    def test_anything_but_codewires_exact_login_fails_closed(self):
        cases = {
            "auth_file_mode": (login(), 0o644),
            "auth_file_not_codewires": (login(refresh="users-own-refresh-token"), 0o600),
            "id_token_claims": (login(plan="business"), 0o600),
            "access_token_claims": (login(exp=NOW - 1), 0o600),
            "auth_file_shape": (login(OPENAI_API_KEY="sk-synthetic"), 0o600),
        }
        for reason, (contents, mode) in cases.items():
            with self.subTest(reason=reason):
                self.workspace.deliver(contents, mode)
                with self.assertRaisesRegex(driver.Failure, f"^{reason}$"):
                    driver.delivered_generation()
        # A file Codex is rewriting in place does not parse: never Codewire's.
        self.workspace.deliver(login()[:40])
        with self.assertRaisesRegex(driver.Failure, "^auth_file_not_codewires$"):
            driver.delivered_generation()
        # The broker's refresh token anywhere in Codewire's file fails.
        document = json.loads(login())
        document["synthetic_extra"] = "CW_KIND_SYNTHETIC_REFRESH_3"
        self.workspace.deliver(json.dumps(document).encode())
        with self.assertRaisesRegex(driver.Failure, "^refresh_token_delivered$"):
            driver.delivered_generation()

    def test_a_symlink_or_directory_is_never_read_as_the_login(self):
        outside = self.workspace.home.parent / "outside.json"
        outside.write_bytes(login())
        outside.chmod(0o600)
        self.workspace.auth.symlink_to(outside)
        with self.assertRaisesRegex(driver.Failure, "^auth_file_not_regular$"):
            driver.delivered_generation()
        self.workspace.auth.unlink()
        self.workspace.auth.mkdir()
        with self.assertRaisesRegex(driver.Failure, "^auth_file_not_regular$"):
            driver.delivered_generation()

    def test_jwt_claims_need_three_parts_and_a_json_object(self):
        for token in ("a.b", "a.b.c.d", "e30..sig", "e30.bm90LWpzb24.sig", "e30.W10.sig", None):
            with self.subTest(token=token), self.assertRaises(driver.Failure):
                driver.jwt_claims(token)
        self.assertEqual(driver.jwt_claims(jwt({"exp": 5}))["exp"], 5)


class FixtureDelivery(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(self)

    def test_a_delivery_is_never_seen_half_written(self):
        # The driver polls while the daemon replaces the login; the fixture
        # must replace it whole, as the daemon does, or the poll fails.
        self.workspace.deliver(login(0))
        stop = threading.Event()

        def deliver_again():
            while not stop.is_set():
                self.workspace.deliver(login(2))
        thread = threading.Thread(target=deliver_again)
        thread.start()
        try:
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                self.assertIn(driver.delivered_generation(), (0, 2))
        finally:
            stop.set()
            thread.join(60)


class SyntheticBackend(unittest.TestCase):
    def setUp(self):
        self.backend = driver.Backend("synthetic-delivered-bearer")
        self.addCleanup(self.backend.close)

    def call(self, server, path, method="GET", bearer="synthetic-delivered-bearer",
             headers=None, body=None):
        request = urllib.request.Request(
            self.backend.url(server, path), method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {bearer}", "ChatGPT-Account-ID": driver.ACCOUNT,
                     **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read()

    def test_only_the_delivered_bearer_is_served_and_never_with_401(self):
        chatgpt = self.backend.chatgpt
        for bearer, account in (("other-bearer", driver.ACCOUNT), ("synthetic-delivered-bearer", "other")):
            status, _ = self.call(chatgpt, "/backend-api/wham/usage", bearer=bearer,
                                  headers={"ChatGPT-Account-ID": account})
            self.assertEqual(status, 403)
        self.assertEqual(self.backend.rejected, 2)
        self.assertEqual(self.backend.routes, {})

    def test_account_usage_websocket_and_responses_answer_like_chatgpt(self):
        status, body = self.call(self.backend.chatgpt, "/backend-api/wham/accounts/check")
        self.assertEqual((status, json.loads(body)["accounts"][0]["id"]), (200, driver.ACCOUNT))
        status, body = self.call(self.backend.chatgpt, "/backend-api/wham/usage")
        self.assertEqual(json.loads(body)["plan_type"], driver.PLAN)
        self.assertEqual(self.call(self.backend.openai, "/backend-api/codex/responses")[0], 426)
        status, body = self.call(self.backend.openai, "/backend-api/codex/responses", "POST",
                                 body={"input": [driver.PROMPT]})
        self.assertEqual(status, 200)
        self.assertIn(driver.MARKER.encode(), body)
        self.assertEqual(self.call(self.backend.openai, "/backend-api/codex/models?client_version=1")[0], 200)
        self.assertEqual(self.backend.routes, {"accounts_check": 1, "usage": 1, "websocket": 1,
                                               "responses": 1, "models": 1})
        # The two base URLs are different origins: Codex would otherwise route
        # its Responses calls to the discovered https backend.
        self.assertNotEqual(self.backend.openai.server_address, self.backend.chatgpt.server_address)

    def test_refresh_revocation_and_unknown_calls_are_recorded(self):
        self.assertEqual(self.call(self.backend.chatgpt, "/oauth/token", "POST", body={})[0], 503)
        self.call(self.backend.chatgpt, "/oauth/revoke", "POST",
                  body={"token": driver.PLACEHOLDER, "token_type_hint": "refresh_token"})
        self.assertEqual(self.call(self.backend.chatgpt, "/backend-api/unknown")[0], 404)
        self.assertEqual(self.backend.refreshes, 1)
        self.assertEqual(self.backend.revocations, [("refresh_token", True)])
        self.assertEqual(self.backend.unknown, 1)


class Modes(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(self)

    def run_mode(self, *argv):
        status = driver.main(list(argv))
        events = self.workspace.events()
        # The stream is closed: never a token, account bearer or file content.
        output = self.workspace.output.getvalue()
        for secret in ("synthetic-kind-signature", driver.PLACEHOLDER, "Bearer"):
            self.assertNotIn(secret, output)
        return status, events

    def test_deliver_reads_account_usage_and_a_turn_with_the_delivered_login(self):
        self.workspace.deliver(login(0))
        status, events = self.run_mode("deliver")
        self.assertEqual(status, 0, events)
        self.assertEqual(events[0]["event"], "delivered")
        self.assertEqual(events[0]["generation"], 0)
        self.assertEqual(events[0]["account"], "chatgpt")
        self.assertEqual(events[0]["usage_calls"], 1)
        self.assertEqual(events[-1], {"event": "complete", "mode": "deliver"})

    def test_deliver_fails_on_a_wrong_bearer_account_type_refresh_or_kept_config(self):
        for synthetic, reason in (("wrong-bearer", "rpc_rejected_account_read"),
                                  ("api-key", "account_not_chatgpt"),
                                  ("refresh", "backend_rejected_or_refreshed"),
                                  ("skip-usage", "backend_calls_missing")):
            with self.subTest(synthetic=synthetic):
                self.workspace.output.truncate(0)
                self.workspace.output.seek(0)
                self.workspace.deliver(login(0))
                with patch.dict(os.environ, {"SYNTHETIC_CODEX_MODE": synthetic}):
                    status, events = self.run_mode("deliver")
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "mode": "deliver", "reason": reason}])
        self.workspace.output.truncate(0)
        self.workspace.output.seek(0)
        self.workspace.config.write_bytes(MANAGED_CONFIG)
        self.assertEqual(self.run_mode("deliver")[1][-1]["reason"], "proxy_config_kept")

    def test_deliver_waits_for_the_daemon_and_fails_without_a_login(self):
        later(0.2, lambda: self.workspace.deliver(login(2)))
        self.assertEqual(self.run_mode("deliver")[0], 0)
        self.workspace.auth.unlink()
        self.workspace.output.truncate(0)
        self.workspace.output.seek(0)
        self.assertEqual(self.run_mode("deliver")[1],
                         [{"event": "failed", "mode": "deliver", "reason": "login_not_delivered"}])

    def test_rotation_requires_a_later_generation_in_the_file(self):
        self.workspace.deliver(login(0))
        later(0.2, lambda: self.workspace.deliver(login(2)))
        status, events = self.run_mode("rotation", "0")
        self.assertEqual(status, 0)
        self.assertEqual(events[0]["generation"], 2)
        self.workspace.output.truncate(0)
        self.workspace.output.seek(0)
        self.assertEqual(self.run_mode("rotation", "2")[1][-1]["reason"], "rotation_not_adopted")

    def test_own_login_stays_untouched_and_codewires_file_comes_back(self):
        self.workspace.deliver(login(1))
        original = self.workspace.auth.read_bytes()
        inode = self.workspace.auth.stat().st_ino
        status, events = self.run_mode("own-login")
        self.assertEqual(status, 0, events)
        self.assertEqual(self.workspace.auth.read_bytes(), original)
        self.assertEqual(self.workspace.auth.stat().st_ino, inode)

    def test_own_login_fails_when_the_daemon_replaces_it(self):
        self.workspace.deliver(login(1))
        with patch.object(driver, "FULL_CHECK", 0.5):
            later(0.2, lambda: self.workspace.deliver(login(1)))
            status, events = self.run_mode("own-login")
        self.assertEqual((status, events[-1]["reason"]), (1, "own_login_touched"))

    def test_logout_revokes_only_the_placeholder_and_stays_logged_out(self):
        self.workspace.deliver(login(1))
        daemon_after_logout(self.workspace)
        status, events = self.run_mode("logout")
        self.assertEqual(status, 0, events)
        self.assertEqual(events[0]["revoked"], "placeholder")
        self.assertFalse(self.workspace.auth.exists())

    def test_logout_fails_if_it_revokes_more_is_not_recorded_or_is_undone(self):
        self.workspace.deliver(login(1))
        with patch.dict(os.environ, {"SYNTHETIC_CODEX_MODE": "revoke-access"}):
            self.assertEqual(self.run_mode("logout")[1][-1]["reason"],
                             "logout_revoked_more_than_placeholder")
        for action, reason in ((None, "logout_not_recorded"),
                               ("undo", "logout_undone")):
            with self.subTest(reason=reason):
                self.workspace.output.truncate(0)
                self.workspace.output.seek(0)
                for marker in self.workspace.state.glob("*"):
                    marker.unlink()
                self.workspace.deliver(login(1))
                if action == "undo":
                    # The wrong redelivery must land after the script has seen
                    # auth.json gone (which can take a while under load) and
                    # before its full check ends.
                    daemon_after_logout(self.workspace, redeliver_after=2.0)
                with patch.object(driver, "FULL_CHECK", 4.0):
                    self.assertEqual(self.run_mode("logout")[1][-1]["reason"], reason)

    def test_redelivery_requires_a_fresh_container(self):
        self.workspace.deliver(login(2))
        self.assertEqual(self.run_mode("redelivered")[0], 0)
        self.workspace.mark_logout()
        self.workspace.output.truncate(0)
        self.workspace.output.seek(0)
        self.assertEqual(self.run_mode("redelivered")[1][-1]["reason"],
                         "logout_survived_new_container")

    def test_revocation_removes_the_login_and_restores_the_proxy_config(self):
        self.workspace.deliver(login(2))
        def daemon_withdraws():
            self.workspace.auth.unlink()
            self.workspace.config.write_bytes(MANAGED_CONFIG)
        later(0.2, daemon_withdraws)
        self.assertEqual(self.run_mode("revoked")[0], 0)
        self.workspace.deliver(login(2))
        self.workspace.output.truncate(0)
        self.workspace.output.seek(0)
        self.assertEqual(self.run_mode("revoked")[1][-1]["reason"], "revoked_login_kept")

    def test_arguments_and_projection_are_closed(self):
        for argv in ([], ["unknown"], ["rotation"], ["rotation", "x"], ["deliver", "extra"]):
            with self.subTest(argv=argv):
                self.workspace.output.truncate(0)
                self.workspace.output.seek(0)
                self.assertEqual(self.run_mode(*argv)[0], 1)
        with patch.dict(os.environ, {"CODEX_CA_CERTIFICATE": "/synthetic/roots"}):
            self.workspace.output.truncate(0)
            self.workspace.output.seek(0)
            self.assertEqual(self.run_mode("revoked")[1][-1]["reason"], "unexpected_projection")


if __name__ == "__main__":
    unittest.main()
