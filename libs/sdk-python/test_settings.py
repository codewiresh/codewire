"""Every state of the journey's sdk-config step, from an explicit environment
and a scratch working directory."""

import os
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

import httpx

from codewire import Codewire
from codewire import _settings
from codewire._settings import parse_dotenv, report_once, resolve_settings
from codewire.v1.api_key_connect import ApiKeyServiceSync, ApiKeyServiceWSGIApplication
from codewire.v1.api_key_pb2 import ListApiKeysResponse

KEY = "cw_synthetic_key"
TOKEN = "synthetic-user-token"


class SettingsTestCase(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="codewire-settings-")
        self.addCleanup(scratch.cleanup)
        self.cwd = Path(scratch.name)

    def isolate_client(self):
        """Give a Codewire() built in this test an empty environment and the
        scratch directory, so nothing of the developer's is read."""
        environ = mock.patch.dict(os.environ, clear=True)
        environ.start()
        self.addCleanup(environ.stop)
        previous = os.getcwd()
        os.chdir(self.cwd)
        self.addCleanup(os.chdir, previous)

    def files(self, **files):
        for name, text in files.items():
            (self.cwd / name).write_text(text, encoding="utf-8")

    def resolve(self, environ, **code):
        return resolve_settings(
            api_key=code.get("api_key"),
            jwt_token=code.get("jwt_token"),
            organization_id=code.get("organization_id"),
            api_url=code.get("api_url"),
            environ=environ,
            cwd=self.cwd,
        )

    def refusal(self, environ):
        with self.assertRaises(ValueError) as refused:
            self.resolve(environ)
        return str(refused.exception)

    def test_key_only(self):
        settings = self.resolve({"CODEWIRE_API_KEY": KEY})
        self.assertEqual(
            (settings.bearer, settings.credential, settings.organization_id, settings.api_url),
            (KEY, "api key", "", "https://codewire.sh"),
        )
        self.assertEqual(settings.warnings, ())

    def test_token_and_organization(self):
        settings = self.resolve(
            {"CODEWIRE_JWT_TOKEN": TOKEN, "CODEWIRE_ORGANIZATION_ID": "org-one"}
        )
        self.assertEqual(
            (settings.bearer, settings.credential, settings.organization_id),
            (TOKEN, "user token", "org-one"),
        )

    def test_org_id_alias(self):
        settings = self.resolve({"CODEWIRE_JWT_TOKEN": TOKEN, "CODEWIRE_ORG_ID": "org-alias"})
        self.assertEqual((settings.bearer, settings.organization_id), (TOKEN, "org-alias"))
        preferred = self.resolve({
            "CODEWIRE_API_KEY": KEY,
            "CODEWIRE_ORGANIZATION_ID": "org-new",
            "CODEWIRE_ORG_ID": "org-old",
        })
        self.assertEqual(preferred.organization_id, "org-new")

    def test_both_set_uses_the_key(self):
        settings = self.resolve({"CODEWIRE_API_KEY": KEY, "CODEWIRE_JWT_TOKEN": TOKEN})
        self.assertEqual((settings.bearer, settings.credential), (KEY, "api key"))
        # A token beside the key in the same source is not reported.
        self.assertEqual(settings.warnings, ())

    def test_neither_is_refused_naming_both(self):
        message = self.refusal({"CODEWIRE_ORGANIZATION_ID": "org-one"})
        self.assertIn("CODEWIRE_API_KEY", message)
        self.assertIn("CODEWIRE_JWT_TOKEN", message)
        self.assertIn("CODEWIRE_API_KEY", self.refusal({"CODEWIRE_API_KEY": "", "CODEWIRE_JWT_TOKEN": ""}))

    def test_token_without_organization_is_refused(self):
        message = self.refusal({"CODEWIRE_JWT_TOKEN": TOKEN})
        self.assertIn("CODEWIRE_ORGANIZATION_ID", message)
        self.assertNotIn(TOKEN, message)

    def test_dotenv_is_used(self):
        self.files(**{".env": f"CODEWIRE_JWT_TOKEN={TOKEN}\nCODEWIRE_ORG_ID=org-file\n"})
        settings = self.resolve({})
        self.assertEqual((settings.bearer, settings.organization_id), (TOKEN, "org-file"))

    def test_dotenv_local_token_beats_dotenv_key(self):
        self.files(**{
            ".env": "CODEWIRE_API_KEY=cw_from_env_file\nCODEWIRE_ORGANIZATION_ID=org-env-file\n",
            ".env.local": f"CODEWIRE_JWT_TOKEN={TOKEN}\n",
        })
        settings = self.resolve({})
        self.assertEqual((settings.bearer, settings.credential), (TOKEN, "user token"))
        # Nothing at or above .env.local sets an organization, so .env's is
        # used and reported.
        self.assertEqual(settings.organization_id, "org-env-file")
        self.assertEqual(len(settings.warnings), 2)
        self.assertRegex(
            settings.warnings[0],
            r"^ignored CODEWIRE_API_KEY in .*\.env: the credential comes from .*\.env\.local$",
        )
        self.assertRegex(
            settings.warnings[1],
            r"^used CODEWIRE_ORGANIZATION_ID in .*\.env: the credential in .*\.env\.local sets no organization$",
        )
        for value in ("cw_from_env_file", "org-env-file"):
            self.assertNotIn(value, " ".join(settings.warnings))

    def test_environment_beats_both_files(self):
        self.files(**{
            ".env": "CODEWIRE_API_KEY=cw_from_env_file\n",
            ".env.local": "CODEWIRE_API_KEY=cw_from_local_file\nCODEWIRE_ORGANIZATION_ID=org-file\n",
        })
        settings = self.resolve({"CODEWIRE_API_KEY": "cw_from_environment", "CODEWIRE_ORG_ID": "org-environment"})
        self.assertEqual(settings.bearer, "cw_from_environment")
        self.assertEqual(settings.organization_id, "org-environment")

    def test_server_in_dotenv_is_ignored_and_reported(self):
        self.files(**{
            ".env": "CODEWIRE_API_URL=https://elsewhere.example.test\n",
            ".env.local": "CODEWIRE_BASE_URL=https://other.example.test\n",
        })
        settings = self.resolve({"CODEWIRE_API_KEY": KEY})
        self.assertEqual(settings.api_url, "https://codewire.sh")
        self.assertEqual(len(settings.warnings), 2)
        self.assertRegex(settings.warnings[0], r"CODEWIRE_BASE_URL in .*\.env\.local")
        self.assertRegex(settings.warnings[1], r"CODEWIRE_API_URL in .*\.env:")
        self.assertNotIn("example.test", " ".join(settings.warnings))

        _settings._reported.difference_update(settings.warnings)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            report_once(settings.warnings)
            report_once(settings.warnings)
        self.assertEqual([str(warning.message) for warning in caught], list(settings.warnings))

    def test_server_aliases_from_the_environment(self):
        for environ, expected in (
            ({"CODEWIRE_SERVER_URL": "https://server.example.test/"}, "https://server.example.test"),
            ({"CODEWIRE_BASE_URL": "https://base.example.test"}, "https://base.example.test"),
            ({
                "CODEWIRE_API_URL": "https://api.example.test",
                "CODEWIRE_SERVER_URL": "https://server.example.test",
                "CODEWIRE_BASE_URL": "https://base.example.test",
            }, "https://api.example.test"),
        ):
            with self.subTest(environ=environ):
                self.assertEqual(self.resolve({"CODEWIRE_API_KEY": KEY, **environ}).api_url, expected)

    def test_a_key_in_code_beats_every_source_and_reports_the_rest(self):
        self.files(**{
            ".env": "CODEWIRE_API_KEY=cw_from_env_file\nCODEWIRE_ORGANIZATION_ID=org-env-file\n",
            ".env.local": "CODEWIRE_JWT_TOKEN=token-from-local-file\n",
        })
        environ = {
            "CODEWIRE_API_KEY": "cw_from_environment",
            "CODEWIRE_ORGANIZATION_ID": "org-environment",
            "CODEWIRE_API_URL": "https://environment.example.test",
        }
        key = self.resolve(environ, api_key="cw_from_code", api_url="https://code.example.test")
        # Code sets no organization, so the environment's is used and reported.
        self.assertEqual(
            (key.bearer, key.organization_id, key.api_url),
            ("cw_from_code", "org-environment", "https://code.example.test"),
        )
        self.assertEqual(len(key.warnings), 4)
        self.assertEqual(
            key.warnings[3],
            "used CODEWIRE_ORGANIZATION_ID in the environment: the credential in code sets no organization",
        )
        for value in ("cw_from_environment", "cw_from_env_file", "token-from-local-file", "org-environment"):
            self.assertNotIn(value, " ".join(key.warnings))

    def test_a_token_in_code_beats_a_key_in_the_environment(self):
        settings = self.resolve(
            {"CODEWIRE_API_KEY": KEY, "CODEWIRE_ORGANIZATION_ID": "org-environment"},
            jwt_token=TOKEN, organization_id="org-code",
        )
        self.assertEqual(
            (settings.bearer, settings.credential, settings.organization_id),
            (TOKEN, "user token", "org-code"),
        )
        self.assertEqual(
            settings.warnings,
            ("ignored CODEWIRE_API_KEY in the environment: the credential comes from code",),
        )

    def test_a_token_in_the_environment_beats_a_key_in_dotenv(self):
        self.files(**{".env": f"CODEWIRE_API_KEY={KEY}\n"})
        settings = self.resolve({"CODEWIRE_JWT_TOKEN": TOKEN, "CODEWIRE_ORG_ID": "org-environment"})
        self.assertEqual((settings.bearer, settings.credential), (TOKEN, "user token"))
        self.assertEqual(len(settings.warnings), 1)
        self.assertRegex(
            settings.warnings[0],
            r"^ignored CODEWIRE_API_KEY in .*\.env: the credential comes from the environment$",
        )
        self.assertNotIn(KEY, settings.warnings[0])

    def test_an_organization_in_code_always_wins(self):
        self.files(**{".env": f"CODEWIRE_JWT_TOKEN={TOKEN}\nCODEWIRE_ORGANIZATION_ID=org-env-file\n"})
        settings = self.resolve(
            {"CODEWIRE_ORGANIZATION_ID": "org-environment"}, organization_id="org-code"
        )
        self.assertEqual((settings.organization_id, settings.warnings), ("org-code", ()))

    def test_the_environment_organization_beats_dotenv_for_a_dotenv_credential(self):
        self.files(**{".env": f"CODEWIRE_JWT_TOKEN={TOKEN}\nCODEWIRE_ORGANIZATION_ID=org-env-file\n"})
        settings = self.resolve({"CODEWIRE_ORGANIZATION_ID": "org-environment"})
        # At or above the credential's source, so nothing is reported.
        self.assertEqual((settings.organization_id, settings.warnings), ("org-environment", ()))

    def test_either_alias_counts_in_the_credential_source(self):
        self.files(**{".env.local": f"CODEWIRE_API_KEY={KEY}\nCODEWIRE_ORG_ID=org-alias-file\n"})
        settings = self.resolve({})
        self.assertEqual((settings.organization_id, settings.warnings), ("org-alias-file", ()))

    def test_a_higher_file_names_the_organization_without_a_report(self):
        self.files(**{
            ".env": f"CODEWIRE_JWT_TOKEN={TOKEN}\n",
            ".env.local": "CODEWIRE_ORGANIZATION_ID=org-local-file\n",
        })
        settings = self.resolve({})
        self.assertEqual((settings.organization_id, settings.warnings), ("org-local-file", ()))

    def test_an_organization_from_below_is_used_and_reported_once(self):
        self.files(**{".env": "CODEWIRE_ORG_ID=org-env-file\n"})
        settings = self.resolve({}, jwt_token=TOKEN)
        self.assertEqual(settings.organization_id, "org-env-file")
        self.assertEqual(len(settings.warnings), 1)
        self.assertRegex(
            settings.warnings[0],
            r"^used CODEWIRE_ORG_ID in .*\.env: the credential in code sets no organization$",
        )
        self.assertNotIn("org-env-file", settings.warnings[0])
        _settings._reported.difference_update(settings.warnings)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            report_once(settings.warnings)
            report_once(settings.warnings)
        self.assertEqual([str(warning.message) for warning in caught], list(settings.warnings))

    def test_parser(self):
        parsed = parse_dotenv(
            "\n".join([
                "# a comment",
                "OTHER_TOOL=ignored",
                "export CODEWIRE_API_KEY='cw single # kept'",
                'CODEWIRE_JWT_TOKEN = "double quoted" # comment',
                "CODEWIRE_ORGANIZATION_ID=org-plain # comment\r",
                "not a setting",
            ]),
            ".env",
        )
        self.assertEqual(parsed, {
            "CODEWIRE_API_KEY": "cw single # kept",
            "CODEWIRE_JWT_TOKEN": "double quoted",
            "CODEWIRE_ORGANIZATION_ID": "org-plain",
        })
        with self.assertRaises(ValueError) as unterminated:
            parse_dotenv(f'CODEWIRE_API_KEY="{KEY}\n', "/scratch/.env")
        self.assertIn("/scratch/.env:1", str(unterminated.exception))
        self.assertNotIn(KEY, str(unterminated.exception))

    def test_an_unreadable_file_names_its_path(self):
        (self.cwd / ".env").mkdir()
        with self.assertRaises(ValueError) as refused:
            self.resolve({}, api_key=KEY)
        self.assertIn(str(self.cwd / ".env"), str(refused.exception))

    def test_the_client_sends_the_resolved_settings_and_never_shows_the_token(self):
        seen = []

        class Fixture(ApiKeyServiceSync):
            def list_api_keys(self, request, ctx):
                seen.append((ctx.request_headers.get("authorization"), request.org_id))
                return ListApiKeysResponse()

        http = httpx.Client(
            transport=httpx.WSGITransport(app=ApiKeyServiceWSGIApplication(Fixture())),
            timeout=5,
        )
        self.addCleanup(http.close)
        self.isolate_client()
        cw = Codewire(
            jwt_token=TOKEN,
            organization_id="org-code",
            api_url="https://code.example.test/",
            timeout=5,
            http_client=http,
        )
        self.addCleanup(cw.close)
        self.assertEqual(cw.api_keys.list(), [])
        self.assertEqual(seen, [(f"Bearer {TOKEN}", "org-code")])
        shown = repr(cw) + str(cw) + repr(cw._connect) + repr(cw._context)
        self.assertIn("https://code.example.test", repr(cw))
        self.assertNotIn(TOKEN, shown)
        settings = self.resolve({}, jwt_token=TOKEN, organization_id="org-code")
        self.assertNotIn(TOKEN, repr(settings))

    def test_older_option_names_still_work(self):
        http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)), timeout=5)
        self.addCleanup(http.close)
        self.isolate_client()
        cw = Codewire(api_key=KEY, base_url="https://old.example.test", org_id="org-old", http_client=http)
        self.addCleanup(cw.close)
        self.assertEqual(repr(cw), "Codewire(api_url='https://old.example.test', organization_id='org-old', credential='api key')")


if __name__ == "__main__":
    unittest.main()
