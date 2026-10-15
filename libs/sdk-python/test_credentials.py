"""Synthetic generated Connect credential consumers; no provider credentials."""

import unittest

import httpx
from connectrpc.code import Code
from connectrpc.errors import ConnectError

from codewire import Codewire, CodewireError, EnrollmentOutcomeUnknownError
from codewire.credentials import _credential
from codewire.v1 import credential_pb2 as pb
from codewire.v1.credential_connect import (
    CredentialServiceWSGIApplication, CredentialMutationServiceWSGIApplication,
    GithubRepositoryServiceWSGIApplication,
)


EXACT = 9_007_199_254_741_009
MAXIMUM = (1 << 64) - 1


class CredentialFixture:
    def __init__(self):
        self.calls = []
        self.after_challenge = False
        self.closed = 0
        self.deadline = 0

    def record(self, method, request, ctx):
        if ctx.request_headers.get("authorization") != "Bearer synthetic-opaque-oauth":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")
        if "org_id" in request.DESCRIPTOR.fields_by_name:
            raise AssertionError("personal credentials must not inherit organization scope")
        self.calls.append((method, request))

    @staticmethod
    def credential(status=pb.CREDENTIAL_STATUS_ACTIVE):
        return pb.Credential(id="credential-one", name="personal", provider="openai",
                             authentication_kind=pb.CREDENTIAL_AUTHENTICATION_KIND_OAUTH,
                             status=status, expires_at_unix=MAXIMUM, revocation_generation=EXACT)

    def list_credentials(self, request, ctx):
        self.record("ListCredentials", request, ctx)
        return pb.ListCredentialsResponse(credentials=[self.credential()],
                                          next_page_token="page-two" if not request.page_token else "")

    def list_github_repositories(self, request, ctx):
        self.record("ListGithubRepositories", request, ctx)
        return pb.ListGithubRepositoriesResponse(repositories=[pb.GithubRepository(
            repository_id="42", full_name="owner/private", default_branch="main",
            clone_url="https://github.com/owner/private.git", is_private=True,
        )], next_page_token="opaque-next")

    def list_github_pending_permissions(self, request, ctx):
        self.record("ListGithubPendingPermissions", request, ctx)
        return pb.ListGithubPendingPermissionsResponse(pending_permissions=[
            pb.GithubAppPendingPermissions(account="octo-org", installation_id=43,
                                           account_kind=pb.GITHUB_APP_ACCOUNT_KIND_ORGANIZATION),
            pb.GithubAppPendingPermissions(account="octo-ent", installation_id=MAXIMUM,
                                           account_kind=pb.GITHUB_APP_ACCOUNT_KIND_ENTERPRISE),
            pb.GithubAppPendingPermissions(account="unknown", installation_id=1),
        ])

    def get_credential(self, request, ctx):
        self.record("GetCredential", request, ctx)
        if request.credential_id == "missing":
            return pb.GetCredentialResponse()
        if request.name == "ssh":
            value = self.credential()
            value.provider = "ssh"
            value.authentication_kind = pb.CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY
            value.ssh_public_key.CopyFrom(pb.SshPublicKey(
                openssh="ssh-ed25519 synthetic-public-key", fingerprint="SHA256:synthetic"))
            return pb.GetCredentialResponse(credential=value)
        statuses = {"revoked": pb.CREDENTIAL_STATUS_REVOKED, "expired": pb.CREDENTIAL_STATUS_EXPIRED,
                    "refresh_failed": pb.CREDENTIAL_STATUS_REFRESH_FAILED}
        return pb.GetCredentialResponse(credential=self.credential(statuses.get(request.name, pb.CREDENTIAL_STATUS_ACTIVE)))

    def revoke_credential(self, request, ctx):
        self.record("RevokeCredential", request, ctx)
        if request.credential_id == "stale":
            raise ConnectError(Code.ABORTED, "stale revision")
        return pb.RevokeCredentialResponse(credential=self.credential(pb.CREDENTIAL_STATUS_REVOKED))

    def delete_credential(self, request, ctx):
        self.record("DeleteCredential", request, ctx)
        return pb.DeleteCredentialResponse()

    def unsupported_mutation(self, request, ctx):
        raise AssertionError("this fixture does not exercise this mutation")

    enroll_github = unsupported_mutation
    complete_github_app_authorization = unsupported_mutation
    add_api_key_credential = unsupported_mutation
    add_claude_subscription_token_credential = unsupported_mutation
    start_claude_sign_in = unsupported_mutation
    complete_claude_sign_in = unsupported_mutation
    rename_credential = unsupported_mutation
    rotate_api_key_credential = unsupported_mutation
    generate_ssh_credential = unsupported_mutation
    add_ssh_credential = unsupported_mutation

    def enroll_codex(self, request, ctx):
        self.record("EnrollCodex", request, ctx)
        self.deadline = int(ctx.request_headers.get("connect-timeout-ms", "0"))
        self.after_challenge = False
        challenge = pb.EnrollCodexResponse(challenge=pb.CodexDeviceChallenge(
            verification_url="https://auth.openai.com/codex/device", user_code="SYNTHETIC-CODE",
            expires_at_unix=MAXIMUM))
        try:
            yield challenge
            self.after_challenge = True
            if request.name == "success":
                yield pb.EnrollCodexResponse(credential=self.credential())
            elif request.name == "error":
                raise ConnectError(Code.UNAVAILABLE, "synthetic unavailable")
            elif request.name == "duplicate":
                yield challenge
        finally:
            self.closed += 1


class CredentialsTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = CredentialFixture()
        metadata = CredentialServiceWSGIApplication(self.fixture)
        mutations = CredentialMutationServiceWSGIApplication(self.fixture)
        repositories = GithubRepositoryServiceWSGIApplication(self.fixture)
        self.paths = []

        def app(environ, start_response):
            path = environ["PATH_INFO"]
            self.paths.append(path)
            service = repositories if path.startswith("/codewire.v1.GithubRepositoryService/") else (
                metadata if path.startswith("/codewire.v1.CredentialService/") else mutations)
            return service(environ, start_response)

        self.http = httpx.Client(transport=httpx.WSGITransport(app=app))
        self.cw = Codewire(api_key="synthetic-opaque-oauth", base_url="https://sdk.example.test",
                           http_client=self.http)

    def tearDown(self):
        self.cw.close()
        self.assertFalse(self.http.is_closed)
        self.http.close()

    def test_metadata_pagination_selectors_uint64_and_truthful_statuses(self):
        values = self.cw.credentials.list()
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0]["revocation_generation"], EXACT)
        self.assertEqual(values[0]["expires_at_unix"], MAXIMUM)
        self.assertIsNone(values[0]["account_hint"])
        self.assertIsNone(values[0]["ssh_public_key"])
        self.assertEqual([request.page_token for _, request in self.fixture.calls], ["", "page-two"])
        self.cw.credentials.get("credential-one")
        self.assertEqual(self.fixture.calls[-1][1].WhichOneof("selector"), "credential_id")
        for status in ["expired", "refresh_failed", "revoked"]:
            self.assertEqual(self.cw.credentials.get_by_name(status)["status"], status)
            self.assertEqual(self.fixture.calls[-1][1].WhichOneof("selector"), "name")
        with self.assertRaisesRegex(RuntimeError, "omitted credential"):
            self.cw.credentials.get("missing")

    def test_repository_page_keeps_owner_singleton_and_allowlisted_metadata(self):
        page = self.cw.credentials.list_github_repositories(page_size=50, page_token="opaque-page")
        self.assertEqual(page, {"repositories": [{"repository_id":"42", "full_name":"owner/private", "default_branch":"main",
            "clone_url":"https://github.com/owner/private.git", "is_private":True, "archived":False, "disabled":False}],
            "next_page_token":"opaque-next"})
        request = self.fixture.calls[0][1]
        self.assertEqual((request.page_size,request.page_token), (50,"opaque-page"))
        self.assertEqual(self.paths,["/codewire.v1.GithubRepositoryService/ListGithubRepositories"])
        self.assertEqual(set(pb.GithubRepository.DESCRIPTOR.fields_by_name), set(page["repositories"][0]))
        for kwargs in [{"page_size":101}, {"page_token":"x"*129}]:
            with self.assertRaises(ValueError):
                self.cw.credentials.list_github_repositories(**kwargs)
        self.assertEqual(len(self.fixture.calls),1)

    def test_pending_permissions_keep_login_id_and_kind_only(self):
        pending = self.cw.credentials.list_github_pending_permissions()
        self.assertEqual(pending, [
            {"account": "octo-org", "installation_id": 43, "account_kind": "organization"},
            {"account": "octo-ent", "installation_id": MAXIMUM, "account_kind": "enterprise"},
        ])
        self.assertEqual(self.paths, ["/codewire.v1.GithubRepositoryService/ListGithubPendingPermissions"])

    def test_ssh_metadata_preserves_public_registration_data(self):
        value = self.cw.credentials.get_by_name("ssh")
        self.assertEqual(value["authentication_kind"], "ssh_key")
        self.assertEqual(value["ssh_public_key"], {
            "openssh": "ssh-ed25519 synthetic-public-key", "fingerprint": "SHA256:synthetic"})
        self.assertEqual(self.paths, ["/codewire.v1.CredentialService/GetCredential"])
        self.assertNotIn("private_key", value)

    def test_mismatched_ssh_metadata_is_not_a_valid_credential(self):
        value = self.fixture.credential()
        value.authentication_kind = pb.CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY
        with self.assertRaisesRegex(RuntimeError, "mismatched SSH"):
            _credential(value)
        value.authentication_kind = pb.CREDENTIAL_AUTHENTICATION_KIND_OAUTH
        value.ssh_public_key.CopyFrom(pb.SshPublicKey(openssh="synthetic-public-key"))
        with self.assertRaisesRegex(RuntimeError, "mismatched SSH"):
            _credential(value)

    def test_lifecycle_exact_cas_and_no_retry(self):
        self.assertEqual(self.cw.credentials.revoke("credential-one", EXACT)["status"], "revoked")
        self.assertEqual(self.fixture.calls[-1][1].expected_revocation_generation, EXACT)
        self.cw.credentials.delete("credential-one", MAXIMUM)
        self.assertEqual(self.fixture.calls[-1][1].expected_revocation_generation, MAXIMUM)
        before = len(self.fixture.calls)
        with self.assertRaises(CodewireError):
            self.cw.credentials.revoke("stale", EXACT)
        self.assertEqual(len(self.fixture.calls), before + 1)
        before = len(self.fixture.calls)
        for invalid in [0, -1, MAXIMUM + 1, True, 1.5]:
            with self.assertRaisesRegex(ValueError, "positive uint64"):
                self.cw.credentials.delete("credential-one", invalid)
        self.assertEqual(len(self.fixture.calls), before)

    def test_enrollment_delivers_challenge_incrementally_and_overrides_only_call_deadline(self):
        stream = self.cw.credentials.enroll_codex("success")
        self.assertEqual(len(self.fixture.calls), 0, "constructing the stream must not consume it")
        challenge = next(stream)
        self.assertEqual(challenge["type"], "challenge")
        self.assertEqual(challenge["challenge"]["expires_at_unix"], MAXIMUM)
        self.assertFalse(self.fixture.after_challenge, "challenge must not wait for enrollment completion")
        self.assertGreater(self.fixture.deadline, 900_000)
        self.assertLessEqual(self.fixture.deadline, 960_000)
        self.assertEqual(self.cw._connect._timeout_ms, 30_000)
        value = next(stream)
        self.assertEqual(value["type"], "credential")
        self.assertEqual(value["credential"]["revocation_generation"], EXACT)
        with self.assertRaises(StopIteration):
            next(stream)
        self.assertEqual(self.fixture.closed, 1)
        self.assertEqual(self.paths, ["/codewire.v1.CredentialMutationService/EnrollCodex"])
        request = self.fixture.calls[0][1]
        self.assertEqual({field.name: field.number for field in request.DESCRIPTOR.fields}, {
            "name": 1, "credential_id": 2, "expected_revocation_generation": 3})
        self.assertFalse(request.HasField("credential_id"))
        self.assertFalse(request.HasField("expected_revocation_generation"))

    def test_missing_error_or_duplicate_ack_is_uncertain_without_retry(self):
        for name in ["eof", "error", "duplicate"]:
            before = len(self.fixture.calls)
            stream = self.cw.credentials.enroll_codex(name)
            self.assertEqual(next(stream)["type"], "challenge")
            with self.assertRaisesRegex(EnrollmentOutcomeUnknownError, "reconcile.*by name"):
                next(stream)
            self.assertEqual(len(self.fixture.calls), before + 1)
            self.assertEqual(self.fixture.calls[-1][0], "EnrollCodex")

    def test_closing_iterator_closes_original_stream_without_continuation(self):
        stream = self.cw.credentials.enroll_codex("drop")
        self.assertEqual(next(stream)["type"], "challenge")
        stream.close()
        self.assertFalse(self.fixture.after_challenge)
        self.assertEqual(self.fixture.closed, 1)
        self.assertEqual([method for method, _ in self.fixture.calls], ["EnrollCodex"])


if __name__ == "__main__":
    unittest.main()
