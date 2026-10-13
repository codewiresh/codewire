"""Personal credential metadata and one-connection, OAuth-only enrollment."""

from __future__ import annotations

from collections.abc import Generator
from typing import Literal, TypedDict

from codewire._context import ConnectContext
from codewire.v1 import credential_pb2 as pb
from codewire.v1.credential_connect import (
    CredentialServiceClientSync, CredentialMutationServiceClientSync, GithubRepositoryServiceClientSync,
)


class SshPublicKey(TypedDict):
    """Public registration data only; never the private key."""

    openssh: str
    fingerprint: str


class Credential(TypedDict):
    """Metadata only; no provider token or protected-store reference."""

    id: str
    name: str
    provider: str
    authentication_kind: Literal["oauth", "api_key", "access_token", "github_app", "ssh_key"]
    account_hint: str | None
    status: Literal["active", "revoked", "expired", "refresh_failed"]
    expires_at_unix: int | None
    revocation_generation: int
    ssh_public_key: SshPublicKey | None


class GithubRepository(TypedDict):
    """Allowlisted metadata, never provider JSON or a checkout grant."""

    repository_id: str
    full_name: str
    default_branch: str
    clone_url: str
    is_private: bool
    archived: bool
    disabled: bool


class GithubRepositoryPage(TypedDict):
    repositories: list[GithubRepository]
    next_page_token: str


class GithubPendingPermissions(TypedDict):
    """An installation that has not yet granted what Codewire needs."""

    account: str
    installation_id: int
    account_kind: Literal["user", "organization", "enterprise"]


_GITHUB_ACCOUNT_KINDS: dict[int, Literal["user", "organization", "enterprise"]] = {
    pb.GITHUB_APP_ACCOUNT_KIND_USER: "user",
    pb.GITHUB_APP_ACCOUNT_KIND_ORGANIZATION: "organization",
    pb.GITHUB_APP_ACCOUNT_KIND_ENTERPRISE: "enterprise",
}


class CodexDeviceChallenge(TypedDict):
    """The one-time code is for the requesting user, never routine logs."""

    verification_url: str
    user_code: str
    expires_at_unix: int


class CodexChallengeEvent(TypedDict):
    type: Literal["challenge"]
    challenge: CodexDeviceChallenge


class CodexCredentialEvent(TypedDict):
    type: Literal["credential"]
    credential: Credential


CodexEnrollmentEvent = CodexChallengeEvent | CodexCredentialEvent


class EnrollmentOutcomeUnknownError(RuntimeError):
    """Missing acknowledgement does not prove that storage did not occur."""

    def __init__(self):
        super().__init__(
            "Codex enrollment acknowledgement is unknown; reconcile the credential "
            "by name before retrying"
        )


# Bounded request admission/cleanup room around the server's original 15-minute
# enrollment. No ordinary call or generated-client default is changed.
_ENROLLMENT_TIMEOUT_MS = 16 * 60 * 1000


def _generation(value: int) -> int:
    if type(value) is not int or not 0 < value <= (1 << 64) - 1:
        raise ValueError("credential revision must be a positive uint64 integer")
    return value


def _credential(value: pb.Credential) -> Credential:
    kinds = {
        pb.CREDENTIAL_AUTHENTICATION_KIND_OAUTH: "oauth",
        pb.CREDENTIAL_AUTHENTICATION_KIND_API_KEY: "api_key",
        pb.CREDENTIAL_AUTHENTICATION_KIND_ACCESS_TOKEN: "access_token",
        pb.CREDENTIAL_AUTHENTICATION_KIND_GITHUB_APP: "github_app",
        pb.CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY: "ssh_key",
    }
    statuses = {
        pb.CREDENTIAL_STATUS_ACTIVE: "active", pb.CREDENTIAL_STATUS_REVOKED: "revoked",
        pb.CREDENTIAL_STATUS_EXPIRED: "expired", pb.CREDENTIAL_STATUS_REFRESH_FAILED: "refresh_failed",
    }
    if value.authentication_kind not in kinds or value.status not in statuses:
        raise RuntimeError("credential response contains unsupported metadata")
    if ((value.authentication_kind == pb.CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY)
            != value.HasField("ssh_public_key")):
        raise RuntimeError("credential response contains mismatched SSH public metadata")
    return {
        "id": value.id, "name": value.name, "provider": value.provider,
        "authentication_kind": kinds[value.authentication_kind],
        "account_hint": value.account_hint if value.HasField("account_hint") else None,
        "status": statuses[value.status],
        "expires_at_unix": value.expires_at_unix if value.HasField("expires_at_unix") else None,
        "revocation_generation": _generation(value.revocation_generation),
        "ssh_public_key": {
            "openssh": value.ssh_public_key.openssh,
            "fingerprint": value.ssh_public_key.fingerprint,
        } if value.HasField("ssh_public_key") else None,
    }


def _response_credential(response) -> Credential:
    if not response.HasField("credential"):
        raise RuntimeError("credential response omitted credential")
    return _credential(response.credential)


class Credentials:
    """Account-scoped credentials; supply a user OAuth bearer, not an org API key.

    Metadata permits account sessions; enrollment and lifecycle require OAuth.
    These methods never choose a delivery mode or retry a mutation.
    """

    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(CredentialServiceClientSync)
        self._mutations = context.transport.client(CredentialMutationServiceClientSync)
        self._repositories = context.transport.client(GithubRepositoryServiceClientSync)

    def list_github_repositories(
        self, *, page_size: int = 50, page_token: str = "",
    ) -> GithubRepositoryPage:
        """One page for the owner's current GitHub singleton, without attaching a profile."""
        if type(page_size) is not int or not 0 <= page_size <= 100 or len(page_token) > 128:
            raise ValueError("invalid GitHub repository selection or page")
        response = self._context.unary(self._repositories.list_github_repositories,
            pb.ListGithubRepositoriesRequest(
                page_size=page_size, page_token=page_token))
        return {"repositories": [{
            "repository_id": value.repository_id, "full_name": value.full_name,
            "default_branch": value.default_branch, "clone_url": value.clone_url,
            "is_private": value.is_private, "archived": value.archived, "disabled": value.disabled,
        } for value in response.repositories], "next_page_token": response.next_page_token}

    def list_github_pending_permissions(self) -> list[GithubPendingPermissions]:
        """Installations of the owner's GitHub App connection still short of what
        Codewire needs, checked live. Login, installation ID and kind only."""
        response = self._context.unary(self._repositories.list_github_pending_permissions,
            pb.ListGithubPendingPermissionsRequest())
        return [{"account": value.account, "installation_id": value.installation_id,
                 "account_kind": _GITHUB_ACCOUNT_KINDS[value.account_kind]}
                for value in response.pending_permissions if value.account_kind in _GITHUB_ACCOUNT_KINDS]

    def list(self) -> list[Credential]:
        result: list[Credential] = []
        seen: set[str] = set()
        page_token = ""
        while True:
            if page_token in seen:
                raise RuntimeError("credential pagination repeated a cursor")
            seen.add(page_token)
            response = self._context.unary(
                self._client.list_credentials, pb.ListCredentialsRequest(page_token=page_token))
            result.extend(_credential(value) for value in response.credentials)
            page_token = response.next_page_token
            if not page_token:
                return result

    def get(self, credential_id: str) -> Credential:
        return _response_credential(self._context.unary(
            self._client.get_credential, pb.GetCredentialRequest(credential_id=credential_id)))

    def get_by_name(self, name: str) -> Credential:
        """Exact case-insensitive owner-scoped name, never an inferred ID."""
        return _response_credential(self._context.unary(
            self._client.get_credential, pb.GetCredentialRequest(name=name)))

    def enroll_codex(self, name: str) -> Generator[CodexEnrollmentEvent, None, None]:
        """Yield the challenge immediately, then committed metadata.

        Close this iterator when leaving early (for example with
        ``contextlib.closing``); closing cancels the original stream. A pending
        synchronous read remains bounded by this call's 16-minute deadline.
        Cancellation does not prove rollback: reconcile by name before retrying.
        """
        stream = self._context.server_stream(
            self._mutations.enroll_codex, pb.EnrollCodexRequest(name=name),
            timeout_ms=_ENROLLMENT_TIMEOUT_MS,
        )
        challenged = False
        try:
            for response in stream:
                event = response.WhichOneof("event")
                if event == "challenge" and not challenged:
                    value = response.challenge
                    if not value.verification_url or not value.user_code or not value.expires_at_unix:
                        raise EnrollmentOutcomeUnknownError()
                    challenged = True
                    yield {"type": "challenge", "challenge": {
                        "verification_url": value.verification_url, "user_code": value.user_code,
                        "expires_at_unix": value.expires_at_unix,
                    }}
                elif event == "credential" and challenged:
                    yield {"type": "credential", "credential": _credential(response.credential)}
                    return
                else:
                    raise EnrollmentOutcomeUnknownError()
            raise EnrollmentOutcomeUnknownError()
        except Exception:
            # Do not retain provider output or confuse an HTTP/codec failure
            # with proof that COMMIT did not occur. GeneratorExit still closes.
            raise EnrollmentOutcomeUnknownError() from None
        finally:
            stream.close()

    def revoke(self, credential_id: str, expected_revocation_generation: int) -> Credential:
        return _response_credential(self._context.unary(
            self._mutations.revoke_credential, pb.RevokeCredentialRequest(
                credential_id=credential_id,
                expected_revocation_generation=_generation(expected_revocation_generation))))

    def delete(self, credential_id: str, expected_revocation_generation: int) -> None:
        """Forget an already-revoked, unreferenced record; not provider logout."""
        self._context.unary(self._mutations.delete_credential, pb.DeleteCredentialRequest(
            credential_id=credential_id,
            expected_revocation_generation=_generation(expected_revocation_generation)))

    def close(self) -> None:
        self._client.close()
        self._mutations.close()
