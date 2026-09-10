"""Material-free personal access profiles over the generated Connect service."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypedDict

from codewire._context import ConnectContext
from codewire.v1 import access_profile_pb2 as pb
from codewire.v1.access_profile_connect import AccessProfileServiceClientSync


class AccessProfileEntry(TypedDict):
    capability_slot: str
    credential_id: str


class AccessProfile(TypedDict):
    id: str
    name: str
    revision: int
    entries: list[AccessProfileEntry]


class EnvironmentAccessProfileBinding(TypedDict):
    """Exact selection, not an access grant or runtime-readiness proof."""

    environment_id: str
    access_profile_id: str
    access_profile_revision: int


class EnvironmentAccessProfile(TypedDict):
    binding: EnvironmentAccessProfileBinding | None
    personal_credentials_confirmed: bool


def _revision(value: int) -> int:
    # bool is an int subclass, but is not an explicit revision.
    if type(value) is not int or not 0 < value <= (1 << 64) - 1:
        raise ValueError("access profile revision must be a positive uint64 integer")
    return value


def _entries(entries: Sequence[AccessProfileEntry]) -> list[pb.AccessProfileEntry]:
    slots: set[str] = set()
    result = []
    for entry in entries:
        slot = entry["capability_slot"]
        if slot in slots:
            raise ValueError("duplicate access profile capability slot")
        slots.add(slot)
        result.append(pb.AccessProfileEntry(
            capability_slot=slot, credential_id=entry["credential_id"]
        ))
    return result


def _profile(value: pb.AccessProfile) -> AccessProfile:
    return {
        "id": value.id,
        "name": value.name,
        "revision": _revision(value.revision),
        "entries": [{"capability_slot": entry.capability_slot,
                     "credential_id": entry.credential_id} for entry in value.entries],
    }


def _binding(value: pb.EnvironmentAccessProfileBinding) -> EnvironmentAccessProfileBinding:
    return {
        "environment_id": value.environment_id,
        "access_profile_id": value.access_profile_id,
        "access_profile_revision": _revision(value.access_profile_revision),
    }


class AccessProfiles:
    """Authenticated-user profiles; organization API keys cannot manage these.

    Supply the existing user OAuth bearer to Codewire. These methods never read
    or upload provider material, infer consent, or fetch-and-retry a stale CAS.
    """

    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(AccessProfileServiceClientSync)

    def list(self) -> list[AccessProfile]:
        """Consume all pages using the server's default page size."""
        profiles: list[AccessProfile] = []
        page_token = ""
        while True:
            response = self._context.unary(
                self._client.list_access_profiles,
                pb.ListAccessProfilesRequest(page_token=page_token),
            )
            profiles.extend(_profile(value) for value in response.access_profiles)
            page_token = response.next_page_token
            if not page_token:
                return profiles

    def get(self, profile_id: str, *, revision: int | None = None) -> AccessProfile:
        """Omitted revision means current; supplied revision is exact."""
        request = pb.GetAccessProfileRequest(access_profile_id=profile_id)
        return self._get(request, revision)

    def get_by_name(self, name: str, *, revision: int | None = None) -> AccessProfile:
        return self._get(pb.GetAccessProfileRequest(name=name), revision)

    def _get(self, request: pb.GetAccessProfileRequest, revision: int | None) -> AccessProfile:
        if revision is not None:
            request.revision = _revision(revision)
        response = self._context.unary(self._client.get_access_profile, request)
        if not response.HasField("access_profile"):
            raise RuntimeError("access profile response omitted access_profile")
        return _profile(response.access_profile)

    def create(self, name: str, entries: Sequence[AccessProfileEntry]) -> AccessProfile:
        response = self._context.unary(
            self._client.create_access_profile,
            pb.CreateAccessProfileRequest(name=name, entries=_entries(entries)),
        )
        if not response.HasField("access_profile"):
            raise RuntimeError("access profile response omitted access_profile")
        return _profile(response.access_profile)

    def update(self, profile_id: str, expected_revision: int,
               entries: Sequence[AccessProfileEntry]) -> AccessProfile:
        """Replace the complete entry set, including an explicitly empty set."""
        response = self._context.unary(
            self._client.update_access_profile,
            pb.UpdateAccessProfileRequest(
                access_profile_id=profile_id,
                expected_revision=_revision(expected_revision), entries=_entries(entries),
            ),
        )
        if not response.HasField("access_profile"):
            raise RuntimeError("access profile response omitted access_profile")
        return _profile(response.access_profile)

    def delete(self, profile_id: str, expected_revision: int) -> None:
        self._context.unary(self._client.delete_access_profile,
                            pb.DeleteAccessProfileRequest(
                                access_profile_id=profile_id,
                                expected_revision=_revision(expected_revision)))

    def get_environment_binding(self, environment_id: str) -> EnvironmentAccessProfile:
        response = self._context.unary(
            self._client.get_environment_access_profile,
            pb.GetEnvironmentAccessProfileRequest(environment_id=environment_id),
        )
        return {
            "binding": _binding(response.binding) if response.HasField("binding") else None,
            "personal_credentials_confirmed": response.personal_credentials_confirmed,
        }

    def close(self) -> None:
        self._client.close()
