"""Conversion from generated protobuf messages to SDK-owned public values."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import ParseDict
from google.protobuf.message import Message
from google.protobuf.timestamp_pb2 import Timestamp


_ENVIRONMENT_DESCRIPTOR_FIELDS = {
    1: "id", 2: "org_id", 3: "created_by", 4: "preset_id", 5: "type",
    6: "name", 7: "state", 8: "desired_state", 9: "error_reason",
    10: "recoverable", 11: "state_changed_at", 12: "retry_count",
    13: "setup_phase", 14: "setup_complete", 15: "setup_error",
    16: "ttl_seconds", 17: "shutdown_at", 18: "cpu_millicores",
    19: "memory_mb", 20: "disk_gb", 21: "total_running_seconds",
    22: "created_at", 23: "started_at", 24: "stopped_at",
    25: "destroyed_at", 26: "protected", 27: "deletion_requested_at",
    28: "deletion_grace_until", 29: "preset_name", 30: "network",
    31: "ports", 32: "isolation_tier", 33: "operation_generation",
    34: "source_selection",
}

_CREATE_ENVIRONMENT_DESCRIPTOR_FIELDS = {
    1: "org_id", 2: "preset_id", 3: "name", 7: "ttl_seconds",
    24: "isolation_tier", 25: "project_spec", 26: "expected_profile_revision",
    27: "confirm_personal_credentials", 28: "confirm_personal_secrets",
    29: "omit_application_previews",
}

_SOURCE_DESCRIPTOR_FIELDS = {
    "EnvironmentSourceSelection": {
        1: "secrets", 2: "credentials", 3: "profile_revision",
    },
    "UpdateEnvironmentSourcesRequest": {
        1: "org_id", 2: "environment_id", 3: "expected_operation_generation",
        4: "expected", 5: "replacement", 6: "allow_restart",
        7: "confirm_personal_credentials", 8: "confirm_personal_secrets",
    },
    "UpdateEnvironmentSourcesResponse": {
        1: "environment_id", 2: "operation_generation", 3: "selection", 4: "outcome",
    },
}

_PRESET_DESCRIPTOR_FIELDS = {
    1: "id", 2: "org_id", 3: "name", 4: "slug", 5: "language",
    6: "official", 7: "description", 8: "build_status", 9: "build_error",
    13: "default_ttl_seconds", 17: "created_at", 18: "project_spec",
}

_CREATE_PRESET_DESCRIPTOR_FIELDS = {
    1: "org_id", 2: "name", 3: "slug", 4: "description",
    8: "default_ttl_seconds", 21: "project_spec",
}

_UPDATE_PRESET_DESCRIPTOR_FIELDS = {
    1: "org_id", 2: "preset_id", 3: "name", 4: "description", 5: "slug",
    9: "default_ttl_seconds", 22: "project_spec",
}

_PROJECT_DESCRIPTOR_FIELDS = {
    "RepositorySpec": {
        1: "source", 2: "branch", 3: "destination", 4: "revision", 5: "known_hosts",
    },
    "ApplicationPort": {1: "port", 2: "label", 3: "access"},
    "ProjectAgents": {1: "install", 2: "tools"},
    "ProjectSkillSelection": {1: "source", 2: "reference", 3: "agents"},
    "ProjectResources": {1: "cpu_millicores", 2: "memory_mib", 3: "disk_gib"},
    "ProjectSecretBindings": {1: "project", 4: "organization", 6: "user"},
    "ProjectCredentialBinding": {1: "profile"},
    "ProjectSpec": {
        1: "schema_version", 2: "preset", 3: "image", 4: "repositories",
        5: "working_directory", 6: "install_command", 7: "startup_script",
        8: "environment", 9: "agents", 11: "skills",
        12: "application_ports", 13: "resources", 14: "secrets", 18: "credentials",
    },
}


def timestamp_string(value: Timestamp) -> str:
    """Render a protobuf timestamp in the SDK's existing second-precision form."""
    return datetime.fromtimestamp(value.seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def proto_to_dict(message: Message) -> dict[str, Any]:
    """Convert a protobuf message without proto-JSON's lossy value coercions."""
    values: dict[str, Any] = {}
    for field in message.DESCRIPTOR.fields:
        value = getattr(message, field.name)
        if field.is_repeated:
            values[field.name] = _repeated_value(field, value)
        elif field.has_presence and not message.HasField(field.name):
            continue
        else:
            values[field.name] = _field_value(field, value)
    return values


def api_key_to_dict(message: Message) -> dict[str, Any]:
    """Render ``codewire.v1.ApiKey`` exactly like the REST API resource."""
    value = proto_to_dict(message)
    for field in ("created_by_name", "created_by_email"):
        if not value.get(field):
            value.pop(field, None)
    return value


def environment_to_dict(message: Message) -> dict[str, Any]:
    """Render an environment with REST's state and port-access spellings."""
    assert_environment_converter_coverage()
    value = proto_to_dict(message)
    if message.HasField("source_selection"):
        value["source_selection"] = environment_source_selection_to_dict(message.source_selection)
    value["state"] = _enum_suffix(message, "state", "ENVIRONMENT_STATE_")
    value["desired_state"] = _enum_suffix(
        message, "desired_state", "DESIRED_STATE_"
    )
    isolation_tier = _enum_suffix(message, "isolation_tier", "ISOLATION_TIER_")
    value["isolation_tier"] = (
        "standard" if isolation_tier in ("unspecified", "standard") else isolation_tier
    )
    value["ports"] = [port_to_dict(port) for port in message.ports]
    return value


def assert_environment_converter_coverage() -> None:
    """Fail when either owned environment adapter drifts from protobuf."""
    from codewire.v1.environment_pb2 import CreateEnvironmentRequest, Environment

    assert_project_spec_converter_coverage()

    _assert_descriptor_coverage(
        "environment", Environment.DESCRIPTOR, _ENVIRONMENT_DESCRIPTOR_FIELDS
    )
    _assert_descriptor_coverage(
        "create environment request",
        CreateEnvironmentRequest.DESCRIPTOR,
        _CREATE_ENVIRONMENT_DESCRIPTOR_FIELDS,
    )
    from codewire.v1 import environment_pb2

    for message_name, expected in _SOURCE_DESCRIPTOR_FIELDS.items():
        _assert_descriptor_coverage(
            message_name, getattr(environment_pb2, message_name).DESCRIPTOR, expected
        )


def assert_project_spec_converter_coverage() -> None:
    """Fail when canonical project intent gains an unmapped field."""
    from codewire.v1 import common_pb2

    for message_name, expected in _PROJECT_DESCRIPTOR_FIELDS.items():
        _assert_descriptor_coverage(
            f"project {message_name}",
            getattr(common_pb2, message_name).DESCRIPTOR,
            expected,
        )


def assert_preset_converter_coverage() -> None:
    """Fail when a preset resource or mutation gains an unmapped field."""
    from codewire.v1.preset_pb2 import (
        CreatePresetRequest,
        Preset,
        UpdatePresetRequest,
    )

    assert_project_spec_converter_coverage()
    _assert_descriptor_coverage("preset", Preset.DESCRIPTOR, _PRESET_DESCRIPTOR_FIELDS)
    _assert_descriptor_coverage(
        "create preset request",
        CreatePresetRequest.DESCRIPTOR,
        _CREATE_PRESET_DESCRIPTOR_FIELDS,
    )
    _assert_descriptor_coverage(
        "update preset request",
        UpdatePresetRequest.DESCRIPTOR,
        _UPDATE_PRESET_DESCRIPTOR_FIELDS,
    )


def _assert_descriptor_coverage(name: str, descriptor: Any, expected: dict[int, str]) -> None:
    fields = descriptor.fields
    if len(fields) != len(expected):
        raise RuntimeError(
            f"codewire: {name} converter covers {len(expected)} descriptor fields, "
            f"expected {len(fields)}"
        )
    for field in fields:
        if expected.get(field.number) != field.name:
            raise RuntimeError(
                f"codewire: {name} converter does not cover descriptor field "
                f"{field.full_name}"
            )


def environment_resize_operation_to_dict(message: Message) -> dict[str, Any]:
    """Render a durable resize operation with the public short state value."""
    value = proto_to_dict(message)
    value["state"] = _enum_suffix(
        message, "state", "ENVIRONMENT_RESIZE_OPERATION_STATE_"
    )
    value["disruption_policy"] = _enum_suffix(
        message, "disruption_policy", "ENVIRONMENT_RESIZE_DISRUPTION_POLICY_"
    )
    value["planned_mode"] = _enum_suffix(
        message, "planned_mode", "ENVIRONMENT_RESIZE_EXECUTION_MODE_"
    )
    value["applied_mode"] = _enum_suffix(
        message, "applied_mode", "ENVIRONMENT_RESIZE_EXECUTION_MODE_"
    )
    return value


def environment_resize_plan_to_dict(message: Message) -> dict[str, Any]:
    """Render an authoritative resize plan with its short execution mode."""
    value = proto_to_dict(message)
    value["execution_mode"] = _enum_suffix(
        message, "execution_mode", "ENVIRONMENT_RESIZE_EXECUTION_MODE_"
    )
    return value


def port_to_dict(message: Message) -> dict[str, Any]:
    """Render a port with REST's short access value."""
    value = proto_to_dict(message)
    value["access"] = _enum_suffix(message, "access", "PORT_ACCESS_")
    return value


def file_entry_to_dict(message: Message) -> dict[str, Any]:
    """Render FileService metadata in the historical REST value shape."""
    value = proto_to_dict(message)
    value["mode"] = f"{message.mode & 0o777:04o}"
    if not message.mod_time.seconds and not message.mod_time.nanos:
        value["mod_time"] = ""
    return value


def project_spec_from_dict(value: dict[str, Any]) -> Message:
    """Encode the SDK's short enum spellings into canonical project intent."""
    from codewire.v1.common_pb2 import ProjectSpec

    assert_project_spec_converter_coverage()
    payload = deepcopy(value)
    _prepare_secret_placement(payload)
    for skill in payload.get("skills", []):
        source = skill.get("source")
        if source not in ("repository", "user"):
            raise ValueError("codewire: project skill source must be repository or user")
        skill["source"] = f"PROJECT_SKILL_SOURCE_{source.upper()}"
    return ParseDict(payload, ProjectSpec())


def _prepare_secret_placement(payload: dict[str, Any]) -> None:
    secrets = payload.get("secrets")
    if secrets is not None and "user" in secrets:
        placement = secrets["user"]
        if type(placement) is not str or placement not in ("local", "platform"):
            raise ValueError("codewire: personal secret placement must be local or platform")
        secrets["user"] = f"PROJECT_STORAGE_PLACEMENT_{placement.upper()}"


def positive_uint64(value: int, name: str) -> int:
    if type(value) is not int or not 0 < value <= (1 << 64) - 1:
        raise ValueError(f"codewire: {name} must be a positive uint64 integer")
    return value


def explicit_bool(value: bool, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"codewire: {name} must be an explicit boolean")
    return value


def environment_source_selection_from_dict(value: dict[str, Any]) -> Message:
    """Preserve complete selections, including explicitly empty replacements."""
    from codewire.v1.environment_pb2 import EnvironmentSourceSelection

    assert_environment_converter_coverage()
    if type(value) is not dict:
        raise ValueError("codewire: source selection must be an explicit object")
    payload = deepcopy(value)
    _prepare_secret_placement(payload)
    has_profile = payload.get("credentials") is not None
    has_revision = payload.get("profile_revision") is not None
    if has_profile != has_revision:
        raise ValueError("codewire: profile selection requires its exact revision")
    if has_revision:
        payload["profile_revision"] = positive_uint64(
            payload["profile_revision"], "profile revision"
        )
    return ParseDict(payload, EnvironmentSourceSelection())


def environment_sources_update_to_dict(message: Message) -> dict[str, Any]:
    """Render the server's source-update result without inventing readiness."""
    assert_environment_converter_coverage()
    if not message.HasField("selection"):
        raise RuntimeError("source update response omitted selection")
    if message.outcome not in (1, 2, 3):
        raise RuntimeError("source update response omitted a recognized outcome")
    positive_uint64(message.operation_generation, "operation generation")
    value = proto_to_dict(message)
    value["selection"] = environment_source_selection_to_dict(message.selection)
    value["outcome"] = _enum_suffix(
        message, "outcome", "ENVIRONMENT_SOURCES_UPDATE_OUTCOME_"
    )
    return value


def environment_source_selection_to_dict(message: Message) -> dict[str, Any]:
    """Reject partial observed selections instead of returning unusable CAS state."""
    if message.HasField("credentials") != message.HasField("profile_revision"):
        raise RuntimeError("source selection requires its exact profile revision")
    if message.HasField("profile_revision"):
        positive_uint64(message.profile_revision, "profile revision")
    return proto_to_dict(message)


def project_spec_to_dict(message: Message) -> dict[str, Any]:
    """Render canonical project intent with the SDK's short enum spellings."""
    assert_project_spec_converter_coverage()
    value = proto_to_dict(message)
    for skill in value["skills"]:
        source = skill["source"]
        skill["source"] = source.removeprefix("project_skill_source_")
    return value


def preset_to_dict(message: Message) -> dict[str, Any]:
    """Render a preset with ProjectSpec as its sole workload configuration."""
    assert_preset_converter_coverage()
    if not message.HasField("project_spec"):
        raise RuntimeError("preset response omitted project_spec")
    value = proto_to_dict(message)
    value["project_spec"] = project_spec_to_dict(message.project_spec)
    return value


def _enum_suffix(message: Message, field_name: str, prefix: str) -> str:
    field = message.DESCRIPTOR.fields_by_name[field_name]
    name = field.enum_type.values_by_number[int(getattr(message, field_name))].name
    return name.removeprefix(prefix).lower()


def _repeated_value(field: FieldDescriptor, value: Any) -> Any:
    if field.message_type is not None and field.message_type.GetOptions().map_entry:
        value_field = field.message_type.fields_by_name["value"]
        return {
            key: _field_value(value_field, item)
            for key, item in value.items()
        }
    return [_field_value(field, item) for item in value]


def _field_value(field: FieldDescriptor, value: Any) -> Any:
    if field.type == FieldDescriptor.TYPE_MESSAGE:
        if field.message_type is not None and field.message_type.full_name == (
            "google.protobuf.Timestamp"
        ):
            return timestamp_string(value)
        converted = proto_to_dict(value)
        if field.message_type is not None and field.message_type.full_name == (
            "codewire.v1.RepositorySpec"
        ):
            if not converted.get("revision"):
                converted.pop("revision", None)
        return converted
    if field.type == FieldDescriptor.TYPE_BYTES:
        return bytes(value)
    if field.type == FieldDescriptor.TYPE_ENUM:
        if field.enum_type.full_name == "codewire.v1.ProjectStoragePlacement":
            if value not in (1, 2):
                raise ValueError("codewire: personal secret placement must be local or platform")
            return "local" if value == 1 else "platform"
        return field.enum_type.values_by_number[int(value)].name.lower()
    return value
