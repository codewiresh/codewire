"""Conversion from generated protobuf messages to the SDK's REST-era values."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from google.protobuf.descriptor import FieldDescriptor
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
    31: "ports", 32: "isolation_tier",
}

_CREATE_ENVIRONMENT_DESCRIPTOR_FIELDS = {
    1: "org_id", 2: "preset_id", 3: "name", 4: "cpu_millicores",
    5: "memory_mb", 6: "disk_gb", 7: "ttl_seconds", 8: "preset_slug",
    9: "repo_url", 10: "branch", 11: "repos", 12: "image",
    13: "install_command", 14: "startup_script", 15: "env_vars",
    16: "agents", 17: "install_agents", 18: "agent", 19: "agent_env",
    20: "secret_project", 21: "app_ports", 22: "include_org_secrets",
    23: "include_user_secrets", 24: "isolation_tier",
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

    _assert_descriptor_coverage(
        "environment", Environment.DESCRIPTOR, _ENVIRONMENT_DESCRIPTOR_FIELDS
    )
    _assert_descriptor_coverage(
        "create environment request",
        CreateEnvironmentRequest.DESCRIPTOR,
        _CREATE_ENVIRONMENT_DESCRIPTOR_FIELDS,
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


def preset_to_dict(message: Message) -> dict[str, Any]:
    """Render PresetService's nested setup config in the SDK's flat shape."""
    value = proto_to_dict(message)
    value["type"] = "sandbox"
    if message.HasField("default_setup_config"):
        setup = proto_to_dict(message.default_setup_config)
        value.update(setup)
        value.pop("default_setup_config", None)
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
        return proto_to_dict(value)
    if field.type == FieldDescriptor.TYPE_BYTES:
        return bytes(value)
    if field.type == FieldDescriptor.TYPE_ENUM:
        return field.enum_type.values_by_number[int(value)].name.lower()
    return value
