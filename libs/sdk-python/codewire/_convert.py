"""Conversion from generated protobuf messages to the SDK's REST-era values."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import Message
from google.protobuf.timestamp_pb2 import Timestamp


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
    value = proto_to_dict(message)
    value["state"] = _enum_suffix(message, "state", "ENVIRONMENT_STATE_")
    value["desired_state"] = _enum_suffix(
        message, "desired_state", "DESIRED_STATE_"
    )
    value["ports"] = [port_to_dict(port) for port in message.ports]
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
