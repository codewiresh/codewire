from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AuditLogEntry")


@_attrs_define
class AuditLogEntry:
    """
    Attributes:
        action (str):
        id (str):
        ip_address (None | str):
        severity (str):
        timestamp (str):
        user_agent (None | str):
        user_email (None | str):
        user_id (None | str):
        metadata (Any | Unset):
    """

    action: str
    id: str
    ip_address: None | str
    severity: str
    timestamp: str
    user_agent: None | str
    user_email: None | str
    user_id: None | str
    metadata: Any | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        action = self.action

        id = self.id

        ip_address: None | str
        ip_address = self.ip_address

        severity = self.severity

        timestamp = self.timestamp

        user_agent: None | str
        user_agent = self.user_agent

        user_email: None | str
        user_email = self.user_email

        user_id: None | str
        user_id = self.user_id

        metadata = self.metadata

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "action": action,
                "id": id,
                "ip_address": ip_address,
                "severity": severity,
                "timestamp": timestamp,
                "user_agent": user_agent,
                "user_email": user_email,
                "user_id": user_id,
            }
        )
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = d.pop("action")

        id = d.pop("id")

        def _parse_ip_address(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        ip_address = _parse_ip_address(d.pop("ip_address"))

        severity = d.pop("severity")

        timestamp = d.pop("timestamp")

        def _parse_user_agent(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_agent = _parse_user_agent(d.pop("user_agent"))

        def _parse_user_email(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_email = _parse_user_email(d.pop("user_email"))

        def _parse_user_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_id = _parse_user_id(d.pop("user_id"))

        metadata = d.pop("metadata", UNSET)

        audit_log_entry = cls(
            action=action,
            id=id,
            ip_address=ip_address,
            severity=severity,
            timestamp=timestamp,
            user_agent=user_agent,
            user_email=user_email,
            user_id=user_id,
            metadata=metadata,
        )

        return audit_log_entry
