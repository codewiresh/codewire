from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.exec_body_env import ExecBodyEnv


T = TypeVar("T", bound="ExecBody")


@_attrs_define
class ExecBody:
    """
    Attributes:
        command (list[str] | None): Command and arguments to execute
        schema (str | Unset): A URL to the JSON Schema for this object.
        env (ExecBodyEnv | Unset): Environment variables
        timeout (int | Unset): Timeout in seconds (default: 600)
        working_dir (str | Unset): Working directory (default: /workspace)
    """

    command: list[str] | None
    schema: str | Unset = UNSET
    env: ExecBodyEnv | Unset = UNSET
    timeout: int | Unset = UNSET
    working_dir: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        command: list[str] | None
        if isinstance(self.command, list):
            command = self.command

        else:
            command = self.command

        schema = self.schema

        env: dict[str, Any] | Unset = UNSET
        if not isinstance(self.env, Unset):
            env = self.env.to_dict()

        timeout = self.timeout

        working_dir = self.working_dir

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "command": command,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if env is not UNSET:
            field_dict["env"] = env
        if timeout is not UNSET:
            field_dict["timeout"] = timeout
        if working_dir is not UNSET:
            field_dict["working_dir"] = working_dir

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.exec_body_env import ExecBodyEnv

        d = dict(src_dict)

        def _parse_command(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                command_type_0 = cast(list[str], data)

                return command_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        command = _parse_command(d.pop("command"))

        schema = d.pop("$schema", UNSET)

        _env = d.pop("env", UNSET)
        env: ExecBodyEnv | Unset
        if isinstance(_env, Unset):
            env = UNSET
        else:
            env = ExecBodyEnv.from_dict(_env)

        timeout = d.pop("timeout", UNSET)

        working_dir = d.pop("working_dir", UNSET)

        exec_body = cls(
            command=command,
            schema=schema,
            env=env,
            timeout=timeout,
            working_dir=working_dir,
        )

        return exec_body
