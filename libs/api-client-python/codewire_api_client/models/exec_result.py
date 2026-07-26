from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExecResult")


@_attrs_define
class ExecResult:
    """
    Attributes:
        exit_code (int):
        stderr (str):
        stdout (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    exit_code: int
    stderr: str
    stdout: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        exit_code = self.exit_code

        stderr = self.stderr

        stdout = self.stdout

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "exit_code": exit_code,
                "stderr": stderr,
                "stdout": stdout,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        exit_code = d.pop("exit_code")

        stderr = d.pop("stderr")

        stdout = d.pop("stdout")

        schema = d.pop("$schema", UNSET)

        exec_result = cls(
            exit_code=exit_code,
            stderr=stderr,
            stdout=stdout,
            schema=schema,
        )

        return exec_result
