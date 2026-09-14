#!/usr/bin/env python3
"""Validate the bounded public subset of Codex exec JSONL without printing it."""

from __future__ import annotations

import json
import os
import stat
import sys
import uuid
from typing import Any


MAX_CAPTURE_BYTES = 1024 * 1024
EXPECTED_MESSAGE = "CW_LIVE_CODEX_OK"
USAGE_KEYS = {
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
}


class InvalidOutput(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidOutput("duplicate JSON field")
        result[key] = value
    return result


def exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 256 and "\x00" not in value


def valid_thread_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def valid_usage(value: Any) -> bool:
    return exact_keys(value, USAGE_KEYS) and all(
        isinstance(value[key], int) and not isinstance(value[key], bool) and value[key] >= 0
        for key in USAGE_KEYS
    )


def load_events(path: str) -> list[dict[str, Any]]:
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size >= MAX_CAPTURE_BYTES:
        raise InvalidOutput("capture is absent, incomplete, or oversized")
    with open(path, "rb") as stream:
        payload = stream.read(MAX_CAPTURE_BYTES)
    if len(payload) != info.st_size or not payload.endswith(b"\n") or b"\x00" in payload:
        raise InvalidOutput("capture is truncated")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidOutput("capture is not UTF-8") from error
    events: list[dict[str, Any]] = []
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n") or line in ("\n", "\r\n"):
            raise InvalidOutput("capture contains an incomplete or blank record")
        try:
            value = json.loads(line, object_pairs_hook=unique_object)
        except (json.JSONDecodeError, InvalidOutput, RecursionError) as error:
            raise InvalidOutput("capture contains invalid JSON") from error
        if not isinstance(value, dict):
            raise InvalidOutput("event is not an object")
        events.append(value)
    return events


def validate(events: list[dict[str, Any]]) -> None:
    if len(events) < 4:
        raise InvalidOutput("lifecycle is incomplete")
    first = events[0]
    if not exact_keys(first, {"type", "thread_id"}) or first["type"] != "thread.started":
        raise InvalidOutput("thread did not start exactly once")
    if not valid_thread_id(first["thread_id"]):
        raise InvalidOutput("thread identifier is invalid")
    if events[1] != {"type": "turn.started"}:
        raise InvalidOutput("turn did not start exactly once")

    seen_ids: set[str] = set()
    agent_messages = 0
    for event in events[2:-1]:
        if not exact_keys(event, {"type", "item"}) or event["type"] != "item.completed":
            raise InvalidOutput("unexpected lifecycle or active item")
        item = event["item"]
        if not exact_keys(item, {"id", "type", "text"}) or not valid_identifier(item["id"]):
            raise InvalidOutput("completed item has an invalid shape")
        if item["id"] in seen_ids:
            raise InvalidOutput("completed item identifier was reused")
        seen_ids.add(item["id"])
        if item["type"] == "reasoning":
            if agent_messages or not isinstance(item["text"], str) or not item["text"].strip():
                raise InvalidOutput("reasoning lifecycle is out of order")
        elif item["type"] == "agent_message":
            agent_messages += 1
            if agent_messages != 1 or item["text"] != EXPECTED_MESSAGE:
                raise InvalidOutput("final message differs")
        else:
            # This rejects error, command, file, web, MCP, collaboration and
            # todo events even when Codex reports them as completed.
            raise InvalidOutput("tool, file, or error event is forbidden")

    if agent_messages != 1:
        raise InvalidOutput("exactly one final message is required")
    final = events[-1]
    if (
        not exact_keys(final, {"type", "usage"})
        or final["type"] != "turn.completed"
        or not valid_usage(final["usage"])
    ):
        raise InvalidOutput("turn did not complete successfully")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    try:
        validate(load_events(argv[1]))
    except (InvalidOutput, OSError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
