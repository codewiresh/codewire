#!/usr/bin/env python3
"""Validate the bounded public subset of Claude stream JSON without printing it."""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import Any


MAX_CAPTURE_BYTES = 1024 * 1024
EXPECTED_MODEL = "claude-sonnet-4-6"
EXPECTED_MESSAGE = "CW_LIVE_CLAUDE_OK"
# The pinned client's one notice for a non-Anthropic base URL, such as the
# managed loopback route: auto-mode classifier requests stay billed.
GATEWAY_NOTICE = "We're changing auto mode to no longer charge for classifier requests in Claude Code."


class InvalidOutput(ValueError):
    pass


def exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidOutput("duplicate JSON field")
        result[key] = value
    return result


def load_frames(path: str) -> list[dict[str, Any]]:
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
    frames: list[dict[str, Any]] = []
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n") or line in ("\n", "\r\n"):
            raise InvalidOutput("capture contains an incomplete or blank record")
        try:
            frame = json.loads(line, object_pairs_hook=unique_object)
        except (json.JSONDecodeError, InvalidOutput, RecursionError) as error:
            raise InvalidOutput("capture contains invalid JSON") from error
        if not isinstance(frame, dict):
            raise InvalidOutput("stream frame is not an object")
        frames.append(frame)
    return frames


def validate(frames: list[dict[str, Any]]) -> None:
    initialized = False
    requesting = False
    noticed = False
    stream_state = 0
    streamed_text = ""
    assistant = False
    completed = False

    for frame in frames:
        if completed:
            raise InvalidOutput("stream continued after its terminal result")
        kind = frame.get("type")
        if kind == "system":
            subtype = frame.get("subtype")
            if subtype == "init":
                if initialized or stream_state != 0:
                    raise InvalidOutput("invalid Claude initialization")
                initialized = True
            elif subtype == "status":
                if not initialized or requesting or stream_state != 0 or frame.get("status") != "requesting":
                    raise InvalidOutput("invalid Claude request status")
                requesting = True
            elif subtype == "informational":
                # Informational only; it never substitutes for a required frame.
                content = frame.get("content")
                if (not initialized or noticed or frame.get("level") != "warning"
                        or not isinstance(content, str) or not content.startswith(GATEWAY_NOTICE)):
                    raise InvalidOutput("invalid Claude notice")
                noticed = True
            else:
                raise InvalidOutput("unknown Claude system frame")
        elif kind == "rate_limit_event":
            if not initialized:
                raise InvalidOutput("rate limit event preceded initialization")
        elif kind == "stream_event":
            if not initialized or not isinstance(frame.get("event"), dict):
                raise InvalidOutput("invalid Claude stream event")
            event = frame["event"]
            event_kind = event.get("type")
            if stream_state == 0 and event_kind == "message_start":
                message = event.get("message")
                if not isinstance(message, dict) or message.get("role") != "assistant" or message.get("model") != EXPECTED_MODEL:
                    raise InvalidOutput("invalid Claude message start")
                stream_state = 1
            elif stream_state == 1 and event_kind == "content_block_start":
                if (not exact_int(event.get("index"), 0)
                        or event.get("content_block") != {"type": "text", "text": ""}):
                    raise InvalidOutput("invalid Claude content start")
                stream_state = 2
            elif stream_state == 2 and event_kind == "content_block_delta":
                delta = event.get("delta")
                if (assistant or not exact_int(event.get("index"), 0)
                        or not isinstance(delta, dict) or delta.get("type") != "text_delta"
                        or not isinstance(delta.get("text"), str)):
                    raise InvalidOutput("invalid Claude content delta")
                if len(streamed_text) + len(delta["text"]) > len(EXPECTED_MESSAGE):
                    raise InvalidOutput("Claude response exceeded its expected marker")
                streamed_text += delta["text"]
            elif stream_state == 2 and event_kind == "content_block_stop":
                if not exact_int(event.get("index"), 0) or streamed_text != EXPECTED_MESSAGE:
                    raise InvalidOutput("Claude content ended without the expected marker")
                stream_state = 3
            elif stream_state == 3 and event_kind == "message_delta":
                delta = event.get("delta")
                if not isinstance(delta, dict) or delta.get("stop_reason") != "end_turn":
                    raise InvalidOutput("Claude message did not end its turn")
                stream_state = 4
            elif stream_state == 4 and event_kind == "message_stop":
                stream_state = 5
            else:
                raise InvalidOutput("unexpected Claude stream transition")
        elif kind == "assistant":
            message = frame.get("message")
            if (not initialized or assistant or stream_state < 2 or streamed_text != EXPECTED_MESSAGE
                    or not isinstance(message, dict) or message.get("role") != "assistant"
                    or message.get("content") != [{"type": "text", "text": EXPECTED_MESSAGE}]):
                raise InvalidOutput("invalid assembled Claude response")
            assistant = True
        elif kind == "result":
            if (not initialized or not assistant or stream_state != 5
                    or frame.get("subtype") != "success" or frame.get("is_error") is not False
                    or not exact_int(frame.get("num_turns"), 1)
                    or frame.get("result") != EXPECTED_MESSAGE):
                raise InvalidOutput("invalid terminal Claude result")
            completed = True
        else:
            raise InvalidOutput("unknown Claude stream frame")

    if not completed:
        raise InvalidOutput("Claude stream did not complete")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    try:
        validate(load_frames(argv[1]))
    except (InvalidOutput, OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
