#!/usr/bin/env python3
"""Run one bounded OpenAI Responses request and emit only a fixed receipt."""

from __future__ import annotations

import http.client
import json
import math
import os
import re
import resource
import sys
from typing import Any


EXPECTED_BASE_URL = "http://127.0.0.1:38081/_codewire/openai/v1"
EXPECTED_API_KEY = "codewire-managed"
RESPONSE_PATH = "/_codewire/openai/v1/responses"
PROMPT = "Reply with exactly CW_LIVE_OPENAI_OK"
MARKER = "CW_LIVE_OPENAI_OK"
ERROR_MARKER = "CW_LIVE_OPENAI_ERROR"
MAX_RESPONSE_BYTES = 262_144
READ_CHUNK_BYTES = 65_536
SOCKET_TIMEOUT_SECONDS = 100
MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
JSON_CONTENT_TYPE = re.compile(
    r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?[ \t]*',
    re.IGNORECASE | re.ASCII,
)


class InvalidResponse(ValueError):
    pass


def disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise InvalidResponse("core limit was not applied")


def validate_inputs(argv: list[str]) -> str:
    if len(argv) != 2 or MODEL_PATTERN.fullmatch(argv[1]) is None:
        raise InvalidResponse("invalid model")
    if (os.environ.get("OPENAI_BASE_URL") != EXPECTED_BASE_URL
            or os.environ.get("OPENAI_API_KEY") != EXPECTED_API_KEY):
        raise InvalidResponse("invalid generated projection")
    return argv[1]


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidResponse("duplicate JSON field")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise InvalidResponse(f"non-finite JSON number: {value}")


def require_finite_numbers(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidResponse("non-finite JSON number")
    if isinstance(value, dict):
        for child in value.values():
            require_finite_numbers(child)
    elif isinstance(value, list):
        for child in value:
            require_finite_numbers(child)


def decode_json(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise InvalidResponse("invalid JSON response") from error
    if not isinstance(parsed, dict):
        raise InvalidResponse("response is not an object")
    require_finite_numbers(parsed)
    return parsed


def validate_headers(response: http.client.HTTPResponse) -> int | None:
    headers: dict[str, list[str]] = {}
    for name, value in response.getheaders():
        headers.setdefault(name.lower(), []).append(value)
    if response.status != 200:
        raise InvalidResponse("unexpected status")
    content_types = headers.get("content-type", [])
    if len(content_types) != 1 or JSON_CONTENT_TYPE.fullmatch(content_types[0]) is None:
        raise InvalidResponse("unexpected content type")
    if headers.get("content-encoding") or headers.get("x-error-json"):
        raise InvalidResponse("opaque response metadata")
    lengths = headers.get("content-length", [])
    if len(lengths) > 1:
        raise InvalidResponse("ambiguous content length")
    if not lengths:
        return None
    if re.fullmatch(r"0|[1-9][0-9]*", lengths[0], re.ASCII) is None:
        raise InvalidResponse("invalid content length")
    length = int(lengths[0])
    if length > MAX_RESPONSE_BYTES:
        raise InvalidResponse("response is oversized")
    return length


def read_bounded(response: http.client.HTTPResponse, expected_length: int | None) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while not response.isclosed():
        chunk = response.read(min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise InvalidResponse("response is oversized")
    payload = b"".join(chunks)
    if expected_length is not None and len(payload) != expected_length:
        raise InvalidResponse("response ended early")
    if not response.isclosed():
        raise InvalidResponse("response did not reach EOF")
    return payload


def validate_response(response: dict[str, Any], model: str) -> None:
    response_id = response.get("id")
    if (not isinstance(response_id, str) or not response_id
            or response.get("object") != "response" or response.get("status") != "completed"
            or "error" not in response or response["error"] is not None
            or "incomplete_details" not in response or response["incomplete_details"] is not None
            or response.get("model") != model):
        raise InvalidResponse("response metadata is invalid")
    output = response.get("output")
    if not isinstance(output, list):
        raise InvalidResponse("response output is invalid")
    messages = 0
    reasoning_items = 0
    for item in output:
        if not isinstance(item, dict):
            raise InvalidResponse("output item is invalid")
        item_type = item.get("type")
        if item_type == "reasoning":
            reasoning_items += 1
            if (reasoning_items != 1 or "content" in item
                    or any("tool" in key or "call" in key or "refusal" in key for key in item)):
                raise InvalidResponse("reasoning item contains content or tool activity")
            continue
        if item_type != "message":
            raise InvalidResponse("unknown or tool output")
        messages += 1
        content = item.get("content")
        if (messages != 1 or item.get("status") != "completed" or item.get("role") != "assistant"
                or any("tool" in key or "call" in key or "refusal" in key for key in item)
                or not isinstance(content, list) or len(content) != 1):
            raise InvalidResponse("assistant message is invalid")
        part = content[0]
        if (not isinstance(part, dict) or part.get("type") != "output_text"
                or part.get("text") != MARKER
                or part.get("annotations") != []
                or any("tool" in key or "call" in key or "refusal" in key for key in part)):
            raise InvalidResponse("assistant output marker is invalid")
    if messages != 1:
        raise InvalidResponse("completed assistant message is absent")


def request(model: str) -> None:
    body = json.dumps(
        {
            "model": model,
            "input": PROMPT,
            "stream": False,
            "background": False,
            "store": False,
            "tools": [],
            "tool_choice": "none",
            "max_output_tokens": 256,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    connection = http.client.HTTPConnection(
        "127.0.0.1", 38_081, timeout=SOCKET_TIMEOUT_SECONDS,
    )
    response: http.client.HTTPResponse | None = None
    try:
        connection.request(
            "POST",
            RESPONSE_PATH,
            body=body,
            headers={
                "Authorization": f"Bearer {EXPECTED_API_KEY}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        expected_length = validate_headers(response)
        payload = read_bounded(response, expected_length)
        validate_response(decode_json(payload), model)
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            connection.close()


def main(argv: list[str]) -> int:
    try:
        disable_core_dumps()
        model = validate_inputs(argv)
        request(model)
    except BaseException:
        sys.stderr.write(ERROR_MARKER + "\n")
        return 1
    sys.stdout.write(MARKER + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
