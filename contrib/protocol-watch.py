#!/usr/bin/env python3

import json
import sys
import time


def resolve_path(value, path):
    current = value
    for part in path.split("."):
        part = part.strip()
        if not part:
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: protocol-watch.py <descriptor>", file=sys.stderr)
        return 1

    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        descriptor = json.load(handle)

    turn_stream = descriptor["turn_stream"]
    events = {entry["method"]: entry for entry in turn_stream["events"]}
    method_field = turn_stream["method_field"]
    turn_id_field = turn_stream.get("turn_id_field", "")
    thread_id_field = turn_stream.get("thread_id_field", "")

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue

        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        method = resolve_path(event, method_field)
        if not isinstance(method, str):
            continue

        spec = events.get(method)
        if spec is None:
            continue

        out = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": method,
            "state": spec["state"],
        }

        turn_id = resolve_path(event, turn_id_field)
        if turn_id is not None:
            out["turn_id"] = turn_id

        thread_id = resolve_path(event, thread_id_field)
        if thread_id is not None:
            out["thread_id"] = thread_id

        kind = spec.get("kind")
        if kind:
            out["kind"] = kind

        token_usage_field = spec.get("token_usage_field")
        if token_usage_field:
            token_usage = resolve_path(event, token_usage_field)
            if token_usage is not None:
                out["token_usage"] = token_usage

        print(json.dumps(out), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
