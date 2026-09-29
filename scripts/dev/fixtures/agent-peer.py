#!/usr/bin/env python3
"""Synthetic native peers for the real cw managed-session acceptance journey.

No provider calls, login files, or repository mutations. Protocol ordering and
failures are deliberately independent of the Rust adapter implementation.
"""
import json
import os
from pathlib import Path
import sys
import uuid


def emit(value):
    print(json.dumps(value), flush=True)


claude = Path(sys.argv[0]).name == "claude"
thread = str(uuid.uuid4())
session = next((sys.argv[i + 1] for i, value in enumerate(sys.argv[:-1])
                if value in ("--session-id", "--resume")), str(uuid.uuid4()))
active = None
model = next((sys.argv[i + 1] for i, value in enumerate(sys.argv[:-1])
              if value == "--model"), None)


def trace(method):
    identity = session if claude else thread
    with Path(f"peer-{identity}.jsonl").open("a") as file:
        file.write(json.dumps({"method": method}) + "\n")


def complete(text, status="completed"):
    global active
    if claude:
        trace(value["type"])
        emit({"type": "result", "session_id": session,
              "subtype": "success" if status == "completed" else "error_during_execution",
              "is_error": status != "completed", "result": text, "usage": {"output_tokens": 1}})
    else:
        if text:
            emit({"method": "item/completed", "params": {"threadId": thread,
                  "turnId": active, "item": {"type": "agentMessage", "text": text}}})
        emit({"method": "turn/completed", "params": {"threadId": thread,
              "turn": {"id": active, "status": status}}})
    active = None


for line in sys.stdin:
    value = json.loads(line)
    if claude:
        if value["type"] == "control_request":
            subtype = value["request"]["subtype"]
            emit({"type": "control_response", "response": {"subtype": "success",
                  "request_id": value["request_id"], "response": {}}})
            if subtype == "interrupt" and active:
                complete("", "interrupted")
        elif value["type"] == "user":
            emit({"type": "system", "subtype": "init", "session_id": session})
            emit({**value, "session_id": session, "isReplay": True})
            text = value["message"]["content"]
            active = str(uuid.uuid4())
            if text != "HOLD":
                complete("PARENT_RECEIVED" if "[Codewire] Managed worker" in text else "RESULT:" + text)
        continue
    method = value.get("method")
    params = value.get("params", {})
    if method in ("initialize", "thread/start", "thread/resume"):
        if method == "thread/start" and params.get("model") == "fixture-startup-failure":
            emit({"id": value["id"], "error": {"code": -32000, "message": "synthetic startup failure"}})
            continue
        if method == "thread/resume":
            thread = params["threadId"]
        trace(method)
        emit({"id": value["id"], "result": {"thread": {"id": thread}}})
    elif method == "turn/start":
        trace(method)
        active = str(uuid.uuid4())
        emit({"id": value["id"], "result": {"turn": {"id": active, "status": "inProgress"}}})
        emit({"method": "turn/started", "params": {"threadId": thread,
              "turn": {"id": active, "status": "inProgress"}}})
        text = params["input"][0]["text"]
        if text != "HOLD":
            complete("PARENT_RECEIVED" if "[Codewire] Managed worker" in text else "RESULT:" + text)
    elif method == "turn/steer":
        if params["expectedTurnId"] != active:
            emit({"id": value["id"], "error": {"code": -32000, "message": "expected turn mismatch"}})
        else:
            emit({"id": value["id"], "result": {"turnId": active}})
            complete("STEERED")
    elif method == "turn/interrupt":
        emit({"id": value["id"], "result": {}})
        if active:
            complete("", "interrupted")
