#!/usr/bin/env python3
"""Synthetic native peers for the real cw managed-session acceptance journey.

No provider calls, login files, or repository mutations. Protocol ordering and
failures are deliberately independent of the Rust adapter implementation.
Every start appends the conversation identity and the arguments the peer was
given to agent-identity.jsonl in its working directory.

The Codex peer traces each turn's effort, and answers two prompts as Codex
0.160.0 reports a provider refusal (#2982): REFUSE_MODEL as a project without
access to the model, retrying until the turn is interrupted, and REFUSE_EFFORT
as a model that does not support the effort.
"""
import json
import os
from pathlib import Path
import sys
import uuid


def emit(value):
    print(json.dumps(value), flush=True)


def trace_identity(agent):
    with Path("agent-identity.jsonl").open("a") as file:
        file.write(json.dumps({"agent": agent, "pid": os.getpid(), "argv": sys.argv[1:],
                               "environment": os.environ.get("CW_ENVIRONMENT"),
                               "session": os.environ.get("CW_SESSION_ID")}) + "\n")


def skill(path):
    """The skill noel lists for `--skill PATH`: the name and description in
    the frontmatter of the directory's SKILL.md, and that file. A path that
    holds no skill loads none, as in noel."""
    file = Path(path) / "SKILL.md"
    try:
        _, frontmatter, _ = file.read_text().split("---\n", 2)
    except (OSError, ValueError):
        return None
    fields = dict(line.split(": ", 1) for line in frontmatter.splitlines() if ": " in line)
    if not fields.get("description", "").strip():
        return None
    return {"name": fields.get("name", file.parent.name), "description": fields["description"], "file": str(file)}


def noel():
    """`noel --mode rpc`: upstream pi's RPC protocol with the run-id,
    expected-run-id, request-id and resume-run extensions, record for record as
    the noel binary (pi `ef09c03f`) sends them for faux/echo. noel opens no
    dialogs; DIALOG stands in for an upstream extension's, and noel gives its
    answer no reply (noel `76843450`). NOTIFY sends the notification noel sends
    when account failover switches accounts, before the reply.

    Prompts: HOLD streams until a steer or abort ends it (a steer saying WAIT
    leaves it streaming); HOLD2 does so again the first time it is resumed;
    LATE settles as the next command arrives, as a run that ends just before
    it is read; DIALOG asks a question first. `--model fixture/json-rpc`
    behaves as a pre-RPC pi build. As noel does, EOF exits 0 and SIGTERM 143,
    mid-run too, without settling. Every start, with its arguments and the
    skill `--skill DIR` loads, every command received, EOF and SIGTERM are
    traced to peer-noel-SESSION.jsonl.

    Runs and the queue are durable as in noel's journal: a run is saved with
    its requestId when it starts and with its end (completed or aborted)
    before agent_settled, the queue whenever it changes, and each reply once
    it ends unaborted. A run saved without an end loads as interrupted, with
    phase `model`: its held reply was never saved. `get_state.lastRun` reports
    it, `resume_run` continues it under the same runId and answers its last
    user message again (after steering the restarted queue still holds), the
    next prompt first records it as aborted, and so does an abort while idle.
    A prompt that repeats a requestId starts nothing and names that run:
    started while it runs or is interrupted, handled once it ended.

    While a file noel-hold-start-SESSION exists, `get_state` is not answered:
    the journey holds a restarted conversation in its startup handshake.
    """
    import signal
    import time

    args = sys.argv[1:]
    option = {args[i]: args[i + 1] for i in range(len(args) - 1) if args[i].startswith("--")}
    session, model = option.get("--session-id"), option.get("--model")
    trace_path = Path(f"peer-noel-{session}.jsonl")
    saved = Path(f"noel-session-{session}.json")
    hold_start = Path(f"noel-hold-start-{session}")

    def trace(record):
        with trace_path.open("a") as file:
            file.write(json.dumps(record) + "\n")

    trace({"event": "start", "argv": args, "skill": skill(option["--skill"]) if "--skill" in option else None})
    trace_identity("noel")
    if model == "fixture/json-rpc":
        for line in sys.stdin:
            value = json.loads(line)
            trace({"received": value})
            emit({"jsonrpc": "2.0", "id": value.get("id"),
                  "error": {"code": -32600, "message": "missing method"}})
        return 0
    if args[:2] != ["--mode", "rpc"] or not session:
        print("noel fixture: expected --mode rpc --session-id SESSION", file=sys.stderr)
        return 2

    run = None
    journal = json.loads(saved.read_text()) if saved.exists() else {}
    messages = journal.get("messageCount", 0)
    last_user, last_reply = journal.get("lastUser"), journal.get("lastReply")
    steering, follow_up = journal.get("steering", []), journal.get("followUp", [])
    runs = [dict(r, status="interrupted" if r["status"] == "running" else r["status"])
            for r in journal.get("runs", [])]

    def on_term(*_):
        trace({"event": "sigterm", "active": run is not None})
        os._exit(143)

    signal.signal(signal.SIGTERM, on_term)

    def now():
        return int(time.time() * 1000)

    def usage():
        return {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 0,
                "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}}

    def respond(request, data=None, error=None):
        reply = {}
        if "id" in request:
            reply["id"] = request["id"]
        reply.update(type="response", command=request.get("type"), success=error is None)
        if error is not None:
            reply["error"] = error
        elif data is not None:
            reply["data"] = data
        emit(reply)

    def save(count=0):
        """A run without an end, resumed or not, loads as interrupted."""
        nonlocal messages
        messages += count
        saved.write_text(json.dumps({"messageCount": messages, "lastUser": last_user, "lastReply": last_reply,
                                     "steering": steering, "followUp": follow_up, "runs": runs}))

    def end_interrupted():
        if runs and runs[-1]["status"] == "interrupted":
            runs[-1]["status"] = "aborted"
            save()

    def user(text):
        nonlocal last_user
        message = {"role": "user", "content": [{"type": "text", "text": text}], "timestamp": now()}
        emit({"type": "message_start", "message": message})
        emit({"type": "message_end", "message": message})
        run["messages"].append(message)
        last_user = text
        save(1)

    def reply_start(text):
        assistant = {"role": "assistant", "content": [], "api": "faux", "provider": "faux",
                     "model": "echo", "usage": usage(), "stopReason": "pending", "timestamp": now()}
        emit({"type": "message_start", "message": assistant})
        emit({"type": "message_update", "usage": usage(),
              "assistantMessageEvent": {"type": "text_start", "contentIndex": 0}})
        emit({"type": "message_update", "usage": usage(),
              "assistantMessageEvent": {"type": "text_delta", "contentIndex": 0, "delta": "[faux/echo] "}})
        run["reply"] = {"assistant": assistant, "text": "[faux/echo] ", "rest": text}

    def reply_end(stop="stop"):
        nonlocal last_reply
        reply = run.pop("reply")
        text = reply["text"]
        if stop == "stop":
            emit({"type": "message_update", "usage": usage(),
                  "assistantMessageEvent": {"type": "text_delta", "contentIndex": 0, "delta": reply["rest"]}})
            text += reply["rest"]
        emit({"type": "message_update", "usage": usage(),
              "assistantMessageEvent": {"type": "text_end", "contentIndex": 0, "content": text}})
        assistant = dict(reply["assistant"], content=[{"type": "text", "text": text}], stopReason=stop)
        if stop == "aborted":
            assistant["errorMessage"] = "Request was aborted"
        else:
            assistant["rawStopReason"] = "stop"
        assistant.update(durationMs=1, thinkingLevel="off")
        emit({"type": "message_end", "message": assistant})
        emit({"type": "turn_end", "message": assistant, "toolResults": []})
        run["messages"].append(assistant)
        if stop == "stop":
            last_reply = text
            save(1)

    def settle(aborted=False):
        nonlocal run
        runs[-1]["status"] = "aborted" if aborted else "completed"
        save()
        emit({"type": "agent_end", "messages": run["messages"], "willRetry": False})
        emit({"type": "agent_settled", "aborted": aborted, "runId": run["id"]})
        aborts, run = run["aborts"], None
        for request in aborts:
            respond(request)

    def deliver(queued):
        """Queued messages join the run as one user message, as noel batches
        them; faux/echo answers the last user message."""
        text = "\n---\n".join(queued)
        queued.clear()
        emit({"type": "queue_update", "steering": list(steering), "followUp": list(follow_up)})
        user(text)
        return text

    def finish():
        """The held reply ends, then each turn steering or follow-ups open."""
        reply_end()
        while steering or follow_up:
            emit({"type": "turn_start"})
            reply_start(deliver(steering if steering else follow_up))
            reply_end()
        settle()

    def fence(expected):
        if expected is None or (run and run["id"] == expected):
            return None
        if run:
            return f"expectedRunId {expected} does not match the active run {run['id']}"
        return f"expectedRunId {expected} does not match: no run is active"

    def repeated(request_id):
        """The reply to a prompt whose requestId already started a run."""
        known = next((r for r in reversed(runs) if request_id is not None and r["requestId"] == request_id), None)
        if known is None:
            return None
        ended = known["status"] in ("completed", "failed", "aborted")
        return {"disposition": "handled" if ended else "started", "runId": known["runId"]}

    def state():
        data = {}
        if model == "faux/echo":
            data["model"] = {"id": "echo", "name": "Faux Echo", "api": "faux", "provider": "faux",
                             "reasoning": False, "contextWindow": 128000}
        data.update(thinkingLevel="off", isStreaming=run is not None, isCompacting=False,
                    steeringMode="all", followUpMode="all",
                    sessionFile=str(Path.cwd() / f"{session}.jsonl"), sessionId=session,
                    autoCompactionEnabled=True, messageCount=messages,
                    pendingMessageCount=len(steering) + len(follow_up),
                    rpcExtensions=["run-id", "expected-run-id", "request-id", "resume-run"])
        if run:
            data["runId"] = run["id"]
        if runs:
            last = runs[-1]
            data["lastRun"] = {"runId": last["runId"]}
            if last["requestId"] is not None:
                data["lastRun"]["requestId"] = last["requestId"]
            data["lastRun"]["status"] = last["status"]
            if last["status"] == "interrupted":
                data["lastRun"]["phase"] = "model"
        return data

    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            trace({"event": "eof", "active": run is not None})
            return 0
        try:
            request = json.loads(line.rstrip(b"\n").rstrip(b"\r"))
        except ValueError as error:
            emit({"type": "response", "command": "parse", "success": False,
                  "error": f"Failed to parse command: {error}"})
            continue
        trace({"received": request})
        kind = request.get("type")
        if run and run["late"] and kind in ("steer", "abort", "prompt"):
            run["late"] = False
            finish()
        if kind == "get_state":
            while hold_start.exists():
                time.sleep(0.05)
            respond(request, state())
        elif kind == "get_last_assistant_text":
            text = (last_reply or "").strip()
            respond(request, {"text": text} if text else {})
        elif kind == "clear_queue":
            cleared = {"steering": list(steering), "followUp": list(follow_up)}
            steering.clear()
            follow_up.clear()
            save()
            emit({"type": "queue_update", "steering": [], "followUp": []})
            respond(request, cleared)
        elif kind == "prompt" and repeated(request.get("requestId")):
            respond(request, repeated(request.get("requestId")))
        elif kind == "prompt" and run:
            behavior = request.get("streamingBehavior")
            if behavior not in ("steer", "followUp"):
                respond(request, error="Agent is already processing. Specify streamingBehavior "
                        "('steer' or 'followUp') to queue the message.")
                continue
            if request.get("requestId") is not None:
                respond(request, error="a prompt with requestId starts a run; send it when no run is active")
                continue
            (steering if behavior == "steer" else follow_up).append(request["message"])
            save()
            emit({"type": "queue_update", "steering": list(steering), "followUp": list(follow_up)})
            respond(request, {"disposition": "queued"})
        elif kind == "prompt":
            if model != "faux/echo":
                respond(request, error=f"active model is not in models config: {model}")
                continue
            text = request["message"]
            end_interrupted()
            run = {"id": str(uuid.uuid4()), "messages": [], "aborts": [], "late": text == "LATE"}
            runs.append({"runId": run["id"], "requestId": request.get("requestId"), "status": "running",
                         "resumeHolds": 1 if text == "HOLD2" else 0})
            save()
            respond(request, {"disposition": "started", "runId": run["id"]})
            emit({"type": "agent_start", "runId": run["id"]})
            emit({"type": "turn_start"})
            user(text)
            if text == "NOTIFY":
                emit({"type": "extension_ui_request", "id": str(uuid.uuid4()), "method": "notify",
                      "message": "fixture account first is rate limited until 14:05 UTC; switched to second",
                      "notifyType": "warning"})
            # Steering an abort left queued joins the next prompt's first round.
            reply_start(deliver(steering) if steering else text)
            if text == "DIALOG":
                emit({"type": "extension_ui_request", "id": str(uuid.uuid4()), "method": "confirm",
                      "title": "Continue?", "message": "A fixture extension asks."})
                answer = json.loads(sys.stdin.buffer.readline())
                trace({"received": answer})
            if text not in ("HOLD", "HOLD2", "LATE"):
                finish()
        elif kind == "resume_run" and run:
            respond(request, error="Cannot resume_run while the agent is running; wait for agent_settled")
        elif kind == "resume_run":
            expected = request.get("expectedRunId")
            if expected is None:
                respond(request, error="Invalid resume_run command: missing field `expectedRunId`")
            elif not runs:
                respond(request, error=f"expectedRunId {expected} does not match: the session has no run")
            elif runs[-1]["runId"] != expected:
                respond(request, error=f"expectedRunId {expected} does not match the last run "
                        f"{runs[-1]['runId']}")
            elif runs[-1]["status"] != "interrupted":
                respond(request, error=f"run {expected} is not interrupted")
            else:
                last = runs[-1]
                last["status"] = "running"
                run = {"id": expected, "messages": [], "aborts": [], "late": False}
                respond(request, {"disposition": "started", "runId": expected})
                emit({"type": "agent_start", "runId": expected})
                emit({"type": "turn_start"})
                # The cut-off model request is sent again, after any steering
                # the restarted queue still holds.
                reply_start(deliver(steering) if steering else last_user)
                if last.get("resumeHolds"):
                    last["resumeHolds"] -= 1
                    save()
                else:
                    finish()
        elif kind in ("steer", "follow_up"):
            refused = fence(request.get("expectedRunId"))
            if refused:
                respond(request, error=refused)
                continue
            (steering if kind == "steer" else follow_up).append(request["message"])
            save()
            emit({"type": "queue_update", "steering": list(steering), "followUp": list(follow_up)})
            respond(request, {"disposition": "queued"})
            # The held reply finishes, then delivers the steer. WAIT keeps it
            # streaming, so an abort that follows leaves the steer queued.
            if run and kind == "steer" and request["message"] != "WAIT":
                finish()
        elif kind == "abort" and not run and runs and runs[-1]["status"] == "interrupted":
            expected = request.get("expectedRunId")
            if expected not in (None, runs[-1]["runId"]):
                respond(request, error=f"expectedRunId {expected} does not match the "
                        f"interrupted run {runs[-1]['runId']}")
            else:
                end_interrupted()
                respond(request)
        elif kind == "abort":
            refused = fence(request.get("expectedRunId"))
            if refused:
                respond(request, error=refused)
            elif run:
                run["aborts"].append(request)
                reply_end("aborted")
                settle(aborted=True)
            else:
                respond(request)
        else:
            respond(request, error=f"Unknown command: {kind}")


if Path(sys.argv[0]).name == "noel":
    sys.exit(noel())


claude = Path(sys.argv[0]).name == "claude"
thread = str(uuid.uuid4())
session = next((sys.argv[i + 1] for i, value in enumerate(sys.argv[:-1])
                if value in ("--session-id", "--resume")), str(uuid.uuid4()))
active = None
model = next((sys.argv[i + 1] for i, value in enumerate(sys.argv[:-1])
              if value == "--model"), None)


trace_identity("claude" if claude else "codex")


def trace(method, **fields):
    identity = session if claude else thread
    with Path(f"peer-{identity}.jsonl").open("a") as file:
        file.write(json.dumps({"method": method, **fields}) + "\n")


def refuse_model():
    """Codex 0.160.0's first retry of a request the provider refused for the
    model: the retries go on until the turn is interrupted, as a project
    without access to the model makes them."""
    details = (f"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to "
               f"model `{model}`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, "
               "request id: req_synthetic0000")
    emit({"method": "error", "params": {"error": {"message": "Reconnecting... 1/5",
          "codexErrorInfo": {"responseStreamDisconnected": {"httpStatusCode": 403}},
          "additionalDetails": details, "misalignment": None},
          "willRetry": True, "threadId": thread, "turnId": active}})


def refuse_effort(effort):
    """Codex 0.160.0's refusal of an effort the model does not support:
    no retry, and the turn fails."""
    global active
    body = json.dumps({"error": {"message": f"Unsupported value: '{effort}' is not supported with the "
                       f"'{model}' model. Supported values are: 'none', 'low', 'medium', 'high', and 'xhigh'.",
                       "type": "invalid_request_error", "param": "reasoning.effort",
                       "code": "unsupported_value"}}, indent=2)
    error = {"message": body, "codexErrorInfo": "other", "additionalDetails": None, "misalignment": None}
    emit({"method": "error", "params": {"error": error, "willRetry": False,
          "threadId": thread, "turnId": active}})
    emit({"method": "turn/completed", "params": {"threadId": thread,
          "turn": {"id": active, "status": "failed", "error": error}}})
    active = None


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
        if method in ("thread/start", "thread/resume") and params.get("model"):
            model = params["model"]
        trace(method)
        emit({"id": value["id"], "result": {"thread": {"id": thread}}})
    elif method == "turn/start":
        trace(method, effort=params.get("effort"))
        active = str(uuid.uuid4())
        emit({"id": value["id"], "result": {"turn": {"id": active, "status": "inProgress"}}})
        emit({"method": "turn/started", "params": {"threadId": thread,
              "turn": {"id": active, "status": "inProgress"}}})
        text = params["input"][0]["text"]
        if text == "REFUSE_MODEL":
            refuse_model()
        elif text == "REFUSE_EFFORT":
            refuse_effort(params.get("effort"))
        elif text != "HOLD":
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
